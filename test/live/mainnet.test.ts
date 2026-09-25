import { TEST_XONLY } from '../helpers/random.js';
import { describe, expect, it } from 'vitest';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '../../src/bytes.js';
import { transactionHash, transactionId } from '../../src/tx/encode.js';
import { SighashContext } from '../../src/sighash.js';
import { parseScript } from '../../src/script/sigops.js';
import {
  classifyScript,
  parseMultisigRedeemScript,
  p2pkScript,
  p2shScript,
} from '../../src/script/standard.js';
import { massBreakdown, storageMass } from '../../src/mass.js';
import { createRestClient } from '../../src/rest.js';
import { entriesFromFundingTransactions } from '../../src/sign.js';
import { RestError } from '../../src/errors.js';
import type { RestTransaction } from '../../src/rest.js';
import type {
  Transaction,
  TransactionOutput,
  UtxoEntry,
} from '../../src/tx/model.js';
import {
  entriesToOracle,
  oracle,
  oracleAvailable,
  txToOracle,
} from '../helpers/oracle.js';

/**
 * Live mainnet checks — run with `yarn test:live`. They read immutable
 * historical transactions and the node's own mass calculation; no funds move.
 */
const LIVE = process.env.KASPA_LIVE === '1';
const REST = process.env.KASPA_REST ?? 'https://api.kaspa.org';

/** Pinned real mainnet transactions. */
const P2PK_TXS = [
  '2de30034c236ebc4d0c6beeb8b78add2d39f699fb943f5a132de793f462c3d23',
];
/** Outgoing spends from large `kaspa:p…` addresses (real multisig treasuries). */
const P2SH_TXS = [
  'f0d97ffbd1e3c99635d92ca2ad2c2a0689520a7e058f39e22440152f7ec3da7a',
  '56a092562da8b2fda013305a78d65766faaeec5005312fca6a0e8fd8feb4dcea',
  'bb5ec3ed8204e7d3747e13de324724bd60a16b0d40ef5e09ffd01baad42556b0',
  '8ef8c03c5447fd96efc3a582de214d92373f071a3aa311e1b08bcdd8fb11b6b7',
];
const BUSY_P2PK_ADDRESS =
  'kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73';

function num(v: unknown): bigint {
  return BigInt(String(v));
}

/**
 * Rebuild a consensus Transaction from the REST view. REST omits sequence,
 * lock time and gas; standard wallets use 0 for all three, and a matching
 * transaction id proves that assumption for each transaction checked.
 */
function fromRest(t: RestTransaction): {
  tx: Transaction;
  entries: UtxoEntry[];
} {
  const inputs = [...(t.inputs ?? [])].sort((a, b) => a.index - b.index);
  const outputs = [...(t.outputs ?? [])].sort((a, b) => a.index - b.index);
  const tx: Transaction = {
    version: t.version ?? 0,
    inputs: inputs.map((i) => ({
      previousOutpoint: {
        transactionId: hexToBytes(i.previous_outpoint_hash),
        index: Number(i.previous_outpoint_index),
      },
      signatureScript: hexToBytes(i.signature_script ?? ''),
      sequence: 0n,
      sigOpCount: Number(i.sig_op_count ?? 0),
      ...(i.compute_budget != null ? { computeBudget: i.compute_budget } : {}),
    })),
    outputs: outputs.map((o): TransactionOutput => ({
      value: num(o.amount),
      scriptPublicKey: {
        version: 0,
        script: hexToBytes(o.script_public_key ?? ''),
      },
    })),
    lockTime: 0n,
    subnetworkId: hexToBytes(t.subnetwork_id ?? '00'.repeat(20)),
    gas: 0n,
    payload: hexToBytes(t.payload ?? ''),
  };
  const entries: UtxoEntry[] = inputs.map((i) => {
    const r = (
      i as unknown as {
        previous_outpoint_resolved: {
          amount: unknown;
          script_public_key: string;
        };
      }
    ).previous_outpoint_resolved;
    return {
      amount: num(r.amount),
      scriptPublicKey: { version: 0, script: hexToBytes(r.script_public_key) },
      blockDaaScore: 0n,
      isCoinbase: false,
    };
  });
  return { tx, entries };
}

/** Split a P2SH signature script into its signature pushes and the redeem script. */
function splitP2sh(sigScript: Uint8Array): {
  sigs: Uint8Array[];
  redeem: Uint8Array;
} {
  const ops = parseScript(sigScript);
  const redeem = ops[ops.length - 1]?.data ?? new Uint8Array();
  return {
    sigs: ops.slice(0, -1).map((o) => o.data ?? new Uint8Array()),
    redeem,
  };
}

describe.skipIf(!LIVE)('live mainnet', () => {
  const rest = createRestClient({ baseUrl: REST });

  it('recomputes the transaction id of real P2PK and P2SH spends', async () => {
    for (const id of [...P2PK_TXS, ...P2SH_TXS]) {
      const t = await rest.getTransaction(id, {
        resolvePreviousOutpoints: 'full',
      });
      const { tx } = fromRest(t);
      expect(bytesToHex(transactionId(tx)), id).toBe(id);
      // The signature-inclusive hash commits to the storage mass (0 if none).
      const { entries } = fromRest(t);
      const sm = storageMass(entries, tx.outputs) ?? 0n;
      expect(bytesToHex(transactionHash(tx, sm)), `hash ${id}`).toBe(t.hash);
    }
  });

  it('every real P2PK signature verifies against our Schnorr signature hash', async () => {
    for (const id of P2PK_TXS) {
      const { tx, entries } = fromRest(
        await rest.getTransaction(id, { resolvePreviousOutpoints: 'full' }),
      );
      const ctx = new SighashContext(tx, entries);
      tx.inputs.forEach((input, i) => {
        const spk = entries[i]!.scriptPublicKey;
        expect(classifyScript(spk)).toBe('p2pk');
        const push = input.signatureScript;
        expect(push.length).toBe(66);
        const sig = push.slice(1, 65);
        const hashType = push[65]!;
        expect(
          schnorr.verify(
            sig,
            ctx.schnorr(i, hashType),
            spk.script.slice(1, 33),
          ),
          `${id}#${i}`,
        ).toBe(true);
      });
    }
  });

  it('every real P2SH multisig signature verifies (Schnorr or ECDSA) with the sliding-window rule', async () => {
    let checked = 0;
    for (const id of P2SH_TXS) {
      const { tx, entries } = fromRest(
        await rest.getTransaction(id, { resolvePreviousOutpoints: 'full' }),
      );
      const ctx = new SighashContext(tx, entries);
      tx.inputs.forEach((input, i) => {
        const entry = entries[i]!;
        if (classifyScript(entry.scriptPublicKey) !== 'p2sh') return;
        const { sigs, redeem } = splitP2sh(input.signatureScript);
        expect(
          bytesToHex(p2shScript(redeem).script),
          `${id}#${i} redeem hash`,
        ).toBe(bytesToHex(entry.scriptPublicKey.script));
        const ms = parseMultisigRedeemScript(redeem);
        if (!ms) return;
        expect(input.sigOpCount, `${id}#${i} sigops`).toBe(ms.pubkeys.length);
        expect(sigs.length).toBe(ms.m);
        let k = 0;
        for (const s of sigs) {
          const sig = s.slice(0, 64);
          const ht = s[64]!;
          let matched = false;
          while (k < ms.pubkeys.length && !matched) {
            const key = ms.pubkeys[k++]!;
            matched = ms.ecdsa
              ? secp256k1.verify(sig, ctx.ecdsa(i, ht), key, {
                  prehash: false,
                  format: 'compact',
                })
              : schnorr.verify(sig, ctx.schnorr(i, ht), key);
          }
          expect(
            matched,
            `${id}#${i} ${ms.ecdsa ? 'ecdsa' : 'schnorr'} ${ms.m}-of-${ms.pubkeys.length}`,
          ).toBe(true);
        }
        checked++;
      });
    }
    expect(checked).toBeGreaterThan(0);
  });

  it.skipIf(!oracleAvailable)(
    'the rusty-kaspa engine accepts the real transactions as rebuilt by us',
    async () => {
      for (const id of [...P2PK_TXS, ...P2SH_TXS]) {
        const { tx, entries } = fromRest(
          await rest.getTransaction(id, { resolvePreviousOutpoints: 'full' }),
        );
        const [r] = oracle([
          {
            op: 'verify',
            tx: txToOracle(tx),
            entries: entriesToOracle(entries),
          },
        ]);
        expect(r!.ok, r!.error).toBe(true);
        r!.result.inputs.forEach(
          (x: { ok: boolean; error: string | null }, i: number) =>
            expect(x.ok, `${id}#${i}: ${x.error}`).toBe(true),
        );
      }
    },
  );

  it('our mass equals the node for real inputs across shapes, including tiny change', async () => {
    let utxos = (await rest.getUtxos([BUSY_P2PK_ADDRESS])).slice(0, 12);
    expect(utxos.length).toBeGreaterThan(4);
    const dst = p2pkScript(TEST_XONLY);
    const shapes: {
      nIn: number;
      outs: bigint[];
      sigScript: number;
      sigOps: number;
    }[] = [
      { nIn: 1, outs: [100_000_000n], sigScript: 66, sigOps: 1 },
      { nIn: 1, outs: [100_000_000n, 10_000_000n], sigScript: 66, sigOps: 1 },
      { nIn: 2, outs: [100_000_000n, 20_000_000n], sigScript: 202, sigOps: 2 },
      { nIn: 3, outs: [50_000_000n, 10_000_000n], sigScript: 236, sigOps: 3 },
      {
        nIn: 5,
        outs: [300_000_000n, 1_000_000n, 2_000_000n],
        sigScript: 368,
        sigOps: 5,
      },
      { nIn: 1, outs: [10_000_000n, 5_000_000n], sigScript: 66, sigOps: 1 },
      {
        nIn: 4,
        outs: [700_000n, 800_000n, 900_000n, 1_000_000n, 1_100_000n],
        sigScript: 66,
        sigOps: 1,
      },
    ];
    const build = (s: (typeof shapes)[number]) => {
      const ins = utxos.slice(0, s.nIn);
      const tx: Transaction = {
        version: 0,
        inputs: ins.map((u) => ({
          previousOutpoint: u.outpoint,
          signatureScript: new Uint8Array(s.sigScript),
          sequence: 0n,
          sigOpCount: s.sigOps,
        })),
        outputs: s.outs.map((v) => ({ value: v, scriptPublicKey: dst })),
        lockTime: 0n,
        subnetworkId: new Uint8Array(20),
        gas: 0n,
        payload: new Uint8Array(0),
      };
      return { ins, tx };
    };
    for (const s of shapes) {
      let { ins, tx } = build(s);
      let node;
      try {
        node = await rest.getMass(tx);
      } catch (e) {
        // The live UTXO set can move between lookup and pricing (a UTXO gets
        // spent); refresh once rather than report a false mismatch.
        if (!(e instanceof RestError) || e.status !== 404) throw e;
        utxos = (await rest.getUtxos([BUSY_P2PK_ADDRESS])).slice(0, 12);
        ({ ins, tx } = build(s));
        node = await rest.getMass(tx);
      }
      const ours = massBreakdown(
        tx,
        ins.map((u) => u.entry),
      );
      const label = `${s.nIn}in/${s.outs.length}out`;
      expect(ours.compute, label).toBe(node.computeMass);
      expect(ours.storage, label).toBe(node.storageMass);
      expect(ours.max, label).toBe(node.mass);
    }
  });

  it('funding transactions are proven by their ID and agree with the UTXO index', async () => {
    const utxos = (await rest.getUtxos([BUSY_P2PK_ADDRESS])).slice(-15);
    expect(utxos.length).toBeGreaterThan(0);
    let proven = 0;
    for (const u of utxos) {
      const id = bytesToHex(u.outpoint.transactionId);
      let funding: Transaction;
      try {
        funding = await rest.getFundingTransaction(id);
      } catch (e) {
        // Unavailable (404) or unprovable from the REST view (non-zero
        // sequences): refused, never mis-proven.
        if (e instanceof RestError && e.status === 404) continue;
        if (e instanceof Error && /could not be proven/.test(e.message))
          continue;
        throw e;
      }
      expect(bytesToHex(transactionId(funding))).toBe(id);
      const [entry] = entriesFromFundingTransactions(
        [
          {
            outpoint: u.outpoint,
            entry: u.entry,
            spend: {
              kind: 'p2pk',
              xOnlyPubkey: u.entry.scriptPublicKey.script.slice(1, 33),
            },
          },
        ],
        [funding],
      );
      expect(entry!.amount).toBe(u.entry.amount);
      expect(bytesToHex(entry!.scriptPublicKey.script)).toBe(
        bytesToHex(u.entry.scriptPublicKey.script),
      );
      proven++;
    }
    expect(proven).toBeGreaterThan(0);
  });
});
