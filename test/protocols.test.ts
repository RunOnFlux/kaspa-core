import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, utf8 } from '../src/bytes.js';
import { encodeAddress } from '../src/address.js';
import { KaspaError } from '../src/errors.js';
import { planTransaction } from '../src/plan.js';
import {
  IGRA_MAINNET_LOCK_SCRIPT,
  IGRA_SUBNETWORK_ID,
  igraEntryPayload,
  IgraNonceNotFoundError,
  mineIgraEntry,
  parseIgraEntryPayload,
  planIgraEntry,
} from '../src/protocols/igra.js';
import {
  KRC20_COMMIT_AMOUNT,
  krc20Inscription,
  krc20Mint,
  krc20Transfer,
} from '../src/protocols/krc20.js';
import { ScriptBuilder } from '../src/script/builder.js';
import { Op } from '../src/script/opcodes.js';
import { p2pkScript } from '../src/script/standard.js';
import {
  finalizeTransaction,
  localSigner,
  signTransaction,
} from '../src/sign.js';
import { spendScriptPublicKey } from '../src/spend.js';
import type { InputPlan, Spend } from '../src/spend.js';
import { transactionId } from '../src/tx/encode.js';
import type { Transaction } from '../src/tx/model.js';
import {
  entriesToOracle,
  oracle,
  oracleAvailable,
  txToOracle,
} from './helpers/oracle.js';
import { Rng } from './helpers/random.js';

const rng = new Rng(7070);
const owner = localSigner(rng.secretKey());
const single: Spend = { kind: 'p2pk', xOnlyPubkey: owner.xOnlyPublicKey };
const ownerAddress = encodeAddress('kaspa', 0, owner.xOnlyPublicKey);

function utxo(spend: Spend, amount: bigint): InputPlan {
  return {
    outpoint: { transactionId: rng.bytes(32), index: 0 },
    entry: {
      amount,
      scriptPublicKey: spendScriptPublicKey(spend),
      blockDaaScore: 1n,
      isCoinbase: false,
    },
    spend,
  };
}

function engineVerify(tx: Transaction, inputs: readonly InputPlan[]) {
  const [r] = oracle<{ inputs: { ok: boolean; error: string | null }[] }>([
    {
      op: 'verify',
      tx: txToOracle(tx),
      entries: entriesToOracle(inputs.map((p) => p.entry)),
    },
  ]);
  if (!r?.ok) throw new Error(`oracle error: ${r?.error}`);
  return r.result!.inputs;
}

describe('KRC-20', () => {
  it('operation JSON matches ZelCore’s byte for byte (key order p, op, tick, amt, to)', () => {
    const op = krc20Transfer(
      { tick: 'NACHO', amount: 123_000_000n, to: ownerAddress },
      'kaspa',
    );
    // ZelCore: JSON.stringify({ p, op, tick, amt, to }, null, 0)
    expect(JSON.stringify(op)).toBe(
      JSON.stringify(
        {
          p: 'krc-20',
          op: 'transfer',
          tick: 'NACHO',
          amt: '123000000',
          to: ownerAddress,
        },
        null,
        0,
      ),
    );
  });

  it('inscription script equals the hand-built ZelCore script', () => {
    const op = krc20Transfer(
      { tick: 'TEST', amount: 1n, to: ownerAddress },
      'kaspa',
    );
    const ins = krc20Inscription(owner.xOnlyPublicKey, op, 'kaspa');
    const expected = new ScriptBuilder()
      .addData(owner.xOnlyPublicKey)
      .addOp(Op.OpCheckSig)
      .addOp(Op.OpFalse)
      .addOp(Op.OpIf)
      .addData(utf8('kasplex'))
      .addI64(0n)
      .addData(utf8(JSON.stringify(op)))
      .addOp(Op.OpEndIf)
      .drain();
    expect(bytesToHex(ins.redeem)).toBe(bytesToHex(expected));
    expect(ins.address.startsWith('kaspa:p')).toBe(true);
  });

  it('rejects inputs that would lose tokens', () => {
    const t = { tick: 'TEST', amount: 1n, to: ownerAddress };
    expect(() => krc20Transfer({ ...t, tick: 'TE' }, 'kaspa')).toThrow(
      KaspaError,
    );
    expect(() => krc20Transfer({ ...t, tick: 'TE"ST' }, 'kaspa')).toThrow(
      KaspaError,
    );
    expect(() => krc20Transfer({ ...t, amount: 0n }, 'kaspa')).toThrow(
      KaspaError,
    );
    expect(() => krc20Transfer({ ...t, amount: -5n }, 'kaspa')).toThrow(
      KaspaError,
    );
    expect(() => krc20Transfer(t, 'kaspatest')).toThrow(KaspaError);
    expect(() =>
      krc20Transfer({ ...t, to: ownerAddress.toUpperCase() }, 'kaspa'),
    ).toThrow(KaspaError);
    expect(() => krc20Transfer({ ...t, to: 'kaspa:qqq' }, 'kaspa')).toThrow(
      KaspaError,
    );
    expect(() =>
      krc20Inscription(new Uint8Array(32), krc20Mint('TEST', 'kaspa'), 'kaspa'),
    ).toThrow(KaspaError);
  });

  it.skipIf(!oracleAvailable)(
    'commit → reveal: the reveal (commit input + funding, sent back to the owner) executes in the engine',
    async () => {
      const ins = krc20Inscription(
        owner.xOnlyPublicKey,
        krc20Transfer({ tick: 'TEST', amount: 5n, to: ownerAddress }, 'kaspa'),
        'kaspa',
      );
      const funding = [
        utxo(single, 5_000_000_000n),
        utxo(single, 700_000_000n),
      ];
      const commit = planTransaction(
        funding,
        [{ scriptPublicKey: ins.scriptPublicKey, amount: KRC20_COMMIT_AMOUNT }],
        { feeRate: 100n, changeSpend: single },
      ).final;
      const signedCommit = finalizeTransaction(
        commit.tx,
        commit.inputs,
        await signTransaction(commit.tx, commit.inputs, [owner]),
      );
      engineVerify(signedCommit, commit.inputs).forEach((r) =>
        expect(r.ok, r.error ?? '').toBe(true),
      );

      const commitIndex = commit.tx.outputs.findIndex(
        (o) =>
          bytesToHex(o.scriptPublicKey.script) ===
          bytesToHex(ins.scriptPublicKey.script),
      );
      const commitUtxo: InputPlan = {
        outpoint: { transactionId: commit.id, index: commitIndex },
        entry: {
          amount: KRC20_COMMIT_AMOUNT,
          scriptPublicKey: ins.scriptPublicKey,
          blockDaaScore: 2n,
          isCoinbase: false,
        },
        spend: ins.spend,
      };
      // Reveal: sweep the commit back to the owner.
      const reveal = planTransaction(
        [],
        [{ scriptPublicKey: p2pkScript(owner.xOnlyPublicKey), amount: 0n }],
        {
          feeRate: 100n,
          changeSpend: single,
          requiredInputs: [commitUtxo],
          sendAll: true,
        },
      ).final;
      expect(reveal.inputs[0]).toBe(commitUtxo);
      expect(reveal.fee).toBeLessThan(KRC20_COMMIT_AMOUNT);
      const signedReveal = finalizeTransaction(
        reveal.tx,
        reveal.inputs,
        await signTransaction(reveal.tx, reveal.inputs, [owner], {
          onlyScripts: [ins.scriptPublicKey],
        }),
      );
      engineVerify(signedReveal, reveal.inputs).forEach((r) =>
        expect(r.ok, r.error ?? '').toBe(true),
      );
      // The reveal publishes the operation JSON in the signature script.
      expect(bytesToHex(signedReveal.inputs[0]!.signatureScript)).toContain(
        bytesToHex(utf8('"op":"transfer"')),
      );
    },
  );
});

describe('Igra entry', () => {
  const L2 = '0x' + 'ab'.repeat(20);

  it('payload layout matches ZelCore’s buildEntryPayload', () => {
    // Port of zelcore utils/igraBridgeHelper.js buildEntryPayload.
    function zelcore(addr: string, amount: string, nonce: number): string {
      const p = new Uint8Array(33);
      p[0] = 0x92;
      p.set(hexToBytes(addr.slice(2).toLowerCase()), 1);
      let a = BigInt(amount);
      for (let i = 0; i < 8; i++) {
        p[21 + i] = Number(a & 0xffn);
        a >>= 8n;
      }
      p[29] = nonce & 0xff;
      p[30] = (nonce >> 8) & 0xff;
      p[31] = (nonce >> 16) & 0xff;
      p[32] = (nonce >>> 24) & 0xff;
      return bytesToHex(p);
    }
    for (const [amt, nonce] of [
      [1_000_000_000n, 0],
      [123_456_789_012n, 65_537],
      [2_900_000_000_000_000_000n, 0xffffffff],
    ] as const) {
      const ours = igraEntryPayload(
        L2.toUpperCase().replace('0X', '0x'),
        amt,
        nonce,
      );
      expect(bytesToHex(ours)).toBe(zelcore(L2, amt.toString(), nonce));
      expect(parseIgraEntryPayload(ours)).toEqual({
        l2Address: L2,
        amount: amt,
        nonce,
      });
    }
  });

  it('refuses bad L2 addresses, sub-minimum amounts and bad nonces', () => {
    expect(() => igraEntryPayload('0x1234', 10n ** 9n, 0)).toThrow(KaspaError);
    expect(() =>
      igraEntryPayload('0x' + '00'.repeat(20), 10n ** 9n, 0),
    ).toThrow(KaspaError);
    expect(() => igraEntryPayload(L2, 999_999_999n, 0)).toThrow(/minimum/);
    expect(() => igraEntryPayload(L2, 10n ** 9n, -1)).toThrow(KaspaError);
    expect(() => igraEntryPayload(L2, 10n ** 9n, 2 ** 32)).toThrow(KaspaError);
  });

  function planned() {
    const utxos = [utxo(single, 3_000_000_000n), utxo(single, 900_000_000n)];
    return {
      utxos,
      plan: planIgraEntry(
        utxos,
        { l2Address: L2, amount: 2_000_000_000n },
        {
          feeRate: 100n,
          changeSpend: single,
        },
      ),
    };
  }

  it.skipIf(!oracleAvailable)(
    'plan → mine → sign: id starts with 97b1, matches the oracle, and executes in the engine',
    async () => {
      const { plan } = planned();
      const f = plan.final;
      expect(f.tx.version).toBe(1);
      expect(bytesToHex(f.tx.subnetworkId)).toBe(
        bytesToHex(IGRA_SUBNETWORK_ID),
      );
      const mined = mineIgraEntry(f, { l2Address: L2, amount: 2_000_000_000n });
      expect(bytesToHex(mined.id).startsWith('97b1')).toBe(true);
      expect(bytesToHex(transactionId(mined.tx))).toBe(bytesToHex(mined.id));
      expect(mined.fee).toBe(f.fee);
      const signed = finalizeTransaction(
        mined.tx,
        mined.inputs,
        await signTransaction(mined.tx, mined.inputs, [owner]),
      );
      const [id, m] = oracle([
        { op: 'txid', tx: txToOracle(signed) },
        {
          op: 'mass',
          tx: txToOracle(signed),
          entries: entriesToOracle(mined.inputs.map((p) => p.entry)),
        },
      ]);
      expect(id!.result.id).toBe(bytesToHex(mined.id));
      expect(String(m!.result.compute)).toBe(mined.mass.compute.toString());
      engineVerify(signed, mined.inputs).forEach((r) =>
        expect(r.ok, r.error ?? '').toBe(true),
      );
      const parsed = parseIgraEntryPayload(signed.payload);
      expect(parsed?.l2Address).toBe(L2);
      expect(parsed?.amount).toBe(2_000_000_000n);
    },
  );

  it('refuses to mine anything that is not exactly the entry', () => {
    const { plan } = planned();
    const f = plan.final;
    const entry = { l2Address: L2, amount: 2_000_000_000n };
    const lockIdx = f.tx.outputs.findIndex(
      (o) =>
        bytesToHex(o.scriptPublicKey.script) ===
        bytesToHex(IGRA_MAINNET_LOCK_SCRIPT.script),
    );
    const bump = (d: bigint) => ({
      ...f,
      tx: {
        ...f.tx,
        outputs: f.tx.outputs.map((o, i) =>
          i === lockIdx ? { ...o, value: o.value + d } : o,
        ),
      },
    });
    // Payload would claim a different amount than is actually locked.
    expect(() => mineIgraEntry(bump(-1n), entry)).toThrow(
      /exactly the entry amount/,
    );
    expect(() =>
      mineIgraEntry(f, { ...entry, amount: 2_000_000_001n }),
    ).toThrow(/exactly the entry amount/);
    expect(() =>
      mineIgraEntry({ ...f, tx: { ...f.tx, version: 0 } }, entry),
    ).toThrow(/version 1/);
    expect(() =>
      mineIgraEntry(
        { ...f, tx: { ...f.tx, subnetworkId: new Uint8Array(20) } },
        entry,
      ),
    ).toThrow(/subnetwork/);
    expect(() =>
      mineIgraEntry(
        { ...f, tx: { ...f.tx, payload: new Uint8Array(0) } },
        entry,
      ),
    ).toThrow(/33 bytes/);
    const signedLike = {
      ...f,
      tx: {
        ...f.tx,
        inputs: f.tx.inputs.map((i) => ({
          ...i,
          signatureScript: Uint8Array.of(1),
        })),
      },
    };
    expect(() => mineIgraEntry(signedLike, entry)).toThrow(/before signing/);
  });

  it('a bounded search reports where to resume', () => {
    const { plan } = planned();
    let err: unknown;
    try {
      mineIgraEntry(
        plan.final,
        { l2Address: L2, amount: 2_000_000_000n },
        { maxAttempts: 1, startNonce: 0 },
      );
    } catch (e) {
      err = e;
    }
    // Nonce 0 is a hit with probability 1/65536; otherwise resume at 1.
    if (err) {
      expect(err).toBeInstanceOf(IgraNonceNotFoundError);
      expect((err as IgraNonceNotFoundError).nextNonce).toBe(1);
    }
  });
});
