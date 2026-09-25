import { describe, expect, it } from 'vitest';
import { bytesToHex, concatBytes, utf8 } from '../src/bytes.js';
import { SIG_HASH_ALL } from '../src/constants.js';
import { ScriptBuilder } from '../src/script/builder.js';
import { Op } from '../src/script/opcodes.js';
import { p2pkScript, p2shSignatureScript } from '../src/script/standard.js';
import { SighashContext } from '../src/sighash.js';
import {
  createSigningBundle,
  createTransaction,
  finalizeTransaction,
  localSigner,
  mergePartialSignatures,
  openSigningBundle,
  signTransaction,
} from '../src/sign.js';
import type { KaspaSigner } from '../src/sign.js';
import {
  multisigSpend,
  spendComputeBudget,
  spendScriptPublicKey,
} from '../src/spend.js';
import type { InputPlan, Spend } from '../src/spend.js';
import { planTransaction } from '../src/plan.js';
import { massBreakdown } from '../src/mass.js';
import type { Transaction, TransactionOutput } from '../src/tx/model.js';
import {
  entriesToOracle,
  oracle,
  oracleAvailable,
  txToOracle,
} from './helpers/oracle.js';
import { Rng, xonly } from './helpers/random.js';

interface VerifyResult {
  inputs: { ok: boolean; error: string | null; p2shSigOps: number }[];
}

function verify(tx: Transaction, inputs: readonly InputPlan[]): VerifyResult {
  const [r] = oracle<VerifyResult>([
    {
      op: 'verify',
      tx: txToOracle(tx),
      entries: entriesToOracle(inputs.map((p) => p.entry)),
    },
  ]);
  if (!r?.ok) throw new Error(`oracle error: ${r?.error}`);
  return r.result!;
}

function utxo(rng: Rng, spend: Spend, amount?: bigint): InputPlan {
  return {
    outpoint: { transactionId: rng.bytes(32), index: rng.range(0, 5) },
    entry: {
      amount: amount ?? BigInt(rng.range(1, 10_000)) * 100_000_000n,
      scriptPublicKey: spendScriptPublicKey(spend),
      blockDaaScore: BigInt(rng.range(1, 500_000_000)),
      isCoinbase: false,
    },
    spend,
  };
}

function outputsFor(
  rng: Rng,
  inputs: readonly InputPlan[],
): TransactionOutput[] {
  const total = inputs.reduce((a, p) => a + p.entry.amount, 0n);
  const fee = 1_000_000n;
  const a = (total - fee) / 3n;
  return [
    { value: a, scriptPublicKey: p2pkScript(xonly(rng)) },
    { value: total - fee - a, scriptPublicKey: p2pkScript(xonly(rng)) },
  ];
}

function shuffle<T>(rng: Rng, xs: T[]): T[] {
  const a = [...xs];
  for (let i = a.length - 1; i > 0; i--) {
    const j = rng.int(i + 1);
    [a[i], a[j]] = [a[j]!, a[i]!];
  }
  return a;
}

describe.skipIf(!oracleAvailable)(
  'signed transactions executed by the rusty-kaspa script engine',
  () => {
    it('single-sig P2PK spends validate', async () => {
      const rng = new Rng(100);
      for (let t = 0; t < 20; t++) {
        const signer = localSigner(rng.secretKey());
        const spend: Spend = {
          kind: 'p2pk',
          xOnlyPubkey: signer.xOnlyPublicKey,
        };
        const inputs = Array.from({ length: rng.range(1, 6) }, () =>
          utxo(rng, spend),
        );
        const tx = createTransaction({
          inputs,
          outputs: outputsFor(rng, inputs),
        });
        const partials = await signTransaction(tx, inputs, [signer]);
        const signed = finalizeTransaction(tx, inputs, partials);
        const res = verify(signed, inputs);
        res.inputs.forEach((r) => expect(r.ok, r.error ?? '').toBe(true));
        expect(signed.inputs.every((i) => i.sigOpCount === 1)).toBe(true);
      }
    });

    it('every M-of-N from 1-of-1 to 15-of-15 validates, with any signer subset and out-of-order partials', async () => {
      const rng = new Rng(101);
      for (let n = 1; n <= 15; n++) {
        for (let m = 1; m <= n; m++) {
          const signers = Array.from({ length: n }, () =>
            localSigner(rng.secretKey()),
          );
          const spend = multisigSpend(
            signers.map((s) => s.xOnlyPublicKey),
            m,
          );
          const inputs = Array.from({ length: rng.range(1, 3) }, () =>
            utxo(rng, spend),
          );
          const tx = createTransaction({
            inputs,
            outputs: outputsFor(rng, inputs),
          });
          // A random subset of at least m signers, each signing on its own device.
          const chosen = shuffle(rng, signers).slice(0, rng.range(m, n));
          const perDevice = await Promise.all(
            chosen.map((s) => signTransaction(tx, inputs, [s])),
          );
          const partials = shuffle(rng, mergePartialSignatures(...perDevice));
          const signed = finalizeTransaction(tx, inputs, partials);
          const res = verify(signed, inputs);
          res.inputs.forEach((r) => {
            expect(r.ok, `${m}-of-${n}: ${r.error}`).toBe(true);
            expect(r.p2shSigOps, `${m}-of-${n} sigops`).toBe(n);
          });
          expect(signed.inputs.every((i) => i.sigOpCount === n)).toBe(true);
        }
      }
    });

    it('a signing bundle survives a JSON relay hop between two devices', async () => {
      const rng = new Rng(102);
      const wallet = localSigner(rng.secretKey());
      const key = localSigner(rng.secretKey());
      const spend = multisigSpend(
        [wallet.xOnlyPublicKey, key.xOnlyPublicKey],
        2,
      );
      const inputs = Array.from({ length: 3 }, () => utxo(rng, spend));
      const tx = createTransaction({
        inputs,
        outputs: outputsFor(rng, inputs),
      });

      // Device A: sign and ship.
      const walletPartials = await signTransaction(tx, inputs, [wallet]);
      const wire = JSON.stringify(
        createSigningBundle(tx, inputs, walletPartials),
      );

      // Device B: open, co-sign, finalise.
      // B re-fetches the UTXOs itself (here: the same entries).
      const opened = openSigningBundle(JSON.parse(wire), {
        trustedEntries: inputs.map((p) => p.entry),
      });
      const keyPartials = await signTransaction(opened.tx, opened.inputs, [
        key,
      ]);
      const signed = finalizeTransaction(opened.tx, opened.inputs, [
        ...opened.partials,
        ...keyPartials,
      ]);
      verify(signed, opened.inputs).inputs.forEach((r) =>
        expect(r.ok, r.error ?? '').toBe(true),
      );
    });

    it('mixed input kinds in one transaction validate', async () => {
      const rng = new Rng(103);
      const a = localSigner(rng.secretKey());
      const b = localSigner(rng.secretKey());
      const c = localSigner(rng.secretKey());
      const p2pk: Spend = { kind: 'p2pk', xOnlyPubkey: a.xOnlyPublicKey };
      const twoOfTwo = multisigSpend([a.xOnlyPublicKey, b.xOnlyPublicKey], 2);
      const twoOfThree = multisigSpend(
        [a.xOnlyPublicKey, b.xOnlyPublicKey, c.xOnlyPublicKey],
        2,
      );
      const inputs = [
        utxo(rng, p2pk),
        utxo(rng, twoOfTwo),
        utxo(rng, twoOfThree),
        utxo(rng, p2pk),
      ];
      const tx = createTransaction({
        inputs,
        outputs: outputsFor(rng, inputs),
      });
      const partials = await signTransaction(tx, inputs, [a, b, c]);
      const signed = finalizeTransaction(tx, inputs, partials);
      verify(signed, inputs).inputs.forEach((r) =>
        expect(r.ok, r.error ?? '').toBe(true),
      );
      expect(signed.inputs.map((i) => i.sigOpCount)).toEqual([1, 2, 3, 1]);
    });

    it('a KRC-20-style inscription P2SH script (p2sh-script) validates', async () => {
      const rng = new Rng(104);
      const signer = localSigner(rng.secretKey());
      const payload = utf8(
        JSON.stringify({
          p: 'krc-20',
          op: 'transfer',
          tick: 'TEST',
          amt: '100',
          to: 'kaspa:q',
        }),
      );
      const redeem = new ScriptBuilder()
        .addData(signer.xOnlyPublicKey)
        .addOp(Op.OpCheckSig)
        .addOp(Op.OpFalse)
        .addOp(Op.OpIf)
        .addData(utf8('kasplex'))
        .addI64(0n)
        .addData(payload)
        .addOp(Op.OpEndIf)
        .drain();
      const spend: Spend = {
        kind: 'p2sh-script',
        redeem,
        signerPubkey: signer.xOnlyPublicKey,
      };
      const inputs = [utxo(rng, spend, 30_000_000n)];
      const tx = createTransaction({
        inputs,
        outputs: [
          {
            value: 29_000_000n,
            scriptPublicKey: p2pkScript(signer.xOnlyPublicKey),
          },
        ],
      });
      const signed = finalizeTransaction(
        tx,
        inputs,
        await signTransaction(tx, inputs, [signer]),
      );
      const res = verify(signed, inputs);
      expect(res.inputs[0]!.ok, res.inputs[0]!.error ?? '').toBe(true);
      expect(res.inputs[0]!.p2shSigOps).toBe(1);
    });

    it('planned transactions (including a compounding chain) validate stage by stage', async () => {
      const rng = new Rng(105);
      const wallet = localSigner(rng.secretKey());
      const key = localSigner(rng.secretKey());
      const spend = multisigSpend(
        [wallet.xOnlyPublicKey, key.xOnlyPublicKey],
        2,
      );
      // 120 small UTXOs: more than fit in one standard 2-of-2 transaction (43).
      const utxos = Array.from({ length: 120 }, () =>
        utxo(rng, spend, BigInt(rng.range(2, 5)) * 100_000_000n),
      );
      const plan = planTransaction(
        utxos,
        [
          {
            scriptPublicKey: p2pkScript(xonly(rng)),
            amount: 300n * 100_000_000n,
          },
        ],
        {
          feeRate: 1n,
          changeSpend: spend,
        },
      );
      expect(plan.stages.length).toBeGreaterThan(0);
      for (const planned of [...plan.stages, plan.final]) {
        const partials = await signTransaction(planned.tx, planned.inputs, [
          wallet,
          key,
        ]);
        const signed = finalizeTransaction(
          planned.tx,
          planned.inputs,
          partials,
        );
        verify(signed, planned.inputs).inputs.forEach((r) =>
          expect(r.ok, r.error ?? '').toBe(true),
        );
        // Mass computed before signing equals mass after (fixed-width signatures).
        const after = massBreakdown(
          signed,
          planned.inputs.map((p) => p.entry),
        );
        expect(after.max).toBe(planned.mass.max);
        const [m] = oracle([
          {
            op: 'mass',
            tx: txToOracle(signed),
            entries: entriesToOracle(planned.inputs.map((p) => p.entry)),
          },
        ]);
        expect(String(m!.result.compute)).toBe(after.compute.toString());
        expect(
          m!.result.storage === null ? null : String(m!.result.storage),
        ).toBe(after.storage?.toString() ?? null);
      }
    });

    it('version 1 spends validate with enough compute budget and fail with one unit less', async () => {
      const rng = new Rng(106);
      const signer = localSigner(rng.secretKey());
      const spend: Spend = { kind: 'p2pk', xOnlyPubkey: signer.xOnlyPublicKey };
      const inputs = [utxo(rng, spend)];
      const build = (budget: number) =>
        createTransaction({
          inputs,
          outputs: outputsFor(rng, inputs),
          version: 1,
          computeBudgets: [budget],
        });
      const ok = build(10);
      const signedOk = finalizeTransaction(
        ok,
        inputs,
        await signTransaction(ok, inputs, [signer]),
      );
      expect(verify(signedOk, inputs).inputs[0]!.ok).toBe(true);
      expect(() => build(9)).toThrow(/compute budget 9 is below/);
      // Budgets are not committed to by the signature: lowering one after
      // signing (as a relay could) keeps the signature valid but the engine
      // rejects the input — which is why the library enforces the floor.
      const signedLow = {
        ...signedOk,
        inputs: signedOk.inputs.map((i) => ({ ...i, computeBudget: 9 })),
      };
      expect(verify(signedLow, inputs).inputs[0]!.ok).toBe(false);
    });

    it('spendComputeBudget is exact: it passes and one unit less fails, for every shape', async () => {
      const rng = new Rng(300);
      const shapes: { n: number; m: number; inscription?: number }[] = [
        { n: 0, m: 0 },
        { n: 2, m: 2 },
        { n: 3, m: 2 },
        { n: 5, m: 3 },
        { n: 15, m: 15 },
        { n: 15, m: 1 },
        { n: 0, m: 0, inscription: 200 },
        { n: 0, m: 0, inscription: 12_000 },
      ];
      for (const sh of shapes) {
        const signers = Array.from({ length: Math.max(1, sh.n) }, () =>
          localSigner(rng.secretKey()),
        );
        let spend: Spend;
        let chosen: KaspaSigner[] = signers;
        if (sh.inscription !== undefined) {
          const redeem = new ScriptBuilder()
            .addData(signers[0]!.xOnlyPublicKey)
            .addOp(Op.OpCheckSig)
            .addOp(Op.OpFalse)
            .addOp(Op.OpIf)
            .addData(rng.bytes(sh.inscription))
            .addOp(Op.OpEndIf)
            .drain();
          spend = {
            kind: 'p2sh-script',
            redeem,
            signerPubkey: signers[0]!.xOnlyPublicKey,
          };
        } else if (sh.n === 0) {
          spend = { kind: 'p2pk', xOnlyPubkey: signers[0]!.xOnlyPublicKey };
        } else {
          const ms = multisigSpend(
            signers.map((x) => x.xOnlyPublicKey),
            sh.m,
          );
          if (ms.kind !== 'p2sh-multisig') throw new Error('unreachable');
          spend = ms;
          // worst case: the last m keys in script order sign (most checks)
          const inOrder = ms.pubkeys.map((k) =>
            signers.find(
              (x) => bytesToHex(x.xOnlyPublicKey) === bytesToHex(k),
            )!,
          );
          chosen = inOrder.slice(inOrder.length - sh.m);
        }
        const inputs = [utxo(rng, spend)];
        const budget = spendComputeBudget(spend);
        const run = async (b: number) => {
          const tx = createTransaction({
            inputs,
            outputs: outputsFor(rng, inputs),
            version: 1,
            computeBudgets: [budget],
          });
          const signed = finalizeTransaction(
            tx,
            inputs,
            await signTransaction(tx, inputs, chosen),
          );
          // Set the budget under test after signing (it is not in the sighash).
          const probe = {
            ...signed,
            inputs: signed.inputs.map((i) => ({ ...i, computeBudget: b })),
          };
          return verify(probe, inputs).inputs[0]!.ok;
        };
        const label =
          sh.inscription !== undefined
            ? `inscription ${sh.inscription}B`
            : `${sh.m}-of-${sh.n}`;
        expect(await run(budget), `${label} budget ${budget}`).toBe(true);
        expect(await run(budget - 1), `${label} budget ${budget - 1}`).toBe(
          false,
        );
      }
    });

    it('KRC-20 reveal: a required inscription input plus selected funding inputs validates', async () => {
      const rng = new Rng(301);
      const owner = localSigner(rng.secretKey());
      const single: Spend = { kind: 'p2pk', xOnlyPubkey: owner.xOnlyPublicKey };
      const redeem = new ScriptBuilder()
        .addData(owner.xOnlyPublicKey)
        .addOp(Op.OpCheckSig)
        .addOp(Op.OpFalse)
        .addOp(Op.OpIf)
        .addData(utf8('kasplex'))
        .addI64(0n)
        .addData(utf8('{"p":"krc-20","op":"transfer","tick":"TEST","amt":"1"}'))
        .addOp(Op.OpEndIf)
        .drain();
      const commit = utxo(
        rng,
        { kind: 'p2sh-script', redeem, signerPubkey: owner.xOnlyPublicKey },
        30_000_000n,
      );
      const funding = Array.from({ length: 3 }, () =>
        utxo(rng, single, 200_000_000n),
      );
      const plan = planTransaction(
        funding,
        [
          {
            scriptPublicKey: p2pkScript(owner.xOnlyPublicKey),
            amount: 250_000_000n,
          },
        ],
        {
          feeRate: 100n,
          changeSpend: single,
          requiredInputs: [commit],
        },
      );
      expect(plan.final.inputs[0]).toBe(commit);
      const signed = finalizeTransaction(
        plan.final.tx,
        plan.final.inputs,
        await signTransaction(plan.final.tx, plan.final.inputs, [owner]),
      );
      verify(signed, plan.final.inputs).inputs.forEach((r) =>
        expect(r.ok, r.error ?? '').toBe(true),
      );
    });

    it('Igra-style version 1 lane transaction with a payload validates, and id and mass match the oracle', async () => {
      const rng = new Rng(302);
      const owner = localSigner(rng.secretKey());
      const single: Spend = { kind: 'p2pk', xOnlyPubkey: owner.xOnlyPublicKey };
      const lane = new Uint8Array(20);
      lane.set([0x97, 0xb1]);
      const payload = Uint8Array.of(0x92, ...rng.bytes(32));
      const utxos = Array.from({ length: 4 }, () =>
        utxo(rng, single, 5_000_000_000n),
      );
      const plan = planTransaction(
        utxos,
        [{ scriptPublicKey: p2pkScript(xonly(rng)), amount: 1_000_000_000n }],
        {
          feeRate: 100n,
          changeSpend: single,
          txVersion: 1,
          subnetworkId: lane,
          payload,
        },
      );
      const f = plan.final;
      expect(f.tx.version).toBe(1);
      expect(f.tx.inputs.every((i) => i.computeBudget === 10)).toBe(true);
      const signed = finalizeTransaction(
        f.tx,
        f.inputs,
        await signTransaction(f.tx, f.inputs, [owner]),
      );
      verify(signed, f.inputs).inputs.forEach((r) =>
        expect(r.ok, r.error ?? '').toBe(true),
      );
      const [id, m] = oracle([
        { op: 'txid', tx: txToOracle(signed) },
        {
          op: 'mass',
          tx: txToOracle(signed),
          entries: entriesToOracle(f.inputs.map((p) => p.entry)),
        },
      ]);
      expect(bytesToHex(f.id)).toBe(id!.result.id);
      expect(String(m!.result.compute)).toBe(f.mass.compute.toString());
    });

    describe('negative controls — the engine must reject these', () => {
      async function twoOfTwoSetup(seed: number) {
        const rng = new Rng(seed);
        const a = localSigner(rng.secretKey());
        const b = localSigner(rng.secretKey());
        const spend = multisigSpend([a.xOnlyPublicKey, b.xOnlyPublicKey], 2);
        if (spend.kind !== 'p2sh-multisig') throw new Error('unreachable');
        const inputs = [utxo(rng, spend)];
        return { rng, a, b, spend, inputs };
      }

      /** Sign input 0 manually for whatever tx we hand it (bypassing library guards). */
      async function rawSigs(
        tx: Transaction,
        inputs: InputPlan[],
        signers: KaspaSigner[],
      ) {
        const digest = new SighashContext(
          tx,
          inputs.map((p) => p.entry),
        ).schnorr(0, SIG_HASH_ALL);
        const byKey = new Map<string, Uint8Array>();
        for (const s of signers) {
          const sig = await s.signDigest(digest);
          byKey.set(
            bytesToHex(s.xOnlyPublicKey),
            concatBytes(
              Uint8Array.of(Op.OpData65),
              sig,
              Uint8Array.of(SIG_HASH_ALL),
            ),
          );
        }
        return byKey;
      }

      it('rejects a multisig input that declares sigOpCount 1 instead of n', async () => {
        const { rng, a, b, spend, inputs } = await twoOfTwoSetup(200);
        const tx = createTransaction({
          inputs,
          outputs: outputsFor(rng, inputs),
        });
        tx.inputs[0]!.sigOpCount = 1;
        const sigs = await rawSigs(tx, inputs, [a, b]);
        const ordered = spend.pubkeys.map((k) => sigs.get(bytesToHex(k))!);
        tx.inputs[0]!.signatureScript = p2shSignatureScript(
          spend.redeem,
          ordered,
        );
        const r = verify(tx, inputs).inputs[0]!;
        expect(r.ok).toBe(false);
      });

      it('rejects signatures in the wrong order', async () => {
        const { rng, a, b, spend, inputs } = await twoOfTwoSetup(201);
        const tx = createTransaction({
          inputs,
          outputs: outputsFor(rng, inputs),
        });
        const sigs = await rawSigs(tx, inputs, [a, b]);
        const reversed = [...spend.pubkeys]
          .reverse()
          .map((k) => sigs.get(bytesToHex(k))!);
        tx.inputs[0]!.signatureScript = p2shSignatureScript(
          spend.redeem,
          reversed,
        );
        expect(verify(tx, inputs).inputs[0]!.ok).toBe(false);
      });

      it('rejects a Bitcoin-style leading OP_0 dummy element', async () => {
        const { rng, a, b, spend, inputs } = await twoOfTwoSetup(202);
        const tx = createTransaction({
          inputs,
          outputs: outputsFor(rng, inputs),
        });
        const sigs = await rawSigs(tx, inputs, [a, b]);
        const ordered = spend.pubkeys.map((k) => sigs.get(bytesToHex(k))!);
        tx.inputs[0]!.signatureScript = concatBytes(
          Uint8Array.of(Op.Op0),
          p2shSignatureScript(spend.redeem, ordered),
        );
        expect(verify(tx, inputs).inputs[0]!.ok).toBe(false);
      });

      it('rejects a signature over a different amount (why the key must fetch UTXOs itself)', async () => {
        const { rng, a, b, inputs } = await twoOfTwoSetup(203);
        const tx = createTransaction({
          inputs,
          outputs: outputsFor(rng, inputs),
        });
        const lied = [
          {
            ...inputs[0]!,
            entry: {
              ...inputs[0]!.entry,
              amount: inputs[0]!.entry.amount + 1n,
            },
          },
        ];
        const partials = await signTransaction(tx, lied, [a, b]);
        const signed = finalizeTransaction(tx, lied, partials);
        expect(verify(signed, inputs).inputs[0]!.ok).toBe(false);
      });
    });
  },
);
