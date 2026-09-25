/**
 * Regressions for the second independent review (signing and UTXO safety).
 * Each test reproduces the reported attack or failure and proves it is
 * now refused.
 */
import { describe, expect, it } from 'vitest';
import { COINBASE_MATURITY } from '../src/constants.js';
import {
  EntryMismatchError,
  FeeTooHighError,
  InvalidTransactionError,
  KaspaError,
  MultisigConfigError,
} from '../src/errors.js';
import { planTransaction } from '../src/plan.js';
import { ScriptBuilder } from '../src/script/builder.js';
import { Op } from '../src/script/opcodes.js';
import { p2pkScript, p2shScript } from '../src/script/standard.js';
import {
  createSigningBundle,
  createTransaction,
  entriesFromFundingTransactions,
  finalizeTransaction,
  localSigner,
  mergePartialSignatures,
  openSigningBundle,
  signTransaction,
} from '../src/sign.js';
import type { PartialSignature, SignedAmountLedger } from '../src/sign.js';
import { multisigSpend, spendScriptPublicKey } from '../src/spend.js';
import type { InputPlan, Spend } from '../src/spend.js';
import { transactionId } from '../src/tx/encode.js';
import { transactionToJson } from '../src/tx/json.js';
import type { Transaction } from '../src/tx/model.js';
import {
  entriesToOracle,
  oracle,
  oracleAvailable,
  txToOracle,
} from './helpers/oracle.js';
import { Rng, TEST_XONLY } from './helpers/random.js';

const KAS = 100_000_000n;
const rng = new Rng(2002);
const victim = localSigner(rng.secretKey());
const attacker = localSigner(rng.secretKey());
const VAULT = multisigSpend(
  [victim.xOnlyPublicKey, attacker.xOnlyPublicKey],
  2,
);
const DST = p2pkScript(TEST_XONLY);

/** A real funding transaction creating two 100 KAS vault outputs. */
function fundedVault(): { funding: Transaction; inputs: InputPlan[] } {
  const funding: Transaction = {
    version: 0,
    inputs: [
      {
        previousOutpoint: { transactionId: rng.bytes(32), index: 0 },
        signatureScript: new Uint8Array(0),
        sequence: 0n,
        sigOpCount: 1,
      },
    ],
    outputs: [0, 1].map(() => ({
      value: 100n * KAS,
      scriptPublicKey: spendScriptPublicKey(VAULT),
    })),
    lockTime: 0n,
    subnetworkId: new Uint8Array(20),
    gas: 0n,
    payload: new Uint8Array(0),
  };
  const id = transactionId(funding);
  const inputs = [0, 1].map((index): InputPlan => ({
    outpoint: { transactionId: id, index },
    entry: {
      amount: 100n * KAS,
      scriptPublicKey: spendScriptPublicKey(VAULT),
      blockDaaScore: 1n,
      isCoinbase: false,
    },
    spend: VAULT,
  }));
  return { funding, inputs };
}

/** The attacker's transaction: 100.9 KAS out of 200 KAS in — a 99.1 KAS fee. */
function theftTx(inputs: InputPlan[]): Transaction {
  return createTransaction({
    inputs,
    outputs: [{ value: 1009n * (KAS / 10n), scriptPublicKey: DST }],
  });
}

/** What the attacker (and a lying UTXO source) claim in one session. */
function lieAbout(inputs: InputPlan[], index: number): InputPlan[] {
  return inputs.map((p, i) =>
    i === index ? { ...p, entry: { ...p.entry, amount: 1n * KAS } } : p,
  );
}

function memoryLedger(): SignedAmountLedger {
  const m = new Map<string, bigint>();
  return { get: (k) => m.get(k), set: (k, v) => void m.set(k, v) };
}

describe('M1: combining signatures from separate sessions to inflate the fee', () => {
  async function session(
    lied: InputPlan[],
    ledger?: SignedAmountLedger,
  ): Promise<PartialSignature[]> {
    const tx = theftTx(lied);
    // The victim "re-fetched" the UTXOs from the same compromised backend.
    const opened = openSigningBundle(createSigningBundle(tx, lied), {
      trustedEntries: lied.map((p) => p.entry),
    });
    return signTransaction(opened.tx, opened.inputs, [victim], {
      onlyScripts: [spendScriptPublicKey(VAULT)],
      ...(ledger ? { signedAmounts: ledger } : {}),
    });
  }

  it.skipIf(!oracleAvailable)(
    'without defences the attack works (why the defences exist)',
    async () => {
      const { inputs } = fundedVault();
      const s1 = await session(lieAbout(inputs, 1)); // victim sees fee 0.1 KAS
      const s2 = await session(lieAbout(inputs, 0)); // victim sees fee 0.1 KAS
      const tx = theftTx(inputs);
      const own = await signTransaction(tx, inputs, [attacker], {
        maxFee: 1000n * KAS,
      });
      const victimSigs = [
        ...s1.filter((p) => p.inputIndex === 0),
        ...s2.filter((p) => p.inputIndex === 1),
      ];
      const signed = finalizeTransaction(
        tx,
        inputs,
        mergePartialSignatures(own, victimSigs),
      );
      const [r] = oracle<{ inputs: { ok: boolean }[] }>([
        {
          op: 'verify',
          tx: txToOracle(signed),
          entries: entriesToOracle(inputs.map((p) => p.entry)),
        },
      ]);
      expect(r!.result!.inputs.map((x) => x.ok)).toEqual([true, true]);
    },
  );

  it('a signed-amount ledger refuses the second session', async () => {
    const { inputs } = fundedVault();
    const ledger = memoryLedger();
    await session(lieAbout(inputs, 1), ledger);
    await expect(session(lieAbout(inputs, 0), ledger)).rejects.toThrow(
      /already signed this outpoint with a different amount/,
    );
  });

  it('funding transactions prove the real amounts, whatever the backend says', async () => {
    const { funding, inputs } = fundedVault();
    const lied = lieAbout(inputs, 1);
    const bundle = createSigningBundle(theftTx(lied), lied);
    expect(() =>
      openSigningBundle(bundle, { fundingTransactions: [funding] }),
    ).toThrow(EntryMismatchError);
    // A forged funding transaction cannot hash to the real outpoint id.
    const forged = {
      ...funding,
      outputs: funding.outputs.map((o) => ({ ...o, value: 1n * KAS })),
    };
    expect(() =>
      openSigningBundle(bundle, { fundingTransactions: [forged] }),
    ).toThrow(/funding transaction not provided/);
    // The honest case opens, with the proven amounts in force.
    const honest = createSigningBundle(
      createTransaction({
        inputs,
        outputs: [{ value: 200n * KAS - KAS / 100n, scriptPublicKey: DST }],
      }),
      inputs,
    );
    const opened = openSigningBundle(honest, {
      fundingTransactions: [funding],
    });
    expect(opened.inputs.map((p) => p.entry.amount)).toEqual([
      100n * KAS,
      100n * KAS,
    ]);
    expect(entriesFromFundingTransactions(inputs, [funding])).toHaveLength(2);
  });

  it('a bundle cannot be opened without an independent amount source', () => {
    const { inputs } = fundedVault();
    const bundle = createSigningBundle(theftTx(inputs), inputs);
    expect(() => openSigningBundle(bundle)).toThrow(
      /no independent source for the input amounts/,
    );
  });

  it('the co-signer’s fee ceiling applies to the amounts in force', () => {
    const { inputs } = fundedVault();
    const bundle = createSigningBundle(theftTx(inputs), inputs);
    expect(() =>
      openSigningBundle(bundle, {
        trustedEntries: inputs.map((p) => p.entry),
      }),
    ).toThrow(FeeTooHighError);
  });
});

describe('M2: transactions without outputs burn every input as fee', () => {
  const u = fundedVault().inputs.slice(0, 1);
  it('are refused when created', () => {
    expect(() => createTransaction({ inputs: u, outputs: [] })).toThrow(
      /no outputs/,
    );
  });
  it('are refused when signed or opened, however they were built', async () => {
    const good = createTransaction({
      inputs: u,
      outputs: [{ value: 100n * KAS - KAS / 100n, scriptPublicKey: DST }],
    });
    const empty: Transaction = { ...good, outputs: [] };
    await expect(
      signTransaction(empty, u, [victim], { maxFee: 1000n * KAS }),
    ).rejects.toThrow(InvalidTransactionError);
    const bundle = createSigningBundle(good, u);
    const forged = { ...bundle, tx: transactionToJson(empty) };
    expect(() =>
      openSigningBundle(forged, { trustedEntries: u.map((p) => p.entry) }),
    ).toThrow(/no outputs/);
  });
  it('signing enforces a fee ceiling (default 5 KAS) even without a planner', async () => {
    const tx = createTransaction({
      inputs: u,
      outputs: [{ value: 94n * KAS, scriptPublicKey: DST }],
    });
    await expect(signTransaction(tx, u, [victim])).rejects.toThrow(
      FeeTooHighError,
    );
    await expect(
      signTransaction(tx, u, [victim], { maxFee: 6n * KAS }),
    ).resolves.toHaveLength(1);
  });
});

describe('L1: coinbase maturity is 1,000 DAA at 10 blocks per second', () => {
  it('matches rusty-kaspa (BPS 10 × COINBASE_MATURITY_SECONDS 100)', () => {
    expect(COINBASE_MATURITY).toBe(1000n);
  });
  it('a 300-DAA-old coinbase output is not selected', () => {
    const owner = localSigner(rng.secretKey());
    const single: Spend = { kind: 'p2pk', xOnlyPubkey: owner.xOnlyPublicKey };
    const cb: InputPlan = {
      outpoint: { transactionId: rng.bytes(32), index: 0 },
      entry: {
        amount: 50n * KAS,
        scriptPublicKey: spendScriptPublicKey(single),
        blockDaaScore: 10_000n,
        isCoinbase: true,
      },
      spend: single,
    };
    expect(() =>
      planTransaction([cb], [{ scriptPublicKey: DST, amount: KAS }], {
        feeRate: 1n,
        changeSpend: single,
        virtualDaaScore: 10_300n,
      }),
    ).toThrow(KaspaError);
  });
});

describe('L2: change can never be locked to an unspendable script', () => {
  const owner = localSigner(rng.secretKey());
  const single: Spend = { kind: 'p2pk', xOnlyPubkey: owner.xOnlyPublicKey };
  const utxos: InputPlan[] = [
    {
      outpoint: { transactionId: rng.bytes(32), index: 0 },
      entry: {
        amount: 100n * KAS,
        scriptPublicKey: spendScriptPublicKey(single),
        blockDaaScore: 1n,
        isCoinbase: false,
      },
      spend: single,
    },
  ];
  const pay = [{ scriptPublicKey: DST, amount: 10n * KAS }];

  it('refuses a redeem script with no signature check (e.g. OP_RETURN)', () => {
    const redeem = Uint8Array.of(0x6a); // OP_RETURN
    const dead: Spend = {
      kind: 'p2sh-script',
      redeem,
      signerPubkey: owner.xOnlyPublicKey,
    };
    expect(() =>
      planTransaction(utxos, pay, { feeRate: 1n, changeSpend: dead }),
    ).toThrow(KaspaError);
  });

  it('refuses a non-canonical multisig (duplicate keys)', () => {
    const k = owner.xOnlyPublicKey;
    const redeem = new ScriptBuilder()
      .addI64(1n)
      .addData(k)
      .addData(k)
      .addI64(2n)
      .addOp(Op.OpCheckMultiSig)
      .drain();
    const dup: Spend = { kind: 'p2sh-multisig', pubkeys: [k, k], m: 1, redeem };
    expect(spendScriptPublicKey(dup)).toEqual(p2shScript(redeem));
    expect(() =>
      planTransaction(utxos, pay, { feeRate: 1n, changeSpend: dup }),
    ).toThrow(MultisigConfigError);
  });
});

describe('L3: change is kept unless it is worth less than spending it later', () => {
  it('10 KAS from a 10.4 KAS UTXO keeps 0.4 KAS change for a tiny fee', () => {
    const owner = localSigner(rng.secretKey());
    const single: Spend = { kind: 'p2pk', xOnlyPubkey: owner.xOnlyPublicKey };
    const u: InputPlan = {
      outpoint: { transactionId: rng.bytes(32), index: 0 },
      entry: {
        amount: 104n * (KAS / 10n),
        scriptPublicKey: spendScriptPublicKey(single),
        blockDaaScore: 1n,
        isCoinbase: false,
      },
      spend: single,
    };
    const plan = planTransaction(
      [u],
      [{ scriptPublicKey: DST, amount: 10n * KAS }],
      { feeRate: 100n, changeSpend: single },
    );
    expect(plan.final.tx.outputs).toHaveLength(2);
    expect(plan.final.fee).toBeLessThan(KAS / 20n);
  });
});

describe('L4: v1 compute budgets cannot be lowered below what the spend needs', () => {
  it('refuses a bundle whose budget was lowered in transit', () => {
    const { inputs } = fundedVault();
    const tx = createTransaction({
      inputs: inputs.slice(0, 1),
      outputs: [{ value: 100n * KAS - KAS / 100n, scriptPublicKey: DST }],
      version: 1,
    });
    const bundle = createSigningBundle(tx, inputs.slice(0, 1));
    const lowered = {
      ...bundle,
      tx: transactionToJson({
        ...tx,
        inputs: tx.inputs.map((i) => ({ ...i, computeBudget: 0 })),
      }),
    };
    expect(() =>
      openSigningBundle(lowered, {
        trustedEntries: [inputs[0]!.entry],
        policy: { allowVersion1: true },
      }),
    ).toThrow(/compute budget 0 is below/);
  });
});
