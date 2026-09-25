import { describe, expect, it } from 'vitest';
import { p2pkScript } from '../src/script/standard.js';
import { localSigner } from '../src/sign.js';
import { multisigSpend, spendScriptPublicKey } from '../src/spend.js';
import type { InputPlan, Spend } from '../src/spend.js';
import { planConsolidation, planTransaction } from '../src/plan.js';
import type { PlannedTransaction } from '../src/plan.js';
import { computeMass, minimumRelayFee } from '../src/mass.js';
import {
  ChangeWouldBeDustError,
  InsufficientFundsError,
  KaspaError,
  NeedsConsolidationError,
} from '../src/errors.js';
import {
  MAXIMUM_STANDARD_TRANSACTION_MASS,
  SOMPI_PER_KASPA,
} from '../src/constants.js';
import { Rng, TEST_XONLY } from './helpers/random.js';

const KAS = SOMPI_PER_KASPA;
const rng0 = new Rng(500);
const A = localSigner(rng0.secretKey());
const B = localSigner(rng0.secretKey());
const VAULT = multisigSpend([A.xOnlyPublicKey, B.xOnlyPublicKey], 2);
const SINGLE: Spend = { kind: 'p2pk', xOnlyPubkey: A.xOnlyPublicKey };
const DST = p2pkScript(TEST_XONLY);

function utxo(
  rng: Rng,
  spend: Spend,
  amount: bigint,
  extra: Partial<InputPlan['entry']> = {},
): InputPlan {
  return {
    outpoint: { transactionId: rng.bytes(32), index: rng.range(0, 3) },
    entry: {
      amount,
      scriptPublicKey: spendScriptPublicKey(spend),
      blockDaaScore: 1000n,
      isCoinbase: false,
      ...extra,
    },
    spend,
  };
}

function assertInvariants(
  p: PlannedTransaction,
  maxMass = MAXIMUM_STANDARD_TRANSACTION_MASS,
): void {
  const totalIn = p.inputs.reduce((a, x) => a + x.entry.amount, 0n);
  const totalOut = p.tx.outputs.reduce((a, o) => a + o.value, 0n);
  expect(totalIn).toBe(totalOut + p.fee);
  expect(p.mass.max <= maxMass).toBe(true);
  expect(p.tx.outputs.every((o) => o.value > 0n)).toBe(true);
  expect(p.fee >= p.mass.compute * 100n || p.fee >= minimumRelayFee(p.tx)).toBe(
    true,
  );
}

describe('planTransaction', () => {
  it('pays with a change output when change is comfortably large', () => {
    const rng = new Rng(1);
    const plan = planTransaction(
      [utxo(rng, VAULT, 100n * KAS)],
      [{ scriptPublicKey: DST, amount: 10n * KAS }],
      {
        feeRate: 1n,
        changeSpend: VAULT,
      },
    );
    expect(plan.stages).toHaveLength(0);
    const f = plan.final;
    assertInvariants(f);
    expect(f.tx.outputs).toHaveLength(2);
    expect(f.changeIndex).toBe(1);
    expect(f.tx.inputs[0]!.sigOpCount).toBe(2);
  });

  it('matches the reference 2-of-2 figures: 454 bytes, 3,194 grams', () => {
    const rng = new Rng(2);
    const plan = planTransaction(
      [utxo(rng, VAULT, 100n * KAS)],
      [{ scriptPublicKey: p2shLike(), amount: 10n * KAS }],
      {
        feeRate: 100n,
        changeSpend: VAULT,
      },
    );
    expect(plan.final.mass.size).toBe(454n);
    expect(plan.final.mass.compute).toBe(3194n);
    expect(plan.final.fee).toBe(319_400n);
  });

  it('folds small change into the fee instead of creating a KIP-9-expensive output', () => {
    const rng = new Rng(3);
    const plan = planTransaction(
      [utxo(rng, SINGLE, 100n * KAS)],
      [{ scriptPublicKey: DST, amount: 99n * KAS + 90_000_000n }],
      {
        feeRate: 1n,
        changeSpend: SINGLE,
      },
    );
    assertInvariants(plan.final);
    expect(plan.final.tx.outputs).toHaveLength(1);
    expect(plan.final.fee).toBe(10_000_000n);
  });

  it('refuses to burn more than maxFoldToFee', () => {
    const rng = new Rng(4);
    expect(() =>
      planTransaction(
        [utxo(rng, SINGLE, 100n * KAS)],
        [{ scriptPublicKey: DST, amount: 98n * KAS }],
        {
          feeRate: 1n,
          changeSpend: SINGLE,
          changeFoldThreshold: 5n * KAS,
          maxFoldToFee: KAS,
        },
      ),
    ).toThrow(ChangeWouldBeDustError);
  });

  it('reports the shortfall when funds are insufficient', () => {
    const rng = new Rng(5);
    try {
      planTransaction(
        [utxo(rng, SINGLE, 1n * KAS)],
        [{ scriptPublicKey: DST, amount: 2n * KAS }],
        { feeRate: 1n, changeSpend: SINGLE },
      );
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(InsufficientFundsError);
      expect((e as InsufficientFundsError).shortfall > KAS).toBe(true);
    }
  });

  it('sendAll spends everything to one output', () => {
    const rng = new Rng(6);
    const utxos = [utxo(rng, SINGLE, 3n * KAS), utxo(rng, SINGLE, 5n * KAS)];
    const plan = planTransaction(
      utxos,
      [{ scriptPublicKey: DST, amount: 0n }],
      { feeRate: 1n, changeSpend: SINGLE, sendAll: true },
    );
    assertInvariants(plan.final);
    expect(plan.final.tx.outputs).toHaveLength(1);
    expect(plan.final.tx.outputs[0]!.value).toBe(8n * KAS - plan.final.fee);
  });

  it('skips immature coinbase outputs and all coinbase outputs when the DAA score is unknown', () => {
    const rng = new Rng(7);
    const cb = utxo(rng, SINGLE, 50n * KAS, {
      isCoinbase: true,
      blockDaaScore: 1000n,
    });
    const normal = utxo(rng, SINGLE, 1n * KAS);
    const recipients = [{ scriptPublicKey: DST, amount: 10n * KAS }];
    expect(() =>
      planTransaction([cb, normal], recipients, {
        feeRate: 1n,
        changeSpend: SINGLE,
      }),
    ).toThrow(InsufficientFundsError);
    expect(() =>
      planTransaction([cb, normal], recipients, {
        feeRate: 1n,
        changeSpend: SINGLE,
        virtualDaaScore: 1999n,
      }),
    ).toThrow(InsufficientFundsError);
    const ok = planTransaction([cb, normal], recipients, {
      feeRate: 1n,
      changeSpend: SINGLE,
      virtualDaaScore: 2000n,
    });
    assertInvariants(ok.final);
  });

  it('never selects excluded outpoints', () => {
    const rng = new Rng(8);
    const a = utxo(rng, SINGLE, 100n * KAS);
    const b = utxo(rng, SINGLE, 20n * KAS);
    const plan = planTransaction(
      [a, b],
      [{ scriptPublicKey: DST, amount: 5n * KAS }],
      {
        feeRate: 1n,
        changeSpend: SINGLE,
        exclude: [a.outpoint],
      },
    );
    expect(plan.final.inputs).toEqual([b]);
  });

  it('builds a compounding chain when one transaction cannot fit, and refuses without allowChain', () => {
    const rng = new Rng(9);
    const utxos = Array.from({ length: 100 }, () => utxo(rng, VAULT, KAS));
    const recipients = [{ scriptPublicKey: DST, amount: 90n * KAS }];
    const plan = planTransaction(utxos, recipients, {
      feeRate: 1n,
      changeSpend: VAULT,
    });
    expect(plan.stages.length).toBeGreaterThan(0);
    for (const s of [...plan.stages, plan.final]) assertInvariants(s);
    expect(plan.totalFee).toBe(
      plan.stages.reduce((a, s) => a + s.fee, 0n) + plan.final.fee,
    );
    // Later stages spend earlier stage outputs by their (pre-signing) id.
    const ids = new Set(
      plan.stages.map((s) => Buffer.from(s.id).toString('hex')),
    );
    expect(
      plan.final.inputs.some((i) =>
        ids.has(Buffer.from(i.outpoint.transactionId).toString('hex')),
      ),
    ).toBe(true);
    expect(() =>
      planTransaction(utxos, recipients, {
        feeRate: 1n,
        changeSpend: VAULT,
        allowChain: false,
      }),
    ).toThrow(NeedsConsolidationError);
  });

  it('rejects a spend descriptor that does not unlock its UTXO', () => {
    const rng = new Rng(10);
    const bad = { ...utxo(rng, SINGLE, KAS), spend: VAULT };
    expect(() =>
      planTransaction([bad], [{ scriptPublicKey: DST, amount: 1n }], {
        feeRate: 1n,
        changeSpend: SINGLE,
      }),
    ).toThrow(KaspaError);
  });

  it('property: every plan conserves value, clears the relay floor and respects the cap', () => {
    const rng = new Rng(11);
    let planned = 0;
    for (let t = 0; t < 150; t++) {
      const spend = rng.bool() ? VAULT : SINGLE;
      const n = rng.range(1, 60);
      const utxos = Array.from({ length: n }, () =>
        utxo(rng, spend, BigInt(rng.range(1, 20_000)) * 1_000_000n),
      );
      const total = utxos.reduce((a, u) => a + u.entry.amount, 0n);
      const amount = (total * BigInt(rng.range(1, 99))) / 100n + 1n;
      try {
        const plan = planTransaction(
          utxos,
          [{ scriptPublicKey: DST, amount }],
          {
            feeRate: BigInt(rng.range(1, 300)),
            changeSpend: spend,
          },
        );
        for (const s of [...plan.stages, plan.final]) assertInvariants(s);
        expect(plan.final.tx.outputs[0]!.value).toBe(amount);
        planned++;
      } catch (e) {
        expect(e).toBeInstanceOf(KaspaError);
      }
    }
    expect(planned).toBeGreaterThan(100);
  });
});

describe('planConsolidation', () => {
  it('sweeps many small UTXOs into mass-capped batches without losing value', () => {
    const rng = new Rng(12);
    const utxos = Array.from({ length: 200 }, () =>
      utxo(rng, VAULT, BigInt(rng.range(1, 50)) * 10_000_000n),
    );
    const batches = planConsolidation(utxos, {
      feeRate: 1n,
      changeSpend: VAULT,
    });
    expect(batches.length).toBeGreaterThan(3);
    let fees = 0n;
    let out = 0n;
    for (const b of batches) {
      assertInvariants(b);
      expect(b.tx.outputs).toHaveLength(1);
      // 43 two-of-two inputs fit with two outputs; a one-output sweep fits 44.
      expect(b.tx.inputs.length).toBeLessThanOrEqual(44);
      fees += b.fee;
      out += b.tx.outputs[0]!.value;
    }
    const swept = batches.reduce(
      (a, b) => a + b.inputs.reduce((x, i) => x + i.entry.amount, 0n),
      0n,
    );
    expect(swept).toBe(out + fees);
  });
});

function p2shLike() {
  return spendScriptPublicKey(VAULT);
}

describe('reference mass table (plan §7)', () => {
  it.each([
    ['P2PK', 1, 66, 2036n],
    ['2-of-2', 2, 202, 3194n],
    ['2-of-3', 3, 236, 4228n],
    ['3-of-5', 5, 368, 6360n],
    ['15-of-15', 15, 1491, 17483n],
  ] as const)(
    '%s 1-in/2-out compute mass',
    (_label, sigOps, sigScript, expected) => {
      const spk =
        sigOps === 1 ? p2pkScript(TEST_XONLY) : spendScriptPublicKey(VAULT);
      const tx = {
        version: 0,
        inputs: [
          {
            previousOutpoint: { transactionId: new Uint8Array(32), index: 0 },
            signatureScript: new Uint8Array(sigScript),
            sequence: 0n,
            sigOpCount: sigOps,
          },
        ],
        outputs: [
          { value: 1n, scriptPublicKey: spk },
          { value: 1n, scriptPublicKey: spk },
        ],
        lockTime: 0n,
        subnetworkId: new Uint8Array(20),
        gas: 0n,
        payload: new Uint8Array(0),
      };
      expect(computeMass(tx)).toBe(expected);
    },
  );
});
