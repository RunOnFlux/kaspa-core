import { describe, expect, it } from 'vitest';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import {
  isValidCompressedPublicKey,
  isValidXOnlyPublicKey,
  xOnlyFromCompressed,
} from '../src/keys.js';
import { kaspaToSompi, sompiToKaspa } from '../src/units.js';
import { privateKeyFromWif, privateKeyToWif } from '../src/wif.js';
import { validateTransactionStructure } from '../src/tx/validate.js';
import { describeTransaction } from '../src/describe.js';
import { p2pkScript } from '../src/script/standard.js';
import { createTransaction, localSigner, xOnlyPublicKey } from '../src/sign.js';
import { multisigSpend, spendScriptPublicKey } from '../src/spend.js';
import type { InputPlan } from '../src/spend.js';
import { planTransaction } from '../src/plan.js';
import { InvalidTransactionError, KaspaError } from '../src/errors.js';
import type { Transaction } from '../src/tx/model.js';
import { Rng, TEST_XONLY } from './helpers/random.js';

describe('keys', () => {
  it('validates x-only and compressed keys and converts between them', () => {
    const sk = new Uint8Array(32).fill(5);
    const compressed = secp256k1.getPublicKey(sk, true);
    const x = xOnlyFromCompressed(compressed);
    expect(bytesToHex(x)).toBe(bytesToHex(schnorr.getPublicKey(sk)));
    expect(isValidXOnlyPublicKey(x)).toBe(true);
    expect(isValidCompressedPublicKey(compressed)).toBe(true);
    expect(isValidXOnlyPublicKey(new Uint8Array(32))).toBe(false);
    expect(isValidXOnlyPublicKey(new Uint8Array(32).fill(0xff))).toBe(false);
    expect(isValidCompressedPublicKey(Uint8Array.of(0x04, ...x))).toBe(false);
    expect(() => xOnlyFromCompressed(new Uint8Array(33))).toThrow(KaspaError);
  });
});

describe('units', () => {
  it.each([
    ['0', 0n],
    ['1', 100_000_000n],
    ['0.1', 10_000_000n],
    ['0.00000001', 1n],
    ['123.45678901', 12_345_678_901n],
    ['28999999999', 2_899_999_999_900_000_000n],
  ])('kaspaToSompi(%s)', (s, v) => {
    expect(kaspaToSompi(s)).toBe(v);
    expect(kaspaToSompi(sompiToKaspa(v))).toBe(v);
  });
  it.each([
    '',
    '-1',
    '1e8',
    '0.000000001',
    '1,000',
    ' 1',
    '.5',
    '1.',
    '29000000001',
  ])('rejects %j', (s) => {
    expect(() => kaspaToSompi(s)).toThrow(KaspaError);
  });
  it('formats without trailing zeros', () => {
    expect(sompiToKaspa(150_000_000n)).toBe('1.5');
    expect(sompiToKaspa(1n)).toBe('0.00000001');
    expect(sompiToKaspa(0n)).toBe('0');
  });
});

describe('WIF (replaces @kaspa/core-lib in ZelCore)', () => {
  // ZelCore test vectors: packages/addresses/__tests__/families/kaspa.test.ts
  it.each([
    [
      'L4bbW6TaWGxdHY1HvmEPzBrgLE8jm8FQgmi5pB1kTzvBJpm5qDWR',
      'dc1ec19756d3b63aeb752ead612087858d1bdc1cf24287dd4f2ab32f6cfe1905',
    ],
    [
      'Ky38semtWa1NPQGGJKcMYXJGF9MhxWsSmEqEvD6PXC5eW8RwFaUc',
      '363c269151c5be140dcdf65ddfb18cc0d967bf2b68972905b5c4888a9b112f27',
    ],
    [
      'L2n65GVindJEWbXFUai32JzKSJFom1S1Hn9PkMsvKQHQrHQNz7H9',
      'a5d7d8a1bb1fa7b849734ea151c1b19511864e7fcdac3ef59911cc83145ccda3',
    ],
  ])('decodes %s', (wif, pk) => {
    const d = privateKeyFromWif(wif, 0x80);
    expect(bytesToHex(d.privateKey)).toBe(pk);
    expect(d.compressed).toBe(true);
    expect(privateKeyToWif(hexToBytes(pk))).toBe(wif);
  });
  it('rejects a bad checksum, wrong network and garbage', () => {
    const good = 'L4bbW6TaWGxdHY1HvmEPzBrgLE8jm8FQgmi5pB1kTzvBJpm5qDWR';
    expect(() => privateKeyFromWif(good.slice(0, -1) + 'S')).toThrow(
      /checksum/,
    );
    expect(() => privateKeyFromWif(good, 0xef)).toThrow(/network/);
    expect(() => privateKeyFromWif('not-a-wif')).toThrow(KaspaError);
  });
});

describe('validateTransactionStructure', () => {
  const rng = new Rng(55);
  const spend = { kind: 'p2pk' as const, xOnlyPubkey: TEST_XONLY };
  const base = (): Transaction =>
    createTransaction({
      inputs: [
        {
          outpoint: { transactionId: rng.bytes(32), index: 0 },
          entry: {
            amount: 10n ** 9n,
            scriptPublicKey: p2pkScript(TEST_XONLY),
            blockDaaScore: 1n,
            isCoinbase: false,
          },
          spend,
        },
      ],
      outputs: [{ value: 1n, scriptPublicKey: p2pkScript(TEST_XONLY) }],
    });
  it.each<[string, (t: Transaction) => void]>([
    ['unknown version', (t) => (t.version = 2)],
    ['no inputs', (t) => (t.inputs = [])],
    [
      'short txid',
      (t) => (t.inputs[0]!.previousOutpoint.transactionId = new Uint8Array(31)),
    ],
    ['sigops overflow', (t) => (t.inputs[0]!.sigOpCount = 256)],
    ['compute budget in v0', (t) => (t.inputs[0]!.computeBudget = 1)],
    ['zero output', (t) => (t.outputs[0]!.value = 0n)],
    [
      'covenant in v0',
      (t) =>
        (t.outputs[0]!.covenant = {
          authorizingInput: 0,
          covenantId: new Uint8Array(32),
        }),
    ],
    [
      'lane in v0',
      (t) =>
        (t.subnetworkId = Uint8Array.of(
          0x97,
          0xb1,
          ...new Array<number>(18).fill(0),
        )),
    ],
    ['gas on native', (t) => (t.gas = 1n)],
    [
      'huge spk',
      (t) =>
        (t.outputs[0]!.scriptPublicKey = {
          version: 0,
          script: new Uint8Array(10_001),
        }),
    ],
  ])('rejects %s', (_name, mutate) => {
    const t = base();
    mutate(t);
    expect(() => validateTransactionStructure(t)).toThrow(
      InvalidTransactionError,
    );
  });
  it('accepts a v1 lane transaction', () => {
    const t = base();
    t.version = 1;
    t.inputs[0]!.sigOpCount = 0;
    t.inputs[0]!.computeBudget = 10;
    t.subnetworkId = Uint8Array.of(
      0x97,
      0xb1,
      0,
      0,
      ...new Array<number>(16).fill(0),
    );
    t.gas = 5n;
    expect(() => validateTransactionStructure(t)).not.toThrow();
  });
});

describe('describeTransaction (co-signer approval screen)', () => {
  const rng = new Rng(77);
  const a = localSigner(rng.secretKey());
  const b = localSigner(rng.secretKey());
  const vault = multisigSpend([a.xOnlyPublicKey, b.xOnlyPublicKey], 2);
  const own = spendScriptPublicKey(vault);
  const utxos: InputPlan[] = [
    {
      outpoint: { transactionId: rng.bytes(32), index: 1 },
      entry: {
        amount: 100n * 100_000_000n,
        scriptPublicKey: own,
        blockDaaScore: 1n,
        isCoinbase: false,
      },
      spend: vault,
    },
  ];
  it('separates what leaves the wallet from change and prices the signed size', () => {
    const plan = planTransaction(
      utxos,
      [{ scriptPublicKey: p2pkScript(TEST_XONLY), amount: 10n * 100_000_000n }],
      {
        feeRate: 100n,
        changeSpend: vault,
      },
    );
    const d = describeTransaction(plan.final.tx, plan.final.inputs, {
      prefix: 'kaspa',
      ownScripts: [own],
    });
    expect(d.sent).toBe(10n * 100_000_000n);
    expect(d.fee).toBe(plan.final.fee);
    expect(d.feeRate).toBe(100n);
    expect(d.outputs.find((o) => o.isOwn)?.address?.startsWith('kaspa:p')).toBe(
      true,
    );
    expect(d.warnings).toEqual([]);
    expect(d.id).toBe(bytesToHex(plan.final.id));
  });
  it('flags foreign inputs, payloads and high fees', () => {
    const tx = createTransaction({
      inputs: utxos,
      outputs: [
        {
          value: 90n * 100_000_000n,
          scriptPublicKey: p2pkScript(
            xOnlyPublicKey(new Uint8Array(32).fill(3)),
          ),
        },
      ],
      payload: Uint8Array.of(1),
    });
    const d = describeTransaction(tx, utxos, {
      prefix: 'kaspa',
      ownScripts: [p2pkScript(TEST_XONLY)],
    });
    expect(d.warnings).toEqual(
      expect.arrayContaining([
        'foreign-input',
        'payload',
        'fee-above-threshold',
      ]),
    );
  });
});
