import { describe, expect, it } from 'vitest';
import { bytesToHex } from '../src/bytes.js';
import { p2pkScript, multisigRedeemScript } from '../src/script/standard.js';
import {
  assembleTransaction,
  createSigningBundle,
  createTransaction,
  finalizeTransaction,
  localSigner,
  openSigningBundle,
  signMessage,
  signTransaction,
  verifyMessage,
} from '../src/sign.js';
import type { KaspaSigner } from '../src/sign.js';
import { multisigSpend, spendScriptPublicKey } from '../src/spend.js';
import type { InputPlan, Spend } from '../src/spend.js';
import {
  IncompleteSignaturesError,
  InvalidTransactionError,
  KaspaError,
  MultisigConfigError,
  SignatureError,
} from '../src/errors.js';
import { Rng, TEST_XONLY, xonly } from './helpers/random.js';

const rng0 = new Rng(900);
const A = localSigner(rng0.secretKey());
const B = localSigner(rng0.secretKey());
const C = localSigner(rng0.secretKey());
const VAULT = multisigSpend(
  [A.xOnlyPublicKey, B.xOnlyPublicKey, C.xOnlyPublicKey],
  2,
);

function setup(spend: Spend = VAULT) {
  const inputs: InputPlan[] = [
    {
      outpoint: { transactionId: rng0.bytes(32), index: 0 },
      entry: {
        amount: 10n ** 10n,
        scriptPublicKey: spendScriptPublicKey(spend),
        blockDaaScore: 1n,
        isCoinbase: false,
      },
      spend,
    },
  ];
  const tx = createTransaction({
    inputs,
    outputs: [
      {
        value: 10n ** 10n - 1_000_000n,
        scriptPublicKey: p2pkScript(TEST_XONLY),
      },
    ],
  });
  return { inputs, tx };
}

describe('multisig configuration guards', () => {
  const k = () => xonly(rng0);
  it('rejects m > n, m < 1, empty, duplicates, wrong key size and non-standard n', () => {
    expect(() => multisigRedeemScript([k(), k()], 3)).toThrow(
      MultisigConfigError,
    );
    expect(() => multisigRedeemScript([k()], 0)).toThrow(MultisigConfigError);
    expect(() => multisigRedeemScript([], 1)).toThrow(MultisigConfigError);
    const dup = k();
    expect(() => multisigRedeemScript([dup, dup], 1)).toThrow(/duplicate/);
    expect(() => multisigRedeemScript([new Uint8Array(33)], 1)).toThrow(
      MultisigConfigError,
    );
    expect(() =>
      multisigRedeemScript(Array.from({ length: 16 }, k), 2),
    ).toThrow(/non-standard/);
    expect(() =>
      multisigRedeemScript(Array.from({ length: 16 }, k), 2, {
        allowNonStandard: true,
      }),
    ).not.toThrow();
    expect(() =>
      multisigRedeemScript(Array.from({ length: 21 }, k), 2, {
        allowNonStandard: true,
      }),
    ).toThrow(MultisigConfigError);
  });

  it('sorting makes the script independent of key order (two devices agree)', () => {
    const keys = [k(), k(), k()];
    expect(bytesToHex(multisigRedeemScript(keys, 2))).toBe(
      bytesToHex(multisigRedeemScript([...keys].reverse(), 2)),
    );
  });
});

describe('signing guards', () => {
  it('only entitled signers sign, and a stranger produces nothing', async () => {
    const { tx, inputs } = setup();
    const stranger = localSigner(rng0.secretKey());
    expect(await signTransaction(tx, inputs, [stranger])).toHaveLength(0);
    expect(await signTransaction(tx, inputs, [A, stranger])).toHaveLength(1);
  });

  it('a signer that returns a bad signature is caught before it leaves the device', async () => {
    const { tx, inputs } = setup();
    const broken: KaspaSigner = {
      xOnlyPublicKey: A.xOnlyPublicKey,
      signDigest: () => new Uint8Array(64),
    };
    await expect(signTransaction(tx, inputs, [broken])).rejects.toThrow(
      SignatureError,
    );
  });

  it('finalize rejects a tampered partial rather than dropping it', async () => {
    const { tx, inputs } = setup();
    const partials = await signTransaction(tx, inputs, [A, B]);
    const bad = partials.map((p, i) =>
      i === 0
        ? {
            ...p,
            signature: p.signature.replace(
              /^../,
              p.signature.startsWith('00') ? '01' : '00',
            ),
          }
        : p,
    );
    expect(() => finalizeTransaction(tx, inputs, bad)).toThrow(SignatureError);
  });

  it('reports missing signatures and refuses to finalize an incomplete transaction', async () => {
    const { tx, inputs } = setup();
    const one = await signTransaction(tx, inputs, [C]);
    const r = assembleTransaction(tx, inputs, one);
    expect(r.missing).toEqual([{ inputIndex: 0, have: 1, need: 2 }]);
    expect(() => finalizeTransaction(tx, inputs, one)).toThrow(
      IncompleteSignaturesError,
    );
  });

  it('uses exactly m signatures even when more arrive', async () => {
    const { tx, inputs } = setup();
    const all = await signTransaction(tx, inputs, [A, B, C]);
    const signed = finalizeTransaction(tx, inputs, all);
    // 2 pushes of 66 bytes + OpPushData1 ‖ len ‖ 102-byte 2-of-3 redeem script.
    expect(signed.inputs[0]!.signatureScript.length).toBe(
      2 * 66 + 2 + (3 + 3 * 33),
    );
  });

  it('refuses a transaction whose sigOpCount disagrees with its spend', async () => {
    const { tx, inputs } = setup();
    tx.inputs[0]!.sigOpCount = 1;
    await expect(signTransaction(tx, inputs, [A])).rejects.toThrow(
      InvalidTransactionError,
    );
  });

  it('refuses a descriptor whose keys disagree with its redeem script', () => {
    if (VAULT.kind !== 'p2sh-multisig') throw new Error('unreachable');
    const lying: Spend = { ...VAULT, pubkeys: [...VAULT.pubkeys].reverse() };
    expect(() => setup(lying)).toThrow(KaspaError);
  });

  it('signing bundles reject unknown formats', () => {
    const { tx, inputs } = setup();
    const b = createSigningBundle(tx, inputs);
    expect(() => openSigningBundle({ ...b, version: 2 as 1 })).toThrow(
      KaspaError,
    );
    expect(
      openSigningBundle(JSON.parse(JSON.stringify(b)), {
        trustedEntries: inputs.map((p) => p.entry),
      }).inputs,
    ).toHaveLength(1);
  });
});

describe('personal messages', () => {
  it('sign/verify round-trips and tampering fails', async () => {
    const sig = await signMessage('Hello Kaspa', A);
    expect(verifyMessage('Hello Kaspa', sig, A.xOnlyPublicKey)).toBe(true);
    expect(verifyMessage('Hello Kaspa!', sig, A.xOnlyPublicKey)).toBe(false);
    expect(verifyMessage('Hello Kaspa', sig, B.xOnlyPublicKey)).toBe(false);
  });
});

describe('JSON forms round-trip every spend kind', () => {
  it('p2pk, p2sh-multisig and p2sh-script survive a relay hop; unknown kinds are refused', async () => {
    const { spendFromJson, spendToJson } = await import('../src/tx/json.js');
    const redeem = new Uint8Array([0x20, ...A.xOnlyPublicKey, 0xac]);
    const spends = [
      { kind: 'p2pk' as const, xOnlyPubkey: A.xOnlyPublicKey },
      VAULT,
      { kind: 'p2sh-script' as const, redeem, signerPubkey: A.xOnlyPublicKey },
    ];
    for (const sp of spends)
      expect(
        spendFromJson(JSON.parse(JSON.stringify(spendToJson(sp)))),
      ).toEqual(sp);
    expect(() => spendFromJson({ kind: 'nope' } as never)).toThrow(KaspaError);
    expect(() =>
      spendFromJson({ kind: 'p2pk', xOnlyPubkey: 'zz' } as never),
    ).toThrow(KaspaError);
  });
});
