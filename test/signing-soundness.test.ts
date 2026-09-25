/**
 * Signature soundness: signing must never leak a private key, and a signature
 * must never be usable to spend anything other than exactly what was approved.
 */
import { schnorr } from '@noble/curves/secp256k1.js';
import { describe, expect, it } from 'vitest';
import { bytesToHex } from '../src/bytes.js';
import { SIG_HASH_ALL } from '../src/constants.js';
import { KaspaError, SignatureError } from '../src/errors.js';
import { p2pkScript } from '../src/script/standard.js';
import { SighashContext } from '../src/sighash.js';
import {
  createTransaction,
  finalizeTransaction,
  localSigner,
  signMessage,
  signTransaction,
  verifyMessage,
  verifyPartialSignature,
  xOnlyPublicKey,
} from '../src/sign.js';
import type { KaspaSigner, PartialSignature } from '../src/sign.js';
import { multisigSpend, spendScriptPublicKey } from '../src/spend.js';
import type { InputPlan, Spend } from '../src/spend.js';
import { privateKeyFromWif, privateKeyToWif } from '../src/wif.js';
import { Rng, TEST_XONLY } from './helpers/random.js';

const CURVE_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const rng = new Rng(4242);
const KEY_A = rng.secretKey();
const KEY_B = rng.secretKey();
const A = localSigner(KEY_A);
const B = localSigner(KEY_B);
const VAULT = multisigSpend([A.xOnlyPublicKey, B.xOnlyPublicKey], 2);

function input(spend: Spend, amount = 10n ** 10n): InputPlan {
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

function setup() {
  const inputs = [input(VAULT), input(VAULT, 5n * 10n ** 9n)];
  const tx = createTransaction({
    inputs,
    outputs: [
      {
        value: 15n * 10n ** 9n - 1_000_000n,
        scriptPublicKey: p2pkScript(TEST_XONLY),
      },
    ],
  });
  return { inputs, tx };
}

const rOf = (sig: Uint8Array) => bytesToHex(sig.subarray(0, 32));

describe('nonces are never reused (a reused nonce reveals the key)', () => {
  it('random auxiliary data: every signature has a distinct R, even over the same digest', () => {
    const seen = new Set<string>();
    const digest = rng.bytes(32);
    for (let i = 0; i < 200; i++) {
      const d = i % 2 === 0 ? digest : rng.bytes(32);
      const sig = A.signDigest(d) as Uint8Array;
      expect(schnorr.verify(sig, d, A.xOnlyPublicKey)).toBe(true);
      seen.add(rOf(sig));
    }
    expect(seen.size).toBe(200);
  });

  it('deterministic mode: the same digest gives the identical signature, different digests never share R', () => {
    const det = localSigner(KEY_A, { deterministic: true });
    const digest = rng.bytes(32);
    const first = det.signDigest(digest) as Uint8Array;
    expect(bytesToHex(det.signDigest(digest) as Uint8Array)).toBe(
      bytesToHex(first),
    );
    const seen = new Set<string>([rOf(first)]);
    for (let i = 0; i < 200; i++)
      seen.add(rOf(det.signDigest(rng.bytes(32)) as Uint8Array));
    expect(seen.size).toBe(201);
  });

  it('two keys signing the same digest with zero aux never share R', () => {
    const digest = rng.bytes(32);
    const a = localSigner(KEY_A, { deterministic: true }).signDigest(digest);
    const b = localSigner(KEY_B, { deterministic: true }).signDigest(digest);
    expect(rOf(a as Uint8Array)).not.toBe(rOf(b as Uint8Array));
  });

  it('every input of a transaction gets a fresh nonce', async () => {
    const { tx, inputs } = setup();
    const partials = await signTransaction(tx, inputs, [A, B]);
    expect(partials).toHaveLength(4);
    const rs = new Set(partials.map((p) => p.signature.slice(0, 64)));
    expect(rs.size).toBe(4);
  });
});

describe('the private key is never exposed', () => {
  const keyHex = bytesToHex(KEY_A);

  it('the signer object carries no key material and cannot be tampered with', () => {
    expect(Object.keys(A).sort()).toEqual([
      'destroy',
      'selfVerifying',
      'signDigest',
      'xOnlyPublicKey',
    ]);
    expect(JSON.stringify(A)).not.toContain(keyHex);
    expect(Object.isFrozen(A)).toBe(true);
    expect(() => {
      (A as { signDigest: unknown }).signDigest = () => new Uint8Array(64);
    }).toThrow(TypeError);
  });

  it('copies the key: wiping the caller buffer neither breaks nor changes the signer', () => {
    const key = Uint8Array.from(KEY_B);
    const s = localSigner(key);
    key.fill(0);
    const d = rng.bytes(32);
    expect(
      schnorr.verify(s.signDigest(d) as Uint8Array, d, B.xOnlyPublicKey),
    ).toBe(true);
  });

  it('invalid keys fail with a clean error that never echoes the input', () => {
    const bad = [
      new Uint8Array(32),
      hexBytes(CURVE_ORDER),
      hexBytes(CURVE_ORDER + 5n),
      new Uint8Array(32).fill(0xff),
    ];
    for (const k of bad) {
      for (const f of [() => localSigner(k), () => xOnlyPublicKey(k)]) {
        let err: unknown;
        try {
          f();
        } catch (e) {
          err = e;
        }
        expect(err).toBeInstanceOf(KaspaError);
        const text = `${(err as Error).message}${(err as Error).stack ?? ''}`;
        expect(text).not.toContain(bytesToHex(k));
      }
    }
    expect(() => localSigner(KEY_A.subarray(0, 31))).toThrow(/32-byte/);
  });

  it('WIF errors never echo the key or payload', () => {
    const wif = privateKeyToWif(KEY_A);
    const corrupt = wif.slice(0, -1) + (wif.endsWith('1') ? '2' : '1');
    let msg = '';
    try {
      privateKeyFromWif(corrupt);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/checksum|WIF/);
    expect(msg).not.toContain(keyHex);
  });

  it('destroy() wipes the key and stops the signer', () => {
    const s = localSigner(Uint8Array.from(KEY_B));
    s.destroy();
    expect(() => s.signDigest(new Uint8Array(32))).toThrow(/destroyed/);
  });

  it('the digest signer only signs 32-byte digests', () => {
    expect(() => A.signDigest(new Uint8Array(31))).toThrow(KaspaError);
    expect(() => A.signDigest(new Uint8Array(64))).toThrow(KaspaError);
  });
});

describe('domain separation', () => {
  it('a personal-message signature can never authorise a transaction input', async () => {
    const { tx, inputs } = setup();
    const digest = new SighashContext(
      tx,
      inputs.map((p) => p.entry),
    ).schnorr(0, SIG_HASH_ALL);
    // A dapp asks the wallet to "sign this message" whose bytes are a sighash.
    const sig = await signMessage(digest, A);
    expect(verifyMessage(digest, sig, A.xOnlyPublicKey)).toBe(true);
    expect(schnorr.verify(sig, digest, A.xOnlyPublicKey)).toBe(false);
    const forged: PartialSignature = {
      inputIndex: 0,
      publicKey: bytesToHex(A.xOnlyPublicKey),
      signature: bytesToHex(sig),
      sighashType: SIG_HASH_ALL,
    };
    expect(verifyPartialSignature(tx, inputs, forged)).toBe(false);
  });
});

describe('a signature authorises exactly one input of exactly one transaction', () => {
  it('fails if the amount, the script, the outputs or the input index change', async () => {
    const { tx, inputs } = setup();
    const [p] = await signTransaction(tx, inputs, [A]);
    if (!p) throw new Error('no partial');
    expect(verifyPartialSignature(tx, inputs, p)).toBe(true);

    const cheaper = inputs.map((q, i) =>
      i === 0
        ? { ...q, entry: { ...q.entry, amount: q.entry.amount - 1n } }
        : q,
    );
    expect(verifyPartialSignature(tx, cheaper, p)).toBe(false);

    const otherVault = multisigSpend([A.xOnlyPublicKey, TEST_XONLY], 1);
    const moved = inputs.map((q, i) =>
      i === 0
        ? {
            ...q,
            spend: otherVault,
            entry: {
              ...q.entry,
              scriptPublicKey: spendScriptPublicKey(otherVault),
            },
          }
        : q,
    );
    expect(verifyPartialSignature(tx, moved, p)).toBe(false);

    const redirected = {
      ...tx,
      outputs: [
        {
          value: tx.outputs[0]!.value,
          scriptPublicKey: p2pkScript(B.xOnlyPublicKey),
        },
      ],
    };
    expect(verifyPartialSignature(redirected, inputs, p)).toBe(false);

    const bigger = {
      ...tx,
      outputs: [{ ...tx.outputs[0]!, value: tx.outputs[0]!.value - 1n }],
    };
    expect(verifyPartialSignature(bigger, inputs, p)).toBe(false);

    expect(verifyPartialSignature(tx, inputs, { ...p, inputIndex: 1 })).toBe(
      false,
    );
  });
});

describe('faulty or malicious signers cannot produce a broken spend', () => {
  const bogus = (produce: (d: Uint8Array) => unknown, claimVerified = false) =>
    ({
      xOnlyPublicKey: A.xOnlyPublicKey,
      signDigest: produce,
      selfVerifying: claimVerified,
    }) as unknown as KaspaSigner;

  it.each([
    [
      'bit-flipped signature',
      (d: Uint8Array) => {
        const s = Uint8Array.from(A.signDigest(d) as Uint8Array);
        s[40] = (s[40] ?? 0) ^ 1;
        return s;
      },
    ],
    ['another key’s signature', (d: Uint8Array) => B.signDigest(d)],
    [
      'signature over another digest',
      () => A.signDigest(new Uint8Array(32).fill(7)),
    ],
    ['short output', () => new Uint8Array(63)],
    ['non-bytes output', () => 'deadbeef'],
  ])(
    'rejects a %s — even when the signer claims to self-verify',
    async (_n, produce) => {
      const { tx, inputs } = setup();
      for (const claim of [false, true]) {
        await expect(
          signTransaction(tx, inputs, [bogus(produce, claim)]),
        ).rejects.toThrow(SignatureError);
      }
    },
  );

  it('finalize refuses to assemble a transaction from a tampered partial', async () => {
    const { tx, inputs } = setup();
    const partials = await signTransaction(tx, inputs, [A, B]);
    const tampered = partials.map((p, i) =>
      i === 0 ? { ...p, signature: flipLastHex(p.signature) } : p,
    );
    expect(() => finalizeTransaction(tx, inputs, tampered)).toThrow(KaspaError);
    expect(() => finalizeTransaction(tx, inputs, partials)).not.toThrow();
  });

  it('message signing rejects a malformed signer output cleanly', async () => {
    await expect(
      signMessage(
        'hi',
        bogus(() => 'nope'),
      ),
    ).rejects.toThrow(SignatureError);
    await expect(
      signMessage(
        'hi',
        bogus(() => new Uint8Array(64)),
      ),
    ).rejects.toThrow(SignatureError);
  });
});

function hexBytes(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0').slice(-64);
  return Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
}

function flipLastHex(hex: string): string {
  const last = hex.slice(-1);
  return hex.slice(0, -1) + (last === '0' ? '1' : '0');
}
