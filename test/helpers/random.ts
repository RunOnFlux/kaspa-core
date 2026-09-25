import { schnorr } from '@noble/curves/secp256k1.js';
import { p2shScript } from '../../src/script/standard.js';
import type {
  ScriptPublicKey,
  Transaction,
  TransactionOutput,
  UtxoEntry,
} from '../../src/tx/model.js';

/** Seeded PRNG (mulberry32) so every failure is reproducible from its seed. */
export class Rng {
  private s: number;
  constructor(seed: number) {
    this.s = seed >>> 0;
  }
  u32(): number {
    this.s = (this.s + 0x6d2b79f5) >>> 0;
    let t = this.s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  }
  int(maxExclusive: number): number {
    return this.u32() % maxExclusive;
  }
  range(min: number, maxInclusive: number): number {
    return min + this.int(maxInclusive - min + 1);
  }
  bool(p = 0.5): boolean {
    return this.u32() / 0x100000000 < p;
  }
  bytes(n: number): Uint8Array {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = this.u32() & 0xff;
    return b;
  }
  u64(): bigint {
    return (BigInt(this.u32()) << 32n) | BigInt(this.u32());
  }
  pick<T>(xs: readonly T[]): T {
    return xs[this.int(xs.length)] as T;
  }
  /** Amounts across the regimes that matter for storage mass. */
  amount(): bigint {
    switch (this.int(6)) {
      case 0:
        return BigInt(this.range(1, 1000));
      case 1:
        return BigInt(this.range(1, 1_000_000));
      case 2:
        return (
          BigInt(this.range(1, 99)) * 1_000_000n +
          BigInt(this.range(0, 999_999))
        );
      case 3:
        return BigInt(this.range(1, 100_000)) * 100_000_000n;
      case 4:
        return BigInt(this.range(1, 0x7fffffff)) * BigInt(this.range(1, 1000));
      default:
        return (this.u64() % 2_900_000_000_000_000_000n) + 1n;
    }
  }
  secretKey(): Uint8Array {
    for (;;) {
      const k = this.bytes(32);
      try {
        schnorr.getPublicKey(k);
        return k;
      } catch {
        /* out of range, retry */
      }
    }
  }
}

/** A valid x-only public key. */
export function xonly(rng: Rng): Uint8Array {
  return schnorr.getPublicKey(rng.secretKey());
}

/** A fixed valid x-only key for tests that just need "some recipient". */
export const TEST_XONLY: Uint8Array = schnorr.getPublicKey(
  new Uint8Array(32).fill(7),
);

export function randomSpk(rng: Rng): ScriptPublicKey {
  switch (rng.int(4)) {
    case 0: {
      // Raw P2PK shape with arbitrary key bytes: consensus encoding does not
      // care whether the key is a curve point, so the differential covers it.
      const script = new Uint8Array(34);
      script[0] = 0x20;
      script.set(rng.bytes(32), 1);
      script[33] = 0xac;
      return { version: 0, script };
    }
    case 1:
      return p2shScript(rng.bytes(rng.range(1, 200)));
    case 2:
      return { version: 0, script: rng.bytes(rng.range(0, 120)) };
    default:
      return { version: rng.range(0, 3), script: rng.bytes(rng.range(0, 40)) };
  }
}

export interface RandomTxOptions {
  version?: 0 | 1;
  minInputs?: number;
  maxInputs?: number;
  maxOutputs?: number;
}

export function randomTransaction(
  rng: Rng,
  opts: RandomTxOptions = {},
): { tx: Transaction; entries: UtxoEntry[] } {
  const version = opts.version ?? (rng.bool(0.7) ? 0 : 1);
  const nIn = rng.range(opts.minInputs ?? 1, opts.maxInputs ?? 6);
  const nOut = rng.range(1, opts.maxOutputs ?? 6);
  const v1 = version === 1;
  const lane = v1 && rng.bool(0.4);
  const subnetworkId = new Uint8Array(20);
  if (lane) subnetworkId.set(rng.bytes(4));
  const outputs: TransactionOutput[] = [];
  for (let i = 0; i < nOut; i++) {
    const o: TransactionOutput = {
      value: rng.amount(),
      scriptPublicKey: randomSpk(rng),
    };
    if (v1 && rng.bool(0.3))
      o.covenant = {
        authorizingInput: rng.range(0, 0xffff),
        covenantId: rng.bytes(32),
      };
    outputs.push(o);
  }
  const tx: Transaction = {
    version,
    inputs: Array.from({ length: nIn }, () => ({
      previousOutpoint: { transactionId: rng.bytes(32), index: rng.u32() },
      signatureScript: rng.bool(0.3)
        ? new Uint8Array(0)
        : rng.bytes(rng.range(0, 300)),
      sequence: rng.bool(0.5) ? 0n : rng.u64(),
      sigOpCount: v1 ? 0 : rng.range(0, 255),
      ...(v1 ? { computeBudget: rng.range(0, 0xffff) } : {}),
    })),
    outputs,
    lockTime: rng.bool(0.6) ? 0n : rng.u64(),
    subnetworkId,
    gas: lane && rng.bool(0.5) ? rng.u64() : 0n,
    payload: rng.bool(0.5) ? new Uint8Array(0) : rng.bytes(rng.range(1, 400)),
  };
  const entries: UtxoEntry[] = Array.from({ length: nIn }, () => {
    const e: UtxoEntry = {
      amount: rng.amount(),
      scriptPublicKey: randomSpk(rng),
      blockDaaScore: rng.u64(),
      isCoinbase: rng.bool(0.1),
    };
    if (v1 && rng.bool(0.2)) e.covenantId = rng.bytes(32);
    return e;
  });
  return { tx, entries };
}
