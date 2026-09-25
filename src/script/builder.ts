import { MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPTS_SIZE } from '../constants.js';
import { InvalidScriptError } from '../errors.js';
import {
  Op,
  OP_1_NEGATE_VAL,
  OP_DATA_MAX_VAL,
  OP_SMALL_INT_MAX_VAL,
  OP_SMALL_INT_MIN_VAL,
} from './opcodes.js';

/**
 * Minimal little-endian sign-magnitude script number (`serialize_i64`).
 * 0 encodes as the empty vector.
 */
export function serializeScriptNum(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array(0);
  const negative = value < 0n;
  let abs = negative ? -value : value;
  const out: number[] = [];
  while (abs > 0n) {
    out.push(Number(abs & 0xffn));
    abs >>= 8n;
  }
  const last = out[out.length - 1] ?? 0;
  if (last & 0x80) {
    out.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    out[out.length - 1] = last | 0x80;
  }
  return Uint8Array.from(out);
}

/** Byte length `addData` would emit for `data`, push opcode included. */
export function canonicalDataSize(data: Uint8Array): number {
  const n = data.length;
  if (n === 0) return 1;
  if (n === 1) {
    const b = data[0] ?? 0;
    if (
      (b >= OP_SMALL_INT_MIN_VAL && b <= OP_SMALL_INT_MAX_VAL) ||
      b === OP_1_NEGATE_VAL
    )
      return 1;
  }
  return n + pushPrefixLength(n);
}

/** Length of the push opcode (plus explicit length bytes) for an `n`-byte push. */
export function pushPrefixLength(n: number): number {
  if (n <= OP_DATA_MAX_VAL) return 1;
  if (n <= 0xff) return 2;
  if (n <= 0xffff) return 3;
  return 5;
}

/**
 * Canonical script builder matching `crypto/txscript/src/script_builder.rs`.
 * `addData` collapses empty data to OP_0, single bytes 1..16 to OP_1..OP_16
 * and 0x81 to OP_1NEGATE — easy to miss, and it matters for arbitrary pushes.
 */
export class ScriptBuilder {
  private parts: number[] = [];

  get length(): number {
    return this.parts.length;
  }

  addOp(op: number): this {
    if (!Number.isInteger(op) || op < 0 || op > 0xff)
      throw new InvalidScriptError('bad opcode');
    this.guard(1);
    this.parts.push(op);
    return this;
  }

  addOps(ops: readonly number[]): this {
    for (const op of ops) this.addOp(op);
    return this;
  }

  addData(data: Uint8Array): this {
    if (data.length > MAX_SCRIPT_ELEMENT_SIZE)
      throw new InvalidScriptError('data push too large');
    this.guard(canonicalDataSize(data));
    const n = data.length;
    if (n === 1) {
      const b = data[0] ?? 0;
      if (b === OP_1_NEGATE_VAL) {
        this.parts.push(Op.Op1Negate);
        return this;
      }
      if (b >= OP_SMALL_INT_MIN_VAL && b <= OP_SMALL_INT_MAX_VAL) {
        this.parts.push(Op.Op1 - 1 + b);
        return this;
      }
    }
    return this.pushWithDataOpcode(data);
  }

  addI64(value: bigint): this {
    if (value === 0n) return this.addOp(Op.Op0);
    if (value === -1n) return this.addOp(Op.Op1Negate);
    if (value >= 1n && value <= 16n)
      return this.addOp(Op.Op1 - 1 + Number(value));
    return this.addData(serializeScriptNum(value));
  }

  drain(): Uint8Array {
    const out = Uint8Array.from(this.parts);
    this.parts = [];
    return out;
  }

  private pushWithDataOpcode(data: Uint8Array): this {
    const n = data.length;
    if (n === 0) {
      this.parts.push(Op.Op0);
      return this;
    }
    if (n <= OP_DATA_MAX_VAL) {
      this.parts.push(n);
    } else if (n <= 0xff) {
      this.parts.push(Op.OpPushData1, n);
    } else if (n <= 0xffff) {
      this.parts.push(Op.OpPushData2, n & 0xff, (n >>> 8) & 0xff);
    } else {
      this.parts.push(
        Op.OpPushData4,
        n & 0xff,
        (n >>> 8) & 0xff,
        (n >>> 16) & 0xff,
        (n >>> 24) & 0xff,
      );
    }
    for (const b of data) this.parts.push(b);
    return this;
  }

  private guard(add: number): void {
    if (this.parts.length + add > MAX_SCRIPTS_SIZE)
      throw new InvalidScriptError('script too large');
  }
}
