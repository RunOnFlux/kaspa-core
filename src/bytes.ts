import { invalidInput } from './errors.js';

export const U64_MAX = (1n << 64n) - 1n;

const HEX_RE = /^(?:[0-9a-f]{2})*$/;

/** Strict lowercase-or-uppercase hex to bytes. Rejects odd length and non-hex. */
export function hexToBytes(hex: string): Uint8Array {
  const h = hex.toLowerCase();
  if (!HEX_RE.test(h)) throw invalidInput('invalid hex string');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Lexicographic byte comparison; shorter prefix sorts first. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * UTF-8 encode without relying on `TextEncoder` (absent on older Hermes).
 * Lone surrogates encode as U+FFFD, matching `TextEncoder`.
 */
export function utf8(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      } else c = 0xfffd;
    } else if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c < 0x10000)
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    else
      out.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 0x3f),
        0x80 | ((c >> 6) & 0x3f),
        0x80 | (c & 0x3f),
      );
  }
  return Uint8Array.from(out);
}

export function assertLength(b: Uint8Array, len: number, what: string): void {
  if (!(b instanceof Uint8Array) || b.length !== len) {
    throw invalidInput(`${what} must be ${len} bytes`);
  }
}

export function assertU64(v: bigint, what: string): void {
  if (typeof v !== 'bigint' || v < 0n || v > U64_MAX)
    throw invalidInput(`${what} must be a u64`);
}

/**
 * Growable little-endian writer matching rusty-kaspa's `HasherBase` helpers.
 * `varBytes` writes a **u64 LE length prefix** — not a Bitcoin varint.
 */
export class Writer {
  private buf: Uint8Array;
  private len = 0;

  constructor(capacity = 256) {
    this.buf = new Uint8Array(capacity);
  }

  private ensure(n: number): void {
    if (this.len + n <= this.buf.length) return;
    let cap = this.buf.length * 2;
    while (cap < this.len + n) cap *= 2;
    const next = new Uint8Array(cap);
    next.set(this.buf.subarray(0, this.len));
    this.buf = next;
  }

  u8(v: number): this {
    this.ensure(1);
    this.buf[this.len++] = v & 0xff;
    return this;
  }

  u16(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xffff)
      throw invalidInput('u16 out of range');
    this.ensure(2);
    this.buf[this.len++] = v & 0xff;
    this.buf[this.len++] = (v >>> 8) & 0xff;
    return this;
  }

  u32(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff)
      throw invalidInput('u32 out of range');
    this.ensure(4);
    for (let i = 0; i < 4; i++) this.buf[this.len++] = (v >>> (8 * i)) & 0xff;
    return this;
  }

  u64(v: bigint): this {
    assertU64(v, 'u64 field');
    this.ensure(8);
    let x = v;
    for (let i = 0; i < 8; i++) {
      this.buf[this.len++] = Number(x & 0xffn);
      x >>= 8n;
    }
    return this;
  }

  bool(b: boolean): this {
    return this.u8(b ? 1 : 0);
  }

  bytes(b: Uint8Array): this {
    this.ensure(b.length);
    this.buf.set(b, this.len);
    this.len += b.length;
    return this;
  }

  /** u64 LE length followed by the bytes (`write_var_bytes`). */
  varBytes(b: Uint8Array): this {
    return this.u64(BigInt(b.length)).bytes(b);
  }

  finish(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}
