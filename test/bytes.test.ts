import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, utf8, Writer } from '../src/bytes.js';
import { Rng } from './helpers/random.js';

describe('bytes', () => {
  it('utf8 matches TextEncoder, including emoji and lone surrogates', () => {
    const rng = new Rng(77);
    const samples = [
      '',
      'kaspa',
      'žluťoučký kůň',
      '😀🚀',
      '\ud800',
      'a\udc00b',
      'x\ud83dy',
    ];
    for (let i = 0; i < 300; i++) {
      let s = '';
      const n = rng.range(0, 20);
      for (let j = 0; j < n; j++) s += String.fromCharCode(rng.int(0x10000));
      samples.push(s);
    }
    const enc = new TextEncoder();
    for (const s of samples)
      expect(bytesToHex(utf8(s))).toBe(bytesToHex(enc.encode(s)));
  });

  it('hex is strict', () => {
    expect(() => hexToBytes('abc')).toThrow();
    expect(() => hexToBytes('zz')).toThrow();
    expect(bytesToHex(hexToBytes('00FFaa'))).toBe('00ffaa');
  });

  it('writer rejects out-of-range integers instead of truncating', () => {
    expect(() => new Writer().u64(-1n)).toThrow();
    expect(() => new Writer().u64(1n << 64n)).toThrow();
    expect(() => new Writer().u16(65536)).toThrow();
    expect(bytesToHex(new Writer().u64(0x0102030405060708n).finish())).toBe(
      '0807060504030201',
    );
    expect(
      bytesToHex(new Writer().varBytes(Uint8Array.of(0xaa)).finish()),
    ).toBe('0100000000000000aa');
  });
});
