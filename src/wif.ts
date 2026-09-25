import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { concatBytes, equalBytes } from './bytes.js';
import { invalidInput } from './errors.js';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const INDEX = new Map<string, number>();
for (let i = 0; i < ALPHABET.length; i++) INDEX.set(ALPHABET.charAt(i), i);

function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (let i = 0; i < s.length; i++) {
    const v = INDEX.get(s.charAt(i));
    if (v === undefined) throw invalidInput('invalid base58 character');
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  for (let i = 0; i < s.length && s.charAt(i) === '1'; i++) bytes.push(0);
  return Uint8Array.from(bytes.reverse());
}

function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    out = ALPHABET.charAt(Number(n % 58n)) + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = `1${out}`;
  }
  return out;
}

function checksum(payload: Uint8Array): Uint8Array {
  return sha256(sha256(payload)).slice(0, 4);
}

export interface DecodedWif {
  privateKey: Uint8Array;
  compressed: boolean;
  /** 0x80 mainnet (ZelCore's Kaspa keys), 0xef testnet. */
  version: number;
}

/**
 * Decode a WIF-encoded private key (base58check). ZelCore stores Kaspa keys
 * this way; this replaces the `@kaspa/core-lib` dependency it used only for
 * WIF parsing. The checksum and the key range are both verified.
 */
export function privateKeyFromWif(
  wif: string,
  expectedVersion?: number,
): DecodedWif {
  if (typeof wif !== 'string' || wif.length < 50 || wif.length > 53) {
    throw invalidInput('not a WIF private key');
  }
  const raw = base58Decode(wif);
  if (raw.length !== 37 && raw.length !== 38)
    throw invalidInput('not a WIF private key');
  const payload = raw.slice(0, raw.length - 4);
  if (!equalBytes(checksum(payload), raw.slice(raw.length - 4)))
    throw invalidInput('WIF checksum mismatch');
  const version = payload[0] ?? 0;
  if (expectedVersion !== undefined && version !== expectedVersion)
    throw invalidInput('WIF network version mismatch');
  const compressed = payload.length === 34;
  if (compressed && payload[33] !== 0x01)
    throw invalidInput('WIF compression flag invalid');
  const privateKey = payload.slice(1, 33);
  try {
    schnorr.getPublicKey(privateKey);
  } catch {
    throw invalidInput('WIF private key out of range');
  }
  return { privateKey, compressed, version };
}

/** Encode a 32-byte private key as compressed WIF (default version 0x80). */
export function privateKeyToWif(
  privateKey: Uint8Array,
  version = 0x80,
): string {
  if (privateKey.length !== 32)
    throw invalidInput('private key must be 32 bytes');
  const payload = concatBytes(
    Uint8Array.of(version),
    privateKey,
    Uint8Array.of(0x01),
  );
  return base58Encode(concatBytes(payload, checksum(payload)));
}
