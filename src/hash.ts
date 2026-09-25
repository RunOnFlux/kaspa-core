import { blake2b } from '@noble/hashes/blake2.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8 } from './bytes.js';

/**
 * Hash domains from `crypto/hashes/src/hashers.rs`. The algorithm per domain is
 * not guessable and is encoded here once:
 *  - blake2b domains: the domain string is the blake2b MAC **key**.
 *  - blake3 domains:  the domain string **zero-padded to 32 bytes** is the key.
 *  - sha256 domain:   `SHA256(SHA256(domain) ‖ data)` — a hashed prefix.
 */
export const Blake2bDomain = {
  TransactionHash: 'TransactionHash',
  TransactionID: 'TransactionID',
  TransactionSigningHash: 'TransactionSigningHash',
  PersonalMessageSigningHash: 'PersonalMessageSigningHash',
} as const;

export const Blake3Domain = {
  PayloadDigest: 'PayloadDigest',
  TransactionRest: 'TransactionRest',
  TransactionV1Id: 'TransactionV1Id',
} as const;

export const Sha256Domain = {
  TransactionSigningHashECDSA: 'TransactionSigningHashECDSA',
} as const;

export type Blake2bDomainName =
  (typeof Blake2bDomain)[keyof typeof Blake2bDomain];
export type Blake3DomainName = (typeof Blake3Domain)[keyof typeof Blake3Domain];
export type Sha256DomainName = (typeof Sha256Domain)[keyof typeof Sha256Domain];

const blake2bKeys = new Map<string, Uint8Array>();
const blake3Keys = new Map<string, Uint8Array>();
const sha256Prefixes = new Map<string, Uint8Array>();

function blake2bKey(domain: string): Uint8Array {
  let k = blake2bKeys.get(domain);
  if (!k) {
    k = utf8(domain);
    blake2bKeys.set(domain, k);
  }
  return k;
}

function blake3Key(domain: string): Uint8Array {
  let k = blake3Keys.get(domain);
  if (!k) {
    const d = utf8(domain);
    if (d.length > 32) throw new Error('blake3 domain longer than 32 bytes');
    k = new Uint8Array(32);
    k.set(d);
    blake3Keys.set(domain, k);
  }
  return k;
}

/** Unkeyed blake2b-256. Used for the P2SH redeem-script hash and `OP_BLAKE2B`. */
export function blake2b256(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32 });
}

/** blake2b-256 keyed with a Kaspa domain string. */
export function blake2bDomain(
  domain: Blake2bDomainName,
  data: Uint8Array,
): Uint8Array {
  return blake2b(data, { dkLen: 32, key: blake2bKey(domain) });
}

/** blake3-256 keyed with a Kaspa domain string zero-padded to 32 bytes. */
export function blake3Domain(
  domain: Blake3DomainName,
  data: Uint8Array,
): Uint8Array {
  return blake3(data, { dkLen: 32, key: blake3Key(domain) });
}

/** `SHA256(SHA256(domain) ‖ data)`. */
export function sha256Domain(
  domain: Sha256DomainName,
  data: Uint8Array,
): Uint8Array {
  let prefix = sha256Prefixes.get(domain);
  if (!prefix) {
    prefix = sha256(utf8(domain));
    sha256Prefixes.set(domain, prefix);
  }
  return sha256(concatBytes(prefix, data));
}

/** A fresh 32-byte zero hash (fresh so callers can never mutate a shared constant). */
export function zeroHash(): Uint8Array {
  return new Uint8Array(32);
}
