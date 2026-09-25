import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from './bytes.js';
import { invalidInput } from './errors.js';

/**
 * True if `key` is a valid BIP340 x-only public key: 32 bytes whose value is
 * the x-coordinate of a point on secp256k1. Funds locked to anything else are
 * unspendable, so every key that ends up in a script is checked with this.
 */
export function isValidXOnlyPublicKey(key: Uint8Array): boolean {
  if (!(key instanceof Uint8Array) || key.length !== 32) return false;
  try {
    schnorr.utils.lift_x(BigInt(`0x${bytesToHex(key)}`));
    return true;
  } catch {
    return false;
  }
}

/** True if `key` is a valid 33-byte compressed SEC1 public key. */
export function isValidCompressedPublicKey(key: Uint8Array): boolean {
  if (!(key instanceof Uint8Array) || key.length !== 33) return false;
  if (key[0] !== 0x02 && key[0] !== 0x03) return false;
  try {
    secp256k1.Point.fromBytes(key).assertValidity();
    return true;
  } catch {
    return false;
  }
}

export function assertXOnlyPublicKey(
  key: Uint8Array,
  what = 'public key',
): void {
  if (!isValidXOnlyPublicKey(key)) {
    throw invalidInput(`${what} is not a valid x-only secp256k1 key`);
  }
}

/**
 * x-only key from a 33-byte compressed key — how an SSP xpub-derived child key
 * becomes a Kaspa Schnorr key. The parity byte is dropped; BIP340 signing
 * handles odd-y keys internally.
 */
export function xOnlyFromCompressed(compressed: Uint8Array): Uint8Array {
  if (!isValidCompressedPublicKey(compressed)) {
    throw invalidInput('not a valid 33-byte compressed public key');
  }
  return compressed.slice(1, 33);
}
