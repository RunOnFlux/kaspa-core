import { InvalidAddressError } from './errors.js';
import {
  p2pkEcdsaScript,
  p2pkScript,
  p2shScriptFromHash,
  classifyScript,
} from './script/standard.js';
import type { ScriptPublicKey } from './tx/model.js';

/**
 * Kaspa address codec — `crypto/addresses/src/bech32.rs`.
 * CashAddr-style base32 with a 40-bit polymod checksum over the 5-bit prefix,
 * a zero separator, the 5-bit payload and eight zero groups.
 */

export type NetworkPrefix = 'kaspa' | 'kaspatest' | 'kaspasim' | 'kaspadev';
export const NETWORK_PREFIXES: readonly NetworkPrefix[] = [
  'kaspa',
  'kaspatest',
  'kaspasim',
  'kaspadev',
];

export const AddressVersion = {
  /** 32-byte x-only Schnorr public key. `kaspa:q…` */
  PubKey: 0,
  /** 33-byte compressed ECDSA public key. */
  PubKeyECDSA: 1,
  /** 32-byte blake2b-256 hash of a redeem script. `kaspa:p…` */
  ScriptHash: 8,
} as const;
export type AddressVersion =
  (typeof AddressVersion)[keyof typeof AddressVersion];

const PAYLOAD_LENGTH: Record<AddressVersion, number> = { 0: 32, 1: 33, 8: 32 };

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const REV_CHARSET = new Map<string, number>();
for (let i = 0; i < CHARSET.length; i++) REV_CHARSET.set(CHARSET.charAt(i), i);

const GENERATORS = [
  0x98f2bc8e61n,
  0x79b76d99e2n,
  0xf33e5fb3c4n,
  0xae2eabe2a8n,
  0x1e4f43e470n,
];

function polymod(values: Iterable<number>): bigint {
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i++) {
      if ((c0 >> BigInt(i)) & 1n) c ^= GENERATORS[i] ?? 0n;
    }
  }
  return c ^ 1n;
}

function checksum(payload5: readonly number[], prefix: string): bigint {
  // Prefixes are ASCII (validated against NETWORK_PREFIXES), so code units are characters.
  const prefix5: number[] = [];
  for (let i = 0; i < prefix.length; i++)
    prefix5.push(prefix.charCodeAt(i) & 0x1f);
  return polymod([...prefix5, 0, ...payload5, 0, 0, 0, 0, 0, 0, 0, 0]);
}

/** 8-bit to 5-bit groups with right padding (`conv8to5`). */
function conv8to5(payload: Uint8Array): number[] {
  const out: number[] = [];
  let buff = 0;
  let bits = 0;
  for (const c of payload) {
    buff = ((buff << 8) | c) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((buff >> bits) & 0x1f);
      buff &= (1 << bits) - 1;
    }
  }
  if (bits > 0) out.push((buff << (5 - bits)) & 0x1f);
  return out;
}

/** 5-bit groups to bytes, discarding right padding (`conv5to8`). */
function conv5to8(payload: readonly number[]): Uint8Array {
  const out: number[] = [];
  let buff = 0;
  let bits = 0;
  for (const c of payload) {
    buff = ((buff << 5) | c) & 0xffff;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((buff >> bits) & 0xff);
      buff &= (1 << bits) - 1;
    }
  }
  return Uint8Array.from(out);
}

function isPrefix(p: string): p is NetworkPrefix {
  return (NETWORK_PREFIXES as readonly string[]).includes(p);
}

function isVersion(v: number): v is AddressVersion {
  return v === 0 || v === 1 || v === 8;
}

export function encodeAddress(
  prefix: NetworkPrefix,
  version: AddressVersion,
  payload: Uint8Array,
): string {
  if (!isPrefix(prefix))
    throw new InvalidAddressError(`unknown prefix ${String(prefix)}`);
  if (!isVersion(version))
    throw new InvalidAddressError(`unknown version ${String(version)}`);
  if (payload.length !== PAYLOAD_LENGTH[version]) {
    throw new InvalidAddressError(
      `version ${version} requires a ${PAYLOAD_LENGTH[version]}-byte payload`,
    );
  }
  const payload8 = new Uint8Array(payload.length + 1);
  payload8[0] = version;
  payload8.set(payload, 1);
  const payload5 = conv8to5(payload8);
  const cs = checksum(payload5, prefix);
  const csBytes = new Uint8Array(5);
  for (let i = 0; i < 5; i++)
    csBytes[4 - i] = Number((cs >> BigInt(8 * i)) & 0xffn);
  const body = [...payload5, ...conv8to5(csBytes)]
    .map((d) => CHARSET[d] ?? '')
    .join('');
  return `${prefix}:${body}`;
}

export interface DecodedAddress {
  prefix: NetworkPrefix;
  version: AddressVersion;
  payload: Uint8Array;
}

export function decodeAddress(address: string): DecodedAddress {
  if (typeof address !== 'string')
    throw new InvalidAddressError('address must be a string');
  const sep = address.indexOf(':');
  if (sep < 0)
    throw new InvalidAddressError('address is missing its network prefix');
  const prefix = address.slice(0, sep);
  const body = address.slice(sep + 1);
  if (!isPrefix(prefix))
    throw new InvalidAddressError(`unknown prefix ${prefix}`);
  if (body.length < 8)
    throw new InvalidAddressError('address payload too short');
  const body5: number[] = [];
  for (const ch of body) {
    const v = REV_CHARSET.get(ch);
    if (v === undefined)
      throw new InvalidAddressError(`invalid character '${ch}'`);
    body5.push(v);
  }
  const payload5 = body5.slice(0, body5.length - 8);
  const cs5 = body5.slice(body5.length - 8);
  const csBytes = conv5to8(cs5);
  if (csBytes.length !== 5) throw new InvalidAddressError('bad checksum size');
  let cs = 0n;
  for (const b of csBytes) cs = (cs << 8n) | BigInt(b);
  if (checksum(payload5, prefix) !== cs)
    throw new InvalidAddressError('bad checksum');
  const payload8 = conv5to8(payload5);
  const version = payload8[0];
  if (version === undefined || !isVersion(version)) {
    throw new InvalidAddressError(`unknown address version ${String(version)}`);
  }
  const payload = payload8.slice(1);
  if (payload.length !== PAYLOAD_LENGTH[version]) {
    throw new InvalidAddressError(`bad payload length for version ${version}`);
  }
  // rusty-kaspa ignores padding bits, so several strings can decode to the same
  // payload. Accept only the canonical encoding so two strings never name one
  // address (and allow-lists/change detection can't be confused).
  if (encodeAddress(prefix, version, payload) !== address) {
    throw new InvalidAddressError('non-canonical address encoding');
  }
  return { prefix, version, payload };
}

export function isValidAddress(
  address: string,
  prefix?: NetworkPrefix,
): boolean {
  try {
    const d = decodeAddress(address);
    return prefix === undefined || d.prefix === prefix;
  } catch {
    return false;
  }
}

/**
 * The locking script an address pays to (`pay_to_address_script`).
 * Pass `expectedPrefix` wherever a user typed the address: a `kaspatest:`
 * address pasted into a mainnet wallet is then an error, not a payment.
 */
export function addressToScriptPublicKey(
  address: string,
  expectedPrefix?: NetworkPrefix,
): ScriptPublicKey {
  const { prefix, version, payload } = decodeAddress(address);
  if (expectedPrefix !== undefined && prefix !== expectedPrefix) {
    throw new InvalidAddressError(
      `expected a ${expectedPrefix}: address, got ${prefix}:`,
    );
  }
  switch (version) {
    case AddressVersion.PubKey:
      return p2pkScript(payload);
    case AddressVersion.PubKeyECDSA:
      return p2pkEcdsaScript(payload);
    case AddressVersion.ScriptHash:
      return p2shScriptFromHash(payload);
  }
}

/** The address for a standard locking script, or `null` if it is non-standard. */
export function scriptPublicKeyToAddress(
  spk: ScriptPublicKey,
  prefix: NetworkPrefix,
): string | null {
  const s = spk.script;
  switch (classifyScript(spk)) {
    case 'p2pk':
      return encodeAddress(prefix, AddressVersion.PubKey, s.slice(1, 33));
    case 'p2pk-ecdsa':
      return encodeAddress(prefix, AddressVersion.PubKeyECDSA, s.slice(1, 34));
    case 'p2sh':
      return encodeAddress(prefix, AddressVersion.ScriptHash, s.slice(2, 34));
    case 'nonstandard':
      return null;
  }
}
