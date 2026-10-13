/**
 * Helpers shared by the REST and wRPC clients: lossless JSON, strict number
 * decoding and one UTXO normaliser, so both transports validate identically.
 * Everything a server returns is untrusted.
 */
import { addressToScriptPublicKey } from '../address.js';
import type { NetworkPrefix } from '../address.js';
import { equalBytes, hexToBytes, U64_MAX } from '../bytes.js';
import { MAX_SOMPI } from '../constants.js';
import { KaspaError } from '../errors.js';
import type { Outpoint, ScriptPublicKey, UtxoEntry } from '../tx/model.js';

/** Runtime globals, typed locally so the package needs neither DOM nor Node types. */
export interface RuntimeGlobals {
  setTimeout: (fn: () => void, ms: number) => unknown;
  clearTimeout: (id: unknown) => void;
}
export const runtime = globalThis as unknown as RuntimeGlobals;

/**
 * Parse JSON keeping integers of 16+ digits as strings, so balances and
 * amounts above 2^53 sompi (~90M KAS) never lose precision.
 */
export function parseJsonSafe(text: string): unknown {
  // Walk the text once, tracking whether we are inside a string literal, and
  // quote only bare integer literals of 16+ digits. A regex cannot tell
  // `"memo": "1234567890123456,"` (inside a string) from a real number.
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text.charAt(i);
    if (c === '"') {
      let j = i + 1;
      while (j < n) {
        const d = text.charAt(j);
        if (d === '\\') j += 2;
        else if (d === '"') break;
        else j += 1;
      }
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i + 1;
      while (j < n && /[0-9.eE+-]/.test(text.charAt(j))) j += 1;
      const lit = text.slice(i, j);
      out += /^-?\d{16,}$/.test(lit) ? `"${lit}"` : lit;
      i = j;
    } else {
      out += c;
      i += 1;
    }
  }
  return JSON.parse(out);
}

/** A u64 from a JSON number (safe range) or a digit string (from `parseJsonSafe`). */
export function toBigInt(
  v: unknown,
  what: string,
  source: 'REST' | 'RPC' = 'RPC',
): bigint {
  let r: bigint | undefined;
  if (typeof v === 'bigint') r = v;
  else if (typeof v === 'string' && /^\d{1,20}$/.test(v)) r = BigInt(v);
  else if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0)
    r = BigInt(v);
  if (r === undefined || r < 0n || r > U64_MAX)
    throw new KaspaError(source, `unexpected ${what} in response`);
  return r;
}

let stringifyCounter = 0;

/**
 * JSON with bigint values emitted as bare integer literals (never strings).
 * Only u64 bigints are accepted. The placeholder marker is unique per call
 * and checked against keys and string values, so input can never collide
 * with it.
 */
export function stringifyWithBigInt(value: unknown): string {
  stringifyCounter = (stringifyCounter + 1) % 0x7fffffff;
  const marker = `__kaspa_u64_${String(stringifyCounter)}_${Math.random().toString(36).slice(2)}__`;
  // Read the raw value from the holder: when something (e.g. @alephium/web3)
  // installs BigInt.prototype.toJSON, JSON.stringify calls it before the
  // replacer and `v` arrives as a string, so u64 fields would go out quoted.
  const s = JSON.stringify(
    value,
    function (this: Record<string, unknown>, k: string, v: unknown) {
      const raw = this[k];
      if (k.includes(marker) || (typeof v === 'string' && v.includes(marker)))
        throw new KaspaError(
          'INVALID_INPUT',
          'input collides with the bigint marker',
        );
      const n = typeof raw === 'bigint' ? raw : v;
      if (typeof n !== 'bigint') return v;
      if (n < 0n || n > U64_MAX)
        throw new KaspaError('INVALID_INPUT', 'bigint outside the u64 range');
      return `${marker}${n.toString()}`;
    },
  );
  return s.replace(new RegExp(`"${marker}(\\d+)"`, 'g'), '$1');
}

export interface KaspaUtxo {
  address: string;
  outpoint: Outpoint;
  entry: UtxoEntry;
}

export interface RawUtxo {
  address: unknown;
  transactionId: unknown;
  index: unknown;
  amount: unknown;
  scriptPublicKey: ScriptPublicKey | undefined;
  blockDaaScore: unknown;
  isCoinbase: unknown;
  /** Hex, or null/undefined for an ordinary UTXO. */
  covenantId?: unknown;
}

/**
 * Validate one UTXO from a server. The script must be the one the reported
 * address encodes, and the address must be one we asked about — a node
 * cannot attribute foreign coins to our addresses.
 */
export function normalizeUtxo(
  raw: RawUtxo,
  requested: ReadonlySet<string>,
  prefix: NetworkPrefix | undefined,
  source: 'REST' | 'RPC',
): KaspaUtxo {
  const fail = (what: string) =>
    new KaspaError(source, `malformed UTXO in response: ${what}`);
  const { transactionId: txid, index, scriptPublicKey: spk } = raw;
  if (typeof txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txid))
    throw fail('transaction id');
  if (
    typeof index !== 'number' ||
    !Number.isInteger(index) ||
    index < 0 ||
    index > 0xffffffff
  )
    throw fail('index');
  if (!spk) throw fail('script');
  const amount = toBigInt(raw.amount, 'amount', source);
  if (amount === 0n || amount > MAX_SOMPI) throw fail('amount');
  if (typeof raw.address !== 'string' || !requested.has(raw.address))
    throw fail('address was not requested');
  const expected = addressToScriptPublicKey(raw.address, prefix);
  if (
    expected.version !== spk.version ||
    !equalBytes(expected.script, spk.script)
  )
    throw fail('script does not match its address');
  const entry: UtxoEntry = {
    amount,
    scriptPublicKey: spk,
    blockDaaScore: toBigInt(raw.blockDaaScore, 'blockDaaScore', source),
    isCoinbase: raw.isCoinbase === true,
  };
  if (raw.covenantId !== undefined && raw.covenantId !== null) {
    if (
      typeof raw.covenantId !== 'string' ||
      !/^[0-9a-fA-F]{64}$/.test(raw.covenantId)
    )
      throw fail('covenant id');
    entry.covenantId = hexToBytes(raw.covenantId.toLowerCase());
  }
  return {
    address: raw.address,
    outpoint: { transactionId: hexToBytes(txid.toLowerCase()), index },
    entry,
  };
}

/** Normalise a list, dropping exact duplicate outpoints (a duplicate would build an invalid tx). */
export function normalizeUtxos(
  raws: readonly RawUtxo[],
  requested: readonly string[],
  prefix: NetworkPrefix | undefined,
  source: 'REST' | 'RPC',
): KaspaUtxo[] {
  const req = new Set(requested);
  const seen = new Set<string>();
  const out: KaspaUtxo[] = [];
  for (const r of raws) {
    const u = normalizeUtxo(r, req, prefix, source);
    const key = `${String(r.transactionId).toLowerCase()}:${String(u.outpoint.index)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(u);
  }
  return out;
}
