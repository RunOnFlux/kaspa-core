/**
 * Igra L2 bridge entries (KAS → iKAS), as ZelCore implements them.
 *
 * An entry is a version 1 transaction on the Igra lane subnetwork that pays
 * the bridge amount to the Igra lock script and carries a 33-byte payload:
 *
 *   0x92 ‖ L2 address (20 B) ‖ amount (u64 LE) ‖ nonce (u32 LE)
 *
 * The nonce is ground until the transaction ID starts with `97b1`. Plan the
 * entry with `planIgraEntry`, mine with `mineIgraEntry`, and only then sign:
 * the signature commits to the payload.
 */
import { bytesToHex, equalBytes, hexToBytes } from '../bytes.js';
import { MAX_SOMPI, TX_VERSION_TOCCATA } from '../constants.js';
import { invalidInput, KaspaError } from '../errors.js';
import { blake3Domain } from '../hash.js';
import { planTransaction } from '../plan.js';
import type { Plan, PlanOptions, PlannedTransaction } from '../plan.js';
import type { InputPlan } from '../spend.js';
import {
  encodeTransaction,
  payloadDigest,
  transactionId,
  TxEncodingFlags,
} from '../tx/encode.js';
import type { ScriptPublicKey, Transaction } from '../tx/model.js';

export const IGRA_ENTRY_TX_PREFIX = 0x92;
/** Igra lane subnetwork: 4-byte namespace `97b10000` followed by zeros. */
export const IGRA_SUBNETWORK_ID: Uint8Array = hexToBytes(
  '97b1000000000000000000000000000000000000',
);
/** Mainnet Igra lock script (P2SH). */
export const IGRA_MAINNET_LOCK_SCRIPT: ScriptPublicKey = {
  version: 0,
  script: hexToBytes(
    'aa205933185b78c71f0833770ca4aa6b62423af00d0efc2832025a23999543f220f787',
  ),
};
/** Minimum entry amount (10 KAS). */
export const IGRA_MIN_ENTRY_AMOUNT = 1_000_000_000n;
/** Required transaction-ID prefix. */
export const IGRA_TX_ID_PREFIX: Uint8Array = Uint8Array.of(0x97, 0xb1);
export const IGRA_ENTRY_PAYLOAD_SIZE = 33;

const L2_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function l2AddressBytes(l2Address: string): Uint8Array {
  if (typeof l2Address !== 'string' || !L2_ADDRESS.test(l2Address))
    throw invalidInput('Igra L2 address must be 0x followed by 40 hex digits');
  const bytes = hexToBytes(l2Address.slice(2).toLowerCase());
  if (bytes.every((b) => b === 0))
    throw invalidInput('Igra L2 address must not be the zero address');
  return bytes;
}

function checkAmount(amount: bigint): void {
  if (typeof amount !== 'bigint' || amount < IGRA_MIN_ENTRY_AMOUNT)
    throw invalidInput('Igra entry amount is below the 10 KAS minimum');
  if (amount > MAX_SOMPI) throw invalidInput('Igra entry amount too large');
}

/** The 33-byte entry payload. */
export function igraEntryPayload(
  l2Address: string,
  amount: bigint,
  nonce: number,
): Uint8Array {
  const addr = l2AddressBytes(l2Address);
  checkAmount(amount);
  if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff)
    throw invalidInput('Igra nonce must be a u32');
  const p = new Uint8Array(IGRA_ENTRY_PAYLOAD_SIZE);
  p[0] = IGRA_ENTRY_TX_PREFIX;
  p.set(addr, 1);
  let a = amount;
  for (let i = 0; i < 8; i++) {
    p[21 + i] = Number(a & 0xffn);
    a >>= 8n;
  }
  let n = nonce;
  for (let i = 0; i < 4; i++) {
    p[29 + i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return p;
}

export interface IgraEntry {
  /** Igra L2 (EVM) recipient, 0x-prefixed. */
  l2Address: string;
  /** Sompi locked on L1 and credited on L2 (≥ 10 KAS). */
  amount: bigint;
  /** Lock script; defaults to mainnet. */
  lockScript?: ScriptPublicKey;
}

/**
 * Plan an entry: a version 1 Igra-lane transaction paying `amount` to the
 * lock script with a placeholder payload of the final size, so mass and fee
 * are exact before mining. Consolidation stages (if any) are plain v0.
 */
export function planIgraEntry(
  utxos: readonly InputPlan[],
  entry: IgraEntry,
  opts: Omit<
    PlanOptions,
    'txVersion' | 'subnetworkId' | 'payload' | 'gas' | 'sendAll'
  >,
): Plan {
  return planTransaction(
    utxos,
    [
      {
        scriptPublicKey: entry.lockScript ?? IGRA_MAINNET_LOCK_SCRIPT,
        amount: entry.amount,
      },
    ],
    {
      ...opts,
      txVersion: TX_VERSION_TOCCATA,
      subnetworkId: IGRA_SUBNETWORK_ID,
      gas: 0n,
      payload: igraEntryPayload(entry.l2Address, entry.amount, 0),
    },
  );
}

export interface MineOptions {
  /** First nonce to try (default 0) — resume a chunked search. */
  startNonce?: number;
  /** Nonces to try before giving up (default 2^22; ~65,536 expected). */
  maxAttempts?: number;
}

export class IgraNonceNotFoundError extends KaspaError {
  constructor(readonly nextNonce: number) {
    super('INVALID_INPUT', `no Igra nonce found; resume at ${nextNonce}`);
  }
}

/**
 * Grind the payload nonce until the ID starts with `97b1`. Refuses anything
 * that is not exactly an entry for `entry`: version 1, Igra subnetwork, zero
 * gas, a 33-byte payload, and exactly one output paying precisely `amount` to
 * the lock script — so the payload can never claim a different amount or
 * recipient than the transaction actually locks. Returns a new planned
 * transaction (the input's `id` is superseded); sign it afterwards.
 */
export function mineIgraEntry(
  planned: PlannedTransaction,
  entry: IgraEntry,
  opts: MineOptions = {},
): PlannedTransaction {
  const tx = planned.tx;
  const lock = entry.lockScript ?? IGRA_MAINNET_LOCK_SCRIPT;
  if (tx.version !== TX_VERSION_TOCCATA)
    throw invalidInput('Igra entries must be version 1 transactions');
  if (!equalBytes(tx.subnetworkId, IGRA_SUBNETWORK_ID))
    throw invalidInput('transaction is not on the Igra subnetwork');
  if (tx.gas !== 0n) throw invalidInput('Igra entries carry zero gas');
  if (tx.payload.length !== IGRA_ENTRY_PAYLOAD_SIZE)
    throw invalidInput('planned payload must be 33 bytes so the mass is final');
  const locks = tx.outputs.filter(
    (o) =>
      o.scriptPublicKey.version === lock.version &&
      equalBytes(o.scriptPublicKey.script, lock.script),
  );
  if (locks.length !== 1 || locks[0]?.value !== entry.amount)
    throw invalidInput(
      'transaction must pay exactly the entry amount to the lock script once',
    );
  if (tx.inputs.some((i) => i.signatureScript.length > 0))
    throw invalidInput(
      'mine before signing: the signature commits to the payload',
    );

  const start = opts.startNonce ?? 0;
  const attempts = opts.maxAttempts ?? 1 << 22;
  if (!Number.isInteger(start) || start < 0 || start > 0xffffffff)
    throw invalidInput('startNonce must be a u32');
  const rest = blake3Domain(
    'TransactionRest',
    encodeTransaction(
      tx,
      TxEncodingFlags.EXCLUDE_PAYLOAD |
        TxEncodingFlags.EXCLUDE_SIGNATURE_SCRIPT |
        TxEncodingFlags.EXCLUDE_MASS_COMMIT,
    ),
  );
  const buf = new Uint8Array(64);
  buf.set(rest, 32);
  const end = Math.min(0x100000000, start + attempts);
  const base = igraEntryPayload(entry.l2Address, entry.amount, 0);
  for (let nonce = start; nonce < end; nonce++) {
    const payload = Uint8Array.from(base);
    let n = nonce;
    for (let i = 0; i < 4; i++) {
      payload[29 + i] = n & 0xff;
      n = Math.floor(n / 256);
    }
    buf.set(payloadDigest(payload), 0);
    const id = blake3Domain('TransactionV1Id', buf);
    if (id[0] !== IGRA_TX_ID_PREFIX[0] || id[1] !== IGRA_TX_ID_PREFIX[1])
      continue;
    const mined: Transaction = { ...tx, payload };
    const check = transactionId(mined);
    if (!equalBytes(check, id))
      throw new KaspaError('INVALID_TRANSACTION', 'Igra id shortcut diverged');
    return { ...planned, tx: mined, id: check };
  }
  throw new IgraNonceNotFoundError(end);
}

/** Parse an entry payload (e.g. to show what a transaction will credit). */
export function parseIgraEntryPayload(payload: Uint8Array): {
  l2Address: string;
  amount: bigint;
  nonce: number;
} | null {
  if (
    payload.length !== IGRA_ENTRY_PAYLOAD_SIZE ||
    payload[0] !== IGRA_ENTRY_TX_PREFIX
  )
    return null;
  let amount = 0n;
  for (let i = 7; i >= 0; i--)
    amount = (amount << 8n) | BigInt(payload[21 + i] ?? 0);
  let nonce = 0;
  for (let i = 3; i >= 0; i--) nonce = nonce * 256 + (payload[29 + i] ?? 0);
  return {
    l2Address: `0x${bytesToHex(payload.subarray(1, 21))}`,
    amount,
    nonce,
  };
}
