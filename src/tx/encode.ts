import { Writer } from '../bytes.js';
import { blake2bDomain, blake3Domain } from '../hash.js';
import { TX_VERSION_TOCCATA } from '../constants.js';
import type { Transaction } from './model.js';

/** `TxEncodingFlags` from `consensus/core/src/hashing/tx.rs`. */
export const TxEncodingFlags = {
  FULL: 0,
  EXCLUDE_SIGNATURE_SCRIPT: 1 << 0,
  EXCLUDE_MASS_COMMIT: 1 << 1,
  EXCLUDE_PAYLOAD: 1 << 2,
} as const;

/**
 * `write_transaction`: the canonical encoding every transaction digest is
 * taken over. Integers little-endian, lengths as u64, `varBytes` = u64 length
 * prefix + bytes.
 *
 * @param storageMassCommit the committed storage mass (`tx.storage_mass()`),
 *   only read when mass commits are not excluded. 0 for wallet-built txs.
 */
export function encodeTransaction(
  tx: Transaction,
  flags: number,
  storageMassCommit = 0n,
): Uint8Array {
  const excludeSig = (flags & TxEncodingFlags.EXCLUDE_SIGNATURE_SCRIPT) !== 0;
  const excludeMass = (flags & TxEncodingFlags.EXCLUDE_MASS_COMMIT) !== 0;
  const excludePayload = (flags & TxEncodingFlags.EXCLUDE_PAYLOAD) !== 0;
  const v1 = tx.version >= TX_VERSION_TOCCATA;
  const w = new Writer(512);

  w.u16(tx.version).u64(BigInt(tx.inputs.length));
  for (const input of tx.inputs) {
    w.bytes(input.previousOutpoint.transactionId).u32(
      input.previousOutpoint.index,
    );
    if (!excludeSig) {
      w.varBytes(input.signatureScript);
      if (!v1) w.u8(input.sigOpCount);
    } else {
      w.varBytes(new Uint8Array(0));
    }
    w.u64(input.sequence);
    if (!excludeMass && v1) w.u16(input.computeBudget ?? 0);
  }

  w.u64(BigInt(tx.outputs.length));
  for (const output of tx.outputs) {
    w.u64(output.value)
      .u16(output.scriptPublicKey.version)
      .varBytes(output.scriptPublicKey.script);
    if (v1) {
      w.bool(output.covenant !== undefined);
      if (output.covenant)
        w.u16(output.covenant.authorizingInput).bytes(
          output.covenant.covenantId,
        );
    }
  }

  w.u64(tx.lockTime).bytes(tx.subnetworkId).u64(tx.gas);
  w.varBytes(excludePayload ? new Uint8Array(0) : tx.payload);

  if (!excludeMass) {
    if (!v1) {
      if (storageMassCommit > 0n) w.u64(storageMassCommit);
    } else {
      w.u64(storageMassCommit);
    }
  }
  return w.finish();
}

/** blake3 `PayloadDigest` of the payload (version 1 transaction IDs). */
export function payloadDigest(payload: Uint8Array): Uint8Array {
  return blake3Domain('PayloadDigest', payload);
}

/**
 * Transaction ID. Excludes signature scripts, so it is **known before
 * signing** — Kaspa's native malleability immunity.
 *  - v0: keyed blake2b `TransactionID` over the encoding without signature
 *    scripts, sigop counts or mass commit (payload included in full).
 *  - v1: keyed blake3, two-stage:
 *    `TransactionV1Id(PayloadDigest(payload) ‖ TransactionRest(rest))`, where
 *    `rest` also excludes the payload. Compute budgets are not committed.
 */
export function transactionId(tx: Transaction): Uint8Array {
  if (tx.version < TX_VERSION_TOCCATA) {
    return blake2bDomain(
      'TransactionID',
      encodeTransaction(
        tx,
        TxEncodingFlags.EXCLUDE_SIGNATURE_SCRIPT |
          TxEncodingFlags.EXCLUDE_MASS_COMMIT,
      ),
    );
  }
  const rest = blake3Domain(
    'TransactionRest',
    encodeTransaction(
      tx,
      TxEncodingFlags.EXCLUDE_PAYLOAD |
        TxEncodingFlags.EXCLUDE_SIGNATURE_SCRIPT |
        TxEncodingFlags.EXCLUDE_MASS_COMMIT,
    ),
  );
  const pd = payloadDigest(tx.payload);
  const both = new Uint8Array(64);
  both.set(pd, 0);
  both.set(rest, 32);
  return blake3Domain('TransactionV1Id', both);
}

/**
 * Signature-inclusive transaction hash (`tx::hash`, flags FULL) — the digest
 * used for block merkle roots and mass commitments; Bitcoin's wtxid analogue.
 */
export function transactionHash(
  tx: Transaction,
  storageMassCommit = 0n,
): Uint8Array {
  return blake2bDomain(
    'TransactionHash',
    encodeTransaction(tx, TxEncodingFlags.FULL, storageMassCommit),
  );
}
