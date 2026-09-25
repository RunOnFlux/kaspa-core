import { Writer } from './bytes.js';
import {
  ALLOWED_SIG_HASH_TYPES,
  SIG_HASH_ANY_ONE_CAN_PAY,
  SIG_HASH_MASK,
  SIG_HASH_NONE,
  SIG_HASH_SINGLE,
  TX_VERSION_TOCCATA,
} from './constants.js';
import { KaspaError } from './errors.js';
import { blake2bDomain, sha256Domain, zeroHash } from './hash.js';
import { isNativeSubnetwork } from './tx/model.js';
import type { Transaction, TransactionOutput, UtxoEntry } from './tx/model.js';

function isAnyoneCanPay(t: number): boolean {
  return (t & SIG_HASH_ANY_ONE_CAN_PAY) === SIG_HASH_ANY_ONE_CAN_PAY;
}
function isNone(t: number): boolean {
  return (t & SIG_HASH_MASK) === SIG_HASH_NONE;
}
function isSingle(t: number): boolean {
  return (t & SIG_HASH_MASK) === SIG_HASH_SINGLE;
}

function writeOutput(w: Writer, o: TransactionOutput, version: number): void {
  w.u64(o.value)
    .u16(o.scriptPublicKey.version)
    .varBytes(o.scriptPublicKey.script);
  if (version >= TX_VERSION_TOCCATA) {
    w.bool(o.covenant !== undefined);
    if (o.covenant)
      w.u16(o.covenant.authorizingInput).bytes(o.covenant.covenantId);
  }
}

/**
 * Reusable signature-hash context for one transaction
 * (rusty-kaspa's `SigHashReusedValues`). The component hashes are pure
 * functions of the transaction, so signing N inputs hashes the outputs once
 * rather than N times. Create a new context if the transaction changes.
 */
export class SighashContext {
  private prevouts?: Uint8Array;
  private sequences?: Uint8Array;
  private sigOpCounts?: Uint8Array;
  private outputs?: Uint8Array;
  private payload?: Uint8Array;

  constructor(
    readonly tx: Transaction,
    readonly entries: readonly UtxoEntry[],
  ) {
    if (entries.length !== tx.inputs.length) {
      throw new KaspaError('SIGHASH', 'one UTXO entry is required per input');
    }
  }

  private previousOutputsHash(t: number): Uint8Array {
    if (isAnyoneCanPay(t)) return zeroHash();
    if (!this.prevouts) {
      const w = new Writer();
      for (const i of this.tx.inputs)
        w.bytes(i.previousOutpoint.transactionId).u32(i.previousOutpoint.index);
      this.prevouts = blake2bDomain('TransactionSigningHash', w.finish());
    }
    return this.prevouts;
  }

  private sequencesHash(t: number): Uint8Array {
    if (isSingle(t) || isAnyoneCanPay(t) || isNone(t)) return zeroHash();
    if (!this.sequences) {
      const w = new Writer();
      for (const i of this.tx.inputs) w.u64(i.sequence);
      this.sequences = blake2bDomain('TransactionSigningHash', w.finish());
    }
    return this.sequences;
  }

  private sigOpCountsHash(t: number): Uint8Array {
    if (isAnyoneCanPay(t)) return zeroHash();
    if (!this.sigOpCounts) {
      const w = new Writer();
      for (const i of this.tx.inputs) w.u8(i.sigOpCount);
      this.sigOpCounts = blake2bDomain('TransactionSigningHash', w.finish());
    }
    return this.sigOpCounts;
  }

  private outputsHash(t: number, index: number): Uint8Array {
    if (isNone(t)) return zeroHash();
    if (isSingle(t)) {
      const o = this.tx.outputs[index];
      if (!o) return zeroHash();
      const w = new Writer();
      writeOutput(w, o, this.tx.version);
      return blake2bDomain('TransactionSigningHash', w.finish());
    }
    if (!this.outputs) {
      const w = new Writer();
      for (const o of this.tx.outputs) writeOutput(w, o, this.tx.version);
      this.outputs = blake2bDomain('TransactionSigningHash', w.finish());
    }
    return this.outputs;
  }

  private payloadHash(): Uint8Array {
    if (
      isNativeSubnetwork(this.tx.subnetworkId) &&
      this.tx.payload.length === 0
    )
      return zeroHash();
    if (!this.payload) {
      this.payload = blake2bDomain(
        'TransactionSigningHash',
        new Writer().varBytes(this.tx.payload).finish(),
      );
    }
    return this.payload;
  }

  /**
   * `calc_schnorr_signature_hash` (`consensus/core/src/hashing/sighash.rs`).
   * Version 1 omits the sigop-count hash and the per-input sigop byte
   * entirely — absent, not zeroed.
   */
  schnorr(index: number, hashType: number): Uint8Array {
    if (!ALLOWED_SIG_HASH_TYPES.includes(hashType)) {
      throw new KaspaError(
        'SIGHASH',
        `unsupported sighash type 0x${hashType.toString(16)}`,
      );
    }
    const input = this.tx.inputs[index];
    const entry = this.entries[index];
    if (!input || !entry)
      throw new KaspaError('SIGHASH', `no input at index ${index}`);
    const v0 = this.tx.version < TX_VERSION_TOCCATA;
    const w = new Writer(256);
    w.u16(this.tx.version)
      .bytes(this.previousOutputsHash(hashType))
      .bytes(this.sequencesHash(hashType));
    if (v0) w.bytes(this.sigOpCountsHash(hashType));
    w.bytes(input.previousOutpoint.transactionId).u32(
      input.previousOutpoint.index,
    );
    w.u16(entry.scriptPublicKey.version).varBytes(entry.scriptPublicKey.script);
    w.u64(entry.amount).u64(input.sequence);
    if (v0) w.u8(input.sigOpCount);
    w.bytes(this.outputsHash(hashType, index))
      .u64(this.tx.lockTime)
      .bytes(this.tx.subnetworkId)
      .u64(this.tx.gas)
      .bytes(this.payloadHash())
      .u8(hashType);
    return blake2bDomain('TransactionSigningHash', w.finish());
  }

  /** `calc_ecdsa_signature_hash`: `SHA256(SHA256(domain) ‖ schnorrHash)`. */
  ecdsa(index: number, hashType: number): Uint8Array {
    return sha256Domain(
      'TransactionSigningHashECDSA',
      this.schnorr(index, hashType),
    );
  }
}

/** One-shot Schnorr signature hash. Prefer `SighashContext` when signing many inputs. */
export function sighash(
  tx: Transaction,
  entries: readonly UtxoEntry[],
  index: number,
  hashType: number,
): Uint8Array {
  return new SighashContext(tx, entries).schnorr(index, hashType);
}

/** One-shot ECDSA signature hash. */
export function sighashEcdsa(
  tx: Transaction,
  entries: readonly UtxoEntry[],
  index: number,
  hashType: number,
): Uint8Array {
  return new SighashContext(tx, entries).ecdsa(index, hashType);
}
