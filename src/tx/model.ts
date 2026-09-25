/**
 * Plain-data transaction model mirroring `consensus/core/src/tx.rs`.
 * No classes with behaviour: every operation is a pure function elsewhere.
 */

export interface ScriptPublicKey {
  /** u16. Forward-compatibility lever; currently 0 for every standard script. */
  version: number;
  script: Uint8Array;
}

export interface Outpoint {
  /** 32-byte transaction id, in the byte order the hasher writes it. */
  transactionId: Uint8Array;
  /** u32 output index. */
  index: number;
}

export interface CovenantBinding {
  /** u16 */
  authorizingInput: number;
  /** 32 bytes */
  covenantId: Uint8Array;
}

export interface TransactionInput {
  previousOutpoint: Outpoint;
  /** Empty until signed. */
  signatureScript: Uint8Array;
  /** u64, 0n by default. */
  sequence: bigint;
  /**
   * u8, version 0 only. Committed to by the signature hash and converted by
   * consensus into the script execution budget. For a multisig input it must
   * equal the number of public keys. Derive it from the spend descriptor;
   * never accept it from a caller.
   */
  sigOpCount: number;
  /** u16, version 1 only (100 grams per unit). */
  computeBudget?: number;
}

export interface TransactionOutput {
  /** Sompi, u64, must be > 0. */
  value: bigint;
  scriptPublicKey: ScriptPublicKey;
  /** Version 1 only. */
  covenant?: CovenantBinding;
}

export interface Transaction {
  /** 0 (native, what wallets send) or 1 (Toccata). */
  version: number;
  inputs: TransactionInput[];
  outputs: TransactionOutput[];
  /** u64 */
  lockTime: bigint;
  /** 20 bytes, all zero for the native subnetwork. */
  subnetworkId: Uint8Array;
  /** u64, 0 except on version 1 non-system lanes. */
  gas: bigint;
  payload: Uint8Array;
}

/** The previous output being spent, as the UTXO index reports it. */
export interface UtxoEntry {
  /** Sompi. */
  amount: bigint;
  scriptPublicKey: ScriptPublicKey;
  blockDaaScore: bigint;
  isCoinbase: boolean;
  /** Version 1 covenant UTXOs only. */
  covenantId?: Uint8Array;
}

export function nativeSubnetworkId(): Uint8Array {
  return new Uint8Array(20);
}

export function isNativeSubnetwork(id: Uint8Array): boolean {
  return id.length === 20 && id.every((b) => b === 0);
}
