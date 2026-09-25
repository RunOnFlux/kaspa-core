/**
 * Typed errors with a stable machine-readable `code`, so consumers can branch
 * without string matching. Messages never contain keys, signatures or bundles.
 */
export type KaspaErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_ADDRESS'
  | 'INVALID_SCRIPT'
  | 'MULTISIG_CONFIG'
  | 'SIGHASH'
  | 'SIGNATURE'
  | 'INCOMPLETE_SIGNATURES'
  | 'INSUFFICIENT_FUNDS'
  | 'NEEDS_CONSOLIDATION'
  | 'CHANGE_WOULD_BE_DUST'
  | 'MASS_CAP_EXCEEDED'
  | 'INVALID_TRANSACTION'
  | 'FEE_TOO_HIGH'
  | 'ENTRY_MISMATCH'
  | 'REST'
  | 'RPC'
  | 'SUBMIT_OUTCOME_UNKNOWN';

export class KaspaError extends Error {
  readonly code: KaspaErrorCode;
  constructor(code: KaspaErrorCode, message: string) {
    super(message);
    this.name = 'KaspaError';
    this.code = code;
  }
}

export class InvalidAddressError extends KaspaError {
  constructor(message: string) {
    super('INVALID_ADDRESS', message);
    this.name = 'InvalidAddressError';
  }
}

export class InvalidScriptError extends KaspaError {
  constructor(message: string) {
    super('INVALID_SCRIPT', message);
    this.name = 'InvalidScriptError';
  }
}

export class MultisigConfigError extends KaspaError {
  constructor(message: string) {
    super('MULTISIG_CONFIG', message);
    this.name = 'MultisigConfigError';
  }
}

export class SignatureError extends KaspaError {
  constructor(message: string) {
    super('SIGNATURE', message);
    this.name = 'SignatureError';
  }
}

export class IncompleteSignaturesError extends KaspaError {
  constructor(message: string) {
    super('INCOMPLETE_SIGNATURES', message);
    this.name = 'IncompleteSignaturesError';
  }
}

export class InsufficientFundsError extends KaspaError {
  /** Additional sompi needed, fees included. */
  readonly shortfall: bigint;
  constructor(shortfall: bigint) {
    super(
      'INSUFFICIENT_FUNDS',
      `Insufficient funds: short by ${shortfall} sompi`,
    );
    this.name = 'InsufficientFundsError';
    this.shortfall = shortfall;
  }
}

export class NeedsConsolidationError extends KaspaError {
  /** Inputs that fit under the mass cap before the target was reached. */
  readonly maxInputs: number;
  constructor(maxInputs: number) {
    super(
      'NEEDS_CONSOLIDATION',
      `Target cannot be reached within the mass cap; at most ${maxInputs} inputs fit. Consolidate UTXOs first.`,
    );
    this.name = 'NeedsConsolidationError';
    this.maxInputs = maxInputs;
  }
}

export class ChangeWouldBeDustError extends KaspaError {
  readonly change: bigint;
  readonly storageMass: bigint;
  constructor(change: bigint, storageMass: bigint) {
    super(
      'CHANGE_WOULD_BE_DUST',
      `Change of ${change} sompi would add ${storageMass} grams of storage mass and is too large to fold into the fee`,
    );
    this.name = 'ChangeWouldBeDustError';
    this.change = change;
    this.storageMass = storageMass;
  }
}

export class MassCapExceededError extends KaspaError {
  readonly mass: bigint;
  readonly cap: bigint;
  constructor(mass: bigint, cap: bigint) {
    super(
      'MASS_CAP_EXCEEDED',
      `Transaction mass ${mass} exceeds the cap of ${cap} grams`,
    );
    this.name = 'MassCapExceededError';
    this.mass = mass;
    this.cap = cap;
  }
}

export class InvalidTransactionError extends KaspaError {
  constructor(message: string) {
    super('INVALID_TRANSACTION', message);
    this.name = 'InvalidTransactionError';
  }
}

export class FeeTooHighError extends KaspaError {
  readonly fee: bigint;
  readonly maxFee: bigint;
  constructor(fee: bigint, maxFee: bigint) {
    super(
      'FEE_TOO_HIGH',
      `Fee of ${fee.toString()} sompi exceeds the ceiling of ${maxFee.toString()} sompi`,
    );
    this.name = 'FeeTooHighError';
    this.fee = fee;
    this.maxFee = maxFee;
  }
}

/** A co-signer's independently fetched UTXO differs from what the bundle claims. */
export class EntryMismatchError extends KaspaError {
  readonly inputIndex: number;
  constructor(inputIndex: number, detail: string) {
    super('ENTRY_MISMATCH', `Input ${inputIndex}: ${detail}`);
    this.name = 'EntryMismatchError';
    this.inputIndex = inputIndex;
  }
}

export class RestError extends KaspaError {
  readonly status: number;
  /** The node's own message, verbatim — the most useful diagnostic available. */
  readonly nodeMessage: string;
  constructor(status: number, nodeMessage: string) {
    super('REST', `Kaspa REST ${status}: ${nodeMessage}`);
    this.name = 'RestError';
    this.status = status;
    this.nodeMessage = nodeMessage;
  }
}

export function invalidInput(message: string): KaspaError {
  return new KaspaError('INVALID_INPUT', message);
}

/** A wRPC node error, connection failure or malformed response. */
export class RpcError extends KaspaError {
  /** The node's own message, verbatim, when the node answered with an error. */
  readonly nodeMessage: string | undefined;
  constructor(message: string, nodeMessage?: string) {
    super('RPC', message);
    this.name = 'RpcError';
    this.nodeMessage = nodeMessage;
  }
}

/**
 * A transaction was sent but no definite answer came back (timeout or lost
 * connection after sending). It **may have been broadcast**. Never rebuild it
 * from different UTXOs — that can pay twice. Re-submit the identical signed
 * transaction (same ID, idempotent) or check for `transactionId` in the
 * mempool / via a UTXO notification.
 */
export class SubmitOutcomeUnknownError extends KaspaError {
  readonly transactionId: string;
  constructor(transactionId: string, cause: string) {
    super(
      'SUBMIT_OUTCOME_UNKNOWN',
      `transaction ${transactionId} may have been broadcast: ${cause}`,
    );
    this.name = 'SubmitOutcomeUnknownError';
    this.transactionId = transactionId;
  }
}
