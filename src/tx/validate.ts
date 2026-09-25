import { U64_MAX, equalBytes } from '../bytes.js';
import {
  MAX_COMPUTE_BUDGET,
  MAX_SCRIPT_PUBLIC_KEY_LEN,
  MAX_SIGNATURE_SCRIPT_LEN,
  MAX_SOMPI,
  MAX_TX_INPUTS,
  MAX_TX_OUTPUTS,
  SUBNETWORK_ID_SIZE,
  TX_VERSION_TOCCATA,
} from '../constants.js';
import { InvalidTransactionError } from '../errors.js';
import { isNativeSubnetwork } from './model.js';
import type { Transaction } from './model.js';

function isU(v: number, bits: number): boolean {
  return Number.isInteger(v) && v >= 0 && v <= 2 ** bits - 1;
}
function isU64(v: bigint): boolean {
  return typeof v === 'bigint' && v >= 0n && v <= U64_MAX;
}
function bytes(v: unknown, len?: number): boolean {
  return v instanceof Uint8Array && (len === undefined || v.length === len);
}

/**
 * Structural and isolation-level validity, mirroring rusty-kaspa's
 * `validate_tx_in_isolation` where it applies to non-coinbase transactions:
 * field widths, counts, sizes, zero-value and overflowing outputs, duplicate
 * inputs, version-specific fields and the subnetwork shape. Throws
 * `InvalidTransactionError`. Run on anything that crossed a trust boundary.
 */
export function validateTransactionStructure(tx: Transaction): void {
  const fail = (m: string): never => {
    throw new InvalidTransactionError(m);
  };
  if (tx.version !== 0 && tx.version !== TX_VERSION_TOCCATA)
    fail(`unknown transaction version ${String(tx.version)}`);
  const v1 = tx.version >= TX_VERSION_TOCCATA;
  if (!Array.isArray(tx.inputs) || tx.inputs.length === 0)
    fail('transaction has no inputs');
  if (tx.inputs.length > MAX_TX_INPUTS) fail('too many inputs');
  if (!Array.isArray(tx.outputs) || tx.outputs.length > MAX_TX_OUTPUTS)
    fail('too many outputs');

  tx.inputs.forEach((i, n) => {
    if (!bytes(i.previousOutpoint.transactionId, 32))
      fail(`input ${n}: transaction id must be 32 bytes`);
    if (!isU(i.previousOutpoint.index, 32))
      fail(`input ${n}: index must be a u32`);
    if (!bytes(i.signatureScript))
      fail(`input ${n}: signature script must be bytes`);
    if (i.signatureScript.length > MAX_SIGNATURE_SCRIPT_LEN)
      fail(`input ${n}: signature script too large`);
    if (!isU64(i.sequence)) fail(`input ${n}: sequence must be a u64`);
    if (v1) {
      if (
        i.computeBudget === undefined ||
        !isU(i.computeBudget, 16) ||
        i.computeBudget > MAX_COMPUTE_BUDGET
      ) {
        fail(`input ${n}: version 1 requires a u16 compute budget`);
      }
    } else {
      if (!isU(i.sigOpCount, 8)) fail(`input ${n}: sigOpCount must be a u8`);
      if (i.computeBudget !== undefined)
        fail(`input ${n}: compute budget is not allowed in version 0`);
    }
  });
  for (let a = 0; a < tx.inputs.length; a++) {
    for (let b = a + 1; b < tx.inputs.length; b++) {
      const x = (tx.inputs[a] as Transaction['inputs'][number])
        .previousOutpoint;
      const y = (tx.inputs[b] as Transaction['inputs'][number])
        .previousOutpoint;
      if (x.index === y.index && equalBytes(x.transactionId, y.transactionId))
        fail('duplicate inputs');
    }
  }

  let total = 0n;
  tx.outputs.forEach((o, n) => {
    if (typeof o.value !== 'bigint' || o.value <= 0n)
      fail(`output ${n}: value must be positive`);
    if (o.value > MAX_SOMPI) fail(`output ${n}: value exceeds MAX_SOMPI`);
    total += o.value;
    if (total > MAX_SOMPI) fail('total output value exceeds MAX_SOMPI');
    if (!isU(o.scriptPublicKey.version, 16))
      fail(`output ${n}: script version must be a u16`);
    if (!bytes(o.scriptPublicKey.script))
      fail(`output ${n}: script must be bytes`);
    if (o.scriptPublicKey.script.length > MAX_SCRIPT_PUBLIC_KEY_LEN)
      fail(`output ${n}: script public key too large`);
    if (o.covenant !== undefined) {
      if (!v1)
        fail(`output ${n}: covenant bindings are not allowed in version 0`);
      if (
        !isU(o.covenant.authorizingInput, 16) ||
        !bytes(o.covenant.covenantId, 32)
      ) {
        fail(`output ${n}: malformed covenant binding`);
      }
    }
  });

  if (!isU64(tx.lockTime)) fail('lockTime must be a u64');
  if (!isU64(tx.gas)) fail('gas must be a u64');
  if (!bytes(tx.subnetworkId, SUBNETWORK_ID_SIZE))
    fail('subnetwork id must be 20 bytes');
  if (!bytes(tx.payload)) fail('payload must be bytes');
  // tx_validation_in_isolation::check_transaction_subnetwork / check_gas
  const native = isNativeSubnetwork(tx.subnetworkId);
  if (!native) {
    if (!v1) fail('non-native subnetworks require version 1');
    const tail = tx.subnetworkId.slice(4);
    if (tail.some((b) => b !== 0))
      fail('subnetwork id must be a 4-byte namespace followed by zeros');
    if (tx.subnetworkId.slice(1).every((b) => b === 0))
      fail('reserved system subnetwork');
  } else if (tx.gas !== 0n) {
    fail('native subnetwork must use zero gas');
  }
}
