import { TX_VERSION_TOCCATA, SUBNETWORK_ID_SIZE } from '../constants.js';
import type {
  Transaction,
  TransactionInput,
  TransactionOutput,
} from './model.js';

/**
 * `transaction_estimated_serialized_size` (`consensus/core/src/mass/mod.rs`).
 * A deterministic sizing function for mass — not a wire format. Kaspa
 * transactions are submitted as JSON, so there is no binary encoding to emit.
 */
export function estimatedSerializedSize(tx: Transaction): bigint {
  let size = 2n + 8n;
  for (const input of tx.inputs) size += inputSize(input, tx.version);
  size += 8n;
  for (const output of tx.outputs) size += outputSize(output);
  size +=
    8n + BigInt(SUBNETWORK_ID_SIZE) + 8n + 32n + 8n + BigInt(tx.payload.length);
  return size;
}

function inputSize(input: TransactionInput, version: number): bigint {
  let s = 32n + 4n + 8n + BigInt(input.signatureScript.length) + 8n;
  if (version >= TX_VERSION_TOCCATA) s += 2n;
  return s;
}

export function outputSize(output: TransactionOutput): bigint {
  let s = 8n + 2n + 8n + BigInt(output.scriptPublicKey.script.length);
  if (output.covenant) s += 2n + 32n;
  return s;
}
