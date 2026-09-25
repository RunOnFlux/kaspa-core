import { U64_MAX, bytesToHex, hexToBytes } from '../bytes.js';
import { KaspaError, invalidInput } from '../errors.js';
import { validateTransactionStructure } from './validate.js';
import type { Spend, InputPlan } from '../spend.js';
import type {
  Outpoint,
  ScriptPublicKey,
  Transaction,
  UtxoEntry,
} from './model.js';

/**
 * JSON-safe forms (hex for bytes, decimal strings for u64) so transactions,
 * input plans and signing bundles survive `JSON.stringify` and a relay hop.
 */

export interface ScriptPublicKeyJson {
  version: number;
  script: string;
}
export interface OutpointJson {
  transactionId: string;
  index: number;
}
export interface TransactionJson {
  version: number;
  inputs: {
    previousOutpoint: OutpointJson;
    signatureScript: string;
    sequence: string;
    sigOpCount: number;
    computeBudget?: number;
  }[];
  outputs: {
    value: string;
    scriptPublicKey: ScriptPublicKeyJson;
    covenant?: { authorizingInput: number; covenantId: string };
  }[];
  lockTime: string;
  subnetworkId: string;
  gas: string;
  payload: string;
}
export interface UtxoEntryJson {
  amount: string;
  scriptPublicKey: ScriptPublicKeyJson;
  blockDaaScore: string;
  isCoinbase: boolean;
  covenantId?: string;
}
export type SpendJson =
  | { kind: 'p2pk'; xOnlyPubkey: string }
  | { kind: 'p2pk-ecdsa'; pubkey: string }
  | { kind: 'p2sh-multisig'; redeem: string; pubkeys: string[]; m: number }
  | { kind: 'p2sh-script'; redeem: string; signerPubkey: string };
export interface InputPlanJson {
  outpoint: OutpointJson;
  entry: UtxoEntryJson;
  spend: SpendJson;
  sequence?: string;
}

function u64(s: unknown, what: string): bigint {
  if (typeof s !== 'string' || !/^\d{1,20}$/.test(s))
    throw invalidInput(`${what} must be a decimal string`);
  const v = BigInt(s);
  if (v > U64_MAX) throw invalidInput(`${what} exceeds u64`);
  return v;
}

function int(v: unknown, what: string): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0)
    throw invalidInput(`${what} must be a non-negative integer`);
  return v;
}

function hex(v: unknown, what: string, len?: number): Uint8Array {
  if (typeof v !== 'string') throw invalidInput(`${what} must be a hex string`);
  const b = hexToBytes(v);
  if (len !== undefined && b.length !== len)
    throw invalidInput(`${what} must be ${len} bytes`);
  return b;
}

/**
 * Run a JSON decoder, turning structural surprises (a missing object, a wrong
 * type) into a typed error instead of a stray TypeError.
 */
function guarded<T>(what: string, f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (e instanceof KaspaError) throw e;
    throw invalidInput(`malformed ${what}`);
  }
}

export const spkToJson = (s: ScriptPublicKey): ScriptPublicKeyJson => ({
  version: s.version,
  script: bytesToHex(s.script),
});
export const spkFromJson = (s: ScriptPublicKeyJson): ScriptPublicKey => ({
  version: int(s.version, 'script version'),
  script: hex(s.script, 'script'),
});
export const outpointToJson = (o: Outpoint): OutpointJson => ({
  transactionId: bytesToHex(o.transactionId),
  index: o.index,
});
export const outpointFromJson = (o: OutpointJson): Outpoint => ({
  transactionId: hex(o.transactionId, 'transaction id', 32),
  index: int(o.index, 'outpoint index'),
});

export function transactionToJson(tx: Transaction): TransactionJson {
  return {
    version: tx.version,
    inputs: tx.inputs.map((i) => ({
      previousOutpoint: outpointToJson(i.previousOutpoint),
      signatureScript: bytesToHex(i.signatureScript),
      sequence: i.sequence.toString(),
      sigOpCount: i.sigOpCount,
      ...(i.computeBudget !== undefined
        ? { computeBudget: i.computeBudget }
        : {}),
    })),
    outputs: tx.outputs.map((o) => ({
      value: o.value.toString(),
      scriptPublicKey: spkToJson(o.scriptPublicKey),
      ...(o.covenant
        ? {
            covenant: {
              authorizingInput: o.covenant.authorizingInput,
              covenantId: bytesToHex(o.covenant.covenantId),
            },
          }
        : {}),
    })),
    lockTime: tx.lockTime.toString(),
    subnetworkId: bytesToHex(tx.subnetworkId),
    gas: tx.gas.toString(),
    payload: bytesToHex(tx.payload),
  };
}

export function transactionFromJson(j: TransactionJson): Transaction {
  const tx = guarded('transaction', (): Transaction => ({
    version: int(j.version, 'version'),
    inputs: j.inputs.map((i) => ({
      previousOutpoint: outpointFromJson(i.previousOutpoint),
      signatureScript: hex(i.signatureScript, 'signature script'),
      sequence: u64(i.sequence, 'sequence'),
      sigOpCount: int(i.sigOpCount, 'sigOpCount'),
      ...(i.computeBudget !== undefined
        ? { computeBudget: int(i.computeBudget, 'compute budget') }
        : {}),
    })),
    outputs: j.outputs.map((o) => ({
      value: u64(o.value, 'value'),
      scriptPublicKey: spkFromJson(o.scriptPublicKey),
      ...(o.covenant
        ? {
            covenant: {
              authorizingInput: int(
                o.covenant.authorizingInput,
                'authorizing input',
              ),
              covenantId: hex(o.covenant.covenantId, 'covenant id', 32),
            },
          }
        : {}),
    })),
    lockTime: u64(j.lockTime, 'lockTime'),
    subnetworkId: hex(j.subnetworkId, 'subnetwork id', 20),
    gas: u64(j.gas, 'gas'),
    payload: hex(j.payload, 'payload'),
  }));
  validateTransactionStructure(tx);
  return tx;
}

export function utxoEntryToJson(e: UtxoEntry): UtxoEntryJson {
  return {
    amount: e.amount.toString(),
    scriptPublicKey: spkToJson(e.scriptPublicKey),
    blockDaaScore: e.blockDaaScore.toString(),
    isCoinbase: e.isCoinbase,
    ...(e.covenantId ? { covenantId: bytesToHex(e.covenantId) } : {}),
  };
}

export function utxoEntryFromJson(e: UtxoEntryJson): UtxoEntry {
  return {
    amount: u64(e.amount, 'amount'),
    scriptPublicKey: spkFromJson(e.scriptPublicKey),
    blockDaaScore: u64(e.blockDaaScore, 'blockDaaScore'),
    isCoinbase: (e.isCoinbase as unknown) === true,
    ...(e.covenantId
      ? { covenantId: hex(e.covenantId, 'covenant id', 32) }
      : {}),
  };
}

export function spendToJson(s: Spend): SpendJson {
  switch (s.kind) {
    case 'p2pk':
      return { kind: 'p2pk', xOnlyPubkey: bytesToHex(s.xOnlyPubkey) };
    case 'p2pk-ecdsa':
      return { kind: 'p2pk-ecdsa', pubkey: bytesToHex(s.pubkey) };
    case 'p2sh-multisig':
      return {
        kind: 'p2sh-multisig',
        redeem: bytesToHex(s.redeem),
        pubkeys: s.pubkeys.map(bytesToHex),
        m: s.m,
      };
    case 'p2sh-script':
      return {
        kind: 'p2sh-script',
        redeem: bytesToHex(s.redeem),
        signerPubkey: bytesToHex(s.signerPubkey),
      };
  }
}

export function spendFromJson(s: SpendJson): Spend {
  return guarded('spend', () => spendFromJsonUnguarded(s));
}

function spendFromJsonUnguarded(s: SpendJson): Spend {
  switch (s.kind) {
    case 'p2pk':
      return { kind: 'p2pk', xOnlyPubkey: hex(s.xOnlyPubkey, 'key', 32) };
    case 'p2pk-ecdsa':
      return { kind: 'p2pk-ecdsa', pubkey: hex(s.pubkey, 'key', 33) };
    case 'p2sh-multisig':
      return {
        kind: 'p2sh-multisig',
        redeem: hex(s.redeem, 'redeem script'),
        pubkeys: s.pubkeys.map((k) => hex(k, 'key', 32)),
        m: int(s.m, 'm'),
      };
    case 'p2sh-script':
      return {
        kind: 'p2sh-script',
        redeem: hex(s.redeem, 'redeem script'),
        signerPubkey: hex(s.signerPubkey, 'key', 32),
      };
    default:
      throw invalidInput('unknown spend kind');
  }
}

export function inputPlanToJson(p: InputPlan): InputPlanJson {
  return {
    outpoint: outpointToJson(p.outpoint),
    entry: utxoEntryToJson(p.entry),
    spend: spendToJson(p.spend),
    ...(p.sequence !== undefined ? { sequence: p.sequence.toString() } : {}),
  };
}

export function inputPlanFromJson(p: InputPlanJson): InputPlan {
  return guarded('input plan', (): InputPlan => ({
    outpoint: outpointFromJson(p.outpoint),
    entry: utxoEntryFromJson(p.entry),
    spend: spendFromJson(p.spend),
    ...(p.sequence !== undefined
      ? { sequence: u64(p.sequence, 'sequence') }
      : {}),
  }));
}
