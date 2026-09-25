import { MAX_PUB_KEYS_PER_MULTISIG } from '../constants.js';
import { InvalidScriptError } from '../errors.js';
import { Op } from './opcodes.js';

export interface ParsedOp {
  opcode: number;
  /** Push data, for push opcodes. */
  data?: Uint8Array;
}

/** Split a script into opcodes and their push data. Throws on a truncated push. */
export function parseScript(script: Uint8Array): ParsedOp[] {
  const ops: ParsedOp[] = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i] ?? 0;
    i += 1;
    let len = -1;
    const lenBytes =
      op === Op.OpPushData1
        ? 1
        : op === Op.OpPushData2
          ? 2
          : op === Op.OpPushData4
            ? 4
            : 0;
    if (i + lenBytes > script.length)
      throw new InvalidScriptError('truncated push length');
    if (op >= Op.OpData1 && op <= Op.OpData75) len = op;
    else if (op === Op.OpPushData1) {
      len = script[i] ?? -1;
      i += 1;
    } else if (op === Op.OpPushData2) {
      len = (script[i] ?? 0) | ((script[i + 1] ?? 0) << 8);
      i += 2;
    } else if (op === Op.OpPushData4) {
      len =
        ((script[i] ?? 0) |
          ((script[i + 1] ?? 0) << 8) |
          ((script[i + 2] ?? 0) << 16)) +
        (script[i + 3] ?? 0) * 0x1000000;
      i += 4;
    }
    if (len >= 0) {
      if (i + len > script.length)
        throw new InvalidScriptError('truncated push');
      ops.push({ opcode: op, data: script.slice(i, i + len) });
      i += len;
    } else {
      ops.push({ opcode: op });
    }
  }
  return ops;
}

const CHECKSIG_LIKE = new Set<number>([
  Op.OpCheckSig,
  Op.OpCheckSigVerify,
  Op.OpCheckSigECDSA,
  0xd7,
  0xd8,
]);
const CHECKMULTISIG_LIKE = new Set<number>([
  Op.OpCheckMultiSig,
  Op.OpCheckMultiSigVerify,
  Op.OpCheckMultiSigECDSA,
]);

/**
 * `deserialize_i64` from rusty-kaspa `data_stack.rs`: little-endian
 * sign-magnitude, **not** required to be minimally encoded, at most 8 bytes.
 * Returns null where rusty-kaspa would error (longer than 8 bytes).
 */
export function deserializeScriptNum(v: Uint8Array): bigint | null {
  if (v.length > 8) return null;
  if (v.length === 0) return 0n;
  const msb = v[v.length - 1] ?? 0;
  const negative = (msb & 0x80) !== 0;
  let acc = BigInt(msb & 0x7f);
  for (let i = v.length - 2; i >= 0; i--) acc = (acc << 8n) + BigInt(v[i] ?? 0);
  return negative ? -acc : acc;
}

/**
 * Signature operations in a redeem script, counted the way the mempool's
 * `p2sh_sig_scanner` does: +1 per CHECKSIG-like opcode (including the
 * from-stack variants), +n per CHECKMULTISIG when preceded by a small-integer
 * or a pushed count in 1..20, otherwise +20. Returns 0 for a malformed script.
 */
export function countRedeemSigOps(redeem: Uint8Array): number {
  let ops: ParsedOp[];
  try {
    ops = parseScript(redeem);
  } catch {
    return 0;
  }
  let sigops = 0;
  let prevCount: number | null = null;
  for (const { opcode, data } of ops) {
    const count = prevCount;
    prevCount = null;
    if (CHECKSIG_LIKE.has(opcode)) sigops += 1;
    else if (CHECKMULTISIG_LIKE.has(opcode))
      sigops += count ?? MAX_PUB_KEYS_PER_MULTISIG;
    else if (opcode >= Op.Op1 && opcode <= Op.Op16)
      prevCount = opcode - Op.Op1 + 1;
    else if (opcode <= Op.OpPushData4) {
      const n = deserializeScriptNum(data ?? new Uint8Array(0));
      if (n !== null && n >= 1n && n <= BigInt(MAX_PUB_KEYS_PER_MULTISIG))
        prevCount = Number(n);
    }
  }
  return sigops;
}
