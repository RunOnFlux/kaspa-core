import {
  MAX_PUB_KEYS_PER_MULTISIG,
  MAX_STANDARD_P2SH_SIG_OPS,
} from '../constants.js';
import { compareBytes } from '../bytes.js';
import { InvalidScriptError, MultisigConfigError } from '../errors.js';
import { blake2b256 } from '../hash.js';
import { isValidCompressedPublicKey, isValidXOnlyPublicKey } from '../keys.js';
import type { ScriptPublicKey } from '../tx/model.js';
import { ScriptBuilder } from './builder.js';
import { Op } from './opcodes.js';

/**
 * The three standard output templates — the whole space. Kaspa has no
 * P2PKH, no SegWit and no Taproot (`crypto/txscript/src/standard.rs`).
 */

/**
 * `OpData32 ‖ x-only key ‖ OpCheckSig`. The key must be a real curve point:
 * funds locked to anything else are burned, so this refuses to build it.
 */
export function p2pkScript(xOnlyPubkey: Uint8Array): ScriptPublicKey {
  if (!isValidXOnlyPublicKey(xOnlyPubkey))
    throw new InvalidScriptError('P2PK key must be a valid 32-byte x-only key');
  const script = new Uint8Array(34);
  script[0] = Op.OpData32;
  script.set(xOnlyPubkey, 1);
  script[33] = Op.OpCheckSig;
  return { version: 0, script };
}

/** `OpData33 ‖ compressed key ‖ OpCheckSigECDSA` */
export function p2pkEcdsaScript(pubkey: Uint8Array): ScriptPublicKey {
  if (!isValidCompressedPublicKey(pubkey))
    throw new InvalidScriptError(
      'ECDSA key must be a valid 33-byte compressed key',
    );
  const script = new Uint8Array(35);
  script[0] = Op.OpData33;
  script.set(pubkey, 1);
  script[34] = Op.OpCheckSigECDSA;
  return { version: 0, script };
}

/** `OpBlake2b ‖ OpData32 ‖ hash ‖ OpEqual` for an already-computed script hash. */
export function p2shScriptFromHash(scriptHash: Uint8Array): ScriptPublicKey {
  if (scriptHash.length !== 32)
    throw new InvalidScriptError('script hash must be 32 bytes');
  const script = new Uint8Array(35);
  script[0] = Op.OpBlake2b;
  script[1] = Op.OpData32;
  script.set(scriptHash, 2);
  script[34] = Op.OpEqual;
  return { version: 0, script };
}

/**
 * P2SH locking script. The script hash is **unkeyed** blake2b-256 of the
 * redeem script (`pay_to_script_hash_script`), exactly what `OP_BLAKE2B`
 * computes at spend time.
 */
export function p2shScript(redeem: Uint8Array): ScriptPublicKey {
  return p2shScriptFromHash(blake2b256(redeem));
}

export type ScriptClass = 'p2pk' | 'p2pk-ecdsa' | 'p2sh' | 'nonstandard';

/** `ScriptClass::from_script` — only these three forms are standard. */
export function classifyScript(spk: ScriptPublicKey): ScriptClass {
  if (spk.version !== 0) return 'nonstandard';
  const s = spk.script;
  if (s.length === 34 && s[0] === Op.OpData32 && s[33] === Op.OpCheckSig)
    return 'p2pk';
  if (s.length === 35 && s[0] === Op.OpData33 && s[34] === Op.OpCheckSigECDSA)
    return 'p2pk-ecdsa';
  if (
    s.length === 35 &&
    s[0] === Op.OpBlake2b &&
    s[1] === Op.OpData32 &&
    s[34] === Op.OpEqual
  ) {
    return 'p2sh';
  }
  return 'nonstandard';
}

export interface MultisigOptions {
  /**
   * Sort keys lexicographically (default true). rusty-kaspa does not sort;
   * sorting is our convention so two devices derive a byte-identical script
   * and therefore the same address. Signature order must follow the
   * script's key order either way.
   */
  sort?: boolean;
  /**
   * Allow n > 15 (default false). Consensus permits up to 20 keys but the
   * mempool refuses P2SH inputs with more than 15 sigops, so such a vault
   * could never be spent through a standard node.
   */
  allowNonStandard?: boolean;
  /** Use OP_CHECKMULTISIGECDSA with 33-byte keys (default false). */
  ecdsa?: boolean;
}

/**
 * `OP_m ‖ (push key)×n ‖ OP_n ‖ OP_CHECKMULTISIG` — byte-identical to
 * `crypto/txscript/src/standard/multisig.rs` for the same key order.
 */
export function multisigRedeemScript(
  pubkeys: readonly Uint8Array[],
  m: number,
  opts: MultisigOptions = {},
): Uint8Array {
  const ecdsa = opts.ecdsa ?? false;
  const keyLen = ecdsa ? 33 : 32;
  const n = pubkeys.length;
  if (!Number.isInteger(m) || m < 1)
    throw new MultisigConfigError('m must be at least 1');
  if (n < 1)
    throw new MultisigConfigError('at least one public key is required');
  if (m > n)
    throw new MultisigConfigError(`m (${m}) exceeds the number of keys (${n})`);
  if (n > MAX_PUB_KEYS_PER_MULTISIG) {
    throw new MultisigConfigError(
      `at most ${MAX_PUB_KEYS_PER_MULTISIG} keys are allowed`,
    );
  }
  if (n > MAX_STANDARD_P2SH_SIG_OPS && !(opts.allowNonStandard ?? false)) {
    throw new MultisigConfigError(
      `more than ${MAX_STANDARD_P2SH_SIG_OPS} keys is non-standard and could never be spent through a standard node`,
    );
  }
  for (const k of pubkeys) {
    if (!(k instanceof Uint8Array) || k.length !== keyLen) {
      throw new MultisigConfigError(`every key must be ${keyLen} bytes`);
    }
    // A key that is not a curve point can never sign: with it in the script the
    // vault may be permanently unspendable. Refuse to build it.
    const ok = ecdsa ? isValidCompressedPublicKey(k) : isValidXOnlyPublicKey(k);
    if (!ok)
      throw new MultisigConfigError(
        'a key is not a valid secp256k1 public key',
      );
  }
  const sorted = [...pubkeys].sort(compareBytes);
  for (let i = 1; i < sorted.length; i++) {
    if (
      compareBytes(
        sorted[i - 1] ?? new Uint8Array(),
        sorted[i] ?? new Uint8Array(),
      ) === 0
    ) {
      throw new MultisigConfigError('duplicate public key');
    }
  }
  const keys = (opts.sort ?? true) ? sorted : [...pubkeys];
  const b = new ScriptBuilder().addI64(BigInt(m));
  for (const k of keys) b.addData(k);
  return b
    .addI64(BigInt(n))
    .addOp(ecdsa ? Op.OpCheckMultiSigECDSA : Op.OpCheckMultiSig)
    .drain();
}

export interface ParsedMultisig {
  m: number;
  pubkeys: Uint8Array[];
  ecdsa: boolean;
}

/**
 * Parse a canonical multisig redeem script, or return null if it is not one.
 * Handles m, n ≤ 16 (small-integer opcodes), which covers every standard
 * script (n ≤ 15).
 */
export function parseMultisigRedeemScript(
  redeem: Uint8Array,
): ParsedMultisig | null {
  const s = redeem;
  if (s.length < 4) return null;
  const last = s[s.length - 1];
  const ecdsa = last === Op.OpCheckMultiSigECDSA;
  if (!ecdsa && last !== Op.OpCheckMultiSig) return null;
  const keyLen = ecdsa ? 33 : 32;
  const mOp = s[0] ?? 0;
  const nOp = s[s.length - 2] ?? 0;
  if (mOp < Op.Op1 || mOp > Op.Op16 || nOp < Op.Op1 || nOp > Op.Op16)
    return null;
  const m = mOp - Op.Op1 + 1;
  const n = nOp - Op.Op1 + 1;
  if (s.length !== 3 + n * (1 + keyLen) || m > n) return null;
  const pubkeys: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const at = 1 + i * (1 + keyLen);
    if (s[at] !== keyLen) return null;
    pubkeys.push(s.slice(at + 1, at + 1 + keyLen));
  }
  return { m, pubkeys, ecdsa };
}

/**
 * Signature script for a P2SH spend: the signature pushes in order, then a
 * canonical push of the redeem script (`pay_to_script_hash_signature_script`).
 * No leading OP_0 — Kaspa's OP_CHECKMULTISIG pops no dummy element.
 */
export function p2shSignatureScript(
  redeem: Uint8Array,
  pushes: readonly Uint8Array[],
): Uint8Array {
  const b = new ScriptBuilder();
  const head: number[] = [];
  for (const p of pushes) head.push(...p);
  b.addData(redeem);
  const tail = b.drain();
  const out = new Uint8Array(head.length + tail.length);
  out.set(head, 0);
  out.set(tail, head.length);
  return out;
}
