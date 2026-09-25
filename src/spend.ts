import {
  BLAKE2B_SCRIPT_UNITS_PER_BYTE,
  FREE_SCRIPT_UNITS_PER_INPUT,
  MAX_COMPUTE_BUDGET,
  MAX_STANDARD_P2SH_SIG_OPS,
  SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT,
  SIG_HASH_ALL,
  SIGOP_SCRIPT_UNITS,
} from './constants.js';
import { equalBytes } from './bytes.js';
import { invalidInput, MultisigConfigError } from './errors.js';
import { assertXOnlyPublicKey, isValidCompressedPublicKey } from './keys.js';
import { pushPrefixLength } from './script/builder.js';
import { countRedeemSigOps } from './script/sigops.js';
import {
  multisigRedeemScript,
  p2pkEcdsaScript,
  p2pkScript,
  p2shScript,
  parseMultisigRedeemScript,
} from './script/standard.js';
import type { MultisigOptions } from './script/standard.js';
import type { Outpoint, ScriptPublicKey, UtxoEntry } from './tx/model.js';

/**
 * How an input is unlocked. One union drives the signature-script size
 * estimate, the `sigOpCount`, which keys may sign, and finalisation, so no
 * call site ever branches on chain semantics.
 */
export type Spend =
  /** Single-sig to a 32-byte x-only key. sigOpCount 1. */
  | { kind: 'p2pk'; xOnlyPubkey: Uint8Array }
  /** Single-sig to a 33-byte ECDSA key. sigOpCount 1. Interop only. */
  | { kind: 'p2pk-ecdsa'; pubkey: Uint8Array }
  /**
   * M-of-N P2SH. `pubkeys` in the order they appear in the redeem script
   * (build it with `multisigSpend` to get the sorted SSP convention).
   * sigOpCount = pubkeys.length.
   */
  | {
      kind: 'p2sh-multisig';
      redeem: Uint8Array;
      pubkeys: Uint8Array[];
      m: number;
    }
  /**
   * Arbitrary P2SH script unlocked by one Schnorr signature followed by the
   * redeem push (KRC-20 reveal, covenant branches). `signerPubkey` is the only
   * key allowed to sign it.
   */
  | { kind: 'p2sh-script'; redeem: Uint8Array; signerPubkey: Uint8Array };

/** A spendable input: where it is, what it locks, and how to unlock it. */
export interface InputPlan {
  outpoint: Outpoint;
  entry: UtxoEntry;
  spend: Spend;
  /** u64, default 0n. */
  sequence?: bigint;
}

/** Build a sorted-key M-of-N spend descriptor (the SSP convention). */
export function multisigSpend(
  pubkeys: readonly Uint8Array[],
  m: number,
  opts: MultisigOptions = {},
): Spend {
  if (opts.ecdsa)
    throw new MultisigConfigError(
      'ECDSA multisig spending is not supported by the signing API',
    );
  const redeem = multisigRedeemScript(pubkeys, m, opts);
  const parsed = parseMultisigRedeemScript(redeem);
  if (!parsed)
    throw new MultisigConfigError(
      'failed to parse the generated redeem script',
    );
  return { kind: 'p2sh-multisig', redeem, pubkeys: parsed.pubkeys, m };
}

/** The locking script a spend descriptor unlocks. */
export function spendScriptPublicKey(spend: Spend): ScriptPublicKey {
  switch (spend.kind) {
    case 'p2pk':
      return p2pkScript(spend.xOnlyPubkey);
    case 'p2pk-ecdsa':
      return p2pkEcdsaScript(spend.pubkey);
    case 'p2sh-multisig':
    case 'p2sh-script':
      return p2shScript(spend.redeem);
  }
}

/** The `sigOpCount` consensus expects for this spend (v0). */
export function spendSigOpCount(spend: Spend): number {
  switch (spend.kind) {
    case 'p2pk':
    case 'p2pk-ecdsa':
      return 1;
    case 'p2sh-multisig':
      return spend.pubkeys.length;
    case 'p2sh-script':
      return countRedeemSigOps(spend.redeem);
  }
}

/** One signature push: OpData65 ‖ 64-byte signature ‖ sighash type. */
export const SIGNATURE_PUSH_SIZE = 66;

/**
 * Exact signature-script length for this spend once signed. Kaspa signatures
 * are fixed-width, so mass computed before signing equals mass after.
 */
export function spendSignatureScriptSize(spend: Spend): number {
  switch (spend.kind) {
    case 'p2pk':
    case 'p2pk-ecdsa':
      return SIGNATURE_PUSH_SIZE;
    case 'p2sh-multisig':
      return (
        spend.m * SIGNATURE_PUSH_SIZE +
        pushPrefixLength(spend.redeem.length) +
        spend.redeem.length
      );
    case 'p2sh-script':
      return (
        SIGNATURE_PUSH_SIZE +
        pushPrefixLength(spend.redeem.length) +
        spend.redeem.length
      );
  }
}

/** Keys allowed to sign this spend (x-only, 32 bytes). */
export function spendSigningKeys(spend: Spend): Uint8Array[] {
  switch (spend.kind) {
    case 'p2pk':
      return [spend.xOnlyPubkey];
    case 'p2pk-ecdsa':
      return [];
    case 'p2sh-multisig':
      return spend.pubkeys;
    case 'p2sh-script':
      return [spend.signerPubkey];
  }
}

/**
 * Validate a descriptor's internal consistency: for multisig, `pubkeys` and
 * `m` must be exactly what the redeem script encodes, in the same order.
 */
export function validateSpend(spend: Spend): void {
  switch (spend.kind) {
    case 'p2pk':
      assertXOnlyPublicKey(spend.xOnlyPubkey, 'p2pk key');
      return;
    case 'p2pk-ecdsa':
      if (!isValidCompressedPublicKey(spend.pubkey))
        throw invalidInput('p2pk-ecdsa key is not a valid compressed key');
      return;
    case 'p2sh-script':
      assertXOnlyPublicKey(spend.signerPubkey, 'p2sh-script signer key');
      // A malformed script scans as 0 sigops, which would declare a zero
      // budget and make the input unspendable at execution time.
      if (countRedeemSigOps(spend.redeem) === 0)
        throw invalidInput(
          'p2sh-script redeem script contains no signature check',
        );
      return;
    case 'p2sh-multisig': {
      if (spend.pubkeys.length > MAX_STANDARD_P2SH_SIG_OPS)
        throw new MultisigConfigError(
          `non-standard multisig: ${spend.pubkeys.length} keys (the mempool relays at most ${MAX_STANDARD_P2SH_SIG_OPS})`,
        );
      const parsed = parseMultisigRedeemScript(spend.redeem);
      if (!parsed || parsed.ecdsa)
        throw new MultisigConfigError(
          'redeem script is not a Schnorr multisig script',
        );
      if (
        parsed.m !== spend.m ||
        parsed.pubkeys.length !== spend.pubkeys.length
      ) {
        throw new MultisigConfigError(
          'm or key count disagrees with the redeem script',
        );
      }
      parsed.pubkeys.forEach((k, i) => {
        const given = spend.pubkeys[i];
        if (!given || !equalBytes(k, given)) {
          throw new MultisigConfigError(
            'public keys disagree with the redeem script order',
          );
        }
      });
      return;
    }
  }
}

/**
 * Stricter check for a script that will **receive** funds (change and
 * consolidation outputs): besides `validateSpend`, a multisig must be one
 * the library would build itself — every key a curve point, no duplicates,
 * at most 15 keys — so change can never be locked where it cannot be spent.
 */
export function validateReceivingSpend(spend: Spend): void {
  validateSpend(spend);
  if (spend.kind === 'p2sh-multisig') {
    const rebuilt = multisigRedeemScript(spend.pubkeys, spend.m, {
      sort: false,
    });
    if (!equalBytes(rebuilt, spend.redeem))
      throw new MultisigConfigError('multisig redeem script is not canonical');
  }
}

/** Assert that the descriptor is consistent and unlocks the UTXO it is attached to. */
export function assertSpendMatchesEntry(plan: InputPlan): void {
  validateSpend(plan.spend);
  const expected = spendScriptPublicKey(plan.spend);
  const actual = plan.entry.scriptPublicKey;
  if (
    expected.version !== actual.version ||
    !equalBytes(expected.script, actual.script)
  ) {
    throw invalidInput(
      `spend descriptor does not match the script public key of outpoint index ${plan.outpoint.index}`,
    );
  }
}

export const DEFAULT_SIGHASH_TYPE = SIG_HASH_ALL;

/**
 * Minimum version 1 compute budget for this spend:
 * `ceil(max(0, 100,000 × sigops + 2 × redeemLen − 9,999) / 10,000)` — one
 * 100,000-unit charge per signature check (the worst case for multisig is one
 * per key, when the signers sit last in script order), 2 units per byte for
 * the P2SH `OP_BLAKE2B` over the redeem script, minus the free per-input
 * allowance. Verified against rusty-kaspa's engine for every M-of-N up to 15
 * and inscription scripts up to 50 KB: this value passes and one less fails.
 * Custom `p2sh-script` redeem scripts that execute hashing opcodes of their
 * own need an explicit budget.
 */
export function spendComputeBudget(spend: Spend): number {
  const sigops = BigInt(spendSigOpCount(spend));
  const redeemLen =
    spend.kind === 'p2sh-multisig' || spend.kind === 'p2sh-script'
      ? BigInt(spend.redeem.length)
      : 0n;
  let units =
    sigops * SIGOP_SCRIPT_UNITS + redeemLen * BLAKE2B_SCRIPT_UNITS_PER_BYTE;
  units =
    units > FREE_SCRIPT_UNITS_PER_INPUT
      ? units - FREE_SCRIPT_UNITS_PER_INPUT
      : 0n;
  const budget =
    (units + SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT - 1n) /
    SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT;
  if (budget > BigInt(MAX_COMPUTE_BUDGET))
    throw invalidInput('spend exceeds the maximum compute budget');
  return Number(budget);
}
