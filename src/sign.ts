import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, equalBytes, hexToBytes, utf8 } from './bytes.js';
import {
  ALLOWED_SIG_HASH_TYPES,
  DEFAULT_MAX_FEE,
  SIG_HASH_ALL,
  SIG_HASH_MASK,
  SIG_HASH_SINGLE,
  TX_VERSION_TOCCATA,
} from './constants.js';
import {
  EntryMismatchError,
  FeeTooHighError,
  IncompleteSignaturesError,
  InvalidTransactionError,
  SignatureError,
  invalidInput,
} from './errors.js';
import { blake2bDomain } from './hash.js';
import { Op } from './script/opcodes.js';
import { p2shSignatureScript } from './script/standard.js';
import { SighashContext } from './sighash.js';
import {
  assertSpendMatchesEntry,
  spendComputeBudget,
  spendSigOpCount,
  spendSigningKeys,
} from './spend.js';
import type { InputPlan } from './spend.js';
import { isNativeSubnetwork, nativeSubnetworkId } from './tx/model.js';
import type {
  Outpoint,
  ScriptPublicKey,
  Transaction,
  TransactionOutput,
  UtxoEntry,
} from './tx/model.js';
import { validateTransactionStructure } from './tx/validate.js';
import { transactionId } from './tx/encode.js';
import {
  inputPlanFromJson,
  inputPlanToJson,
  transactionFromJson,
  transactionToJson,
} from './tx/json.js';
import type { InputPlanJson, TransactionJson } from './tx/json.js';

/**
 * A signer is anything that can produce a BIP340 signature over a 32-byte
 * digest for one x-only key. The library never sees a seed or private key
 * through this interface: a local key, a hardware wallet (Ledger APDU) or a
 * secure enclave all fit, which is why `signDigest` may be async.
 *
 * Never implement a signer as "send the digest to the other device and sign
 * whatever arrives": a blind remote digest signer defeats review. A co-signing
 * device must receive the whole `SigningBundle` and recompute every digest
 * itself.
 */
export interface KaspaSigner {
  /** 32-byte x-only public key. */
  readonly xOnlyPublicKey: Uint8Array;
  /** 64-byte BIP340 Schnorr signature over `digest`. */
  signDigest(digest: Uint8Array): Uint8Array | Promise<Uint8Array>;
  /**
   * Informational. `signTransaction` skips its own verification only for
   * signers created by `localSigner` (tracked internally, not by this flag),
   * whose `schnorr.sign` already verifies its output; every other signer's
   * output is verified, and `finalizeTransaction` re-verifies all partials.
   */
  readonly selfVerifying?: boolean;
}

export interface LocalSignerOptions {
  /**
   * Use 32 zero bytes of auxiliary randomness — identical to libsecp256k1's
   * `sign_schnorr_no_aux_rand` and rusty-kaspa's `no_aux_rand`. Default false
   * (fresh randomness per signature, as BIP340 recommends).
   */
  deterministic?: boolean;
}

/** A `KaspaSigner` holding a private key in memory. */
export interface LocalSigner extends KaspaSigner {
  /**
   * Zero-fill this signer's copy of the key and refuse further signing.
   * Best effort: JavaScript cannot guarantee no other copy exists.
   */
  destroy(): void;
}

/** A signer over a raw 32-byte secp256k1 private key (copied; the caller may wipe theirs). */
export function localSigner(
  privateKey: Uint8Array,
  opts: LocalSignerOptions = {},
): LocalSigner {
  const key = Uint8Array.from(checkedPrivateKey(privateKey));
  const xOnlyPublicKey = publicKeyOf(key);
  const aux = opts.deterministic ? new Uint8Array(32) : undefined;
  let destroyed = false;
  const signer: LocalSigner = {
    xOnlyPublicKey,
    // BIP340 derives the nonce from the key, the digest and fresh auxiliary
    // randomness, so a nonce is never reused across digests; noble's
    // schnorr.sign also verifies the signature it produces before returning,
    // so a faulted computation cannot release a key-revealing signature.
    signDigest: (digest: Uint8Array) => {
      if (destroyed) throw invalidInput('signer was destroyed');
      if (!(digest instanceof Uint8Array) || digest.length !== 32)
        throw invalidInput('digest must be a 32-byte Uint8Array');
      return schnorr.sign(digest, key, aux);
    },
    selfVerifying: true,
    destroy: () => {
      destroyed = true;
      key.fill(0);
    },
  };
  VERIFIED_SIGNERS.add(signer);
  return Object.freeze(signer);
}

/** Signers whose `signDigest` is known to verify its own output. */
const VERIFIED_SIGNERS = new WeakSet<KaspaSigner>();

function checkedPrivateKey(privateKey: Uint8Array): Uint8Array {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32)
    throw invalidInput('private key must be a 32-byte Uint8Array');
  return privateKey;
}

// Never surface the underlying error: it could describe the key.
function publicKeyOf(privateKey: Uint8Array): Uint8Array {
  try {
    return schnorr.getPublicKey(privateKey);
  } catch {
    throw invalidInput('private key out of range');
  }
}

/** x-only public key for a private key. */
export function xOnlyPublicKey(privateKey: Uint8Array): Uint8Array {
  return publicKeyOf(checkedPrivateKey(privateKey));
}

export interface CreateTransactionParams {
  inputs: readonly InputPlan[];
  outputs: readonly TransactionOutput[];
  /** Default 0. */
  version?: number;
  lockTime?: bigint;
  payload?: Uint8Array;
  subnetworkId?: Uint8Array;
  gas?: bigint;
  /**
   * Version 1 only: compute budget per input. Defaults to the exact minimum
   * for each spend (`spendComputeBudget`), verified against the engine.
   */
  computeBudgets?: readonly number[];
}

/**
 * Build an unsigned transaction. `sigOpCount` (v0) and the compute budget (v1)
 * are derived from each input's spend descriptor — never taken from the
 * caller — every descriptor is checked against the UTXO it claims to unlock,
 * and the result is structurally validated.
 */
export function createTransaction(p: CreateTransactionParams): Transaction {
  const version = p.version ?? 0;
  const v1 = version >= TX_VERSION_TOCCATA;
  const tx: Transaction = {
    version,
    inputs: p.inputs.map((plan, i) => {
      assertSpendMatchesEntry(plan);
      const base = {
        previousOutpoint: {
          transactionId: plan.outpoint.transactionId,
          index: plan.outpoint.index,
        },
        signatureScript: new Uint8Array(0),
        sequence: plan.sequence ?? 0n,
        sigOpCount: v1 ? 0 : spendSigOpCount(plan.spend),
      };
      if (!v1) return base;
      const min = spendComputeBudget(plan.spend);
      const budget = p.computeBudgets?.[i] ?? min;
      if (budget < min)
        throw new InvalidTransactionError(
          `input ${i} compute budget ${budget} is below the ${min} its spend needs`,
        );
      return { ...base, computeBudget: budget };
    }),
    outputs: p.outputs.map((o) => ({ ...o })),
    lockTime: p.lockTime ?? 0n,
    subnetworkId: p.subnetworkId ?? nativeSubnetworkId(),
    gas: p.gas ?? 0n,
    payload: p.payload ?? new Uint8Array(0),
  };
  validateTransactionStructure(tx);
  assertHasOutputs(tx);
  return tx;
}

/** One signature over one input by one key. JSON-safe. */
export interface PartialSignature {
  inputIndex: number;
  /** hex, 32-byte x-only key */
  publicKey: string;
  /** hex, 64-byte BIP340 signature */
  signature: string;
  sighashType: number;
}

const HEX64 = /^[0-9a-f]{64}$/i;
const HEX128 = /^[0-9a-f]{128}$/i;

/** Throw unless `p` is a well-formed partial signature (untrusted JSON boundary). */
export function assertPartialSignatureShape(
  p: unknown,
): asserts p is PartialSignature {
  const x = p as Partial<PartialSignature> | null;
  if (
    typeof x !== 'object' ||
    x === null ||
    typeof x.inputIndex !== 'number' ||
    !Number.isInteger(x.inputIndex) ||
    x.inputIndex < 0 ||
    typeof x.publicKey !== 'string' ||
    !HEX64.test(x.publicKey) ||
    typeof x.signature !== 'string' ||
    !HEX128.test(x.signature) ||
    typeof x.sighashType !== 'number' ||
    !ALLOWED_SIG_HASH_TYPES.includes(x.sighashType)
  ) {
    throw new SignatureError('malformed partial signature');
  }
}

/**
 * Sighash policy. Anything other than SIG_HASH_ALL lets outputs (or other
 * inputs) change after signing, so it requires an explicit opt-in, and
 * SIG_HASH_SINGLE on an input with no matching output — which commits to no
 * output at all — is always refused.
 */
function checkSighashType(
  type: number,
  allowNonAll: boolean,
  inputIndex: number,
  outputCount: number,
): void {
  if (!ALLOWED_SIG_HASH_TYPES.includes(type))
    throw new SignatureError('unsupported sighash type');
  if (type !== SIG_HASH_ALL && !allowNonAll)
    throw new SignatureError(
      'only SIG_HASH_ALL is accepted unless allowNonAllSighash is set',
    );
  if ((type & SIG_HASH_MASK) === SIG_HASH_SINGLE && inputIndex >= outputCount)
    throw new SignatureError(
      'SIG_HASH_SINGLE on an input without a matching output commits to nothing',
    );
}

/**
 * Consensus allows a transaction without outputs; a wallet never wants one —
 * every input would go to the fee.
 */
function assertHasOutputs(tx: Transaction): void {
  if (tx.outputs.length === 0)
    throw new InvalidTransactionError(
      'transaction has no outputs: all input value would be burned as fee',
    );
}

function assertInputsMatch(
  tx: Transaction,
  inputs: readonly InputPlan[],
): void {
  validateTransactionStructure(tx);
  assertHasOutputs(tx);
  if (tx.inputs.length !== inputs.length) {
    throw new InvalidTransactionError(
      'one input plan is required per transaction input',
    );
  }
  const v1 = tx.version >= TX_VERSION_TOCCATA;
  tx.inputs.forEach((ti, i) => {
    const plan = inputs[i];
    if (!plan) throw new InvalidTransactionError(`missing input plan ${i}`);
    assertSpendMatchesEntry(plan);
    if (
      !equalBytes(
        ti.previousOutpoint.transactionId,
        plan.outpoint.transactionId,
      ) ||
      ti.previousOutpoint.index !== plan.outpoint.index
    ) {
      throw new InvalidTransactionError(
        `input ${i} outpoint does not match its plan`,
      );
    }
    // Compute budgets are not committed to by the signature hash, so a relay
    // could lower one after signing; enforce the spend's floor everywhere.
    if (v1 && (ti.computeBudget ?? 0) < spendComputeBudget(plan.spend)) {
      throw new InvalidTransactionError(
        `input ${i} compute budget ${ti.computeBudget ?? 0} is below the ${spendComputeBudget(plan.spend)} its spend needs`,
      );
    }
    if (!v1 && ti.sigOpCount !== spendSigOpCount(plan.spend)) {
      throw new InvalidTransactionError(
        `input ${i} declares sigOpCount ${ti.sigOpCount} but its spend requires ${spendSigOpCount(plan.spend)}`,
      );
    }
  });
}

function entriesOf(inputs: readonly InputPlan[]) {
  return inputs.map((p) => p.entry);
}

export interface SignOptions {
  /** Default SIG_HASH_ALL. */
  sighashType?: number;
  /** Required to sign with any type other than SIG_HASH_ALL. */
  allowNonAllSighash?: boolean;
  /**
   * Refuse to sign unless **every** input spends one of these scripts.
   * A co-signer (SSP Key) must pass the vault script(s) the user is approving:
   * otherwise a malicious proposer could add inputs from another script the
   * same key belongs to, and the key would sign them too.
   */
  onlyScripts?: readonly ScriptPublicKey[];
  /**
   * Refuse to sign if the fee (inputs − outputs, from the entries given)
   * exceeds this. Default `DEFAULT_MAX_FEE` (5 KAS).
   */
  maxFee?: bigint;
  /**
   * Durable per-outpoint record of the amount this device signed with.
   * Kaspa's signature hash commits only to the input being signed's own
   * amount, so a lying co-signer or UTXO source can collect signatures for
   * different inputs across separate sessions — each claiming a different
   * input is small — and combine them into one transaction with a huge real
   * fee. With a ledger, re-signing an outpoint under a different amount is
   * refused. SSP Key should persist one.
   */
  signedAmounts?: SignedAmountLedger;
}

/** Storage for `SignOptions.signedAmounts`; keys are `txidhex:index`. */
export interface SignedAmountLedger {
  get(outpoint: string): bigint | undefined | Promise<bigint | undefined>;
  set(outpoint: string, amount: bigint): void | Promise<void>;
}

function outpointKey(plan: InputPlan): string {
  return `${bytesToHex(plan.outpoint.transactionId)}:${String(plan.outpoint.index)}`;
}

function sameScript(a: ScriptPublicKey, b: ScriptPublicKey): boolean {
  return a.version === b.version && equalBytes(a.script, b.script);
}

/**
 * Sign every input each signer is entitled to sign. Refuses transactions whose
 * outputs exceed their inputs, enforces the sighash policy and the optional
 * input allowlist, and verifies each signature before returning it (unless the
 * signer already did), so a faulty signer or transport cannot hand an invalid
 * signature to the co-signer.
 */
export async function signTransaction(
  tx: Transaction,
  inputs: readonly InputPlan[],
  signers: readonly KaspaSigner[],
  opts: SignOptions = {},
): Promise<PartialSignature[]> {
  const sighashType = opts.sighashType ?? SIG_HASH_ALL;
  const allowNonAll = opts.allowNonAllSighash ?? false;
  assertInputsMatch(tx, inputs);
  const totalIn = inputs.reduce((a, p) => a + p.entry.amount, 0n);
  const totalOut = tx.outputs.reduce((a, o) => a + o.value, 0n);
  if (totalOut > totalIn)
    throw new InvalidTransactionError('outputs exceed inputs');
  const maxFee = opts.maxFee ?? DEFAULT_MAX_FEE;
  if (totalIn - totalOut > maxFee)
    throw new FeeTooHighError(totalIn - totalOut, maxFee);
  if (opts.onlyScripts) {
    const allowed = opts.onlyScripts;
    inputs.forEach((plan, i) => {
      if (!allowed.some((s) => sameScript(s, plan.entry.scriptPublicKey)))
        throw new SignatureError(
          `input ${i} spends a script outside the approved set`,
        );
    });
  }
  const ledger = opts.signedAmounts;
  if (ledger) {
    for (let i = 0; i < inputs.length; i++) {
      const plan = inputs[i] as InputPlan;
      const seen = await ledger.get(outpointKey(plan));
      if (seen !== undefined && seen !== plan.entry.amount)
        throw new EntryMismatchError(
          i,
          'this device already signed this outpoint with a different amount',
        );
    }
  }
  const ctx = new SighashContext(tx, entriesOf(inputs));
  const out: PartialSignature[] = [];
  for (let i = 0; i < inputs.length; i++) {
    const plan = inputs[i];
    if (!plan) continue;
    if (plan.spend.kind === 'p2pk-ecdsa') {
      throw new SignatureError(
        'ECDSA inputs are not supported by the signing API',
      );
    }
    const keys = spendSigningKeys(plan.spend);
    for (const signer of signers) {
      if (!keys.some((k) => equalBytes(k, signer.xOnlyPublicKey))) continue;
      checkSighashType(sighashType, allowNonAll, i, tx.outputs.length);
      const digest = ctx.schnorr(i, sighashType);
      const sig = await signer.signDigest(digest);
      if (
        !(sig instanceof Uint8Array) ||
        sig.length !== 64 ||
        (!VERIFIED_SIGNERS.has(signer) &&
          !schnorr.verify(sig, digest, signer.xOnlyPublicKey))
      ) {
        throw new SignatureError(
          `signer produced an invalid signature for input ${i}`,
        );
      }
      out.push({
        inputIndex: i,
        publicKey: bytesToHex(signer.xOnlyPublicKey),
        signature: bytesToHex(sig),
        sighashType,
      });
    }
  }
  if (ledger && out.length > 0)
    for (const plan of inputs)
      await ledger.set(outpointKey(plan), plan.entry.amount);
  return out;
}

export interface VerifyOptions {
  /** Accept partials signed with a type other than SIG_HASH_ALL. */
  allowNonAllSighash?: boolean;
}

/** True if `partial` is a well-formed, valid signature by an entitled key over its input. */
export function verifyPartialSignature(
  tx: Transaction,
  inputs: readonly InputPlan[],
  partial: PartialSignature,
  ctx: SighashContext = new SighashContext(tx, entriesOf(inputs)),
  opts: VerifyOptions = {},
): boolean {
  try {
    assertPartialSignatureShape(partial);
    const plan = inputs[partial.inputIndex];
    if (!plan) return false;
    checkSighashType(
      partial.sighashType,
      opts.allowNonAllSighash ?? false,
      partial.inputIndex,
      tx.outputs.length,
    );
    const key = hexToBytes(partial.publicKey);
    if (!spendSigningKeys(plan.spend).some((k) => equalBytes(k, key)))
      return false;
    return schnorr.verify(
      hexToBytes(partial.signature),
      ctx.schnorr(partial.inputIndex, partial.sighashType),
      key,
    );
  } catch {
    return false;
  }
}

function signaturePush(sigHex: string, sighashType: number): Uint8Array {
  const push = new Uint8Array(66);
  push[0] = Op.OpData65;
  push.set(hexToBytes(sigHex), 1);
  push[65] = sighashType;
  return push;
}

export interface FinalizeResult {
  tx: Transaction;
  /** Inputs that still lack signatures (empty when complete). */
  missing: { inputIndex: number; have: number; need: number }[];
}

/**
 * Assemble signature scripts. Every partial is re-verified against a fresh
 * signature hash; an invalid partial is an error, never silently dropped —
 * a co-signer that sends garbage should be noticed. For multisig, exactly
 * `m` signatures are emitted **in the order their keys appear in the redeem
 * script**: the engine walks signatures against keys and may skip keys but
 * never reorder, and a mismatch is a hard NullFail.
 */
export function assembleTransaction(
  tx: Transaction,
  inputs: readonly InputPlan[],
  partials: readonly PartialSignature[],
  opts: VerifyOptions = {},
): FinalizeResult {
  assertInputsMatch(tx, inputs);
  const ctx = new SighashContext(tx, entriesOf(inputs));
  for (const p of partials) {
    if (!verifyPartialSignature(tx, inputs, p, ctx, opts)) {
      throw new SignatureError(
        `invalid partial signature for input ${String((p as Partial<PartialSignature>).inputIndex)}`,
      );
    }
  }
  const missing: FinalizeResult['missing'] = [];
  const signed = tx.inputs.map((ti, i) => {
    const plan = inputs[i];
    if (!plan) throw new InvalidTransactionError(`missing input plan ${i}`);
    const mine = partials.filter((p) => p.inputIndex === i);
    const byKey = (key: Uint8Array) =>
      mine.find((p) => equalBytes(hexToBytes(p.publicKey), key));
    let signatureScript: Uint8Array = new Uint8Array(0);
    const spend = plan.spend;
    switch (spend.kind) {
      case 'p2pk': {
        const p = byKey(spend.xOnlyPubkey);
        if (p) signatureScript = signaturePush(p.signature, p.sighashType);
        else missing.push({ inputIndex: i, have: 0, need: 1 });
        break;
      }
      case 'p2sh-script': {
        const p = byKey(spend.signerPubkey);
        if (p)
          signatureScript = p2shSignatureScript(spend.redeem, [
            signaturePush(p.signature, p.sighashType),
          ]);
        else missing.push({ inputIndex: i, have: 0, need: 1 });
        break;
      }
      case 'p2sh-multisig': {
        const pushes: Uint8Array[] = [];
        for (const key of spend.pubkeys) {
          if (pushes.length === spend.m) break;
          const p = byKey(key);
          if (p) pushes.push(signaturePush(p.signature, p.sighashType));
        }
        if (pushes.length === spend.m)
          signatureScript = p2shSignatureScript(spend.redeem, pushes);
        else
          missing.push({ inputIndex: i, have: pushes.length, need: spend.m });
        break;
      }
      case 'p2pk-ecdsa':
        throw new SignatureError(
          'ECDSA inputs are not supported by the signing API',
        );
    }
    return { ...ti, signatureScript };
  });
  return { tx: { ...tx, inputs: signed }, missing };
}

/** Like `assembleTransaction`, but throws unless every input is fully signed. */
export function finalizeTransaction(
  tx: Transaction,
  inputs: readonly InputPlan[],
  partials: readonly PartialSignature[],
  opts: VerifyOptions = {},
): Transaction {
  const r = assembleTransaction(tx, inputs, partials, opts);
  if (r.missing.length > 0) {
    const detail = r.missing
      .map((m) => `input ${m.inputIndex}: ${m.have}/${m.need}`)
      .join(', ');
    throw new IncompleteSignaturesError(
      `transaction is not fully signed (${detail})`,
    );
  }
  return r.tx;
}

/**
 * Everything a co-signer needs, JSON-safe, to recompute every signature hash
 * independently and add its own signatures.
 */
export interface SigningBundle {
  format: 'kaspa-core-signing-bundle';
  version: 1;
  tx: TransactionJson;
  inputs: InputPlanJson[];
  partials: PartialSignature[];
}

export function createSigningBundle(
  tx: Transaction,
  inputs: readonly InputPlan[],
  partials: readonly PartialSignature[] = [],
): SigningBundle {
  assertInputsMatch(tx, inputs);
  partials.forEach(assertPartialSignatureShape);
  return {
    format: 'kaspa-core-signing-bundle',
    version: 1,
    tx: transactionToJson(tx),
    inputs: inputs.map(inputPlanToJson),
    partials: [...partials],
  };
}

/**
 * What a bundle from another device may contain. Everything defaults to
 * **false**: a plain version 0, native-subnetwork transaction with no
 * payload, no lock time and zero sequences — what SSP vault spends are. A
 * compromised proposer or relay cannot slip a lane, payload or time-locked
 * transaction past a co-signer whose UI only shows outputs.
 */
export interface BundlePolicy {
  allowVersion1?: boolean;
  allowPayload?: boolean;
  allowNonNativeSubnetwork?: boolean;
  allowLockTime?: boolean;
  allowNonZeroSequence?: boolean;
  /** Version 1 covenant outputs. */
  allowCovenants?: boolean;
  /** Fee ceiling for the bundle, from the entries in force. Default `DEFAULT_MAX_FEE`. */
  maxFee?: bigint;
}

export function assertTransactionPolicy(
  tx: Transaction,
  policy: BundlePolicy = {},
): void {
  const deny = (m: string): never => {
    throw new InvalidTransactionError(`bundle policy: ${m}`);
  };
  if (tx.version !== 0 && !policy.allowVersion1)
    deny('version 1 transactions are not allowed');
  if (tx.payload.length > 0 && !policy.allowPayload)
    deny('payloads are not allowed');
  if (!isNativeSubnetwork(tx.subnetworkId) && !policy.allowNonNativeSubnetwork)
    deny('non-native subnetworks are not allowed');
  if (tx.lockTime !== 0n && !policy.allowLockTime)
    deny('lock times are not allowed');
  if (tx.inputs.some((i) => i.sequence !== 0n) && !policy.allowNonZeroSequence)
    deny('non-zero sequences are not allowed');
  if (tx.outputs.some((o) => o.covenant) && !policy.allowCovenants)
    deny('covenant outputs are not allowed');
}

/**
 * Replace the entries a bundle *claims* with entries the co-signer fetched
 * itself, failing loudly on any disagreement. Amount and previous script are
 * committed to by the signature hash; trusting them from the other device is
 * the lever for a malicious-amount attack.
 */
export function assertEntriesMatch(
  inputs: readonly InputPlan[],
  trusted: readonly UtxoEntry[],
): InputPlan[] {
  if (trusted.length !== inputs.length)
    throw new EntryMismatchError(
      -1,
      'trusted entries do not cover every input',
    );
  return inputs.map((plan, i) => {
    const t = trusted[i] as UtxoEntry;
    if (t.amount !== plan.entry.amount)
      throw new EntryMismatchError(i, 'amount differs from the UTXO index');
    if (!sameScript(t.scriptPublicKey, plan.entry.scriptPublicKey))
      throw new EntryMismatchError(
        i,
        'script public key differs from the UTXO index',
      );
    const next: InputPlan = { ...plan, entry: t };
    assertSpendMatchesEntry(next);
    return next;
  });
}

export interface OpenBundleOptions {
  /**
   * Entries fetched independently by this device, in input order. When given
   * (and a co-signer should always give them), the bundle's claimed entries
   * must match exactly and are replaced by these.
   */
  trustedEntries?: readonly UtxoEntry[];
  /**
   * The same guarantee, but in the shape a UTXO lookup returns (e.g. REST
   * `getUtxos` for the vault address): matched to the bundle's inputs by
   * outpoint. An input absent from this device's own lookup — spent, or never
   * existed — is an `EntryMismatchError`.
   */
  trustedUtxos?: readonly { outpoint: Outpoint; entry: UtxoEntry }[];
  /**
   * The strongest source: the transactions that created each input. Each is
   * identified by recomputing its ID, which commits to its outputs' values and
   * scripts, so the amounts are proven without trusting any server. See
   * `entriesFromFundingTransactions`.
   */
  fundingTransactions?: readonly Transaction[];
  /**
   * Accept the amounts the bundle claims, with no independent source. Never
   * for a co-signer: the fee could be anything.
   */
  trustBundleEntries?: boolean;
  policy?: BundlePolicy;
}

/**
 * Entries proven by the transactions that created them: an input's funding
 * transaction is found by recomputing transaction IDs, and its output at the
 * input's index supplies the amount and script. A server cannot forge this
 * without breaking the hash.
 */
export function entriesFromFundingTransactions(
  inputs: readonly InputPlan[],
  funding: readonly Transaction[],
): UtxoEntry[] {
  const byId = new Map<string, Transaction>();
  for (const t of funding) byId.set(bytesToHex(transactionId(t)), t);
  return inputs.map((plan, i) => {
    const prev = byId.get(bytesToHex(plan.outpoint.transactionId));
    if (!prev)
      throw new EntryMismatchError(i, 'funding transaction not provided');
    const out = prev.outputs[plan.outpoint.index];
    if (!out)
      throw new EntryMismatchError(i, 'funding transaction has no such output');
    return {
      amount: out.value,
      scriptPublicKey: out.scriptPublicKey,
      blockDaaScore: plan.entry.blockDaaScore,
      isCoinbase: plan.entry.isCoinbase,
    };
  });
}

/** Align an unordered UTXO lookup to `inputs` by outpoint. */
export function entriesForInputs(
  inputs: readonly InputPlan[],
  utxos: readonly { outpoint: Outpoint; entry: UtxoEntry }[],
): UtxoEntry[] {
  return inputs.map((plan, i) => {
    const hit = utxos.find(
      (u) =>
        u.outpoint.index === plan.outpoint.index &&
        equalBytes(u.outpoint.transactionId, plan.outpoint.transactionId),
    );
    if (!hit)
      throw new EntryMismatchError(
        i,
        "not found in this device's own UTXO lookup (spent or never existed)",
      );
    return hit.entry;
  });
}

export function openSigningBundle(
  bundle: SigningBundle,
  opts: OpenBundleOptions = {},
): {
  tx: Transaction;
  inputs: InputPlan[];
  partials: PartialSignature[];
} {
  if (
    typeof bundle !== 'object' ||
    bundle === null ||
    bundle.format !== 'kaspa-core-signing-bundle' ||
    bundle.version !== 1 ||
    !Array.isArray(bundle.inputs) ||
    !Array.isArray(bundle.partials)
  ) {
    throw invalidInput('unsupported signing bundle');
  }
  const tx = transactionFromJson(bundle.tx);
  let inputs = bundle.inputs.map(inputPlanFromJson);
  assertInputsMatch(tx, inputs);
  assertTransactionPolicy(tx, opts.policy);
  if (
    !opts.trustedEntries &&
    !opts.trustedUtxos &&
    !opts.fundingTransactions &&
    opts.trustBundleEntries !== true
  )
    throw new EntryMismatchError(
      -1,
      'no independent source for the input amounts: pass trustedUtxos, trustedEntries or fundingTransactions',
    );
  if (opts.trustedEntries)
    inputs = assertEntriesMatch(inputs, opts.trustedEntries);
  if (opts.trustedUtxos)
    inputs = assertEntriesMatch(
      inputs,
      entriesForInputs(inputs, opts.trustedUtxos),
    );
  if (opts.fundingTransactions)
    inputs = assertEntriesMatch(
      inputs,
      entriesFromFundingTransactions(inputs, opts.fundingTransactions),
    );
  const totalIn = inputs.reduce((a, p) => a + p.entry.amount, 0n);
  const totalOut = tx.outputs.reduce((a, o) => a + o.value, 0n);
  if (totalOut > totalIn)
    throw new InvalidTransactionError('outputs exceed inputs');
  const maxFee = opts.policy?.maxFee ?? DEFAULT_MAX_FEE;
  if (totalIn - totalOut > maxFee)
    throw new FeeTooHighError(totalIn - totalOut, maxFee);
  bundle.partials.forEach(assertPartialSignatureShape);
  return { tx, inputs, partials: [...bundle.partials] };
}

/**
 * Merge partial-signature sets, de-duplicating by (input, key). **The first
 * occurrence wins**, so merge local signatures first: a later duplicate from
 * a remote device can never displace a valid local one.
 */
export function mergePartialSignatures(
  ...sets: readonly (readonly PartialSignature[])[]
): PartialSignature[] {
  const seen = new Map<string, PartialSignature>();
  for (const set of sets) {
    for (const p of set) {
      assertPartialSignatureShape(p);
      const k = `${String(p.inputIndex)}:${p.publicKey.toLowerCase()}`;
      if (!seen.has(k)) seen.set(k, p);
    }
  }
  return [...seen.values()];
}

// ---------------------------------------------------------------------------
// Personal message signing (`wallet/core/src/message.rs`)
// ---------------------------------------------------------------------------

function messageBytes(message: string | Uint8Array): Uint8Array {
  return typeof message === 'string' ? utf8(message) : message;
}

/** keyed blake2b-256 `PersonalMessageSigningHash` over the raw message bytes. */
export function personalMessageHash(message: string | Uint8Array): Uint8Array {
  return blake2bDomain('PersonalMessageSigningHash', messageBytes(message));
}

export async function signMessage(
  message: string | Uint8Array,
  signer: KaspaSigner,
): Promise<Uint8Array> {
  const digest = personalMessageHash(message);
  const sig = await signer.signDigest(digest);
  if (
    !(sig instanceof Uint8Array) ||
    sig.length !== 64 ||
    !schnorr.verify(sig, digest, signer.xOnlyPublicKey)
  )
    throw new SignatureError('signer produced an invalid signature');
  return sig;
}

export function verifyMessage(
  message: string | Uint8Array,
  signature: Uint8Array,
  xOnlyPubkey: Uint8Array,
): boolean {
  try {
    return schnorr.verify(signature, personalMessageHash(message), xOnlyPubkey);
  } catch {
    return false;
  }
}
