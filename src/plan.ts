import {
  COINBASE_MATURITY,
  DEFAULT_MAX_FEE,
  DEFAULT_MAX_FEE_RATE,
  MAX_SOMPI,
  MAX_TX_INPUTS,
  MAXIMUM_STANDARD_TRANSACTION_MASS,
  TX_VERSION_TOCCATA,
} from './constants.js';
import { equalBytes } from './bytes.js';
import {
  ChangeWouldBeDustError,
  FeeTooHighError,
  InsufficientFundsError,
  InvalidScriptError,
  InvalidTransactionError,
  MassCapExceededError,
  NeedsConsolidationError,
  invalidInput,
} from './errors.js';
import { isValidCompressedPublicKey, isValidXOnlyPublicKey } from './keys.js';
import { feeForRate, massBreakdown, minimumRelayFee } from './mass.js';
import type { MassBreakdown } from './mass.js';
import { classifyScript } from './script/standard.js';
import {
  assertSpendMatchesEntry,
  spendComputeBudget,
  spendScriptPublicKey,
  spendSigOpCount,
  spendSignatureScriptSize,
  validateReceivingSpend,
} from './spend.js';
import type { InputPlan, Spend } from './spend.js';
import { transactionId } from './tx/encode.js';
import { nativeSubnetworkId } from './tx/model.js';
import type {
  Outpoint,
  ScriptPublicKey,
  Transaction,
  TransactionOutput,
} from './tx/model.js';
import { validateTransactionStructure } from './tx/validate.js';

export interface Recipient {
  scriptPublicKey: ScriptPublicKey;
  /** Sompi, > 0. Ignored for `sendAll`. */
  amount: bigint;
}

export interface PlanOptions {
  /** Sompi per gram, typically from `/info/fee-estimate`. Minimum 1. */
  feeRate: bigint;
  /** How change (and consolidation outputs) will be locked and later spent. */
  changeSpend: Spend;
  /**
   * Current virtual DAA score, required to spend coinbase outputs (maturity is
   * 1,000 DAA at 10 blocks per second). If omitted, **all** coinbase UTXOs are skipped rather than
   * risking an immature spend.
   */
  virtualDaaScore?: bigint;
  /** Outpoints already committed to in-flight transactions. */
  exclude?: readonly Outpoint[];
  /** Default 100,000 grams (wallet-standard cap). */
  maxMass?: bigint;
  /**
   * Change below this is folded into the fee. Default: what spending the
   * change later as one more input would cost at `feeRate` — change worth
   * less than that is dust. KIP-9 storage mass is priced separately (a change
   * output that would make the transaction more expensive than it is worth,
   * or exceed the mass cap, is folded regardless).
   */
  changeFoldThreshold?: bigint;
  /**
   * Never fold more than this into the fee — throw instead of silently burning
   * the user's money. Default 100,000,000 sompi (1 KAS).
   */
  maxFoldToFee?: bigint;
  /**
   * Per-transaction fee ceiling (default 5 KAS). A safety rail against an
   * untrusted fee source; exceeding it throws `FeeTooHighError`.
   */
  maxFee?: bigint;
  /** Reject a fee rate above this (default 10,000 sompi/gram, ~100× the network floor). */
  maxFeeRate?: bigint;
  /** `largest-first` (default) or `smallest-first` to sweep dust deliberately. */
  strategy?: 'largest-first' | 'smallest-first';
  /** Spend everything to a single recipient; no change output. */
  sendAll?: boolean;
  /** Allow a compounding chain when one transaction cannot fit (default true). */
  allowChain?: boolean;
  /**
   * Inputs that must be spent by the final transaction, first and in order —
   * e.g. the P2SH commit output a KRC-20 reveal spends. Further inputs are
   * selected from `utxos` to cover the rest.
   */
  requiredInputs?: readonly InputPlan[];
  payload?: Uint8Array;
  /**
   * Final transaction version: 0 (default) or 1 (Toccata). Version 1 inputs
   * get the exact minimum compute budget for their spend. Consolidation
   * stages are always plain version 0.
   */
  txVersion?: 0 | 1;
  /** Version 1 lane subnetwork id for the final transaction (e.g. Igra). */
  subnetworkId?: Uint8Array;
  /** Version 1 lane gas for the final transaction. */
  gas?: bigint;
}

export interface PlannedTransaction {
  tx: Transaction;
  inputs: InputPlan[];
  fee: bigint;
  mass: MassBreakdown;
  /** Index of the change output, if any. */
  changeIndex?: number;
  /** Transaction ID — known before signing. */
  id: Uint8Array;
}

export interface Plan {
  /** Consolidation transactions to sign and broadcast first, in order. May be empty. */
  stages: PlannedTransaction[];
  final: PlannedTransaction;
  totalFee: bigint;
}

interface Resolved {
  feeRate: bigint;
  changeSpk: ScriptPublicKey;
  changeSpend: Spend;
  maxMass: bigint;
  foldThreshold: bigint;
  maxFold: bigint;
  maxFee: bigint;
  payload: Uint8Array;
  version: 0 | 1;
  subnetworkId: Uint8Array;
  gas: bigint;
  required: InputPlan[];
}

/** The plain version 0 shape used for consolidation stages. */
function asStage(r: Resolved): Resolved {
  return {
    ...r,
    version: 0,
    subnetworkId: nativeSubnetworkId(),
    gas: 0n,
    payload: new Uint8Array(0),
    required: [],
  };
}

/** Sizing proxy: the transaction with fixed-width placeholder signature scripts. */
function sized(tx: Transaction, inputs: readonly InputPlan[]): Transaction {
  return {
    ...tx,
    inputs: tx.inputs.map((ti, i) => ({
      ...ti,
      signatureScript: new Uint8Array(
        spendSignatureScriptSize((inputs[i] as InputPlan).spend),
      ),
    })),
  };
}

/**
 * Internal builder: inputs are validated once up front in `planTransaction`,
 * so selection (which rebuilds candidates many times) skips re-validation.
 */
function build(
  inputs: readonly InputPlan[],
  outputs: readonly TransactionOutput[],
  r: Resolved,
): Transaction {
  const v1 = r.version >= TX_VERSION_TOCCATA;
  return {
    version: r.version,
    inputs: inputs.map((p) => {
      const base = {
        previousOutpoint: {
          transactionId: p.outpoint.transactionId,
          index: p.outpoint.index,
        },
        signatureScript: new Uint8Array(0),
        sequence: p.sequence ?? 0n,
        sigOpCount: v1 ? 0 : spendSigOpCount(p.spend),
      };
      return v1
        ? { ...base, computeBudget: spendComputeBudget(p.spend) }
        : base;
    }),
    outputs: outputs.map((o) => ({ ...o })),
    lockTime: 0n,
    subnetworkId: r.subnetworkId,
    gas: r.gas,
    payload: r.payload,
  };
}

/** Fee at `feeRate` for this exact shape, computed on the signed size. */
function feeFor(
  inputs: readonly InputPlan[],
  outputs: readonly TransactionOutput[],
  r: Resolved,
): { fee: bigint; mass: MassBreakdown } {
  const tx = sized(build(inputs, outputs, r), inputs);
  const entries = inputs.map((p) => p.entry);
  return {
    fee: feeForRate(tx, entries, r.feeRate),
    mass: massBreakdown(tx, entries),
  };
}

function finish(
  inputs: readonly InputPlan[],
  outputs: readonly TransactionOutput[],
  fee: bigint,
  r: Resolved,
  changeIndex?: number,
): PlannedTransaction {
  const tx = build(inputs, outputs, r);
  const entries = inputs.map((p) => p.entry);
  const mass = massBreakdown(sized(tx, inputs), entries);
  validatePlanned(tx, inputs, fee, mass, r);
  return {
    tx,
    inputs: [...inputs],
    fee,
    mass,
    ...(changeIndex !== undefined ? { changeIndex } : {}),
    id: transactionId(tx),
  };
}

function validatePlanned(
  tx: Transaction,
  inputs: readonly InputPlan[],
  fee: bigint,
  mass: MassBreakdown,
  r: Resolved,
): void {
  validateTransactionStructure(tx);
  if (tx.outputs.length === 0)
    throw new InvalidTransactionError('transaction has no outputs');
  const totalOut = tx.outputs.reduce((a, o) => a + o.value, 0n);
  const totalIn = inputs.reduce((a, p) => a + p.entry.amount, 0n);
  if (totalIn > MAX_SOMPI)
    throw new InvalidTransactionError('input value exceeds MAX_SOMPI');
  if (totalIn !== totalOut + fee)
    throw new InvalidTransactionError('value is not conserved');
  if (mass.storage === null)
    throw new InvalidTransactionError('storage mass is incomputable');
  if (mass.max > r.maxMass) throw new MassCapExceededError(mass.max, r.maxMass);
  const floor = minimumRelayFee(sized(tx, inputs));
  if (fee < floor)
    throw new InvalidTransactionError(
      `fee ${fee.toString()} is below the relay floor ${floor.toString()}`,
    );
  if (fee > r.maxFee) throw new FeeTooHighError(fee, r.maxFee);
}

function sameOutpoint(a: Outpoint, b: Outpoint): boolean {
  return a.index === b.index && equalBytes(a.transactionId, b.transactionId);
}

function spendable(
  utxos: readonly InputPlan[],
  opts: PlanOptions,
): InputPlan[] {
  const excluded = opts.exclude ?? [];
  return utxos.filter((u) => {
    if (excluded.some((e) => sameOutpoint(e, u.outpoint))) return false;
    // Covenant-bound outputs follow their covenant's spending rules, which a
    // plain wallet spend does not satisfy (and they change storage mass).
    if (u.entry.covenantId !== undefined) return false;
    if (u.entry.isCoinbase) {
      if (opts.virtualDaaScore === undefined) return false;
      if (u.entry.blockDaaScore + COINBASE_MATURITY > opts.virtualDaaScore)
        return false;
    }
    return u.entry.amount > 0n;
  });
}

/**
 * Refuse outputs that would burn funds or never relay: non-standard scripts,
 * and pay-to-pubkey scripts whose key is not a curve point.
 */
function assertStandardRecipient(spk: ScriptPublicKey, index: number): void {
  const cls = classifyScript(spk);
  if (cls === 'nonstandard')
    throw new InvalidScriptError(
      `recipient ${index} has a non-standard script and would not relay`,
    );
  if (cls === 'p2pk' && !isValidXOnlyPublicKey(spk.script.slice(1, 33)))
    throw new InvalidScriptError(
      `recipient ${index} pays to an invalid key; the funds would be burned`,
    );
  if (
    cls === 'p2pk-ecdsa' &&
    !isValidCompressedPublicKey(spk.script.slice(1, 34))
  )
    throw new InvalidScriptError(
      `recipient ${index} pays to an invalid key; the funds would be burned`,
    );
}

type PayResult =
  | { kind: 'ok'; planned: PlannedTransaction }
  | { kind: 'insufficient' }
  /** Funds suffice but the change can neither be output nor folded into the fee. */
  | { kind: 'unfoldable-change'; change: bigint; storageMass: bigint };

/**
 * Try to pay `recipients` from exactly `inputs`. Throws MassCapExceeded when
 * the inputs cannot fit in one transaction even without change.
 */
function tryPay(
  inputs: readonly InputPlan[],
  recipients: readonly Recipient[],
  r: Resolved,
  sendAll: boolean,
): PayResult {
  const totalIn = inputs.reduce((a, p) => a + p.entry.amount, 0n);

  if (sendAll) {
    const recipient = recipients[0] as Recipient;
    const out = (value: bigint) => [
      { scriptPublicKey: recipient.scriptPublicKey, value },
    ];
    // Iterate: the fee depends on the output value only through storage mass.
    let fee = feeFor(inputs, out(totalIn), r).fee;
    for (let k = 0; k < 8; k++) {
      if (fee >= totalIn) return { kind: 'insufficient' };
      const next = feeFor(inputs, out(totalIn - fee), r).fee;
      if (next <= fee) break;
      fee = next;
    }
    if (fee >= totalIn) return { kind: 'insufficient' };
    return { kind: 'ok', planned: finish(inputs, out(totalIn - fee), fee, r) };
  }

  const target = recipients.reduce((a, x) => a + x.amount, 0n);
  const base: TransactionOutput[] = recipients.map((x) => ({
    scriptPublicKey: x.scriptPublicKey,
    value: x.amount,
  }));
  const noChange = feeFor(inputs, base, r);
  if (noChange.mass.max > r.maxMass)
    throw new MassCapExceededError(noChange.mass.max, r.maxMass);
  if (totalIn < target + noChange.fee) return { kind: 'insufficient' };

  // Try with change, iterating because change affects storage mass affects fee.
  let fee = noChange.fee;
  let lastStorage = 0n;
  for (let k = 0; k < 8; k++) {
    const change = totalIn - target - fee;
    if (change <= 0n || change < r.foldThreshold) break;
    const outs = [...base, { scriptPublicKey: r.changeSpk, value: change }];
    const f = feeFor(inputs, outs, r);
    lastStorage = f.mass.storage ?? 0n;
    if (f.mass.max > r.maxMass) break;
    if (f.fee <= fee)
      return {
        kind: 'ok',
        planned: finish(inputs, outs, fee, r, base.length),
      };
    fee = f.fee;
  }

  // Fold the (small, or unrepresentable) change into the fee — within limits.
  const folded = totalIn - target - noChange.fee;
  if (folded > r.maxFold)
    return {
      kind: 'unfoldable-change',
      change: folded,
      storageMass: lastStorage,
    };
  return { kind: 'ok', planned: finish(inputs, base, totalIn - target, r) };
}

function consolidationStage(
  inputs: readonly InputPlan[],
  r: Resolved,
): PlannedTransaction | null {
  const s = asStage(r);
  const totalIn = inputs.reduce((a, p) => a + p.entry.amount, 0n);
  const out = (value: bigint) => [{ scriptPublicKey: s.changeSpk, value }];
  let fee = feeFor(inputs, out(totalIn), s).fee;
  for (let k = 0; k < 8; k++) {
    if (fee >= totalIn) return null;
    const next = feeFor(inputs, out(totalIn - fee), s).fee;
    if (next <= fee) break;
    fee = next;
  }
  if (fee >= totalIn) return null;
  return finish(inputs, out(totalIn - fee), fee, s, 0);
}

/** Largest number of these inputs (in order) that fit under the mass cap as a 1-output sweep. */
function maxFittingInputs(inputs: readonly InputPlan[], r: Resolved): number {
  const s = asStage(r);
  let lo = 0;
  let hi = Math.min(inputs.length, MAX_TX_INPUTS);
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    const slice = inputs.slice(0, mid);
    const total = slice.reduce((a, p) => a + p.entry.amount, 0n);
    const { mass } = feeFor(
      slice,
      [{ scriptPublicKey: s.changeSpk, value: total }],
      s,
    );
    if (mass.max <= s.maxMass) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/** Cost at `feeRate` of spending one output of `spend` later as an extra input. */
function futureSpendCost(spend: Spend, feeRate: bigint): bigint {
  // outpoint (32 + 4) + script length (8) + script + sequence (8) + sigOpCount (1)
  const bytes = 53n + BigInt(spendSignatureScriptSize(spend));
  const compute = bytes + 1000n * BigInt(spendSigOpCount(spend));
  const transient = 2n * bytes;
  return (compute > transient ? compute : transient) * feeRate;
}

function resolve(opts: PlanOptions): Resolved {
  const maxFeeRate = opts.maxFeeRate ?? DEFAULT_MAX_FEE_RATE;
  if (opts.feeRate < 1n)
    throw invalidInput('fee rate must be at least 1 sompi per gram');
  if (opts.feeRate > maxFeeRate)
    throw invalidInput(
      `fee rate ${opts.feeRate.toString()} exceeds the ceiling of ${maxFeeRate.toString()} sompi/gram`,
    );
  const version = opts.txVersion ?? 0;
  if (version !== 0 && version !== TX_VERSION_TOCCATA)
    throw invalidInput('txVersion must be 0 or 1');
  // Change and consolidation outputs are locked to this; it must be spendable.
  validateReceivingSpend(opts.changeSpend);
  return {
    feeRate: opts.feeRate,
    changeSpend: opts.changeSpend,
    changeSpk: spendScriptPublicKey(opts.changeSpend),
    maxMass: opts.maxMass ?? MAXIMUM_STANDARD_TRANSACTION_MASS,
    foldThreshold:
      opts.changeFoldThreshold ??
      futureSpendCost(opts.changeSpend, opts.feeRate),
    maxFold: opts.maxFoldToFee ?? 100_000_000n,
    maxFee: opts.maxFee ?? DEFAULT_MAX_FEE,
    payload: opts.payload ?? new Uint8Array(0),
    version,
    subnetworkId: opts.subnetworkId ?? nativeSubnetworkId(),
    gas: opts.gas ?? 0n,
    required: [...(opts.requiredInputs ?? [])],
  };
}

function assertUniqueOutpoints(plans: readonly InputPlan[]): void {
  for (let a = 0; a < plans.length; a++) {
    for (let b = a + 1; b < plans.length; b++) {
      if (
        sameOutpoint(
          (plans[a] as InputPlan).outpoint,
          (plans[b] as InputPlan).outpoint,
        )
      )
        throw invalidInput('the same UTXO appears twice');
    }
  }
}

/**
 * Select inputs and build the transaction(s) paying `recipients`.
 *
 * Mass is computed on the exact signed size (Kaspa signatures are
 * fixed-width), so the plan's fee and mass are final before any signing.
 * Every returned transaction has passed `validatePlanned`: structurally valid,
 * value conserved, fee between the relay floor and `maxFee`, mass under the
 * cap. Recipients are refused if they would burn funds or never relay.
 */
export function planTransaction(
  utxos: readonly InputPlan[],
  recipients: readonly Recipient[],
  opts: PlanOptions,
): Plan {
  const r = resolve(opts);
  const sendAll = opts.sendAll ?? false;
  if (recipients.length === 0)
    throw invalidInput('at least one recipient is required');
  if (sendAll && recipients.length !== 1)
    throw invalidInput('sendAll requires exactly one recipient');
  recipients.forEach((x, i) => {
    assertStandardRecipient(x.scriptPublicKey, i);
    if (!sendAll && (x.amount <= 0n || x.amount > MAX_SOMPI))
      throw invalidInput('recipient amount out of range');
  });
  for (const u of [...r.required, ...utxos]) assertSpendMatchesEntry(u);
  assertUniqueOutpoints([...r.required, ...utxos]);
  if (
    r.required.some((q) =>
      (opts.exclude ?? []).some((e) => sameOutpoint(e, q.outpoint)),
    )
  )
    throw invalidInput('a required input is also excluded');

  const required = r.required;
  const pool = spendable(utxos, opts).sort((a, b) => {
    const d = a.entry.amount - b.entry.amount;
    const asc = d < 0n ? -1 : d > 0n ? 1 : 0;
    return (opts.strategy ?? 'largest-first') === 'smallest-first' ? asc : -asc;
  });
  if (pool.length === 0 && required.length === 0)
    throw new InsufficientFundsError(
      recipients.reduce((a, x) => a + x.amount, 0n),
    );

  const allowChain = opts.allowChain ?? true;
  let unfoldable: Extract<PayResult, { kind: 'unfoldable-change' }> | null =
    null;
  let hitCap = false;

  // Single-transaction attempt: grow the input set until it pays.
  const limit = Math.min(pool.length, MAX_TX_INPUTS - required.length);
  const first = sendAll ? limit : required.length > 0 ? 0 : 1;
  for (let k = first; k <= limit; k++) {
    let res: PayResult;
    try {
      res = tryPay([...required, ...pool.slice(0, k)], recipients, r, sendAll);
    } catch (e) {
      if (!(e instanceof MassCapExceededError)) throw e;
      hitCap = true;
      break;
    }
    if (res.kind === 'ok')
      return { stages: [], final: res.planned, totalFee: res.planned.fee };
    unfoldable = res.kind === 'unfoldable-change' ? res : null;
  }
  if (!hitCap && unfoldable && pool.length <= limit) {
    throw new ChangeWouldBeDustError(unfoldable.change, unfoldable.storageMass);
  }

  if (!allowChain) {
    const fit = maxFittingInputs(pool, r);
    if (fit < pool.length) throw new NeedsConsolidationError(fit);
    throw new InsufficientFundsError(
      shortfall([...required, ...pool], recipients, r, []),
    );
  }

  // Compounding chain: sweep batches into single outputs, then pay from those.
  const stages: PlannedTransaction[] = [];
  let queue = [...pool];
  for (let guard = 0; guard < 64; guard++) {
    const fit = maxFittingInputs(queue, r);
    if (fit >= queue.length) {
      try {
        const res = sendAll
          ? tryPay([...required, ...queue], recipients, r, true)
          : payFromQueue(queue, recipients, r);
        if (res.kind === 'ok') {
          const totalFee =
            stages.reduce((a, s) => a + s.fee, 0n) + res.planned.fee;
          return { stages, final: res.planned, totalFee };
        }
        if (res.kind === 'unfoldable-change')
          throw new ChangeWouldBeDustError(res.change, res.storageMass);
      } catch (e) {
        if (!(e instanceof MassCapExceededError)) throw e;
      }
      break;
    }
    if (fit < 2) throw new NeedsConsolidationError(fit);
    // Sweep the smallest `fit` inputs so large ones stay available for the payment.
    const bySize = [...queue].sort((a, b) =>
      a.entry.amount < b.entry.amount
        ? -1
        : a.entry.amount > b.entry.amount
          ? 1
          : 0,
    );
    const batch = bySize.slice(0, fit);
    const stage = consolidationStage(batch, r);
    if (!stage) break;
    stages.push(stage);
    const out = stage.tx.outputs[0] as TransactionOutput;
    const synthetic: InputPlan = {
      outpoint: { transactionId: stage.id, index: 0 },
      // blockDaaScore is unknown until acceptance; neither sighash nor mass reads it.
      entry: {
        amount: out.value,
        scriptPublicKey: out.scriptPublicKey,
        blockDaaScore: 0n,
        isCoinbase: false,
      },
      spend: r.changeSpend,
    };
    const batchSet = new Set(batch);
    queue = [synthetic, ...queue.filter((u) => !batchSet.has(u))].sort(
      (a, b) =>
        a.entry.amount < b.entry.amount
          ? 1
          : a.entry.amount > b.entry.amount
            ? -1
            : 0,
    );
  }
  throw new InsufficientFundsError(
    shortfall([...required, ...pool], recipients, r, stages),
  );
}

function payFromQueue(
  queue: readonly InputPlan[],
  recipients: readonly Recipient[],
  r: Resolved,
): PayResult {
  let last: PayResult = { kind: 'insufficient' };
  for (let k = r.required.length > 0 ? 0 : 1; k <= queue.length; k++) {
    last = tryPay([...r.required, ...queue.slice(0, k)], recipients, r, false);
    if (last.kind === 'ok') return last;
  }
  return last;
}

/** How much more is needed, fees included, so the caller can show a real number. */
function shortfall(
  available: readonly InputPlan[],
  recipients: readonly Recipient[],
  r: Resolved,
  stages: readonly PlannedTransaction[],
): bigint {
  const totalAvailable = available.reduce((a, p) => a + p.entry.amount, 0n);
  const target = recipients.reduce((a, x) => a + x.amount, 0n);
  let fee = stages.reduce((a, s) => a + s.fee, 0n);
  try {
    const inputs = available.slice(0, MAX_TX_INPUTS);
    fee += feeFor(
      inputs,
      recipients.map((x) => ({
        scriptPublicKey: x.scriptPublicKey,
        value: x.amount > 0n ? x.amount : 1n,
      })),
      r,
    ).fee;
  } catch {
    /* sizing failed (e.g. a zero amount); report the value shortfall alone */
  }
  const short = target + fee - totalAvailable;
  return short > 0n ? short : 1n;
}

/**
 * Sweep UTXOs into as few outputs as possible (one per mass-capped batch),
 * paying to `changeSpend`. Useful for miners and busy vaults before a large
 * send. Batches are independent (no chaining), so they can be signed and
 * broadcast in any order.
 */
export function planConsolidation(
  utxos: readonly InputPlan[],
  opts: Pick<
    PlanOptions,
    | 'feeRate'
    | 'changeSpend'
    | 'virtualDaaScore'
    | 'exclude'
    | 'maxMass'
    | 'maxFee'
    | 'maxFeeRate'
  >,
): PlannedTransaction[] {
  const r = resolve(opts);
  for (const u of utxos) assertSpendMatchesEntry(u);
  assertUniqueOutpoints(utxos);
  let queue = spendable(utxos, opts).sort((a, b) =>
    a.entry.amount < b.entry.amount
      ? -1
      : a.entry.amount > b.entry.amount
        ? 1
        : 0,
  );
  const out: PlannedTransaction[] = [];
  while (queue.length > 1) {
    const fit = maxFittingInputs(queue, r);
    if (fit < 2) break;
    const stage = consolidationStage(queue.slice(0, fit), r);
    if (!stage) break;
    out.push(stage);
    queue = queue.slice(fit);
  }
  return out;
}
