import {
  BLOCK_MASS_LIMIT_COMPUTE,
  BLOCK_MASS_LIMIT_TRANSIENT,
  COVENANT_ID_SIZE,
  GRAMS_PER_COMPUTE_BUDGET_UNIT,
  GRAMS_PER_SIGOP_COUNT_UNIT,
  MASS_PER_SCRIPT_PUB_KEY_BYTE,
  MASS_PER_TX_BYTE,
  MINIMUM_RELAY_TRANSACTION_FEE_PER_KG,
  STORAGE_MASS_PARAMETER,
  TRANSIENT_BYTE_TO_MASS_FACTOR,
  TX_VERSION_TOCCATA,
  UTXO_CONST_STORAGE,
  UTXO_UNIT_SIZE,
} from './constants.js';
import { invalidInput } from './errors.js';
import type {
  ScriptPublicKey,
  Transaction,
  TransactionOutput,
  UtxoEntry,
} from './tx/model.js';
import { estimatedSerializedSize } from './tx/size.js';

/**
 * Transaction mass — `consensus/core/src/mass/mod.rs`. All arithmetic is
 * `bigint` with Rust's truncating integer division; a float port diverges on
 * exactly the adversarial inputs (tiny outputs) where the result decides
 * acceptance.
 */

/** size × 1 + Σ(2 + spk.len) × 10 + Σ sigOpCount × 1000 (v0) or Σ computeBudget × 100 (v1). */
export function computeMass(tx: Transaction): bigint {
  const size = estimatedSerializedSize(tx);
  let spkBytes = 0n;
  for (const o of tx.outputs)
    spkBytes += 2n + BigInt(o.scriptPublicKey.script.length);
  let scriptMass = 0n;
  if (tx.version >= TX_VERSION_TOCCATA) {
    for (const i of tx.inputs)
      scriptMass +=
        BigInt(i.computeBudget ?? 0) * GRAMS_PER_COMPUTE_BUDGET_UNIT;
  } else {
    for (const i of tx.inputs)
      scriptMass += BigInt(i.sigOpCount) * GRAMS_PER_SIGOP_COUNT_UNIT;
  }
  return (
    size * MASS_PER_TX_BYTE +
    spkBytes * MASS_PER_SCRIPT_PUB_KEY_BYTE +
    scriptMass
  );
}

/** Raw transient mass: size × 4. */
export function transientMass(tx: Transaction): bigint {
  return estimatedSerializedSize(tx) * TRANSIENT_BYTE_TO_MASS_FACTOR;
}

/**
 * Transient mass in compute-mass units: `ceil(raw × compute_limit / transient_limit)`.
 * Exact integer form of rusty-kaspa's float cofactor (0.5 on mainnet).
 */
export function normalizedTransientMass(tx: Transaction): bigint {
  const raw = transientMass(tx);
  return (
    (raw * BLOCK_MASS_LIMIT_COMPUTE + BLOCK_MASS_LIMIT_TRANSIENT - 1n) /
    BLOCK_MASS_LIMIT_TRANSIENT
  );
}

/** `utxo_plurality`: 100-byte storage units a UTXO occupies (1 for every standard script). */
export function utxoPlurality(
  spk: ScriptPublicKey,
  hasCovenant: boolean,
): bigint {
  const size =
    UTXO_CONST_STORAGE +
    BigInt(spk.script.length) +
    (hasCovenant ? COVENANT_ID_SIZE : 0n);
  return (size + UTXO_UNIT_SIZE - 1n) / UTXO_UNIT_SIZE;
}

interface Cell {
  plurality: bigint;
  amount: bigint;
}

/**
 * KIP-9 storage mass: `max(0, C·Σ p²/out − inputs term)`. The inputs term is
 * harmonic (`C·Σ p²/in`) on the relaxed path — output plurality 1, input
 * plurality 1, or both exactly 2 — and arithmetic otherwise
 * (`|I| · (C / max(1, Σin / |I|))`). Returns `null` if an amount is zero
 * (incomputable; rusty-kaspa treats that as too high).
 */
export function storageMass(
  entries: readonly UtxoEntry[],
  outputs: readonly TransactionOutput[],
  storageMassParameter: bigint = STORAGE_MASS_PARAMETER,
): bigint | null {
  const C = storageMassParameter;
  const outs: Cell[] = outputs.map((o) => ({
    plurality: utxoPlurality(o.scriptPublicKey, o.covenant !== undefined),
    amount: o.value,
  }));
  const ins: Cell[] = entries.map((e) => ({
    plurality: utxoPlurality(e.scriptPublicKey, e.covenantId !== undefined),
    amount: e.amount,
  }));
  if (outs.some((c) => c.amount <= 0n) || ins.some((c) => c.amount <= 0n))
    return null;

  let outsPlurality = 0n;
  let harmonicOuts = 0n;
  for (const c of outs) {
    outsPlurality += c.plurality;
    harmonicOuts += (C * c.plurality * c.plurality) / c.amount;
  }

  let relaxed: boolean;
  if (outsPlurality === 1n) relaxed = true;
  else if (ins.length > 2) relaxed = false;
  else {
    const insPlurality = ins.reduce((a, c) => a + c.plurality, 0n);
    relaxed =
      insPlurality === 1n || (outsPlurality === 2n && insPlurality === 2n);
  }

  if (relaxed) {
    let harmonicIns = 0n;
    for (const c of ins)
      harmonicIns += (C * c.plurality * c.plurality) / c.amount;
    return harmonicOuts > harmonicIns ? harmonicOuts - harmonicIns : 0n;
  }

  let insPlurality = 0n;
  let sumIns = 0n;
  for (const c of ins) {
    insPlurality += c.plurality;
    sumIns += c.amount;
  }
  let meanIns = sumIns / insPlurality;
  if (meanIns < 1n) meanIns = 1n;
  const arithmeticIns = insPlurality * (C / meanIns);
  return harmonicOuts > arithmeticIns ? harmonicOuts - arithmeticIns : 0n;
}

export interface MassBreakdown {
  size: bigint;
  compute: bigint;
  transient: bigint;
  normalizedTransient: bigint;
  /** `null` if incomputable (a zero amount). */
  storage: bigint | null;
  /** max(compute, normalizedTransient, storage): what the block limit and standard cap see. */
  max: bigint;
}

export function massBreakdown(
  tx: Transaction,
  entries: readonly UtxoEntry[],
): MassBreakdown {
  const compute = computeMass(tx);
  const transient = transientMass(tx);
  const normalizedTransient = normalizedTransientMass(tx);
  const storage = storageMass(entries, tx.outputs);
  let max = compute > normalizedTransient ? compute : normalizedTransient;
  if (storage === null) max = BigInt(Number.MAX_SAFE_INTEGER);
  else if (storage > max) max = storage;
  return {
    size: estimatedSerializedSize(tx),
    compute,
    transient,
    normalizedTransient,
    storage,
    max,
  };
}

/**
 * The mempool's relay floor: 100 sompi per gram of
 * max(compute, normalized transient). Storage mass carries no fee floor
 * (`check_transaction_standard_in_context`).
 */
export function minimumRelayFee(tx: Transaction): bigint {
  const c = computeMass(tx);
  const t = normalizedTransientMass(tx);
  const feeMass = c > t ? c : t;
  // minimum_required_transaction_relay_fee: sompi/kg × grams / 1000, never zero.
  const fee = (feeMass * MINIMUM_RELAY_TRANSACTION_FEE_PER_KG) / 1000n;
  return fee === 0n ? MINIMUM_RELAY_TRANSACTION_FEE_PER_KG : fee;
}

/**
 * Fee at a given rate, priced on the full mass **including** storage (how the
 * rusty-kaspa wallet generator charges for mempool priority), never below the
 * relay floor.
 */
export function feeForRate(
  tx: Transaction,
  entries: readonly UtxoEntry[],
  feeRateSompiPerGram: bigint,
): bigint {
  if (feeRateSompiPerGram < 1n)
    throw invalidInput('fee rate must be at least 1 sompi per gram');
  const m = massBreakdown(tx, entries);
  if (m.storage === null)
    throw invalidInput('storage mass is incomputable (zero amount)');
  const fee = m.max * feeRateSompiPerGram;
  const floor = minimumRelayFee(tx);
  return fee > floor ? fee : floor;
}
