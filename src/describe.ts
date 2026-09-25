import { bytesToHex, equalBytes } from './bytes.js';
import { SOMPI_PER_KASPA } from './constants.js';
import { InvalidTransactionError } from './errors.js';
import { isValidCompressedPublicKey, isValidXOnlyPublicKey } from './keys.js';
import { massBreakdown } from './mass.js';
import type { MassBreakdown } from './mass.js';
import { scriptPublicKeyToAddress } from './address.js';
import type { NetworkPrefix } from './address.js';
import { classifyScript } from './script/standard.js';
import type { ScriptClass } from './script/standard.js';
import { transactionId } from './tx/encode.js';
import { isNativeSubnetwork } from './tx/model.js';
import type { ScriptPublicKey, Transaction, UtxoEntry } from './tx/model.js';
import { validateTransactionStructure } from './tx/validate.js';
import { spendSignatureScriptSize } from './spend.js';
import type { InputPlan } from './spend.js';

export type DescribeWarning =
  | 'version-1'
  | 'payload'
  | 'non-native-subnetwork'
  | 'lock-time'
  | 'non-zero-sequence'
  | 'nonstandard-output'
  | 'burn-output'
  | 'fee-above-threshold'
  | 'fee-rate-above-threshold'
  | 'foreign-input'
  | 'covenant-output';

export interface DescribedInput {
  index: number;
  outpoint: string;
  amount: bigint;
  address: string | null;
  scriptClass: ScriptClass;
  /** The input spends one of `ownScripts`. */
  isOwn: boolean;
}

export interface DescribedOutput {
  index: number;
  value: bigint;
  address: string | null;
  scriptClass: ScriptClass;
  /** Pays back to one of `ownScripts` (change). */
  isOwn: boolean;
}

export interface TransactionDescription {
  id: string;
  version: number;
  inputs: DescribedInput[];
  outputs: DescribedOutput[];
  totalIn: bigint;
  totalOut: bigint;
  /** Implicit: Σinputs − Σoutputs. */
  fee: bigint;
  /** Σ of outputs that are not `ownScripts` — what actually leaves the wallet. */
  sent: bigint;
  mass: MassBreakdown;
  /** fee / max(mass), sompi per gram. */
  feeRate: bigint;
  payloadHex: string;
  warnings: DescribeWarning[];
}

export interface DescribeOptions {
  prefix: NetworkPrefix;
  /** The wallet's own locking scripts (vault, change). Compared by bytes. */
  ownScripts?: readonly ScriptPublicKey[];
  /** Warn above this fee (default 1 KAS). */
  feeWarningThreshold?: bigint;
  /** Warn above this fee rate (default 1,000 sompi/gram, 10× the floor). */
  feeRateWarningThreshold?: bigint;
}

function same(a: ScriptPublicKey, b: ScriptPublicKey): boolean {
  return a.version === b.version && equalBytes(a.script, b.script);
}

/**
 * Everything an approval screen must show before a key signs. Computed from
 * the transaction and **entries the caller fetched itself** — pass trusted
 * entries (or input plans built on them), not the ones a bundle claims.
 * With input plans, unsigned inputs are sized at their final signature length. Ownership is decided by comparing
 * script bytes, never address strings.
 */
export function describeTransaction(
  tx: Transaction,
  entriesOrInputs: readonly (UtxoEntry | InputPlan)[],
  opts: DescribeOptions,
): TransactionDescription {
  validateTransactionStructure(tx);
  if (entriesOrInputs.length !== tx.inputs.length)
    throw new InvalidTransactionError('one entry is required per input');
  const isPlan = (x: UtxoEntry | InputPlan): x is InputPlan => 'spend' in x;
  const entries = entriesOrInputs.map((x) => (isPlan(x) ? x.entry : x));
  // Size unsigned inputs at their final (fixed-width) signature-script length
  // when the spend is known, so fee rate reflects what will be broadcast.
  const sizedTx: Transaction = {
    ...tx,
    inputs: tx.inputs.map((ti, n) => {
      const x = entriesOrInputs[n] as UtxoEntry | InputPlan;
      return ti.signatureScript.length === 0 && isPlan(x)
        ? {
            ...ti,
            signatureScript: new Uint8Array(spendSignatureScriptSize(x.spend)),
          }
        : ti;
    }),
  };
  const own = opts.ownScripts ?? [];
  const isOwn = (s: ScriptPublicKey) => own.some((o) => same(o, s));
  const warnings = new Set<DescribeWarning>();

  const inputs = tx.inputs.map((i, n): DescribedInput => {
    const e = entries[n] as UtxoEntry;
    const mine = isOwn(e.scriptPublicKey);
    if (own.length > 0 && !mine) warnings.add('foreign-input');
    return {
      index: n,
      outpoint: `${bytesToHex(i.previousOutpoint.transactionId)}:${String(i.previousOutpoint.index)}`,
      amount: e.amount,
      address: scriptPublicKeyToAddress(e.scriptPublicKey, opts.prefix),
      scriptClass: classifyScript(e.scriptPublicKey),
      isOwn: mine,
    };
  });

  const outputs = tx.outputs.map((o, n): DescribedOutput => {
    const cls = classifyScript(o.scriptPublicKey);
    if (cls === 'nonstandard') warnings.add('nonstandard-output');
    if (o.covenant) warnings.add('covenant-output');
    if (
      (cls === 'p2pk' &&
        !isValidXOnlyPublicKey(o.scriptPublicKey.script.slice(1, 33))) ||
      (cls === 'p2pk-ecdsa' &&
        !isValidCompressedPublicKey(o.scriptPublicKey.script.slice(1, 34)))
    )
      warnings.add('burn-output');
    return {
      index: n,
      value: o.value,
      address: scriptPublicKeyToAddress(o.scriptPublicKey, opts.prefix),
      scriptClass: cls,
      isOwn: isOwn(o.scriptPublicKey),
    };
  });

  const totalIn = entries.reduce((a, e) => a + e.amount, 0n);
  const totalOut = tx.outputs.reduce((a, o) => a + o.value, 0n);
  if (totalOut > totalIn)
    throw new InvalidTransactionError('outputs exceed inputs');
  const fee = totalIn - totalOut;
  const sent = outputs
    .filter((o) => !o.isOwn)
    .reduce((a, o) => a + o.value, 0n);
  const mass = massBreakdown(sizedTx, entries);
  const feeRate = mass.max > 0n ? fee / mass.max : 0n;

  if (tx.version !== 0) warnings.add('version-1');
  if (tx.payload.length > 0) warnings.add('payload');
  if (!isNativeSubnetwork(tx.subnetworkId))
    warnings.add('non-native-subnetwork');
  if (tx.lockTime !== 0n) warnings.add('lock-time');
  if (tx.inputs.some((i) => i.sequence !== 0n))
    warnings.add('non-zero-sequence');
  if (fee > (opts.feeWarningThreshold ?? SOMPI_PER_KASPA))
    warnings.add('fee-above-threshold');
  if (feeRate > (opts.feeRateWarningThreshold ?? 1000n))
    warnings.add('fee-rate-above-threshold');

  return {
    id: bytesToHex(transactionId(tx)),
    version: tx.version,
    inputs,
    outputs,
    totalIn,
    totalOut,
    fee,
    sent,
    mass,
    feeRate,
    payloadHex: bytesToHex(tx.payload),
    warnings: [...warnings],
  };
}
