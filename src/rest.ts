import { addressToScriptPublicKey } from './address.js';
import type { NetworkPrefix } from './address.js';
import { bytesToHex, hexToBytes } from './bytes.js';
import { DEFAULT_MAX_FEE_RATE } from './constants.js';
import { transactionId } from './tx/encode.js';
import {
  KaspaError,
  RestError,
  SubmitOutcomeUnknownError,
  invalidInput,
} from './errors.js';
import { isNativeSubnetwork } from './tx/model.js';
import type { Transaction } from './tx/model.js';
import {
  normalizeUtxos,
  parseJsonSafe,
  runtime,
  stringifyWithBigInt,
  toBigInt,
} from './net/common.js';
import type { KaspaUtxo, RawUtxo } from './net/common.js';

export { parseJsonSafe };
export type { KaspaUtxo };
import type { InputPlan, Spend } from './spend.js';
import { assertSpendMatchesEntry } from './spend.js';

/**
 * Thin typed client for kaspa-rest-server (api.kaspa.org and self-hosted
 * instances). Host injected, `fetch` injectable, no retries — both consumers
 * own their retry and failover policy. Never imported by the core.
 *
 * Limitation of the server, not of this client: its submit model has no
 * `payload`, `gas` or compute-budget fields, so only **version 0 transactions
 * without a payload** can be submitted over REST. Payload-carrying and
 * version 1 transactions need a wRPC node.
 */

/** The subset of `fetch` the client needs, so no DOM or Node typings are required. */
export interface FetchResponseLike {
  ok: boolean;
  status: number;
  text(): Promise<string>;
}
/**
 * Deliberately omits `signal` so the real global `fetch` is assignable to
 * `FetchLike`; an AbortSignal is attached at runtime when available.
 */
export interface FetchInitLike {
  method: string;
  headers: Record<string, string>;
  body?: string;
}
export type FetchLike = (
  url: string,
  init: FetchInitLike,
) => Promise<FetchResponseLike>;

/** Runtime globals, typed locally so the package needs neither DOM nor Node types. */
interface FetchGlobals {
  fetch?: FetchLike;
  AbortController?: new () => { signal: unknown; abort(): void };
}
const fetchGlobals = globalThis as unknown as FetchGlobals;

export interface RestClientOptions {
  /** e.g. `https://api.kaspa.org` — no trailing slash required. */
  baseUrl: string;
  /** Defaults to the global `fetch`. */
  fetch?: FetchLike;
  /** Per-request timeout. Default 20,000 ms. */
  timeoutMs?: number;
  headers?: Record<string, string>;
  /** Permit a plain `http://` base URL (local development only). Default false. */
  allowInsecureHttp?: boolean;
  /** Refuse UTXO responses with more entries than this. Default 50,000. */
  maxUtxos?: number;
  /**
   * Network prefix every address must carry (e.g. `'kaspa'`). Recommended:
   * without it, a mainnet wallet could be handed testnet addresses.
   */
  prefix?: NetworkPrefix;
}

export interface FeeBucket {
  /** sompi per gram */
  feerate: number;
  estimatedSeconds: number;
}
export interface FeeEstimate {
  priorityBucket: FeeBucket;
  normalBuckets: FeeBucket[];
  lowBuckets: FeeBucket[];
}
export type FeeTier = 'economy' | 'normal' | 'fast';

export interface RestTxInput {
  transaction_id: string;
  index: number;
  previous_outpoint_hash: string;
  previous_outpoint_index: string | number;
  previous_outpoint_address?: string | null;
  previous_outpoint_amount?: number | string | null;
  signature_script?: string | null;
  sig_op_count?: string | number | null;
  compute_budget?: number | null;
}
export interface RestTxOutput {
  transaction_id: string;
  index: number;
  amount: number | string;
  script_public_key?: string | null;
  script_public_key_address?: string | null;
  script_public_key_type?: string | null;
}
export interface RestTransaction {
  transaction_id: string;
  subnetwork_id?: string | null;
  hash?: string | null;
  mass?: string | null;
  payload?: string | null;
  block_hash?: string[] | null;
  block_time?: number | null;
  version?: number | null;
  is_accepted?: boolean | null;
  accepting_block_hash?: string | null;
  accepting_block_blue_score?: number | null;
  inputs?: RestTxInput[] | null;
  outputs?: RestTxOutput[] | null;
}
export interface MassResponse {
  mass: bigint;
  storageMass: bigint;
  computeMass: bigint;
}
export interface AcceptanceResponse {
  transactionId: string;
  accepted: boolean;
  acceptingBlockHash?: string;
  acceptingBlueScore?: number;
  acceptingTimestamp?: number;
}

/** The REST submit model for a transaction. */
export function toRestSubmitModel(tx: Transaction): Record<string, unknown> {
  if (tx.version !== 0)
    throw invalidInput(
      'kaspa-rest-server can only submit version 0 transactions',
    );
  if (tx.payload.length > 0)
    throw invalidInput(
      'kaspa-rest-server cannot submit a transaction with a payload',
    );
  if (tx.gas !== 0n || !isNativeSubnetwork(tx.subnetworkId)) {
    throw invalidInput(
      'kaspa-rest-server can only submit native-subnetwork transactions without gas',
    );
  }
  return {
    version: tx.version,
    inputs: tx.inputs.map((i) => ({
      previousOutpoint: {
        transactionId: bytesToHex(i.previousOutpoint.transactionId),
        index: i.previousOutpoint.index,
      },
      signatureScript: bytesToHex(i.signatureScript),
      sequence: i.sequence,
      sigOpCount: i.sigOpCount,
    })),
    outputs: tx.outputs.map((o) => ({
      amount: o.value,
      scriptPublicKey: {
        version: o.scriptPublicKey.version,
        scriptPublicKey: bytesToHex(o.scriptPublicKey.script),
      },
    })),
    lockTime: tx.lockTime,
    subnetworkId: bytesToHex(tx.subnetworkId),
  };
}

/** Map a fee estimate to a rate in sompi/gram, falling back across buckets, never below 1. */
export function pickFeeRate(
  estimate: FeeEstimate,
  tier: FeeTier = 'normal',
  maxFeeRate: bigint = DEFAULT_MAX_FEE_RATE,
): bigint {
  const rateOf = (b: unknown): number | undefined => {
    const r = (b as { feerate?: unknown } | undefined)?.feerate;
    return typeof r === 'number' && Number.isFinite(r) && r > 0 ? r : undefined;
  };
  if (typeof estimate !== 'object' || estimate === null)
    throw new KaspaError('REST', 'malformed fee estimate');
  const priority = rateOf(estimate.priorityBucket);
  const normal = rateOf(
    Array.isArray(estimate.normalBuckets)
      ? estimate.normalBuckets[0]
      : undefined,
  );
  const low = rateOf(
    Array.isArray(estimate.lowBuckets) ? estimate.lowBuckets[0] : undefined,
  );
  const rate =
    tier === 'fast'
      ? (priority ?? normal ?? low)
      : tier === 'economy'
        ? (low ?? normal ?? priority)
        : (normal ?? priority ?? low);
  if (rate === undefined || rate < 1) return 1n;
  // The estimate comes from an untrusted server: clamp, never trust.
  const r = BigInt(Math.ceil(Math.min(rate, Number(maxFeeRate))));
  return r > maxFeeRate ? maxFeeRate : r;
}

/**
 * Attach a spend descriptor to REST UTXOs, checking that the descriptor
 * really unlocks each one.
 */
export function utxosToInputPlans(
  utxos: readonly KaspaUtxo[],
  spend: Spend,
): InputPlan[] {
  return utxos.map((u) => {
    const plan: InputPlan = { outpoint: u.outpoint, entry: u.entry, spend };
    assertSpendMatchesEntry(plan);
    return plan;
  });
}

export class KaspaRestClient {
  private readonly base: string;
  private readonly fetchFn: FetchLike;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;
  private readonly maxUtxos: number;
  private readonly prefix: NetworkPrefix | undefined;

  constructor(opts: RestClientOptions) {
    const secure = /^https:\/\//.test(opts.baseUrl);
    const insecureOk =
      opts.allowInsecureHttp === true && /^http:\/\//.test(opts.baseUrl);
    if (!secure && !insecureOk)
      throw invalidInput(
        'baseUrl must be an https URL (set allowInsecureHttp for local http)',
      );
    this.maxUtxos = opts.maxUtxos ?? 50_000;
    this.prefix = opts.prefix;
    this.base = opts.baseUrl.replace(/\/+$/, '');
    const f = opts.fetch ?? fetchGlobals.fetch;
    if (typeof f !== 'function')
      throw invalidInput('no fetch implementation available');
    this.fetchFn = f;
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    this.headers = opts.headers ?? {};
  }

  private async request(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    // AbortController is optional (older runtimes); the race enforces the timeout regardless.
    const controller = fetchGlobals.AbortController
      ? new fetchGlobals.AbortController()
      : undefined;
    let timer: unknown;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = runtime.setTimeout(() => {
        controller?.abort();
        reject(
          new KaspaError(
            'REST',
            `request timed out after ${this.timeoutMs} ms`,
          ),
        );
      }, this.timeoutMs);
    });
    try {
      const headers: Record<string, string> = {
        accept: 'application/json',
        ...this.headers,
      };
      if (body !== undefined) headers['content-type'] = 'application/json';
      const init: FetchInitLike = { method, headers };
      if (body !== undefined) init.body = stringifyWithBigInt(body);
      const withSignal = controller
        ? Object.assign({}, init, { signal: controller.signal })
        : init;
      const res = await Promise.race([
        this.fetchFn(`${this.base}${path}`, withSignal),
        timeout,
      ]);
      const text = await Promise.race([res.text(), timeout]);
      if (!res.ok) {
        let message = text;
        try {
          const j = parseJsonSafe(text) as {
            detail?: unknown;
            error?: unknown;
          };
          const d = j.detail ?? j.error;
          if (d !== undefined)
            message = typeof d === 'string' ? d : JSON.stringify(d);
        } catch {
          /* keep raw text */
        }
        throw new RestError(res.status, message);
      }
      return parseJsonSafe(text);
    } finally {
      runtime.clearTimeout(timer);
    }
  }

  async getUtxos(addresses: readonly string[]): Promise<KaspaUtxo[]> {
    if (addresses.length === 0) return [];
    for (const a of addresses) addressToScriptPublicKey(a, this.prefix);
    const raw =
      addresses.length === 1
        ? await this.request(
            'GET',
            `/addresses/${encodeURIComponent(addresses[0] ?? '')}/utxos`,
          )
        : await this.request('POST', '/addresses/utxos', { addresses });
    if (!Array.isArray(raw))
      throw new KaspaError('REST', 'unexpected UTXO response');
    if (raw.length > this.maxUtxos)
      throw new KaspaError(
        'REST',
        `UTXO response exceeds ${this.maxUtxos} entries`,
      );
    const raws: RawUtxo[] = raw.map((u) => {
      const x = u as {
        address?: unknown;
        outpoint?: { transactionId?: unknown; index?: unknown };
        utxoEntry?: {
          amount?: unknown;
          scriptPublicKey?: { scriptPublicKey?: unknown };
          blockDaaScore?: unknown;
          isCoinbase?: unknown;
        };
      };
      const script = x.utxoEntry?.scriptPublicKey?.scriptPublicKey;
      return {
        address: x.address,
        transactionId: x.outpoint?.transactionId,
        index: x.outpoint?.index,
        amount: x.utxoEntry?.amount,
        // The REST server reports the bare script; standard scripts are version 0.
        scriptPublicKey:
          typeof script === 'string' && /^([0-9a-fA-F]{2})*$/.test(script)
            ? { version: 0, script: hexToBytes(script.toLowerCase()) }
            : undefined,
        blockDaaScore: x.utxoEntry?.blockDaaScore,
        isCoinbase: x.utxoEntry?.isCoinbase,
      };
    });
    return normalizeUtxos(raws, addresses, this.prefix, 'REST');
  }

  async getBalance(address: string): Promise<bigint> {
    const r = (await this.request(
      'GET',
      `/addresses/${encodeURIComponent(address)}/balance`,
    )) as { balance: unknown };
    return toBigInt(r.balance, 'balance', 'REST');
  }

  async getFeeEstimate(): Promise<FeeEstimate> {
    return (await this.request('GET', '/info/fee-estimate')) as FeeEstimate;
  }

  /** Submit a signed transaction. Returns the transaction id (hex). */
  async submit(
    tx: Transaction,
    opts: { replaceByFee?: boolean; allowOrphan?: boolean } = {},
  ): Promise<string> {
    const body = {
      transaction: toRestSubmitModel(tx),
      allowOrphan: opts.allowOrphan ?? false,
    };
    const local = bytesToHex(transactionId(tx));
    let r: { transactionId?: string; error?: string };
    try {
      r = (await this.request(
        'POST',
        `/transactions?replaceByFee=${opts.replaceByFee ? 'true' : 'false'}`,
        body,
      )) as { transactionId?: string; error?: string };
    } catch (e) {
      // An HTTP status is the server's answer; anything else (timeout,
      // network failure) leaves the outcome unknown.
      if (e instanceof RestError) throw e;
      throw new SubmitOutcomeUnknownError(
        local,
        e instanceof Error ? e.message : String(e),
      );
    }
    if (r.error) throw new RestError(200, r.error);
    if (!r.transactionId)
      throw new KaspaError('REST', 'submit returned no transaction id');
    if (r.transactionId.toLowerCase() !== local)
      throw new KaspaError(
        'REST',
        `node reported transaction id ${r.transactionId} but this transaction is ${local}`,
      );
    return local;
  }

  /** The node's own mass calculation for an (unsigned or signed) transaction. */
  async getMass(tx: Transaction): Promise<MassResponse> {
    const r = (await this.request(
      'POST',
      '/transactions/mass',
      toRestSubmitModel(tx),
    )) as {
      mass: unknown;
      storage_mass: unknown;
      compute_mass: unknown;
    };
    return {
      mass: toBigInt(r.mass, 'mass', 'REST'),
      storageMass: toBigInt(r.storage_mass, 'storage_mass'),
      computeMass: toBigInt(r.compute_mass, 'compute_mass'),
    };
  }

  async getTransaction(
    id: string,
    opts: { resolvePreviousOutpoints?: 'no' | 'light' | 'full' } = {},
  ): Promise<RestTransaction> {
    const q = opts.resolvePreviousOutpoints
      ? `?resolve_previous_outpoints=${resolveMode(opts.resolvePreviousOutpoints)}`
      : '';
    return (await this.request(
      'GET',
      `/transactions/${encodeURIComponent(id)}${q}`,
    )) as RestTransaction;
  }

  /**
   * The transaction with ID `id`, rebuilt from the REST view and **proven by
   * its ID**: the result is returned only if it hashes to `id`, so its outputs
   * (amounts and scripts) are exactly what the chain committed to, whatever
   * the server claims. Pass these to `openSigningBundle({ fundingTransactions })`
   * to prove input amounts without trusting any backend.
   *
   * Best effort: REST omits sequence, lock time and gas, which are taken as 0.
   * Transactions from wallets that set them (some number input sequences
   * 0, 1, 2, …) cannot be proven and throw — fail-closed, never mis-proven.
   * On mainnet roughly nine in ten recent transactions prove. The
   * `signedAmounts` ledger is the defence that does not depend on this.
   */
  async getFundingTransaction(id: string): Promise<Transaction> {
    if (typeof id !== 'string' || !/^[0-9a-fA-F]{64}$/.test(id))
      throw invalidInput('transaction id must be 64 hex characters');
    const want = id.toLowerCase();
    const t = await this.getTransaction(want, {
      resolvePreviousOutpoints: 'no',
    });
    let tx: Transaction;
    try {
      tx = transactionFromRest(t);
    } catch (e) {
      throw new KaspaError(
        'REST',
        `malformed transaction ${want}: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    if (bytesToHex(transactionId(tx)) !== want)
      throw new KaspaError(
        'REST',
        `transaction ${want} could not be proven: the server's data does not hash to its id`,
      );
    return tx;
  }

  async getHistoryPage(
    address: string,
    opts: {
      limit?: number;
      before?: number;
      after?: number;
      resolvePreviousOutpoints?: 'no' | 'light' | 'full';
      acceptance?: 'accepted' | 'rejected';
    } = {},
  ): Promise<RestTransaction[]> {
    const q: string[] = [`limit=${queryInt(opts.limit ?? 50, 'limit', 500)}`];
    if (opts.before !== undefined)
      q.push(`before=${queryInt(opts.before, 'before')}`);
    if (opts.after !== undefined)
      q.push(`after=${queryInt(opts.after, 'after')}`);
    q.push(
      `resolve_previous_outpoints=${resolveMode(opts.resolvePreviousOutpoints)}`,
    );
    if (opts.acceptance !== undefined) {
      if (opts.acceptance !== 'accepted' && opts.acceptance !== 'rejected')
        throw invalidInput('acceptance must be accepted or rejected');
      q.push(`acceptance=${opts.acceptance}`);
    }
    const r = await this.request(
      'GET',
      `/addresses/${encodeURIComponent(address)}/full-transactions-page?${q.join('&')}`,
    );
    return Array.isArray(r) ? (r as RestTransaction[]) : [];
  }

  /**
   * Offset-paged history (`/full-transactions?limit&offset`), newest first —
   * the shape ZelCore's CSV export pages through. Prefer `getHistoryPage`
   * (cursor-based) for live views: offsets shift as new transactions land.
   */
  async getHistoryByOffset(
    address: string,
    opts: {
      limit?: number;
      offset?: number;
      resolvePreviousOutpoints?: 'no' | 'light' | 'full';
    } = {},
  ): Promise<RestTransaction[]> {
    const q = [
      `limit=${queryInt(opts.limit ?? 50, 'limit', 500)}`,
      `offset=${queryInt(opts.offset ?? 0, 'offset')}`,
      `resolve_previous_outpoints=${resolveMode(opts.resolvePreviousOutpoints)}`,
    ];
    const r = await this.request(
      'GET',
      `/addresses/${encodeURIComponent(address)}/full-transactions?${q.join('&')}`,
    );
    return Array.isArray(r) ? (r as RestTransaction[]) : [];
  }

  async getTransactionAcceptance(
    ids: readonly string[],
  ): Promise<AcceptanceResponse[]> {
    const r = await this.request('POST', '/transactions/acceptance', {
      transactionIds: ids,
    });
    return Array.isArray(r) ? (r as AcceptanceResponse[]) : [];
  }

  async getVirtualChainBlueScore(): Promise<bigint> {
    const r = (await this.request('GET', '/info/virtual-chain-blue-score')) as {
      blueScore: unknown;
    };
    return toBigInt(r.blueScore, 'blueScore', 'REST');
  }

  /** Current virtual DAA score — pass to `planTransaction` to spend matured coinbase outputs. */
  async getVirtualDaaScore(): Promise<bigint> {
    const r = (await this.request('GET', '/info/blockdag')) as {
      virtualDaaScore: unknown;
    };
    return toBigInt(r.virtualDaaScore, 'virtualDaaScore', 'REST');
  }
}

export function createRestClient(opts: RestClientOptions): KaspaRestClient {
  return new KaspaRestClient(opts);
}

function queryInt(
  v: number,
  what: string,
  max = Number.MAX_SAFE_INTEGER,
): number {
  if (!Number.isSafeInteger(v) || v < 0 || v > max)
    throw invalidInput(`${what} must be an integer between 0 and ${max}`);
  return v;
}

function resolveMode(v: 'no' | 'light' | 'full' | undefined): string {
  const mode = v ?? 'light';
  if (mode !== 'no' && mode !== 'light' && mode !== 'full')
    throw invalidInput('resolvePreviousOutpoints must be no, light or full');
  return mode;
}

const HEX = /^([0-9a-fA-F]{2})*$/;
function restHex(v: unknown, what: string): Uint8Array {
  if (typeof v !== 'string' || !HEX.test(v)) throw invalidInput(`bad ${what}`);
  return hexToBytes(v.toLowerCase());
}
function restInt(v: unknown, what: string, max: number): number {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 0 || n > max)
    throw invalidInput(`bad ${what}`);
  return n;
}

/** Rebuild a consensus transaction from the REST view (sequence, lock time and gas taken as 0). */
function transactionFromRest(t: RestTransaction): Transaction {
  const version = restInt(t.version ?? 0, 'version', 0xffff);
  const ins = [...(t.inputs ?? [])].sort((a, b) => a.index - b.index);
  const outs = [...(t.outputs ?? [])].sort((a, b) => a.index - b.index);
  ins.forEach((x, i) => {
    if (x.index !== i) throw invalidInput('input indexes are not contiguous');
  });
  outs.forEach((x, i) => {
    if (x.index !== i) throw invalidInput('output indexes are not contiguous');
  });
  const tx: Transaction = {
    version,
    inputs: ins.map((i) => ({
      previousOutpoint: {
        transactionId: restHex(i.previous_outpoint_hash, 'outpoint'),
        index: restInt(i.previous_outpoint_index, 'outpoint index', 0xffffffff),
      },
      signatureScript: restHex(i.signature_script ?? '', 'signature script'),
      sequence: 0n,
      sigOpCount:
        version >= 1 ? 0 : restInt(i.sig_op_count ?? 0, 'sigOpCount', 0xff),
      ...(version >= 1
        ? {
            computeBudget: restInt(
              i.compute_budget ?? 0,
              'computeBudget',
              0xffff,
            ),
          }
        : {}),
    })),
    outputs: outs.map((o) => ({
      value: toBigInt(o.amount, 'amount', 'REST'),
      // Standard scripts are version 0; anything else fails the id proof.
      scriptPublicKey: {
        version: 0,
        script: restHex(o.script_public_key ?? '', 'script'),
      },
    })),
    lockTime: 0n,
    subnetworkId: restHex(t.subnetwork_id ?? '00'.repeat(20), 'subnetwork'),
    gas: 0n,
    payload: restHex(t.payload ?? '', 'payload'),
  };
  return tx;
}
