/**
 * Pure-TypeScript Kaspa wRPC client (JSON encoding) — replaces the rusty-kaspa
 * WASM `RpcClient`. Protocol: `docs/WRPC_PROTOCOL.md`.
 *
 * Unlike REST, wRPC can submit **every** transaction kind: version 1, payload
 * carrying and lane transactions (ZelCore messages, Igra entries).
 *
 * The node is untrusted. The client verifies the node's network and sync
 * state on every connection, validates and attributes every UTXO, clamps fee
 * estimates (`pickFeeRate`), checks that a submitted transaction's ID equals
 * the locally computed one, caps message sizes, and times out every request.
 * It only ever sends op names from a fixed allowlist, because a frame the
 * server cannot parse makes it drop the connection without a reply.
 */
import { addressToScriptPublicKey } from './address.js';
import type { NetworkPrefix } from './address.js';
import { bytesToHex, hexToBytes } from './bytes.js';
import {
  invalidInput,
  KaspaError,
  RpcError,
  SubmitOutcomeUnknownError,
} from './errors.js';
import {
  normalizeUtxo,
  normalizeUtxos,
  parseJsonSafe,
  runtime,
  stringifyWithBigInt,
  toBigInt,
} from './net/common.js';
import type { KaspaUtxo, RawUtxo } from './net/common.js';
import type { FeeEstimate } from './rest.js';
import { transactionId } from './tx/encode.js';
import type {
  ScriptPublicKey,
  Transaction,
  TransactionInput,
  TransactionOutput,
} from './tx/model.js';
import { validateTransactionStructure } from './tx/validate.js';

// ---------------------------------------------------------------------------
// Transport abstraction
// ---------------------------------------------------------------------------

/** The subset of the WHATWG `WebSocket` the client needs (browser, Node ≥ 22, React Native). */
export interface WebSocketLike {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  // Handler parameters are `any` so the platform `WebSocket` (whose handlers
  // take DOM `Event` subtypes) is assignable without a cast.
  /* eslint-disable @typescript-eslint/no-explicit-any */
  onopen: ((ev: any) => unknown) | null;
  onmessage: ((ev: any) => unknown) | null;
  onerror: ((ev: any) => unknown) | null;
  onclose: ((ev: any) => unknown) | null;
  /* eslint-enable @typescript-eslint/no-explicit-any */
}
export type WebSocketFactory = (url: string) => WebSocketLike;

/** A string-URL-only fetch — works under Capacitor's HTTP shim. */
export type ResolverFetch = (
  url: string,
) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

interface WrpcGlobals {
  WebSocket?: new (url: string) => WebSocketLike;
  fetch?: ResolverFetch;
  setInterval: (fn: () => void, ms: number) => unknown;
  clearInterval: (id: unknown) => void;
  crypto?: { getRandomValues(a: Uint32Array): Uint32Array };
}
const g = globalThis as unknown as WrpcGlobals;

const OPEN = 1;

// ---------------------------------------------------------------------------
// Networks and endpoints
// ---------------------------------------------------------------------------

export type KaspaNetworkId = 'mainnet' | 'testnet-10' | 'testnet-11';

const PREFIX: Record<KaspaNetworkId, NetworkPrefix> = {
  mainnet: 'kaspa',
  'testnet-10': 'kaspatest',
  'testnet-11': 'kaspatest',
};

/** Public resolvers (rusty-kaspa `rpc/wrpc/client/Resolvers.toml`). */
export const PUBLIC_RESOLVERS: readonly string[] = [
  'eric',
  'maxim',
  'sean',
  'troy',
]
  .map((n) => `https://${n}.kaspa.stream`)
  .concat(
    ['john', 'mike', 'paul', 'alex'].map((n) => `https://${n}.kaspa.red`),
    ['jake', 'mark', 'adam', 'liam'].map((n) => `https://${n}.kaspa.green`),
    ['noah', 'ryan', 'jack', 'luke'].map((n) => `https://${n}.kaspa.blue`),
  );

/** Every op this client may send (a misspelt op makes the node drop the socket). */
const OPS = [
  'ping',
  'getServerInfo',
  'getBlockDagInfo',
  'getSinkBlueScore',
  'getUtxosByAddresses',
  'getBalanceByAddress',
  'getBalancesByAddresses',
  'getFeeEstimate',
  'getMempoolEntry',
  'getMempoolEntriesByAddresses',
  'submitTransaction',
  'submitTransactionReplacement',
  'subscribe',
  'unsubscribe',
] as const;
export type WrpcOp = (typeof OPS)[number];
const OP_SET: ReadonlySet<string> = new Set(OPS);

export interface WrpcClientOptions {
  /** Network the node must be on. Checked with `getServerInfo` on every connection. */
  networkId: KaspaNetworkId;
  /**
   * Fixed node URLs (`wss://…`), tried in order. Recommended for production:
   * your own kaspad with `--utxoindex --rpclisten-json`.
   */
  urls?: readonly string[];
  /**
   * Fall back to the public resolvers (default true when `urls` is empty).
   * Public resolvers only list Borsh endpoints; the client requests the Borsh
   * URL and connects to the proxy's `/wrpc/json` path.
   */
  useResolvers?: boolean;
  resolvers?: readonly string[];
  /** Defaults to `globalThis.WebSocket`. */
  webSocket?: WebSocketFactory;
  /** For the resolver lookup; defaults to `globalThis.fetch`. Called with a string URL only. */
  fetch?: ResolverFetch;
  /** Permit `ws://` / `http://` (local development only). Default false. */
  allowInsecure?: boolean;
  /** Default true: refuse a node that is not synced. */
  requireSynced?: boolean;
  /** Default true: refuse a node without the UTXO index (needed for balances and UTXOs). */
  requireUtxoIndex?: boolean;
  /** Default 30,000 ms. */
  requestTimeoutMs?: number;
  /** Default 10,000 ms per connection attempt. */
  connectTimeoutMs?: number;
  /** Refuse inbound frames larger than this many characters. Default 64 MiB. */
  maxMessageSize?: number;
  /** Refuse UTXO responses with more entries than this. Default 50,000. */
  maxUtxos?: number;
  /** RPC `ping` interval to keep proxies from idling the socket out. Default 30,000 ms; 0 disables. */
  keepaliveMs?: number;
  /** Reconnect (and re-subscribe) after an unexpected close. Default true. */
  autoReconnect?: boolean;
  /** Called when the connection is established or lost. */
  onConnectionChange?: (connected: boolean, url: string | undefined) => void;
}

export interface ServerInfo {
  rpcApiVersion: number;
  rpcApiRevision: number;
  serverVersion: string;
  networkId: string;
  hasUtxoIndex: boolean;
  isSynced: boolean;
  virtualDaaScore: bigint;
}

export interface MempoolEntry {
  fee: bigint;
  isOrphan: boolean;
  transaction: Transaction;
  /** Computed locally from `transaction`, never taken from the node. */
  transactionId: string;
}

export interface MempoolEntriesForAddress {
  address: string;
  sending: MempoolEntry[];
  receiving: MempoolEntry[];
}

export interface UtxosChanged {
  added: KaspaUtxo[];
  removed: KaspaUtxo[];
}

// ---------------------------------------------------------------------------
// RPC transaction JSON (docs/WRPC_PROTOCOL.md §4.10)
// ---------------------------------------------------------------------------

function spkToRpc(spk: ScriptPublicKey): string {
  return spk.version.toString(16).padStart(4, '0') + bytesToHex(spk.script);
}

function spkFromRpc(v: unknown): ScriptPublicKey {
  if (typeof v !== 'string' || !/^([0-9a-fA-F]{2}){2,}$/.test(v))
    throw new RpcError('malformed scriptPublicKey in response');
  return {
    version: parseInt(v.slice(0, 4), 16),
    script: hexToBytes(v.slice(4).toLowerCase()),
  };
}

/** The wRPC JSON form of a transaction (u64 values stay bigint → bare JSON integers). */
export function toRpcTransaction(tx: Transaction): Record<string, unknown> {
  validateTransactionStructure(tx);
  const v1 = tx.version >= 1;
  return {
    version: tx.version,
    inputs: tx.inputs.map((i) => ({
      previousOutpoint: {
        transactionId: bytesToHex(i.previousOutpoint.transactionId),
        index: i.previousOutpoint.index,
      },
      signatureScript: bytesToHex(i.signatureScript),
      sequence: i.sequence,
      // The key is required even for v1, where it must be 0.
      sigOpCount: v1 ? 0 : i.sigOpCount,
      ...(v1 ? { computeBudget: i.computeBudget ?? 0 } : {}),
    })),
    outputs: tx.outputs.map((o) => ({
      value: o.value,
      scriptPublicKey: spkToRpc(o.scriptPublicKey),
      ...(o.covenant
        ? {
            covenant: {
              authorizingInput: o.covenant.authorizingInput,
              covenantId: bytesToHex(o.covenant.covenantId),
            },
          }
        : {}),
    })),
    lockTime: tx.lockTime,
    subnetworkId: bytesToHex(tx.subnetworkId),
    gas: tx.gas,
    payload: bytesToHex(tx.payload),
    // The mempool recomputes storage mass; one of mass/storageMass must be present.
    mass: 0,
  };
}

function rec(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v))
    throw new RpcError(`malformed ${what} in response`);
  return v as Record<string, unknown>;
}

function hexField(v: unknown, what: string, len?: number): Uint8Array {
  if (typeof v !== 'string' || !/^([0-9a-fA-F]{2})*$/.test(v))
    throw new RpcError(`malformed ${what} in response`);
  const b = hexToBytes(v.toLowerCase());
  if (len !== undefined && b.length !== len)
    throw new RpcError(`malformed ${what} in response`);
  return b;
}

function intField(v: unknown, what: string, max: number): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > max)
    throw new RpcError(`malformed ${what} in response`);
  return v;
}

/** Decode a node's transaction JSON, structurally validated. */
export function fromRpcTransaction(json: unknown): Transaction {
  const t = json as Record<string, unknown> | null;
  if (typeof t !== 'object' || t === null)
    throw new RpcError('malformed transaction in response');
  const version = intField(t.version, 'version', 0xffff);
  const inputs = t.inputs;
  const outputs = t.outputs;
  if (!Array.isArray(inputs) || !Array.isArray(outputs))
    throw new RpcError('malformed transaction in response');
  const tx: Transaction = {
    version,
    inputs: inputs.map((raw): TransactionInput => {
      const i = rec(raw, 'input');
      const op = rec(i.previousOutpoint, 'outpoint');
      const input: TransactionInput = {
        previousOutpoint: {
          transactionId: hexField(op.transactionId, 'outpoint', 32),
          index: intField(op.index, 'outpoint index', 0xffffffff),
        },
        signatureScript: hexField(i.signatureScript, 'signatureScript'),
        sequence: toBigInt(i.sequence, 'sequence'),
        sigOpCount: intField(i.sigOpCount, 'sigOpCount', 0xff),
      };
      if (version >= 1)
        input.computeBudget = intField(
          i.computeBudget ?? 0,
          'computeBudget',
          0xffff,
        );
      return input;
    }),
    outputs: outputs.map((raw): TransactionOutput => {
      const o = rec(raw, 'output');
      const out: TransactionOutput = {
        value: toBigInt(o.value, 'value'),
        scriptPublicKey: spkFromRpc(o.scriptPublicKey),
      };
      const c = o.covenant as Record<string, unknown> | null | undefined;
      if (c) {
        out.covenant = {
          authorizingInput: intField(c.authorizingInput, 'covenant', 0xffff),
          covenantId: hexField(c.covenantId, 'covenant id', 32),
        };
      }
      return out;
    }),
    lockTime: toBigInt(t.lockTime, 'lockTime'),
    subnetworkId: hexField(t.subnetworkId, 'subnetworkId', 20),
    gas: toBigInt(t.gas ?? 0, 'gas'),
    payload: hexField(t.payload ?? '', 'payload'),
  };
  try {
    validateTransactionStructure(tx);
  } catch (e) {
    throw new RpcError(
      `node returned an invalid transaction: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  return tx;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

interface Pending {
  method: string;
  resolve(v: unknown): void;
  reject(e: unknown): void;
  timer: unknown;
}

type Listener = (payload: unknown) => void;

interface Subscription {
  scope: 'UtxosChanged' | 'VirtualDaaScoreChanged';
  addresses?: string[];
  notification: string;
  handler: Listener;
}

function randomIndex(n: number): number {
  if (g.crypto) {
    const a = new Uint32Array(1);
    g.crypto.getRandomValues(a);
    return (a[0] ?? 0) % n;
  }
  return Math.floor(Math.random() * n);
}

function shuffled<T>(xs: readonly T[]): T[] {
  const a = [...xs];
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    const t = a[i] as T;
    a[i] = a[j] as T;
    a[j] = t;
  }
  return a;
}

export class KaspaWrpcClient {
  readonly networkId: KaspaNetworkId;
  readonly prefix: NetworkPrefix;
  private readonly opts: Required<
    Omit<
      WrpcClientOptions,
      'onConnectionChange' | 'webSocket' | 'fetch' | 'urls' | 'resolvers'
    >
  > & {
    urls: readonly string[];
    resolvers: readonly string[];
    onConnectionChange?: WrpcClientOptions['onConnectionChange'];
  };
  private readonly wsFactory: WebSocketFactory;
  private readonly fetchFn: ResolverFetch | undefined;
  private ws: WebSocketLike | undefined;
  private url: string | undefined;
  private connecting: Promise<void> | undefined;
  /** True only after the node passed the network/sync/index checks. */
  private ready = false;
  private closedByUser = false;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private readonly subs = new Set<Subscription>();
  private keepalive: unknown;
  private reconnectTimer: unknown;
  private reconnectDelay = 1000;
  /** Bumped by `close()`: an attempt from an older epoch never completes. */
  private epoch = 0;
  private stableTimer: unknown;

  constructor(opts: WrpcClientOptions) {
    if (!Object.prototype.hasOwnProperty.call(PREFIX, opts.networkId))
      throw invalidInput(
        `unsupported network ${JSON.stringify(opts.networkId)}`,
      );
    this.networkId = opts.networkId;
    this.prefix = PREFIX[opts.networkId];
    const urls = opts.urls ?? [];
    const allowInsecure = opts.allowInsecure ?? false;
    for (const u of urls) checkUrl(u, allowInsecure, 'ws');
    this.opts = {
      networkId: opts.networkId,
      urls,
      useResolvers: opts.useResolvers ?? urls.length === 0,
      resolvers: opts.resolvers ?? PUBLIC_RESOLVERS,
      allowInsecure,
      requireSynced: opts.requireSynced ?? true,
      requireUtxoIndex: opts.requireUtxoIndex ?? true,
      requestTimeoutMs: opts.requestTimeoutMs ?? 30_000,
      connectTimeoutMs: opts.connectTimeoutMs ?? 10_000,
      maxMessageSize: opts.maxMessageSize ?? 32 * 1024 * 1024,
      maxUtxos: opts.maxUtxos ?? 50_000,
      keepaliveMs: opts.keepaliveMs ?? 30_000,
      autoReconnect: opts.autoReconnect ?? true,
      onConnectionChange: opts.onConnectionChange,
    };
    for (const r of this.opts.resolvers) checkUrl(r, allowInsecure, 'http');
    const ctor = g.WebSocket;
    const factory =
      opts.webSocket ?? (ctor ? (u: string) => new ctor(u) : undefined);
    if (!factory) throw invalidInput('no WebSocket implementation available');
    this.wsFactory = factory;
    this.fetchFn = opts.fetch ?? g.fetch?.bind(globalThis);
  }

  /** The node currently connected to, if any. */
  get currentUrl(): string | undefined {
    return this.isConnected ? this.url : undefined;
  }

  get isConnected(): boolean {
    return this.ready && this.ws?.readyState === OPEN;
  }

  /**
   * Connect (idempotent). Tries fixed URLs first, then resolvers, verifying
   * each node. Also re-opens a client after `close()`.
   */
  connect(): Promise<void> {
    this.closedByUser = false;
    return this.ensureConnected();
  }

  private ensureConnected(): Promise<void> {
    if (this.closedByUser) return Promise.reject(new RpcError('client closed'));
    if (this.isConnected) return Promise.resolve();
    if (!this.connecting) {
      const epoch = this.epoch;
      const attempt = this.connectAny(epoch).finally(() => {
        if (this.connecting === attempt) this.connecting = undefined;
      });
      this.connecting = attempt;
    }
    return this.connecting;
  }

  /** Close for good: stops reconnecting and rejects everything in flight. */
  close(): void {
    this.closedByUser = true;
    this.epoch += 1;
    this.connecting = undefined;
    runtime.clearTimeout(this.reconnectTimer);
    this.teardown(new RpcError('client closed'), false);
  }

  private async connectAny(epoch: number): Promise<void> {
    const errors: string[] = [];
    const stale = () => epoch !== this.epoch || this.closedByUser;
    for (const url of this.opts.urls) {
      if (stale()) break;
      if (await this.tryUrl(url, errors, epoch)) return;
    }
    if (this.opts.useResolvers) {
      for (const resolver of shuffled(this.opts.resolvers)) {
        if (stale()) break;
        let url: string;
        try {
          url = await this.resolve(resolver);
        } catch (e) {
          errors.push(
            `${resolver}: ${e instanceof Error ? e.message : String(e)}`,
          );
          continue;
        }
        if (await this.tryUrl(url, errors, epoch)) return;
      }
    }
    if (stale()) throw new RpcError('client closed');
    throw new RpcError(
      `could not connect to a ${this.networkId} node (${errors.length} attempts failed${errors[0] ? `; first: ${errors[0]}` : ''})`,
    );
  }

  private async resolve(resolver: string): Promise<string> {
    if (!this.fetchFn)
      throw new RpcError('no fetch implementation for the resolver');
    const fetchFn = this.fetchFn;
    // One deadline covers the headers and the body: a resolver that stalls
    // mid-body must not hang connect().
    const text = await withTimeout(
      (async () => {
        const res = await fetchFn(
          `${resolver}/v2/kaspa/${this.networkId}/tls/wrpc/borsh`,
        );
        if (!res.ok) throw new RpcError(`resolver answered ${res.status}`);
        return res.text();
      })(),
      this.opts.connectTimeoutMs,
      'resolver timed out',
    );
    if (text.length > 4096) throw new RpcError('resolver response too large');
    const body = parseJsonSafe(text) as { url?: unknown } | null;
    if (
      typeof body !== 'object' ||
      body === null ||
      typeof body.url !== 'string'
    )
      throw new RpcError('malformed resolver response');
    // Public resolvers only list Borsh listeners; the proxies serve JSON on /wrpc/json.
    const url = body.url.replace(/\/wrpc\/borsh\/?$/, '/wrpc/json');
    if (!/\/wrpc\/json$/.test(url))
      throw new RpcError('resolver returned an unexpected URL');
    checkUrl(url, false, 'ws');
    return url;
  }

  private async tryUrl(
    url: string,
    errors: string[],
    epoch: number,
  ): Promise<boolean> {
    if (this.closedByUser || epoch !== this.epoch) return false;
    try {
      await this.open(url);
      const info = parseServerInfo(await this.send('getServerInfo', {}));
      if (info.networkId !== this.networkId)
        throw new RpcError(
          `node is on ${info.networkId}, expected ${this.networkId}`,
        );
      if (this.opts.requireSynced && !info.isSynced)
        throw new RpcError('node is not synced');
      if (this.opts.requireUtxoIndex && !info.hasUtxoIndex)
        throw new RpcError('node has no UTXO index');
      for (const s of this.subs) await this.send('subscribe', scopeParams(s));
      if (this.closedByUser || epoch !== this.epoch)
        throw new RpcError('client closed');
      this.ready = true;
      // Reset the backoff only once the connection has proved stable, so a
      // node that accepts and immediately drops us cannot force a 1 s loop.
      runtime.clearTimeout(this.stableTimer);
      this.stableTimer = runtime.setTimeout(() => {
        if (this.isConnected) this.reconnectDelay = 1000;
      }, 30_000);
      this.startKeepalive();
      this.notifyConnection(true, url);
      return true;
    } catch (e) {
      errors.push(`${url}: ${e instanceof Error ? e.message : String(e)}`);
      this.teardown(e instanceof Error ? e : new RpcError(String(e)), true);
      return false;
    }
  }

  private open(url: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const ws = this.wsFactory(url);
      this.ws = ws;
      this.url = url;
      const timer = runtime.setTimeout(() => {
        if (settled) return;
        settled = true;
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        reject(new RpcError('connection timed out'));
      }, this.opts.connectTimeoutMs);
      ws.onopen = () => {
        if (settled) return;
        settled = true;
        runtime.clearTimeout(timer);
        resolve();
      };
      ws.onerror = () => {
        if (settled) return;
        settled = true;
        runtime.clearTimeout(timer);
        reject(new RpcError('connection failed'));
      };
      ws.onclose = (ev: { code?: number }) => {
        if (!settled) {
          settled = true;
          runtime.clearTimeout(timer);
          reject(new RpcError(`connection closed (${String(ev.code ?? '')})`));
          return;
        }
        if (this.ws === ws) this.onUnexpectedClose(ev.code);
      };
      ws.onmessage = (ev: { data?: unknown }) => {
        if (this.ws === ws) this.onFrame(ev.data);
      };
    });
  }

  private onUnexpectedClose(code: number | undefined): void {
    const url = this.url;
    const wasReady = this.ready;
    this.teardown(
      new RpcError(`connection lost (${String(code ?? '')})`),
      true,
    );
    if (wasReady) this.notifyConnection(false, url);
    this.scheduleReconnect();
  }

  /** A throwing UI callback must never break connection handling. */
  private notifyConnection(up: boolean, url: string | undefined): void {
    try {
      this.opts.onConnectionChange?.(up, url);
    } catch {
      /* ignore */
    }
  }

  private scheduleReconnect(): void {
    if (this.closedByUser || !this.opts.autoReconnect || this.subs.size === 0)
      return; // without subscriptions the next call reconnects on demand
    const delay = this.reconnectDelay;
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30_000);
    runtime.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = runtime.setTimeout(() => {
      this.ensureConnected().catch(() => {
        this.scheduleReconnect();
      });
    }, delay);
  }

  /** Drop the socket and reject in-flight requests. */
  private teardown(err: Error, keepSubs: boolean): void {
    this.ready = false;
    runtime.clearTimeout(this.stableTimer);
    g.clearInterval(this.keepalive);
    this.keepalive = undefined;
    const ws = this.ws;
    this.ws = undefined;
    if (ws) {
      ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    }
    for (const [id, p] of this.pending) {
      runtime.clearTimeout(p.timer);
      p.reject(err);
      this.pending.delete(id);
    }
    if (!keepSubs) this.subs.clear();
  }

  private startKeepalive(): void {
    g.clearInterval(this.keepalive);
    if (this.opts.keepaliveMs <= 0) return;
    const ws = this.ws;
    this.keepalive = g.setInterval(() => {
      // A half-open socket (NAT drop, network handover) never fires onclose:
      // an unanswered ping is the only signal, so treat it as a lost link.
      this.send('ping', {}, Math.min(this.opts.keepaliveMs, 10_000)).catch(
        () => {
          if (this.ws === ws && ws?.readyState === OPEN)
            this.onUnexpectedClose(4000);
        },
      );
    }, this.opts.keepaliveMs);
  }

  private onFrame(data: unknown): void {
    if (typeof data !== 'string') return; // JSON endpoint only sends text frames
    if (data.length > this.opts.maxMessageSize) {
      this.onUnexpectedClose(1009);
      return;
    }
    let msg: {
      id?: unknown;
      method?: unknown;
      params?: unknown;
      error?: { message?: unknown } | null;
    };
    try {
      msg = parseJsonSafe(data) as typeof msg;
    } catch {
      return;
    }
    if (typeof msg !== 'object' || msg === null) return;
    if (typeof msg.id === 'number') {
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      runtime.clearTimeout(p.timer);
      if (msg.error) {
        const m =
          typeof msg.error.message === 'string'
            ? msg.error.message
            : 'unknown error';
        p.reject(new RpcError(`${p.method}: ${m}`, m));
      } else if (msg.method !== undefined && msg.method !== p.method) {
        p.reject(new RpcError(`${p.method}: response for a different method`));
      } else if (
        typeof msg.params !== 'object' ||
        msg.params === null ||
        Array.isArray(msg.params)
      ) {
        p.reject(new RpcError(`${p.method}: malformed response`));
      } else {
        p.resolve(msg.params);
      }
      return;
    }
    if (
      typeof msg.method === 'string' &&
      msg.params &&
      typeof msg.params === 'object'
    ) {
      for (const s of this.subs) {
        if (s.notification !== msg.method) continue;
        const inner = (msg.params as Record<string, unknown>)[s.scope];
        if (inner === undefined) continue;
        try {
          s.handler(inner);
        } catch {
          /* a throwing listener must not break the connection */
        }
      }
    }
  }

  /**
   * Send one request once connected to a verified node. Only allowlisted
   * ops; `params` must be an object.
   */
  async call(
    method: WrpcOp,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    if (!this.isConnected) await this.ensureConnected();
    return this.send(method, params);
  }

  /** Raw send on the current socket (also used while verifying a node). */
  private send(
    method: WrpcOp,
    params: Record<string, unknown>,
    timeoutMs = this.opts.requestTimeoutMs,
  ): Promise<unknown> {
    if (!OP_SET.has(method))
      return Promise.reject(
        invalidInput(`unsupported wRPC op ${String(method as unknown)}`),
      );
    if (typeof params !== 'object' || params === null || Array.isArray(params))
      return Promise.reject(invalidInput('params must be an object'));
    const ws = this.ws;
    if (!ws || ws.readyState !== OPEN)
      return Promise.reject(new RpcError('not connected'));
    const id = this.nextId;
    this.nextId = this.nextId >= 0x7fffffff ? 1 : this.nextId + 1;
    const frame = stringifyWithBigInt({ id, method, params });
    return new Promise<unknown>((resolve, reject) => {
      const timer = runtime.setTimeout(() => {
        this.pending.delete(id);
        reject(new RpcError(`${method} timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      this.pending.set(id, { method, resolve, reject, timer });
      try {
        ws.send(frame);
      } catch (e) {
        runtime.clearTimeout(timer);
        this.pending.delete(id);
        reject(
          new RpcError(
            `send failed: ${e instanceof Error ? e.message : String(e)}`,
          ),
        );
      }
    });
  }

  private checkAddresses(addresses: readonly string[]): string[] {
    const list = addresses as unknown;
    if (!Array.isArray(list)) throw invalidInput('addresses must be an array');
    const out: string[] = [];
    for (const a of list as unknown[]) {
      if (typeof a !== 'string') throw invalidInput('address must be a string');
      addressToScriptPublicKey(a, this.prefix);
      out.push(a);
    }
    return out;
  }

  // -- node state -----------------------------------------------------------

  async getServerInfo(): Promise<ServerInfo> {
    return parseServerInfo(await this.call('getServerInfo', {}));
  }

  /** Current virtual DAA score — pass to `planTransaction` to spend matured coinbase outputs. */
  async getVirtualDaaScore(): Promise<bigint> {
    const r = (await this.call('getBlockDagInfo', {})) as {
      virtualDaaScore?: unknown;
    };
    return toBigInt(r.virtualDaaScore, 'virtualDaaScore');
  }

  async getSinkBlueScore(): Promise<bigint> {
    const r = (await this.call('getSinkBlueScore', {})) as {
      blueScore?: unknown;
    };
    return toBigInt(r.blueScore, 'blueScore');
  }

  // -- balances and UTXOs ---------------------------------------------------

  async getBalance(address: string): Promise<bigint> {
    const [a] = this.checkAddresses([address]);
    const r = (await this.call('getBalanceByAddress', { address: a })) as {
      balance?: unknown;
    };
    return toBigInt(r.balance, 'balance');
  }

  async getBalances(
    addresses: readonly string[],
  ): Promise<Map<string, bigint>> {
    const req = this.checkAddresses(addresses);
    if (req.length === 0) return new Map();
    const r = (await this.call('getBalancesByAddresses', {
      addresses: req,
    })) as {
      entries?: unknown;
    };
    if (!Array.isArray(r.entries))
      throw new RpcError('malformed balances response');
    const wanted = new Set(req);
    const out = new Map<string, bigint>();
    for (const raw of r.entries as unknown[]) {
      const e = rec(raw, 'balance entry');
      if (typeof e.address !== 'string' || !wanted.has(e.address))
        throw new RpcError('balance for an address that was not requested');
      out.set(
        e.address,
        e.balance === null ? 0n : toBigInt(e.balance, 'balance'),
      );
    }
    return out;
  }

  /** UTXOs for our addresses, validated, attributed and de-duplicated. */
  async getUtxos(addresses: readonly string[]): Promise<KaspaUtxo[]> {
    const req = this.checkAddresses(addresses);
    if (req.length === 0) return [];
    const r = (await this.call('getUtxosByAddresses', { addresses: req })) as {
      entries?: unknown;
    };
    if (!Array.isArray(r.entries))
      throw new RpcError('malformed UTXO response');
    if (r.entries.length > this.opts.maxUtxos)
      throw new RpcError(`UTXO response exceeds ${this.opts.maxUtxos} entries`);
    return normalizeUtxos(r.entries.map(rawRpcUtxo), req, this.prefix, 'RPC');
  }

  // -- fees -----------------------------------------------------------------

  /** Raw estimate; always pass it through `pickFeeRate`, which clamps it. */
  async getFeeEstimate(): Promise<FeeEstimate> {
    const r = (await this.call('getFeeEstimate', {})) as { estimate?: unknown };
    if (typeof r.estimate !== 'object' || r.estimate === null)
      throw new RpcError('malformed fee estimate');
    return r.estimate as FeeEstimate;
  }

  // -- mempool ----------------------------------------------------------------

  async getMempoolEntry(
    id: string,
    includeOrphanPool = false,
  ): Promise<MempoolEntry | null> {
    if (typeof id !== 'string' || !/^[0-9a-fA-F]{64}$/.test(id))
      throw invalidInput('transaction id must be 64 hex characters');
    try {
      const r = (await this.call('getMempoolEntry', {
        transactionId: id.toLowerCase(),
        includeOrphanPool,
        filterTransactionPool: false,
      })) as { mempoolEntry?: unknown };
      const entry = mempoolEntry(r.mempoolEntry);
      // A node that lacks our transaction cannot forge one hashing to its id.
      if (entry.transactionId !== id.toLowerCase())
        throw new RpcError('mempool entry for a different transaction');
      return entry;
    } catch (e) {
      if (e instanceof RpcError && /not found/i.test(e.nodeMessage ?? ''))
        return null;
      throw e;
    }
  }

  async getMempoolEntriesByAddresses(
    addresses: readonly string[],
    includeOrphanPool = false,
  ): Promise<MempoolEntriesForAddress[]> {
    const req = this.checkAddresses(addresses);
    if (req.length === 0) return [];
    const r = (await this.call('getMempoolEntriesByAddresses', {
      addresses: req,
      includeOrphanPool,
      filterTransactionPool: false,
    })) as { entries?: unknown };
    if (!Array.isArray(r.entries))
      throw new RpcError('malformed mempool response');
    const wanted = new Set(req);
    return (r.entries as unknown[]).map((raw) => {
      const e = rec(raw, 'mempool entry');
      if (typeof e.address !== 'string' || !wanted.has(e.address))
        throw new RpcError(
          'mempool entry for an address that was not requested',
        );
      const address = e.address;
      const list = (v: unknown) => {
        if (!Array.isArray(v)) throw new RpcError('malformed mempool response');
        return v.map(mempoolEntry);
      };
      // A "receiving" entry must actually pay this address. Mempool data is
      // advisory either way: unconfirmed transactions can be fabricated.
      const spk = addressToScriptPublicKey(address, this.prefix);
      const receiving = list(e.receiving);
      for (const m of receiving) {
        const pays = m.transaction.outputs.some(
          (o) =>
            o.scriptPublicKey.version === spk.version &&
            bytesToHex(o.scriptPublicKey.script) === bytesToHex(spk.script),
        );
        if (!pays)
          throw new RpcError(
            'receiving mempool entry does not pay the address',
          );
      }
      return { address, sending: list(e.sending), receiving };
    });
  }

  // -- submission -------------------------------------------------------------

  /**
   * Submit a signed transaction (any version, payload or lane). Returns the
   * transaction ID after checking the node reports the one we computed.
   */
  async submitTransaction(tx: Transaction): Promise<string> {
    const expected = assertSubmittable(tx);
    const r = (await this.submitOnce(expected, 'submitTransaction', {
      transaction: toRpcTransaction(tx),
      allowOrphan: false,
    })) as { transactionId?: unknown };
    return checkSubmittedId(r.transactionId, expected);
  }

  /**
   * Replace-by-fee: submit `tx`, which double-spends a mempool transaction
   * with a higher fee. Returns the new ID and the transaction it replaced.
   */
  async submitTransactionReplacement(
    tx: Transaction,
  ): Promise<{ transactionId: string; replaced: Transaction }> {
    const expected = assertSubmittable(tx);
    const r = (await this.submitOnce(expected, 'submitTransactionReplacement', {
      transaction: toRpcTransaction(tx),
    })) as { transactionId?: unknown; replacedTransaction?: unknown };
    return {
      transactionId: checkSubmittedId(r.transactionId, expected),
      replaced: fromRpcTransaction(r.replacedTransaction),
    };
  }

  /**
   * Send a submission. Before the frame is sent, failures are definite; after
   * it, only an answer from the node is — a timeout or lost connection is
   * `SubmitOutcomeUnknownError`.
   */
  private async submitOnce(
    expectedId: string,
    method: 'submitTransaction' | 'submitTransactionReplacement',
    params: Record<string, unknown>,
  ): Promise<unknown> {
    if (!this.isConnected) await this.ensureConnected();
    try {
      return await this.send(method, params);
    } catch (e) {
      if (e instanceof RpcError && e.nodeMessage === undefined)
        throw new SubmitOutcomeUnknownError(expectedId, e.message);
      throw e;
    }
  }

  // -- subscriptions ----------------------------------------------------------

  /**
   * Live UTXO changes for `addresses`. Entries are validated like
   * `getUtxos`; malformed notifications are dropped. Survives reconnects.
   * Returns an async unsubscribe.
   */
  async subscribeUtxosChanged(
    addresses: readonly string[],
    onChange: (change: UtxosChanged) => void,
  ): Promise<() => Promise<void>> {
    const req = this.checkAddresses(addresses);
    if (req.length === 0)
      throw invalidInput('subscribe to at least one address');
    const wanted = new Set(req);
    const parse = (list: unknown): KaspaUtxo[] =>
      Array.isArray(list)
        ? list.flatMap((e) => {
            try {
              return [normalizeUtxo(rawRpcUtxo(e), wanted, this.prefix, 'RPC')];
            } catch {
              return []; // entries for other subscribers' addresses, or malformed
            }
          })
        : [];
    const sub: Subscription = {
      scope: 'UtxosChanged',
      addresses: req,
      notification: 'utxosChangedNotification',
      handler: (p) => {
        const x = p as { added?: unknown; removed?: unknown };
        const change = { added: parse(x.added), removed: parse(x.removed) };
        if (change.added.length > 0 || change.removed.length > 0)
          onChange(change);
      },
    };
    return this.addSubscription(sub);
  }

  /** Virtual DAA score ticks (~10 per second on mainnet). */
  async subscribeVirtualDaaScore(
    onScore: (score: bigint) => void,
  ): Promise<() => Promise<void>> {
    return this.addSubscription({
      scope: 'VirtualDaaScoreChanged',
      notification: 'virtualDaaScoreChangedNotification',
      handler: (p) => {
        try {
          onScore(
            toBigInt(
              (p as { virtualDaaScore?: unknown }).virtualDaaScore,
              'score',
            ),
          );
        } catch {
          /* drop malformed */
        }
      },
    });
  }

  private async addSubscription(
    sub: Subscription,
  ): Promise<() => Promise<void>> {
    if (!this.isConnected) await this.ensureConnected();
    this.subs.add(sub);
    try {
      await this.send('subscribe', scopeParams(sub));
    } catch (e) {
      this.subs.delete(sub);
      throw e;
    }
    return async () => {
      if (!this.subs.delete(sub) || !this.isConnected) return;
      const others = [...this.subs].filter((s) => s.scope === sub.scope);
      if (sub.scope === 'UtxosChanged') {
        // Keep addresses another listener still watches.
        const kept = new Set(others.flatMap((s) => s.addresses ?? []));
        const drop = (sub.addresses ?? []).filter((a) => !kept.has(a));
        if (drop.length === 0) return;
        await this.send('unsubscribe', {
          UtxosChanged: { addresses: drop },
        }).catch(() => undefined);
      } else if (others.length === 0) {
        await this.send('unsubscribe', scopeParams(sub)).catch(() => undefined);
      }
    };
  }
}

function parseServerInfo(v: unknown): ServerInfo {
  const r = v as Record<string, unknown> | null;
  if (
    typeof r !== 'object' ||
    r === null ||
    typeof r.networkId !== 'string' ||
    typeof r.isSynced !== 'boolean' ||
    typeof r.hasUtxoIndex !== 'boolean'
  )
    throw new RpcError('malformed getServerInfo response');
  return {
    rpcApiVersion: Number(r.rpcApiVersion),
    rpcApiRevision: Number(r.rpcApiRevision),
    serverVersion: String(r.serverVersion),
    networkId: r.networkId,
    hasUtxoIndex: r.hasUtxoIndex,
    isSynced: r.isSynced,
    virtualDaaScore: toBigInt(r.virtualDaaScore, 'virtualDaaScore'),
  };
}

function scopeParams(s: Subscription): Record<string, unknown> {
  return s.scope === 'UtxosChanged'
    ? { UtxosChanged: { addresses: s.addresses ?? [] } }
    : { [s.scope]: {} };
}

function rawRpcUtxo(e: unknown): RawUtxo {
  const x = e as {
    address?: unknown;
    outpoint?: { transactionId?: unknown; index?: unknown };
    utxoEntry?: {
      amount?: unknown;
      scriptPublicKey?: unknown;
      blockDaaScore?: unknown;
      isCoinbase?: unknown;
      covenantId?: unknown;
    };
  };
  let spk: ScriptPublicKey | undefined;
  try {
    spk = spkFromRpc(x.utxoEntry?.scriptPublicKey);
  } catch {
    spk = undefined;
  }
  return {
    address: x.address,
    transactionId: x.outpoint?.transactionId,
    index: x.outpoint?.index,
    amount: x.utxoEntry?.amount,
    scriptPublicKey: spk,
    blockDaaScore: x.utxoEntry?.blockDaaScore,
    isCoinbase: x.utxoEntry?.isCoinbase,
    covenantId: x.utxoEntry?.covenantId,
  };
}

function mempoolEntry(v: unknown): MempoolEntry {
  const e = v as { fee?: unknown; is_orphan?: unknown; transaction?: unknown };
  if (typeof e !== 'object' || e === null)
    throw new RpcError('malformed mempool entry');
  const transaction = fromRpcTransaction(e.transaction);
  return {
    fee: toBigInt(e.fee, 'fee'),
    isOrphan: e.is_orphan === true,
    transaction,
    transactionId: bytesToHex(transactionId(transaction)),
  };
}

function assertSubmittable(tx: Transaction): string {
  validateTransactionStructure(tx);
  if (tx.inputs.some((i) => i.signatureScript.length === 0))
    throw invalidInput('refusing to submit an unsigned transaction');
  return bytesToHex(transactionId(tx));
}

function checkSubmittedId(v: unknown, expected: string): string {
  if (typeof v !== 'string' || v.toLowerCase() !== expected)
    throw new KaspaError(
      'RPC',
      `node reported transaction id ${String(v)}, expected ${expected}`,
    );
  return expected;
}

function checkUrl(
  url: string,
  allowInsecure: boolean,
  kind: 'ws' | 'http',
): void {
  const secure = kind === 'ws' ? /^wss:\/\/[^\s]+$/ : /^https:\/\/[^\s]+$/;
  const insecure = kind === 'ws' ? /^ws:\/\/[^\s]+$/ : /^http:\/\/[^\s]+$/;
  if (
    typeof url !== 'string' ||
    !(secure.test(url) || (allowInsecure && insecure.test(url)))
  )
    throw invalidInput(
      `${JSON.stringify(url)} is not a ${kind === 'ws' ? 'wss' : 'https'} URL (set allowInsecure for local development)`,
    );
}

function withTimeout<T>(
  p: Promise<T>,
  ms: number,
  message: string,
): Promise<T> {
  let timer: unknown;
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      timer = runtime.setTimeout(() => {
        reject(new RpcError(message));
      }, ms);
    }),
  ]).finally(() => {
    runtime.clearTimeout(timer);
  });
}

export function createWrpcClient(opts: WrpcClientOptions): KaspaWrpcClient {
  return new KaspaWrpcClient(opts);
}

export { pickFeeRate } from './rest.js';
export type { FeeEstimate, FeeTier } from './rest.js';
export type { KaspaUtxo } from './net/common.js';
export { utxosToInputPlans } from './rest.js';
