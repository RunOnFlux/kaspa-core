import { describe, expect, it } from 'vitest';
import { encodeAddress } from '../src/address.js';
import { bytesToHex } from '../src/bytes.js';
import {
  KaspaError,
  RestError,
  RpcError,
  SubmitOutcomeUnknownError,
} from '../src/errors.js';
import { planTransaction } from '../src/plan.js';
import { createRestClient } from '../src/rest.js';
import { p2pkScript } from '../src/script/standard.js';
import {
  createTransaction,
  finalizeTransaction,
  localSigner,
  signTransaction,
} from '../src/sign.js';
import { spendScriptPublicKey } from '../src/spend.js';
import type { InputPlan, Spend } from '../src/spend.js';
import { transactionId } from '../src/tx/encode.js';
import type { Transaction } from '../src/tx/model.js';
import {
  createWrpcClient,
  fromRpcTransaction,
  pickFeeRate,
  toRpcTransaction,
  utxosToInputPlans,
} from '../src/wrpc.js';
import type {
  WebSocketFactory,
  WebSocketLike,
  WrpcClientOptions,
} from '../src/wrpc.js';
import { Rng, TEST_XONLY, xonly } from './helpers/random.js';
import { parseJsonSafe, stringifyWithBigInt } from '../src/net/common.js';

/** What the node would see on the wire. */
const wire = (x: unknown): unknown => parseJsonSafe(stringifyWithBigInt(x));

// ---------------------------------------------------------------------------
// A fake kaspad JSON-wRPC endpoint
// ---------------------------------------------------------------------------

interface Req {
  id: number;
  method: string;
  params: Record<string, unknown>;
}
type Handler = (req: Req, node: FakeNode) => unknown;

class FakeNode {
  sockets: FakeSocket[] = [];
  received: { url: string; raw: string; req: Req }[] = [];
  info = {
    hasUtxoIndex: true,
    isSynced: true,
    networkId: 'mainnet',
    rpcApiRevision: 0,
    rpcApiVersion: 1,
    serverVersion: '2.1.0',
    virtualDaaScore: 548260860,
  };
  handlers: Record<string, Handler> = {};
  /** URLs whose sockets fail before `open`. */
  dead = new Set<string>();

  factory = (url: string): WebSocketLike => {
    const s = new FakeSocket(url, this);
    this.sockets.push(s);
    return s;
  };

  notify(method: string, params: unknown): void {
    for (const s of this.sockets)
      if (s.readyState === 1) s.push(JSON.stringify({ method, params }));
  }
}

class FakeSocket implements WebSocketLike {
  readyState = 0;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null = null;

  constructor(
    readonly url: string,
    private readonly node: FakeNode,
  ) {
    setTimeout(() => {
      if (node.dead.has(url)) {
        this.readyState = 3;
        this.onerror?.({});
        this.onclose?.({ code: 1006 });
        return;
      }
      this.readyState = 1;
      this.onopen?.({});
    }, 0);
  }

  send(data: string): void {
    const req = JSON.parse(data) as Req;
    this.node.received.push({ url: this.url, raw: data, req });
    setTimeout(() => {
      if (this.readyState !== 1) return;
      const h = this.node.handlers[req.method];
      let body: unknown;
      if (req.method === 'getServerInfo' && !h)
        body = { params: this.node.info };
      else if (!h)
        body = {
          error: { code: 0, message: 'RPC method not found', data: null },
        };
      else {
        try {
          const r = h(req, this.node);
          if (r === NO_REPLY) return;
          body = typeof r === 'string' ? { raw: r } : { params: r };
        } catch (e) {
          body = {
            error: { code: 0, message: (e as Error).message, data: null },
          };
        }
      }
      const b = body as { raw?: string };
      this.push(
        b.raw !== undefined
          ? b.raw.replace('__ID__', String(req.id))
          : JSON.stringify({
              id: req.id,
              method: req.method,
              ...(body as object),
            }),
      );
    }, 0);
  }

  push(text: string): void {
    this.onmessage?.({ data: text });
  }

  close(): void {
    if (this.readyState === 3) return;
    this.readyState = 3;
    setTimeout(() => this.onclose?.({ code: 1000 }), 0);
  }

  /** Simulate the server dropping the connection. */
  drop(): void {
    this.readyState = 3;
    this.onclose?.({ code: 1006 });
  }
}

const NO_REPLY = Symbol('no reply');

const rng = new Rng(8080);
const owner = localSigner(rng.secretKey());
const single: Spend = { kind: 'p2pk', xOnlyPubkey: owner.xOnlyPublicKey };
const ADDR = encodeAddress('kaspa', 0, owner.xOnlyPublicKey);
const SPK_HEX = '0000' + bytesToHex(p2pkScript(owner.xOnlyPublicKey).script);

function client(node: FakeNode, extra: Partial<WrpcClientOptions> = {}) {
  return createWrpcClient({
    networkId: 'mainnet',
    urls: ['wss://a.test/json'],
    webSocket: node.factory,
    keepaliveMs: 0,
    requestTimeoutMs: 200,
    connectTimeoutMs: 200,
    ...extra,
  });
}

function utxoJson(
  over: Record<string, unknown> = {},
  entry: Record<string, unknown> = {},
) {
  return {
    address: ADDR,
    outpoint: { index: 1, transactionId: 'cd'.repeat(32) },
    utxoEntry: {
      amount: 500000000,
      blockDaaScore: 23097751,
      covenantId: null,
      isCoinbase: false,
      scriptPublicKey: SPK_HEX,
      ...entry,
    },
    ...over,
  };
}

async function signedTx(
  version: 0 | 1 = 0,
  payload = new Uint8Array(0),
): Promise<{
  tx: Transaction;
  inputs: InputPlan[];
}> {
  const inputs: InputPlan[] = [
    {
      outpoint: { transactionId: rng.bytes(32), index: 0 },
      entry: {
        amount: 10n ** 10n,
        scriptPublicKey: spendScriptPublicKey(single),
        blockDaaScore: 1n,
        isCoinbase: false,
      },
      spend: single,
    },
  ];
  const unsigned = createTransaction({
    inputs,
    outputs: [
      {
        value: 10n ** 10n - 1_000_000n,
        scriptPublicKey: p2pkScript(TEST_XONLY),
      },
    ],
    version,
    payload,
  });
  const tx = finalizeTransaction(
    unsigned,
    inputs,
    await signTransaction(unsigned, inputs, [owner]),
  );
  return { tx, inputs };
}

// ---------------------------------------------------------------------------

describe('wRPC: connection and node verification', () => {
  it('frames requests exactly as the node expects and reads results from params', async () => {
    const node = new FakeNode();
    node.handlers.getBalanceByAddress = () => ({ balance: 7 });
    const c = client(node);
    expect(await c.getBalance(ADDR)).toBe(7n);
    const frame = JSON.parse(
      node.received[node.received.length - 1]!.raw,
    ) as Record<string, unknown>;
    expect(Object.keys(frame).sort()).toEqual(['id', 'method', 'params']);
    expect(frame.method).toBe('getBalanceByAddress');
    expect(frame.params).toEqual({ address: ADDR });
    expect(Number.isInteger(frame.id)).toBe(true);
    expect(node.received[0]!.req.method).toBe('getServerInfo');
    c.close();
  });

  it.each([
    [
      'wrong network',
      { networkId: 'testnet-10' },
      /testnet-10, expected mainnet/,
    ],
    ['not synced', { isSynced: false }, /not synced/],
    ['no UTXO index', { hasUtxoIndex: false }, /no UTXO index/],
  ])(
    'refuses a node that is on the %s, and fails over to the next URL',
    async (_n, info, err) => {
      const bad = new FakeNode();
      Object.assign(bad.info, info);
      const c = client(bad, { urls: ['wss://a.test/json'] });
      await expect(c.connect()).rejects.toThrow(err);
      expect(c.isConnected).toBe(false);

      const node = new FakeNode();
      const sockets: string[] = [];
      const factory = (url: string) => {
        sockets.push(url);
        if (url.includes('bad')) {
          const f = bad.factory(url);
          return f;
        }
        return node.factory(url);
      };
      const c2 = client(node, {
        urls: ['wss://bad.test/json', 'wss://good.test/json'],
        webSocket: factory,
      });
      await c2.connect();
      expect(c2.currentUrl).toBe('wss://good.test/json');
      c2.close();
    },
  );

  it('never sends a caller request to a node before it has been verified', async () => {
    const node = new FakeNode();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    node.handlers.getServerInfo = () => {
      void gate.then(() => {
        const s = node.sockets[0]!;
        const req = node.received.find(
          (r) => r.req.method === 'getServerInfo',
        )!.req;
        s.push(
          JSON.stringify({
            id: req.id,
            method: 'getServerInfo',
            params: { ...node.info, networkId: 'testnet-10' },
          }),
        );
      });
      return NO_REPLY;
    };
    node.handlers.getUtxosByAddresses = () => ({ entries: [utxoJson()] });
    const c = client(node, { requestTimeoutMs: 1000 });
    const p = c.getUtxos([ADDR]);
    await new Promise((r) => setTimeout(r, 20));
    release();
    await expect(p).rejects.toThrow(/expected mainnet/);
    expect(node.received.map((r) => r.req.method)).not.toContain(
      'getUtxosByAddresses',
    );
    c.close();
  });

  it('refuses insecure URLs, unknown networks and unknown ops', async () => {
    const node = new FakeNode();
    expect(() => client(node, { urls: ['ws://a.test'] })).toThrow(KaspaError);
    expect(() => client(node, { urls: ['https://a.test'] })).toThrow(
      KaspaError,
    );
    expect(() =>
      client(node, { urls: ['ws://a.test'], allowInsecure: true }),
    ).not.toThrow();
    expect(() => client(node, { networkId: 'devnet' as 'mainnet' })).toThrow(
      KaspaError,
    );
    const c = client(node);
    await expect(c.call('shutdown' as 'ping', {})).rejects.toThrow(
      /unsupported wRPC op/,
    );
    await expect(
      c.call('ping', [] as unknown as Record<string, unknown>),
    ).rejects.toThrow(/object/);
    expect(node.received.map((r) => r.req.method)).not.toContain('shutdown');
    c.close();
  });

  it('times out a request the node never answers and rejects in-flight requests on close', async () => {
    const node = new FakeNode();
    node.handlers.getBalanceByAddress = () => NO_REPLY;
    const c = client(node);
    await expect(c.getBalance(ADDR)).rejects.toThrow(/timed out/);
    const p = c.getBalance(ADDR);
    await new Promise((r) => setTimeout(r, 5));
    c.close();
    await expect(p).rejects.toThrow(/client closed/);
  });

  it('turns a node error into an RpcError carrying the node message', async () => {
    const node = new FakeNode();
    node.handlers.getBalanceByAddress = () => {
      throw new Error('request deserialization error');
    };
    const c = client(node);
    const e = await c.getBalance(ADDR).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(RpcError);
    expect((e as RpcError).nodeMessage).toBe('request deserialization error');
    c.close();
  });

  it('drops an oversized frame and the connection instead of parsing it', async () => {
    const node = new FakeNode();
    node.handlers.getBalanceByAddress = () =>
      `{"id":__ID__,"method":"getBalanceByAddress","params":{"balance":1,"pad":"${'x'.repeat(5000)}"}}`;
    const c = client(node, { maxMessageSize: 1000, autoReconnect: false });
    await expect(c.getBalance(ADDR)).rejects.toThrow(/connection lost/);
    c.close();
  });

  it('resolves a node through a resolver, requesting Borsh and connecting to /wrpc/json', async () => {
    const node = new FakeNode();
    const asked: string[] = [];
    const c = client(node, {
      urls: [],
      resolvers: ['https://r1.test', 'https://r2.test'],
      fetch: async (url: string) => {
        asked.push(url);
        if (url.startsWith('https://r1.test'))
          return { ok: false, status: 523, text: async () => '' };
        return {
          ok: true,
          status: 200,
          text: async () =>
            '{"uid":"1","url":"wss://kate.kaspa.red/kaspa/mainnet/wrpc/borsh"}',
        };
      },
    });
    await c.connect();
    expect(c.currentUrl).toBe('wss://kate.kaspa.red/kaspa/mainnet/wrpc/json');
    expect(
      asked.every((u) => u.endsWith('/v2/kaspa/mainnet/tls/wrpc/borsh')),
    ).toBe(true);
    c.close();

    const evil = client(node, {
      urls: [],
      resolvers: ['https://r.test'],
      fetch: async () => ({
        ok: true,
        status: 200,
        text: async () => '{"url":"ws://evil.test/wrpc/borsh"}',
      }),
    });
    await expect(evil.connect()).rejects.toThrow(/could not connect/);
  });
});

describe('wRPC: data from the node is untrusted', () => {
  it('keeps full 64-bit precision on balances', async () => {
    const node = new FakeNode();
    node.handlers.getBalanceByAddress = () =>
      '{"id":__ID__,"method":"getBalanceByAddress","params":{"balance":1152921504606846977}}';
    const c = client(node);
    expect(await c.getBalance(ADDR)).toBe(1152921504606846977n);
    c.close();
  });

  it('parses UTXOs with versioned scripts and de-duplicates them', async () => {
    const node = new FakeNode();
    node.handlers.getUtxosByAddresses = (req) => {
      expect(req.params).toEqual({ addresses: [ADDR] });
      return { entries: [utxoJson(), utxoJson()] };
    };
    const c = client(node);
    const us = await c.getUtxos([ADDR]);
    expect(us).toHaveLength(1);
    expect(us[0]!.entry.amount).toBe(500_000_000n);
    expect(us[0]!.entry.scriptPublicKey.version).toBe(0);
    expect(bytesToHex(us[0]!.entry.scriptPublicKey.script)).toBe(
      SPK_HEX.slice(4),
    );
    c.close();
  });

  it.each([
    [
      'a foreign script attributed to our address',
      utxoJson(
        {},
        { scriptPublicKey: '0000' + bytesToHex(p2pkScript(xonly(rng)).script) },
      ),
    ],
    [
      'an address we never asked about',
      utxoJson({ address: encodeAddress('kaspa', 0, xonly(rng)) }),
    ],
    ['a zero amount', utxoJson({}, { amount: 0 })],
    [
      'a negative index',
      utxoJson({ outpoint: { index: -1, transactionId: 'cd'.repeat(32) } }),
    ],
    ['a bad txid', utxoJson({ outpoint: { index: 0, transactionId: 'zz' } })],
    [
      'a non-zero script version',
      utxoJson({}, { scriptPublicKey: '0001' + SPK_HEX.slice(4) }),
    ],
  ])('refuses %s', async (_n, bad) => {
    const node = new FakeNode();
    node.handlers.getUtxosByAddresses = () => ({ entries: [bad] });
    const c = client(node);
    await expect(c.getUtxos([ADDR])).rejects.toThrow(/malformed UTXO/);
    c.close();
  });

  it('refuses addresses from another network before sending anything', async () => {
    const node = new FakeNode();
    const c = client(node);
    await expect(
      c.getUtxos([encodeAddress('kaspatest', 0, TEST_XONLY)]),
    ).rejects.toThrow(KaspaError);
    expect(node.received.map((r) => r.req.method)).not.toContain(
      'getUtxosByAddresses',
    );
    c.close();
  });

  it('fee estimates are clamped by pickFeeRate', async () => {
    const node = new FakeNode();
    node.handlers.getFeeEstimate = () => ({
      estimate: {
        lowBuckets: [{ estimatedSeconds: 1, feerate: 100.0 }],
        normalBuckets: [{ estimatedSeconds: 1, feerate: 1e12 }],
        priorityBucket: { estimatedSeconds: 1, feerate: 150.5 },
      },
    });
    const c = client(node);
    const est = await c.getFeeEstimate();
    expect(pickFeeRate(est, 'normal')).toBe(10_000n);
    expect(pickFeeRate(est, 'fast')).toBe(151n);
    c.close();
  });
});

describe('wRPC: transaction encoding and submission', () => {
  it('v0: sigOpCount, no computeBudget, u64s as bare integers, spk as a versioned hex string', async () => {
    const { tx } = await signedTx(0);
    const json = toRpcTransaction(tx);
    const input = (json.inputs as Record<string, unknown>[])[0]!;
    expect(input.sigOpCount).toBe(1);
    expect('computeBudget' in input).toBe(false);
    const out = (json.outputs as Record<string, unknown>[])[0]!;
    expect(out.scriptPublicKey).toBe(
      '0000' + bytesToHex(p2pkScript(TEST_XONLY).script),
    );
    expect(json.mass).toBe(0);
    expect(bytesToHex(transactionId(fromRpcTransaction(json)))).toBe(
      bytesToHex(transactionId(tx)),
    );
  });

  it('v1 with payload: sigOpCount 0 plus the compute budget, and round-trips', async () => {
    const { tx } = await signedTx(1, Uint8Array.of(1, 2, 3));
    const json = toRpcTransaction(tx);
    const input = (json.inputs as Record<string, unknown>[])[0]!;
    expect(input.sigOpCount).toBe(0);
    expect(input.computeBudget).toBe(10);
    expect(json.payload).toBe('010203');
    const back = fromRpcTransaction(wire(json));
    expect(back.inputs[0]!.computeBudget).toBe(10);
    expect(bytesToHex(transactionId(back))).toBe(bytesToHex(transactionId(tx)));
  });

  it('submits and returns the id only when the node reports the one computed locally', async () => {
    const { tx } = await signedTx(1, Uint8Array.of(9));
    const id = bytesToHex(transactionId(tx));
    const node = new FakeNode();
    let sent: Record<string, unknown> | undefined;
    node.handlers.submitTransaction = (req) => {
      sent = req.params;
      return { transactionId: id };
    };
    const c = client(node);
    expect(await c.submitTransaction(tx)).toBe(id);
    expect(sent?.allowOrphan).toBe(false);
    const raw = node.received.find(
      (r) => r.req.method === 'submitTransaction',
    )!.raw;
    expect(raw).toContain('"sequence":0');
    expect(raw).not.toContain('"sequence":"0"');

    node.handlers.submitTransaction = () => ({
      transactionId: 'ab'.repeat(32),
    });
    await expect(c.submitTransaction(tx)).rejects.toThrow(/expected/);
    c.close();
  });

  it('refuses to submit an unsigned or structurally invalid transaction', async () => {
    const { tx } = await signedTx(0);
    const node = new FakeNode();
    const c = client(node);
    const unsigned = {
      ...tx,
      inputs: tx.inputs.map((i) => ({
        ...i,
        signatureScript: new Uint8Array(0),
      })),
    };
    await expect(c.submitTransaction(unsigned)).rejects.toThrow(/unsigned/);
    const zero = { ...tx, outputs: [{ ...tx.outputs[0]!, value: 0n }] };
    await expect(c.submitTransaction(zero)).rejects.toThrow(KaspaError);
    expect(node.received.map((r) => r.req.method)).not.toContain(
      'submitTransaction',
    );
    c.close();
  });

  it('decodes mempool entries (snake_case is_orphan) and computes their ids locally', async () => {
    const { tx } = await signedTx(0);
    const node = new FakeNode();
    node.handlers.getMempoolEntriesByAddresses = () => ({
      entries: [
        {
          address: ADDR,
          receiving: [],
          sending: [
            {
              fee: 2000000,
              is_orphan: false,
              transaction: wire(toRpcTransaction(tx)),
            },
          ],
        },
      ],
    });
    node.handlers.getMempoolEntry = () => {
      throw new Error('Transaction 00 not found');
    };
    const c = client(node);
    const [e] = await c.getMempoolEntriesByAddresses([ADDR]);
    expect(e!.sending[0]!.fee).toBe(2_000_000n);
    expect(e!.sending[0]!.transactionId).toBe(bytesToHex(transactionId(tx)));
    expect(await c.getMempoolEntry('00'.repeat(32))).toBeNull();
    c.close();
  });
});

describe('wRPC: subscriptions', () => {
  it('delivers validated UTXO changes for our addresses only', async () => {
    const node = new FakeNode();
    node.handlers.subscribe = () => ({ id: 6619 });
    node.handlers.unsubscribe = () => ({});
    const c = client(node);
    const changes: unknown[] = [];
    const off = await c.subscribeUtxosChanged([ADDR], (ch) => changes.push(ch));
    const sub = node.received.find((r) => r.req.method === 'subscribe')!.req;
    expect(sub.params).toEqual({ UtxosChanged: { addresses: [ADDR] } });

    node.notify('utxosChangedNotification', {
      UtxosChanged: {
        added: [
          utxoJson(),
          utxoJson({ address: encodeAddress('kaspa', 0, xonly(rng)) }),
        ],
        removed: [],
      },
    });
    // Not ours at all: dropped without a callback.
    node.notify('utxosChangedNotification', {
      UtxosChanged: {
        added: [utxoJson({ address: encodeAddress('kaspa', 0, xonly(rng)) })],
        removed: [],
      },
    });
    await new Promise((r) => setTimeout(r, 5));
    expect(changes).toHaveLength(1);
    expect((changes[0] as { added: unknown[] }).added).toHaveLength(1);

    await off();
    expect(node.received[node.received.length - 1]!.req).toMatchObject({
      method: 'unsubscribe',
      params: { UtxosChanged: { addresses: [ADDR] } },
    });
    c.close();
  });

  it('re-subscribes after the connection drops', async () => {
    const node = new FakeNode();
    node.handlers.subscribe = () => ({ id: 1 });
    const states: boolean[] = [];
    const c = client(node, { onConnectionChange: (up) => states.push(up) });
    const scores: bigint[] = [];
    await c.subscribeVirtualDaaScore((s) => scores.push(s));
    node.notify('virtualDaaScoreChangedNotification', {
      VirtualDaaScoreChanged: { virtualDaaScore: 5 },
    });
    await new Promise((r) => setTimeout(r, 5));
    node.sockets[0]!.drop();
    await new Promise((r) => setTimeout(r, 1200));
    expect(c.isConnected).toBe(true);
    expect(node.sockets).toHaveLength(2);
    const subs = node.received.filter((r) => r.req.method === 'subscribe');
    expect(subs).toHaveLength(2);
    expect(subs[1]!.url).toBe('wss://a.test/json');
    node.notify('virtualDaaScoreChangedNotification', {
      VirtualDaaScoreChanged: { virtualDaaScore: 6 },
    });
    await new Promise((r) => setTimeout(r, 5));
    expect(scores).toEqual([5n, 6n]);
    expect(states).toEqual([true, false, true]);
    c.close();
  });
});

// ---------------------------------------------------------------------------
// Second independent review (network layer) — each finding reproduced
// ---------------------------------------------------------------------------

describe('wRPC review: liveness and lifecycle', () => {
  it('M1: an unanswered keepalive ping tears down a half-open connection', async () => {
    const node = new FakeNode();
    node.handlers.ping = () => NO_REPLY;
    node.handlers.getBalanceByAddress = () => ({ balance: 1 });
    const states: boolean[] = [];
    const c = client(node, {
      keepaliveMs: 40,
      onConnectionChange: (up) => states.push(up),
    });
    await c.connect();
    await new Promise((r) => setTimeout(r, 150));
    expect(c.isConnected).toBe(false);
    expect(states).toEqual([true, false]);
    // The next call reconnects on demand.
    expect(await c.getBalance(ADDR)).toBe(1n);
    expect(node.sockets.length).toBe(2);
    c.close();
  });

  it('M2: a resolver that stalls mid-body cannot hang connect()', async () => {
    const node = new FakeNode();
    const c = client(node, {
      urls: [],
      resolvers: ['https://r.test'],
      connectTimeoutMs: 100,
      fetch: async () => ({
        ok: true,
        status: 200,
        text: () => new Promise<string>(() => undefined),
      }),
    });
    const t0 = Date.now();
    await expect(c.connect()).rejects.toThrow(/could not connect/);
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it('M2: an oversized resolver body is refused', async () => {
    const node = new FakeNode();
    const c = client(node, {
      urls: [],
      resolvers: ['https://r.test'],
      fetch: async () => ({
        ok: true,
        status: 200,
        text: async () =>
          `{"url":"wss://a.test/wrpc/borsh","pad":"${'x'.repeat(5000)}"}`,
      }),
    });
    await expect(c.connect()).rejects.toThrow(/could not connect/);
  });

  it('L1: close() then connect() starts a fresh attempt', async () => {
    const node = new FakeNode();
    const c = client(node, { connectTimeoutMs: 300 });
    const first = c.connect();
    c.close();
    await expect(first).rejects.toThrow(/client closed/);
    const t0 = Date.now();
    await c.connect();
    expect(Date.now() - t0).toBeLessThan(200);
    expect(c.isConnected).toBe(true);
    c.close();
  });

  it('L2: calls after close() are refused instead of silently reconnecting', async () => {
    const node = new FakeNode();
    const c = client(node);
    await c.connect();
    c.close();
    const sockets = node.sockets.length;
    await expect(c.getBalance(ADDR)).rejects.toThrow(/client closed/);
    expect(node.sockets.length).toBe(sockets);
  });

  it('L3: a throwing onConnectionChange cannot fail a good connection', async () => {
    const node = new FakeNode();
    const c = client(node, {
      onConnectionChange: () => {
        throw new Error('UI bug');
      },
    });
    await c.connect();
    expect(c.isConnected).toBe(true);
    c.close();
  });
});

describe('wRPC review: submissions and mempool', () => {
  it('M4: a submit that times out is "outcome unknown", a node rejection is not', async () => {
    const { tx } = await signedTx(0);
    const node = new FakeNode();
    node.handlers.submitTransaction = () => NO_REPLY;
    const c = client(node);
    const e = await c.submitTransaction(tx).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(SubmitOutcomeUnknownError);
    expect((e as SubmitOutcomeUnknownError).transactionId).toBe(
      bytesToHex(transactionId(tx)),
    );
    node.handlers.submitTransaction = () => {
      throw new Error('Rejected transaction x: orphan');
    };
    const r = await c.submitTransaction(tx).catch((x: unknown) => x);
    expect(r).toBeInstanceOf(RpcError);
    expect(r).not.toBeInstanceOf(SubmitOutcomeUnknownError);
    c.close();
  });

  it('M4: REST submit — timeout is outcome unknown, an HTTP error is not', async () => {
    const { tx } = await signedTx(0);
    const slow = createRestClient({
      baseUrl: 'https://x.test',
      timeoutMs: 20,
      fetch: () => new Promise<never>(() => undefined),
    });
    await expect(slow.submit(tx)).rejects.toBeInstanceOf(
      SubmitOutcomeUnknownError,
    );
    const rejecting = createRestClient({
      baseUrl: 'https://x.test',
      fetch: async () => ({
        ok: false,
        status: 400,
        text: async () => '{"detail":"orphan"}',
      }),
    });
    await expect(rejecting.submit(tx)).rejects.toBeInstanceOf(RestError);
  });

  it('M3: a mempool entry for a different transaction is refused', async () => {
    const { tx } = await signedTx(0);
    const node = new FakeNode();
    node.handlers.getMempoolEntry = () => ({
      mempoolEntry: {
        fee: 1,
        is_orphan: false,
        transaction: wire(toRpcTransaction(tx)),
      },
    });
    const c = client(node);
    await expect(c.getMempoolEntry('ee'.repeat(32))).rejects.toThrow(
      /different transaction/,
    );
    const id = bytesToHex(transactionId(tx));
    expect((await c.getMempoolEntry(id))?.transactionId).toBe(id);
    c.close();
  });

  it('L9: a "receiving" mempool entry must pay the address', async () => {
    const { tx } = await signedTx(0); // pays TEST_XONLY, not ADDR
    const node = new FakeNode();
    node.handlers.getMempoolEntriesByAddresses = () => ({
      entries: [
        {
          address: ADDR,
          sending: [],
          receiving: [
            {
              fee: 1,
              is_orphan: false,
              transaction: wire(toRpcTransaction(tx)),
            },
          ],
        },
      ],
    });
    const c = client(node);
    await expect(c.getMempoolEntriesByAddresses([ADDR])).rejects.toThrow(
      /does not pay/,
    );
    c.close();
  });
});

describe('wRPC review: encoding and validation edge cases', () => {
  it('L4: the bigint marker cannot be injected and only u64 bigints serialise', () => {
    expect(() => stringifyWithBigInt({ a: -5n })).toThrow(/u64/);
    expect(() => stringifyWithBigInt({ a: 1n << 64n })).toThrow(/u64/);
    expect(stringifyWithBigInt({ a: (1n << 64n) - 1n })).toBe(
      '{"a":18446744073709551615}',
    );
    const out = stringifyWithBigInt({ __kaspa_bigint__1: 'x', v: 7n });
    expect(JSON.parse(out)).toEqual({ __kaspa_bigint__1: 'x', v: 7 });
  });

  it('L5: covenant-bound UTXOs keep their covenant id and are never selected by the planner', async () => {
    const node = new FakeNode();
    node.handlers.getUtxosByAddresses = () => ({
      entries: [utxoJson({}, { covenantId: 'ab'.repeat(32) })],
    });
    const c = client(node);
    const [u] = await c.getUtxos([ADDR]);
    expect(bytesToHex(u!.entry.covenantId!)).toBe('ab'.repeat(32));
    const plans = utxosToInputPlans([u!], single);
    expect(() =>
      planTransaction(
        plans,
        [{ scriptPublicKey: p2pkScript(TEST_XONLY), amount: 1000n }],
        {
          feeRate: 1n,
          changeSpend: single,
        },
      ),
    ).toThrow(KaspaError);
    c.close();
  });

  it('L7: the platform WebSocket is assignable without a cast', () => {
    const f: WebSocketFactory = (u) => new WebSocket(u);
    expect(typeof f).toBe('function');
  });

  it('L8: malformed but well-framed responses are RpcErrors, not TypeErrors', async () => {
    const node = new FakeNode();
    node.handlers.getBalanceByAddress = () =>
      '{"id":__ID__,"method":"getBalanceByAddress"}';
    node.handlers.getBalancesByAddresses = () => ({ entries: [null] });
    const c = client(node);
    await expect(c.getBalance(ADDR)).rejects.toBeInstanceOf(RpcError);
    await expect(c.getBalances([ADDR])).rejects.toBeInstanceOf(RpcError);
    expect(() =>
      fromRpcTransaction({
        version: 0,
        inputs: [null],
        outputs: [],
        lockTime: 0,
        subnetworkId: '00'.repeat(20),
      }),
    ).toThrow(RpcError);
    c.close();
  });

  it('I1: prototype keys are not networks', () => {
    expect(() =>
      client(new FakeNode(), { networkId: 'toString' as 'mainnet' }),
    ).toThrow(KaspaError);
  });

  it('I4: a REST client pinned to mainnet refuses testnet addresses', async () => {
    const rest = createRestClient({
      baseUrl: 'https://x.test',
      prefix: 'kaspa',
      fetch: async () => ({ ok: true, status: 200, text: async () => '[]' }),
    });
    await expect(
      rest.getUtxos([encodeAddress('kaspatest', 0, TEST_XONLY)]),
    ).rejects.toThrow(KaspaError);
  });
});
