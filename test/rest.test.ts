import { Rng, TEST_XONLY, xonly } from './helpers/random.js';
import { encodeAddress } from '../src/address.js';
import { describe, expect, it } from 'vitest';
import {
  createRestClient,
  parseJsonSafe,
  pickFeeRate,
  toRestSubmitModel,
} from '../src/rest.js';
import type { FetchInitLike, FetchLike } from '../src/rest.js';
import { RestError, KaspaError } from '../src/errors.js';
import { p2pkScript } from '../src/script/standard.js';
import type { Transaction } from '../src/tx/model.js';
import { bytesToHex } from '../src/bytes.js';
import { transactionId } from '../src/tx/encode.js';
import { stringifyWithBigInt } from '../src/net/common.js';

type Call = { url: string; init: FetchInitLike | undefined };

function mockFetch(
  responder: (
    url: string,
    init?: FetchInitLike,
  ) => { status?: number; body: string },
) {
  const calls: Call[] = [];
  const f: FetchLike = async (url: string, init: FetchInitLike) => {
    calls.push({ url, init });
    const r = responder(url, init);
    return new Response(r.body, { status: r.status ?? 200 });
  };
  return { f, calls };
}

const tx: Transaction = {
  version: 0,
  inputs: [
    {
      previousOutpoint: {
        transactionId: new Uint8Array(32).fill(0xab),
        index: 1,
      },
      signatureScript: new Uint8Array([1, 2]),
      sequence: 0n,
      sigOpCount: 1,
    },
  ],
  outputs: [
    {
      value: 2_900_000_000_000_000_000n,
      scriptPublicKey: p2pkScript(TEST_XONLY),
    },
  ],
  lockTime: 0n,
  subnetworkId: new Uint8Array(20),
  gas: 0n,
  payload: new Uint8Array(0),
};

describe('REST client', () => {
  it('accepts the real global fetch without a cast', () => {
    expect(() =>
      createRestClient({ baseUrl: 'https://x.test', fetch: globalThis.fetch }),
    ).not.toThrow();
  });

  it('keeps precision on large integers', () => {
    expect(parseJsonSafe('{"balance": 12345678901234567890}')).toEqual({
      balance: '12345678901234567890',
    });
    expect(parseJsonSafe('[1, 2]')).toEqual([1, 2]);
  });

  it('parses UTXOs into bigint entries with version-0 scripts', async () => {
    const addr = encodeAddress('kaspa', 0, TEST_XONLY);
    const utxoJson = (over: Record<string, unknown> = {}) => ({
      address: addr,
      outpoint: { transactionId: 'ab'.repeat(32), index: 3 },
      utxoEntry: {
        amount: '99999999999999999',
        scriptPublicKey: {
          scriptPublicKey: '20' + bytesToHex(TEST_XONLY) + 'ac',
        },
        blockDaaScore: '7',
        isCoinbase: true,
      },
      ...over,
    });
    const { f } = mockFetch(() => ({
      body: JSON.stringify([utxoJson(), utxoJson()]),
    }));
    const [u, dup] = await createRestClient({
      baseUrl: 'https://x.test/',
      fetch: f,
    }).getUtxos([addr]);
    expect(dup).toBeUndefined();
    // A node attributing foreign coins to our address, or answering for an
    // address we never asked about, is refused.
    const other = encodeAddress('kaspa', 0, xonly(new Rng(5)));
    for (const bad of [
      utxoJson({ address: other }),
      {
        ...utxoJson(),
        utxoEntry: {
          ...utxoJson().utxoEntry,
          scriptPublicKey: {
            scriptPublicKey: '20' + bytesToHex(xonly(new Rng(6))) + 'ac',
          },
        },
      },
      { ...utxoJson(), utxoEntry: { ...utxoJson().utxoEntry, amount: 0 } },
    ]) {
      const { f: g } = mockFetch(() => ({ body: JSON.stringify([bad]) }));
      await expect(
        createRestClient({ baseUrl: 'https://x.test', fetch: g }).getUtxos([
          addr,
        ]),
      ).rejects.toThrow(/malformed UTXO/);
    }
    expect(u!.entry.amount).toBe(99_999_999_999_999_999n);
    expect(u!.entry.scriptPublicKey.version).toBe(0);
    expect(u!.entry.isCoinbase).toBe(true);
    expect(u!.outpoint.index).toBe(3);
  });

  it('submits bigints as bare JSON integers and returns the verified id', async () => {
    const id = bytesToHex(transactionId(tx));
    const { f, calls } = mockFetch(() => ({
      body: JSON.stringify({ transactionId: id }),
    }));
    expect(
      await createRestClient({ baseUrl: 'https://x.test', fetch: f }).submit(
        tx,
      ),
    ).toBe(id);
    expect(calls[0]!.url).toBe(
      'https://x.test/transactions?replaceByFee=false',
    );
    const body = String(calls[0]!.init!.body);
    expect(body).toContain('"amount":2900000000000000000');
    expect(body).toContain('"sigOpCount":1');
  });

  it('refuses a node-reported id that differs from the local transaction id', async () => {
    const { f } = mockFetch(() => ({ body: '{"transactionId":"cafe"}' }));
    await expect(
      createRestClient({ baseUrl: 'https://x.test', fetch: f }).submit(tx),
    ).rejects.toThrow(/reported transaction id/);
  });

  it('surfaces the node message verbatim on rejection', async () => {
    const { f } = mockFetch(() => ({
      status: 400,
      body: '{"detail":"transaction has 1000 fees which is under the required amount"}',
    }));
    const err = await createRestClient({ baseUrl: 'https://x.test', fetch: f })
      .submit(tx)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RestError);
    expect((err as RestError).nodeMessage).toContain(
      'under the required amount',
    );
  });

  it('refuses transactions the REST submit model cannot carry', () => {
    expect(() =>
      toRestSubmitModel({ ...tx, payload: new Uint8Array([1]) }),
    ).toThrow(KaspaError);
    expect(() => toRestSubmitModel({ ...tx, version: 1 })).toThrow(KaspaError);
  });

  it('maps fee tiers with fallbacks and a floor of 1', () => {
    const est = {
      priorityBucket: { feerate: 300, estimatedSeconds: 1 },
      normalBuckets: [{ feerate: 120, estimatedSeconds: 2 }],
      lowBuckets: [],
    };
    expect(pickFeeRate(est, 'fast')).toBe(300n);
    expect(pickFeeRate(est, 'normal')).toBe(120n);
    expect(pickFeeRate(est, 'economy')).toBe(120n);
    expect(
      pickFeeRate(
        {
          ...est,
          priorityBucket: { feerate: 0.2, estimatedSeconds: 1 },
          normalBuckets: [],
        },
        'fast',
      ),
    ).toBe(1n);
  });

  it('covers the read endpoints, query building and timeouts', async () => {
    const routes: Record<string, string> = {
      '/addresses/kaspa%3Aa/balance':
        '{"address":"kaspa:a","balance":98765432109876543}',
      '/info/fee-estimate':
        '{"priorityBucket":{"feerate":2,"estimatedSeconds":1},"normalBuckets":[],"lowBuckets":[]}',
      '/info/virtual-chain-blue-score': '{"blueScore":546273992}',
      '/info/blockdag': '{"virtualDaaScore":"548220557"}',
      '/transactions/abc?resolve_previous_outpoints=full':
        '{"transaction_id":"abc"}',
      '/addresses/kaspa%3Aa/full-transactions-page?limit=5&before=10&resolve_previous_outpoints=light&acceptance=accepted':
        '[{"transaction_id":"h1"}]',
    };
    const calls: string[] = [];
    const f: FetchLike = async (url, init) => {
      const path = url.replace('https://x.test', '');
      calls.push(`${init.method} ${path}`);
      if (path === '/transactions/mass')
        return new Response('{"mass":10,"storage_mass":3,"compute_mass":10}');
      if (path === '/transactions/acceptance')
        return new Response('[{"transactionId":"abc","accepted":true}]');
      if (path === '/addresses/utxos') return new Response('[]');
      const body = routes[path];
      return new Response(body ?? '{"detail":"nope"}', {
        status: body ? 200 : 404,
      });
    };
    const c = createRestClient({ baseUrl: 'https://x.test/', fetch: f });
    expect(await c.getBalance('kaspa:a')).toBe(98_765_432_109_876_543n);
    expect(pickFeeRate(await c.getFeeEstimate(), 'fast')).toBe(2n);
    expect(await c.getVirtualChainBlueScore()).toBe(546_273_992n);
    expect(await c.getVirtualDaaScore()).toBe(548_220_557n);
    expect(
      (await c.getTransaction('abc', { resolvePreviousOutpoints: 'full' }))
        .transaction_id,
    ).toBe('abc');
    expect(
      await c.getHistoryPage('kaspa:a', {
        limit: 5,
        before: 10,
        acceptance: 'accepted',
      }),
    ).toHaveLength(1);
    expect(await c.getMass(tx)).toEqual({
      mass: 10n,
      storageMass: 3n,
      computeMass: 10n,
    });
    expect((await c.getTransactionAcceptance(['abc']))[0]!.accepted).toBe(true);
    expect(
      await c.getUtxos([
        encodeAddress('kaspa', 0, TEST_XONLY),
        encodeAddress('kaspa', 8, new Uint8Array(32)),
      ]),
    ).toEqual([]);
    expect(await c.getUtxos([])).toEqual([]);
    await expect(c.getTransaction('missing')).rejects.toThrow(RestError);
    expect(calls).toContain('POST /addresses/utxos');

    const slow = createRestClient({
      baseUrl: 'https://x.test',
      timeoutMs: 20,
      fetch: () => new Promise<never>(() => undefined),
    });
    await expect(slow.getBalance('kaspa:a')).rejects.toThrow(/timed out/);
  });
});

describe('REST funding-transaction proofs', () => {
  function restView(t: Transaction, amountDelta = 0n) {
    return {
      transaction_id: bytesToHex(transactionId(t)),
      version: t.version,
      subnetwork_id: bytesToHex(t.subnetworkId),
      payload: t.payload.length ? bytesToHex(t.payload) : null,
      inputs: t.inputs.map((i, index) => ({
        index,
        previous_outpoint_hash: bytesToHex(i.previousOutpoint.transactionId),
        previous_outpoint_index: String(i.previousOutpoint.index),
        signature_script: bytesToHex(i.signatureScript),
        sig_op_count: String(i.sigOpCount),
      })),
      outputs: t.outputs.map((o, index) => ({
        index,
        amount: o.value + (index === 0 ? amountDelta : 0n),
        script_public_key: bytesToHex(o.scriptPublicKey.script),
      })),
    };
  }
  const client = (body: unknown) =>
    createRestClient({
      baseUrl: 'https://x.test',
      fetch: async () => ({
        ok: true,
        status: 200,
        text: async () => stringifyWithBigInt(body),
      }),
    });

  it('returns the transaction only when it hashes to the requested id', async () => {
    const id = bytesToHex(transactionId(tx));
    const got = await client(restView(tx)).getFundingTransaction(id);
    expect(bytesToHex(transactionId(got))).toBe(id);
    expect(got.outputs[0]!.value).toBe(tx.outputs[0]!.value);
  });

  it('a server lying about an amount cannot pass the proof', async () => {
    const id = bytesToHex(transactionId(tx));
    await expect(
      client(restView(tx, 1n)).getFundingTransaction(id),
    ).rejects.toThrow(/could not be proven/);
    await expect(
      client({ ...restView(tx), inputs: [{ index: 3 }] }).getFundingTransaction(
        id,
      ),
    ).rejects.toThrow(/malformed transaction/);
    await expect(
      client(restView(tx)).getFundingTransaction('zz'),
    ).rejects.toThrow(KaspaError);
  });
});
