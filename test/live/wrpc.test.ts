import { afterAll, describe, expect, it } from 'vitest';
import { bytesToHex } from '../../src/bytes.js';
import { RpcError } from '../../src/errors.js';
import { IGRA_SUBNETWORK_ID } from '../../src/protocols/igra.js';
import { p2pkScript } from '../../src/script/standard.js';
import {
  createTransaction,
  finalizeTransaction,
  localSigner,
  signTransaction,
} from '../../src/sign.js';
import { spendScriptPublicKey } from '../../src/spend.js';
import type { InputPlan, Spend } from '../../src/spend.js';
import { transactionId } from '../../src/tx/encode.js';
import { createWrpcClient, pickFeeRate } from '../../src/wrpc.js';
import { createRestClient } from '../../src/rest.js';
import { Rng, TEST_XONLY } from '../helpers/random.js';

/**
 * Live mainnet wRPC checks — `yarn test:live`. Connects through the public
 * resolvers (or KASPA_WRPC=wss://…/json). No funds move: the submissions
 * spend outpoints that do not exist, and the node's orphan rejection quotes
 * the transaction ID it computed from our encoding.
 */
const LIVE = process.env.KASPA_LIVE === '1';
const URL = process.env.KASPA_WRPC;
const BUSY =
  'kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73';

const client = createWrpcClient({
  networkId: 'mainnet',
  ...(URL ? { urls: [URL] } : {}),
  requestTimeoutMs: 45_000,
});

afterAll(() => {
  client.close();
});

async function unspendable(
  version: 0 | 1,
  payload: Uint8Array,
  subnetworkId?: Uint8Array,
) {
  const rng = new Rng(Date.now());
  const owner = localSigner(rng.secretKey());
  const single: Spend = { kind: 'p2pk', xOnlyPubkey: owner.xOnlyPublicKey };
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
    ...(subnetworkId ? { subnetworkId } : {}),
  });
  return finalizeTransaction(
    unsigned,
    inputs,
    await signTransaction(unsigned, inputs, [owner]),
  );
}

describe.skipIf(!LIVE)('live mainnet wRPC', () => {
  it('connects to a verified, synced mainnet node with a UTXO index', async () => {
    await client.connect();
    const info = await client.getServerInfo();
    expect(info.networkId).toBe('mainnet');
    expect(info.isSynced).toBe(true);
    expect(info.hasUtxoIndex).toBe(true);
    expect(client.currentUrl).toMatch(/^wss:\/\//);
    expect(await client.getVirtualDaaScore()).toBeGreaterThan(548_000_000n);
  });

  it('UTXOs agree with the REST server on every outpoint both report', async () => {
    const [ws, rest] = await Promise.all([
      client.getUtxos([BUSY]),
      createRestClient({ baseUrl: 'https://api.kaspa.org' }).getUtxos([BUSY]),
    ]);
    expect(ws.length).toBeGreaterThan(10);
    const byKey = new Map(
      rest.map((u) => [
        `${bytesToHex(u.outpoint.transactionId)}:${u.outpoint.index}`,
        u,
      ]),
    );
    let common = 0;
    for (const u of ws) {
      const r = byKey.get(
        `${bytesToHex(u.outpoint.transactionId)}:${u.outpoint.index}`,
      );
      if (!r) continue;
      common++;
      expect(u.entry.amount).toBe(r.entry.amount);
      expect(u.entry.blockDaaScore).toBe(r.entry.blockDaaScore);
      expect(bytesToHex(u.entry.scriptPublicKey.script)).toBe(
        bytesToHex(r.entry.scriptPublicKey.script),
      );
    }
    expect(common).toBeGreaterThan(ws.length / 2);
  });

  it('balance and fee estimate are well-formed', async () => {
    expect(await client.getBalance(BUSY)).toBeGreaterThan(0n);
    const b = await client.getBalances([BUSY]);
    expect(b.get(BUSY)).toBeGreaterThan(0n);
    const rate = pickFeeRate(await client.getFeeEstimate(), 'normal');
    expect(rate).toBeGreaterThanOrEqual(1n);
  });

  it.each([
    ['v0 native', 0, new Uint8Array(0), undefined],
    ['v0 with a message payload', 0, new Uint8Array([0x68, 0x69]), undefined],
    ['v1 with a payload', 1, new Uint8Array([1, 2, 3]), undefined],
    ['v1 Igra lane', 1, new Uint8Array(33).fill(0x92), IGRA_SUBNETWORK_ID],
  ] as const)(
    '%s: the node decodes our encoding to the same transaction ID',
    async (_n, version, payload, subnetwork) => {
      const tx = await unspendable(version, payload, subnetwork);
      const id = bytesToHex(transactionId(tx));
      const err = await client.submitTransaction(tx).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RpcError);
      const msg = (err as RpcError).nodeMessage ?? '';
      // "Rejected transaction <id>: transaction <id> is an orphan ..."
      expect(msg).toContain(`Rejected transaction ${id}`);
      expect(msg).toMatch(/orphan/);
    },
  );

  it('delivers virtual DAA score notifications and unsubscribes', async () => {
    const scores: bigint[] = [];
    const off = await client.subscribeVirtualDaaScore((s) => scores.push(s));
    const deadline = Date.now() + 10_000;
    while (scores.length < 3 && Date.now() < deadline)
      await new Promise((r) => setTimeout(r, 100));
    await off();
    expect(scores.length).toBeGreaterThanOrEqual(3);
    expect(scores[2]! > scores[0]!).toBe(true);
  });

  it('mempool lookups work', async () => {
    const entries = await client.getMempoolEntriesByAddresses([BUSY]);
    expect(entries[0]?.address).toBe(BUSY);
    expect(await client.getMempoolEntry('00'.repeat(32))).toBeNull();
  });
});
