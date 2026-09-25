import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import {
  SIG_HASH_ALL,
  SIG_HASH_ANY_ONE_CAN_PAY,
  SIG_HASH_NONE,
  SIG_HASH_SINGLE,
} from '../src/constants.js';
import {
  addressToScriptPublicKey,
  decodeAddress,
  encodeAddress,
} from '../src/address.js';
import {
  EntryMismatchError,
  FeeTooHighError,
  InvalidAddressError,
  InvalidScriptError,
  InvalidTransactionError,
  KaspaError,
  MultisigConfigError,
  SignatureError,
} from '../src/errors.js';
import { p2pkScript } from '../src/script/standard.js';
import {
  createSigningBundle,
  createTransaction,
  finalizeTransaction,
  localSigner,
  mergePartialSignatures,
  openSigningBundle,
  signTransaction,
} from '../src/sign.js';
import { multisigSpend, spendScriptPublicKey } from '../src/spend.js';
import type { InputPlan, Spend } from '../src/spend.js';
import { planTransaction } from '../src/plan.js';
import { parseJsonSafe, pickFeeRate, createRestClient } from '../src/rest.js';
import { transactionFromJson, transactionToJson } from '../src/tx/json.js';
import { Rng, TEST_XONLY, xonly } from './helpers/random.js';

const rng0 = new Rng(31337);
const A = localSigner(rng0.secretKey());
const B = localSigner(rng0.secretKey());
const C = localSigner(rng0.secretKey());
const VAULT = multisigSpend([A.xOnlyPublicKey, B.xOnlyPublicKey], 2);
const OTHER_VAULT = multisigSpend([A.xOnlyPublicKey, C.xOnlyPublicKey], 2);
const DST = p2pkScript(TEST_XONLY);
const KAS = 100_000_000n;

function utxo(spend: Spend, amount = 10n * KAS): InputPlan {
  return {
    outpoint: { transactionId: rng0.bytes(32), index: 0 },
    entry: {
      amount,
      scriptPublicKey: spendScriptPublicKey(spend),
      blockDaaScore: 1n,
      isCoinbase: false,
    },
    spend,
  };
}

/** Tests of other checks open bundles without an independent amount source. */
const TRUST = { trustBundleEntries: true } as const;

function simpleTx(inputs: InputPlan[]) {
  return createTransaction({
    inputs,
    outputs: [
      {
        value: inputs.reduce((a, p) => a + p.entry.amount, 0n) - KAS / 100n,
        scriptPublicKey: DST,
      },
    ],
  });
}

describe('keys that can never sign are refused (vault-freeze attack)', () => {
  const offCurve = new Uint8Array(32); // x = 0 is not on secp256k1
  it('multisig with an off-curve key', () => {
    expect(() => multisigSpend([offCurve, A.xOnlyPublicKey], 1)).toThrow(
      MultisigConfigError,
    );
  });
  it('P2PK locking script to an off-curve key', () => {
    expect(() => p2pkScript(offCurve)).toThrow(InvalidScriptError);
  });
  it('a recipient whose key would burn funds', () => {
    const burn = new Uint8Array(34);
    burn[0] = 0x20;
    burn[33] = 0xac;
    expect(() =>
      planTransaction(
        [utxo(VAULT)],
        [{ scriptPublicKey: { version: 0, script: burn }, amount: KAS }],
        { feeRate: 1n, changeSpend: VAULT },
      ),
    ).toThrow(InvalidScriptError);
  });
  it('a non-standard recipient', () => {
    expect(() =>
      planTransaction(
        [utxo(VAULT)],
        [
          {
            scriptPublicKey: { version: 0, script: Uint8Array.of(0x51) },
            amount: KAS,
          },
        ],
        { feeRate: 1n, changeSpend: VAULT },
      ),
    ).toThrow(InvalidScriptError);
  });
});

describe('an untrusted fee source cannot drain the wallet', () => {
  it('pickFeeRate clamps a hostile estimate', () => {
    const hostile = {
      priorityBucket: { feerate: 1e12, estimatedSeconds: 1 },
      normalBuckets: [{ feerate: 1e12, estimatedSeconds: 1 }],
      lowBuckets: [{ feerate: 1e12, estimatedSeconds: 1 }],
    };
    expect(pickFeeRate(hostile, 'normal')).toBe(10_000n);
    expect(pickFeeRate(hostile, 'fast', 500n)).toBe(500n);
  });
  it('pickFeeRate rejects a malformed estimate instead of crashing', () => {
    expect(() => pickFeeRate(null as never)).toThrow(KaspaError);
    expect(pickFeeRate({} as never)).toBe(1n);
  });
  it('the planner refuses a fee rate above the ceiling', () => {
    expect(() =>
      planTransaction([utxo(VAULT)], [{ scriptPublicKey: DST, amount: KAS }], {
        feeRate: 10_001n,
        changeSpend: VAULT,
      }),
    ).toThrow(/ceiling/);
  });
  it('the planner refuses a fee above maxFee', () => {
    expect(() =>
      planTransaction(
        [utxo(VAULT, 1000n * KAS)],
        [{ scriptPublicKey: DST, amount: KAS }],
        { feeRate: 10_000n, changeSpend: VAULT, maxFee: KAS / 10n },
      ),
    ).toThrow(FeeTooHighError);
  });
  it('the planner refuses duplicate UTXOs from a lying server', () => {
    const u = utxo(VAULT);
    expect(() =>
      planTransaction([u, { ...u }], [{ scriptPublicKey: DST, amount: KAS }], {
        feeRate: 1n,
        changeSpend: VAULT,
      }),
    ).toThrow(/twice/);
  });
});

describe('sighash policy', () => {
  it('non-ALL types need an explicit opt-in to sign', async () => {
    const inputs = [utxo(VAULT)];
    const tx = simpleTx(inputs);
    await expect(
      signTransaction(tx, inputs, [A], { sighashType: SIG_HASH_NONE }),
    ).rejects.toThrow(SignatureError);
    const ok = await signTransaction(tx, inputs, [A], {
      sighashType: SIG_HASH_ALL | SIG_HASH_ANY_ONE_CAN_PAY,
      allowNonAllSighash: true,
    });
    expect(ok).toHaveLength(1);
  });
  it('SIGHASH_SINGLE with no matching output is refused even with the opt-in', async () => {
    const inputs = [utxo(VAULT), utxo(VAULT)];
    const tx = simpleTx(inputs); // 2 inputs, 1 output
    await expect(
      signTransaction(tx, inputs, [A], {
        sighashType: SIG_HASH_SINGLE,
        allowNonAllSighash: true,
      }),
    ).rejects.toThrow(/commits to nothing/);
  });
  it('finalize refuses a non-ALL partial unless allowed', async () => {
    const inputs = [utxo(VAULT)];
    const tx = simpleTx(inputs);
    const weak = await signTransaction(tx, inputs, [A], {
      sighashType: SIG_HASH_NONE,
      allowNonAllSighash: true,
    });
    const strong = await signTransaction(tx, inputs, [B]);
    expect(() => finalizeTransaction(tx, inputs, [...weak, ...strong])).toThrow(
      SignatureError,
    );
    expect(() =>
      finalizeTransaction(tx, inputs, [...weak, ...strong], {
        allowNonAllSighash: true,
      }),
    ).not.toThrow();
  });
});

describe('co-signer input allowlist (foreign-vault attack)', () => {
  it('refuses to sign when any input spends outside the approved scripts', async () => {
    // A is in both vaults; the proposer slips in an input from OTHER_VAULT.
    const inputs = [utxo(VAULT), utxo(OTHER_VAULT)];
    const tx = simpleTx(inputs);
    await expect(
      signTransaction(tx, inputs, [A], {
        onlyScripts: [spendScriptPublicKey(VAULT)],
      }),
    ).rejects.toThrow(/outside the approved set/);
    // Without the allowlist it would have signed both — the reason it exists.
    expect(await signTransaction(tx, inputs, [A])).toHaveLength(2);
  });
});

describe('signing bundles from another device', () => {
  async function bundleFor(
    over: Partial<Parameters<typeof createTransaction>[0]> = {},
  ) {
    const inputs = [utxo(VAULT)];
    const tx = createTransaction({
      inputs,
      outputs: [{ value: 5n * KAS, scriptPublicKey: DST }],
      ...over,
    });
    return {
      inputs,
      bundle: JSON.parse(
        JSON.stringify(
          createSigningBundle(
            tx,
            inputs,
            await signTransaction(tx, inputs, [A]),
          ),
        ),
      ),
    };
  }
  it('default policy refuses payloads, lock times, sequences and v1', async () => {
    const withPayload = await bundleFor({ payload: Uint8Array.of(1, 2, 3) });
    expect(() => openSigningBundle(withPayload.bundle, TRUST)).toThrow(
      /payload/,
    );
    const withLock = await bundleFor({ lockTime: 1_000n });
    expect(() => openSigningBundle(withLock.bundle, TRUST)).toThrow(
      /lock time/,
    );
    const v1 = await bundleFor({ version: 1 });
    expect(() => openSigningBundle(v1.bundle, TRUST)).toThrow(/version 1/);
    expect(() =>
      openSigningBundle(withPayload.bundle, {
        ...TRUST,
        policy: { allowPayload: true },
      }),
    ).not.toThrow();
  });
  it('trusted entries replace the claimed ones and any disagreement fails loudly', async () => {
    const { bundle, inputs } = await bundleFor();
    const truth = inputs.map((p) => p.entry);
    expect(
      openSigningBundle(bundle, { trustedEntries: truth }).inputs[0]!.entry,
    ).toEqual(truth[0]);
    const lie = [{ ...truth[0]!, amount: truth[0]!.amount + 1n }];
    expect(() => openSigningBundle(bundle, { trustedEntries: lie })).toThrow(
      EntryMismatchError,
    );
  });
  it('trustedUtxos aligns an unordered lookup by outpoint and refuses unknown inputs', async () => {
    const { bundle, inputs } = await bundleFor();
    const lookup = [
      {
        outpoint: { transactionId: rng0.bytes(32), index: 9 },
        entry: inputs[0]!.entry,
      },
      { outpoint: inputs[0]!.outpoint, entry: inputs[0]!.entry },
    ];
    expect(
      openSigningBundle(bundle, { trustedUtxos: lookup }).inputs,
    ).toHaveLength(1);
    expect(() =>
      openSigningBundle(bundle, { trustedUtxos: [lookup[0]!] }),
    ).toThrow(/own UTXO lookup/);
  });
  it('malformed partials are rejected at the boundary', async () => {
    const { bundle } = await bundleFor();
    bundle.partials[0].inputIndex = '0';
    expect(() => openSigningBundle(bundle, TRUST)).toThrow(SignatureError);
  });
  it('merging keeps the first (local) partial for a key', async () => {
    const inputs = [utxo(VAULT)];
    const tx = simpleTx(inputs);
    const local = await signTransaction(tx, inputs, [A]);
    const forged = [{ ...local[0]!, signature: '00'.repeat(64) }];
    const merged = mergePartialSignatures(local, forged);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.signature).toBe(local[0]!.signature);
  });
  it('strict JSON decoding rejects wrong lengths and oversized integers', () => {
    const tx = simpleTx([utxo(VAULT)]);
    const j = transactionToJson(tx);
    const shortId = structuredClone(j);
    shortId.inputs[0]!.previousOutpoint.transactionId = 'ab'.repeat(31);
    expect(() => transactionFromJson(shortId)).toThrow(KaspaError);
    const huge = structuredClone(j);
    huge.outputs[0]!.value = '1'.repeat(21);
    expect(() => transactionFromJson(huge)).toThrow(KaspaError);
    const zero = structuredClone(j);
    zero.outputs[0]!.value = '0';
    expect(() => transactionFromJson(zero)).toThrow(InvalidTransactionError);
    expect(() => transactionFromJson(null as never)).toThrow(KaspaError);
  });
});

describe('transaction construction guards', () => {
  it('refuses to sign a transaction whose outputs exceed its inputs', async () => {
    const inputs = [utxo(VAULT, KAS)];
    const tx = createTransaction({
      inputs,
      outputs: [{ value: 2n * KAS, scriptPublicKey: DST }],
    });
    await expect(signTransaction(tx, inputs, [A])).rejects.toThrow(
      /exceed inputs/,
    );
  });
  it('refuses duplicate inputs and zero outputs at construction', () => {
    const u = utxo(VAULT);
    expect(() =>
      createTransaction({
        inputs: [u, u],
        outputs: [{ value: KAS, scriptPublicKey: DST }],
      }),
    ).toThrow(/duplicate/);
    expect(() =>
      createTransaction({
        inputs: [u],
        outputs: [{ value: 0n, scriptPublicKey: DST }],
      }),
    ).toThrow(/positive/);
  });
  it('localSigner refuses a string posing as a key', () => {
    expect(() =>
      localSigner('0123456789abcdef0123456789abcdef' as never),
    ).toThrow(KaspaError);
  });
});

describe('address safety', () => {
  const addr = encodeAddress('kaspa', 0, TEST_XONLY);
  it('a testnet address pasted into a mainnet wallet is refused', () => {
    const test = encodeAddress('kaspatest', 0, TEST_XONLY);
    expect(() => addressToScriptPublicKey(test, 'kaspa')).toThrow(
      InvalidAddressError,
    );
    expect(addressToScriptPublicKey(addr, 'kaspa')).toEqual(
      p2pkScript(TEST_XONLY),
    );
  });
  it('a non-canonical encoding (non-zero padding bits) is refused', () => {
    // Recompute a valid checksum over a payload whose padding bits are set:
    // rusty-kaspa would accept it; one address must have exactly one string.
    const CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    const G = [
      0x98f2bc8e61n,
      0x79b76d99e2n,
      0xf33e5fb3c4n,
      0xae2eabe2a8n,
      0x1e4f43e470n,
    ];
    const polymod = (v: number[]) => {
      let c = 1n;
      for (const d of v) {
        const c0 = c >> 35n;
        c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
        for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= G[i]!;
      }
      return c ^ 1n;
    };
    const body = addr.slice('kaspa:'.length);
    const chars = (x: string) =>
      Array.from({ length: x.length }, (_, i) => x.charAt(i));
    const p5 = chars(body.slice(0, -8)).map((ch) => CS.indexOf(ch));
    p5[p5.length - 1] = p5[p5.length - 1]! | 0b00001; // a padding bit
    const prefix5 = chars('kaspa').map((ch) => ch.charCodeAt(0) & 0x1f);
    const cs = polymod([...prefix5, 0, ...p5, 0, 0, 0, 0, 0, 0, 0, 0]);
    const cs5: number[] = [];
    for (let i = 7; i >= 0; i--) cs5.push(Number((cs >> BigInt(5 * i)) & 31n));
    const forged = `kaspa:${[...p5, ...cs5].map((d) => CS[d]).join('')}`;
    expect(forged).not.toBe(addr);
    expect(() => decodeAddress(forged)).toThrow(/non-canonical/);
  });
});

describe('REST hardening', () => {
  it('large integers are quoted without corrupting strings', () => {
    expect(
      parseJsonSafe('{"a":"x:1234567890123456,","b":12345678901234567890}'),
    ).toEqual({
      a: 'x:1234567890123456,',
      b: '12345678901234567890',
    });
    expect(parseJsonSafe('{"s":"quote \\" then 99999999999999999"}')).toEqual({
      s: 'quote " then 99999999999999999',
    });
    expect(parseJsonSafe('[1.5, -2, 1e3]')).toEqual([1.5, -2, 1000]);
  });
  it('plain http is refused unless explicitly allowed', () => {
    const f = (async () => new Response('[]')) as never;
    expect(() =>
      createRestClient({ baseUrl: 'http://x.test', fetch: f }),
    ).toThrow(KaspaError);
    expect(() =>
      createRestClient({
        baseUrl: 'http://localhost:8000',
        fetch: f,
        allowInsecureHttp: true,
      }),
    ).not.toThrow();
  });
  it('UTXOs are validated and de-duplicated', async () => {
    const pk = xonly(rng0);
    const addr = encodeAddress('kaspa', 0, pk);
    const row = {
      address: addr,
      outpoint: { transactionId: 'ab'.repeat(32), index: 0 },
      utxoEntry: {
        amount: '100',
        scriptPublicKey: {
          scriptPublicKey: bytesToHex(p2pkScript(pk).script),
        },
        blockDaaScore: '1',
      },
    };
    const mk = (body: unknown) =>
      createRestClient({
        baseUrl: 'https://x.test',
        fetch: async () => new Response(JSON.stringify(body)),
      });
    expect(await mk([row, row]).getUtxos([addr])).toHaveLength(1);
    await expect(
      mk([{ ...row, outpoint: { transactionId: 'zz', index: 0 } }]).getUtxos([
        addr,
      ]),
    ).rejects.toThrow(KaspaError);
    await expect(
      mk([{ ...row, outpoint: { ...row.outpoint, index: -1 } }]).getUtxos([
        addr,
      ]),
    ).rejects.toThrow(KaspaError);
    await expect(mk([row]).getUtxos(['kaspa:x'])).rejects.toThrow(KaspaError);
  });
});

describe('noble sanity', () => {
  it('hexToBytes/bytesToHex round-trip a key', () => {
    expect(bytesToHex(hexToBytes(bytesToHex(TEST_XONLY)))).toBe(
      bytesToHex(TEST_XONLY),
    );
  });
});
