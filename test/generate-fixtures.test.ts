import { describe, it } from 'vitest';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bytesToHex } from '../src/bytes.js';
import { ALLOWED_SIG_HASH_TYPES } from '../src/constants.js';
import { NETWORK_PREFIXES } from '../src/address.js';
import {
  entriesToOracle,
  oracle,
  oracleAvailable,
  txToOracle,
} from './helpers/oracle.js';
import { Rng, randomTransaction, xonly } from './helpers/random.js';

/**
 * Regenerates `test/fixtures/*.json` from the rusty-kaspa oracle so CI can
 * check the library without a Rust toolchain. Run: `yarn fixtures`.
 * Inputs are generated here; expected outputs come only from the oracle.
 */
const WRITE = process.env.KASPA_WRITE_FIXTURES === '1';
const DIR = resolve(import.meta.dirname, 'fixtures');

function write(name: string, data: unknown): void {
  writeFileSync(resolve(DIR, name), `${JSON.stringify(data, null, 1)}\n`);
}

function must<T>(r: { ok: boolean; result?: T; error?: string }): T {
  if (!r.ok) throw new Error(r.error);
  return r.result as T;
}

describe.skipIf(!WRITE || !oracleAvailable)(
  'generate fixtures from the oracle',
  () => {
    it('writes fixtures', () => {
      const rng = new Rng(0xfeed);
      const meta = {
        generatedBy: 'kaspa-core-oracle',
        rustyKaspaRev: '01b532e8b553523216471682649693af92f0fd16',
      };

      const addrCases = Array.from({ length: 60 }, () => {
        const version = rng.pick([0, 1, 8] as const);
        return {
          prefix: rng.pick(NETWORK_PREFIXES),
          version,
          payload: bytesToHex(rng.bytes(version === 1 ? 33 : 32)),
        };
      });
      const addrRes = oracle(
        addrCases.map((c) => ({ op: 'encodeAddress', ...c })),
      );
      write('addresses.json', {
        ...meta,
        cases: addrCases.map((c, i) => ({
          ...c,
          address: must<{ address: string }>(addrRes[i]!).address,
        })),
      });

      const msCases = Array.from({ length: 30 }, () => {
        const n = rng.range(1, 15);
        return {
          keys: Array.from({ length: n }, () => bytesToHex(xonly(rng))),
          m: rng.range(1, n),
        };
      });
      const msRes = oracle(
        msCases.map((c) => ({ op: 'multisigRedeem', ...c })),
      );
      write('multisig.json', {
        ...meta,
        cases: msCases.map((c, i) => ({
          ...c,
          ...must<{ redeem: string; spk: string }>(msRes[i]!),
        })),
      });

      const txCases = Array.from({ length: 60 }, () => randomTransaction(rng));
      const idRes = oracle(
        txCases.map((c) => ({ op: 'txid', tx: txToOracle(c.tx) })),
      );
      const massRes = oracle(
        txCases.map((c) => ({
          op: 'mass',
          tx: txToOracle(c.tx),
          entries: entriesToOracle(c.entries),
        })),
      );
      const shReqs = txCases.map((c) => ({
        op: 'sighash',
        tx: txToOracle(c.tx),
        entries: entriesToOracle(c.entries),
        index: rng.int(c.tx.inputs.length),
        hashType: rng.pick(ALLOWED_SIG_HASH_TYPES),
      }));
      const shRes = oracle(shReqs);
      write('transactions.json', {
        ...meta,
        cases: txCases.map((c, i) => ({
          tx: txToOracle(c.tx),
          entries: entriesToOracle(c.entries),
          id: must<{ id: string; hash: string }>(idRes[i]!),
          mass: must(massRes[i]!),
          sighash: {
            index: shReqs[i]!.index,
            hashType: shReqs[i]!.hashType,
            ...must<{ schnorr: string; ecdsa: string }>(shRes[i]!),
          },
        })),
      });

      const sigCases = Array.from({ length: 20 }, () => ({
        secret: bytesToHex(rng.secretKey()),
        digest: bytesToHex(rng.bytes(32)),
      }));
      const sigRes = oracle(
        sigCases.map((c) => ({ op: 'schnorrSignNoAux', ...c })),
      );
      write('signatures.json', {
        ...meta,
        cases: sigCases.map((c, i) => ({
          ...c,
          ...must<{ signature: string; xonly: string }>(sigRes[i]!),
        })),
      });
    });
  },
);
