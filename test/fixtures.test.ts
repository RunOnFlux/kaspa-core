import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import { decodeAddress, encodeAddress } from '../src/address.js';
import type { AddressVersion, NetworkPrefix } from '../src/address.js';
import { multisigRedeemScript, p2shScript } from '../src/script/standard.js';
import { transactionHash, transactionId } from '../src/tx/encode.js';
import { SighashContext } from '../src/sighash.js';
import { computeMass, storageMass, transientMass } from '../src/mass.js';
import { estimatedSerializedSize } from '../src/tx/size.js';
import { localSigner } from '../src/sign.js';
import type { Transaction, UtxoEntry } from '../src/tx/model.js';

/** Static vectors produced by rusty-kaspa (see generate-fixtures.test.ts). Runs everywhere. */
const load = (name: string) =>
  JSON.parse(
    readFileSync(resolve(import.meta.dirname, 'fixtures', name), 'utf8'),
  );

function txFromFixture(t: any): Transaction {
  return {
    version: t.version,
    inputs: t.inputs.map((i: any) => ({
      previousOutpoint: { transactionId: hexToBytes(i.txid), index: i.index },
      signatureScript: hexToBytes(i.sigScript),
      sequence: BigInt(i.sequence),
      sigOpCount: i.sigOpCount,
      ...(t.version >= 1 ? { computeBudget: i.computeBudget } : {}),
    })),
    outputs: t.outputs.map((o: any) => ({
      value: BigInt(o.value),
      scriptPublicKey: { version: o.spkVersion, script: hexToBytes(o.spk) },
      ...(o.covenant
        ? {
            covenant: {
              authorizingInput: o.covenant.authorizingInput,
              covenantId: hexToBytes(o.covenant.covenantId),
            },
          }
        : {}),
    })),
    lockTime: BigInt(t.lockTime),
    subnetworkId: hexToBytes(t.subnetworkId),
    gas: BigInt(t.gas),
    payload: hexToBytes(t.payload),
  };
}

function entriesFromFixture(es: any[]): UtxoEntry[] {
  return es.map((e) => ({
    amount: BigInt(e.amount),
    scriptPublicKey: { version: e.spkVersion, script: hexToBytes(e.spk) },
    blockDaaScore: BigInt(e.blockDaaScore),
    isCoinbase: e.isCoinbase,
    ...(e.covenantId ? { covenantId: hexToBytes(e.covenantId) } : {}),
  }));
}

describe('rusty-kaspa fixture vectors', () => {
  it('addresses', () => {
    for (const c of load('addresses.json').cases) {
      expect(
        encodeAddress(
          c.prefix as NetworkPrefix,
          c.version as AddressVersion,
          hexToBytes(c.payload),
        ),
      ).toBe(c.address);
      expect(bytesToHex(decodeAddress(c.address).payload)).toBe(c.payload);
    }
  });

  it('multisig redeem and P2SH scripts', () => {
    for (const c of load('multisig.json').cases) {
      const redeem = multisigRedeemScript(c.keys.map(hexToBytes), c.m, {
        sort: false,
      });
      expect(bytesToHex(redeem)).toBe(c.redeem);
      expect(bytesToHex(p2shScript(redeem).script)).toBe(c.spk);
    }
  });

  it('transaction ids, hashes, mass and signature hashes', () => {
    for (const c of load('transactions.json').cases) {
      const tx = txFromFixture(c.tx);
      const entries = entriesFromFixture(c.entries);
      expect(bytesToHex(transactionId(tx))).toBe(c.id.id);
      expect(bytesToHex(transactionHash(tx))).toBe(c.id.hash);
      expect(estimatedSerializedSize(tx).toString()).toBe(String(c.mass.size));
      expect(computeMass(tx).toString()).toBe(String(c.mass.compute));
      expect(transientMass(tx).toString()).toBe(String(c.mass.transient));
      const sm = storageMass(entries, tx.outputs);
      expect(sm === null ? null : sm.toString()).toBe(
        c.mass.storage === null ? null : String(c.mass.storage),
      );
      const ctx = new SighashContext(tx, entries);
      expect(bytesToHex(ctx.schnorr(c.sighash.index, c.sighash.hashType))).toBe(
        c.sighash.schnorr,
      );
      expect(bytesToHex(ctx.ecdsa(c.sighash.index, c.sighash.hashType))).toBe(
        c.sighash.ecdsa,
      );
    }
  });

  it('deterministic signatures match libsecp256k1', async () => {
    for (const c of load('signatures.json').cases) {
      const s = localSigner(hexToBytes(c.secret), { deterministic: true });
      expect(bytesToHex(s.xOnlyPublicKey)).toBe(c.xonly);
      expect(bytesToHex(await s.signDigest(hexToBytes(c.digest)))).toBe(
        c.signature,
      );
    }
  });
});
