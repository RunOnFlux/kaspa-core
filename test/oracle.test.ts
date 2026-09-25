import { describe, expect, it } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import {
  encodeAddress,
  decodeAddress,
  NETWORK_PREFIXES,
} from '../src/address.js';
import type { AddressVersion } from '../src/address.js';
import { ScriptBuilder } from '../src/script/builder.js';
import { countRedeemSigOps } from '../src/script/sigops.js';
import { multisigRedeemScript, p2shScript } from '../src/script/standard.js';
import { transactionHash, transactionId } from '../src/tx/encode.js';
import { SighashContext } from '../src/sighash.js';
import { ALLOWED_SIG_HASH_TYPES } from '../src/constants.js';
import { computeMass, storageMass, transientMass } from '../src/mass.js';
import { estimatedSerializedSize } from '../src/tx/size.js';
import { localSigner, personalMessageHash } from '../src/sign.js';
import {
  oracle,
  oracleAvailable,
  txToOracle,
  entriesToOracle,
} from './helpers/oracle.js';
import { Rng, randomTransaction, xonly } from './helpers/random.js';

/**
 * Differential tests against rusty-kaspa itself. Every case is generated from
 * a fixed seed; a failure message includes enough to reproduce it.
 */
describe.skipIf(!oracleAvailable)('differential vs rusty-kaspa oracle', () => {
  it('address encode/decode matches for every version and prefix', () => {
    const rng = new Rng(1);
    const cases: {
      prefix: (typeof NETWORK_PREFIXES)[number];
      version: AddressVersion;
      payload: Uint8Array;
    }[] = [];
    for (let i = 0; i < 400; i++) {
      const version = rng.pick([0, 1, 8] as const);
      cases.push({
        prefix: rng.pick(NETWORK_PREFIXES),
        version,
        payload: rng.bytes(version === 1 ? 33 : 32),
      });
    }
    const res = oracle(
      cases.map((c) => ({
        op: 'encodeAddress',
        prefix: c.prefix,
        version: c.version,
        payload: bytesToHex(c.payload),
      })),
    );
    res.forEach((r, i) => {
      const c = cases[i]!;
      expect(r.ok, r.error).toBe(true);
      const ours = encodeAddress(c.prefix, c.version, c.payload);
      expect(ours).toBe(r.result.address);
      const d = decodeAddress(ours);
      expect(d.prefix).toBe(c.prefix);
      expect(d.version).toBe(c.version);
      expect(bytesToHex(d.payload)).toBe(bytesToHex(c.payload));
    });
  });

  it('canonical data pushes match across every length boundary', () => {
    const rng = new Rng(2);
    const lengths = [
      0, 1, 2, 74, 75, 76, 254, 255, 256, 257, 65534, 65535, 65536, 70000,
    ];
    const data: Uint8Array[] = [];
    for (const n of lengths) data.push(rng.bytes(n));
    for (let v = 0; v <= 20; v++) data.push(Uint8Array.of(v));
    data.push(Uint8Array.of(0x81), Uint8Array.of(0x80), Uint8Array.of(0xff));
    const res = oracle(
      data.map((d) => ({ op: 'pushData', data: bytesToHex(d) })),
    );
    res.forEach((r, i) => {
      expect(r.ok, r.error).toBe(true);
      expect(bytesToHex(new ScriptBuilder().addData(data[i]!).drain())).toBe(
        r.result.script,
      );
    });
  });

  it('script integers match rusty-kaspa add_i64', () => {
    const rng = new Rng(3);
    const values: bigint[] = [
      0n,
      -1n,
      1n,
      16n,
      17n,
      -2n,
      127n,
      128n,
      -128n,
      -129n,
      255n,
      256n,
      32767n,
      32768n,
      -32768n,
    ];
    values.push(9223372036854775807n, -9223372036854775807n);
    for (let i = 0; i < 200; i++) {
      const v = BigInt.asIntN(64, rng.u64());
      if (v !== -9223372036854775808n) values.push(v);
    }
    const res = oracle(
      values.map((v) => ({ op: 'pushI64', value: v.toString() })),
    );
    res.forEach((r, i) => {
      expect(r.ok, r.error).toBe(true);
      expect(bytesToHex(new ScriptBuilder().addI64(values[i]!).drain())).toBe(
        r.result.script,
      );
    });
  });

  it('multisig redeem scripts and P2SH locking scripts are byte-identical', () => {
    const rng = new Rng(4);
    const cases: { keys: Uint8Array[]; m: number }[] = [];
    for (let i = 0; i < 200; i++) {
      const n = rng.range(1, 15);
      cases.push({
        keys: Array.from({ length: n }, () => xonly(rng)),
        m: rng.range(1, n),
      });
    }
    const res = oracle(
      cases.map((c) => ({
        op: 'multisigRedeem',
        keys: c.keys.map(bytesToHex),
        m: c.m,
      })),
    );
    res.forEach((r, i) => {
      const c = cases[i]!;
      expect(r.ok, r.error).toBe(true);
      // rusty-kaspa does not sort; compare with sorting disabled.
      const redeem = multisigRedeemScript(c.keys, c.m, { sort: false });
      expect(bytesToHex(redeem)).toBe(r.result.redeem);
      expect(bytesToHex(p2shScript(redeem).script)).toBe(r.result.spk);
    });
  });

  it('transaction id and hash match for v0 and v1 (incl. payloads, lanes, covenants)', () => {
    const rng = new Rng(5);
    const txs = Array.from({ length: 400 }, () => randomTransaction(rng).tx);
    const res = oracle(txs.map((tx) => ({ op: 'txid', tx: txToOracle(tx) })));
    res.forEach((r, i) => {
      const tx = txs[i]!;
      expect(r.ok, r.error).toBe(true);
      expect(
        bytesToHex(transactionId(tx)),
        `txid case ${i} v${tx.version}`,
      ).toBe(r.result.id);
      expect(
        bytesToHex(transactionHash(tx)),
        `hash case ${i} v${tx.version}`,
      ).toBe(r.result.hash);
    });
  });

  it('schnorr and ecdsa signature hashes match for every sighash type, v0 and v1', () => {
    const rng = new Rng(6);
    const reqs: Record<string, unknown>[] = [];
    const ours: { schnorr: string; ecdsa: string; label: string }[] = [];
    for (let i = 0; i < 250; i++) {
      const { tx, entries } = randomTransaction(rng);
      const ctx = new SighashContext(tx, entries);
      for (let k = 0; k < 3; k++) {
        const index = rng.int(tx.inputs.length);
        const hashType = rng.pick(ALLOWED_SIG_HASH_TYPES);
        reqs.push({
          op: 'sighash',
          tx: txToOracle(tx),
          entries: entriesToOracle(entries),
          index,
          hashType,
        });
        ours.push({
          schnorr: bytesToHex(ctx.schnorr(index, hashType)),
          ecdsa: bytesToHex(ctx.ecdsa(index, hashType)),
          label: `case ${i}/${k} v${tx.version} idx ${index} type 0x${hashType.toString(16)}`,
        });
      }
    }
    oracle(reqs).forEach((r, i) => {
      expect(r.ok, r.error).toBe(true);
      expect(ours[i]!.schnorr, ours[i]!.label).toBe(r.result.schnorr);
      expect(ours[i]!.ecdsa, ours[i]!.label).toBe(r.result.ecdsa);
    });
  });

  it('size, compute, transient and storage mass match rusty-kaspa MassCalculator', () => {
    const rng = new Rng(7);
    const cases = Array.from({ length: 500 }, () =>
      randomTransaction(rng, {
        maxInputs: rng.range(1, 12),
        maxOutputs: rng.range(1, 12),
      }),
    );
    const res = oracle(
      cases.map((c) => ({
        op: 'mass',
        tx: txToOracle(c.tx),
        entries: entriesToOracle(c.entries),
      })),
    );
    res.forEach((r, i) => {
      const { tx, entries } = cases[i]!;
      expect(r.ok, r.error).toBe(true);
      const label = `mass case ${i} v${tx.version} ${tx.inputs.length}in/${tx.outputs.length}out`;
      expect(estimatedSerializedSize(tx).toString(), label).toBe(
        String(r.result.size),
      );
      expect(computeMass(tx).toString(), label).toBe(String(r.result.compute));
      expect(transientMass(tx).toString(), label).toBe(
        String(r.result.transient),
      );
      const sm = storageMass(entries, tx.outputs);
      expect(sm === null ? null : sm.toString(), label).toBe(
        r.result.storage === null ? null : String(r.result.storage),
      );
    });
  });

  it('redeem-script sigop counting matches p2sh_sig_scanner, including non-minimal counts', () => {
    const rng = new Rng(10);
    const scripts: Uint8Array[] = [];
    const nm = (n: number, width: number) => {
      const b = new Uint8Array(width);
      b[0] = n;
      return b; // little-endian, zero-padded: non-minimal
    };
    for (let i = 0; i < 400; i++) {
      const b = new ScriptBuilder();
      const ops = rng.range(1, 8);
      for (let k = 0; k < ops; k++) {
        switch (rng.int(7)) {
          case 0:
            b.addOp(0xac);
            break;
          case 1:
            b.addI64(BigInt(rng.range(1, 20))).addOp(0xae);
            break;
          case 2:
            b.addData(nm(rng.range(1, 25), rng.range(2, 9))).addOp(0xae);
            break;
          case 3:
            b.addOp(0xae);
            break;
          case 4:
            b.addData(rng.bytes(rng.range(1, 40)));
            break;
          case 5:
            b.addOp(rng.pick([0xa9, 0xab, 0xad, 0xaf, 0xd7, 0xd8]));
            break;
          default:
            b.addOp(rng.pick([0x00, 0x4f, 0x51, 0x60, 0x87, 0x63, 0x68]));
        }
      }
      scripts.push(b.drain());
    }
    scripts.push(Uint8Array.of(0x4c)); // truncated push
    const reqs = scripts.map((redeem) => ({
      op: 'p2shSigScanner',
      sigScript: bytesToHex(new ScriptBuilder().addData(redeem).drain()),
      spk: bytesToHex(p2shScript(redeem).script),
    }));
    oracle(reqs).forEach((r, i) => {
      expect(r.ok, r.error).toBe(true);
      expect(countRedeemSigOps(scripts[i]!), bytesToHex(scripts[i]!)).toBe(
        r.result.sigops,
      );
    });
  });

  it('personal message hash matches', () => {
    const rng = new Rng(8);
    const msgs = [
      new Uint8Array(0),
      new TextEncoder().encode('hello'),
      ...Array.from({ length: 50 }, () => rng.bytes(rng.range(1, 500))),
    ];
    oracle(
      msgs.map((m) => ({ op: 'personalMessageHash', message: bytesToHex(m) })),
    ).forEach((r, i) => {
      expect(r.ok, r.error).toBe(true);
      expect(bytesToHex(personalMessageHash(msgs[i]!))).toBe(r.result.hash);
    });
  });

  it('deterministic local signer is bit-identical to libsecp256k1 sign_schnorr_no_aux_rand', async () => {
    const rng = new Rng(9);
    const cases = Array.from({ length: 100 }, () => ({
      secret: rng.secretKey(),
      digest: rng.bytes(32),
    }));
    const res = oracle(
      cases.map((c) => ({
        op: 'schnorrSignNoAux',
        secret: bytesToHex(c.secret),
        digest: bytesToHex(c.digest),
      })),
    );
    for (let i = 0; i < cases.length; i++) {
      const r = res[i]!;
      const c = cases[i]!;
      expect(r.ok, r.error).toBe(true);
      const signer = localSigner(c.secret, { deterministic: true });
      expect(bytesToHex(signer.xOnlyPublicKey)).toBe(r.result.xonly);
      expect(bytesToHex(await signer.signDigest(c.digest))).toBe(
        r.result.signature,
      );
      expect(
        schnorr.verify(
          hexToBytes(r.result.signature),
          c.digest,
          signer.xOnlyPublicKey,
        ),
      ).toBe(true);
    }
  });
});
