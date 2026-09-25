import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { bytesToHex } from '../../src/bytes.js';
import type { Transaction, UtxoEntry } from '../../src/tx/model.js';

/**
 * Bridge to the Rust differential oracle (`oracle/`), which links rusty-kaspa's
 * own consensus and script-engine crates. Tests that need it are skipped when
 * the binary is absent; the static fixtures in `test/fixtures` cover CI.
 */
export const ORACLE_PATH =
  process.env.KASPA_ORACLE ??
  resolve(import.meta.dirname, '../../oracle/target/release/kaspa-core-oracle');
export const oracleAvailable = existsSync(ORACLE_PATH);

export interface OracleResponse<T = any> {
  id: number;
  ok: boolean;
  result?: T;
  error?: string;
}

/** Run a batch of requests; results come back in the same order. */
export function oracle<T = any>(
  requests: Record<string, unknown>[],
): OracleResponse<T>[] {
  const withIds = requests.map((r, i) => ({ id: i, ...r }));
  const dir = mkdtempSync(join(tmpdir(), 'kaspa-oracle-'));
  const file = join(dir, 'requests.json');
  try {
    writeFileSync(file, JSON.stringify(withIds));
    const out = execFileSync(ORACLE_PATH, [file], {
      stdio: ['ignore', 'pipe', 'inherit'],
      maxBuffer: 512 * 1024 * 1024,
      timeout: 120_000,
    }).toString();
    return JSON.parse(out) as OracleResponse<T>[];
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export function txToOracle(tx: Transaction): Record<string, unknown> {
  return {
    version: tx.version,
    inputs: tx.inputs.map((i) => ({
      txid: bytesToHex(i.previousOutpoint.transactionId),
      index: i.previousOutpoint.index,
      sigScript: bytesToHex(i.signatureScript),
      sequence: i.sequence.toString(),
      sigOpCount: i.sigOpCount,
      computeBudget: i.computeBudget ?? 0,
    })),
    outputs: tx.outputs.map((o) => ({
      value: o.value.toString(),
      spkVersion: o.scriptPublicKey.version,
      spk: bytesToHex(o.scriptPublicKey.script),
      covenant: o.covenant
        ? {
            authorizingInput: o.covenant.authorizingInput,
            covenantId: bytesToHex(o.covenant.covenantId),
          }
        : null,
    })),
    lockTime: tx.lockTime.toString(),
    subnetworkId: bytesToHex(tx.subnetworkId),
    gas: tx.gas.toString(),
    payload: bytesToHex(tx.payload),
  };
}

export function entriesToOracle(
  entries: readonly UtxoEntry[],
): Record<string, unknown>[] {
  return entries.map((e) => ({
    amount: e.amount.toString(),
    spkVersion: e.scriptPublicKey.version,
    spk: bytesToHex(e.scriptPublicKey.script),
    blockDaaScore: e.blockDaaScore.toString(),
    isCoinbase: e.isCoinbase,
    covenantId: e.covenantId ? bytesToHex(e.covenantId) : null,
  }));
}
