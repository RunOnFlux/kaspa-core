/**
 * KRC-20 (Kasplex) commit/reveal inscriptions.
 *
 * The inscription is a P2SH redeem script that the owner's key unlocks and
 * that carries the operation as dead data:
 *
 *   <x-only pubkey> OP_CHECKSIG OP_FALSE OP_IF "kasplex" OP_0 <json> OP_ENDIF
 *
 * Commit: pay a small deposit to the script's `kaspa:p…` address.
 * Reveal: spend that output (spend kind `p2sh-script`), which publishes the
 * JSON on chain; the indexer (Kasplex) applies the operation.
 */
import {
  addressToScriptPublicKey,
  scriptPublicKeyToAddress,
} from '../address.js';
import type { NetworkPrefix } from '../address.js';
import { utf8 } from '../bytes.js';
import { invalidInput } from '../errors.js';
import { assertXOnlyPublicKey } from '../keys.js';
import { ScriptBuilder } from '../script/builder.js';
import { Op } from '../script/opcodes.js';
import { p2shScript } from '../script/standard.js';
import type { Spend } from '../spend.js';
import type { ScriptPublicKey } from '../tx/model.js';

/** Commit deposit ZelCore uses (0.3 KAS); returned to the owner by the reveal. */
export const KRC20_COMMIT_AMOUNT = 30_000_000n;

const TICK = /^[A-Za-z]{4,6}$/;
const AMOUNT = /^[1-9][0-9]{0,77}$/;

export interface Krc20Transfer {
  /** Ticker, 4–6 letters. */
  tick: string;
  /** Amount in token base units, as a positive integer. */
  amount: bigint;
  /** Recipient address. */
  to: string;
}

/** A KRC-20 operation. Keys serialise in the order Kasplex expects. */
export type Krc20Operation =
  | { p: 'krc-20'; op: 'transfer'; tick: string; amt: string; to: string }
  | { p: 'krc-20'; op: 'mint'; tick: string; to?: string };

/**
 * Validated `transfer` operation. `to` must decode under `expectedPrefix` —
 * tokens sent to a malformed or wrong-network address are lost.
 */
export function krc20Transfer(
  t: Krc20Transfer,
  expectedPrefix: NetworkPrefix,
): Krc20Operation {
  if (!TICK.test(t.tick)) throw invalidInput('KRC-20 tick must be 4-6 letters');
  const amt = typeof t.amount === 'bigint' ? t.amount.toString() : '';
  if (!AMOUNT.test(amt))
    throw invalidInput('KRC-20 amount must be a positive integer');
  const to = canonicalAddress(t.to, expectedPrefix);
  return { p: 'krc-20', op: 'transfer', tick: t.tick, amt, to };
}

/** Validated `mint` operation (optionally minting to another address). */
export function krc20Mint(
  tick: string,
  expectedPrefix: NetworkPrefix,
  to?: string,
): Krc20Operation {
  if (!TICK.test(tick)) throw invalidInput('KRC-20 tick must be 4-6 letters');
  return to === undefined
    ? { p: 'krc-20', op: 'mint', tick }
    : {
        p: 'krc-20',
        op: 'mint',
        tick,
        to: canonicalAddress(to, expectedPrefix),
      };
}

/** Decoding is canonical-only, so a decodable address is already canonical. */
function canonicalAddress(
  address: string,
  expectedPrefix: NetworkPrefix,
): string {
  addressToScriptPublicKey(address, expectedPrefix);
  return address;
}

export interface Krc20Inscription {
  /** The redeem script revealed by the reveal transaction. */
  redeem: Uint8Array;
  /** P2SH output script the commit pays to. */
  scriptPublicKey: ScriptPublicKey;
  /** The commit's `kaspa:p…` address. */
  address: string;
  /** Spend descriptor for the reveal's commit input. */
  spend: Spend;
}

/** Inscription redeem script, P2SH script/address and reveal spend. */
export function krc20Inscription(
  ownerXOnlyPubkey: Uint8Array,
  operation: Krc20Operation,
  prefix: NetworkPrefix,
): Krc20Inscription {
  assertXOnlyPublicKey(ownerXOnlyPubkey);
  const redeem = new ScriptBuilder()
    .addData(ownerXOnlyPubkey)
    .addOp(Op.OpCheckSig)
    .addOp(Op.OpFalse)
    .addOp(Op.OpIf)
    .addData(utf8('kasplex'))
    .addI64(0n)
    .addData(utf8(JSON.stringify(operation)))
    .addOp(Op.OpEndIf)
    .drain();
  const scriptPublicKey = p2shScript(redeem);
  const address = scriptPublicKeyToAddress(scriptPublicKey, prefix);
  if (address === null) throw invalidInput(`unknown network prefix ${prefix}`);
  return {
    redeem,
    scriptPublicKey,
    address,
    spend: { kind: 'p2sh-script', redeem, signerPubkey: ownerXOnlyPubkey },
  };
}
