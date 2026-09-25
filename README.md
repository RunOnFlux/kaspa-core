# @runonflux/kaspa-core

Pure-TypeScript Kaspa transaction library: addresses, scripts, **M-of-N P2SH multisig**, signature hashes, BIP340 signing, KIP-9 mass and fees, and input selection. No WASM, no Rust, two runtime dependencies (`@noble/hashes`, `@noble/curves`), runs unchanged in browsers, MV3 service workers, Electron, Node 20+ and React Native (Hermes).

Built for two products that share one codebase: **SSP** (2-of-2 and enterprise M-of-N vaults signed across two devices) and **ZelCore** (single-signature sends, KRC-20 commit/reveal, Igra lanes).

> **Status: 1.0.0, stable.** Every consensus-critical function is verified against rusty-kaspa itself (see [Verification](#verification)). Real mainnet transactions and signatures are reproduced exactly. Two rounds of independent security review found no critical issues, and every finding is fixed with a regression test. Every SSP and ZelCore flow, from single-sig to a 10-of-15 multisig, has been proven with funded mainnet transactions whose mass matched the node's to the gram ([AUDIT.md](./AUDIT.md) §6.1).

## Install

```bash
yarn add @runonflux/kaspa-core
```

ESM only (like its noble dependencies). Everything lives in the main entry except the REST client, which is `@runonflux/kaspa-core/rest` so the core never fetches.

## Quick start

### Single-signature send (ZelCore)

```ts
import {
  localSigner,
  planTransaction,
  signTransaction,
  finalizeTransaction,
  addressToScriptPublicKey,
} from '@runonflux/kaspa-core';
import type { Spend } from '@runonflux/kaspa-core';
import {
  createRestClient,
  pickFeeRate,
  utxosToInputPlans,
} from '@runonflux/kaspa-core/rest';

const rest = createRestClient({ baseUrl: 'https://api.kas.zelcore.io' });
const signer = localSigner(privateKey32); // raw 32-byte key
const spend: Spend = { kind: 'p2pk', xOnlyPubkey: signer.xOnlyPublicKey };

const utxos = utxosToInputPlans(await rest.getUtxos([myAddress]), spend);
const plan = planTransaction(
  utxos,
  [
    {
      scriptPublicKey: addressToScriptPublicKey(recipient),
      amount: 1_000_000_000n,
    },
  ],
  {
    feeRate: pickFeeRate(await rest.getFeeEstimate(), 'normal'),
    changeSpend: spend,
  },
);
for (const t of [...plan.stages, plan.final]) {
  const signed = finalizeTransaction(
    t.tx,
    t.inputs,
    await signTransaction(t.tx, t.inputs, [signer]),
  );
  await rest.submit(signed);
}
```

### 2-of-2 across two devices (SSP)

```ts
import {
  multisigSpend,
  spendScriptPublicKey,
  scriptPublicKeyToAddress,
  signTransaction,
  createSigningBundle,
  openSigningBundle,
  describeTransaction,
  mergePartialSignatures,
  finalizeTransaction,
} from '@runonflux/kaspa-core';

// Both devices derive the same vault: keys are sorted, so order does not matter.
const vault = multisigSpend([walletXOnlyKey, keyXOnlyKey], 2);
const vaultAddress = scriptPublicKeyToAddress(
  spendScriptPublicKey(vault),
  'kaspa',
); // kaspa:p…

// Wallet: plan, half-sign, ship through the relay.
const partials = await signTransaction(plan.final.tx, plan.final.inputs, [
  walletSigner,
]);
const wire = JSON.stringify(
  createSigningBundle(plan.final.tx, plan.final.inputs, partials),
);

// Key: open with ITS OWN view of the UTXOs, show the user, co-sign only the vault.
const trusted = await rest.getUtxos([vaultAddress]); // the key's own lookup
const opened = openSigningBundle(JSON.parse(wire), {
  trustedUtxos: trusted, // matched by outpoint; refuses without an independent source
}); // default policy: v0, no payload, no lock time, native subnetwork, fee ≤ 5 KAS
const summary = describeTransaction(opened.tx, opened.inputs, {
  prefix: 'kaspa',
  ownScripts: [spendScriptPublicKey(vault)],
}); // show summary.outputs, summary.sent, summary.fee, summary.warnings
const keyPartials = await signTransaction(
  opened.tx,
  opened.inputs,
  [keySigner],
  {
    onlyScripts: [spendScriptPublicKey(vault)],
    signedAmounts: persistentLedger, // { get(outpoint), set(outpoint, amount) } in the key's storage
  },
);
const signed = finalizeTransaction(
  opened.tx,
  opened.inputs,
  mergePartialSignatures(keyPartials, opened.partials), // local first
);
```

**A co-signer must use all four guards**, which is why they are shown above:

- **`trustedUtxos`** (or `trustedEntries` / `fundingTransactions`): this device's own view of the inputs replaces what the bundle claims. Any disagreement, or an input the lookup doesn't contain, throws. `openSigningBundle` refuses to open without one. `fundingTransactions` (e.g. from `rest.getFundingTransaction`) proves amounts from the transactions that created them, so no backend has to be trusted.
- **`signedAmounts`**: Kaspa's signature hash commits only to the signed input's own amount. Without a ledger, an attacker could collect signatures for different inputs across separate sessions, lying about a different input each time, and combine them into one transaction with a huge real fee. The ledger refuses to re-sign an outpoint under a different amount.
- **`onlyScripts`**: refuses to sign inputs from any other script the same key belongs to (e.g. a second vault).
- **`describeTransaction`**: what the user must see: recipients, the amount actually leaving the wallet, the fee, and warnings such as `foreign-input`, `payload` or `fee-above-threshold`.

Submitting can end in `SubmitOutcomeUnknownError`, meaning the request was sent but no answer came back. The transaction may be on the network: re-submit the identical signed transaction, or look it up. Never rebuild it from different UTXOs.

The transaction ID is known before anything is signed (`plan.final.id`), because Kaspa's ID excludes signature scripts, so a relay can pin a proposal to its final ID at creation time.

### Node connection (wRPC)

`@runonflux/kaspa-core/wrpc` is a pure-TypeScript JSON-wRPC client, the replacement for the WASM `RpcClient`. It uses the platform `WebSocket` (browsers, MV3, Electron, Node ≥ 22, React Native), or one you inject, so no `w3cwebsocket` polyfill is needed. The resolver lookup calls `fetch` with a plain string URL, so Capacitor's HTTP shim works too.

```ts
import {
  createWrpcClient,
  pickFeeRate,
  utxosToInputPlans,
} from '@runonflux/kaspa-core/wrpc';

const rpc = createWrpcClient({ networkId: 'mainnet' }); // public resolvers; or urls: ['wss://your-node/…']
const utxos = await rpc.getUtxos([address]);
const feeRate = pickFeeRate(await rpc.getFeeEstimate(), 'normal');
// … plan, sign, finalize …
const id = await rpc.submitTransaction(signed); // any version, payload or lane
const off = await rpc.subscribeUtxosChanged([address], ({ added, removed }) =>
  refresh(),
);
```

The node is treated as untrusted:

- Every connection is checked with `getServerInfo`: right network, synced, UTXO index present. Otherwise the client fails over to the next node.
- No caller request reaches a node before those checks pass.
- UTXOs must carry the script of the address they are reported for, and only requested addresses are accepted. Amounts keep full 64-bit precision.
- Fee estimates go through `pickFeeRate`, which clamps them.
- A submitted transaction's ID must equal the one computed locally.
- Frames are size-capped, every request times out, and only allowlisted ops are ever sent.

After a drop the client reconnects with backoff and re-subscribes. The live suite submits unspendable v0, payload, v1 and Igra-lane transactions to mainnet, and the node's rejection quotes the same transaction ID we computed. For production, run your own kaspad with `--utxoindex --rpclisten-json` and keep the resolvers as a fallback. The protocol is documented in [docs/WRPC_PROTOCOL.md](./docs/WRPC_PROTOCOL.md).

### KRC-20 (ZelCore)

```ts
const op = krc20Transfer(
  { tick: 'NACHO', amount: 100n, to: recipient },
  'kaspa',
);
const ins = krc20Inscription(ownerXOnly, op, 'kaspa'); // { redeem, scriptPublicKey, address, spend }
// Commit: pay KRC20_COMMIT_AMOUNT to ins.scriptPublicKey (a normal planTransaction).
// Reveal: spend the commit output back to yourself.
const reveal = planTransaction([], [{ scriptPublicKey: ownP2pk, amount: 0n }], {
  feeRate,
  changeSpend: spend,
  sendAll: true,
  requiredInputs: [
    { outpoint: commitOutpoint, entry: commitEntry, spend: ins.spend },
  ],
});
```

The script and JSON are byte-identical to ZelCore's current inscription. The tick, amount and recipient are validated first, including the recipient's network, so a malformed operation cannot lose tokens. The whole commit → reveal flow runs in rusty-kaspa's script engine in the tests.

### Igra bridge entries (ZelCore)

```ts
const entry = { l2Address: '0x…', amount: 2_000_000_000n };
const plan = planIgraEntry(utxos, entry, { feeRate, changeSpend: spend }); // v1 lane, exact mass
const mined = mineIgraEntry(plan.final, entry); // grinds the nonce until the ID starts with 97b1
// sign `mined` (never before mining: the signature commits to the payload), then submit over wRPC
```

`mineIgraEntry` refuses a transaction unless all of these hold:

- it is version 1, on the Igra subnetwork, with zero gas;
- it pays exactly `amount` to the lock script, once;
- it is still unsigned.

So the payload can never claim a different amount than the one actually locked. The payload layout matches ZelCore's `buildEntryPayload` byte for byte. A mined entry's ID and mass match rusty-kaspa, and the entry runs in its script engine.

### Utilities

`kaspaToSompi('1.5')` / `sompiToKaspa(150000000n)` (exact, no floating point); `privateKeyFromWif` / `privateKeyToWif`; `xOnlyFromCompressed`, `isValidXOnlyPublicKey`; `addressToScriptPublicKey(address, 'kaspa')` (refuses a testnet address in a mainnet wallet); `validateTransactionStructure`; `planConsolidation` for UTXO sweeps.

### M-of-N

`multisigSpend(keys, m)` for any 1 ≤ m ≤ n ≤ 15. More than 15 keys is refused by default because the mempool will not relay a P2SH input with more than 15 sigops; `{ allowNonStandard: true }` permits up to the consensus limit of 20. Any subset of at least `m` signers can sign, on any number of devices, in any order: `finalizeTransaction` orders signatures by key position as the script engine requires.

## Design

- **Spend descriptors.** Every input carries a `Spend` (`p2pk`, `p2sh-multisig`, `p2sh-script`, `p2pk-ecdsa`). It drives the sigop count, the exact signature-script size for mass, which keys may sign, and finalisation. `sigOpCount` is always derived from it, never taken from a caller: undercounting it is a consensus failure.
- **Injected signers.** A `KaspaSigner` is `{ xOnlyPublicKey, signDigest(digest) }`, possibly async. Local keys, a Ledger or a secure enclave all fit. The library never holds seeds. A co-signing device receives the whole bundle and recomputes every digest itself — never a blind remote digest signer.
- **Serialisable partial signatures.** `SigningBundle` and `PartialSignature` are plain JSON. Every partial is re-verified at finalisation; an invalid one is an error, never silently dropped.
- **Exact mass before signing.** Kaspa signatures are fixed-width, so the planner computes the final mass and fee before any key is touched.
- **KIP-9 aware planning.** Small change is folded into the fee (default below 0.5 KAS) because storage mass makes tiny outputs disproportionately expensive, but never more than 1 KAS is folded silently. When a payment needs more inputs than fit under the 100,000-gram standard cap, the planner returns a **compounding chain** whose later stages spend earlier stage outputs by their pre-computed IDs, so the whole chain can be signed in one pass.
- **Safety rails by default.** Keys must be curve points (an invalid key can freeze a vault); fee rate ≤ 10,000 sompi/g and fee ≤ 5 KAS unless raised; `SIG_HASH_ALL` only; recipients that would burn funds or never relay are refused; bundles open under a default-deny policy. See [SECURITY.md](./SECURITY.md).
- **`bigint` and `Uint8Array` everywhere.** No `Number` in consensus arithmetic, no `Buffer`, no `TextEncoder`, no DOM or Node types in the public API.

## Verification

The test suite runs at four levels. All pass at the rusty-kaspa commit pinned in `oracle/Cargo.toml`.

| Level                                               | What it proves                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Differential oracle** (`test/oracle.test.ts`)     | Byte-identical to rusty-kaspa for addresses, pushes, script integers, multisig redeem and P2SH scripts, v0 and v1 transaction IDs and hashes, Schnorr and ECDSA signature hashes for all six hash types, size and all three mass dimensions, message hashes, and deterministic signatures (bit-identical to libsecp256k1) across thousands of seeded random cases                                                                                                                                                                                                                                                                    |
| **Script engine execution** (`test/engine.test.ts`) | Transactions signed by this library are **executed by rusty-kaspa's own script engine** under consensus budgets: single-sig, every M-of-N from 1-of-1 to 15-of-15 with random signer subsets and shuffled partials, a JSON relay hop, mixed input kinds, a KRC-20 inscription spend, a 120-UTXO compounding chain, a KRC-20 reveal, an Igra-style v1 lane transaction, and the exact v1 compute budget for every shape (it passes; one unit less fails). Negative controls confirm the engine rejects an undercounted sigop count, reversed signature order, a Bitcoin-style dummy element, and a signature over a lied-about amount |
| **Mainnet** (`test/live`, `yarn test:live`)         | Real mainnet transactions rebuilt by this library reproduce their IDs and hashes; their real Schnorr and **15-key ECDSA multisig** signatures verify against our signature hashes; rusty-kaspa's engine accepts them as rebuilt; our mass equals the node's `/transactions/mass` on real inputs                                                                                                                                                                                                                                                                                                                                      |
| **Security regressions** (`test/security.test.ts`)  | Every audit finding: off-curve keys, fee ceilings, sighash policy, input allowlist, bundle policy, trusted entries, strict decoding, canonical addresses, REST hardening                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **Static fixtures** (`test/fixtures`)               | Oracle-generated vectors so CI covers everything above without a Rust toolchain                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

The oracle (`oracle/`) is a dev-only Rust binary that links rusty-kaspa's consensus and script-engine crates. It is never shipped. See `oracle/README.md`.

## Limitations

- **REST submission is version 0 without a payload.** kaspa-rest-server's submit model has no `payload`, `gas` or compute-budget fields. Use the wRPC client for payload-carrying and version 1 transactions (ZelCore messages, Igra lanes).
- **Public resolvers list only Borsh endpoints.** The wRPC client connects to the same proxies' `/wrpc/json` path, which works today but is proxy configuration, not protocol. Production deployments should run their own JSON-wRPC node.
- **PSKT:** `SigningBundle` is this library's own JSON format, not PSKT.
- **ECDSA:** signature hashes, scripts and addresses are supported; the signing API is Schnorr-only.
- **Performance:** pure-JS curve math. A typical 1–20 input transaction signs in tens of milliseconds; a 1,000-UTXO consolidation takes about 5 s on a desktop.

## Development

```bash
yarn install
yarn type-check && yarn lint && yarn format:check && yarn test && yarn build
yarn oracle:build     # needs cargo; enables the oracle and engine suites
yarn fixtures         # regenerate test/fixtures from the oracle
yarn test:live        # mainnet checks against api.kaspa.org (KASPA_REST to override)
```

224 tests offline plus 15 live against mainnet; 92% line coverage (`yarn coverage`).

On a Kaspa hard fork: bump the rusty-kaspa `rev` in `oracle/Cargo.toml`, rebuild the oracle, run the full suite, then regenerate fixtures.

## Licence

MIT. An independent implementation written against the rusty-kaspa source (ISC); no third-party code is vendored.
