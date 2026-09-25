# kaspa-core audit — 2026-09-24

Library: `@runonflux/kaspa-core` 1.0.0.

Scope:

- Functional coverage for every Kaspa flow in **SSP** (SSP Wallet, SSP Key, ssp-relay-enterprise) and **ZelCore** (desktop, mobile, extension).
- Security.
- Dependencies and release readiness.

Method: two rounds of review, plus execution against rusty-kaspa's own crates (see [Verification](#6-verification)).

- **Round 1 (0.2.0):** a line-by-line review by the author and one independent adversarial review.
- **Round 2 (0.3.0):** after the wRPC client, KRC-20 and Igra modules were added, two more independent adversarial reviews. One covered signing and UTXO safety, the other the network clients. Each reviewer reproduced its findings with executable tests before reporting them.
- **Execution:** every consensus-critical path is run against rusty-kaspa's own crates.

## 1. Verdict

| Consumer                                      | Ready?                                                                                                                                                                                                                                                                                                 | What remains                                                                                        |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| **SSP** (2-of-2 and enterprise M-of-N vaults) | **Yes.** Every SSP flow is implemented, hardened, verified against the real script engine, and proven with funded mainnet spends (§6.1).                                                                                                                                                               | —                                                                                                   |
| **ZelCore** (single-sig hot wallet)           | **Yes.** Every ZelCore Kaspa flow is covered, including the transport: the pure-TypeScript wRPC client submits payload, version 1 and Igra-lane transactions (verified live: a mainnet node decodes all four kinds to our transaction IDs). The KRC-20 and Igra helpers produce ZelCore's exact bytes. | One funded single-sig send, a KRC-20 commit/reveal and an Igra entry. PSKT only if a dapp needs it. |

No Critical findings in either round.

- **Round 1:** two High and four Medium, all fixed (§4).
- **Round 2:** six Medium, and several Low and Info, all fixed (§4.2).

Every fix has a regression test. The dependency tree has zero known vulnerabilities (§5).

## 2. Functional coverage

### 2.1 SSP

| Flow                                                     | Status                                                                                                                                           | Evidence                                                              |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| Derive vault address from xpub-derived keys              | ✅ `xOnlyFromCompressed` → `multisigSpend` (sorted keys, so both devices agree) → `spendScriptPublicKey` → `scriptPublicKeyToAddress`            | `features.test` keys; `sign.test` sorting; oracle multisig suite      |
| Refuse keys that can never sign                          | ✅ every key must be a curve point                                                                                                               | `security.test` vault-freeze suite                                    |
| Plan a payment from vault UTXOs                          | ✅ `planTransaction`: KIP-9-aware change folding, mass cap, compounding chains, coinbase maturity, fee ceilings                                  | `plan.test`, property test, engine chain test                         |
| Know the transaction ID before signing (relay pinning)   | ✅ `PlannedTransaction.id`                                                                                                                       | engine and oracle txid suites                                         |
| Wallet half-signs, ships a bundle through the relay      | ✅ `signTransaction` → `createSigningBundle` (JSON)                                                                                              | engine relay-hop test                                                 |
| Key verifies independently and co-signs                  | ✅ `openSigningBundle(bundle, { trustedEntries, policy })`, `signTransaction(…, { onlyScripts })`, `describeTransaction` for the approval screen | `security.test` bundle and allowlist suites; `features.test` describe |
| Finalise in key order and broadcast                      | ✅ `finalizeTransaction` + REST `submit` (id verified against local)                                                                             | engine M-of-N suite (all 120 configurations); `rest.test`             |
| Enterprise M-of-N up to 15, any signer subset, any order | ✅                                                                                                                                               | engine suite: every m-of-n 1…15, shuffled partials                    |
| Relay-side signature registration                        | ✅ `verifyPartialSignature` runs server-side with no keys                                                                                        | `sign.test`                                                           |
| Balances, UTXOs, history, confirmations                  | ✅ REST client: UTXOs, balances, paged history, acceptance, blue score, DAA score                                                                | `rest.test`, live suite                                               |
| Amount entry and display                                 | ✅ `kaspaToSompi` (exact, no float) / `sompiToKaspa`                                                                                             | `features.test` units                                                 |
| Network safety (mainnet vs testnet)                      | ✅ `addressToScriptPublicKey(addr, 'kaspa')` refuses a `kaspatest:` paste                                                                        | `security.test` address safety                                        |

### 2.2 ZelCore

| Flow                                               | Build/sign/validate                                                                                                                           | Submit          | Evidence                                                                            |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ----------------------------------------------------------------------------------- |
| Native KAS send                                    | ✅                                                                                                                                            | ✅ REST         | engine P2PK suite; live mainnet signatures                                          |
| Send with a message payload                        | ✅                                                                                                                                            | ✅ wRPC         | engine v1 payload test; live wRPC id check                                          |
| Fee estimate (economy/normal/fast)                 | ✅ `pickFeeRate` (clamped) + planner                                                                                                          | —               | `rest.test`, `security.test`                                                        |
| KRC-20 commit                                      | ✅ `krc20Transfer` / `krc20Inscription` (ZelCore's exact script and JSON; tick, amount and network-checked recipient validated)               | ✅ REST or wRPC | `protocols.test` byte equality; engine commit                                       |
| KRC-20 reveal                                      | ✅ `requiredInputs: [commit]`, `sendAll` back to the owner                                                                                    | ✅ REST or wRPC | `protocols.test` commit → reveal in the engine                                      |
| Igra bridge entry (v1 lane, payload, nonce mining) | ✅ `planIgraEntry` → `mineIgraEntry` (refuses any mismatch between payload and locked amount) → sign                                          | ✅ wRPC         | `protocols.test` (id and mass match the oracle, engine accepts); live wRPC id check |
| WIF private keys (drop `@kaspa/core-lib`)          | ✅ `privateKeyFromWif` / `privateKeyToWif`                                                                                                    | —               | ZelCore vectors in `features.test`                                                  |
| Address generation                                 | ✅ (ZelCore's own codec already matches; vectors reproduce)                                                                                   | —               | `address.test`                                                                      |
| Message signing for dapps (`window.kasware`)       | ✅ `personalMessageHash` / `signMessage` / `verifyMessage`                                                                                    | —               | oracle message-hash suite                                                           |
| PSKT signing for dapps                             | ⚠️ not implemented; `SigningBundle` is not PSKT                                                                                               | —               | build only if a target dapp requires it                                             |
| UTXO / DAA subscriptions                           | ✅ `subscribeUtxosChanged` (validated and address-attributed), `subscribeVirtualDaaScore`; survive reconnects                                 | wRPC            | `wrpc.test`; live DAA subscription                                                  |
| Node connection (replaces WASM `RpcClient`)        | ✅ resolver or fixed URLs, node verification, failover, keepalive, reconnect; no `w3cwebsocket` polyfill; string-URL `fetch` (Capacitor-safe) | wRPC            | `wrpc.test` (fake node); live suite                                                 |
| Ledger                                             | ⚠️ `KaspaSigner` interface ready; the APDU transport is ZelCore work                                                                          | —               | —                                                                                   |

**Nothing blocks removing ZelCore's WASM any more.** The wRPC client (`@runonflux/kaspa-core/wrpc`) is a separate entry point, so SSP never loads it unless it chooses to.

The removal also drops these workarounds:

- the `kaspa_bg.wasm` loaders
- the `w3cwebsocket` polyfill
- the Capacitor resolver workaround
- the extension's `keepNames`
- `@kaspa/core-lib`
- the ×2 reveal fee rate
- the Igra lane-fee compensation

## 3. Threat model

Funds are held in P2SH multisig vaults (SSP) and single-key P2PK (ZelCore).

**Untrusted:**

- the REST server and the wRPC node (UTXOs, balances, fee estimates, mempool, submission results);
- the resolver;
- the relay server;
- for a co-signer, the other device and everything it sends.

**Trusted:** the device's own keys. Its own UTXO lookups are trusted only as far as the backend behind them is.

Kaspa's signature hash is BIP143-like.

- **What it commits to:** all outputs, every input's outpoint, and the input being signed's own amount and previous script.
- **What it does not commit to:** the other inputs' amounts, and v1 compute budgets.
- **Consequence:** an attacker can collect signatures for different inputs across separate sessions, lying about a different input's amount each time, and combine them into one transaction with a huge real fee (finding R2-1).

The realistic attacks are therefore:

- overpaying fees, whether in one session or across sessions;
- getting a key to sign more than the user approved;
- creating unspendable outputs;
- a node lying about transport state.

§4 and §4.2 address them.

## 4. Security findings

Severity is the pre-fix severity. "Reviewer" = found by the independent reviewer; "Author" = found in the author's pass. Every fix has a regression test in `test/security.test.ts` unless noted.

| #   | Sev          | Finding                                                                                                                                                                                                                                  | Fix                                                                                                                                                            | Found by          |
| --- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| 1   | **High**     | Off-curve keys accepted in multisig and P2PK scripts. rusty-kaspa aborts `OP_CHECKMULTISIG` on the first invalid key it walks, so one malicious enterprise member could **freeze a vault forever** by submitting a key that sorts first. | Every key is validated as a curve point (`lift_x`) in `multisigRedeemScript`, `p2pkScript`, spend descriptors; recipients paying to a burn key are refused.    | Reviewer + Author |
| 2   | **High**     | No bound on fee rate or total fee: a hostile `/info/fee-estimate` could drain a wallet into fees.                                                                                                                                        | `pickFeeRate` validates and clamps (default 10,000 sompi/g); planner refuses `feeRate > maxFeeRate` and `fee > maxFee` (default 5 KAS) with `FeeTooHighError`. | Reviewer + Author |
| 3   | Medium       | Bundle fields that change meaning (version, lane, payload, lock time, sequence) accepted from the other device.                                                                                                                          | `openSigningBundle` enforces a default-deny `BundlePolicy`; `assertTransactionPolicy` exported.                                                                | Reviewer          |
| 4   | Medium       | A co-signer signs every input its key is entitled to — a proposer could add inputs from **another vault** the same key belongs to.                                                                                                       | `signTransaction(…, { onlyScripts })` refuses any input outside the approved scripts; `describeTransaction` flags `foreign-input`.                             | Reviewer          |
| 5   | Medium       | Any sighash type accepted in signing and finalisation; `SIGHASH_SINGLE` on an input without a matching output commits to nothing.                                                                                                        | `SIG_HASH_ALL` only unless `allowNonAllSighash`; the unbound `SINGLE` case is always refused.                                                                  | Reviewer          |
| 6   | Medium (DoS) | `mergePartialSignatures` let a later remote duplicate displace a valid local partial; `inputIndex` unchecked.                                                                                                                            | First occurrence wins; strict partial-signature shape validation at every boundary.                                                                            | Reviewer          |
| 7   | Low          | JSON decoding did not check byte lengths or integer ranges.                                                                                                                                                                              | Strict decoders + `validateTransactionStructure` (mirrors rusty-kaspa isolation checks) on every decoded transaction.                                          | Reviewer          |
| 8   | Low          | `localSigner` accepted a 32-character string as a key.                                                                                                                                                                                   | `instanceof Uint8Array` check.                                                                                                                                 | Reviewer          |
| 9   | Low          | `parseJsonSafe` regex could rewrite digits inside JSON strings.                                                                                                                                                                          | Replaced by a string-aware scanner.                                                                                                                            | Reviewer          |
| 10  | Low          | UTXO responses barely validated; duplicates not removed; no size cap.                                                                                                                                                                    | Field validation, de-duplication, `maxUtxos` cap; planner refuses duplicate outpoints.                                                                         | Reviewer + Author |
| 11  | Low          | `submit` returned whatever id the server reported.                                                                                                                                                                                       | Compared with the locally computed id; mismatch throws.                                                                                                        | Reviewer          |
| 12  | Low          | Sigop scanner matched only minimally-encoded counts (rusty-kaspa accepts non-minimal) and returned 0 for malformed scripts.                                                                                                              | Exact port of `deserialize_i64`; zero-sigop `p2sh-script` refused. Differentially tested against `p2sh_sig_scanner` over 401 scripts.                          | Reviewer          |
| 13  | Info         | Several strings could decode to one address (padding bits ignored, as in rusty-kaspa).                                                                                                                                                   | Only the canonical encoding is accepted.                                                                                                                       | Reviewer          |
| 14  | Info         | Plain `http://` REST URLs accepted.                                                                                                                                                                                                      | HTTPS required unless `allowInsecureHttp`.                                                                                                                     | Reviewer          |
| 15  | Low          | Construction accepted duplicate inputs, zero outputs and outputs exceeding inputs.                                                                                                                                                       | `createTransaction` validates structure; `signTransaction` refuses outputs > inputs.                                                                           | Author            |
| 16  | Low          | A `kaspatest:` address pasted into a mainnet wallet silently converted to a mainnet script.                                                                                                                                              | `addressToScriptPublicKey(address, expectedPrefix)`.                                                                                                           | Author            |
| 17  | Info         | An approval screen computing fee rate on an unsigned transaction would overstate it.                                                                                                                                                     | `describeTransaction` sizes unsigned inputs at their final signature length.                                                                                   | Author            |

**Confirmed correct** by both passes: signature hash (v0/v1, all six types, ECDSA wrapper); transaction id and hash encodings; serialized size, compute, transient and KIP-9 storage mass; multisig script layout and key-order signature rules; P2SH hashing; value conservation, MAX_SOMPI and count checks; coinbase maturity; linear-time parsers; no prototype-pollution path; no secrets in error messages.

### 4.2 Round 2 findings (0.3.0)

"R2" findings came from the two round-2 reviewers. Each one was reproduced by a test before it was fixed, and each has a regression test in `test/review-2.test.ts` or `test/wrpc.test.ts`.

| #     | Sev    | Finding                                                                                                                                                                                                                                                                     | Fix                                                                                                                                                                                                                                                                                                                                                                                    |
| ----- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R2-1  | Medium | **Cross-session fee inflation.** Each input's signature commits only to its own amount. A lying co-signer, or a compromised UTXO backend, could collect victim signatures for different inputs in separate sessions and combine them. Proven in the engine: a 99.1 KAS fee. | `signedAmounts` ledger: a device refuses to re-sign an outpoint under a different amount. `openSigningBundle` now **fails closed** unless `trustedUtxos`, `trustedEntries` or `fundingTransactions` are given. `fundingTransactions` proves amounts from the transactions that created them (transaction-ID commitment), and `getFundingTransaction` (REST) fetches them, best effort. |
| R2-2  | Medium | Transactions with **zero outputs** were accepted (consensus allows them), so every input went to the fee. The round-1 regression test covered a zero-_value_ output instead.                                                                                                | Refused in `createTransaction`, `signTransaction`, `openSigningBundle` and `finalizeTransaction`. Signing now enforces a **fee ceiling** (`maxFee`, default 5 KAS) independent of the planner, and `BundlePolicy.maxFee` does the same.                                                                                                                                                |
| R2-3  | Medium | A silent or half-open node was never detected: the keepalive swallowed ping timeouts, so balances and subscriptions went stale.                                                                                                                                             | An unanswered ping tears the connection down, which triggers reconnect and resubscribe.                                                                                                                                                                                                                                                                                                |
| R2-4  | Medium | A resolver that stalled mid-body hung `connect()` and every later call.                                                                                                                                                                                                     | One deadline covers headers and body, and the body is capped at 4 KB.                                                                                                                                                                                                                                                                                                                  |
| R2-5  | Medium | `getMempoolEntry(id)` returned whatever transaction the node sent.                                                                                                                                                                                                          | The returned transaction must hash to `id`.                                                                                                                                                                                                                                                                                                                                            |
| R2-6  | Medium | A lost submit response looked like a rejection, so a wallet that rebuilt the transaction from other UTXOs could pay twice.                                                                                                                                                  | `SubmitOutcomeUnknownError` (wRPC and REST) whenever the frame was sent but no definite answer came back. Its documentation says to re-submit the identical transaction, never a new selection.                                                                                                                                                                                        |
| R2-7  | Low    | Coinbase maturity was 200 DAA; mainnet requires 1,000 (10 bps × 100 s).                                                                                                                                                                                                     | `COINBASE_MATURITY = 1000n`, verified against the pinned rusty-kaspa.                                                                                                                                                                                                                                                                                                                  |
| R2-8  | Low    | The planner never validated `changeSpend`, so change could be locked to an unspendable script.                                                                                                                                                                              | `validateReceivingSpend`: a spend must be valid, and a multisig must be canonical (curve points, distinct keys, at most 15).                                                                                                                                                                                                                                                           |
| R2-9  | Low    | Up to 0.5 KAS of change was folded into the fee even when a change output cost a fraction of that. Paying 10 KAS from a 10.4 KAS UTXO cost 0.40 KAS instead of 0.027 KAS.                                                                                                   | The fold threshold now defaults to the cost of spending the change later. KIP-9 storage mass is already priced into the fee.                                                                                                                                                                                                                                                           |
| R2-10 | Low    | v1 compute budgets were not checked against the spend. Budgets are not in the signature hash, so a relay could lower one after signing.                                                                                                                                     | A floor of `spendComputeBudget` is enforced at creation, signing, bundle opening and finalisation.                                                                                                                                                                                                                                                                                     |
| R2-11 | Low    | Client lifecycle problems: `close()` followed by `connect()` joined a stale attempt; calls made after `close()` reconnected silently; a throwing `onConnectionChange` broke connecting; a node could force a reconnect every second.                                        | Connection epochs; calls after `close()` are refused; callbacks are isolated; the backoff resets only after 30 s of stable connection.                                                                                                                                                                                                                                                 |
| R2-12 | Low    | `stringifyWithBigInt`: the marker could collide in object keys, and negative bigints were emitted.                                                                                                                                                                          | A per-call unique marker, checked in both keys and values; only u64 bigints are accepted.                                                                                                                                                                                                                                                                                              |
| R2-13 | Low    | UTXO `covenantId` was dropped, so covenant-bound coins sent to a wallet could be selected, mis-priced or rejected.                                                                                                                                                          | The covenant ID is parsed; the planner never selects covenant UTXOs; `BundlePolicy` denies covenant outputs by default; `describeTransaction` warns about them.                                                                                                                                                                                                                        |
| R2-14 | Low    | Malformed but well-framed responses raised `TypeError`s.                                                                                                                                                                                                                    | Every response and element is shape-checked and raises `RpcError`.                                                                                                                                                                                                                                                                                                                     |
| R2-15 | Low    | Mempool "receiving" entries were not tied to the address.                                                                                                                                                                                                                   | A receiving entry must pay the address. Mempool data is documented as advisory.                                                                                                                                                                                                                                                                                                        |
| R2-16 | Low    | The platform `WebSocket` was not assignable to `WebSocketLike`.                                                                                                                                                                                                             | Handler parameter types loosened; covered by a type test.                                                                                                                                                                                                                                                                                                                              |
| R2-17 | Info   | Several small items: truncated PUSHDATA length bytes parsed leniently; no way to wipe a local key; n = 16 multisig accepted from bundles; prototype keys passed the network check; the REST client had no network pinning.                                                  | `parseScript` throws. `LocalSigner.destroy()`. Spends with more than 15 keys are refused. `hasOwnProperty` for the network check. `RestClientOptions.prefix`.                                                                                                                                                                                                                          |

**Confirmed sound by round 2** (both reviewers, with proofs):

- **Nonces:** fresh 32-byte auxiliary randomness per signature; deterministic mode is BIP340-safe; noble self-verifies each signature.
- **No key leakage:** none through errors, JSON, WIF parsing or the signer object.
- **Domain separation:** message and transaction signatures use separate domains.
- **Sighash:** byte-identical to rusty-kaspa for v0 and v1.
- **Multisig finalisation:** exactly m signatures, in key order, all re-verified.
- **Attribution and precision:** UTXO attribution holds, and u64 precision is exact in both directions.
- **Network confusion:** the network is verified before any caller request reaches a node.
- **Resolver:** no URL downgrade; only allowlisted ops are ever sent.
- **KRC-20:** the JSON cannot be injected.
- **Igra:** the payload and the locked amount are bound together.
- **Planner:** value conservation and fee and mass caps hold.

### 4.1 Residual risks and integrator obligations

These cannot be solved inside a library; each consumer must do them.

1. **SSP Key must:**
   - open bundles with an independent amount source: `trustedUtxos` from its own lookup, ideally a different backend from the wallet's, plus `fundingTransactions` where they are available;
   - sign with `onlyScripts: [vault script]` and a **persistent `signedAmounts` ledger**. The ledger is what closes R2-1 when the backend itself is compromised;
   - render `describeTransaction` (outputs, `sent`, fee, warnings) before the user approves.
2. On `SubmitOutcomeUnknownError`, re-submit the identical signed transaction or look it up. **Never** re-plan from different UTXOs.
3. For production, run a dedicated JSON-wRPC node (`--utxoindex --rpclisten-json`). Public resolvers only list Borsh endpoints; the `/wrpc/json` path swap works today but depends on how the proxies are configured.
4. Pass `expectedPrefix` whenever converting a user-entered address, and set `prefix` on REST clients.
5. React Native needs `crypto.getRandomValues` (e.g. `react-native-get-random-values`); noble fails closed without it.
6. JavaScript cannot guarantee key zeroisation. Keep private keys in the platform keystore, create `localSigner`s only for the duration of a signing session, and call `destroy()` afterwards.
7. Kaspa hard-forks roughly yearly. On each fork: bump the oracle's rusty-kaspa pin, run the suite, port, regenerate fixtures (`oracle/README.md`).
8. Whether the mempool itself rejects transactions above 100,000 grams (vs only the wallet convention) is unverified; the library enforces 100,000 either way.

## 5. Dependencies

Runtime: **two**, both exact-pinned, both audited upstream.

| Package         | Version        | Notes                                                                                                                                               |
| --------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@noble/curves` | 2.4.0 (latest) | Upgraded from 2.2.0: **2.3.0 was a security release** — guaranteed constant-time execution and secret-scalar blinding after a Trail of Bits review. |
| `@noble/hashes` | 2.4.0 (latest) | Deduplicated under curves.                                                                                                                          |

Development: every tool at its latest release **except TypeScript**, held at 6.0.3 because `typescript-eslint` (latest 8.70.1) supports TypeScript `<6.1` only; TypeScript 7 (the native compiler) is blocked until it does. ESLint 10.11, Vitest 5.0, Vite 8.3, Prettier 3.9, `@types/node` 26.6.

- `yarn audit`: **0 vulnerabilities** in 179 packages (3 at runtime). Re-checked for 0.3.0: no new dependencies; `yarn outdated` lists only TypeScript (held, see above).
- No `^`/`~` anywhere; `yarn.lock` and `oracle/Cargo.lock` committed; Rust crates exact-pinned; rusty-kaspa pinned by commit.
- CI: GitHub Actions pinned to commit SHAs, `permissions: contents: read`, `--frozen-lockfile`, production `yarn audit`, Node 22 and 24.
- Publishing: `publishConfig` with npm provenance; `files` limited to `dist`, `LICENSE`, `README.md`; no install scripts; `sideEffects: false`; ESM with an `exports` map.

## 6. Verification

| Suite                                | What it proves                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Differential vs rusty-kaspa oracle   | Byte-identical addresses, pushes, script numbers, multisig and P2SH scripts, v0/v1 ids and hashes, Schnorr and ECDSA sighashes (all types), mass (all dimensions), sigop scanning, message hashes, deterministic signatures                                                                                                                     |
| Script-engine execution              | Library-signed transactions executed by rusty-kaspa's engine with consensus budgets: single-sig, all 120 M-of-N up to 15-of-15, relay hop, mixed inputs, KRC-20 inscription and reveal, compounding chain, Igra v1 lane with payload, and the **exact** v1 compute budget (passes; one less fails) for every shape. Negative controls rejected. |
| Mainnet (live)                       | Real transaction ids and hashes reproduced; real Schnorr and 15-key ECDSA multisig signatures verify against our sighash; engine accepts them as rebuilt; our mass equals the node's                                                                                                                                                            |
| Unit, property, security regressions | Planner invariants over random UTXO sets; every finding in §4 and §4.2; signing soundness (nonce uniqueness, no key exposure, domain separation, signature binding, faulty signers)                                                                                                                                                             |
| wRPC (fake node + live)              | Framing, node verification and failover, precision, attribution, v0/v1 encoding, submission outcomes, subscriptions and reconnects. Live: a mainnet node decodes v0, payload, v1 and Igra-lane transactions to our IDs; UTXOs agree with REST; funding transactions prove the UTXO index's amounts                                              |

**224 tests pass** offline (plus 15 live against mainnet). Coverage: **92% lines, 89% statements, 95% functions, 80% branches**; consensus-critical modules 92–100% lines. The REST and wRPC clients are covered further by the live suites.

### 6.1 Funded mainnet verification (2026-09-25)

Real transactions were built, signed and submitted by 1.0.0-candidate code from throwaway keys; all were accepted. For every transaction, the mass the node reported was checked against the library's prediction: it was **identical to the gram**.

| Scenario                                                             | Transaction                                                                                                        |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Single-sig send, 7 outputs (wRPC)                                    | [`3650f55d0bdb…`](https://explorer.kaspa.org/txs/3650f55d0bdb0532404dd9248afd9e45eda06699692f7326cb2f9473fed8010d) |
| SSP 2-of-2: bundle, key's own lookup + funding proof + ledger (REST) | [`d0e3b8bdc912…`](https://explorer.kaspa.org/txs/d0e3b8bdc9126152d958ae2e051bcfd4613c79dd2e0fa8f334a4e6dfd7f68147) |
| Enterprise 2-of-3 signed by A + C                                    | [`df96c008af12…`](https://explorer.kaspa.org/txs/df96c008af12199eaeadae587165865a788fa4568940094ebf44b48bb4889456) |
| Consolidation, 5 multisig inputs                                     | [`efc9c03dffe8…`](https://explorer.kaspa.org/txs/efc9c03dffe897eb72b7b468ceef7d3398f01683617456cc4e9294f946361c67) |
| 2-of-2 vault sweep                                                   | [`57bdc9616030…`](https://explorer.kaspa.org/txs/57bdc961603040b12cc74d3fa62c331bb073c645b852bdd5ada3675022aac793) |
| Send with a message payload (wRPC)                                   | [`a8ed8f7c9568…`](https://explorer.kaspa.org/txs/a8ed8f7c9568ffbdc22a77d05da57931bb1739c50e4010957c6c4cbc382a2184) |
| KRC-20 commit                                                        | [`f522263f17ba…`](https://explorer.kaspa.org/txs/f522263f17ba7424b4308b543c3d35dc9d0df4973f4e4534e0414b6154531afd) |
| KRC-20 reveal                                                        | [`baf7c482a281…`](https://explorer.kaspa.org/txs/baf7c482a281e2b5dbe03fd723802b8ad2c6e7eaa5ab02cc5f9783c0753460de) |
| Igra entry (v1 lane, mined nonce; 10 iKAS credited on L2)            | [`97b18694a925…`](https://explorer.kaspa.org/txs/97b18694a925dfa6f78e06f4c4580d8c0fc1a04fea98b8051c4693e43023a009) |
| Enterprise 4-of-7 (random signers, per-device JSON hops)             | [`566c13d2de33…`](https://explorer.kaspa.org/txs/566c13d2de33a732602d0e482591bd997755b57f6f1e4b89ef296aeb8d454f80) |
| Enterprise 6-of-10                                                   | [`91129c0134d1…`](https://explorer.kaspa.org/txs/91129c0134d164e61949d93f343ab7c6b7c176f24213a318e0f43340248938ab) |
| Enterprise 10-of-15 (15 sigops, 1,161-byte signature script)         | [`729ebde012ba…`](https://explorer.kaspa.org/txs/729ebde012ba2bf19301d38fff237f926cc0820c8809b9f1a0c59c6f5b98cec6) |

All 14 transactions the library built (the table plus enterprise funding and the final sweep back) were accepted; their fees totalled about 0.19 KAS.

## 7. Release checklist

- [x] Functional coverage for every SSP flow
- [x] ZelCore transaction building for every flow
- [x] Independent security review; all findings fixed with regression tests
- [x] Dependencies latest (TypeScript excepted, see §5), exact-pinned, 0 vulnerabilities
- [x] CI hardened
- [x] Funded spends on chain: SSP 2-of-2, M-of-N up to 10-of-15, consolidation; ZelCore single-sig, message payload, KRC-20 commit/reveal, Igra entry (§6.1)
- [ ] Create `RunOnFlux/kaspa-core`, push, green CI, publish 1.0.0 to npm
- [x] ZelCore: wRPC client, KRC-20 and Igra helpers (the WASM can be removed)
- [x] Second independent review round; all findings fixed with regression tests
