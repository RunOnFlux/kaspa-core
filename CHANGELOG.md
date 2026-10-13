# Changelog

## 1.0.1 — 2026-10-13

### Fixed

- `stringifyWithBigInt` reads the raw value, so u64 fields stay bare JSON integers when another library installs `BigInt.prototype.toJSON` (e.g. `@alephium/web3`). They went out as quoted strings, and JSON wRPC rejected `submitTransaction` with "request deserialization error" (REST tolerated it).
- The change planner no longer refuses sends that leave a small change (about 0.15–0.4 KAS) at higher fee rates with `ChangeWouldBeDustError`. Storage mass makes the fee depend on the change, and the fixed-point loop did not settle in 8 rounds; it now finds the largest change whose own fee fits. Plans the old loop settled on are unchanged, adding an input is still preferred over a storage-heavy change, and folding is unchanged when no change amount fits.

## 1.0.0 — 2026-09-25

First stable release. The API is unchanged from 0.3.0.

- Funded mainnet verification ([AUDIT.md](./AUDIT.md) §6.1). Every flow was run on mainnet and accepted, with node-reported mass identical to ours: single-sig; SSP 2-of-2 through the full co-signer flow; enterprise 2-of-3, 4-of-7, 6-of-10 and 10-of-15 with random signer subsets; consolidation; a message payload; KRC-20 commit/reveal; an Igra bridge entry.
- `publishConfig.provenance` removed for the first, local publish; provenance returns with trusted publishing from CI.

## 0.3.0 — 2026-09-24

ZelCore parity (the WASM can be removed) and a second independent security review ([AUDIT.md](./AUDIT.md) §4.2).

### Added

- **`@runonflux/kaspa-core/wrpc`**: a pure-TypeScript JSON-wRPC client, replacing the WASM `RpcClient`.
  - Resolver or fixed URLs; every node is checked for network, sync state and UTXO index before any request.
  - Failover, keepalive that detects dead nodes, reconnect with re-subscription.
  - UTXOs, balances, fee estimates, mempool, and submission of every transaction kind (v1, payload, lanes).
  - UTXO and DAA-score subscriptions.
  - The protocol is documented with live captures in `docs/WRPC_PROTOCOL.md`.
- **KRC-20:** `krc20Transfer`, `krc20Mint`, `krc20Inscription` (ZelCore's exact script and JSON, validated).
- **Igra entries:** `igraEntryPayload`, `planIgraEntry`, `mineIgraEntry` (binds the payload to the locked amount), `parseIgraEntryPayload`.
- **Amount sources and the ledger:** `SignOptions.signedAmounts` (ledger), `SignOptions.maxFee`, `OpenBundleOptions.fundingTransactions`, `entriesFromFundingTransactions`, and REST `getFundingTransaction` (proven by transaction ID).
- `SubmitOutcomeUnknownError` for REST and wRPC submissions.
- REST: `getHistoryByOffset` and the `prefix` option. Also `LocalSigner.destroy()`, `validateReceivingSpend`, and a `covenant-output` warning.

### Security

- **Breaking:** `openSigningBundle` refuses to open without an independent amount source. Pass `trustBundleEntries: true` to opt out explicitly.
- Transactions without outputs are refused everywhere.
- Signing enforces a fee ceiling (default 5 KAS).
- v1 compute budgets have a floor, the spend's minimum, everywhere.
- Change scripts must be valid and canonical.
- Covenant UTXOs are never selected, and covenant outputs are denied by default.
- Only library-created signers may skip re-verification (a signer's `selfVerifying` flag is no longer trusted).
- Digest signers only accept 32-byte digests.
- Key errors never echo the key.
- REST and wRPC UTXOs must match the script of the address they are reported for, and only requested addresses are accepted.
- `stringifyWithBigInt` uses a unique marker and accepts only u64 values.
- REST query parameters are allowlisted.

### Fixed

- Coinbase maturity is 1,000 DAA, not 200.
- Small change is no longer folded into the fee when keeping it is cheaper.
- `parseScript` rejects a truncated PUSHDATA length.

## 0.2.0 — 2026-09-24

Security hardening and the remaining SSP/ZelCore functionality, after a full audit ([AUDIT.md](./AUDIT.md)).

### Security

- Every key placed in a script must be a valid secp256k1 point; off-curve keys could freeze a multisig vault.
- Fee-rate and per-transaction fee ceilings (`maxFeeRate`, `maxFee`, `FeeTooHighError`); `pickFeeRate` validates and clamps untrusted estimates.
- `openSigningBundle` enforces a default-deny `BundlePolicy` and accepts `trustedEntries` (`EntryMismatchError` on any disagreement).
- `signTransaction` accepts an `onlyScripts` input allowlist and refuses transactions whose outputs exceed their inputs.
- `SIG_HASH_ALL` only unless `allowNonAllSighash`; unbound `SIGHASH_SINGLE` always refused.
- Partial signatures validated at every boundary; `mergePartialSignatures` keeps the first occurrence.
- Strict JSON decoding and `validateTransactionStructure` (mirrors rusty-kaspa isolation checks).
- Canonical-only address decoding; `addressToScriptPublicKey(address, expectedPrefix)`.
- REST: HTTPS by default, string-aware large-integer parsing, validated and de-duplicated UTXOs, submit id verified locally.
- Sigop scanner is an exact port of rusty-kaspa's (non-minimal counts accepted); zero-sigop `p2sh-script` refused.

### Added

- `describeTransaction` for approval screens.
- Version 1 planning (`txVersion`, `subnetworkId`, `gas`) and `spendComputeBudget` (exact, engine-verified).
- `requiredInputs` in the planner (KRC-20 reveal).
- `kaspaToSompi` / `sompiToKaspa`, `privateKeyFromWif` / `privateKeyToWif`, `xOnlyFromCompressed`, key validators.

### Changed

- `@noble/curves` and `@noble/hashes` 2.2.0 → 2.4.0 (constant-time hardening). Dev tooling to latest (ESLint 10, Vitest 5, Vite 8).
- `engines.node` ≥ 20.19 (noble 2.4 requirement).

## 0.1.0 — 2026-09-24

Initial implementation: addresses, scripts, M-of-N P2SH multisig, v0/v1 ids and sighashes, BIP340 signing with injected signers, signing bundles, KIP-9 mass and fees, input selection with compounding chains, REST client. Verified against a rusty-kaspa oracle and mainnet data.
