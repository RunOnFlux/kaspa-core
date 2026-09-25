# Security policy

`@runonflux/kaspa-core` builds and signs transactions that move real funds. Please report vulnerabilities privately.

## Reporting

Use GitHub's private vulnerability reporting on this repository (**Security → Report a vulnerability**) with a description, affected versions and a reproduction if possible. Please do not open a public issue for a suspected vulnerability.

## Supported versions

Only the latest published version receives security fixes while the library is pre-1.0.

## Threat model in one paragraph

The REST server, the wRPC node and resolver, the relay server and, for a co-signer, the other device are all untrusted.

Kaspa's signature hash covers all outputs, but only the amount of the input being signed. The library defends against the attacks this leaves open:

- **Fee inflation, including across signing sessions:** fee-rate and fee ceilings at planning _and_ signing, independent amount sources, and a per-outpoint signed-amount ledger.
- **Signing more than the user approved:** bundle policy, input allowlist, and `SIG_HASH_ALL` by default.
- **Unspendable outputs:** keys must be curve points, change scripts must be canonical, and transactions without outputs are refused.
- **A lying node:** network verification, UTXO attribution, transaction-ID checks, and `SubmitOutcomeUnknownError`.

See [AUDIT.md](./AUDIT.md) for the findings and fixes.

## Integrator obligations

A co-signing device **must**:

1. Open bundles with an independent amount source. `openSigningBundle` refuses without one. Use `trustedUtxos` from its own lookup, preferably a different backend from the proposer's, and `fundingTransactions` where available.
2. Keep a **persistent `signedAmounts` ledger** and pass it with `onlyScripts: [the vault's script]` to `signTransaction`.
3. Show the user `describeTransaction(...)` (recipients, `sent`, fee and `warnings`) before signing.

Every wallet must treat `SubmitOutcomeUnknownError` as "maybe broadcast". Re-submit the identical signed transaction, never one rebuilt from different UTXOs.

Also: pass `expectedPrefix` when converting user-entered addresses, provide `crypto.getRandomValues` on React Native, and keep private keys in the platform keystore rather than in long-lived objects, and call `destroy()` on a `localSigner` when the session ends (JavaScript cannot guarantee zeroisation).
