# kaspa-core-oracle

A dev-only differential oracle. It links rusty-kaspa's own `kaspa-consensus-core`, `kaspa-txscript`, `kaspa-addresses` and `kaspa-hashes` crates, pinned to a commit in `Cargo.toml`, so every answer is consensus's answer. **Never shipped** in the npm package.

```bash
cargo build --release --manifest-path oracle/Cargo.toml   # ~2 min first build
```

The test suite finds the binary at `oracle/target/release/kaspa-core-oracle` (override with `KASPA_ORACLE`). Without it, the oracle and engine suites are skipped and the static fixtures still run.

## Protocol

The binary reads a JSON array of requests from a file path argument (or stdin) and prints a JSON array of `{ id, ok, result | error }` in the same order. Byte fields are hex; u64 fields are decimal strings.

| op                    | request                        | result                                                                                |
| --------------------- | ------------------------------ | ------------------------------------------------------------------------------------- |
| `encodeAddress`       | `prefix, version, payload`     | `address`                                                                             |
| `decodeAddress`       | `address`                      | `prefix, version, payload`                                                            |
| `pushData`            | `data`                         | `script` (canonical push)                                                             |
| `pushI64`             | `value`                        | `script` (`add_i64`)                                                                  |
| `multisigRedeem`      | `keys[], m`                    | `redeem, spk`                                                                         |
| `p2sh`                | `redeem`                       | `spk`                                                                                 |
| `txid`                | `tx`                           | `id, hash`                                                                            |
| `sighash`             | `tx, entries, index, hashType` | `schnorr, ecdsa`                                                                      |
| `mass`                | `tx, entries`                  | `size, compute, transient, storage`                                                   |
| `verify`              | `tx, entries`                  | per input `ok, error, p2shSigOps` — executes the script engine with consensus budgets |
| `personalMessageHash` | `message`                      | `hash`                                                                                |
| `schnorrSignNoAux`    | `secret, digest`               | `signature, xonly`                                                                    |

Transaction wire format: `{ version, inputs: [{ txid, index, sigScript, sequence, sigOpCount, computeBudget }], outputs: [{ value, spkVersion, spk, covenant? }], lockTime, subnetworkId, gas, payload }`; entries: `[{ amount, spkVersion, spk, blockDaaScore, isCoinbase, covenantId? }]`.

## On a hard fork

1. Bump `rev` in `Cargo.toml` to the release that activates the fork.
2. `yarn oracle:build && yarn test` — every divergence shows up as a failing differential case.
3. Port the change, then `yarn fixtures` to refresh the static vectors.
