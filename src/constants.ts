/**
 * Consensus and standardness constants, each verified against rusty-kaspa
 * `master` at commit 01b532e8 (2026-09-22). The source file is named per line.
 */

// consensus/core/src/constants.rs
export const SOMPI_PER_KASPA = 100_000_000n;
export const MAX_SOMPI = 2_900_000_000_000_000_000n;
export const TX_VERSION = 0;
export const TX_VERSION_TOCCATA = 1;
export const LOCK_TIME_THRESHOLD = 500_000_000_000n;
export const MAX_SCRIPT_PUBLIC_KEY_VERSION = 0;
export const STORAGE_MASS_PARAMETER = 1_000_000_000_000n;
export const TRANSIENT_BYTE_TO_MASS_FACTOR = 4n;
export const MAX_TX_IN_SEQUENCE_NUM = (1n << 64n) - 1n;
export const SEQUENCE_LOCK_TIME_DISABLED = 1n << 63n;

// consensus/core/src/config/params.rs (MAINNET_PARAMS)
export const MASS_PER_TX_BYTE = 1n;
export const MASS_PER_SCRIPT_PUB_KEY_BYTE = 10n;
export const MASS_PER_SIG_OP = 1000n;
export const BLOCK_MASS_LIMIT_COMPUTE = 500_000n;
export const BLOCK_MASS_LIMIT_STORAGE = 500_000n;
export const BLOCK_MASS_LIMIT_TRANSIENT = 1_000_000n;
export const MAX_TX_INPUTS = 1000;
export const MAX_TX_OUTPUTS = 1000;
export const MAX_SIGNATURE_SCRIPT_LEN = 250_000;
export const MAX_SCRIPT_PUBLIC_KEY_LEN = 10_000;
export const COINBASE_MATURITY = 1000n;

// consensus/core/src/mass/units.rs
export const GRAMS_PER_SIGOP_COUNT_UNIT = 1000n;
export const GRAMS_PER_COMPUTE_BUDGET_UNIT = 100n;
export const SCRIPT_UNITS_PER_GRAM = 100n;
/** 10,000 script units per compute-budget unit. */
export const SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT =
  GRAMS_PER_COMPUTE_BUDGET_UNIT * SCRIPT_UNITS_PER_GRAM;
/** Free per-input allowance before the committed budget: 9,999 script units. */
export const FREE_SCRIPT_UNITS_PER_INPUT =
  SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT - 1n;
/** One signature check at mainnet mass_per_sig_op (1000 grams): 100,000 script units. */
export const SIGOP_SCRIPT_UNITS = 1000n * SCRIPT_UNITS_PER_GRAM;
/** OP_BLAKE2B pricing (`HashOpcodePricing::Blake2b`), charged on the P2SH redeem hash. */
export const BLAKE2B_SCRIPT_UNITS_PER_BYTE = 2n;
export const MAX_COMPUTE_BUDGET = 0xffff;

// consensus/core/src/mass/mod.rs (utxo_plurality)
export const UTXO_CONST_STORAGE = 63n;
export const UTXO_UNIT_SIZE = 100n;
export const COVENANT_ID_SIZE = 32n;

/**
 * NOT consensus: rusty-kaspa wallet-core's standard transaction mass cap
 * (`wallet/core/src/tx/mass.rs`). Every Kaspa wallet honours it so its
 * transactions behave predictably. The hard ceiling is the per-block limit.
 */
export const MAXIMUM_STANDARD_TRANSACTION_MASS = 100_000n;

/**
 * NOT consensus: safety rails against an untrusted fee source. A REST server
 * that returns an absurd fee rate must not be able to drain a wallet into fees.
 * The live network rate is ~100 sompi/gram; these leave ample headroom.
 */
export const DEFAULT_MAX_FEE_RATE = 10_000n;
/** Per-transaction fee ceiling used by the planner unless overridden: 5 KAS. */
export const DEFAULT_MAX_FEE = 500_000_000n;

// mining/src/mempool/config.rs — 100,000 sompi per kilogram = 100 sompi per gram.
export const MINIMUM_RELAY_TRANSACTION_FEE_PER_KG = 100_000n;
export const MINIMUM_FEE_RATE_SOMPI_PER_GRAM = 100n;

// crypto/txscript/src/lib.rs
export const MAX_PUB_KEYS_PER_MULTISIG = 20;
export const MAX_SCRIPTS_SIZE = 1_000_000;
export const MAX_SCRIPT_ELEMENT_SIZE = 1_000_000;

// mining/src/mempool/check_transaction_standard.rs
export const MAX_STANDARD_P2SH_SIG_OPS = 15;

// consensus/core/src/subnets.rs
export const SUBNETWORK_ID_SIZE = 20;

// consensus/core/src/hashing/sighash_type.rs
export const SIG_HASH_ALL = 0x01;
export const SIG_HASH_NONE = 0x02;
export const SIG_HASH_SINGLE = 0x04;
export const SIG_HASH_ANY_ONE_CAN_PAY = 0x80;
export const SIG_HASH_MASK = 0x07;
export const ALLOWED_SIG_HASH_TYPES: readonly number[] = [
  SIG_HASH_ALL,
  SIG_HASH_NONE,
  SIG_HASH_SINGLE,
  SIG_HASH_ALL | SIG_HASH_ANY_ONE_CAN_PAY,
  SIG_HASH_NONE | SIG_HASH_ANY_ONE_CAN_PAY,
  SIG_HASH_SINGLE | SIG_HASH_ANY_ONE_CAN_PAY,
];
