/**
 * The opcodes this library emits or recognises, from
 * `crypto/txscript/src/opcodes/mod.rs`. Kaspa's script engine is a btcd
 * lineage fork, but note: `0xaa` is OP_BLAKE2B here (OP_HASH256 in Bitcoin),
 * and OP_HASH160 / OP_RIPEMD160 do not exist at all.
 */
export const Op = {
  Op0: 0x00,
  OpFalse: 0x00,
  OpData1: 0x01,
  OpData32: 0x20,
  OpData33: 0x21,
  OpData65: 0x41,
  OpData75: 0x4b,
  OpPushData1: 0x4c,
  OpPushData2: 0x4d,
  OpPushData4: 0x4e,
  Op1Negate: 0x4f,
  Op1: 0x51,
  OpTrue: 0x51,
  Op16: 0x60,
  OpIf: 0x63,
  OpEndIf: 0x68,
  OpEqual: 0x87,
  OpCheckMultiSigECDSA: 0xa9,
  OpBlake2b: 0xaa,
  OpCheckSigECDSA: 0xab,
  OpCheckSig: 0xac,
  OpCheckSigVerify: 0xad,
  OpCheckMultiSig: 0xae,
  OpCheckMultiSigVerify: 0xaf,
  OpCheckLockTimeVerify: 0xb0,
  OpCheckSequenceVerify: 0xb1,
} as const;

export const OP_SMALL_INT_MIN_VAL = 1;
export const OP_SMALL_INT_MAX_VAL = 16;
export const OP_1_NEGATE_VAL = 0x81;
export const OP_DATA_MAX_VAL = 75;
