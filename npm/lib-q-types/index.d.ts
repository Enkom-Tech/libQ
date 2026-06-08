/**
 * Structured error object (`lib_q_core::wasm_common::wasm_js_error`).
 */
export interface LibQWasmError {
  /** Stable string category, e.g. `LIB_Q_HPKE`. */
  code: string;
  /** FNV-1a 32-bit id of `code` for numeric switching. */
  codeNumeric: number;
  message: string;
}

/** `@lib-q/hpke` — single-shot seal */
export interface HpkeSealResult {
  encapsulatedKeyHex: string;
  ciphertextHex: string;
}

/** Serialized sender context (snake_case keys as emitted by `serde` on the Rust structs). */
export interface HpkeSenderWire {
  encapsulated_key_hex: string;
  shared_secret_hex: string;
  exporter_secret_hex: string;
  key_hex: string;
  nonce_hex: string;
  aead: string;
  sequence_number: number;
  max_sequence_number: number;
  state: string;
}

/** `@lib-q/hpke` — `hpkeSetupSender` */
export interface HpkeSetupSenderResult {
  encapsulated_key_hex: string;
  sender: HpkeSenderWire;
}

/** `@lib-q/hpke` — `hpkeSenderSeal` */
export interface HpkeSenderSealResult {
  ciphertext_hex: string;
  sender: HpkeSenderWire;
}

/** Receiver context wire (snake_case). */
export interface HpkeReceiverWire {
  shared_secret_hex: string;
  key_hex: string;
  nonce_hex: string;
  aead: string;
  sequence_number: number;
  max_sequence_number: number;
  state: string;
}

/** `@lib-q/hpke` — `hpkeSetupReceiver` */
export interface HpkeSetupReceiverResult {
  receiver: HpkeReceiverWire;
}

/** `@lib-q/hpke` — `hpkeReceiverOpen` */
export interface HpkeReceiverOpenResult {
  plaintext: Uint8Array;
  receiver: HpkeReceiverWire;
}

/** `@lib-q/cb-kem` */
export interface CbKemKeypair {
  public_key_hex: string;
  secret_key_hex: string;
}

export interface CbKemEncapsulateResult {
  ciphertext_hex: string;
  shared_secret_hex: string;
}

export interface CbKemDecapsulateResult {
  sharedSecretHex: string;
}

/** `@lib-q/hqc` */
export interface HqcKeygenResult {
  publicKey: string;
  secretKey: string;
}

export interface HqcEncapsulateResult {
  ciphertext: string;
  sharedSecret: string;
}

export interface HqcDecapsulateResult {
  sharedSecretHex: string;
}

/** `@lib-q/slh-dsa` — shapes depend on parameter set; keys and signatures are hex strings in JS. */
export interface SlhDsaKeypair {
  verifying_key_hex: string;
  signing_key_hex: string;
}

export interface SlhDsaSignResult {
  signature_hex: string;
}

/** `@lib-q/zkp` — preimage API (object return from prove path) */
export interface ZkpPreimageProof {
  /** Proof payload; exact fields depend on build configuration. */
  [key: string]: unknown;
}

/** `@lib-q/prf` — Gold PRF return shape (`goldPrfU256BeHex`). */
export interface GoldPrfU256HexOut {
  output_hex: string;
}

/** `@lib-q/prf` — hex string outputs */
export type PrfHexString = string;

/** `@lib-q/random` */
export type SecureRandomBytes = Uint8Array;

/** `@lib-q/mac` */
export type QcwMacKeyBytes = Uint8Array;
export type QcwMacTagBytes = Uint8Array;

/** `@lib-q/blind-pcs` */
export interface BlindPcsOpenResult {
  messageHex: string;
  blindHex: string;
}

/** `@lib-q/double-kem` */
export interface DoubleKemEncapResult {
  wireHex: string;
  sharedSecretHex: string;
}

/** `@lib-q/fhe` */
export interface FheKeygenResult {
  seed: string;
  dimension: number;
  modulus: number;
}

export interface FheCiphertextWire {
  dimension: number;
  modulus: number;
  nonce: string;
  plaintextLen: number;
  body: number[];
  mask: number[];
}

export type FheEvalOpWire =
  | { op: "addConstant"; value: number }
  | { op: "mulConstant"; value: number }
  | { op: "addCiphertext"; ciphertext: FheCiphertextWire };

/** `@lib-q/threshold-kem` */
export interface ThresholdKemShareVerifier {
  index: number;
  commitmentHex: string;
}

export interface ThresholdKemPublicKeyWire {
  profileId: number;
  threshold: number;
  mlKemPublicKeyHex: string;
  shareVerifiers: ThresholdKemShareVerifier[];
}

export interface ThresholdKemPartialWire {
  index: number;
  shareBytesHex: string;
  tagHex: string;
}

export interface ThresholdKemKeygenShare {
  index: number;
  threshold: number;
  commitmentHex: string;
  shareBytes: Uint8Array;
}

export interface ThresholdKemEncapResult {
  sharedSecret: Uint8Array;
  ciphertextHex: string;
  wire: Uint8Array;
}

/** `@lib-q/threshold-sig` */
export interface ThresholdSigShareVerifier {
  index: number;
  verifyingKeyHex: string;
  commitmentHex: string;
}

export interface ThresholdSigPublicKeyWire {
  profileId: number;
  threshold: number;
  groupKeyHex: string;
  shareVerifiers: ThresholdSigShareVerifier[];
}

export interface ThresholdSigRound1Commitment {
  index: number;
  nonceCommitmentHex: string;
  bindingHex: string;
}

export interface ThresholdSigRound2Partial {
  index: number;
  zHex: string;
  proofHex: string;
}

export interface ThresholdSigSignatureWire {
  rAggHex: string;
  zHex: string;
  signers: number[];
}

export interface ThresholdSigAggregateResult {
  signature: ThresholdSigSignatureWire;
  signatureBytesHex: string;
  wire: Uint8Array;
}
