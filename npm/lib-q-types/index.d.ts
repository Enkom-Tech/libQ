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
