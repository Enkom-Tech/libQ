# HPKE API Reference

This document summarizes the **public** surface of `lib-q-hpke`. For design intent, PSK wire formats, and interoperability notes, see [hpke-architecture.md](../../docs/hpke-architecture.md). For module layout, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Conventions

- **Post-quantum only:** The shipped HPKE path uses ML-KEM for `HpkeKem::*` and PQ-friendly KDF/AEAD choices. There is no classical KEM in this stack.
- **Result type:** `HpkeContext` methods return `lib_q_core::Result<T>` (alias for `Result<T, lib_q_core::Error>`). Lower-level helpers may use `HpkeResult<T>` (`Result<T, HpkeError>`). `HpkeError` converts into `lib_q_core::Error` via `impl From<HpkeError> for lib_q_core::Error` in `src/error.rs`.
- **KEM `CryptoProvider` vs HPKE crypto backend:** `HpkeContext::with_provider` configures only the inner `KemContext`. HPKE encapsulation, KDF, AEAD, and export use `Arc<dyn HpkeCryptoProvider + Send + Sync>` (default `PostQuantumProvider`). Replace the latter with `HpkeContext::with_hpke_crypto` / `set_hpke_crypto`.

## `lib_q_hpke::interop`

Deterministic intersection of peer advertisements:

- `HpkeInteropProfile` — `RfcStrictPq` (RFC 9180 PSK wire; no lib-Q–only PSK suffix in strict mode) vs `LibQExtensions` (optional commitment suffix and feature-gated AEAD).
- `HpkeCapabilities` — ordered suite list, supported modes, ordered PSK wire preferences.
- `negotiate_hpke_capabilities(&local, &remote)` — returns `NegotiatedHpkeParams` or `HpkeNegotiationError` (no silent downgrade).
- `cipher_suite_supported_by_build` — rejects suites that need missing Cargo features (for example duplex-sponge AEAD).

Bind serialized capability bytes into an application-level authenticated transcript; this crate does not implement a transport protocol.

## `HpkeContext`

Main entry point: holds a `KemContext`, the active [`HpkeCipherSuite`](../src/types.rs), [`HpkePskWireFormat`](../src/types.rs) for PSK / AuthPSK encapsulated-key layout, an `Arc<dyn HpkeCryptoProvider + Send + Sync>` for HPKE crypto, and a `Box<dyn CryptoRng + Send>` for setup/single-shot RNG (default OS-backed when `secure-rng` is enabled).

### Constructors and suite

```rust
impl HpkeContext {
    pub fn new() -> Self;
    pub fn with_provider(provider: Box<dyn lib_q_core::CryptoProvider>) -> Self;
    pub fn with_hpke_crypto(hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>) -> Self;
    pub fn set_hpke_crypto(&mut self, hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>);
    pub fn set_rng(&mut self, rng: Box<dyn CryptoRng + Send>);

    pub fn cipher_suite(&self) -> &HpkeCipherSuite;
    pub fn set_cipher_suite(&mut self, cipher_suite: HpkeCipherSuite);

    pub fn psk_wire_format(&self) -> HpkePskWireFormat;
    pub fn set_psk_wire_format(&mut self, format: HpkePskWireFormat);
}
```

### Single-shot (Base schedule)

```rust
impl HpkeContext {
    pub fn seal(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> lib_q_core::Result<(Vec<u8>, Vec<u8>)>;

    pub fn open(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> lib_q_core::Result<Vec<u8>>;
}
```

### Multi-shot setup (all modes)

All setup methods return `lib_q_core::Result<…>`.

```rust
impl HpkeContext {
    pub fn setup_sender(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
    ) -> lib_q_core::Result<HpkeSenderContext>;

    pub fn setup_receiver(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
    ) -> lib_q_core::Result<HpkeReceiverContext>;

    pub fn setup_sender_psk(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> lib_q_core::Result<HpkeSenderContext>;

    pub fn setup_receiver_psk(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> lib_q_core::Result<HpkeReceiverContext>;

    pub fn setup_sender_auth(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        sender_sk: &KemSecretKey,
        sender_pk: &KemPublicKey,
    ) -> lib_q_core::Result<HpkeSenderContext>;

    pub fn setup_receiver_auth(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        sender_pk: &KemPublicKey,
    ) -> lib_q_core::Result<HpkeReceiverContext>;

    pub fn setup_sender_auth_psk(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender_sk: &KemSecretKey,
        sender_pk: &KemPublicKey,
    ) -> lib_q_core::Result<HpkeSenderContext>;

    pub fn setup_receiver_auth_psk(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender_pk: &KemPublicKey,
    ) -> lib_q_core::Result<HpkeReceiverContext>;
}
```

## `HpkeSenderContext` / `HpkeReceiverContext`

Defined in [`types.rs`](../src/types.rs). Sensitive fields use [`SecretBytes`](../src/types.rs) (`Zeroizing<Vec<u8>>`). Important **public** fields:

| Field | Meaning |
|--------|---------|
| `shared_secret`, `exporter_secret`, `key`, `nonce` | Schedule-derived material (zeroized on drop) |
| `cipher_suite` | Active suite for export / labels |
| `aead` | AEAD algorithm for this context |
| `encapsulated_key` | Sender only: wire bytes for the receiver |
| `sequence_number`, `max_sequence_number` | Base nonce XOR counter |
| `state` | `HpkeContextState` (`Active`, `NeedsRekey`, `Closed`) |

### Methods (`impl` blocks in `lib.rs`)

```rust
impl HpkeSenderContext {
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> lib_q_core::Result<Vec<u8>>;
    pub fn export(&self, exporter_context: &[u8], length: usize) -> lib_q_core::Result<Vec<u8>>;
    pub fn encapsulated_key(&self) -> &[u8];
    pub fn can_encrypt(&self) -> bool;
    pub fn increment_sequence(&mut self) -> Result<(), HpkeError>;
    pub fn close(&mut self);
}

impl HpkeReceiverContext {
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> lib_q_core::Result<Vec<u8>>;
    pub fn export(&self, exporter_context: &[u8], length: usize) -> lib_q_core::Result<Vec<u8>>;
    pub fn can_decrypt(&self) -> bool;
    pub fn increment_sequence(&mut self) -> Result<(), HpkeError>;
    pub fn close(&mut self);
}
```

`seal` / `open` on these contexts return `lib_q_core::Error` on state misuse (for example `Closed` or sequence overflow), not always `HpkeError`.

## Mode and PSK wire enums

```rust
pub enum HpkeMode {
    Base = 0x00,
    Psk = 0x01,
    Auth = 0x02,
    AuthPsk = 0x03,
}

pub enum HpkePskWireFormat {
    Rfc9180,
    LibQCommitmentSuffix,
}
```

See doc comments on `HpkePskWireFormat` in `types.rs` for interoperability rules.

## Algorithm identifiers (`types.rs`)

### `HpkeKem`

```rust
pub enum HpkeKem {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl HpkeKem {
    pub fn algorithm_id(self) -> u16;
    pub fn shared_secret_len(self) -> usize;
    pub fn enc_len(self) -> usize;
    pub fn public_key_len(self) -> usize;
    pub fn secret_key_len(self) -> usize;
}
```

### `HpkeKdf`

```rust
pub enum HpkeKdf {
    HkdfShake128,
    HkdfShake256,
    HkdfSha3_256,
    HkdfSha3_512,
}

impl HpkeKdf {
    pub fn algorithm_id(self) -> u16;
    pub fn digest_len(self) -> usize;
    pub fn extract_len(self) -> usize;
}
```

### `HpkeAead`

```rust
pub enum HpkeAead {
    Saturnin256,
    Shake256,
    DuplexSpongeAead, // requires crate feature `duplex-sponge-aead`
    Export,
}

impl HpkeAead {
    pub fn algorithm_id(self) -> u16;
    pub fn key_len(self) -> usize;
    pub fn nonce_len(self) -> usize;
    pub fn tag_len(self) -> usize;
}
```

### `HpkeCipherSuite`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeCipherSuite {
    pub kem: HpkeKem,
    pub kdf: HpkeKdf,
    pub aead: HpkeAead,
}

impl HpkeCipherSuite {
    pub fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self;
    pub fn identifier(&self) -> Vec<u8>;
}
```

## `HpkeError`

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum HpkeError {
    KemError { algorithm: HpkeKem, operation: KemOperation, cause: String },
    KdfError { algorithm: HpkeKdf, operation: KdfOperation, cause: String },
    AeadError { algorithm: HpkeAead, operation: AeadOperation, cause: String },
    SecurityError { validation: SecurityValidation, cause: String },
    ProtocolError { stage: ProtocolStage, cause: String },
    ConfigError { setting: String, cause: String },
    CryptoError(String),
    InvalidInput { parameter: String, value: String, expected: String },
    FeatureNotEnabled { feature: String },
    NotImplemented { feature: String },
    InconsistentPsk,
}
```

Constructors such as `HpkeError::kem_error`, `kdf_error`, `aead_error`, `security_error`, `protocol_error`, `invalid_input`, `feature_not_enabled`, and `not_implemented` are defined on `HpkeError` in `src/error.rs`.

## Provider traits

HPKE crypto inside the crate is expressed through split traits in [`providers/traits.rs`](../src/providers/traits.rs):

- **`KemProvider`** — encapsulate, decapsulate, `auth_encapsulate` / `auth_decapsulate`, key validation, ML-KEM-oriented helpers.
- **`KdfProvider`** — extract / expand for `HpkeKdf`.
- **`AeadProvider`** — AEAD seal/open and key/nonce validation.
- **`HpkeCryptoProvider`** — `KemProvider + KdfProvider + AeadProvider` plus `name()` and `supported_algorithms()`.

The default implementation is [`PostQuantumProvider`](../src/providers/post_quantum.rs) (`LibQKemProvider`, `create_hash`, `create_aead`).

## Security helpers (`security::memory_safety`)

[`SecureKey`](../src/security/memory_safety.rs) and [`SecureBytes`](../src/security/memory_safety.rs) wrap sensitive buffers with explicit zeroization. `SecureKey::new(data, key_type)` requires `data.len() == key_type.expected_length()` and rejects all-zero keys.

Use [`validate_kem_key`](../src/security/validation.rs) for wire-format KEM key length checks against `HpkeKem`.

## Usage examples

Use fallible `LibQCryptoProvider::new()` in real programs.

```rust
use lib_q_core::{Algorithm, KemContext, KemPublicKey, KemSecretKey};
use lib_q_hpke::HpkeContext;
use libq::LibQCryptoProvider;

fn basic_hpke_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Box::new(LibQCryptoProvider::new()?);
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message = b"Hello, HPKE!";
    let (encapsulated_key, ciphertext) =
        hpke_ctx.seal(&recipient_pk, b"info", b"aad", message)?;

    let decrypted = hpke_ctx.open(&encapsulated_key, &recipient_sk, b"info", b"aad", &ciphertext)?;
    assert_eq!(decrypted, message);
    Ok(())
}
```

### Handling errors from `seal` / `open`

Match on `lib_q_core::Error`, not `HpkeError`, when using `HpkeContext` directly:

```rust
use lib_q_core::Error;

match hpke_ctx.seal(&recipient_pk, info, aad, message) {
    Ok(pair) => { /* use pair */ }
    Err(Error::InternalError { operation, details }) => {
        eprintln!("HPKE failed: {} — {}", operation, details);
    }
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

## Threading

`HpkeContext` and the sender/receiver contexts are ordinary Rust types with interior mutation where used; treat them as **not** `Sync` unless your `CryptoProvider` / `KemContext` wrapper documents otherwise. Share across threads with `Mutex`/`RwLock` or pass owned contexts per task.
