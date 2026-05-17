# lib-q-hpke

RFC 9180–aligned Hybrid Public Key Encryption using **post-quantum-only** primitives (ML-KEM family for the HPKE KEM role in the default provider path; no classical KEM or classical signatures in that path).

## Overview

lib-q-hpke implements HPKE for the lib-q stack: protocol logic and types in this crate, with KEM/AEAD/hash work delegated through `lib-q-kem`, `lib-q-aead`, and `lib-q-hash`. The high-level [`HpkeContext`](src/lib.rs) holds a `lib_q_core::CryptoProvider` for `KemContext` **and** an `Arc<dyn HpkeCryptoProvider + Send + Sync>` (default [`PostQuantumProvider`](src/providers/post_quantum.rs)) for encapsulation, KDF, AEAD, and exporter operations. Use [`HpkeContext::with_hpke_crypto`](src/lib.rs) to swap the HPKE backend; `with_provider` only replaces the inner `KemContext` crypto. Today the default provider wires **ML-KEM only** for HPKE KEM (other PQ KEMs may exist in the workspace but are not in the `HpkeKem` catalog yet).

## Interoperability

Profiles, a mode×suite matrix, and fixture provenance are documented under the workspace [interoperability.md](../../docs/interoperability.md) and [hpke-architecture.md](../../docs/hpke-architecture.md). For code, see [`lib_q_hpke::interop`](src/interop.rs). Run the integrator-oriented example (requires `std`):

`cargo run -p lib-q-hpke --example hpke_interop_negotiation --features std`

## Supported Algorithms

### Key Encapsulation Mechanisms (KEM)
- ML-KEM-512 (Level 1 security)
- ML-KEM-768 (Level 3 security)
- ML-KEM-1024 (Level 5 security)

### Key Derivation Functions (KDF)
- HKDF-SHAKE128
- HKDF-SHAKE256
- HKDF-SHA3-256
- HKDF-SHA3-512

### Authenticated Encryption (AEAD)
- Saturnin-256 (32-byte key, 16-byte nonce, 32-byte tag)
- SHAKE256-based AEAD (16-byte tag)
- Keccak duplex-sponge AEAD via `lib-q-aead` — enable Cargo feature **`duplex-sponge-aead`** on this crate (when using the umbrella `lib-q` crate, enable **`hpke-duplex-aead`**)
- Export-only mode (`HpkeAead::Export`) for exporter-secret usage without message encryption

## Quick Start

```rust
use lib_q_core::{Algorithm, KemContext, KemPublicKey, KemSecretKey};
use lib_q_hpke::HpkeContext;
use libq::LibQCryptoProvider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create HPKE context (umbrella `lib-q` crate, Rust name `libq`)
    let provider = Box::new(LibQCryptoProvider::new()?);
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());
    
    // Encrypt message
    let message = b"Hello, HPKE!";
    let (encapsulated_key, ciphertext) = hpke_ctx.seal(
        &recipient_pk,
        b"application-info",
        b"additional-data",
        message,
    )?;
    
    // Decrypt message
    let decrypted = hpke_ctx.open(
        &encapsulated_key,
        &recipient_sk,
        b"application-info",
        b"additional-data",
        &ciphertext,
    )?;
    
    assert_eq!(decrypted, message);
    Ok(())
}
```

## HPKE Modes

### Base Mode
Standard HPKE without additional authentication.

```rust
let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"session-info")?;
let ciphertext = sender_ctx.seal(b"aad", message)?;
```

### PSK Mode
Pre-shared key authentication.

```rust
let psk = b"shared-secret-key";
let psk_id = b"psk-identifier";
let mut sender_ctx = hpke_ctx.setup_sender_psk(
    &recipient_pk,
    b"session-info",
    psk,
    psk_id,
)?;
```

### Auth Mode
Sender authentication using asymmetric keys.

```rust
let mut sender_ctx = hpke_ctx.setup_sender_auth(
    &recipient_pk,
    b"session-info",
    &sender_sk,
    &sender_pk,
)?;
```

### AuthPSK Mode
Combined PSK and sender authentication.

```rust
let mut sender_ctx = hpke_ctx.setup_sender_auth_psk(
    &recipient_pk,
    b"session-info",
    psk,
    psk_id,
    &sender_sk,
    &sender_pk,
)?;
```

### PSK / AuthPSK wire format

For PSK and AuthPSK modes, the default is [`HpkePskWireFormat::Rfc9180`](src/types.rs) (RFC 9180 on-the-wire layout). Both peers may set [`HpkePskWireFormat::LibQCommitmentSuffix`](src/types.rs) with [`HpkeContext::set_psk_wire_format`](src/lib.rs) to reject wrong `(psk, psk_id)` or a mismatched primary KEM ciphertext before decapsulation; that suffix is **not** interoperable with strict third-party RFC 9180 implementations.

## Cargo features (summary)

| Feature | Purpose |
|---------|---------|
| `std` | Standard library support |
| `alloc` | Required for normal operation (enforced by the crate) |
| `ml-kem` | ML-KEM through `lib-q-kem` (default) |
| `hash` | HKDF hash backends via `lib-q-hash` (default) |
| `saturnin` / `shake256` | AEAD algorithms (defaults) |
| `duplex-sponge-aead` | Duplex-sponge AEAD in `HpkeAead::DuplexSpongeAead` |
| `wasm` | `wasm32` bindings and helpers |
| `secure-rng` | OS-backed RNG where applicable (default) |

See [`Cargo.toml`](Cargo.toml) for the full feature matrix and optional dev dependencies.

## Documentation

- [Architecture overview](../docs/hpke-architecture.md) — workspace-level HPKE design (PQ-only path, PSK wire format, interoperability)
- [API Reference](docs/API_REFERENCE.md) — public API
- [Security Considerations](docs/SECURITY_CONSIDERATIONS.md) — security analysis and best practices
- [Architecture details](docs/ARCHITECTURE.md) — module layout and provider wiring in this crate

## Testing

The implementation includes comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run specific test suites
cargo test --test psk_mode_comprehensive_tests
cargo test --test authpsk_mode_comprehensive_tests
cargo test --test security_validation_comprehensive_tests
```

## Wire sizes (KEM)

Public key and encapsulated ciphertext lengths match [`HpkeKem`](src/types.rs) (`public_key_len` / `enc_len`):

| KEM | NIST category (approx.) | Public key | Encapsulated ciphertext |
|-----|-------------------------|------------|-------------------------|
| ML-KEM-512 | 1 | 800 B | 768 B |
| ML-KEM-768 | 3 | 1184 B | 1088 B |
| ML-KEM-1024 | 5 | 1568 B | 1568 B |

AEAD ciphertext expansion is plaintext length plus the AEAD tag (e.g. 32 bytes for Saturnin-256); see `HpkeAead::tag_len` in `src/types.rs`.

## Dependencies

- `lib-q-core` - Core cryptographic types and interfaces
- `lib-q-kem` - Key encapsulation mechanism implementations
- `lib-q-hash` - Hash function implementations
- `lib-q-aead` - Authenticated encryption implementations
- `lib-q` (Rust import `libq`) — `LibQCryptoProvider` for demos; production integrations may use narrower providers

## License

This project is licensed under the same terms as the lib-q project.
