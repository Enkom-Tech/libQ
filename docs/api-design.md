# lib-Q API design

This document summarizes how the workspace exposes cryptography. It is **descriptive**, not a duplicate of `rustdoc`—prefer `cargo doc -p <crate> --open` for signatures and error types.

## Layers

1. **Algorithm crates** (`lib-q-ml-kem`, `lib-q-ml-dsa`, `lib-q-slh-dsa`, `lib-q-fn-dsa`, `lib-q-cb-kem`, `lib-q-hqc`, …) — NIST-oriented implementations, often `no_std`+`alloc` capable, minimal dependencies. Additional crates cover symmetric primitives (for example `lib-q-saturnin`, `lib-q-romulus`), hashes/Keccak-family digests, and research or protocol-building pieces (`lib-q-ring-sig`, `lib-q-lattice-zkp`, …). Large proving stacks (`lib-q-stark-*`, `lib-q-plonky*`) sit alongside these as infrastructure, usually behind optional `lib-q` features.
2. **Facade / integration crates** (`lib-q-kem`, `lib-q-sig`, `lib-q-hpke`, `lib-q-hash`, `lib-q-aead`, `lib-q-random`, `lib-q-zkp`, …) — provider wiring, feature-gated algorithms, ergonomic entry points.
3. **Core** (`lib-q-core`) — `KemContext`, `SignatureContext`, `HashContext`, `AeadContext`, `CryptoProvider`, validation, and WASM helpers where built. It re-exports `Algorithm` (and related identifiers) from `lib-q-types` for convenience; depend on **`lib-q-types`** directly when you want algorithm names without pulling core into a leaf crate.
4. **Umbrella** (`lib-q`) — feature-gated re-exports for applications that want one dependency line; not the only supported integration style (see [README.md](../README.md)). Zero-knowledge / STARK surfaces are optional (`zkp`, `zkp-plonky*`, …) on this crate.

Identifiers for policy and registry (`Algorithm`, `AlgorithmCategory`, `SecurityLevel`) live in **`lib-q-types`** so low-level crates can name algorithms without depending on all of `lib-q-core`.

## Naming and errors

- Operations return `lib_q_core::Result` / crate-local `Result` types with structured errors (`InvalidKeySize`, `InvalidAlgorithm`, …) rather than stringly-typed failures.
- HPKE uses `lib_q_hpke::Result` / `HpkeError`; ZKP uses `lib_q_zkp` error enums—check each crate.
- AEAD decryption has a semantic layer (`AeadDecryptSemantic`) used by some providers; the umbrella `libq::aead::context()` path stays on plain `Result` until you opt into semantic outcomes from a concrete AEAD crate (see [adr/003-aead-decrypt-layers.md](adr/003-aead-decrypt-layers.md)).

## Typical usage patterns

The Rust examples import `Algorithm` from **`lib-q-types`**. That requires a **direct** `lib-q-types` entry in your crate’s `Cargo.toml` (transitive dependencies are not in scope for `use`). The same type is `lib_q_core::Algorithm` if you depend on core only.

### KEM + core provider (std)

Contexts and provider from **`lib-q-core`**; algorithm enum from **`lib-q-types`** as above.

```rust
use lib_q_core::{KemContext, LibQCryptoProvider};
use lib_q_types::Algorithm;

fn main() -> lib_q_core::Result<()> {
    let mut kem = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let keypair = kem.generate_keypair(Algorithm::MlKem768, None)?;
    let _pk = keypair.public_key();
    let _sk = keypair.secret_key();
    Ok(())
}
```

### HPKE single-shot seal/open

`HpkeContext::new` / `with_provider` default to an RFC 9180–style suite with **ML-KEM-512** as the HPKE KEM. Recipient keys must match that suite (or call `set_cipher_suite` on `HpkeContext` before `seal` / `open`). Multi-message flows use `setup_sender` / `setup_receiver` and `HpkeSenderContext` / `HpkeReceiverContext`; see [hpke-architecture.md](hpke-architecture.md).

**Interop negotiation:** use `lib_q_hpke::interop` to advertise and deterministically intersect `HpkeCipherSuite`, `HpkeMode`, and PSK wire formats under a chosen `HpkeInteropProfile` (`RfcStrictPq` vs `LibQExtensions`). The result must be copied into your authenticated handshake bytes; see [interoperability.md](interoperability.md).

```rust
use lib_q_core::{KemContext, KemPublicKey, KemSecretKey, LibQCryptoProvider};
use lib_q_hpke::HpkeContext;
use lib_q_types::Algorithm;

fn demo() -> Result<(), Box<dyn std::error::Error>> {
    let mut hpke = HpkeContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let mut kem = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let kp = kem.generate_keypair(Algorithm::MlKem512, None)?;
    let recipient_pk = KemPublicKey::new(kp.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(kp.secret_key().as_bytes().to_vec());

    let msg = b"hello";
    let (encap, ct) = hpke.seal(&recipient_pk, b"info", b"aad", msg)?;
    let out = hpke.open(&encap, &recipient_sk, b"info", b"aad", &ct)?;
    assert_eq!(out, msg);
    Ok(())
}
```

### Signatures

Use **`lib-q-sig`** (ML-DSA / SLH-DSA wiring) or **`lib-q-fn-dsa`** directly for FN-DSA; the umbrella `lib-q` crate aggregates behind features. See each crate’s `README` for the exact feature flags (`ml-dsa`, `slh-dsa`, `fn-dsa`, …).

## What is intentionally **not** in this repo

- A stable `lib_q::simple` façade module as shown in older drafts of this file.
- C ABI or generic TLS/SSH bindings as first-class shipped APIs (integrators build those on top of byte-oriented PQC primitives if their threat model allows hybrid transition).

## Related docs

- [interoperability.md](interoperability.md) — byte-level interop expectations.
- [memory-architecture.md](memory-architecture.md) — allocation and `no_std` notes.
- [hpke-architecture.md](hpke-architecture.md) — HPKE layering.
- [entropy-validation.md](entropy-validation.md) — RNG / validation for selected providers.
- [security.md](security.md) — security posture and review notes.
- [adr/003-aead-decrypt-layers.md](adr/003-aead-decrypt-layers.md) — AEAD decrypt API layers.
