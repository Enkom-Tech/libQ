# lib-Q API design

This document summarizes how the workspace exposes cryptography. It is **descriptive**, not a duplicate of `rustdoc`—prefer `cargo doc -p <crate> --open` for signatures and error types.

## Layers

1. **Algorithm crates** (`lib-q-ml-kem`, `lib-q-ml-dsa`, `lib-q-slh-dsa`, `lib-q-fn-dsa`, `lib-q-cb-kem`, `lib-q-hqc`, …) — NIST-oriented implementations, often `no_std`+`alloc` capable, minimal dependencies.
2. **Facade / integration crates** (`lib-q-kem`, `lib-q-sig`, `lib-q-hpke`, `lib-q-hash`, …) — provider wiring, feature-gated algorithms, ergonomic entry points.
3. **Core** (`lib-q-core`) — `Algorithm`, `KemContext`, `SignatureContext`, `CryptoProvider`, validation, and WASM helpers where built.
4. **Umbrella** (`lib-q`) — feature-gated re-exports for applications that want one dependency line; not the only supported integration style (see [README.md](../README.md)).

Identifiers for policy and registry (`Algorithm`, `AlgorithmCategory`) live in **`lib-q-types`** so low-level crates can name algorithms without depending on all of `lib-q-core`.

## Naming and errors

- Operations return `lib_q_core::Result` / crate-local `Result` types with structured errors (`InvalidKeySize`, `InvalidAlgorithm`, …) rather than stringly-typed failures.
- HPKE uses `lib_q_hpke::Result` / `HpkeError`; ZKP uses `lib_q_zkp` error enums—check each crate.

## Typical usage patterns

### KEM + core provider (std)

```rust
use lib_q_core::{Algorithm, KemContext};
use lib_q_core::providers::libq_provider::LibQCryptoProvider;

fn main() -> lib_q_core::Result<()> {
    let mut kem = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let keypair = kem.generate_keypair(Algorithm::MlKem768, None)?;
    let _pk = keypair.public_key();
    let _sk = keypair.secret_key();
    Ok(())
}
```

### HPKE single-shot seal/open

```rust
use lib_q_core::{Algorithm, KemContext, KemPublicKey, KemSecretKey};
use lib_q_core::providers::libq_provider::LibQCryptoProvider;
use lib_q_hpke::HpkeContext;

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
