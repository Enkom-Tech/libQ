# Memory architecture

## Scope

Memory behavior in lib-Q is **not uniform across the workspace**. Crates such as `lib-q-hpke`, `lib-q-zkp`, and protocol glue use **`alloc` / `Vec<u8>`** where RFCs or proof objects require variable-length buffers. Core KEM and signature **wire formats** are still fixed by NIST parameter sets (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, CB-KEM, HQC), and hot paths are written to avoid unnecessary allocation where the API allows.

This page describes **design goals and patterns**; for exact buffer sizes and stack behavior, follow the crate you compile (`lib-q-ml-kem`, `lib-q-ml-dsa`, `lib-q-hpke`, etc.) and its `README` / module documentation.

## Design goals

1. **Fixed wire sizes** — Public keys, secret keys, ciphertexts, and signatures match NIST/FIPS byte lengths for the enabled parameter set (see each crate's `constants` or equivalent module).
2. **Secret hygiene** — Sensitive material uses the `zeroize` crate where types are wired for it:
   - **`lib-q-core`** — `KemSecretKey`, `SigSecretKey`, and `AeadKey` implement `Zeroize` and `ZeroizeOnDrop` over heap-backed key bytes ([`lib-q-core/src/traits.rs`](../lib-q-core/src/traits.rs)). Layer-B AEAD semantic decrypt returns verified plaintext as `Zeroizing<Vec<u8>>` in [`DecryptSemanticOutcome::Success`](../lib-q-core/src/aead_semantic.rs).
   - **`lib-q-hpke`** — Labeled key-schedule fields use `SecretBytes` (`Zeroizing<Vec<u8>>`) in [`types.rs`](../lib-q-hpke/src/types.rs). Additional wrappers (`SecureKey`, `SecureBytes`, `SecureStackBuffer`) live in [`security/memory_safety.rs`](../lib-q-hpke/src/security/memory_safety.rs) and are exported from the [`security`](../lib-q-hpke/src/security/mod.rs) module. Algorithm crates may still hold secrets in plain `[u8]` or `Vec<u8>` internally where no wrapper is attached; treat “uses zeroize in the public type” as a per-type guarantee, not a blanket workspace property.
3. **Bounded inputs** — Public APIs validate lengths before operating on caller-supplied slices; maximum message sizes are policy-dependent and documented per crate.
4. **`no_std` vs `std`** — True `no_std` trees require opting out of default features on the crates you depend on; the umbrella `lib-q` crate may still pull `std` through optional integration (see [README.md](../README.md#no_std-embedded-and-webassembly) — *no_std, embedded, and WebAssembly*).

## WebAssembly and host memory

On `wasm32-unknown-unknown`, Rust allocations sit in **linear memory**; freed pages are not cryptographically scrubbed by the host. Bundles that cross the JavaScript boundary may copy secrets into the **JS heap**, where drop hooks in WASM cannot erase them. Integrators should read [wasm-security-model.md](wasm-security-model.md) alongside this page.

## What this repository does **not** guarantee

- **Global “zero heap”** — The workspace is not a single stack-only binary; do not assume absence of `Vec` or allocator use without reading the specific crate.
- **Worst-case stack depth** — Stack usage depends on algorithm, features, and LTO; embedded integrators should measure with their own linker scripts and `-Z emit-stack-sizes` (or vendor tooling) rather than rely on illustrative tables.
- **Residual secret bytes after drop** — `zeroize` clears Rust-visible buffers; it does not pin pages, lock swap, or guarantee that copies (moved stack temporaries, allocator metadata, debug builds) are gone. High-assurance products need platform-specific handling outside this library.

## Further reading

- [entropy-validation.md](entropy-validation.md) — randomness and validation knobs (e.g. CB-KEM provider + `SecurityValidator`).
- [hpke-architecture.md](hpke-architecture.md) — HPKE contexts, `SecretBytes`, and secure key helpers.
- [security.md](security.md) — constant-time scope, secure memory patterns, and limits.
- [wasm-security-model.md](wasm-security-model.md) — WASM linear memory, JS interop, and opaque-handle guidance.
- [SECURITY.md](../SECURITY.md) — threat model and limits.
