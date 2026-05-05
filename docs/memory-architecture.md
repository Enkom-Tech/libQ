# Memory architecture

## Scope

Memory behavior in lib-Q is **not uniform across the workspace**. Crates such as `lib-q-hpke`, `lib-q-zkp`, and protocol glue use **`alloc` / `Vec<u8>`** where RFCs or proof objects require variable-length buffers. Core KEM and signature **wire formats** are still fixed by NIST parameter sets (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, CB-KEM, HQC), and hot paths are written to avoid unnecessary allocation where the API allows.

This page describes **design goals and patterns**; for exact buffer sizes and stack behavior, follow the crate you compile (`lib-q-ml-kem`, `lib-q-ml-dsa`, `lib-q-hpke`, etc.) and its `README` / module documentation.

## Design goals

1. **Fixed wire sizes** — Public keys, secret keys, ciphertexts, and signatures match NIST/FIPS byte lengths for the enabled parameter set (see each crate’s `constants` or equivalent module).
2. **Secret hygiene** — Sensitive byte arrays use `zeroize` (or crate-local secure buffers) where types support it; see [`lib-q-hpke` security/memory](../lib-q-hpke/src/security/) for HPKE-specific helpers such as `SecureKey`.
3. **Bounded inputs** — Public APIs validate lengths before operating on caller-supplied slices; maximum message sizes are policy-dependent and documented per crate.
4. **`no_std` vs `std`** — True `no_std` trees require opting out of default features on the crates you depend on; the umbrella `lib-q` crate may still pull `std` through optional integration (see [README.md](../README.md) *no_std, embedded, and WebAssembly*).

## What this repository does **not** guarantee

- **Global “zero heap”** — The workspace is not a single stack-only binary; do not assume absence of `Vec` or allocator use without reading the specific crate.
- **Worst-case stack depth** — Stack usage depends on algorithm, features, and LTO; embedded integrators should measure with their own linker scripts and `-Z emit-stack-sizes` (or vendor tooling) rather than rely on illustrative tables.

## Further reading

- [entropy-validation.md](entropy-validation.md) — randomness and validation knobs (e.g. CB-KEM provider + `SecurityValidator`).
- [hpke-architecture.md](hpke-architecture.md) — HPKE contexts and secure key helpers.
- [SECURITY.md](../SECURITY.md) — threat model and limits.
