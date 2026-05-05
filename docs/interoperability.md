# Interoperability

## What “interop” means here

lib-Q targets **NIST post-quantum** algorithms and **SHA-3–family** XOFs/hashes with **Saturnin / SHAKE-centered** symmetric options (see [SECURITY.md](../SECURITY.md)). Interoperability in this repository means:

1. **Canonical byte formats** — Keys, signatures, and ciphertexts match NIST/FIPS and RFC-defined encodings for the algorithms you enable (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, CB-KEM, HQC, HPKE per [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)).
2. **Cross-crate consistency** — `lib-q-types` algorithm IDs and `lib-q-core` provider/context APIs keep naming aligned across KEM, signature, hash, and AEAD crates.
3. **Test vectors** — KATs, ACVP-style harnesses, and cross-implementation checks live in algorithm crates (for example ML-DSA: [lib-q-ml-dsa/docs/INTEROPERABILITY.md](../lib-q-ml-dsa/docs/INTEROPERABILITY.md)).

There is **no** maintained compatibility shim for **classical** public-key ecosystems (RSA/ECC/X25519 TLS cipher suites, libsodium `crypto_box`, OpenSSL EVP stacks, or WireGuard’s Curve25519) as a security mechanism—those conflict with the project’s PQC-first policy. Building bridges to legacy protocols is an **integrator responsibility** outside this repo.

## Serialization

- **Primary on-the-wire form**: raw bytes (`[u8]` / `Vec<u8>`) as produced by keypair, sign, encapsulate, and HPKE APIs.
- **Serde / WASM**: enabled per crate via features (for example `lib-q-types` / `lib-q-core` `serde`, `wasm`); see each crate’s `Cargo.toml` and `README`.

## HPKE

HPKE interop follows **RFC 9180** with lib-Q’s **PQ-only** KEM and KDF/AEAD catalog (`lib-q-hpke`); see [hpke-architecture.md](hpke-architecture.md) and [lib-q-hpke/docs/API_REFERENCE.md](../lib-q-hpke/docs/API_REFERENCE.md).

## Where to look next

| Topic | Location |
|-------|----------|
| ML-DSA encoding & external vectors | [lib-q-ml-dsa/docs/INTEROPERABILITY.md](../lib-q-ml-dsa/docs/INTEROPERABILITY.md) |
| FN-DSA KAT / verification | [lib-q-fn-dsa/docs/KAT_VERIFICATION.md](../lib-q-fn-dsa/docs/KAT_VERIFICATION.md) |
| HPKE details | [hpke-architecture.md](hpke-architecture.md), `lib-q-hpke/README.md` |
| Workspace layout | [README.md](../README.md) |
