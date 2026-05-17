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

### Profiles (PQ HPKE)

Integrators should pick an explicit **interop profile** before exchanging bytes:

| Profile | Meaning | PSK / AuthPSK wire | Algorithm IDs |
|--------|---------|-------------------|----------------|
| **RfcStrictPq** | RFC 9180 schedule; default PSK encapsulation matches RFC 9180. | [`HpkePskWireFormat::Rfc9180`](../lib-q-hpke/src/types.rs) only in this profile’s negotiation matrix. | ML-KEM + HKDF catalog from `HpkeKem` / `HpkeKdf`; AEAD IDs are lib-Q–assigned where not yet on an IANA registry—treat third-party interop as **profile-gated**, not “generic RFC 9180 DHKEM”. |
| **LibQExtensions** | Same RFC schedule where applicable, plus lib-Q–specific wire and algorithms. | Optional [`HpkePskWireFormat::LibQCommitmentSuffix`](../lib-q-hpke/src/types.rs) (bilateral opt-in). | Includes non-IANA AEAD such as duplex-sponge (`duplex-sponge-aead` feature); document `LIBQ_HPKE_INTEROP_PROFILE_DOC` (`CARGO_PKG_VERSION`) alongside your on-wire version. |

Deterministic suite selection lives in `lib_q_hpke::interop` (`HpkeCapabilities`, `negotiate_hpke_capabilities`). Bind the serialized capability bytes into an **application-authenticated** transcript (handshake, MLS, or your own MAC’d blob); the crate does not provide transport security.

### Mode × suite matrix (representative)

Rows use shorthand `KEM/KDF/AEAD`. Columns: **cross_release** (stable within documented semver for that cell), **third_party** (possible only with a matching profile-aware peer), **libq_only**, **stability** (`stable` vs `experimental` for algorithm IDs on the wire).

| Mode | Suite (example) | PSK wire | `duplex-sponge-aead` | cross_release | third_party | libq_only | stability |
|------|-----------------|----------|----------------------|----------------|-------------|-----------|-----------|
| Base | ML-KEM-512 / HKDF-SHAKE256 / Saturnin-256 | n/a | off | yes | profile-gated | no | stable (suite IDs as shipped) |
| Psk | same | Rfc9180 | off | yes | profile-gated | no | stable |
| Auth / AuthPsk | same | Rfc9180 | off | yes | profile-gated | no | stable; sender `sk`/`pk` binding is enforced before encapsulation |
| Psk / AuthPsk | same | LibQCommitmentSuffix | off | yes | no | yes | experimental wire |
| Base / Psk / … | same | any | duplex AEAD on | feature-gated | no | yes | experimental unless/until IDs are standardized and aliased |

Frozen negotiation fixtures for CI live under [`lib-q-hpke/tests/fixtures/`](../lib-q-hpke/tests/fixtures/README.md).

## Where to look next

| Topic | Location |
|-------|----------|
| ML-DSA encoding & external vectors | [lib-q-ml-dsa/docs/INTEROPERABILITY.md](../lib-q-ml-dsa/docs/INTEROPERABILITY.md) |
| FN-DSA KAT / verification | [lib-q-fn-dsa/docs/KAT_VERIFICATION.md](../lib-q-fn-dsa/docs/KAT_VERIFICATION.md) |
| HPKE details | [hpke-architecture.md](hpke-architecture.md), `lib-q-hpke/README.md` |
| Workspace layout | [README.md](../README.md) |
