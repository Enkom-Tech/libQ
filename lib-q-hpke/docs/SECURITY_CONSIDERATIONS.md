# Security considerations for lib-q-hpke

This note summarizes how the crate approaches security properties and where to read the real implementation. It is not a substitute for RFC 9180, FIPS 203, or a formal analysis of your deployment.

## Threat model (engineering view)

### Classical and quantum adversaries

- **Confidentiality / integrity** for HPKE payloads depend on the chosen **KEM** (`HpkeKem`), **KDF** (`HpkeKdf`), and **AEAD** (`HpkeAead`) in [`HpkeCipherSuite`](../src/types.rs). The default provider path uses **ML-KEM** and PQ-friendly hashes/AEADs (see [`PostQuantumProvider`](../src/providers/post_quantum.rs)).
- **Quantum-capable adversaries** are in scope for the stated ML-KEM / SHAKE / SHA3 building blocks; concrete bit-strength follows parameter set choice (ML-KEM-512 / 768 / 1024).

### Side-channel and implementation attacks

- The codebase aims for **constant-time primitives** where applicable (`security/constant_time.rs`), **zeroization** of sensitive buffers (`zeroize`, `SecretBytes`, secure-memory helpers in `security/memory_safety.rs`), and **structured validation** (`security/validation.rs`, `security/policy.rs`).
- Rust’s memory model rules out typical C-style memory corruption in safe code; `lib-q-hpke` uses `#![forbid(unsafe_code)]`.

## Properties by mechanism

### Confidentiality

- Payload secrecy is provided by the HPKE key schedule plus the negotiated **AEAD** (for example Saturnin-256 or SHAKE256 AEAD when selected in the suite). **Export-only** (`HpkeAead::Export`) does not encrypt application messages; it exists for exporter-secret usage.

### Authenticity and integrity

- **AEAD** supplies ciphertext integrity for application data once keys are established.
- **PSK / AuthPSK** bind an additional secret or sender KEM keys into the schedule per RFC 9180 mode rules; see `hpke_core.rs` and mode tests under `tests/`.
- **Auth / AuthPSK sender binding:** before encapsulation, the implementation checks that the sender’s secret key matches the supplied public key for the active ML-KEM parameter set (derive/verify path in `hpke_core.rs`). Reject inconsistent sender material rather than mixing secrets.
- **PSK wire format:** [`HpkePskWireFormat::Rfc9180`](../src/types.rs) matches RFC 9180 on the wire. [`LibQCommitmentSuffix`](../src/types.rs) adds a libQ-only commitment so peers can reject inconsistent `(psk, psk_id)` or primary ciphertext **before** decapsulation when both sides opt in (`HpkeContext::set_psk_wire_format`). That format is **not** interoperable with strict third-party RFC 9180 stacks.

### Key-binding (MAL-BIND / LEAK-BIND) is out of scope for Base-mode ML-KEM

- `key_schedule` (`hpke_core.rs`) derives `secret`/`key`/`base_nonce`/`exp` from the KEM's raw shared secret plus `mode || psk_id_hash || info_hash`; it does **not** independently mix the recipient's public key into that derivation. This matches RFC 9180 exactly — the RFC relies on the **KEM itself** to bind the recipient key (DHKEM's `Encap`/`Decap` compute the shared secret as `ExtractAndExpand(dh, enc || pkRm[ || pkSm])`, so `pkRm` is already inside `kem_context`).
- `HpkeKem` only offers ML-KEM (512/768/1024), and `lib-q-kem`'s ML-KEM `encapsulate`/`decapsulate` (`lib-q-kem/src/ml_kem.rs:118-185`) call the plain FIPS-203 `EncapsulationKey::encapsulate` / `DecapsulationKey::decapsulate` with no extra binding step. Unlike DHKEM, ML-KEM's shared secret is not proven bound to a specific `(pk, sk)` pair — the literature names this gap MAL-BIND-K-PK / LEAK-BIND-K-PK (Cremers, Dax, Medinger, "Keeping Up with the KEMs"; and Djimnaibeye et al., "NAIBI", eprint 2026/1525, §1, which states FIPS 203's `seed` key-encoding arm restores the *ciphertext* axis but not the *public-key* axis).
- Net effect: a party that accepts an ML-KEM public key from an untrusted source (e.g. a multi-recipient, certified-delivery, or anonymous-membership protocol layered on this crate) gets no guarantee that one ciphertext decapsulates to the same derived key under two different, adversarially chosen `(pk, sk)` pairs. `grep -rniE 'mal-?bind|leak-?bind|key-?committ' --include=*.rs lib-q-ml-kem lib-q-kem lib-q-hpke` returns 0 lines: there is no code, test, or (until now) documentation of this property in the crate.
- No in-repo consumer is affected today: `lib-q-hpke` is reachable only from the `lib-q` facade crate as an optional re-exported feature (`lib-q/Cargo.toml`, `hpke` feature), with zero call sites in `lib-q/src`, so no internal construction currently relies on decapsulation binding. If you build one on top of this crate, mix the recipient public key (or its hash) into `info`/AAD yourself, or use a committing KEM — this crate does not do it for you.

### Forward secrecy

- Forward secrecy properties follow RFC 9180 and how you use HPKE (ephemeral sender KEM, recipient static vs ephemeral keys, rekeying). The crate does not change the protocol’s FS story; your key lifetimes and deployment do.

## Implementation notes

### Constant-time helpers

Utilities such as `constant_time_eq`, `constant_time_select`, and `constant_time_copy` live in [`security/constant_time.rs`](../src/security/constant_time.rs). Prefer these over naive byte comparisons when comparing secrets in new code paths.

### Zeroization

- Schedule secrets in contexts use [`SecretBytes`](../src/types.rs) (`Zeroizing<Vec<u8>>`).
- Key material on the HPKE entry points (`setup_sender`/`setup_receiver`/`seal`/`open`) is
  `lib_q_core::KemPublicKey`/`KemSecretKey`. It is length-checked before use: `hpke_core` rejects a
  recipient public key whose length does not match the cipher suite's KEM, and the KEM provider
  re-validates public and secret keys ahead of every encapsulate/decapsulate.
- `KemSecretKey` implements `Zeroize`. Wrap long-lived key material in `Zeroizing<_>`, or call
  `.zeroize()` on it once you are finished with it, so its buffer is scrubbed at a point you
  control.
- The crate does not define its own HPKE key wrapper types; use the `lib_q_core` KEM key types
  directly.
- [`SecureKey` / `SecureBytes`](../src/security/memory_safety.rs) provide additional wrappers for application-side secret handling.

### Validation

- [`validate_kem_key`](../src/security/validation.rs) enforces expected ML-KEM wire lengths for `HpkeKem`.
- Broader policy hooks live under `security/policy.rs`.

### Randomness

- `HpkeContext::new` defaults to [`EntropyCryptoRng`](../src/security/prng.rs) for setup and single-shot `seal` when the `secure-rng` feature is enabled (OS-backed entropy via `lib-q-random`). Tests may call `HpkeContext::set_rng` with a deterministic `CryptoRng` implementation.

### Auth mode helpers in `PostQuantumProvider`

Auth / AuthPSK encapsulation paths use RFC 9180–style KEM authentication plus internal helpers in `post_quantum.rs` (for example `create_auth_tag` / `verify_auth_tag` over SHA3-256 of `shared_secret || sender_pk || encapsulated_key`, and related commitment helpers). **Do not treat this document as the normative spec**—use RFC 9180 and the source for ordering and exact inputs.

## Errors and observability

- Many HPKE failures surface to callers as `lib_q_core::Error` (often `InternalError`) after `From<HpkeError>` conversion (`src/error.rs`). Logging should avoid printing raw key material even when `Debug` redacts some structs.

## Testing and assurance

- Conformance and regression coverage live in `lib-q-hpke/tests/` (for example `rfc9180_compliance_tests.rs`, mode-specific suites, `auth_encap_validation_tests.rs`).
- Negotiation fixtures and provenance are under `tests/fixtures/` (see `tests/fixtures/README.md`).
- Randomized property tests are under `tests/randomized_property_tests.rs`. There is currently no fuzz harness (`fuzz/` directory) for this crate; do not read the security module list as fuzz coverage.
- Run `cargo test -p lib-q-hpke` (with the features you ship) as part of your release process.

## Operational checklist

1. Pick `HpkeCipherSuite` explicitly when not using defaults; keep KEM sizes aligned with `HpkeKem` for all parties.
2. Run `negotiate_hpke_capabilities` (or an equivalent) under a chosen `HpkeInteropProfile`, and bind the serialized inputs into an authenticated application transcript.
3. For PSK modes, agree on **`HpkePskWireFormat`** out of band; default is RFC 9180.
4. Enable **`duplex-sponge-aead`** only when every peer supports `HpkeAead::DuplexSpongeAead` and you have analyzed that AEAD’s properties for your threat model.
5. Rekey or rotate before sequence numbers exhaust policy (`HpkeContextState::NeedsRekey`).
6. If you build a multi-recipient, certified-delivery, or membership-disclosure protocol on this crate, do not assume decapsulation is bound to a specific public key — ML-KEM (the crate's only KEM) does not provide MAL-BIND-K-PK / LEAK-BIND-K-PK guarantees (see "Key-binding" above). Mix the recipient public key (or its hash) into `info` or AAD yourself if your threat model needs that.

## Related reading

- [hpke-architecture.md](../../docs/hpke-architecture.md) — workspace HPKE architecture
- [ARCHITECTURE.md](ARCHITECTURE.md) — crate module map
- [API_REFERENCE.md](API_REFERENCE.md) — public API summary
- Djimnaibeye, Sow, Hassan, Tieudjo, Tchawa, "NAIBI: Binding Reconciliation KEMs and Ephemeral Key Agreement over Non-Split Commutative Algebras" ([eprint 2026/1525](https://eprint.iacr.org/2026/1525)) — source for the MAL-BIND-K-PK terminology and the claim that ML-KEM lacks it
