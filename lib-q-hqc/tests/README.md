# HQC test suite

Tests for [`lib-q-hqc`](../). Enable features as needed; most integration tests require
`alloc` and a parameter-set feature (`hqc128`, `hqc192`, `hqc256`, or `hqc`).

```bash
cargo test -p lib-q-hqc --features alloc,hqc
```

## Layout

| Category | Files | What they exercise |
|----------|-------|-------------------|
| **KEM integration** | `integration_test.rs` | Full HQC-1/3/5 KEM round-trips (pinned seeds + many varied keypairs), error-correcting code encode/decode, asserted PKE encrypt/decrypt, repeated encaps/decaps |
| **PKE round-trip** | `pke_roundtrip_basic.rs`, `pke_roundtrip_test.rs` | PKE encrypt/decrypt with asserted equality over distinct keypairs |
| **KAT / PRNG** | `nist_kem_kat.rs`, `hardened_dudect_smoke.rs`, `shake256_prng_kat.rs`, `sha3_hqc_kat.rs`, … | Authoritative NIST KEM KAT (`kats/official/`, `pk`/`ct`/`ss`/`sk`); hardened decaps timing smoke |
| **Parameter compliance** | `compliance_parameter_validation.rs`, `compliance/parameter_validation.rs` | Parameter constants vs `lib-q-types::hqc` and specification |
| **SIMD** | `simd_correctness.rs`, `simd_unit_tests.rs`, `simd_infrastructure_test.rs`, `simd_debug_utils/` | AVX2 vs portable bit-exact equivalence |
| **DRBG / AES** | `aes_ctr_drbg_test.rs`, `aes_verification.rs`, `bearssl_aes_verification.rs`, `bearssl_vs_rust_aes_comparison.rs`, `drbg_interop_tests.rs`, `prng_compatibility_test.rs` | DRBG backends and AES interoperability |
| **Vectors / algebra** | `vect_mul_equivalence.rs`, `vect_set_random_analysis.rs`, `test_direct_h_storage.rs`, `message_conversion_test.rs` | Polynomial / vector operations |
| **Cross-checks** | `hqc_keygen_cross_compatibility_test.rs`, `verify_public_key_format.rs`, `official_specification_verification_test.rs`, `compliance/cross_implementation.rs` | Key formats and cross-implementation checks |
| **Provider / smoke** | `basic_functionality_test.rs`, `wasm_smoke.rs` | libQ provider wiring, WASM compile smoke |
| **Stress / diagnostics** | `comprehensive_validation.rs`, `comprehensive_failure_analysis_test.rs`, `noise_diagnostic_test.rs`, `random_keypair_failure_test.rs`, `rm_block_analysis_test.rs`, `reference_analysis.rs` | `#[ignore]`d stress checks (e.g. `random_keypair_failure_test` asserts zero failures over large OS-random batches) and debugging aids; run on demand, not default CI gates |

Historical debug harnesses are under [`archive/`](archive/README.md) and are not run in CI.

## CI coverage

Workspace CI (`algorithm-tests` / `simd-debug-tests`) runs HQC with `alloc,hqc128,simd-avx2`
and SIMD unit / cross-implementation checks. See
[docs/audit-package/README.md](../docs/audit-package/README.md) for what is and is not
verified.

## Feature flags

| Feature | Purpose |
|---------|---------|
| `alloc` | Required for most integration tests |
| `hqc128` / `hqc192` / `hqc256` | Parameter set under test |
| `hqc` | All parameter sets |
| `simd-avx2` | SIMD paths (with portable fallback) |

## Contributing tests

- Match existing file naming (`*_test.rs` or descriptive `snake_case.rs`).
- Gate parameter-specific tests with the appropriate `hqc*` feature.
- Do not add marketing claims to test output; assert behaviour only.
- Prefer deterministic, varied seeds for always-on round-trip gates so they stay
  reproducible. Reserve `#[ignore]` for genuinely slow stress runs, and never rationalize
  a decode failure as "expected" — HQC's spec decryption-failure rate is negligible, so a
  mismatch is a correctness regression.
