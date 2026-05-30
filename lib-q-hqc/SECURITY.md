# Security assurance (`lib-q-hqc`)

Security posture, verification scope, and known limits for the HQC KEM crate. For an
evidence-based assessment with open findings, see
[docs/audit-package/README.md](docs/audit-package/README.md).

**Status:** not production-ready. Randomized KEM/PKE round-trip correctness, byte-exact
NIST KEM KAT (F3), and internal wall-clock self-certification (F4) are verified in-repo
(see [What is verified](#what-is-verified-in-this-repository)); accredited lab evaluation
and instrumented power/EM TVLA remain out of scope.

## Specification alignment

The implementation targets the [NIST HQC specification (October 2024)](https://pqc-hqc.org/doc/hqc-specification_2024-10-30.pdf).
Cryptographic object sizes are defined in [`lib-q-types::hqc`](../lib-q-types/src/hqc.rs)
and mirrored in `params_correct`:

| Set | N1 | N2 | OMEGA | DELTA | Public key (B) | Ciphertext (B) |
|-----|----|----|-------|-------|----------------|----------------|
| HQC-128 | 46 | 384 | 66 | 15 | 2241 | 4433 |
| HQC-192 | 56 | 640 | 103 | 16 | 4522 | 8978 |
| HQC-256 | 90 | 640 | 134 | 29 | 7245 | 14421 |

Parameter validation tests in `tests/compliance_parameter_validation.rs` and
`tests/compliance/parameter_validation.rs` check these constants against the
specification.

## What is verified in this repository

| Area | Evidence |
|------|----------|
| KEM round-trip (pinned seeds) | `tests/integration_test.rs` — HQC-1/3/5 shared-secret match with fixed key and encapsulation PRNG seeds |
| KEM round-trip (varied keys, all sets) | `tests/integration_test.rs::test_kem_roundtrip_varied_keys_all_params` — many independent keypairs per parameter set |
| PKE round-trip (varied keys) | `tests/integration_test.rs::test_pke_integration`, `tests/pke_roundtrip_basic.rs` — distinct keypairs, asserted equality |
| Randomized decapsulation (stress) | `tests/random_keypair_failure_test.rs` (`#[ignore]`, on demand) — zero failures observed over large OS-random batches |
| Error-correcting codes encode/decode | `src/reed_muller.rs`, `src/reed_solomon.rs`, `src/concatenated_code.rs` unit tests — full N1-byte RM/RS/concatenated round-trip and single-error correction |
| SHAKE256 PRNG | `tests/shake256_prng_kat.rs`, `tests/sha3_hqc_kat.rs` |
| NIST KEM KAT (HQC-128/192/256) | `tests/nist_kem_kat.rs` — byte-exact `pk`/`ct`/`ss`/`sk` (NIST layout) vs `kats/official/`; full `.rsp` sweep; provenance in `kats/official/PROVENANCE.md`; CI `test-hqc` |
| NIST `sk` import/export | `HqcKemSecretKey::to_nist_bytes()` / `from_nist_bytes()` — wire `dk_pke ‖ sigma ‖ ek_pke`; gated in `nist_kem_kat.rs` |
| Hardened decapsulation | Feature `hardened` — `subtle` CT compare/select on implicit rejection; `tests/hardened_dudect_smoke.rs` |
| Internal timing self-cert | `lib-q-sca-test` feature `hqc-hardened` (builds `lib-q-hqc` with `hardened`) — nine wall-clock TVLA targets; CI smoke in `algorithm-tests` |
| SIMD vs portable | `tests/simd_correctness.rs`; CI `simd-debug-tests` |
| Provider / types | `tests/basic_functionality_test.rs` |
| WASM smoke | `tests/wasm_smoke.rs` |

## What is not verified

- **Accredited or instrumented side-channel certification** — internal wall-clock TVLA
  smoke (`hqc-hardened`) is pre-laboratory screening only; no power/EM traces, no
  ~10⁶-trace TVLA, and no independent lab report.

## SIMD

AVX2 paths use bounded `unsafe` with runtime feature detection and bit-exact fallback to
portable code. See `tests/simd_correctness.rs` and [docs/simd-architecture.md](docs/simd-architecture.md).

## Implementation properties

- **Memory safety:** Rust ownership; `zeroize` on sensitive buffers when enabled.
- **Constant-time intent:** Polynomial and decoding paths are written for constant-time
  execution where the specification requires it; this is not a substitute for measurement.
- **Pure Rust:** No C/FFI in the KEM path; auditable Rust only.

## Known limitations

### Side-channel tooling

HQC is wired into [`lib-q-sca-test`](../lib-q-sca-test) via the `hqc-hardened` feature,
which builds `lib-q-hqc` with the `hardened` feature (nine wall-clock targets: keygen /
encapsulate / decapsulate × HQC-128/192/256). Results
are software timing regression evidence only; see
[side-channel self-certification](../docs/sca-self-certification.md) for boundaries vs
accredited evaluation.

### Formal verification

No machine-checked proof (Kani, etc.) ships with this crate. Correctness relies on tests
and manual review.

## Recommendations

**Development**

1. Run `cargo test -p lib-q-hqc --features alloc,hqc` before merging crypto changes.
2. Run Clippy with `-D warnings` on touched code.
3. Run `cargo test -p lib-q-hqc --release --features alloc,hqc,random,bearssl-aes --test nist_kem_kat` after KEM/PKE changes.
4. Run `cargo test -p lib-q-sca-test --features hqc-hardened` after timing-sensitive changes.

**Deployment**

Do not use this crate for production confidentiality without your own security review
and any required external evaluation. Third-party cryptographic audit is recommended for
high-assurance deployments regardless.

## Reporting security issues

Follow the workspace [SECURITY.md](../SECURITY.md) policy (private disclosure via
GitHub security advisories or **github@enkom.dev**).

## References

- [NIST PQC project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [HQC specification (October 2024)](https://pqc-hqc.org/doc/hqc-specification_2024-10-30.pdf)
- [Internal assessment](docs/audit-package/README.md)
