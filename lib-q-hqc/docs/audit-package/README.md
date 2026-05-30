# HQC implementation assessment

This is an **internal engineering assessment** of [`lib-q-hqc`](../../). It records
what is verifiable from the source, tests, and CI in this repository, and the open
items that block a production-readiness claim. It is not an independent audit and
confers no certification. No accredited laboratory has evaluated this crate; no
third party has reviewed it unless stated in a signed release note.

The assessment is intentionally conservative: where a claim could not be verified
from artifacts in this repository, it is listed as an open item rather than asserted.

## Summary

`lib-q-hqc` is a pure-Rust HQC KEM (HQC-128/192/256) with portable and optional
AVX2 paths. Core building blocks (Reed–Solomon, Reed–Muller, concatenated code,
SHAKE256 PRNG, PKE, KEM) are implemented and exercised by tests. Randomized
encrypt/decrypt and encapsulate/decapsulate round-trips are verified across all
parameter sets on both the portable and AVX2 paths (see [Verified facts](#verified-facts)
and resolved findings F1–F4). **The crate is not production-ready**: byte-exact KEM KAT
(F3) and internal wall-clock self-certification (F4) are closed in-repo, but accredited
lab evaluation, instrumented power/EM TVLA, and team acceptance remain out of scope.

## Verified facts

The following are confirmed by running the tests in this repository and by reading
[`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml).

| Item | Evidence | Notes |
|------|----------|-------|
| KEM round-trip on fixed seeds | `tests/integration_test.rs` — `test_full_hqc1/3/5_integration`, `test_multiple_kem_operations` (pass) | Shared secrets match for HQC-1/3/5 using a fixed NIST KAT key seed and fixed SHAKE256 encapsulation PRNG seeds |
| KEM round-trip on varied keys | `tests/integration_test.rs` — `test_kem_roundtrip_varied_keys_all_params` (pass) | Many independent keypairs per parameter set; deterministic varied seeds |
| PKE round-trip on varied keys | `tests/integration_test.rs` — `test_pke_integration`; `tests/pke_roundtrip_basic.rs` (pass) | Distinct keypairs, asserted message equality |
| Error-correcting code round-trip | `src/reed_muller.rs`, `src/reed_solomon.rs`, `src/concatenated_code.rs` unit tests (pass) | Full N1-byte RM/RS/concatenated encode+decode and single-error correction |
| Provider / type integration | `tests/basic_functionality_test.rs` (pass) | libQ provider wiring and type compilation |
| SIMD equivalence to portable | CI `simd-debug-tests` runs `simd_unit_tests` and `cross_implementation`; `tests/simd_correctness.rs` | AVX2 paths checked for bit-exact equivalence under `RUST_SIMD_DEBUG=1` |
| SHAKE256 PRNG KAT | `tests/shake256_prng_kat.rs`, `tests/sha3_hqc_kat.rs` | PRNG output compared against reference values |
| NIST KEM KAT (all vectors) | `tests/nist_kem_kat.rs` — `hqc*_kat_count0`, `hqc*_kat_all` (pass, non-ignored) | Byte-exact `pk`/`ct`/`ss`/`sk` (NIST layout) vs `kats/official/hqc-{1,3,5}/PQCkemKAT_*.rsp`; SHAKE/XOF KEM flow; provenance pinned in `kats/official/PROVENANCE.md`; CI `test-hqc` |
| Hardened decapsulation | `lib-q-hqc` feature `hardened`; `tests/hardened_dudect_smoke.rs` | `subtle` CT implicit-rejection path; dudect-style smoke in CI `algorithm-tests` |
| Internal timing self-cert (F4) | `lib-q-sca-test` feature `hqc-hardened` (hardened build); nine targets in [`docs/sca-self-certification.md`](../../../docs/sca-self-certification.md) | Wall-clock fixed-vs-random TVLA smoke only; not accredited certification |
| Platform builds | CI `wasm-validation`, `wasm-bindgen-smoke`, cross-platform matrix | Builds for `wasm32-unknown-unknown`; no_std / embedded targets per crate config |

CI exercises HQC under `algorithm-tests` (`alloc,hqc128,simd-avx2`, security and SIMD
test toggles, parameter sets `hqc128,hqc192,hqc256`) and the SIMD debug job on
non-PR events.

## Findings

F1 and F2 were investigated and resolved in an earlier pass. F3 and F4 are closed at the
internal-evidence level in this pass; production-readiness and external certification are
still not claimed.

### F1 — Randomized KEM/PKE decapsulation reliability (resolved)

Original concern: the KEM round-trip was demonstrated only with pinned seeds, the
randomized PKE round-trip tests were `#[ignore]`d for "probabilistic failures," and an
in-code comment claimed OS-backed keys could "hit rare PKE decode mismatches."

Investigation: a decapsulation mismatch under HQC's implicit-rejection construction
occurs exactly when PKE decryption fails to recover the message. The current PKE path
was exercised over large random-key batches on both the portable schoolbook multiply
and the AVX2 multiply:

- ~62,000 random-key round-trips total (≈1,400 portable + ≈900 + 60,000 AVX2),
  spanning HQC-128/192/256 — **zero** decapsulation mismatches.
- Measured codeword noise weight averages ~34 % of the block, well inside the
  concatenated-code correction radius.

By the rule of three, zero failures in ~62,000 trials bounds the observed failure rate
to below ~5×10⁻⁵ at 95 % confidence — inconsistent with the previously assumed
1–2 % rate and consistent with HQC's negligible spec decryption-failure rate. The
earlier behavior had already been corrected in the sampling and `gf2x` reduction paths;
the residual gap was test/documentation debt. Resolution:

- `tests/pke_roundtrip_basic.rs` round-trip tests un-ignored.
- `tests/integration_test.rs::test_pke_integration` now asserts message equality over
  multiple distinct keypairs (previously decrypted without asserting).
- Added `test_kem_roundtrip_varied_keys_all_params` covering many independent keys per
  parameter set.
- Removed the misleading "rare PKE decode mismatches" comments.

### F2 — Reed–Muller message-length limitation (resolved)

Original concern: documentation claimed the Reed–Muller path decoded only 28 of the
46 HQC-128 RS symbols.

Investigation: the full N1-byte RM encode→decode round-trip and single-error correction
both succeed for the complete 46-byte block (`src/reed_muller.rs` unit tests). The
"28-byte" figure was a stale, overly conservative assertion in
`test_reed_muller_error_correction` (it checked `message[0..28]`), not a code limit.
Resolution: that test now asserts the full 46-byte block, and the limitation claim was
removed from `SECURITY.md`.

### F3 — NIST KEM KAT conformance (resolved, bounded)

**Root cause:** Three separate issues blocked byte-exact KAT agreement: (1) public keys
were serialized as `h ‖ s` instead of the wire format `seed_ek ‖ s`; (2) SHA3-256 domain
separators for `H` and `G` were swapped relative to the reference (`H` → domain 1,
`G` → domain 0); (3) authoritative vectors now live under `kats/official/` (NIST `.req` seeds, `.rsp`
for Oct 2024 parameters).

**Evidence:** `tests/nist_kem_kat.rs` runs non-ignored `hqc128/192/256_kat_count0` and
`hqc*_kat_all` against `kats/official/hqc-{1,3,5}/PQCkemKAT_*.rsp`, asserting byte-exact
`pk`/`ct`/`ss`/`sk` (NIST `dk_pke ‖ sigma ‖ ek_pke`), decapsulated shared secret, and
`from_nist_bytes` round-trip. Encapsulation uses `m = seed[32..48]` and PQCgenKAT-chained
`salt`. SHA-256 pins in `kats/official/PROVENANCE.md`.

**CI:** `.github/actions/test-hqc` runs
`cargo test --release --features alloc,hqc,random --test nist_kem_kat`.

**Out of scope:** Legacy 2249-byte `pk` NIST submission `.rsp` layouts (not retained in-repo).

### F4 — Internal side-channel self-certification (resolved, bounded)

**Evidence:** `lib-q-sca-test` feature `hqc-hardened` registers nine wall-clock TVLA
targets (keygen / encapsulate / decapsulate × HQC-128/192/256) in
`run_timing_battery`, with CI smoke via `hqc_hardened_tvla_and_dudect_smoke` and
`self_cert_smoke` (`algorithm-tests` and integration-tests jobs).

**Boundary:** This is pre-laboratory software timing screening only. No accredited lab,
no ~10⁶-trace instrumented TVLA, and no power/EM or microarchitectural channels are
claimed. See [side-channel self-certification](../../../docs/sca-self-certification.md).

### F5 — Documentation defects (corrected)

The following defects were corrected in this pass:

- **`lib-q-hqc/README.md`** — removed false "100% failure rate / production ready" claims;
  reconciled object sizes to [`lib-q-types::hqc`](../../../lib-q-types/src/hqc.rs);
  status now points to this assessment.
- **`lib-q-hqc/SECURITY.md`** — removed unverifiable KAT/compliance assertions; fixed
  HQC-128 `PUBLIC_KEY_BYTES` (2241, not 2249); corrected the HQC-128 `N2` parameter
  (384, not 640); removed the stale Reed–Muller "28-byte" limitation; aligned with the
  current findings.
- **`tests/README.md`** — replaced fictional test inventory with the actual file layout.

## Recommendations

1. ~~Resolve F2 and re-enable the randomized round-trip tests~~ (done).
2. ~~Add non-ignored NIST KEM KAT tests and wire them into CI (F3)~~ (done).
3. ~~Correct the documentation defects in F5~~ (done).
4. ~~Scope HQC into workspace side-channel self-cert tooling (F4)~~ (done — internal
   wall-clock battery only).
5. Before any production-readiness discussion: complete team security review, and if
   required, engage an accredited lab for instrumented TVLA / power / EM evaluation.

## Status

**Not production-ready.** Functional correctness (F1/F2), byte-exact KEM KAT (F3), and
internal timing self-cert coverage (F4) are evidenced in this repository. That does not
substitute for accredited side-channel certification or deployment sign-off. Do not deploy
for confidentiality guarantees without your own security review and any required external
evaluation.
