# Security assurance (`lib-q-hqc`)

Security posture, verification scope, and known limits for the HQC KEM crate. For an
evidence-based assessment with open findings, see
[docs/audit-package/README.md](docs/audit-package/README.md).

**Status:** not production-ready. Randomized KEM/PKE round-trip correctness, byte-exact
regression-pin KEM KAT self-consistency (F3 — self-generated vectors, not official HQC reference
data; see `kats/regression-pins/PROVENANCE.md` for a known divergence from the official
reference), and internal wall-clock self-certification (F4) are verified in-repo
(see [What is verified](#what-is-verified-in-this-repository)); accredited lab evaluation,
genuine upstream KAT conformance, and instrumented power/EM TVLA remain out of scope.

## Specification alignment

The implementation targets the [NIST HQC specification (2025-08-22)](https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf)
— the post-selection construction with implicit-rejection `FO_m` and `(ek, salt)` binding into `K`
and `θ` (see `src/hqc_kem.rs` and `kats/regression-pins/PROVENANCE.md`). It supersedes the earlier
[October 2024 specification](https://pqc-hqc.org/doc/hqc-specification_2024-10-30.pdf).
Cryptographic object sizes are defined in [`lib-q-types::hqc`](../lib-q-types/src/hqc.rs)
and mirrored in `params`:

| Set | N1 | N2 | OMEGA | DELTA | Public key (B) | Ciphertext (B) |
|-----|----|----|-------|-------|----------------|----------------|
| HQC-128 | 46 | 384 | 66 | 15 | 2241 | 4433 |
| HQC-192 | 56 | 640 | 100 | 16 | 4514 | 8978 |
| HQC-256 | 90 | 640 | 131 | 29 | 7237 | 14421 |

The `OMEGA` column above was fixed 2026-08-09 (card `t_71d4f79a`) from 103/134 (HQC-192/256) to the
v5.0.0 reference's 100/131 (`Hqc3Params::OMEGA_R` was also fixed from 115 to the reference's 114);
those wrong values gave the secret support `(x, y)` the wrong Hamming weight, verified against the
upstream `intermediates_values` oracle in `kats/reference-intermediates/`. This is a breaking
wire-format change for HQC-192/256 keys, ciphertexts, and shared secrets — see `CHANGELOG.md`.

The HQC-192/256 public key sizes above were fixed from 4522/7245 (card `t_1558e72f`): those were
the HQC round-3 (2020 submission) values, which used a 40-byte `seed_ek` (40 + 4482 = 4522,
40 + 7205 = 7245); the v5.0.0 spec's 32-byte `seed_ek` gives 32 + 4482 = 4514 and 32 + 7205 = 7237.
HQC-128 was already migrated (2249 → 2241); HQC-192/256 were not, and the extra 8 bytes were inert
zero padding rather than data — a pure interop break, not a semantic divergence. **This is a
breaking wire-format change**: the whole public key is absorbed into `hash_h` during encapsulation,
so the ciphertext and shared secret change too for HQC-192/256; peers on `lib-q-types <= 0.0.10` do
not interoperate. At-rest keys convert losslessly by truncation (`pk_new = pk_old[..4514]` resp.
`[..7237]`) because the dropped bytes are provably zero and the retained prefix is byte-identical.

Parameter validation tests in `tests/compliance_parameter_validation.rs` and
`tests/compliance/parameter_validation.rs` check these constants against the
specification.

### Non-standard code/decoder optimizations (tracked, not adopted)

Published proposals reduce HQC key/ciphertext sizes by redesigning the error-correcting
code or decoder — e.g. ePrint [2026/656](https://eprint.iacr.org/2026/656) (a two-level
generalized concatenated code plus reliability-based errors-and-erasures decoding, up to
4.34 % smaller for NIST-1) and HARE. These change `n` and the wire sizes, so they are
**breaking, non-interoperable, and off-standard**; this crate does not implement them and
targets the NIST spec above instead. Rationale, verified figures, and the side-channel
caveat the 2026/656 authors raise for the threshold-based scheme are in
[docs/code-decoder-optimizations.md](docs/code-decoder-optimizations.md).

## What is verified in this repository

| Area | Evidence |
|------|----------|
| KEM round-trip (pinned seeds) | `tests/integration_test.rs` — HQC-1/3/5 shared-secret match with fixed key and encapsulation PRNG seeds |
| KEM round-trip (varied keys, all sets) | `tests/integration_test.rs::test_kem_roundtrip_varied_keys_all_params` — many independent keypairs per parameter set |
| PKE round-trip (varied keys) | `tests/integration_test.rs::test_pke_integration`, `tests/pke_roundtrip_basic.rs` — distinct keypairs, asserted equality |
| Randomized decapsulation (stress) | `tests/random_keypair_failure_test.rs` (`#[ignore]`, on demand) — zero failures observed over large OS-random batches |
| Error-correcting codes encode/decode | `src/reed_muller.rs`, `src/reed_solomon.rs`, `src/concatenated_code.rs` unit tests — full N1-byte RM/RS/concatenated round-trip and single-error correction |
| SHAKE256 PRNG | `tests/shake256_prng_kat.rs`, `tests/sha3_hqc_kat.rs` |
| Regression-pin KEM KAT (HQC-128/192/256) | `tests/nist_kem_kat.rs` — byte-exact `pk`/`ct`/`ss`/`sk` (NIST layout) vs `kats/regression-pins/` (self-generated by this crate, NOT official HQC reference data); full `.rsp` sweep; provenance and a known divergence from the official reference in `kats/regression-pins/PROVENANCE.md`; CI `test-hqc` |
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

### Power/EM side channel on fixed-weight sampling (not implemented, not mitigated)

[Hesse, Krausz, Murugananthan, Wollinger, Güneysu, "Power Reveals Timing Conceals" (ePrint
2026/1462)](https://eprint.iacr.org/2026/1462) demonstrates a practical power-analysis
key-recovery attack on HQC's fixed-weight vector sampling — the exact algorithm this
crate ports as `HqcPke::vect_generate_random_support1` (`src/hqc_pke.rs:506`, keygen
secret `x`/`y`) and `vect_generate_random_support2` (`:550`, ephemeral encryption noise
`r1`/`r2`/`e`); see `docs/vector-operations.md`'s posture table. Their first attack
targets support generation directly (100% key-recovery success, 900,000 distinguisher
calls against an unmasked implementation, following the Guo et al. CHES 2022 strategy);
their second targets a masked implementation's support *conversion* step with a
single-trace attack, also 100% success, by exploiting unintended share recombination.

This crate implements neither masking nor a hiding countermeasure (dummy operations,
shuffling, bitslicing) anywhere in the HQC fixed-weight sampler. The attacked control flow
is present verbatim: the variable-iteration rejection loop's data-dependent `break`
(`src/hqc_pke.rs:530`) and the O(i) duplicate scan over already-accepted secret positions
(`:538-543`) in `vect_generate_random_support1`, used directly on the long-term secret key
material `x`, `y` in keygen — the more sensitive of the two paths. The sibling
`vect_generate_random_support2` (ephemeral noise, lower severity) already uses an
arithmetic sign-bit mask for its own dedup write (`:588-593`), so the crate has the masked-
flow idiom in-crate already; it is simply not applied to `support1`. The paper is concrete,
published evidence that the "instrumented power/EM TVLA remain out of scope" limitation
above is not hypothetical for this code path on any target with physical or
co-located-process power/EM access (e.g. embedded, smartcard, cloud coresident) — and this
crate explicitly supports `no_std`/WASM targets (README.md), which are exactly that class.
The paper finds dummy-operation hiding scales only linearly with the number of dummy ops
(weak), while shuffling on the masked target fully prevented their second attack — i.e. a
masking-only or dummy-op-only fix would not be sufficient if this crate ever hardens this
path; both masking *and* hiding (shuffling) would be required.

Distinct from sibling iacr-radar card ENK-508 (ePrint 2026/1491), which targets load/store
leakage of `vect_generate_random_support1`/`2`'s *output* support words — a different
observable (memory access pattern) than this paper's target (the sampler's data-dependent
*control flow*, observed via power). Both papers attack the same two functions from
different angles; a hardening pass should address both assessments together.

No code change is made here: adding masking/shuffling to the sampler is a deliberate
architecture and threat-model decision (target platform, performance budget) for a
maintainer, not a drive-by literature-triage patch. A source review cannot settle a
power-domain claim either way — power leakage is a physical/per-device property, not a
source-level one (unlike timing or constant-time-source review) — so this section records
the paper's findings and their mapping onto this crate's symbols, not an independent
confirmation. Current side-channel coverage for this crate is whole-operation wall-clock
only (`SECURITY.md:12`, `:100-105`); no test isolates the sampler, and no power/EM trace of
any kind has been taken of this code.

Verdict: GAP

libQ's `no_std`/WASM support means an embedded or co-located-adversary deployment target is
plausible, and no power-domain check of this sampler has ever been run — this is not a
deployment libQ has formally excluded from its threat model. Follow-up hardening (masked
and/or shuffled rewrite of `vect_generate_random_support1`, gated behind the `hardened`
feature, output byte-identical to today's KATs) is tracked separately as board card
`ENK-1320` so it does not block this documentation
change; this card is not reopened for it.

### Formal verification

No machine-checked proof (Kani, etc.) ships with this crate. Correctness relies on tests
and manual review.

## Recommendations

**Development**

1. Run `cargo test -p lib-q-hqc --features alloc,hqc` before merging crypto changes.
2. Run Clippy with `-D warnings` on touched code.
3. Run `cargo test -p lib-q-hqc --release --features alloc,hqc,random --test nist_kem_kat` after KEM/PKE changes (uses seeded keygen; no AES DRBG required). Enable `kat-drbg` only when validating DRBG-specific reference paths.
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
- [HQC specification (2025-08-22)](https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf)
- [Internal assessment](docs/audit-package/README.md)
