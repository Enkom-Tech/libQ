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

### Formal verification

No machine-checked proof (Kani, etc.) ships with this crate. Correctness relies on tests
and manual review.

### Side-channel: load/store leakage of sparse secret vectors (ePrint 2026/1491)

Banegas, Smith, and Zahreddine, "Exploiting Load/Store Leakage of Sparse Vectors for
Key Recovery in HQC" ([ePrint 2026/1491](https://eprint.iacr.org/2026/1491)), attack
the HQC reference C implementation on Cortex-M4: they compile it with GCC 14.2.1 `-Os`
for `ARMv7E-M`, find that the multiply routine loads each 64-bit word of the secret
sparse vector `y` with an `ldrd` instruction and spills at least one half to the stack,
and build a zero-word distinguisher from EM traces that classifies each word as
zero/nonzero. Because `y` (`ω = 66` of `n = 17 669` bits for HQC-1, `hw(y) ≪ n`) is
overwhelmingly zero, this leaks most of the long-term secret key directly, cutting
HQC-1 key recovery to ≈2^46 bit operations at 32-bit hint granularity. Their own
Table 2 names the attacked C functions precisely: `schoolbook_mul` (called from
`vect_mul`) loading `y` on **every decapsulation** (`u·y`) and on keygen (`h·y`), plus
`vect_write_support_to_vector` (storing the freshly-sampled support in dense form) and
`vect_add`.

**Correction to an earlier assessment on this issue's board card (2026-08-31):** that
comment concluded libQ's exposure was "narrowed to the transient `support[]` array in
the sampler, not a sparse-form multiply" because `PolynomialOps::sparse_dense_mul` is
off the KEM path (`simd/avx2/mod.rs:53-59`). That conflates two different things:
`sparse_dense_mul` is an unrelated trait method HQC never calls for its polynomial
product; the paper's actual target, `vect_mul`→`schoolbook_mul`, is a **dense×dense**
multiply over a vector that happens to hold a sparse secret — precisely what libQ's
`schoolbook_vect_mul_mod_xnm1` (`src/hqc_pke.rs:1029`) is. That prior conclusion is
superseded by this section.

**libQ's structural counterpart, confirmed present and reachable:**
- `schoolbook_vect_mul_mod_xnm1` (`src/hqc_pke.rs:1029-1075`) is a line-for-line port of
  the reference C `schoolbook_mul`: it loads `a[i]` once per outer iteration
  (`src/hqc_pke.rs:1047`, `for (i, &ai) in a.iter().enumerate())`) and tests each of its
  64 bits in an inner loop (`:1048-1064`) — the same structure the paper diagrams.
- `vect_mul` (`src/hqc_pke.rs:737-750`) calls it whenever AVX2 is unavailable: any
  non-x86_64 target, or x86_64 without runtime AVX2 support (`simd-avx2` is
  gated `target_arch = "x86_64"` only — `src/hqc_pke.rs:742`).
- The secret vector is passed as the **first** operand at both call sites the paper's
  Table 2 lists as decapsulation/keygen targets: `decrypt`'s `vect_mul(&mut tmp1, &y,
  &u)` (`src/hqc_pke.rs:298`, executed on every decapsulation) and `keygen`'s
  `vect_mul(&mut s, &y, &h)` (`src/hqc_pke.rs:200`) — matching the paper's observation
  that "secret sparse vectors are always passed as the first operand."
- `vect_write_support_to_vector` (`src/hqc_pke.rs:613`), the dense-encoding store the
  paper's Table 2 names as a second leakage source, is unchanged from the prior
  assessment; the keygen sampler `vect_generate_random_support1` still branches on
  secret positions (`src/hqc_pke.rs:530` rejection test, `:538-543` collision scan).

**libQ explicitly ships this code for the attacked microcontroller class.** The crate's
`no_std` feature is CI-verified against `thumbv7em-none-eabi` — ARMv7E-M, the Cortex-M4
ISA family the paper's experiments target — for `hqc128` (HQC-1, the parameter set the
paper's headline numbers use): `.github/actions/test-hqc/action.yml:122-129`
(`cargo check --no-default-features --features "no_std,hqc128" --target
thumbv7em-none-eabi`). AVX2 is x86_64-only, so on this target `vect_mul` always takes
the `schoolbook_vect_mul_mod_xnm1` path above. This assessment re-ran that exact CI
check (`cargo check -p lib-q-hqc --no-default-features --features "no_std,hqc128"
--target thumbv7em-none-eabi`) and it built clean today, confirming the claim rather
than trusting the CI config.

**Binary-level check (new for this assessment, not merely source-level plausibility):**
compiling `lib-q-hqc` for `thumbv7em-none-eabi` with `hqc128,no_std` at `-C
opt-level=s` (matching the paper's `-Os`) and disassembling
`schoolbook_vect_mul_mod_xnm1`'s emitted Thumb-2 asm shows the same instruction-level
shape the paper exploits: the secret word is loaded with a register-pair `ldrd r0, r2,
[r5], #8` and immediately spilled to the stack with `strd r2, r0, [sp, #36]`, then
reloaded a 32-bit half at a time (`ldr r3, [sp, #36]`) inside the per-bit loop that
tests it. This is an `ldrd`-load-then-stack-spill-then-reload pattern for the secret
word — the general load/store leakage class (Marshall, Page & Webb) the paper's attack
depends on — observed directly in libQ's own compiled output, not inferred from the
reference C. It is not a reproduction of the paper's measured low/high-half asymmetry:
that asymmetry was measured with GCC 14.2.1 on real Cortex-M4 EM traces, is a
compiler+register-allocator-specific property, and confirming it for rustc/LLVM here
would need actual traces, which this assessment does not have.

Existing side-channel coverage remains whole-operation only (`SECURITY.md:12`, `:70`);
the nearest CT test times full `decapsulate` (`tests/hardened_dudect_smoke.rs:9`), not
the multiply's per-word memory-access pattern, so nothing in this crate's test suite
would catch a regression here.

**Not checked:** actual EM/power traces of a `thumbv7em-none-eabi` build (this
assessment is disassembly-only, no hardware-in-the-loop measurement); the AVX2 path
(`avx2_vect_mul_mod_xnm1`, Toom-3 + Karatsuba + PCLMUL) is a structurally different
algorithm the paper does not analyse and this assessment did not separately audit;
whether the same `ldrd`/spill shape appears at other optimization levels or rustc
versions.

libQ ships, and CI-verifies, a build of the paper's exact attacked function shape for
the paper's exact target microcontroller family, with no masking or alternate
representation of `y`/`x` to remove the sparsity. Follow-up card ENK-1322 tracks the
remediation options the paper itself proposes (per-call additive masking of the sparse
vector, or storing it in a transform domain) and, if masking is adopted, re-running
this disassembly check to confirm the spill no longer carries secret-zero information.

Verdict: GAP

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
