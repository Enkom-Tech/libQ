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

The `OMEGA` column above was fixed 2026-08-09 from 103/134 (HQC-192/256) to the
v5.0.0 reference's 100/131 (`Hqc3Params::OMEGA_R` was also fixed from 115 to the reference's 114);
those wrong values gave the secret support `(x, y)` the wrong Hamming weight, verified against the
upstream `intermediates_values` oracle in `kats/reference-intermediates/`. This is a breaking
wire-format change for HQC-192/256 keys, ciphertexts, and shared secrets — see `CHANGELOG.md`.

The HQC-192/256 public key sizes above were fixed from 4522/7245: those were
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

## Classical security margin (Information-Set Decoding literature)

HQC's IND-CCA2 security reduces to the hardness of syndrome decoding for random
quasi-cyclic codes in the sublinear-weight regime. The best known classical attacks are
Information-Set Decoding (ISD) variants (Prange, Stern, and refinements). This crate does
not implement or track ISD attack costs itself; this section records the current best
published estimate against the parameter sets above so an integrator can see where the
posture stands.

- **[eprint 2026/1498](https://eprint.iacr.org/2026/1498)** — Carrier, Hatey, Luzzi,
  Tillich, "Multilevel Amortized Gaussian Elimination in Information-Set Decoding:
  Applications to HQC and PCG" (2026). Introduces MAGE-Stern, a multilevel
  amortized-Gaussian-elimination variant of Stern's ISD algorithm that reuses partial
  pivots across search iterations. Under a consistent logic-gate cost model, MAGE-Stern
  improves the best previously known ISD attack against HQC by approximately 3 bits in
  time complexity while reducing memory complexity by about 12 bits. The paper estimates
  the **standardized HQC Category I parameter set (`Hqc1Params`, `SECURITY_LEVEL = 128`)
  at approximately 140 bits classical security, about 3 bits below its NIST security
  target** — i.e. a margin erosion, not a break. The paper's own abstract gives no
  comparably quantified single figure for HQC-192/256 (`Hqc3Params`, `Hqc5Params`); this
  crate has not independently re-derived one and treats the ~140-bit estimate as applying
  only to the Category I set named above.
- **Register of the claim:** this is a **logic-gate cost-model complexity estimate**, not
  a demonstrated break. No key recovery has been shown feasible against HQC-128 at its
  published parameters, and this crate is not aware of any implemented attack. The
  estimate narrows — it does not eliminate — the margin between HQC-128 and its intended
  NIST Category I floor.
- **This crate defers to upstream HQC's own parameter selection** and makes no
  independent bit-security claim for any parameter set beyond the table above; this
  section only records the datapoint from the cited paper so a downstream integrator
  making a Category I risk decision can find it. Whether upstream HQC's own security
  estimates already account for this attack is a standards-tracking question this crate
  defers to upstream and does not settle here.

Verdict: MARGIN-EROSION


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

Distinct from ePrint 2026/1491, which targets load/store
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
feature, output byte-identical to today's KATs) is tracked separately as
a follow-up so it does not block this documentation
change.

### ARM Cortex-M4 poly-mul / sampler-expansion optimizations (ePrint 2026/1450, informational)

[Jang, Shin, Kim, Hong, Kwon, "Optimizing Polynomial Multiplication and Fixed-Weight
Sampling for HQC on ARM Cortex-M4" (ePrint
2026/1450)](https://eprint.iacr.org/2026/1450) — the full PDF was fetched and read for
this assessment, not only the abstract — is a performance/engineering paper, not an
attack: it reports (i) a dirty-aware register-allocation policy (SPF) and XOR-operation
reordering for the Frobenius Additive-FFT (FAFFT) polynomial-multiplication butterfly
that cuts VMOV register-move instructions by 37.6-48.1% at an unchanged EOR count, plus
a 34%-sparser FAFFT modulus for HQC-1; (ii) a rewrite of `vect_write_support_to_vector`
(WSV) — the function that scatters a fixed-weight support (a list of *ω* positions)
into a dense bit vector, distinct from the support-generation step that produces that
list — using Cortex-M4 IT-block/`orreq` predicated instructions and 4-way unrolling,
cutting its inner-loop cost from ~22 to ~6 cycles/word; and (iii) an optional cache of
the public transforms/hash recomputed under a fixed key. All figures are measured on a
NUCLEO-L4R5ZI (Cortex-M4) board; the paper does not claim or describe an attack.

**Contribution (i), FAFFT poly-mul, is out-of-model for this crate.** libQ does not
implement FAFFT: `grep -rniE 'fafft|frobenius' src` returns nothing under
`lib-q-hqc/src`. Polynomial multiplication here is `vect_mul` (`src/hqc_pke.rs:737`),
which dispatches to the scalar `schoolbook_vect_mul_mod_xnm1`
(`src/hqc_pke.rs:1029`) or, on `x86_64` with runtime AVX2, a Toom-3 + recursive
Karatsuba + PCLMUL path (`src/simd/avx2/gf2x.rs`) — neither shares code, structure, or
register-pressure profile with the paper's bit-sliced Cortex-M4 GP/VFP butterfly, so
the VMOV-count and sparser-modulus results do not transfer.

**Contribution (ii) targets `vect_write_support_to_vector`, not the sampler ePrint 2026/1462
and 2026/1491 flagged.** Reading the full paper (Section 4) corrects an assumption a source
read of the abstract alone would invite: HQC's fixed-weight sampling is two steps —
`vect_generate_random_support1/2` extracts the *ω* support positions from the XOF
(rejection sampling), then `vect_write_support_to_vector` (WSV) scatters that support
into the dense length-*n* bit vector. The paper optimizes only the second step, WSV;
it does not touch, and its Section 4 does not claim to touch, the first step's control
flow. libQ's WSV (`src/hqc_pke.rs:613-636`) is a line-for-line port of the paper's own
described *baseline*: for each output word `i` it loops over every support element `j`
and accumulates `bit_tab[j] & mask` where `mask` is a branchless constant-time
comparison (`:628-631`, verbatim: `let val1 = 1u32 ^ ((tmp as u32 | tmp.wrapping_neg() as u32) >> 31);
let mask = (-(val1 as i64)) as u64;`) — the same `mask = -1 xor ((t | -t) >> 31)` construction the
paper cites (its Eq. 2) as the official implementation's branchless technique that its
own optimization preserves the constant-time property of while replacing the 8
mask-instructions/word with 2 predicated `orreq`s. **libQ's WSV is therefore already
constant-time by the same design the paper starts from** — no data-dependent branch,
no secret-dependent memory address, loop bounds fixed by `weight`/vector length — and
the paper's contribution here is a Cortex-M4 Thumb-2 assembly speed optimization of
that already-safe routine, not a fix for a gap. This is unrelated to ePrint
2026/1462 and ePrint 2026/1491, which both target `vect_generate_random_
support1`'s *first*-step rejection sampling (`src/hqc_pke.rs:506`: the rejection
`break` at `:530`, the O(i) duplicate scan at `:538-540`, tracked as an open GAP with
hardening follow-ups) — a different function, a different step, and a gap this paper
does not address at all. The two assessments must not be conflated: this paper gives
no reason to revise the 2026/1462 and 2026/1491 GAP verdict on `vect_generate_random_support1`,
and those assessments give no reason to treat WSV as unsafe.

No hardening follow-up is warranted from contribution (ii): WSV has no gap to close.
Adopting the paper's Cortex-M4-specific predicated/unrolled assembly for speed alone
would mean hand-writing target-specific `unsafe`/asm for one architecture, which cuts
against this crate's stated pure-Rust, portable, `no_std`/WASM/`thumbv7em-none-eabi`-
alike posture ("Implementation properties" above, `README.md`) for a routine that is not on this
crate's measured hot path relative to `schoolbook_vect_mul_mod_xnm1`/AVX2 `gf2x.rs`.

**Contribution (iii), fixed-key caching, is a protocol/API-level optimization, not a
security property**, and orthogonal to (i)/(ii): it caches `H(ek)` and the forward
transforms of the public `h`/`s` under a fixed key, all public values, compared via a
full-length constant-time equality check on cache lookup (the paper states this
preserves the constant-time property; no secret is cached). This crate's public KEM
API (`encapsulate`/`decapsulate`) does not expose a fixed-key session/cache concept,
so adopting it would be an API-shape change for a specific deployment pattern (a
device repeatedly decapsulating under its own fixed key), not a drop-in optimization;
noted here for completeness and not evaluated further.

No code change is made here: this section is a documentation-only literature
assessment (`git diff` for this change touches only this file). This paper found no
new vulnerability in libQ — its poly-mul target (FAFFT) is absent from this crate, and
its sampler target (WSV) is already constant-time here by the same design the paper's
own baseline uses — so nothing here changes the priority, scope, or verdict of
the hardening follow-ups for the open GAP on the unrelated `vect_generate_random_
support1` rejection-sampling step.

**Not checked:** reproducing any of the paper's cycle counts (no Cortex-M4 hardware or
ARM Thumb-2 toolchain measurement in this environment; the `thumbv7em-none-eabi`
target is only compile-checked elsewhere in this repo, per the 2026/1491
assessment); whether libQ's
`vect_generate_random_support2` (the sibling of `support1`, used for `r1`/`r2`/`e`)
has the identical duplicate-scan shape — plausible by inspection but not the subject
of this assessment; the AVX2 `gf2x.rs` path's own constant-time properties, which this
paper does not analyse either.

Verdict: INFORMATIONAL

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

**Correction to an earlier assessment of this issue (2026-08-31):** that
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

**Independent re-check, no ARM disassembler (this assessment, follow-up pass):** this
VM's `objdump`/`readelf` toolchain has no ARM decoder (`objdump -i` lists only
`i386`/`x86-64`; `rustup component add llvm-tools-preview` fails offline —
`error opening file for download: Read-only file system`), so the binary-level check
above could not be repeated with a disassembler. It was repeated a different way
instead: `RUSTFLAGS="-C opt-level=s" cargo rustc -p lib-q-hqc --no-default-features
--features "no_std,hqc128" --target thumbv7em-none-eabi -- --emit=asm` (verified via
`cargo rustc -v` that `-C opt-level=s`, appearing after the profile's own `-C
opt-level=2`, is the flag rustc actually applies — repeated `-C` flags are last-wins)
emits readable Thumb-2 `.s` text directly, with `.loc` directives tying each
instruction back to a `hqc_pke.rs` source line — no disassembler needed at all, and
reproducible in any VM with only `cargo`. In the emitted
`schoolbook_vect_mul_mod_xnm1`, the `.loc 33 1047 …` instructions (source line 1047,
`for (i, &ai) in a.iter().enumerate()`) are `ldrd r0, r1, [r4], #8` (load `ai`,
post-increment the pointer) immediately followed by `strd r1, r0, [sp, #32]` (spill
both halves to two adjacent stack slots, one word apart); the `.loc 33 1049 …`
instructions (source line 1049, the `(ai >> bit) & 1` mask) then reload the two halves
with two separate `ldr` instructions, `ldr r2, [sp, #32]` and `ldr r1, [sp, #36]`, once
per one of the 64 bit-loop iterations. This confirms, independently of the paper's GCC
build and of the prior objdump-based check, that rustc/LLVM produces the same
load-then-spill-then-repeated-half-reload shape for this function — the general
load/store leakage class the paper's attack depends on is not GCC-specific. It still
does not confirm the paper's measured low-half/high-half *signal-strength* asymmetry:
that is an EM-measurement property of the physical part and traces, not something
readable off assembly text, and remains unverified here as the paragraph above
already states.

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
representation of `y`/`x` to remove the sparsity. A follow-up tracks the
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
