# Security

See the workspace-level [SECURITY](../SECURITY.md) for the reporting process and the
overall claim: "Side channels — implementation is written with timing and cache
awareness; we do not claim completed independent side-channel evaluation for all
targets." This file narrows that claim to `lib-q-fn-dsa` and records one open item.

## Physical side-channel scope: no masking countermeasure exists (informational — ePrint 2026/1534, 2025/628)

**This crate defends `Flr` (the `binary64` real-number type used in signing) against
timing leakage only. It has no masking countermeasure against power/EM analysis, and
none is claimed.**

### What the paper says

IACR ePrint 2026/1534 (Berthet, "Masking, Sequences, and FALCON") is a theoretical
methodology paper, not an attack and not a shipped implementation. It proposes masking
FALCON's non-linear real-number operators — inversion, inverse square root, square
root — by expressing each as a convergent sequence (Newton–Raphson, Halley, or Heron)
whose first term is approximated by a masked minimax polynomial, then gives a t-probing
/ NI / SNI / MIMO-SNI security analysis of the resulting gadgets. It ships no code and
finds no defect in any existing masked implementation; its predecessor, ePrint 2025/628
(Berthet & Tavernier, "Improving the masked division for the FALCON signature"),
covered only the masked floating-point inverse and is cited by 2026/1534 as the prior
state of the art it generalizes. Neither paper is cited anywhere else in this repo —
`grep -rIl '2026/1534\|2025/628' --include='*.rs' --include='*.toml' --include='*.json' .`
returns no matches (checked at `836a0ef`, current `origin/main`). Source of truth for
that check is code and manifests, since this file necessarily names both papers.

### What this crate actually computes, mapped by symbol

Verified against `836a0ef` (current `origin/main`). `Flr` is the `binary64` real type
(`fn-dsa-sign/src/flr.rs`); `flr_native.rs` is the hardware-opcode backend
(`x86_64`/`aarch64`/`riscv64`), `flr_emu.rs` the portable software-emulated one used on
every other target.

- **Inversion** (`Flr::ONE / x`) runs inside `poly_LDL_fft`
  (`fn-dsa-sign/src/poly.rs:1065`, AVX2 mirror `fn-dsa-sign/src/poly_avx2.rs:377`) and
  its `logn == 1` base case (`fn-dsa-sign/src/sampler.rs:510`, AVX2 mirror
  `sampler_avx2.rs:292`). The divisor (`g00_re`) is one FFT coefficient of the secret
  Gram matrix derived from the signer's secret basis (`f`, `g`, `F`, `G`) — the operand
  is sensitive. `flr_emu_diff.rs:594` records that "every division in this crate is
  `Flr::ONE / x`". A helper `flc_div` (`poly.rs:40`) exists but is called only from
  `poly_div_fft` (`poly.rs:989`) and `poly_LDLmv_fft` (`poly.rs:1183`), both wrapped in
  `/* unused */` (dead code, not compiled) — not a live exposure. Two further `/* unused
  */` divisions exist and are likewise dead: `poly_invnorm2_fft` (`poly.rs:1008`) and
  `poly_div_selfadj_fft` (`poly.rs:1049`). The live divisions are exactly the four call
  sites named above, plus the scalar `impl Div for Flr` plumbing (`flr.rs:255-305`).
- **Square root** (`Flr::sqrt`, implemented at `flr_emu.rs:676` and mirrored in
  `flr_native.rs:545`) is called on the secret FFT diagonal values `d11_re`/`d00_re`
  produced by the same LDL decomposition, at every leaf of the recursive Gaussian
  sampler tree: `sampler.rs:530`, `sampler.rs:551`, `sampler_avx2.rs:312`,
  `sampler_avx2.rs:333` (`d11_re.sqrt() * INV_SIGMA[logn]`).
- **Inverse square root** — the third function the paper targets — **has no symbol in
  this crate** (`grep -rniE 'invsqrt|rsqrt' lib-q-fn-dsa --include='*.rs'` → no matches;
  the `--include` is required because this file's own text would otherwise match). This
  is not an oversight: the crate already applies the paper's own alternative (§4.4,
  "No division square root", its Eq. 19: `√x = x·(1/√x)`) in the equivalent
  public-constant form —
  `INV_SIGMA` (`sampler.rs:49`) is a fixed table indexed only by `logn` (a public
  parameter, not secret), so `d.sqrt() * INV_SIGMA[logn]` never needs a runtime
  `1/√(secret)`. One of the paper's three target functions is therefore inapplicable to
  this codebase's actual construction, not merely unmasked.

### Where this diverges from the paper's assumed context — a larger surface, not a smaller one

The paper frames inversion and inverse-square-root as **key-generation-time**
operations on a persisted FALCON-tree `leaf.value` (its Eq. 1–4, citing [23] Algorithm
4/15) and treats masking the signing-time inversion (its Eq. 2–3, `ccs`/`x`) as the
"only documented use" of that same value. This crate (following upstream Pornin
`fn-dsa-rust`'s design, which `lib-q-fn-dsa` tracks) keeps no persisted floating-point
tree: `poly_LDL_fft`'s decomposition and the sampler's `sqrt` calls above are
recomputed from the secret basis **inside `sign_inner`** (`fn-dsa-sign/src/lib.rs:541`
→ `sampler.rs:563`/`sampler_avx2.rs:345`) on **every signature**, not once at key
generation. `fn-dsa-kgen` itself uses fixed-point arithmetic throughout
(`fn-dsa-kgen/src/fxp.rs`) and has no floating-point `sqrt`/inversion call at all
(`grep -nE 'sqrt|Flr' fn-dsa-kgen/src` matches only comments and an unrelated hardcoded
`√2` constant in `vect.rs`). So the exposure the paper analyzes at key-generation time
recurs here, on the identical operators, once per tree node per `sign()` call.

### No masking exists today

`grep -rniE 'masking|probing|non-interference|\bgadget\b'
fn-dsa-sign/src fn-dsa-kgen/src` → no matches. Both call sites above run on plain
(unshared) `Flr` values.

### What this crate does claim, and why that claim is not contradicted

The crate's own README states "Constant-Time Operations: All cryptographic operations
are constant-time to prevent timing attacks" — a **timing**-only claim. `flr.rs:72–74`
is explicit about the same scope: "operations are over secret values and thus should
take care not to leak information through side-channels, in particular timing." The
`div_emu`/`sqrt_emu` Cargo features (`flr.rs:76–103`) exist to swap a platform's
non-constant-time FPU divide/sqrt opcode for a data-independent integer routine — that
is a **timing** countermeasure, and neither it nor anything else in this crate defends
against power or electromagnetic trace analysis. Nothing in 2026/1534 or 2025/628
contradicts a claim this crate actually makes: no masking or power/EM-resistance claim
exists for FN-DSA here to begin with (workspace `SECURITY.md`: "we do not claim
completed independent side-channel evaluation for all targets").

### Why this is recorded even though nothing is broken

`lib-q-fn-dsa`'s own README lists FN-DSA-512 — the exact parameter set both papers
analyze — for "IoT devices", and `docs/CONSTRAINED_DEVICE_SUITE.md` recommends it for
"constrained uplink / IoT". That is precisely the deployment class where an attacker
with physical proximity (a power or EM probe) is a realistic threat, unlike a
data-center server — the class 2026/1534 and 2025/628's t-probing/NI model addresses
and the timing-only model above does not.

**Verdict: OUT-OF-MODEL.** Masking is absent, but masking was never claimed for FN-DSA
signing in the first place; this is not a regression against a stated guarantee. It is
recorded here so a future embedded/IoT integration decision does not have to
rediscover it, and so the next agent who reads 2026/1534 or 2025/628 does not re-walk
this call-graph from scratch.

### Follow-up

No code change follows from this paper alone: it supplies a security analysis of a
*proposed* design, not gadgets to drop in, and neither the inversion nor the square
root above is masked today for any parameter set. Implementing masked inversion/sqrt
per this methodology is new engineering work — choosing a representation, an iteration
count, a minimax-polynomial order, and then re-deriving the NI/SNI assignment above for
*this* crate's actual `Flr` representation, none of which 2026/1534 does for a
concrete implementation — and is out of scope for this documentation pass. It is not
tracked separately as an implementation follow-up: there is no concrete embedded/IoT deployment
of this crate today whose threat model requires it, and a speculative masked
implementation without one would be exactly the kind of unrequested scope this repo's
review process rejects.

## ePrint 2026/1531 assessment (fixed-point Falcon signing)

**Paper:** De Almeida Braga, Fouque, Lachguel, Prest, "Toward a Secure Fixed-Point
Implementation of the Falcon Signature Scheme", [ePrint 2026/1531](https://eprint.iacr.org/2026/1531).
Read: the abstract page and, this pass, the full PDF (`https://eprint.iacr.org/2026/1531.pdf`,
converted to text; both math-heavy appendices B and the empirical Section 7 were skimmed rather
than checked equation-by-equation — see "Not checked" below for the residual gap).

**What the paper does.** Falcon's signing procedure is floating-point, which is the
documented obstacle to FPU-less targets, constant-time division, and masking. Pornin
(ePrint 2019/893) already ships a portable integer-emulated-float signing path, at a large
performance cost. This paper instead analyzes a **fixed-point** signing implementation: a
boundedness analysis (four keygen-time quantities bound almost every intermediate variable,
enforced by a modified keygen that rejects <50% of keys) and a precision analysis (a Rényi
divergence argument, conditioned on error bounds that are — the paper's own words — "for now,
partly empirical," derived from experiments rather than a closed-form proof). The reference
implementation is C, ~2x slower than native-float Falcon, ~10x faster than emulated-float
Falcon.

**Correction to the prior pass of this assessment.** The prior pass (which read only the
abstract) listed as an open reason not to adopt the paper's approach that it was "not yet
published in a venue with community cryptanalysis beyond the eprint itself." That is **false**:
this eprint's own text ("Difference with the conference version", and its acknowledgments
thanking "the anonymous reviewers of CRYPTO") states it is an **extended version of a paper
already published at IACR CRYPTO 2026** — a top-tier peer-reviewed venue. The theorem statements
and proofs did receive cryptographic peer review; what remains unreviewed by a venue is only the
empirical error-bound instantiation (Section 7) and the C reference implementation, neither of
which a CRYPTO review would have covered anyway. This does not change the bottom-line verdict
(below) but the peer-review point is dropped from the reasons for it, since it no longer holds.

**Also worth recording (does not change the verdict, no action follows for this crate today).**
Section 5.1 of the paper describes an independent implementation-correctness hazard for any
FN-DSA implementation, floating- or fixed-point: two mathematically equivalent signers can
diverge on a KAT at a rate of about 1/8000, because `SamplerZ`'s first truncation step is
discontinuous at exact-integer centers (an instance of the phenomenon [LTYZ25] / EUROCRYPT 2025
describes). The paper's own tweak in `Sign` (splitting the target into integer/fractional parts)
triggers exactly this, and it is fixed only by two changes to `SamplerZ`/`BerExp`/`ApproxExp`
that the paper says would themselves change the FN-DSA KAT vectors. `lib-q-fn-dsa-sign` does not
implement that target-splitting tweak, so this specific trigger does not apply to this crate's
current signing path — noted here because it bears on interoperability risk for *any* future
FN-DSA sign-path change here, fixed-point or not, not because it is a defect in the code today.

**How this crate's FN-DSA sign path maps onto that problem.**

- `lib-q-fn-dsa` is this workspace's Falcon/FN-DSA facade (`lib-q-fn-dsa-alg`, crate name
  `fn_dsa`); its signing crate is `fn-dsa-sign` (`lib-q-fn-dsa-sign`, crate name
  `fn_dsa_sign`). Both are ports of upstream Pornin `fn-dsa` v0.3.0
  (`lib-q-fn-dsa/fn-dsa/Cargo.toml`).
- Falcon signing here **is floating-point**: the sign context and expanded basis are typed
  over `flr::Flr` throughout `fn-dsa-sign/src/lib.rs` (e.g. the FFT-format basis field).
  `Flr` is an IEEE-754 binary64 value (`fn-dsa-sign/src/flr.rs`).
- The backend is picked by `target_arch` **alone** — no Cargo feature moves it
  (`fn-dsa-sign/src/flr.rs`, header comment):
  - `x86_64` / `aarch64` / `arm64ec` / `riscv64` → `flr_native.rs`, **hardware `f64`**.
  - everything else (`wasm32`, `arm`, `x86`, …) → `flr_emu.rs`, **software (integer-emulated)
    float** — a byte-faithful port of the exact Pornin 2019/893 approach the paper cites as
    its performance baseline (`fn-dsa-sign/src/flr.rs`, `flr_emu.rs` header: "The
    implementation uses only integer operations and strives to be constant-time.").
- The default (native) backend's constant-timeness is a **documented hardware assumption**,
  not a guarantee: `fn-dsa-sign/src/flr_native.rs` (header) — "it should be used only for
  architectures for which the hardware can be assumed to operate in a sufficiently
  constant-time way." This is exactly the property the paper's abstract calls out
  ("floating-point division is not constant time on many processors").
- The crate already carries a mitigation for that: the `div_emu` and `sqrt_emu` Cargo
  features replace the native backend's hardware divide/sqrt opcode with the same
  data-independent bit-by-bit integer routine `flr_emu.rs` uses
  (`fn-dsa-sign/src/flr.rs`). **Both are off by default**
  (`lib-q-fn-dsa/fn-dsa-sign/Cargo.toml`: `default = []`), and — verified this run —
  `cargo test -p lib-q-fn-dsa-sign --all-features` does not exist as a run configuration
  in this repo's CI; per `fn-dsa-sign/src/flr.rs`, the workspace `--all-features`
  clippy pass compile-checks both flags but no CI row executes tests under them. A runtime
  claim ("native FP division here is constant-time") that only holds *without* these flags
  is therefore not exercised by CI either way.
- the "Constant-Time Operations" bullet in `lib-q-fn-dsa/README.md` makes a blanket claim — "All cryptographic operations are
  constant-time to prevent timing attacks" — that the sign path's own source comments do
  not unconditionally support: on the default build, for the architectures the crate
  optimizes for and ships pre-built (x86_64/aarch64, README "Optimized
  implementations for x86_64 and ARM64 architectures"), the constant-time property rests on
  an unverified hardware assumption, with an existing but non-default mitigation.
- The Welch t-test in `lib-q-fn-dsa/tests/constant_time.rs` measures whole-`sign()`
  wall-clock means and explicitly disclaims proof: `constant_time.rs` (module docs) — "proof of
  constant-time-ness -- passing here means 'no timing effect this test's power could
  resolve was observed today,' not 'this code is constant-time.'" It does not isolate FP
  division/sqrt specifically, and does not run under `div_emu`/`sqrt_emu`.
- **Fixed-point precedent already exists in this crate, but only for keygen.**
  `fn-dsa-kgen/src/fxp.rs` defines `Fxr`, a 64-bit (32.32) fixed-point type ported
  from the upstream reference, used during key generation. No equivalent type exists under
  `fn-dsa-sign/src/`. The paper's contribution — extending fixed-point arithmetic to the
  *signing* procedure, with new boundedness/precision analysis to make that sound — has no
  counterpart here; adopting it would extend an existing in-crate idiom rather than
  introduce a new one.

**Assessment.** This paper is relevant to `fn-dsa-sign`'s floating-point sign path, but it
is not a drop-in fix and adopting it now would not be prudent:

1. The paper's own precision analysis is "for now, partly empirical" — its main security
   theorem is conditioned on error bounds derived from experiments, not a closed-form proof.
   Adopting an unaudited academic prototype (C only, no reference Rust implementation, no
   published KATs) in place of the current native-float or Pornin-emulated-float paths
   would trade an implementation with a fully understood (if not unconditionally proven)
   floating-point error model for one whose precision argument is explicitly incomplete.
2. It requires a **modified key generation** with a new rejection step (rejecting <50% of
   keys against four threshold quantities) — a change to `fn-dsa-kgen`'s sampling/rejection
   logic, not just the sign path, with its own correctness and KAT implications.
3. Peer review to date covers the theorem statements, not deployment: the paper is a CRYPTO
   2026 publication (see correction above), but its precision analysis is explicitly conditioned
   on empirically-derived error bounds, not proved ones, and the reference implementation is C
   only, with no published KATs against which a port could be checked for byte-exactness.

What this paper does **not** change is the finding independent of it: the README's
blanket constant-time claim is broader than what `fn-dsa-sign`'s own documented backend
assumptions support on the default build, and the existing `div_emu`/`sqrt_emu` mitigation
for that is off by default and untested at runtime by CI. That is this crate's actual,
actionable gap, tracked as a separate follow-up (default-enable
`div_emu`/`sqrt_emu`, or narrow the README claim) — independent of, and not resolved by,
whether the ePrint 2026/1531 fixed-point approach is ever adopted.

#### What is verified in this repository (FP sign backend)

| Area | Evidence |
|------|----------|
| Backend selection is `target_arch`-only, not feature-gated | `fn-dsa-sign/src/flr.rs` (header comment) |
| Native vs. emulated backend bit-for-bit agreement (test-only) | `fn-dsa-sign/src/flr_emu_diff.rs`, compiled on native-backend arches under `#[cfg(test)]`; runs in ordinary `cargo test --workspace` |
| Emulated backend as *production* code, on the arches that select it | CI `fn-dsa-emulated-float` job: this crate's suite under `wasm32-wasip1` / wasmtime |
| KAT byte-exactness vs. upstream Pornin `fn-dsa` v0.3.0 | `lib-q-fn-dsa/fn-dsa/tests/upstream_oracle_kat.rs` — `cargo test -p lib-q-fn-dsa-alg --test upstream_oracle_kat` (2 tests, both `ok`, re-run 2026-09-08) |
| Whole-signature timing (statistical, not backend-isolating) | `lib-q-fn-dsa/tests/constant_time.rs` — Welch t-test, message-class and key-class axes |

#### What is not verified

- Whether native hardware `f64` divide/sqrt is actually data-independent-time on any
  specific x86_64/aarch64/riscv64 CPU libQ ships to — a per-microarchitecture physical
  property, not something a source review or this crate's tests can settle.
- The sign path under `div_emu`/`sqrt_emu` at runtime — compile-checked only
  (`--all-features` clippy), never executed in CI.
- Whether `flr_emu.rs` is fully constant-time on the wasm32/arm targets that select it in
  production — it "strives to be" and is a byte-faithful upstream port; not independently
  audited here.
- The ePrint 2026/1531 PDF's math-heavy appendices (B: deferred proofs of Lemmas 2–13) were read
  but not independently re-derived; the empirical benchmark methodology in Section 7 (error
  bounds obtained from "extensive experiments," exact test count/coverage) was read but not
  reproduced — reproducing it would require building and running the paper's own C/Python
  reference code, which this assessment did not do.

### Recommendations

**Development**

1. Run `cargo test -p lib-q-fn-dsa-alg --test upstream_oracle_kat` after any change to
   `fn-dsa-sign`, `fn-dsa-kgen`, or `flr*.rs` — proves no floating-point-backend change
   moved a signature byte relative to the upstream reference.
2. Run `cargo test -p lib-q-fn-dsa-sign --features div_emu,sqrt_emu` before relying on the
   FPU-constant-time mitigation for a deployment target — it is compile-checked but not
   exercised by default CI.

**Deployment**

- On x86_64/aarch64/riscv64 with an unassessed FPU divide/sqrt implementation and a
  co-located timing adversary in the threat model, do not rely on the default build's
  constant-time claim for the sign path without independently verifying the CPU's FP divide
  timing, or building with `div_emu`/`sqrt_emu`.
- Do not use this crate for production signing without independent security review;
  FIPS 206 is unpublished and this implementation is pre-standardization.

### References

- [ePrint 2026/1531](https://eprint.iacr.org/2026/1531) — De Almeida Braga, Fouque,
  Lachguel, Prest, "Toward a Secure Fixed-Point Implementation of the Falcon Signature
  Scheme" (this assessment; extended version of the IACR CRYPTO 2026 paper).
- [ePrint 2019/893](https://eprint.iacr.org/2019/893) — Pornin, the emulated-float Falcon
  implementation this crate's `flr_emu.rs` ports.
- Lin, Tibouchi, Yu, Zhang, "Do Not Disturb a Sleeping Falcon" (LTYZ25), EUROCRYPT 2025 —
  the KAT-divergence phenomenon cited above ("Also worth recording").
- [docs/fn-dsa-nist-gate.md](../docs/fn-dsa-nist-gate.md) — FN-DSA publication gate (FIPS 206 not yet published).


**Verdict: GAP** (README constant-time claim broader than the default build supports).

---

Report vulnerabilities per the main [lib-Q SECURITY](../SECURITY.md) or the project
contact.
