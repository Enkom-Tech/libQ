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
state of the art it generalizes. Neither paper is cited anywhere else in this repo
(`grep -rIl '2026/1534\|2025/628' .` → no matches, checked at HEAD `c96add6`).

### What this crate actually computes, mapped by symbol

Verified against HEAD `c96add6`. `Flr` is the `binary64` real type
(`fn-dsa-sign/src/flr.rs`); `flr_native.rs` is the hardware-opcode backend
(`x86_64`/`aarch64`/`riscv64`), `flr_emu.rs` the portable software-emulated one used on
every other target.

- **Inversion** (`Flr::ONE / x`) runs inside `poly_LDL_fft`
  (`fn-dsa-sign/src/poly.rs:1065`, AVX2 mirror `fn-dsa-sign/src/poly_avx2.rs:377`) and
  its `logn == 1` base case (`fn-dsa-sign/src/sampler.rs:510`, AVX2 mirror
  `sampler_avx2.rs:292`). The divisor (`g00_re`) is one FFT coefficient of the secret
  Gram matrix derived from the signer's secret basis (`f`, `g`, `F`, `G`) — the operand
  is sensitive. This is the crate's *only* division: `flr_emu_diff.rs:594` records
  "every division in this crate is `Flr::ONE / x`". A second call site,
  `flc_div` (`poly.rs:40`), exists only inside `poly_div_fft` and `poly_invnorm2_fft`,
  both wrapped in `/* unused */` (dead code, not compiled) — not a live exposure.
- **Square root** (`Flr::sqrt`, implemented at `flr_emu.rs:676` and mirrored in
  `flr_native.rs:545`) is called on the secret FFT diagonal values `d11_re`/`d00_re`
  produced by the same LDL decomposition, at every leaf of the recursive Gaussian
  sampler tree: `sampler.rs:530`, `sampler.rs:551`, `sampler_avx2.rs:312`,
  `sampler_avx2.rs:333` (`d11_re.sqrt() * INV_SIGMA[logn]`).
- **Inverse square root** — the third function the paper targets — **has no symbol in
  this crate** (`grep -rniE 'invsqrt|rsqrt' lib-q-fn-dsa` → no matches). This is not an
  oversight: the crate already applies the paper's own alternative (§4.4, "No division
  square root", its Eq. 19: `√x = x·(1/√x)`) in the equivalent public-constant form —
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
filed as a separate implementation card: there is no concrete embedded/IoT deployment
of this crate today whose threat model requires it, and a speculative masked
implementation without one would be exactly the kind of unrequested scope this repo's
review process rejects.

---

Report vulnerabilities per the main [lib-Q SECURITY](../SECURITY.md) or the project
contact.
