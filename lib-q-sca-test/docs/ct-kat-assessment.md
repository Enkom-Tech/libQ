# CT-KAT coverage assessment (ePrint 2026/1418)

Radar card: **ENK-489** (Hive `iacr-radar`, idempotency `iacr-eprint-2026-1418`).
Assessed against libQ `main` at commit `47080f6` (2026-09-08).

## What the paper is

Seung-Won Lee, Min-Seo Kim, Su-Min Jeong, Hwa-Jeong Seo, *"CT-KAT: A Multilayer
Analysis Platform for Automated Screening of Constant-Time Risks in PQC C
Implementations"*, IACR ePrint 2026/1418 (<https://eprint.iacr.org/2026/1418>).

CT-KAT is a **screening harness for C implementations**, not a new detection
algorithm. From one YAML spec it (1) validates a build and its KAT vectors,
(2) auto-generates C harnesses that mark secret buffers with Valgrind client
requests, then runs four layers: Valgrind/Memcheck structural taint checking,
`ct-matrix` (the same harness rebuilt under gcc and clang at `-O0`…`-Os`),
`asm-scan` (greps the emitted assembly at every optimization level for
surviving `div` instructions, since compilers usually strength-reduce a
constant divisor but a secret-dependent one survives), and, when configured,
a `dudect`/TVLA statistical timing layer (Welch's *t*-test over
fixed-vs-random input classes, largest `|t|` over percentile crops of the
upper tail, plus Cohen's *d*). Verdicts are drawn from a nine-class taxonomy
under a **default-deny** policy: an unreviewed structural `FAIL`, a
build-sensitive result, or an untriaged `asm-scan` candidate all block a CI
gate; only `robust` and `accepted-variable-time` (each requiring a recorded
triage justification) pass it.

Evaluated on a PQClean-based corpus of ML-KEM, ML-DSA, SLH-DSA/SPHINCS+ and
Falcon reference C implementations, CT-KAT: classified baseline ML-KEM as
`robust`; classified a KyberSlash reproduction (secret-dependent division in
`poly_compress`, visible only at `-Os`/`-O0`, invisible to a single `-O0`
Valgrind-only run) as `varlat-secret-risk`; classified ML-DSA and
SLH-DSA/SPHINCS+ as `accepted-variable-time` after triage attributed their
structural `FAIL`s to specification-permitted rejection-sampling / signature
state, not secret-key-dependent leakage (dudect corroborated this on the
signature targets: `|t| ≤ 1.75` for ML-DSA, `1.52` for SLH-DSA/SPHINCS+-128f,
both under the paper's own warning threshold); and retained Falcon-512 as
`needs-analysis` (Gaussian-sampling/floating-point findings with no
public-only explanation).

## Scope note: CT-KAT does not run on libQ as shipped

libQ is a pure-Rust workspace. CT-KAT's structural and `asm-scan` layers are
architected around C source: harnesses are generated from C templates,
secret regions are tainted via Valgrind **client-request macros** compiled
into the C harness, and `ct-matrix`/`asm-scan` recompile that C harness under
gcc/clang. None of that toolchain applies to a `rustc`/LLVM-compiled crate
without first building an equivalent C-ABI shim and a from-scratch harness
generator — out of scope here (a separate, larger undertaking, not a gap this
assessment enumerates). This assessment therefore does **not** claim libQ
should adopt the CT-KAT tool. It uses the paper's coverage bar — automated,
repeatable **screening for secret-dependent timing** across the three
NIST-standardized schemes it names — to check libQ's own equivalent tooling,
the TVLA/dudect self-certification battery in this crate
(`lib-q-sca-test`, `src/self_cert.rs`), which already implements the same
statistical layer (Welch's *t*-test, fixed-vs-random classes) CT-KAT's
`dudect` layer uses.

## Per-scheme coverage in libQ

All three schemes CT-KAT targets are present in this workspace:
`lib-q-ml-kem/`, `lib-q-ml-dsa/`, `lib-q-slh-dsa/` (plus the `lib-q-sig`
facade at `lib-q-sig/src/slh_dsa.rs`).

| Scheme | `lib-q-sca-test` TVLA/dudect battery target | Per-crate `tests/constant_time.rs` |
|---|---|---|
| ML-KEM | **Yes** — `lib-q-ml-kem:decapsulate`, gated `#[cfg(feature = "mlkem")]` (`src/self_cert.rs:96-108`) | None (`lib-q-ml-kem/tests/` has no `constant_time.rs`) |
| ML-DSA | **Yes** — `lib-q-ml-dsa:sign`, gated `#[cfg(feature = "mldsa")]` (`src/self_cert.rs:110-121`) | None (`lib-q-ml-dsa/tests/` has no `constant_time.rs`) |
| SLH-DSA | **No** — no `slh`/`sphincs` target, gate, or reference anywhere in this crate | **Yes** — `lib-q-slh-dsa/tests/constant_time.rs`, but it is a **functional** comparison-hardening smoke, not a timing screen (see below) |

(For context, the same battery also covers HQC — `lib-q-hqc:hqc*`, gated
`#[cfg(feature = "hqc-hardened")]`, `src/self_cert.rs:137-217` — and
lattice-zkp — `lib-q-lattice-zkp:prove_opening`, gated
`#[cfg(feature = "lattice-zkp-hardened")]`, `src/self_cert.rs:123-135` —
neither of which CT-KAT's PQClean corpus names.)

**Observed gap:** `lib-q-sca-test`'s `run_timing_battery` (`src/self_cert.rs`)
is gated on exactly three feature flags — `mlkem`, `mldsa`, `hqc-hardened`
(plus `lattice-zkp-hardened`) — and none of them bring SLH-DSA into scope.
`grep -rniE 'slh|sphincs' src/ tests/` (excluding this doc) returns nothing:
SLH-DSA has no TVLA/dudect target in this crate at all, gated or otherwise.
The crate's own README (`README.md:3`) states its scope as
"hardened **lib-q-ml-kem**, **lib-q-ml-dsa**, and **lib-q-lattice-zkp**
paths" — SLH-DSA was never in scope, not merely disabled by a feature flag.

`lib-q-slh-dsa/tests/constant_time.rs` exists, but it self-declares a
narrower purpose than a timing screen (`tests/constant_time.rs:5-9`):

> Constant-time and comparison-hardening smoke tests for SLH-DSA. ... exercise
> `lib_q_core::Utils::constant_time_compare` and ensure verification rejects
> altered signatures. They do not replace dedicated timing analysis or
> `dudect`-style measurement.

It asserts that a signature-comparison helper is used and that corrupted
signatures are rejected — a functional/API-usage check, not a measurement of
whether SLH-DSA signing time varies with the secret key. So while ML-KEM and
ML-DSA have no per-crate `tests/constant_time.rs` at all (their only timing
screen is the shared battery), SLH-DSA has a file with that name and yet
**also** has no timing screen: the file that could have been dudect-style
timing coverage is a different kind of test.

## What CI actually runs, versus what CT-KAT would require

Two independent CI surfaces touch "constant time" and neither closes the
SLH-DSA gap:

- The dedicated `constant-time` job (`.github/workflows/security.yml`,
  job `constant-time` starting at line 129) runs
  `cargo test --test constant_time -p lib-q-sha3` (line 153),
  `-p lib-q-k12` (line 154),
  `cargo test --test security_tests -p lib-q-fn-dsa ... test_signing_latency_smoke welch_t_detects_synthetic_shift`
  (line 162), and
  `cargo test --features "std,secure,zeroize" --test constant_time -p lib-q-random`
  (line 163). None of ML-KEM, ML-DSA or SLH-DSA is named in this job.
- The `lib-q-sca-test` self-cert **smoke** (a reduced-sample plumbing check,
  not the full battery) runs twice in `.github/workflows/ci.yml`:
  `--features hqc-hardened --test self_cert_report -- --exact self_cert_smoke`
  (line 1792, covering the default `mlkem`+`mldsa` targets plus `hqc`) and
  `--features lattice-zkp-hardened --test self_cert_report self_cert_smoke`
  (line 2048, covering `mlkem`+`mldsa`+`lattice-zkp`). Both runs exercise
  ML-KEM and ML-DSA (default features); neither can exercise SLH-DSA, because
  no SLH-DSA target exists in the crate for a feature flag to select.

CT-KAT's own methodology bar for a scheme it accepts as "screened" is: a
dudect/TVLA harness run under a fixed measurement environment, its result
recorded and triaged. By that bar, ML-KEM and ML-DSA clear it in libQ (one
target each, always exercised by the smoke) and SLH-DSA does not (zero
targets, never exercised by anything timing-related).

## Verdict

SLH-DSA is the third NIST-standardized scheme CT-KAT names, libQ ships a
production implementation of it (`lib-q-slh-dsa`, plus the `lib-q-sig`
facade), and libQ's own TVLA/dudect self-certification battery — the direct
analogue of CT-KAT's statistical layer — has no target for it, while it does
for the other two. This is a real coverage asymmetry in this crate's stated
scope, not a limitation of CT-KAT's C-specific tooling (which is why the
verdict is not OUT-OF-MODEL) and not a case where existing coverage already
answers the question CT-KAT screens for (which is why it is not
INFORMATIONAL). The follow-up work — an SLH-DSA target in
`run_timing_battery`, feature-gated like the existing three, wired into the
`ci.yml` self-cert smoke the same way `hqc-hardened`/`lattice-zkp-hardened`
are — is tracked separately as **ENK-1364** and is out of scope for this
assessment (documentation only; no `lib-q-sca-test` source was touched by
this change).

Verdict: GAP

## Not checked

- Whether SLH-DSA's reference algorithm (hash-based, randomized signing) is
  amenable to the same fixed-vs-random Welch's-*t* harness shape the
  ML-KEM/ML-DSA targets use, or needs a different construction (e.g. a
  fixed-vs-random *randomizer* axis instead of a fixed-vs-random *key* axis,
  the way the paper's own ML-DSA/SLH-DSA dudect harnesses hold the message
  fixed rather than the key) — left to ENK-1364.
- Whether `lib-q-sig`'s SLH-DSA facade (`lib-q-sig/src/slh_dsa.rs`) has any
  timing coverage distinct from the `lib-q-slh-dsa` crate's own — not read.
- Whether GIP's `sdk/.libq-revision` pin tracks this assessment's commit —
  not diffed; this assessment used latest `origin/main`
  (`47080f6`), not the pin.
