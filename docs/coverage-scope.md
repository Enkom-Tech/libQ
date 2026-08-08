# Coverage scope and enforcement tiers

This document defines how [test-coverage.md](test-coverage.md) policy maps to **measured paths** and **CI gates**. Line coverage is collected with `cargo-tarpaulin` (LLVM profile) and summarized from Cobertura `line-rate`. Branch totals in those reports are often zero (`branches-valid="0"`); optional branch floors are enforced only when the report includes branch data.

## Tiers

| Tier | Intent | Policy target | Current CI gate (see workflows) |
|------|--------|---------------|----------------------------------|
| Core library slice | `lib-q-core` sources under `lib-q-core/src`, excluding `wasm/` in PR coverage | ≥80% line on cryptographic API, validation, providers | **78%** line: PR `test-coverage` when `lib-q-core` is the affected package, the `lib-q-core` step in [coverage.yml](../.github/workflows/coverage.yml), and [`verify-workspace-coverage.sh`](../scripts/verify-workspace-coverage.sh) for local sweeps, which reads that floor from the workflows rather than restating it. |
| Other affected crates | The package chosen by PR `test-coverage` when the diff hits a listed prefix (see below), or the `lib-q` / `lib-q-core` fallback | ≥80% line (policy); gates ratchet toward that | PR `test-coverage`: default **70%** line; **exceptions** (still below 70% measured portable line): `lib-q-ml-dsa` **60%**, `lib-q-keccak`/`lib-q-kem` **65%**, `lib-q-zkp` **65%**, `lib-q-sig` **66%**, `lib-q-hpke` **66%**, `lib-q-aead`/`lib-q-cb-kem` **68%**. [coverage.yml](../.github/workflows/coverage.yml) (push to `main`, path-filtered PRs, weekly schedule) uses the same exception list plus default **70** for all other crates in its scripted batches, and additionally floors `lib-q-fn-dsa` at **68%**. |
| Security-critical subset | `lib-q-sig/src/lib.rs`, `ml_dsa.rs`, `provider.rs` (same sources built for `std`+`ml-dsa`) | ≥95% line, 100% branch when tooling emits branches | [security-critical-coverage.yml](../.github/workflows/security-critical-coverage.yml): **70%** line on that scoped set (other `src/*.rs` files are feature-gated and are not part of the denominator); **100%** branch when reported |

**PR package selection:** [.github/workflows/pr.yml](../.github/workflows/pr.yml) picks a single package by scanning the diff against ordered lists (`CORE_CRATES`, `CRYPTO_CRATES`, `UTIL_CRATES`, then Stark/plonk workspace members). The first matching prefix wins. If none match, the job tests `lib-q` when `lib-q/`, `Cargo.toml`, or `Cargo.lock` changed, and otherwise defaults to `lib-q-core`. Workspace members outside those lists are not individually targeted by this job.

For any PR package other than the umbrella `lib-q`, tarpaulin scopes `--include-files` to that package’s own sources (conventionally `<crate>/src/**`, or `examples/*.rs` for the example-only `lib-q-examples` member) so Cobertura `line-rate` is not dominated by dependency code. Resolution is shared by [scripts/print-tarpaulin-include-args.sh](../scripts/print-tarpaulin-include-args.sh) (used from the `rust-test` action and [scripts/run-coverage.sh](../scripts/run-coverage.sh)); CI fails the coverage step if a non-empty `-p`/`--packages` target would run without `--include-files`. Exceptions: `lib-q-core` additionally excludes other member crates and `wasm/` under PR settings; `lib-q-keccak` also excludes `advanced_simd.rs` (nightly/simd-only) plus `x86_simd_avx512.rs` and `x86.rs` (the AVX-512 batched permutation and the x86 SIMD absorption entrypoints — `target_feature`-gated, so a runner without AVX-512/AVX2 takes the scalar fallback and never executes the intrinsic bodies); `lib-q-ml-dsa` excludes `src/simd/avx2.rs`, the `src/simd/avx2/` tree, and `src/ml_dsa_generic/instantiations/avx2.rs` because those sources are built only with `simd256`, while default coverage runs use the portable backend; `lib-q-intrinsics` excludes the opposite-ISA file for the runner (`arm64.rs` on x86_64, `avx2.rs` on aarch64, both on other architectures). AVX2/simd256 behavior is still covered by tests in [.github/workflows/ci.yml](../.github/workflows/ci.yml) (`ml-dsa-compliance`, e.g. `determinism` with `simd256`). The scheduled/push [Test Coverage workflow](../.github/workflows/coverage.yml) also runs a second, **non-gated** tarpaulin pass for `lib-q-ml-dsa` with `--ml-dsa-simd256` (stable only); reports land under `combined-coverage/.../crypto/lib-q-ml-dsa-simd256/`. Local equivalent: `bash scripts/run-coverage.sh --crate lib-q-ml-dsa --ml-dsa-simd256 --threshold 0 --output-dir coverage-ml-dsa-avx2`. To sweep every workspace package from `cargo metadata`: [scripts/verify-workspace-coverage.sh](../scripts/verify-workspace-coverage.sh) — reads the per-crate floors out of [pr.yml](../.github/workflows/pr.yml) and [coverage.yml](../.github/workflows/coverage.yml) at run time rather than restating them (`coverage.yml` wins where both define a crate, since it is the fuller table). Note `lib-q-fn-dsa`'s **68%** floor appears only in `coverage.yml`'s `CRYPTO_CRATES` case — `pr.yml`'s per-package selector has no `lib-q-fn-dsa` branch, so a PR selecting that package as the single affected crate falls to `pr.yml`'s default **70%**, one point stricter than the calibrated floor.

## What the gate can silently stop measuring

A coverage percentage is a fraction, and both halves can be corrupted without the number ever
looking wrong. [scripts/ci-guard-coverage-honesty.sh](../scripts/ci-guard-coverage-honesty.sh)
(run on every PR from `core-validation` in [ci.yml](../.github/workflows/ci.yml)) asserts the
failure modes this repository has actually hit:

1. **Numerator — test-name filters.** No `cargo tarpaulin` command may pass test *names* after
   libtest's `--` separator; only scheduling/output flags (`--test-threads=1` for `lib-q-kem`) are
   allowed. A name filter shrinks the set of tests that runs while `--include-files` leaves the
   denominator untouched, so the result describes the filter. `lib-q-fn-dsa` carried
   `-- keypair_generation test_basic_fn_dsa_functionality sign_and_verify seeded_sign`, which ran
   6 of its 34 tests and measured **69/161 = 42.86%** against a 68% floor; with the filter removed
   the same code measures **129/161 = 80.12%** (measured locally, `x86_64-pc-windows-msvc`,
   cargo-tarpaulin 0.32.8 `--engine llvm`; CI's Linux figure will differ slightly).
   The files to inspect are **discovered** by walking the repo for shell/YAML/PowerShell files that
   mention tarpaulin, not read off a list, and command text is reached by tainting every variable
   that flows into the invocation — so neither a new workflow nor a different append idiom
   (`CMD+=`, or a filter parked in a variable named nothing like "cmd") escapes it.
2. **Selection — silently skipped packages.** The `coverage-skip` step in the
   [rust-test action](../.github/actions/rust-test/action.yml) matched `*"lib-q-keccak"*` as a
   substring, which also swallowed the unrelated sibling `lib-q-keccak-digest`: it took the no_std
   compile-check path and its coverage never ran on any PR. The predicate is now an exact match,
   and the guard runs the **shipped** predicate against every workspace package **under every
   input shape the action accepts** — `package:`, `packages:`, a `packages:` entry carrying an
   `@features` suffix, a package inside a longer `packages:` list, and a non-`no_std` `features:`
   string. Driving only `package:` would leave the `$PACKAGES` arm unexercised, and `ci.yml` really
   does pass `packages:`. Only packages on an explicit allowlist may be skipped; `lib-q-keccak`
   remains skipped there (no_std rlib under a panic=abort profile) and is gated by `coverage.yml`
   at 65% instead.
3. **Denominator — source hidden in nested crates.** `--include-files '<crate>/src/**'` cannot see
   a nested cargo package. The guard fails on any nested package inside a workspace member that is
   neither a member itself nor in `[workspace].exclude`, unless it is recorded as a known gap.
4. **Denominator — narrowed head-on.** A whole-crate `--include-files` must name a directory glob
   (`<crate>/src/*`, `<crate>/src/**`, `*.rs`); pointing it at `<crate>/src/lib.rs` shrinks the
   denominator to one file. Deliberately scoped tiers are allowed from `NARROW_INCLUDE_ALLOWLIST`,
   keyed by *file* so the security-critical tier's narrow includes cannot license the same
   narrowing in the whole-crate gate. Symmetrically, an `--exclude-files` reaching inside a
   member's own `src/` must appear in `SRC_EXCLUDE_ALLOWLIST` — the ~15 existing ones are all
   code the runner cannot execute (SIMD/arch-gated bodies, non-compiled cfgs) and each carries its
   reason there. Excluding a file that merely lacks tests now fails the build.

**What the guard does not cover** (a green run is not a proof the number is right): it is static
and never runs tarpaulin; CHECK 1's taint analysis is per-file, so a command assembled across two
files is not modelled; CHECK 4 does not allowlist coarse `<crate>/*` exclusions such as the
sibling-crate list `lib-q-core` uses, so an exclusion naming the crate under `--packages` would
pass; and discovery keys on the literal string `tarpaulin`, so a wrapper that never spells the
tool's name is invisible. These are recorded in the script header rather than papered over.

### Known gap: FN-DSA nested crates

`lib-q-fn-dsa`'s gated percentage describes `lib-q-fn-dsa/src/lib.rs` (161 measurable lines) and
nothing else. The five nested crates `lib-q-fn-dsa/fn-dsa{,-comm,-kgen,-sign,-vrfy}` hold roughly
37k lines and are outside the denominator — including `fn-dsa-kgen/src/poly.rs`, where a portable
keygen livelock survived from 2026-05-17 to 2026-07-27 with no coverage signal. **Read
"lib-q-fn-dsa: 80%" as a statement about the wrapper, not about FN-DSA.**

They cannot simply be added to `--include-files`: they are not workspace members, so
`tarpaulin --packages lib-q-fn-dsa` never runs their own test suites, and widening the denominator
without running those suites would crater the figure and break the gate blind. Closing this is
measure-then-gate: add report-only (`--threshold 0`) tarpaulin rows for each nested crate to
`coverage.yml` — the precedent already exists there for `lib-q-ml-dsa --ml-dsa-simd256` — then set
floors from what CI prints. Note that `--packages <name>` will not resolve for a non-member, so
those rows need a manifest-path invocation or the crates need to become workspace members first;
that has not been verified on a Linux runner. The entry in `NESTED_PACKAGE_EXCEPTIONS` keeps the
gap visible until then.

### Known gap: published crates in no gate list at all

The gap above is about a crate whose *number* understates it. This one is about crates with no
number at all.

Coverage is gated by **name**. `pr.yml` builds `ALL_CRATES` from four hardcoded lists, finds the
first crate the PR touched, and measures that one against the `case` statement's threshold;
`coverage.yml` walks its own `CORE_CRATES` / `CRYPTO_CRATES` / `UTIL_CRATES`. A crate named in
none of them is never measured against any floor.

Nothing surfaces this. A crate absent from every list cannot lower a percentage that is never
computed for it, so the Test Coverage workflow is green whether its coverage is 90% or 0%.

**Baseline 2026-08-08: 77 published crates, 46 gated names, 31 published crates outside all of
them** — including `lib-q-saturnin`, `lib-q-hqc`, `lib-q-slh-dsa` and `lib-q-mayo`.

**Now: 69 gated names, 8 unmeasured**, all 8 recorded with a reason in
`scripts/coverage-floor-exemptions.txt`. 23 of the 31 were measured and gated in
`coverage.yml`'s `extended-coverage` job.

Two consequences of the gap that remain worth stating plainly:

- **A green "Test Coverage" run says nothing about a crate that is not gated.** It is not weak
  evidence about it; it is no evidence.
- `pr.yml` `break`s at the first affected crate, so even among gated crates a PR touching two of
  them measures only one. Still true.

### How the 23 were gated

`extended-coverage` is a separate, sharded job rather than more crates appended to the job above,
because that one already runs ~65 min per-crate plus a ~40 min workspace pass against a 150 min
timeout. It runs `stable` only: these floors are regression backstops, and re-measuring the same
lines under a second toolchain buys little for the runner time.

Every floor is **measured on CI, then set ~5 points under** — a backstop, not an aspiration. The
CI figure is recorded beside each threshold in both workflows so a reader can see the headroom
without re-running anything. Raise them as coverage improves; that is the ratchet.

**Calibrate from a CI log, not from a laptop.** The first cut of these floors was measured on
Windows and was wrong by a wide margin — `lib-q-rocca-s` reads 48.32% there and **98.21%** on CI,
against a different denominator (387 lines vs 224). Every floor still passed, which was exactly
the danger: `lib-q-rocca-s` sat 55 points above its floor, so anything short of a catastrophic
regression would have gone unnoticed. Retuning against CI's own numbers removed ~369 points of
accumulated slack across the 23 crates. A WSL run is not a substitute either: it disagreed with CI
by up to 44 points on the same crate, because this box has cargo-tarpaulin 0.35.2 while CI pins
0.37.0.

### The measurement itself was blind for feature-gated crates

Worth understanding before trusting any coverage number here. `run-coverage.sh` built each crate
with **default features**, so code behind a non-default feature was never compiled and therefore
never counted — while still looking like a clean run:

- `lib-q-blind-pcs` keeps its whole implementation behind `blind-pcs`. Its coverage run
  instrumented an empty crate and reported *"No coverable lines found"*, i.e. 0%, which any
  `--threshold 0` accepts happily. It measures **88.89%** once the feature is on.
- `lib-q-saturnin` shipped four modules the run never saw. `aead_short.rs` (110/115),
  `qcb.rs` (138/140), `tbc.rs` (18/19) and `commit.rs` (9/9) were all well tested and all
  invisible. `simd/avx2.rs` read **0/39 despite having a dedicated `simd_equivalence.rs` suite**;
  with `simd-avx2` on it is 257/263.

Both now have explicit feature sets in `run-coverage.sh`. The general lesson: **a floor set from a
default-features run on a feature-gated crate is calibrated against a fiction.** Check what the
run actually compiles before trusting the percentage.

`simd-neon` is deliberately *not* enabled for Saturnin: it is `aarch64`-gated, so on x86_64 it
would sit in the denominator at 0 however good the tests are — the same argument as the
`lib-q-keccak` / `lib-q-ml-dsa` / `lib-q-stark-monty31` entries in that script.

### What is still unmeasured, and why

`scripts/ci_guard_coverage_floors.py` (run in `ci.yml`'s `core-validation`) keeps the remaining
gap from growing: every published crate must be gated or listed with a reason; a newly published
crate fails until someone decides which, and an exemption for a crate that has since been gated
also fails, so the file cannot rot. It also checks that a crate gated in both `pr.yml` and
`coverage.yml` carries the **same** floor in both — two hand-maintained copies of one set of
measurements otherwise drift silently, and the dangerous direction is quiet: lower the `pr.yml`
number and PRs stop catching a regression the scheduled job would only find days later.

The 8 remaining split three ways, and they are not the same kind of thing:

| | crates | why |
|---|---|---|
| Impractical to instrument | `lib-q-dkg`, `lib-q-threshold-raccoon`, `lib-q-threshold-kem-lattice`, `lib-q-blind-token` | keygen far too slow under debug tarpaulin; already recorded in `coverage.yml` |
| No coverable lines | `lib-q-fn-dsa-alg`, `lib-q-stark-baby-bear` | tarpaulin reports *"No coverable lines found"* so every threshold above 0 fails and 0 enforces nothing. Their tests **do** run and pass (33 for stark-baby-bear) — generic code inlined into callers, **not** untested crates |
| Genuinely untested | `lib-q-hqc-traits` | 0.00%, 0/11 lines, `running 0 tests`. The honest fix is tests, not a threshold |
| Deferred | `lib-q-zk-encryption-proof` | RED, awaiting cryptographer sign-off; instrumented build exceeds 10 min locally so it has no measured floor yet |

## Security-critical paths (line targets)

These are the first scoped paths used for the dedicated workflow; extend the list in that workflow when new stable entry points warrant it.

- `lib-q-sig/src/lib.rs` — façade entry points re-exported by `lib-q-sig`
- `lib-q-sig/src/ml_dsa.rs` — ML-DSA sign/verify and key-handling surfaced through `lib-q-sig`
- `lib-q-sig/src/provider.rs` — algorithm routing and `SignatureOperations` bridge

KEM and AEAD equivalents can be added similarly (for example `lib-q-kem` / `lib-q-hpke` facade modules) once each has a stable, test-covered surface matching this pattern.

## Ratcheting

When `scripts/run-coverage.sh` or the PR coverage job passes at least **two** consecutive runs above the next milestone, raise the floor in **two** places: [.github/workflows/pr.yml](../.github/workflows/pr.yml) and the per-crate `case` branches in [.github/workflows/coverage.yml](../.github/workflows/coverage.yml). `ci_guard_coverage_floors.py` fails if those two disagree, so they cannot drift apart.

[`scripts/verify-workspace-coverage.sh`](../scripts/verify-workspace-coverage.sh) no longer needs updating — it **reads** the floors out of those workflows at run time. It used to keep a third copy in `effective_threshold_for`, and that copy had already gone stale: the 23 floors added on 2026-08-08 were never mirrored into it, so a local sweep would have applied the generic 70% default to crates whose real floors range from 3% to 92% and reported failures CI does not have. Do not reintroduce a hardcoded table there.

**Measure on Linux.** CI gates on Linux, and on this repo the same commit measures very differently on Windows: Linux read higher on 20 of 23 crates (up to +29 points, `lib-q-mayo` 65.56% → 94.83%) with a different *denominator* on 17 of them, because Linux compiles more code (`lib-q-fn-dsa-kgen` 2186 lines → 3674). A Windows sweep is not evidence about the CI gate; WSL works. `verify-workspace-coverage.sh` warns when not run on Linux, and prints each floor's **margin**, flagging any that are `TIGHT` (<2 points, will flake) or `LOOSE` (>12 points, no longer protecting much).

## Scripts

- [scripts/extract-coverage-percent.sh](../scripts/extract-coverage-percent.sh) — `line` (default) or `branch` metric from `cobertura.xml`
- [scripts/check-coverage-metrics.sh](../scripts/check-coverage-metrics.sh) — `--line-min` and optional `--branch-min` (branch skipped if no data)
- [scripts/print-tarpaulin-include-args.sh](../scripts/print-tarpaulin-include-args.sh) — emits scoped `--include-files` for one workspace package (used by `rust-test` and `run-coverage.sh`)
- [scripts/run-coverage.sh](../scripts/run-coverage.sh) / [scripts/run-coverage.ps1](../scripts/run-coverage.ps1) — local parity with CI flags where possible
