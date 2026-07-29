# Coverage scope and enforcement tiers

This document defines how [test-coverage.md](test-coverage.md) policy maps to **measured paths** and **CI gates**. Line coverage is collected with `cargo-tarpaulin` (LLVM profile) and summarized from Cobertura `line-rate`. Branch totals in those reports are often zero (`branches-valid="0"`); optional branch floors are enforced only when the report includes branch data.

## Tiers

| Tier | Intent | Policy target | Current CI gate (see workflows) |
|------|--------|---------------|----------------------------------|
| Core library slice | `lib-q-core` sources under `lib-q-core/src`, excluding `wasm/` in PR coverage | ≥80% line on cryptographic API, validation, providers | **78%** line: PR `test-coverage` when `lib-q-core` is the affected package, the `lib-q-core` step in [coverage.yml](../.github/workflows/coverage.yml), and [`effective_threshold_for`](../scripts/verify-workspace-coverage.sh) for local workspace sweeps. |
| Other affected crates | The package chosen by PR `test-coverage` when the diff hits a listed prefix (see below), or the `lib-q` / `lib-q-core` fallback | ≥80% line (policy); gates ratchet toward that | PR `test-coverage`: default **70%** line; **exceptions** (still below 70% measured portable line): `lib-q-ml-dsa` **60%**, `lib-q-keccak`/`lib-q-kem` **65%**, `lib-q-zkp` **65%**, `lib-q-sig` **66%**, `lib-q-hpke` **66%**, `lib-q-aead`/`lib-q-cb-kem` **68%**. [coverage.yml](../.github/workflows/coverage.yml) (push to `main`, path-filtered PRs, weekly schedule) uses the same exception list plus default **70** for all other crates in its scripted batches, and additionally floors `lib-q-fn-dsa` at **68%**. |
| Security-critical subset | `lib-q-sig/src/lib.rs`, `ml_dsa.rs`, `provider.rs` (same sources built for `std`+`ml-dsa`) | ≥95% line, 100% branch when tooling emits branches | [security-critical-coverage.yml](../.github/workflows/security-critical-coverage.yml): **70%** line on that scoped set (other `src/*.rs` files are feature-gated and are not part of the denominator); **100%** branch when reported |

**PR package selection:** [.github/workflows/pr.yml](../.github/workflows/pr.yml) picks a single package by scanning the diff against ordered lists (`CORE_CRATES`, `CRYPTO_CRATES`, `UTIL_CRATES`, then Stark/plonk workspace members). The first matching prefix wins. If none match, the job tests `lib-q` when `lib-q/`, `Cargo.toml`, or `Cargo.lock` changed, and otherwise defaults to `lib-q-core`. Workspace members outside those lists are not individually targeted by this job.

For any PR package other than the umbrella `lib-q`, tarpaulin scopes `--include-files` to that package’s own sources (conventionally `<crate>/src/**`, or `examples/*.rs` for the example-only `lib-q-examples` member) so Cobertura `line-rate` is not dominated by dependency code. Resolution is shared by [scripts/print-tarpaulin-include-args.sh](../scripts/print-tarpaulin-include-args.sh) (used from the `rust-test` action and [scripts/run-coverage.sh](../scripts/run-coverage.sh)); CI fails the coverage step if a non-empty `-p`/`--packages` target would run without `--include-files`. Exceptions: `lib-q-core` additionally excludes other member crates and `wasm/` under PR settings; `lib-q-keccak` also excludes `advanced_simd.rs` (nightly/simd-only) plus `x86_simd_avx512.rs` and `x86.rs` (the AVX-512 batched permutation and the x86 SIMD absorption entrypoints — `target_feature`-gated, so a runner without AVX-512/AVX2 takes the scalar fallback and never executes the intrinsic bodies); `lib-q-ml-dsa` excludes `src/simd/avx2.rs`, the `src/simd/avx2/` tree, and `src/ml_dsa_generic/instantiations/avx2.rs` because those sources are built only with `simd256`, while default coverage runs use the portable backend; `lib-q-intrinsics` excludes the opposite-ISA file for the runner (`arm64.rs` on x86_64, `avx2.rs` on aarch64, both on other architectures). AVX2/simd256 behavior is still covered by tests in [.github/workflows/ci.yml](../.github/workflows/ci.yml) (`ml-dsa-compliance`, e.g. `determinism` with `simd256`). The scheduled/push [Test Coverage workflow](../.github/workflows/coverage.yml) also runs a second, **non-gated** tarpaulin pass for `lib-q-ml-dsa` with `--ml-dsa-simd256` (stable only); reports land under `combined-coverage/.../crypto/lib-q-ml-dsa-simd256/`. Local equivalent: `bash scripts/run-coverage.sh --crate lib-q-ml-dsa --ml-dsa-simd256 --threshold 0 --output-dir coverage-ml-dsa-avx2`. To sweep every workspace package from `cargo metadata`: [scripts/verify-workspace-coverage.sh](../scripts/verify-workspace-coverage.sh) — `effective_threshold_for` mirrors the per-crate floors in [pr.yml](../.github/workflows/pr.yml) and [coverage.yml](../.github/workflows/coverage.yml) (including **78%** for `lib-q-core` and the lowered floors below **70** where applicable).

## What the gate can silently stop measuring

A coverage percentage is a fraction, and both halves can be corrupted without the number ever
looking wrong. [scripts/ci-guard-coverage-honesty.sh](../scripts/ci-guard-coverage-honesty.sh)
(run on every PR from `core-validation` in [ci.yml](../.github/workflows/ci.yml)) asserts the three
failure modes this repository has actually hit:

1. **Numerator — test-name filters.** No `cargo tarpaulin` command may pass test *names* after
   libtest's `--` separator; only scheduling/output flags (`--test-threads=1` for `lib-q-kem`) are
   allowed. A name filter shrinks the set of tests that runs while `--include-files` leaves the
   denominator untouched, so the result describes the filter. `lib-q-fn-dsa` carried
   `-- keypair_generation test_basic_fn_dsa_functionality sign_and_verify seeded_sign`, which ran
   6 of its 34 tests and measured **69/161 = 42.86%** against a 68% floor; with the filter removed
   the same code measures **129/161 = 80.12%** (measured locally, `x86_64-pc-windows-msvc`,
   cargo-tarpaulin 0.32.8 `--engine llvm`; CI's Linux figure will differ slightly).
2. **Selection — silently skipped packages.** The `coverage-skip` step in the
   [rust-test action](../.github/actions/rust-test/action.yml) matched `*"lib-q-keccak"*` as a
   substring, which also swallowed the unrelated sibling `lib-q-keccak-digest`: it took the no_std
   compile-check path and its coverage never ran on any PR. The predicate is now an exact match,
   and the guard evaluates the shipped predicate against every workspace package, allowing only
   packages on an explicit allowlist to be skipped. `lib-q-keccak` remains skipped there (no_std
   rlib under a panic=abort profile) and is gated by `coverage.yml` at 65% instead.
3. **Denominator — source hidden in nested crates.** `--include-files '<crate>/src/**'` cannot see
   a nested cargo package. The guard fails on any nested package inside a workspace member that is
   neither a member itself nor in `[workspace].exclude`, unless it is recorded as a known gap.

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

## Security-critical paths (line targets)

These are the first scoped paths used for the dedicated workflow; extend the list in that workflow when new stable entry points warrant it.

- `lib-q-sig/src/lib.rs` — façade entry points re-exported by `lib-q-sig`
- `lib-q-sig/src/ml_dsa.rs` — ML-DSA sign/verify and key-handling surfaced through `lib-q-sig`
- `lib-q-sig/src/provider.rs` — algorithm routing and `SignatureOperations` bridge

KEM and AEAD equivalents can be added similarly (for example `lib-q-kem` / `lib-q-hpke` facade modules) once each has a stable, test-covered surface matching this pattern.

## Ratcheting

When `scripts/run-coverage.sh` or the PR coverage job passes at least **two** consecutive runs above the next milestone, raise the floor in [.github/workflows/pr.yml](../.github/workflows/pr.yml), the per-crate `case` branches in [.github/workflows/coverage.yml](../.github/workflows/coverage.yml), and [`scripts/verify-workspace-coverage.sh`](../scripts/verify-workspace-coverage.sh) (`effective_threshold_for`, including the `lib-q-core` branch) so scheduled runs and local sweeps stay comparable.

## Scripts

- [scripts/extract-coverage-percent.sh](../scripts/extract-coverage-percent.sh) — `line` (default) or `branch` metric from `cobertura.xml`
- [scripts/check-coverage-metrics.sh](../scripts/check-coverage-metrics.sh) — `--line-min` and optional `--branch-min` (branch skipped if no data)
- [scripts/print-tarpaulin-include-args.sh](../scripts/print-tarpaulin-include-args.sh) — emits scoped `--include-files` for one workspace package (used by `rust-test` and `run-coverage.sh`)
- [scripts/run-coverage.sh](../scripts/run-coverage.sh) / [scripts/run-coverage.ps1](../scripts/run-coverage.ps1) — local parity with CI flags where possible
