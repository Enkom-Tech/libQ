# Coverage scope and enforcement tiers

This document defines how [test-coverage.md](test-coverage.md) policy maps to **measured paths** and **CI gates**. Line coverage is collected with `cargo-tarpaulin` (LLVM profile) and summarized from Cobertura `line-rate`. Branch totals in those reports are often zero (`branches-valid="0"`); optional branch floors are enforced only when the report includes branch data.

## Tiers

| Tier | Intent | Policy target | Current CI gate (see workflows) |
|------|--------|---------------|----------------------------------|
| Core library slice | `lib-q-core` sources under `lib-q-core/src`, excluding `wasm/` in PR coverage | ≥80% line on cryptographic API, validation, providers | PR `test-coverage`: **78%** line when `lib-q-core` is affected |
| Other affected crates | Full package under test when a crate path appears in the PR diff | ≥80% line (policy); gates ratchet toward that | PR `test-coverage`: default **70%** line; **exceptions** (still below 70% measured portable line): `lib-q-ml-dsa` **60%**, `lib-q-keccak`/`lib-q-kem` **65%**, `lib-q-zkp` **65%**, `lib-q-sig` **66%**, `lib-q-hpke` **66%**, `lib-q-aead`/`lib-q-cb-kem` **68%**. Scheduled [coverage.yml](../.github/workflows/coverage.yml) uses the same per-crate floors beside `COVERAGE_THRESHOLD` **70** for crates that already meet it. |
| Security-critical subset | `lib-q-sig/src/lib.rs`, `ml_dsa.rs`, `provider.rs` (same sources built for `std`+`ml-dsa`) | ≥95% line, 100% branch when tooling emits branches | [security-critical-coverage.yml](../.github/workflows/security-critical-coverage.yml): **70%** line on that scoped set (other `src/*.rs` files are feature-gated and are not part of the denominator); **100%** branch when reported |

For any PR package other than the umbrella `lib-q`, tarpaulin scopes `--include-files` to that package’s own sources (conventionally `<crate>/src/**`, or `examples/*.rs` for the example-only `lib-q-examples` member) so Cobertura `line-rate` is not dominated by dependency code. Resolution is shared by [scripts/print-tarpaulin-include-args.sh](../scripts/print-tarpaulin-include-args.sh) (used from the `rust-test` action and [scripts/run-coverage.sh](../scripts/run-coverage.sh)); CI fails the coverage step if a non-empty `-p`/`--packages` target would run without `--include-files`. Exceptions: `lib-q-core` additionally excludes other member crates and `wasm/` under PR settings; `lib-q-keccak` also excludes `advanced_simd.rs` (nightly/simd-only); `lib-q-ml-dsa` excludes `src/simd/avx2/**` and `src/ml_dsa_generic/instantiations/avx2.rs` because those sources are built only with `simd256`, while default coverage runs use the portable backend. AVX2/simd256 behavior is still covered by tests in [.github/workflows/ci.yml](../.github/workflows/ci.yml) (`ml-dsa-compliance`, e.g. `determinism` with `simd256`). The scheduled/push [Test Coverage workflow](../.github/workflows/coverage.yml) also runs a second, **non-gated** tarpaulin pass for `lib-q-ml-dsa` with `--ml-dsa-simd256` (stable only); reports land under `combined-coverage/.../crypto/lib-q-ml-dsa-simd256/`. Local equivalent: `bash scripts/run-coverage.sh --crate lib-q-ml-dsa --ml-dsa-simd256 --threshold 0 --output-dir coverage-ml-dsa-avx2`. To sweep the whole workspace: [scripts/verify-workspace-coverage.sh](../scripts/verify-workspace-coverage.sh).

## Security-critical paths (line targets)

These are the first scoped paths used for the dedicated workflow; extend the list in that workflow when new stable entry points warrant it.

- `lib-q-sig/src/ml_dsa.rs` — ML-DSA sign/verify and key-handling surfaced through `lib-q-sig`
- `lib-q-sig/src/provider.rs` — algorithm routing and `SignatureOperations` bridge

KEM and AEAD equivalents can be added similarly (for example `lib-q-kem` / `lib-q-hpke` facade modules) once each has a stable, test-covered surface matching this pattern.

## Ratcheting

When `scripts/run-coverage.sh` or the PR coverage job passes at least **two** consecutive runs above the next milestone, raise the floor in [.github/workflows/pr.yml](../.github/workflows/pr.yml), the per-crate `case` branches in [.github/workflows/coverage.yml](../.github/workflows/coverage.yml), and [`scripts/verify-workspace-coverage.sh`](../scripts/verify-workspace-coverage.sh) (`effective_threshold_for`) so scheduled runs and local sweeps stay comparable.

## Scripts

- [scripts/extract-coverage-percent.sh](../scripts/extract-coverage-percent.sh) — `line` (default) or `branch` metric from `cobertura.xml`
- [scripts/check-coverage-metrics.sh](../scripts/check-coverage-metrics.sh) — `--line-min` and optional `--branch-min` (branch skipped if no data)
- [scripts/print-tarpaulin-include-args.sh](../scripts/print-tarpaulin-include-args.sh) — emits scoped `--include-files` for one workspace package (used by `rust-test` and `run-coverage.sh`)
- [scripts/run-coverage.sh](../scripts/run-coverage.sh) / [scripts/run-coverage.ps1](../scripts/run-coverage.ps1) — local parity with CI flags where possible
