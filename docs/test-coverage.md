# Test Coverage Requirements

lib-Q maintains strict test coverage requirements as a NIST-approved quantum-resistant cryptographic library:

- **80% line coverage** for core cryptographic functionality (library code under test, not the whole workspace aggregate)
- **95% line coverage** for designated **security-critical** paths (see [coverage-scope.md](coverage-scope.md))
- **100% branch coverage** for those same paths **when** the coverage backend reports branch data (optional gate; see below)
- **Comprehensive test vectors** for cryptographic algorithms (KATs and conformance tests per algorithm crate)

Scoped paths, scripts, and ratcheting policy are described in [coverage-scope.md](coverage-scope.md).

## Running Coverage Tests

### Windows

```powershell
# Run coverage for a specific crate
.\scripts\run-coverage.ps1 -Crate "lib-q-core"

# Run coverage with custom threshold
.\scripts\run-coverage.ps1 -LineThreshold 90
```

### Linux/macOS

```bash
# Run coverage for a specific crate
./scripts/run-coverage.sh --crate lib-q-core

# Run coverage with custom threshold
./scripts/run-coverage.sh --threshold 90
```

### Metrics helper

```bash
# Line percentage (default) from cobertura.xml or HTML fallback
./scripts/extract-coverage-percent.sh coverage

# Branch percentage when Cobertura has branches-valid > 0 (otherwise exits 2)
./scripts/extract-coverage-percent.sh coverage branch

# Enforce floors (branch check skipped if no branch data)
./scripts/check-coverage-metrics.sh --dir coverage --line-min 80 --branch-min 100
```

## Coverage Strategy

To work toward the policy targets:

1. **Focus on core functionality**: Prioritize core cryptographic operations and validation layers
2. **Use Known Answer Tests (KATs)**: Validate against published test vectors
3. **Test edge cases**: Error handling and boundary conditions
4. **Property-based testing**: Cryptographic invariants where appropriate
5. **Narrow denominators for PR gates**: Use crate-scoped or `include-files` filters so percentages reflect the package under review (see `rust-test` / `run-coverage.sh`)

## CI Integration

Coverage is enforced in layers:

- **Pull requests** ([`pr.yml`](../.github/workflows/pr.yml)): tarpaulin runs for the **affected** workspace package with package-specific **line** floors (ratcheted over time). The reusable `rust-test` action uses [`check-coverage-metrics.sh`](../scripts/check-coverage-metrics.sh). Optional input `coverage-branch-threshold` applies only when Cobertura includes branch data.
- **Scheduled / path-triggered** ([`coverage.yml`](../.github/workflows/coverage.yml)): per-crate runs via `run-coverage.sh` and combined artifacts.
- **Security-critical subset** ([`security-critical-coverage.yml`](../.github/workflows/security-critical-coverage.yml)): Tarpaulin `--include-files` limited to `lib-q-sig/src/lib.rs`, `ml_dsa.rs`, and `provider.rs` (the sources built under `std`+`ml-dsa`), with a **70%** line floor; optional branch floor (no-op when `branches-valid=0`).

PR line floors are **lower than** the 80%/95% policy targets until every gated crate consistently meets the next milestone; then raise the numbers in `pr.yml` (and usually `COVERAGE_THRESHOLD` in `coverage.yml`) together.

## Coverage Exclusions

Some code may be legitimately excluded from coverage requirements:

- Debug-only code paths
- Platform-specific optimizations that cannot be exercised in CI
- Panic handlers in `no_std` environments
- WASM-only modules when the coverage build uses native `std` (explicit `--exclude-files` in scripts/actions)

Tarpaulin sets the Rust cfg flag `tarpaulin` while instrumenting. To omit a function from coverage **only** under tarpaulin, use:

```rust
#[cfg(not(tarpaulin))]
fn excluded_function() {
    // Not counted when running cargo tarpaulin
}
```

Prefer excluding **files** via tarpaulin CLI (`--exclude-files`) when whole modules are irrelevant to a given gate.
