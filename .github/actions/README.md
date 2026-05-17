# GitHub Actions for libQ

This directory contains reusable GitHub Actions for the libQ project.

## Available Actions

### `rust-test`

A comprehensive Rust testing action that supports:
- Regular unit and integration tests
- Release mode tests
- Coverage analysis with configurable thresholds
- Support for no_std environments

#### Usage

```yaml
- name: Run tests
  uses: ./.github/actions/rust-test
  with:
    features: "all-algorithms"
    run-coverage: "true"
    coverage-threshold: "78"
    package: "lib-q-core"
```

`pr.yml` sets `coverage-threshold` per affected package (see `docs/coverage-scope.md`); the default below is only the action default when callers omit the input.

#### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `working-directory` | Working directory for the crate | `.` |
| `features` | Features to enable for testing | `""` |
| `package` | Specific package to test | `""` |
| `rust-version` | Rust toolchain version | `stable` |
| `run-release-tests` | Whether to run release tests | `true` |
| `run-coverage` | Whether to run coverage tests | `false` |
| `coverage-threshold` | Minimum **line** coverage (Cobertura `line-rate`) | `95` |
| `coverage-branch-threshold` | Optional minimum **branch** coverage when `branches-valid > 0` | `""` (skip) |

### `rust-build`

A reusable action for building and validating Rust code.

### `wasm-build`

Builds WebAssembly targets (web, nodejs) via wasm-pack. Supports `out-dir` (default `pkg`), `rust-version` (default `stable`), and feature flags.

### `crate-publish`

Publishes Rust crates to crates.io. The CD workflow uses `rust-lang/crates-io-auth-action` (Trusted Publishing) and passes its token output to this action. Configure this repository as a trusted publisher at https://crates.io/settings/publishing for workflow `cd.yml` before releasing.

## Workflow Integration

The actions are used in the following workflows:

- **PR Workflow** (`pr.yml`): Uses `rust-test` for focused coverage checks on PRs
- **Coverage Workflow** (`coverage.yml`): Uses direct script calls for comprehensive coverage analysis
- **CI Workflow** (`ci.yml`): Uses `rust-build` for continuous integration

## Coverage Analysis

Coverage analysis is performed in two ways:

1. **PR Coverage Check**: Focused coverage check on specific packages
   - Uses the `rust-test` action
   - Configured in `pr.yml`
   - Only checks the package being modified

2. **Full Coverage Analysis**: Comprehensive coverage analysis
   - Uses direct script calls to `scripts/run-coverage.sh`
   - Configured in `coverage.yml`
   - Runs on main branch and scheduled weekly
   - Generates coverage badges

3. **Security-critical scoped coverage**: `security-critical-coverage.yml` runs tarpaulin with `include-files` on facade paths listed in `docs/coverage-scope.md`