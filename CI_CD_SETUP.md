# CI/CD Setup

This document describes the CI/CD pipeline configuration for lib-Q.

## Workflows

### CI Pipeline (`.github/workflows/ci.yml`)

- **Triggers**: `push` / `pull_request` on `main` and `develop`, `workflow_dispatch`, and a weekly schedule (`cron: 0 5 * * 0`).
- **PR vs full runs**: Pull requests run a slimmer set of jobs to save minutes. Pushes to `main`/`develop`, the weekly schedule, and manual dispatch also run heavier jobs (e.g. cross-platform builds, valgrind, HQC SIMD debug, full ML-DSA audit script, ZKP recursive aggregation, extended benchmarks where enabled).
- **Core validation**: Fast gate (15 min timeout)—format, security audit, workspace Clippy with all features (`rust-build`).
- **Test matrix**: Feature and package combinations via `rust-test` (e.g. `std`, `all-algorithms`, ML-KEM, ML-DSA modes, `no_std`, WASM, ZKP, `lib-q-random`, `lib-q-ring`, `lib-q-lattice-zkp`, STARK crates). Non-PR runs also `cargo check` both ring crates for `thumbv7em-none-eabi` and execute `lib-q-sca-test` (see `ci.yml`).
- **WASM validation**: `wasm-build` across several crates; additional Romulus `no_std` / `wasm32` smoke checks.
- **Cross-platform builds**: Non-PR only; multiple OS/target combinations.
- **Algorithm tests**: Composite `test-*` actions for Keccak, SHA3, K12 (in `lib-q-hash`), Saturnin, FN-DSA, RNG (`lib-q-random`), CB-KEM, SLH-DSA, HPKE, and HQC (see [Composite actions](#composite-actions)).
- **Benchmark manifest** (`bench-shards-validate`): On every run (including PRs), validates [`.github/benchmark-shards.toml`](.github/benchmark-shards.toml) and compile-checks each shard with `cargo bench --no-run`.
- **Benchmark matrix** (`bench-matrix`): On every run (including PRs), emits and verifies GitHub Actions matrix JSON from the manifest (`bench-shards-to-json.sh` + `verify-matrix`); no Criterion execution on PRs.
- **Per-crate benchmarks** (non-PR only): `bench-warm-cache` compiles all manifest shards once; `performance-benches` runs ~23 parallel shards (`max-parallel: 12`) via [`run-bench-shard`](.github/actions/run-bench-shard). Bench jobs use `concurrency` groups under `ci-benches-${{ github.ref }}` with `cancel-in-progress: true` so force-pushes cancel stale warm-cache and shard runs. Criterion uses `--quick --warm-up-time 1`.
- **Other jobs**: ML-DSA compliance, documentation generation, integration tests, SIMD debug for HQC, etc.

### CD Pipeline (`.github/workflows/cd.yml`)

- **Trigger**: Version tags matching `v*`.
- **Pre-release validation**: Workspace `Cargo.toml` version must match the tag; `rust-build` + `cargo test --all-features --release`.
- **Rust publishing**: Crates publish in dependency order across **tiers 0–16** via `rust-lang/crates-io-auth-action` (crates.io **Trusted Publishing** / OIDC) and `./.github/actions/crate-publish`. Exact package lists per tier are defined only in `cd.yml`.
- **WASM / npm**: `wasm-build` then `./.github/actions/npm-publish` for scoped `@lib-q/*` packages (requires `NPM_TOKEN`).
- **Post-release**: GitHub Release with changelog; post-release security verification (install published `lib-q`, smoke-load `@lib-q/core`, constant-time tests where applicable). **`post-release` and `cd-summary` wait on `publish-rust-tier-17`** so the GitHub release is cut after the last crates.io tier (including the `lib-q` umbrella).

### Security Pipeline (`.github/workflows/security.yml`)

- **Triggers**: `push` / `pull_request` on `main` and `develop`, and daily schedule (`cron: 0 2 * * *`).
- **Core**: `rust-build` with audit; NIST-focused checks via `cargo run -p lib-q-utils --bin security-validator`.
- **Additional jobs**: Cryptographic validation, dependency and compliance-style checks, reporting suitable for PRs (see workflow file for the current job list).

### PR Validation (`.github/workflows/pr.yml`)

- **Core validation**: `rust-build` (audit, format, Clippy on `lib-q`), plus `cargo doc --all-features --no-deps --document-private-items`.
- **Security validation**: Classical-crypto policy and SHA-3 compliance via `lib-q-utils` `security-validator`.
- **Test coverage**: Targeted coverage for crates touched by the PR (`rust-test` with per-crate thresholds). For scope and thresholds, see `docs/coverage-scope.md`.

### Test Coverage (`.github/workflows/coverage.yml`)

- **Triggers**: Pushes to `main`, PRs to `main` when certain paths change (`lib-q-keccak`, `lib-q-core`, or this workflow), and weekly schedule.
- **Behavior**: `cargo-tarpaulin`, stable and nightly matrix, line coverage threshold (see `COVERAGE_THRESHOLD` in the workflow).

### Security-critical coverage (`.github/workflows/security-critical-coverage.yml`)

- **Triggers**: `workflow_dispatch` and weekly schedule.
- **Behavior**: Scoped tarpaulin on security-critical facade paths (e.g. `lib-q-sig` with ML-DSA features), with thresholds enforced via `scripts/check-coverage-metrics.sh`.

### ZKP fuzz (scheduled) (`.github/workflows/zkp-fuzz-scheduled.yml`)

- **Triggers**: Weekly schedule and `workflow_dispatch`.
- **Behavior**: `cargo-fuzz` targets under `lib-q-zkp/fuzz` (bounded time); does not gate PR CI.

### Dependency updates

- **Dependabot**: `.github/dependabot.yml` for GitHub Actions and cargo ecosystem updates.

## Composite actions

There is **no** `security-validation` composite. Security checks use `rust-build`, `rust-test`, and workflow-local steps (including `lib-q-utils` `security-validator`).

### Rust Build (`.github/actions/rust-build`)

Primary reusable gate: toolchain, cache, integration-test layout check, optional audit / fmt / Clippy / tests / workspace builds / WASM or cross-compile flags. Used heavily in `ci.yml`, `pr.yml` (subset), `cd.yml`, and `security.yml`.

```yaml
- uses: ./.github/actions/rust-build
  with:
    run-security-audit: "true"
    run-format-check: "true"
    run-clippy: "true"
    run-tests: "false"
    run-workspace-builds: "false"
    features: "all-algorithms"
```

### Rust Test (`.github/actions/rust-test`)

Matrix tests in `ci.yml`; optional tarpaulin coverage (used in `pr.yml` with per-package thresholds). See `.github/actions/README.md` for inputs.

### WASM Build (`.github/actions/wasm-build`)

Used in `ci.yml` and `cd.yml` (wasm-pack; supports `out-dir`, feature flags, `check-only`).

### Crate publish / NPM publish

- **`.github/actions/crate-publish`**: `cargo publish` with token from OIDC (`crates-io-auth-action`) in CD.
- **`.github/actions/npm-publish`**: Node **20**, npm CLI **11.6.2+**, dual-target `pkg/web` + `pkg/nodejs` (seeds root `package.json` before `npm pkg set`). Publishes with `secrets.NPM_TOKEN` when set; on `E404`/`ENEEDAUTH` retries via **npm Trusted Publishing** (OIDC; requires `id-token: write` and a trusted publisher for `Enkom-Tech/libQ` / workflow `cd.yml` on npm). Do not pass `--provenance` with token auth. `@lib-q/types` is a separate job (`fail-fast: false` on the WASM matrix).

### Performance benchmark (`.github/actions/performance-benchmark`)

Reusable local/manual runner: executes [`scripts/run-bench-shards.sh`](scripts/run-bench-shards.sh) (manifest-driven). CI uses the `performance-benches` matrix in `ci.yml`, not this action directly.

**Maintainer workflow:** when adding `[[bench]]` to a workspace crate, add a matching `[[shard]]` in [`.github/benchmark-shards.toml`](.github/benchmark-shards.toml), then run `./scripts/validate-bench-shards.sh` and `./scripts/bench-shards-to-json.sh` (includes `verify-matrix`).

### Run benchmark shard (`.github/actions/run-bench-shard`)

Runs one manifest row: `cargo bench -p <package>` with optional `--features` / `--bench`. Matrix shards use `actions/cache/restore@v5` only; `bench-warm-cache` restores, compiles, then `actions/cache/save@v5`.

### Algorithm-specific test actions

CI’s `algorithm-tests` job passes inputs aligned with `.github/workflows/ci.yml` (values below match that matrix; copy from the workflow if you need an exact replica).

#### Keccak (`.github/actions/test-keccak`)

```yaml
- uses: ./.github/actions/test-keccak
  with:
    working-directory: "lib-q-keccak"
    features: "asm,simd"
    rust-version: "nightly"
    run-benchmarks: "true"
    test-algorithms: ""
```

#### SHA3 (`.github/actions/test-sha3`)

```yaml
- uses: ./.github/actions/test-sha3
  with:
    working-directory: "lib-q-sha3"
    features: "alloc,oid"
    rust-version: "stable"
    run-benchmarks: "false"
    test-algorithms: "sha3-224,sha3-256,sha3-384,sha3-512,keccak224,keccak256,keccak384,keccak512,turboshake128,turboshake256"
```

#### K12 (`.github/actions/test-k12`)

K12 tests run against **`lib-q-hash`** in CI (not `lib-q-k12`).

```yaml
- uses: ./.github/actions/test-k12
  with:
    working-directory: "lib-q-hash"
    features: "alloc,oid,getrandom"
    rust-version: "stable"
    run-benchmarks: "false"
    test-algorithms: "kangarootwelve"
```

#### Saturnin (`.github/actions/test-saturnin`)

```yaml
- uses: ./.github/actions/test-saturnin
  with:
    working-directory: "lib-q-saturnin"
    features: "aead,aead-short,block-cipher,hash,stream,alloc"
    rust-version: "stable"
    run-benchmarks: "false"
    test-algorithms: "aead,aead-short,block-cipher,hash,stream"
```

#### FN-DSA (`.github/actions/test-fn-dsa`)

```yaml
- uses: ./.github/actions/test-fn-dsa
  with:
    working-directory: "lib-q-fn-dsa"
    features: "std,rand"
    rust-version: "stable"
    run-benchmarks: "false"
    run-security-tests: "true"
    run-constant-time: "true"
```

#### RNG (`.github/actions/test-rng`)

```yaml
- uses: ./.github/actions/test-rng
  with:
    working-directory: "lib-q-random"
    features: "std,secure,zeroize"
    rust-version: "stable"
    run-benchmarks: "true"
    run-entropy-validation: "true"
    run-security-tests: "true"
    run-constant-time: "true"
    test-algorithms: "secure,deterministic,hardware,user"
```

#### CB-KEM (`.github/actions/test-cb-kem`)

```yaml
- uses: ./.github/actions/test-cb-kem
  with:
    working-directory: "lib-q-cb-kem"
    features: "cbkem348864"
    rust-version: "stable"
    run-benchmarks: "true"
    run-security-tests: "true"
    run-constant-time: "true"
    test-algorithms: "cbkem348864,cbkem460896,cbkem6688128,cbkem6960119,cbkem8192128,cbkem8192128f"
```

#### SLH-DSA (`.github/actions/test-slh-dsa`)

```yaml
- uses: ./.github/actions/test-slh-dsa
  with:
    working-directory: "lib-q-slh-dsa"
    features: "alloc"
    rust-version: "stable"
    run-benchmarks: "true"
    run-security-tests: "true"
    run-constant-time: "true"
    test-algorithms: "sha2-128f,sha2-192f,sha2-256f,shake128f,shake192f,shake256f"
```

#### HPKE (`.github/actions/test-hpke`)

```yaml
- uses: ./.github/actions/test-hpke
  with:
    working-directory: "lib-q-hpke"
    features: "ml-kem,saturnin,shake256,hash,secure-rng"
    rust-version: "stable"
    run-benchmarks: "false"
    run-security-tests: "true"
    run-constant-time: "true"
    test-algorithms: "ml-kem512,saturnin256,shake256"
```

#### HQC (`.github/actions/test-hqc`)

```yaml
- uses: ./.github/actions/test-hqc
  with:
    working-directory: "lib-q-hqc"
    features: "alloc,hqc128,simd-avx2"
    rust-version: "stable"
    run-benchmarks: "false"
    run-security-tests: "true"
    run-simd-tests: "true"
    test-algorithms: "hqc128,hqc192,hqc256"
```

## Configuration

### Secrets and publishing auth

- **crates.io**: CD uses `./.github/actions/crates-io-auth`, which prefers the repo secret **`CARGO_REGISTRY_TOKEN`** when set; otherwise it falls back to **Trusted Publishing** (OIDC) via `rust-lang/crates-io-auth-action@v1`. For OIDC-only runs, configure each published crate under **Settings → Trusted Publishing** with `Enkom-Tech/libQ` + workflow `cd.yml` ([docs](https://crates.io/docs/trusted-publishing)).
- **npm**: `NPM_TOKEN` — required for `npm-publish` in `cd.yml`.

### Environment requirements

- **Rust**: **1.94.1** minimum (workspace `rust-version` in [Cargo.toml](Cargo.toml)).
- **Node.js**: **20** for npm publish actions; **18+** is still a reasonable local baseline for WASM tooling where not pinned by CI.
- **Development tools**: `cargo-audit`, `cargo-tarpaulin` (coverage workflows), `wasm-pack`, and `cargo-fuzz` (ZKP scheduled workflow).

## Publishing targets

### Rust crates (crates.io)

Publishing order and membership are defined **only** in `cd.yml` (tiers 0–16). In addition to umbrella and algorithm crates, the pipeline includes **platform/intrinsics**, **HQC**, **`lib-q-poseidon`**, **`lib-q-zkp`**, and the **`lib-q-stark-*`** / **`lib-q-plonky-*`** crate families. The following are representative, not exhaustive:

**Workspace-only (not in `cd.yml` publish tiers):** examples package, **`lib-q-ring`**, **`lib-q-lattice-zkp`**, **`lib-q-ring-sig`**, **`lib-q-prf`**, **`lib-q-sca-test`**, and other tooling crates—built and tested in CI but not released through this CD graph unless added to `cd.yml`.

- **`lib-q`** — Meta crate re-exporting the workspace surface.
- **`lib-q-core`**, **`lib-q-utils`**, **`lib-q-platform`**, **`lib-q-intrinsics`**, **`lib-q-random`** — Infrastructure and utilities.
- **Hashes**: **`lib-q-keccak`**, **`lib-q-sha3`**, **`lib-q-k12`**, **`lib-q-hash`**.
- **KEMs**: **`lib-q-kem`**, **`lib-q-ml-kem`**, **`lib-q-cb-kem`**, **`lib-q-hqc`**.
- **Signatures**: **`lib-q-sig`**, **`lib-q-ml-dsa`**, **`lib-q-fn-dsa`**, **`lib-q-slh-dsa`**.
- **AEAD / symmetric**: **`lib-q-aead`**, **`lib-q-saturnin`**, etc.
- **`lib-q-hpke`**, **`lib-q-zkp`**, STARK / Plonky2-related crates per tier blocks in `cd.yml`.

Any crate included in the WASM publish matrix in `cd.yml` must declare in its `Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib", "rlib"]
```

`wasm-pack` needs `cdylib` for `.wasm` artifacts; `rlib` keeps the crate usable as a normal Rust dependency.

### NPM packages (npmjs.com)

Per `cd.yml` `publish-wasm-packages` matrix (names and `out-dir` vary by crate). Manual publish: [docs/npm-publish.md](docs/npm-publish.md) (`scripts/publish-npm-ordered.sh` / `.ps1`).

- **`@lib-q/core`**, **`@lib-q/ml-kem`**, **`@lib-q/kem`**, **`@lib-q/sig`**, **`@lib-q/hash`**, **`@lib-q/utils`**, **`@lib-q/fn-dsa`**, **`@lib-q/aead`**, **`@lib-q/hpke`**, **`@lib-q/zkp`**, **`@lib-q/random`**, **`@lib-q/hqc`**, **`@lib-q/slh-dsa`**, **`@lib-q/cb-kem`**, **`@lib-q/ring-sig`**, **`@lib-q/prf`**, **`@lib-q/stark`**, **`@lib-q/plonky`**, **`@lib-q/poseidon`**, **`@lib-q/lattice-zkp`**, **`@lib-q/ring`**, **`@lib-q/types`** (22 total; see [docs/npm-coverage.md](docs/npm-coverage.md))

### Additional publishing

- **GitHub Release** with generated changelog body (see `post-release` job in `cd.yml`).

## Implemented algorithms

### Hash functions

- **Keccak** (FIPS 202) — SHA-3 family and related modes.
- **SHA-3** (FIPS 202) — SHA3 and SHAKE variants (see crate docs for exact profiles).
- **KangarooTwelve** — Keccak-based XOF (exposed via hash crates as documented in the workspace).

### Digital signatures

- **ML-DSA** (FIPS 204) — Module-Lattice Digital Signature Algorithm.
- **FN-DSA** (FIPS 206) — Falcon-based Digital Signature Algorithm (naming per project/npm metadata).
- **SLH-DSA** (FIPS 205) — Stateless Hash-Based Digital Signature Algorithm.

### Key encapsulation mechanisms (KEMs)

- **ML-KEM** (FIPS 203).
- **CB-KEM** — Code-based KEM (NIST code-based KEM family).
- **HQC** — Hamming Quasi-Cyclic KEM.

### Authenticated encryption

- **Saturnin** — Symmetric suite used in PQ-oriented constructions.

### Additional components

- **HPKE** — Hybrid Public Key Encryption.
- **Zero-knowledge proofs** — STARK-related stack and `lib-q-zkp`.
- **Platform intrinsics** — SIMD-oriented helpers where applicable.
- **Core types** — Shared types and traits across crates.

## Algorithm implementation status

**Legend:**

- Complete/Full/Integrated/Published
- Partial (has gaps)
- Basic (minimal implementation)
- Missing/Not Available

| Algorithm | Implementation | Testing | CI/CD | Publishing |
|-----------|----------------|---------|-------|------------|
| Keccak | Complete | Full | Integrated | Published |
| SHA-3 | Complete | Full | Integrated | Published |
| K12 | Complete | Full | Integrated | Published |
| Saturnin | Complete | Full | Integrated | Published |
| ML-DSA | Complete | Full | Integrated | Published |
| FN-DSA | Complete | Full | Integrated | Published |
| ML-KEM | Complete | Full | Integrated | Published |
| CB-KEM | Complete | Full | Integrated | Published |
| HQC | Evolving | See crate CI | Integrated | Published |
| SLH-DSA | Complete | Full | Integrated | Published |
| HPKE | Complete | Full | Integrated | Published |
| ZKP | Partial | Basic + scheduled fuzz | Integrated | Published |

## Testing status

### SLH-DSA

- Core, integration, KATs, ACVP, and dedicated CI action: see crate and workflow history for current counts.

### HPKE

- Core and algorithm-agnostic tests; dedicated CI action.

### HQC

- Implementation and tests are active in CI (including SIMD paths on supported runners); treat crate README and `lib-q-hqc` tests as the live status source.

## Performance

- **Pipeline time**: Depends on event type (full vs PR), typically on the order of tens of minutes for a complete main-branch run.
- **Parallelism**: Independent jobs run in parallel where GitHub Actions allows.
- **Caching**: Cargo cache keys based on lockfiles and workflow context.
