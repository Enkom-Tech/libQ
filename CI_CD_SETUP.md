# CI/CD Setup

This document describes the CI/CD pipeline configuration for lib-Q.

## Workflows

### CI Pipeline (`.github/workflows/ci.yml`)
- **Core Validation**: Fast initial validation (15 min timeout)
- **Parallel Test Matrix**: Multiple test configurations running simultaneously
- **Cross-Platform Builds**: Multi-platform compilation
- **Performance Benchmarks**: Dedicated performance benchmarking
- **Algorithm-Specific Testing**: Specialized testing for cryptographic algorithms

### CD Pipeline (`.github/workflows/cd.yml`)
- **Pre-Release Validation**: Version consistency checking
- **Parallel Publishing**: Rust crates and WASM packages published simultaneously
- **Post-Release Tasks**: Automated changelog generation and release creation
- **Security Verification**: Post-release security validation

### Security Pipeline (`.github/workflows/security.yml`)
- **Core Security Validation**: Fast initial security checks
- **Parallel Security Jobs**: Multiple security validations running simultaneously
- **Security Reporting**: Security status reporting with PR integration

### PR Validation (`.github/workflows/pr.yml`)
- **Core Validation**: Fast initial PR validation
- **Parallel Security Checks**: Security validation running in parallel
- **Test Coverage**: Coverage analysis

## Composite Actions

### Security Validation Action (`.github/actions/security-validation/`)
```yaml
- uses: ./.github/actions/security-validation
  with:
    features: "all-algorithms"
    run-nist-validation: "true"
    run-crypto-validation: "true"
    run-constant-time: "true"
    run-memory-safety: "true"
    run-dependency-audit: "true"
```

### Performance Benchmark Action (`.github/actions/performance-benchmark/`)
```yaml
- uses: ./.github/actions/performance-benchmark
  with:
    features: "all-algorithms"
    iterations: "100"
    save-results: "true"
    compare-baseline: "false"
```

## Configuration

### Required Secrets
```yaml
CARGO_REGISTRY_TOKEN: "crates.io publish token"
NPM_TOKEN: "npm publish token"
```

### Environment Requirements
- **Rust 1.70+**
- **Node.js 18+** (for WASM development)
- **Development tools**: cargo-audit, cargo-tarpaulin, wasm-pack

## Publishing Targets
- **Rust crate**: `crates.io` (lib-q)
- **NPM package**: `@lib-q/core`
- **GitHub release** with automated changelog generation

## Performance
- **Pipeline execution time**: ~25-35 minutes
- **Parallel execution**: Jobs run in parallel where possible
- **Smart caching**: Optimized cache keys and dependency management