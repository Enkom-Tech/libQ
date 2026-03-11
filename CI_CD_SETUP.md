# CI/CD Setup

This document describes the CI/CD pipeline configuration for lib-Q.

## Workflows

### CI Pipeline (`.github/workflows/ci.yml`)
- **Core Validation**: Fast initial validation (15 min timeout)
- **Parallel Test Matrix**: Multiple test configurations running simultaneously
- **Cross-Platform Builds**: Multi-platform compilation
- **Performance Benchmarks**: Dedicated performance benchmarking
- **Algorithm-Specific Testing**: Specialized testing for cryptographic algorithms (ML-DSA, FN-DSA, SHA3, Keccak, K12, Saturnin)

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

### Algorithm-Specific Test Actions

#### Keccak Test Action (`.github/actions/test-keccak/`)
```yaml
- uses: ./.github/actions/test-keccak
  with:
    working-directory: "lib-q-keccak"
    features: "alloc"
    rust-version: "stable"
    run-benchmarks: "true"
    test-algorithms: "keccak-256,keccak-512"
```

#### SHA3 Test Action (`.github/actions/test-sha3/`)
```yaml
- uses: ./.github/actions/test-sha3
  with:
    working-directory: "lib-q-sha3"
    features: "std"
    rust-version: "stable"
    run-benchmarks: "true"
    test-algorithms: "sha3-256,sha3-512,shake128,shake256"
```

#### K12 Test Action (`.github/actions/test-k12/`)
```yaml
- uses: ./.github/actions/test-k12
  with:
    working-directory: "lib-q-hash"
    features: "std"
    rust-version: "stable"
    run-benchmarks: "true"
    test-algorithms: "kangaroo-twelve"
```

#### Saturnin Test Action (`.github/actions/test-saturnin/`)
```yaml
- uses: ./.github/actions/test-saturnin
  with:
    working-directory: "lib-q-saturnin"
    features: "aead,aead-short,block-cipher,hash,stream,alloc"
    rust-version: "stable"
    run-benchmarks: "false"
    test-algorithms: "aead,aead-short,block-cipher,hash,stream"
```

#### FN-DSA Test Action (`.github/actions/test-fn-dsa/`)
```yaml
- uses: ./.github/actions/test-fn-dsa
  with:
    working-directory: "lib-q-fn-dsa"
    features: "std,rand"
    rust-version: "stable"
    run-benchmarks: "true"
    run-security-tests: "true"
    run-constant-time: "true"
    test-algorithms: "fn-dsa,fn-dsa-512,fn-dsa-1024"
```

#### CB-KEM Test Action (`.github/actions/test-cb-kem/`)
```yaml
- uses: ./.github/actions/test-cb-kem
  with:
    working-directory: "lib-q-cb-kem"
    features: "cbkem348864,sha3-hash"
    rust-version: "stable"
    run-benchmarks: "true"
    run-security-tests: "true"
    run-constant-time: "true"
    test-algorithms: "cbkem348864,cbkem460896,cbkem6688128,cbkem6960119,cbkem8192128"
```

#### SLH-DSA Test Action (`.github/actions/test-slh-dsa/`)
```yaml
- uses: ./.github/actions/test-slh-dsa
  with:
    working-directory: "lib-q-slh-dsa"
    features: "alloc"
    rust-version: "stable"
    run-benchmarks: "true"
    run-security-tests: "true"
    run-constant-time: "true"
    test-algorithms: "slh-dsa-sha256-128f,slh-dsa-sha256-192f,slh-dsa-sha256-256f,slh-dsa-shake256-128f,slh-dsa-shake256-192f,slh-dsa-shake256-256f"
```

#### HPKE Test Action (`.github/actions/test-hpke/`)
```yaml
- uses: ./.github/actions/test-hpke
  with:
    working-directory: "lib-q-hpke"
    features: "std,ml-kem,saturnin"
    rust-version: "stable"
    run-benchmarks: "true"
    run-security-tests: "true"
    run-constant-time: "true"
    test-algorithms: "hpke-ml-kem-512,hpke-ml-kem-768,hpke-ml-kem-1024"
```

## Configuration

### Required Secrets
```yaml
CARGO_REGISTRY_TOKEN: "crates.io publish token"
NPM_TOKEN: "npm publish token"
```

### Environment Requirements
- **Rust 1.94+** (see workspace [Cargo.toml](Cargo.toml) `rust-version`)
- **Node.js 18+** (for WASM development)
- **Development tools**: cargo-audit, cargo-tarpaulin, wasm-pack

## Publishing Targets

### Rust Crates (crates.io)
- **`lib-q`** - Complete library (re-exports everything)
- **`lib-q-core`** - Core types and traits
- **`lib-q-keccak`** - Keccak hash functions
- **`lib-q-sha3`** - SHA-3 family hash functions
- **`lib-q-k12`** - KangarooTwelve hash function
- **`lib-q-kem`** - Key Encapsulation Mechanisms (ML-KEM, CB-KEM, HQC)
- **`lib-q-ml-kem`** - ML-KEM specific implementation
- **`lib-q-sig`** - Digital Signatures (ML-DSA, FN-DSA, SLH-DSA)
- **`lib-q-hash`** - Hash Functions (SHAKE256, SHAKE128, cSHAKE256)
- **`lib-q-aead`** - Authenticated Encryption
- **`lib-q-utils`** - Utility functions
- **`lib-q-zkp`** - Zero-Knowledge Proofs
- **`lib-q-fn-dsa`** - FN-DSA Digital Signatures (FIPS 206)
- **`lib-q-cb-kem`** - Classical McEliece KEM (Code-based post-quantum KEM)

### NPM Packages (npmjs.com)
- **`@lib-q/core`** - Complete library for Node.js
- **`@lib-q/ml-kem`** - ML-KEM only package
- **`@lib-q/kem`** - KEM-only package
- **`@lib-q/sig`** - Signature-only package
- **`@lib-q/hash`** - Hash-only package
- **`@lib-q/utils`** - Utilities-only package
- **`@lib-q/fn-dsa`** - FN-DSA signature-only package

Any crate added to the WASM publish matrix in `cd.yml` must have in its `Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib", "rlib"]
```

wasm-pack requires `cdylib` to produce `.wasm` artifacts; `rlib` is kept so the crate remains usable as a Rust dependency.

### Additional Publishing
- **GitHub release** with automated changelog generation

## Implemented Algorithms

### Hash Functions
- **Keccak** (FIPS 202) - SHA-3 family hash functions
- **SHA-3** (FIPS 202) - SHA3-256, SHA3-512, SHAKE128, SHAKE256
- **KangarooTwelve** - Fast hash function based on Keccak

### Digital Signatures
- **ML-DSA** (FIPS 204) - Module-Lattice Digital Signature Algorithm
- **FN-DSA** (FIPS 206) - Falcon-based Digital Signature Algorithm
- **SLH-DSA** (FIPS 205) - Stateless Hash-based Digital Signature Algorithm

### Key Encapsulation Mechanisms (KEMs)
- **ML-KEM** (FIPS 203) - Module-Lattice Key Encapsulation Mechanism
- **CB-KEM** - Code-based post-quantum KEM
- **HQC** - Hamming Quasi-Cyclic KEM

### Authenticated Encryption
- **Saturnin** - Post-quantum symmetric algorithm suite

### Additional Components
- **HPKE** - Hybrid Public Key Encryption
- **Zero-Knowledge Proofs** - zk-STARKs implementation
- **Platform Intrinsics** - SIMD optimizations for x86_64 and ARM64
- **Core Types** - Common types and traits for all algorithms

## Algorithm Implementation Status

**Legend:**
- ✅ Complete/Full/Integrated/Published
- ⚠️ Partial (has issues)
- 🔄 Basic (minimal implementation)
- ❌ Missing/Not Available

| Algorithm | Implementation | Testing | CI/CD | Publishing |
|-----------|---------------|---------|-------|------------|
| Keccak | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| SHA-3 | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| K12 | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| Saturnin | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| ML-DSA | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| FN-DSA | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| ML-KEM | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| CB-KEM | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| HQC | 🔄 Planned | 🔄 Basic | ✅ Integrated | ✅ Published |
| SLH-DSA | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| HPKE | ✅ Complete | ✅ Full | ✅ Integrated | ✅ Published |
| ZKP | 🔄 Partial | 🔄 Basic | ✅ Integrated | ✅ Published |

## Testing Status

### SLH-DSA Testing Status
- **Core functionality**: ✅ 184/184 unit tests passing
- **Integration tests**: ✅ All tests passing
- **Known Answer Tests**: ✅ All passing
- **ACVP validation**: ✅ All passing
- **CI/CD Integration**: ✅ Fully integrated with dedicated test action

### HPKE Testing Status
- **Core functionality**: ✅ 71/71 unit tests passing
- **Algorithm-agnostic tests**: ✅ 5/5 tests passing
- **Documentation tests**: ✅ All doc tests passing
- **CI/CD Integration**: ✅ Fully integrated with dedicated test action

### HQC Implementation Status
- **Implementation**: 🔄 Planned (placeholder implementation with "(planned)" indicators)
- **API Integration**: ✅ Available in `available_algorithms()` with clear status indicators
- **Feature Flag**: ✅ `hqc` feature flag available
- **Future Work**: Full implementation planned for future releases

## Performance
- **Pipeline execution time**: ~25-35 minutes
- **Parallel execution**: Jobs run in parallel where possible
- **Smart caching**: Optimized cache keys and dependency management