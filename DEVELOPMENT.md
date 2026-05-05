# lib-Q Development Guide

This guide covers the development setup, CI/CD pipeline, security practices, and workflow for contributing to lib-Q. For the contribution process, security checklist, and PR template, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quick Start

### Prerequisites

- **Rust 1.94.1+** (see [Cargo.toml](Cargo.toml) `rust-version`; latest stable recommended)
- **Git** with proper signing setup
- **Node.js 18+** (for WASM development)
- **Development tools** (see installation below)

### Installation

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install development tools
cargo install cargo-audit cargo-tarpaulin wasm-pack cargo-outdated

# Clone repository
git clone https://github.com/Enkom-Tech/libQ.git
cd libQ

# Optional: install pre-commit hooks (Python; use pip or conda)
# pip install pre-commit && pre-commit install

# Verify setup
./scripts/security-check.sh  # Linux/macOS
# or
./scripts/security-check.ps1  # Windows
```

## CI/CD Pipeline Overview

### Workflows

1. **CI (`ci.yml`)**: Runs on every push and PR
   - Security audit and dependency scanning
   - Code quality checks (formatting, linting)
   - Comprehensive testing across platforms
   - WASM compilation and testing
   - Performance benchmarks
   - Documentation generation
   - Cross-platform compilation

2. **CD (`cd.yml`)**: Runs on version tags
   - Pre-release validation
   - Automated publishing to crates.io
   - WASM package publishing to NPM
   - GitHub release creation
   - Post-release security verification

3. **Security (`security.yml`)**: Dedicated security validation
   - Cryptographic algorithm validation
   - Constant-time verification
   - Memory safety checks
   - Post-quantum compliance
   - WASM security validation

4. **PR Validation (`pr.yml`)**: Pull request specific checks
   - Code quality and security
   - Test coverage analysis
   - Performance regression detection
   - Documentation validation

5. **Coverage (`coverage.yml`)**: Code coverage reporting

6. **Security-critical coverage (`security-critical-coverage.yml`)**: Scheduled / manual tarpaulin on high-risk façade paths (thresholds via `scripts/check-coverage-metrics.sh`)

7. **ZKP fuzz (`zkp-fuzz-scheduled.yml`)**: Weekly / manual bounded `cargo-fuzz` runs under `lib-q-zkp/fuzz` (does not gate PR CI)

For composite actions, path triggers, and job-level detail, see [CI_CD_SETUP.md](CI_CD_SETUP.md).

### Security Checks

The CI/CD pipeline includes comprehensive security validation:

- **NIST Compliance**: Ensures only post-quantum algorithms are used
- **Constant-Time Operations**: Validates timing attack resistance
- **Memory Safety**: Checks for proper zeroization and memory handling
- **Dependency Security**: Automated vulnerability scanning
- **Cryptographic Validation**: Algorithm-specific security checks

## Development Workflow

### 1. Feature Development

```bash
# Create feature branch
git checkout -b feature/amazing-feature

# Make changes following security guidelines
# (see Security Guidelines section)

# Run local checks
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/security-check.sh

# Commit with proper message
git commit -s -m "feat: add amazing feature

- Implements new post-quantum algorithm
- Includes comprehensive tests
- Follows security guidelines
- No classical crypto introduced"
```

### 2. Security Review Process

Every change must pass security review:

1. **Self-Review**: Run security checks locally
2. **Automated Checks**: CI pipeline validates security
3. **Manual Review**: Security team reviews cryptographic changes
4. **Final Approval**: Maintainer approval required

### 3. Pull Request Process

1. **Create PR** with detailed description
2. **Automated Checks** run (CI, security, coverage)
3. **Security Review** by security team
4. **Code Review** by maintainers
5. **Final Approval** and merge

## Security Guidelines

### Cryptographic Requirements

Align with [SECURITY.md](SECURITY.md): **no classical public-key cryptography** (RSA, finite-field/ECC DH, ECDSA, Ed25519, etc.) for confidentiality, authenticity, or integrity in the project’s PQC threat model. **Hashing and XOFs** in the cryptographic design target the **SHA-3 family** (SHAKE, cSHAKE, and related APIs exposed by workspace crates). **Post-quantum asymmetric** constructions follow NIST-standardized modules (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, CB-KEM family, etc.).

Symmetric and ancillary primitives may appear inside **reviewed, standards-aligned paths** (for example Saturnin and SHAKE-based AEAD in HPKE tiers, or components required by specific NIST PQC or RNG constructions). Do not introduce classical asymmetric schemes as the primary security mechanism.

- **Constant-time intent** on sensitive cryptographic paths (full guarantees need target-specific review)
- **Proper memory zeroization** using the `zeroize` crate where types permit

### Code Security

```rust
// Good: Constant-time comparison
use subtle::ConstantTimeEq;

fn verify_signature(sig: &[u8], expected: &[u8]) -> bool {
    sig.ct_eq(expected).unwrap_u8() == 1
}

// Good: Memory zeroization
use zeroize::Zeroize;

#[derive(Zeroize)]
struct SecretKey {
    key: [u8; 32],
}

// Good: Input validation
fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() > MAX_SIZE {
        return Err(Error::InputTooLarge);
    }
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeySize);
    }
    // ... encryption logic
}

// ❌ Bad: Classical public-key or forbidden hash families for security guarantees
// (Do not use RSA/ECC/classical signatures for those roles; avoid non–SHA-3 hashes
//  as the primary design hash where SECURITY.md applies.)

// ❌ Bad: Timing attack vulnerable
fn verify_signature(sig: &[u8], expected: &[u8]) -> bool {
    sig == expected  // Timing attack vulnerable!
}
```

### Testing Requirements

- **100% code coverage** for cryptographic functions
- **Property-based testing** with `proptest`
- **Constant-time verification** tests
- **Fuzzing tests** for all public APIs
- **WASM compatibility** tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_constant_time_operation() {
        // Test that operation is constant-time
        let input1 = [1u8; 32];
        let input2 = [2u8; 32];
        
        // Measure timing for both inputs
        // Should be statistically similar
    }

    proptest! {
        #[test]
        fn test_property_based(input: Vec<u8>) {
            // Property-based test
            if input.len() <= MAX_SIZE {
                let result = encrypt(&input, &[0u8; 32]).unwrap();
                assert_eq!(decrypt(&result, &[0u8; 32]).unwrap(), input);
            }
        }
    }
}
```

## Publishing Process

### Version Management

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Release Process

1. **Version Bump**: Update `Cargo.toml` version
2. **Create Tag**: `git tag v1.0.0`
3. **Push Tag**: `git push origin v1.0.0`
4. **Automated Release**: CI/CD handles publishing
5. **Verification**: Post-release security checks

### Publishing Targets

- **Rust crates**: Every workspace member except the `examples` harness is published to `crates.io` in dependency order (see `.github/workflows/cd.yml`; CI guards that new members are included).
- **NPM packages** (WASM bundles via `wasm-pack` in CD): `@lib-q/core`, `@lib-q/ml-kem`, `@lib-q/kem`, `@lib-q/sig`, `@lib-q/fn-dsa`, `@lib-q/hash`, `@lib-q/utils`.
- **GitHub Release**: With changelog (automated)

## Development Tools

### Required Tools

```bash
# Install development tools
cargo install cargo-audit cargo-tarpaulin wasm-pack cargo-outdated

# Optional: pre-commit hooks (Python — pip install pre-commit && pre-commit install)
```

### Useful Scripts

- `./scripts/security-check.sh`: Security validation
- `cargo audit`: Dependency vulnerability scanning
- `cargo tarpaulin`: Code coverage analysis
- `wasm-pack build`: WASM compilation
- `cargo bench`: Performance benchmarking

### IDE Configuration

#### VS Code

```json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.cargo.features": "all",
    "rust-analyzer.procMacro.enable": true,
    "rust-analyzer.cargo.buildScripts.enable": true
}
```

#### IntelliJ IDEA / CLion

- Enable Rust plugin
- Configure clippy as external tool
- Set up code formatting rules

## Troubleshooting

### Common Issues

1. **WASM Build Failures**
   ```bash
   # Clean and rebuild; match CI getrandom + panic settings for wasm32-unknown-unknown
   # (see README "no_std, embedded, and WebAssembly" and .github/actions/wasm-build/action.yml).
   cargo clean
   wasm-pack build --target nodejs --features "wasm,all-algorithms"
   ```

2. **Security Check Failures**
   ```bash
   # The script has no --verbose flag; trace shell steps if needed:
   bash -x ./scripts/security-check.sh
   # Or run individual checks (cargo audit, wasm-pack, tarpaulin) from the script body.
   ```

3. **Test Failures**
   ```bash
   # Run specific test
   cargo test test_name --features "all-algorithms"
   
   # Run with output
   cargo test -- --nocapture
   ```

### Performance Issues

- Use `cargo bench` to identify regressions
- Profile with `cargo flamegraph`
- Check WASM performance with browser dev tools

## Contributing Guidelines

### Code Style

- Follow Rust style guidelines
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Maximum line length: 100 characters

### Documentation

- All public APIs must be documented
- Include usage examples
- Document security considerations
- Use `cargo doc` to generate documentation

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### Security Reporting

For security issues:

1. **DO NOT** create public issues
2. **Email** github@enkom.dev
3. **Use** the security report template
4. **Follow** responsible disclosure

## Support

- **Documentation**: [docs.rs/lib-q](https://docs.rs/lib-q)
- **Issues**: [GitHub Issues](https://github.com/Enkom-Tech/libQ/issues)
- **Security**: github@enkom.dev
- **Discussions**: [GitHub Discussions](https://github.com/Enkom-Tech/libQ/discussions)

## License

By contributing to lib-Q, you agree that your contributions will be licensed under the Apache 2.0 License.
