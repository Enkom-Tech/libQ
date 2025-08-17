# lib-Q Development Guide

This guide covers the development setup, CI/CD pipeline, security practices, and workflow for contributing to lib-Q.

## Quick Start

### Prerequisites

- **Rust 1.70+** (latest stable recommended)
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
cd lib-q

# Install pre-commit hooks
cargo install pre-commit
pre-commit install

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
cargo test --all-features
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

- **NO classical algorithms**: RSA, ECC, AES, SHA-256, etc.
- **ONLY NIST-approved post-quantum algorithms**
- **ONLY SHA-3 family hash functions** (SHAKE256, SHAKE128, cSHAKE256)
- **Constant-time operations** for all cryptographic functions
- **Proper memory zeroization** using the `zeroize` crate

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

// ❌ Bad: Classical crypto
use sha2::Sha256;  // Not allowed!

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

- **Rust Crate**: `crates.io` (automated)
- **NPM Package**: `@lib-q/core` (automated)
- **GitHub Release**: With changelog (automated)

## Development Tools

### Required Tools

```bash
# Install development tools
cargo install cargo-audit cargo-tarpaulin wasm-pack cargo-outdated

# Install pre-commit hooks
cargo install pre-commit
pre-commit install
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
   # Clean and rebuild
   cargo clean
   wasm-pack build --target nodejs --features "wasm,all-algorithms"
   ```

2. **Security Check Failures**
   ```bash
   # Run with verbose output
   ./scripts/security-check.sh --verbose
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
2. **Email** security@lib-q.org
3. **Use** the security report template
4. **Follow** responsible disclosure

## Support

- **Documentation**: [docs.rs/lib-q](https://docs.rs/lib-q)
- **Issues**: [GitHub Issues](https://github.com/Enkom-Tech/libQ/issues)
- **Security**: security@lib-q.org
- **Discussions**: [GitHub Discussions](https://github.com/Enkom-Tech/libQ/discussions)

## License

By contributing to lib-Q, you agree that your contributions will be licensed under the Apache 2.0 License.
