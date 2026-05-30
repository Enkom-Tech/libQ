# Contributing to lib-Q

Thank you for your interest in contributing to lib-Q! This document outlines the development practices, security guidelines, and contribution process.

## Security-First Development

lib-Q is a cryptography library, which means security is paramount. All contributions must follow these principles:

### 1. **Post-quantum asymmetric and SHA-3–aligned design**
- **Do not** use **classical public-key** schemes (RSA, finite-field/ECC DH, ECDSA, Ed25519, etc.) for confidentiality, authenticity, or integrity in the library’s PQC mission; follow [SECURITY.md](SECURITY.md).
- **Do** use **NIST-track / standardized PQC** (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, CB-KEM family, etc.) for those roles.
- **Hashes / XOFs** in new cryptographic design should stay in the **SHA-3 family** (SHAKE, cSHAKE, and related workspace APIs). Symmetric choices follow existing crate patterns (e.g. Saturnin, SHAKE-based AEAD). Some standardized or infrastructure paths may use other primitives already under review—mirror existing crates rather than inventing new classical stacks.
- **ZKP**: The production-facing transparent proof stack is **zk-STARK–based** (`lib-q-zkp` and related crates). **`lib-q-lattice-zkp`** is an explicit research path for module-lattice statements. Do not add pairing-based or classical-curve trusted-setup SNARKs as the primary PQ story without maintainer agreement.

### 2. **Constant-Time Operations**
- All cryptographic operations must be constant-time
- No branching based on secret data
- Use constant-time comparison functions
- Avoid table lookups with secret indices

### 3. **Memory Safety**
- Use Rust's ownership model to prevent memory leaks
- Zeroize sensitive memory after use
- No unsafe code without thorough review
- Validate all input sizes and bounds

### 4. **Side-Channel Resistance**
- No timing attacks
- No power analysis vulnerabilities
- No cache timing attacks
- Use secure random number generation

### 5. **WebAssembly and parallelism**
- Do **not** enable **`parallel`** on `lib-q-stark-rayon`, **`parallel`** on `lib-q-stark-util`, or **`parallelhash`** on `lib-q-hash` for `wasm32-unknown-unknown` builds; these combinations fail with `compile_error!` by design.
- Prefer `cargo check --target wasm32-unknown-unknown` with the workspace `getrandom` cfg from [docs/wasm-compilation.md](docs/wasm-compilation.md) when touching RNG or feature graphs that pull `getrandom`.

## Development Setup

For full development workflow, CI/CD pipeline, and troubleshooting, see [DEVELOPMENT.md](DEVELOPMENT.md).

### Prerequisites
- Rust 1.96.0+ (see [Cargo.toml](Cargo.toml) `rust-version`; latest stable recommended)
- `wasm-pack` for WASM compilation
- `cargo-audit` for security audits
- `cargo-tarpaulin` for code coverage

### Setup Commands
```bash
# Install development tools
cargo install wasm-pack cargo-audit cargo-tarpaulin

# Clone and setup
git clone https://github.com/Enkom-Tech/libQ.git
cd libQ
cargo build
```

## Code Standards

### Rust Code Style
- Follow Rust style guidelines
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Maximum line length: 100 characters

### Linting (Clippy)
Before submitting, ensure there are no Clippy issues. Run from the workspace root:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

CI runs Clippy with `-D warnings` (see `.github/workflows/ci.yml`); use the command above locally so PRs match the gate.

### Documentation
- All public APIs must be documented
- Include usage examples
- Document security considerations
- Use `cargo doc` to generate documentation

### Testing Requirements
- **100% code coverage** for cryptographic functions
- Property-based testing with `proptest`
- Property-based or fuzz-style tests for public APIs (continuous fuzzing e.g. `cargo fuzz` encouraged where applicable)
- Constant-time verification tests
- WASM compatibility tests

## Security Review Process

### Before Submitting
1. **Self-review**: Check your code against security guidelines
2. **Static analysis**: Run `cargo audit` and `cargo clippy --all-targets --all-features`
3. **Testing**: Ensure all tests pass, including WASM tests
4. **Documentation**: Update relevant documentation

### Review Checklist
- [ ] No classical cryptographic algorithms used
- [ ] Only NIST-approved post-quantum algorithms used
- [ ] Only SHA-3 family hash functions used (SHAKE256, SHAKE128, cSHAKE256)
- [ ] Only post-quantum secure ZKP systems used (zk-STARKs)
- [ ] All operations are constant-time
- [ ] Memory is properly zeroized
- [ ] Input validation is comprehensive
- [ ] Error handling is secure
- [ ] No unsafe code (or thoroughly justified)
- [ ] Tests cover edge cases and error conditions
- [ ] Documentation is complete and accurate

## Testing Guidelines

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_constant_time_operation() {
        // Test that operation is constant-time
    }

    proptest! {
        #[test]
        fn test_property_based(input: Vec<u8>) {
            // Property-based test
        }
    }
}
```

### Integration Tests
- Test complete workflows
- Test error conditions
- Test WASM compilation
- Test performance characteristics

### Property-based / fuzz-style tests
Use `proptest` or `arbitrary` to exercise public APIs with generated inputs. Continuous fuzzing (e.g. `cargo fuzz`) is encouraged where applicable.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_encryption(input in prop::collection::vec(any::<u8>(), 0..MAX_SIZE)) {
            let result = encrypt(&input, &[0u8; 32]).unwrap();
            assert_eq!(decrypt(&result, &[0u8; 32]).unwrap(), input);
        }
    }
}
```

## Performance Requirements

### Benchmarks
- All cryptographic operations must be benchmarked
- Compare against reference implementations
- Monitor for performance regressions
- WASM performance must be acceptable

### Memory Usage
- Minimize memory allocations
- Use stack allocation when possible
- Profile memory usage in WASM

## WASM Compatibility

### Compilation
```bash
# Build for WASM
wasm-pack build --target web
wasm-pack build --target nodejs
```

### Testing
```bash
# Test WASM compilation
wasm-pack test --headless --firefox
wasm-pack test --headless --chrome
```

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes with a signed-off commit: `git commit -s -m 'Add amazing feature'`
4. **Push** to the branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### PR Template
```markdown
## Description
Brief description of changes

## Security Considerations
- [ ] No classical crypto used
- [ ] Only NIST-approved post-quantum algorithms used
- [ ] Constant-time operations verified
- [ ] Memory safety ensured
- [ ] Input validation complete

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] WASM tests pass
- [ ] Performance benchmarks updated

## Documentation
- [ ] API documentation updated
- [ ] Examples added/updated
- [ ] Security notes documented
```

## Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes to API
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

## Getting Help

- **Security issues**: Email github@enkom.dev (private)
- **General questions**: Open an issue on GitHub
- **Development questions**: Join our Discord/Matrix
- **AI-Generated Wiki**: [https://deepwiki.com/Enkom-Tech/libQ](https://deepwiki.com/Enkom-Tech/libQ)

## Roadmap Contributions

We welcome contributions to our roadmap:
- Algorithm implementations
- Performance optimizations
- Platform support
- Documentation improvements
- Security audits

## License

By contributing to lib-Q, you agree that your contributions will be licensed under the Apache 2.0 License.

Security is everyone's responsibility.
