# Contributing to lib-Q

Thank you for your interest in contributing to lib-Q! This document outlines the development practices, security guidelines, and contribution process.

## Security-First Development

lib-Q is a cryptography library, which means security is paramount. All contributions must follow these principles:

### 1. **Zero Classical Crypto**
- **NEVER** use classical cryptographic algorithms (RSA, ECC, AES, SHA-256, etc.)
- **ONLY** use NIST-approved post-quantum algorithms
- **ONLY** use SHA-3 family hash functions (SHAKE256, SHAKE128, cSHAKE256)
- **ONLY** use post-quantum secure ZKP systems (zk-STARKs, not classical SNARKs)
- All classical crypto is considered broken in our threat model

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

## Development Setup

### Prerequisites
- Rust 1.70+ (latest stable recommended)
- `wasm-pack` for WASM compilation
- `cargo-audit` for security audits
- `cargo-tarpaulin` for code coverage

### Setup Commands
```bash
# Install development tools
cargo install wasm-pack cargo-audit cargo-tarpaulin

# Clone and setup
git clone https://github.com/lib-q/lib-q.git
cd lib-q
cargo build
```

## Code Standards

### Rust Code Style
- Follow Rust style guidelines
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Maximum line length: 100 characters

### Documentation
- All public APIs must be documented
- Include usage examples
- Document security considerations
- Use `cargo doc` to generate documentation

### Testing Requirements
- **100% code coverage** for cryptographic functions
- Property-based testing with `proptest`
- Fuzzing tests for all public APIs
- Constant-time verification tests
- WASM compatibility tests

## Security Review Process

### Before Submitting
1. **Self-review**: Check your code against security guidelines
2. **Static analysis**: Run `cargo audit` and `cargo clippy`
3. **Testing**: Ensure all tests pass, including WASM tests
4. **Documentation**: Update relevant documentation

### Review Checklist
- [ ] No classical cryptographic algorithms used
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

### Fuzzing Tests
```rust
#[cfg(test)]
mod fuzz {
    use super::*;
    use arbitrary::Arbitrary;

    #[derive(Arbitrary)]
    struct FuzzInput {
        data: Vec<u8>,
        key: Vec<u8>,
    }

    #[test]
    fn fuzz_encryption(input: FuzzInput) {
        // Fuzzing test
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
3. **Commit** your changes: `git commit -m 'Add amazing feature'`
4. **Push** to the branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### PR Template
```markdown
## Description
Brief description of changes

## Security Considerations
- [ ] No classical crypto used
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

- **Security issues**: Email security@lib-q.org (private)
- **General questions**: Open an issue on GitHub
- **Development questions**: Join our Discord/Matrix

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
