# GitHub Actions for lib-Q

This directory contains reusable GitHub Actions for the lib-Q project. These actions provide standardized testing and validation workflows for different components of the library.

## Available Actions

### test-keccak
Tests the Keccak sponge function implementation with comprehensive validation.

**Inputs:**
- `working-directory`: Working directory for keccak crate (default: `lib-q-sponge/keccak`)
- `features`: Features to enable for testing (default: `"asm"`)
- `rust-version`: Rust toolchain version to use (default: `"stable"`)
- `run-benchmarks`: Whether to run benchmarks (requires nightly) (default: `"false"`)
- `run-simd`: Whether to run SIMD tests (requires nightly) (default: `"false"`)

**Features:**
- Security audit with cargo audit
- Code formatting checks with cargo fmt
- Clippy linting with strict warnings
- Build tests with different feature combinations
- Cross-compilation tests (ARM64)
- WASM compilation tests
- SIMD tests (nightly only)
- Benchmarking (nightly only)

### test-ascon
Tests the Ascon sponge function implementation with comprehensive validation.

**Inputs:**
- `working-directory`: Working directory for ascon crate (default: `lib-q-sponge/ascon`)
- `features`: Features to enable for testing (default: `""`)
- `rust-version`: Rust toolchain version to use (default: `"stable"`)
- `run-benchmarks`: Whether to run benchmarks (requires nightly) (default: `"false"`)

**Features:**
- Security audit with cargo audit
- Code formatting checks with cargo fmt
- Clippy linting with strict warnings
- Build tests with different feature combinations
- Cross-compilation tests (ARM64)
- WASM compilation tests
- Constant-time operation verification
- Benchmarking (nightly only)

### test-lib-q-sponge
Tests the main lib-q-sponge crate integration and re-export functionality.

**Inputs:**
- `working-directory`: Working directory for lib-q-sponge crate (default: `lib-q-sponge`)
- `features`: Features to enable for testing (default: `"asm"`)
- `rust-version`: Rust toolchain version to use (default: `"stable"`)
- `run-benchmarks`: Whether to run benchmarks (requires nightly) (default: `"false"`)

**Features:**
- Security audit with cargo audit
- Code formatting checks with cargo fmt
- Clippy linting with strict warnings
- Build tests with different feature combinations
- Integration tests for Keccak re-exports
- Integration tests for Ascon re-exports
- Cross-compilation tests (ARM64)
- WASM compilation tests
- Documentation generation
- Benchmarking (nightly only)

### test-sha3
Tests the SHA-3 hash function implementations integrated into lib-q-hash.

**Inputs:**
- `working-directory`: Working directory for hash crate (default: `lib-q-hash`)
- `features`: Features to enable for testing (default: `"alloc,oid"`)
- `rust-version`: Rust toolchain version to use (default: `"stable"`)
- `test-algorithms`: Comma-separated list of algorithms to test

**Features:**
- Security audit with cargo audit
- Code formatting checks with cargo fmt
- Clippy linting with strict warnings
- Build tests with different feature combinations
- Algorithm-specific tests
- Cross-compilation tests (ARM64)
- WASM compilation tests

### test-k12
Tests the KangarooTwelve (K12) hash function implementation integrated into lib-q-hash.

**Inputs:**
- `working-directory`: Working directory for hash crate (default: `lib-q-hash`)
- `features`: Features to enable for testing (default: `"alloc,oid"`)
- `rust-version`: Rust toolchain version to use (default: `"stable"`)
- `run-benchmarks`: Whether to run benchmarks (requires nightly) (default: `"false"`)

**Features:**
- Security audit with cargo audit
- Code formatting checks with cargo fmt
- Clippy linting with strict warnings
- Build tests with different feature combinations
- K12-specific tests
- Cross-compilation tests (ARM64)
- WASM compilation tests
- Benchmarking (nightly only)

## Usage Examples

### Basic Usage
```yaml
- uses: ./.github/actions/test-keccak
  with:
    working-directory: lib-q-sponge/keccak
    features: "asm"
    rust-version: "stable"
```

### With Nightly Features
```yaml
- uses: ./.github/actions/test-ascon
  with:
    working-directory: lib-q-sponge/ascon
    rust-version: "nightly"
    run-benchmarks: "true"
```

### Integration Testing
```yaml
- uses: ./.github/actions/test-lib-q-sponge
  with:
    working-directory: lib-q-sponge
    features: "asm"
    rust-version: "stable"
```

## Security Features

All actions include comprehensive security validation:

1. **Security Audits**: Cargo audit with strict warning enforcement
2. **Constant-Time Verification**: Tests for constant-time operations where applicable
3. **Memory Safety**: Clippy checks for unsafe code patterns
4. **Cross-Platform Validation**: Tests on multiple architectures and platforms
5. **WASM Compatibility**: Ensures cryptographic functions work in WebAssembly environments

## Performance Features

Actions support performance testing when using nightly Rust:

1. **Benchmarking**: Automated performance benchmarks
2. **SIMD Testing**: Vector instruction set testing
3. **Cross-Compilation**: ARM64 target validation
4. **Feature Combinations**: Testing with different optimization features

## Integration Testing

The lib-q-sponge action includes comprehensive integration tests:

1. **Re-export Validation**: Ensures Keccak and Ascon functions are properly re-exported
2. **Cross-Sponge Testing**: Verifies both sponge functions work together
3. **API Consistency**: Tests that the unified API works correctly
4. **Documentation Generation**: Ensures documentation builds correctly

## Best Practices

1. **Always use the latest stable Rust** for production builds
2. **Enable nightly features** for comprehensive testing and benchmarking
3. **Test all feature combinations** to ensure compatibility
4. **Run cross-compilation tests** for embedded and WASM targets
5. **Verify constant-time operations** for security-critical functions
6. **Include integration tests** to ensure components work together

## Troubleshooting

### Common Issues

1. **Build Failures**: Check that all dependencies are properly configured
2. **Test Failures**: Ensure test data and expected outputs are correct
3. **Performance Issues**: Verify that SIMD features are enabled for target platforms
4. **Cross-Compilation Issues**: Check that target toolchains are properly installed

### Debugging

1. **Enable Verbose Output**: Add `--verbose` flags to cargo commands
2. **Check Feature Dependencies**: Verify that required features are enabled
3. **Validate Test Data**: Ensure test vectors match expected cryptographic outputs
4. **Review Security Audits**: Address any security warnings from cargo audit
