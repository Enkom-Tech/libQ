# GitHub Actions for lib-Q

This directory contains reusable GitHub Actions for the lib-Q project. These actions provide standardized testing and validation workflows for different components of the library.

## Available Actions

### rust-build
Comprehensive Rust build action with security validation and quality checks.

**Inputs:**
- `working-directory`: Working directory for the crate (default: `"."`)
- `features`: Features to enable for building (default: `""`)
- `rust-version`: Rust toolchain version to use (default: `"stable"`)
- `run-security-audit`: Whether to run security audit (default: `"true"`)
- `run-format-check`: Whether to run format check (default: `"true"`)
- `run-clippy`: Whether to run clippy linting (default: `"true"`)
- `run-tests`: Whether to run tests (default: `"true"`)
- `run-wasm-check`: Whether to run WASM compilation check (default: `"false"`)
- `run-cross-compilation`: Whether to run cross-compilation tests (default: `"false"`)
- `target`: Cross-compilation target (if enabled) (default: `"aarch64-unknown-linux-gnu"`)

**Features:**
- Security audit with cargo audit
- Code formatting checks with cargo fmt
- Clippy linting with strict warnings
- Build tests with different feature combinations
- WASM compilation tests
- Cross-compilation tests

### rust-test
Reusable Rust test action with matrix support and comprehensive testing.

**Inputs:**
- `working-directory`: Working directory for the crate (default: `"."`)
- `features`: Features to enable for testing (default: `""`)
- `package`: Specific package to test (optional) (default: `""`)
- `rust-version`: Rust toolchain version to use (default: `"stable"`)
- `run-release-tests`: Whether to run release tests (default: `"true"`)
- `run-coverage`: Whether to run coverage tests (default: `"false"`)
- `coverage-threshold`: Minimum coverage threshold percentage (default: `"95"`)

**Features:**
- Matrix-based testing support
- Release and debug test runs
- Coverage reporting with thresholds
- Package-specific testing
- Comprehensive test execution

### wasm-build
Reusable WASM build action with multiple targets and package support.

**Inputs:**
- `working-directory`: Working directory for the crate (default: `"."`)
- `features`: Features to enable for building (default: `""`)
- `targets`: Comma-separated list of targets (web,nodejs) (default: `"web,nodejs"`)
- `rust-version`: Rust toolchain version to use (default: `"stable"`)
- `verify-artifacts`: Whether to verify build artifacts (default: `"true"`)
- `cache-pkg`: Whether to cache pkg directory (default: `"true"`)

**Features:**
- Multiple target support (web, nodejs)
- Artifact verification
- Caching optimization
- Feature-based builds

### crate-publish
Reusable action for publishing Rust crates to crates.io.

**Inputs:**
- `package`: Package name to publish (required)
- `token`: Cargo registry token (required)
- `working-directory`: Working directory for the crate (default: `"."`)
- `dry-run`: Whether to do a dry run (default: `"false"`)

**Features:**
- Token validation
- Dry run support
- Error handling
- Consistent publishing workflow

### npm-publish
Reusable action for publishing NPM packages.

**Inputs:**
- `package-name`: NPM package name (required)
- `package-description`: Package description (required)
- `package-keywords`: Comma-separated package keywords (required)
- `working-directory`: Working directory containing the package (default: `"pkg"`)
- `token`: NPM token (required)
- `version`: Package version (required)
- `dry-run`: Whether to do a dry run (default: `"false"`)

**Features:**
- Automatic package metadata configuration
- Token validation
- Dry run support
- Consistent NPM publishing workflow

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

### Basic Build Usage
```yaml
- uses: ./.github/actions/rust-build
  with:
    working-directory: "."
    features: "all-algorithms"
    run-security-audit: "true"
    run-format-check: "true"
    run-clippy: "true"
    run-tests: "true"
```

### Matrix Testing
```yaml
- uses: ./.github/actions/rust-test
  with:
    features: ${{ matrix.features }}
    package: ${{ matrix.package || '' }}
    run-release-tests: "true"
    run-coverage: "false"
```

### WASM Building
```yaml
- uses: ./.github/actions/wasm-build
  with:
    working-directory: "lib-q-kem"
    features: "wasm,ml-kem"
    targets: "web,nodejs"
    verify-artifacts: "true"
```

### Crate Publishing
```yaml
- uses: ./.github/actions/crate-publish
  with:
    package: "lib-q-core"
    token: ${{ secrets.CARGO_REGISTRY_TOKEN }}
    dry-run: "false"
```

### NPM Publishing
```yaml
- uses: ./.github/actions/npm-publish
  with:
    package-name: "@lib-q/core"
    package-description: "Post-quantum cryptography library for Node.js"
    package-keywords: "cryptography,post-quantum,security,wasm"
    token: ${{ secrets.NPM_TOKEN }}
    version: ${{ github.ref_name }}
```

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

## Refactoring Benefits

The new reusable actions provide significant benefits:

1. **Eliminated Duplication**: Reduced ~1000+ lines of duplicated code across workflows
2. **Consistent Patterns**: Standardized build, test, and publish workflows
3. **Matrix Support**: Efficient parallel execution of similar tasks
4. **Maintainability**: Single source of truth for common operations
5. **Error Handling**: Centralized error handling and validation
6. **Security**: Consistent security validation across all workflows

## Best Practices

1. **Always use the latest stable Rust** for production builds
2. **Enable nightly features** for comprehensive testing and benchmarking
3. **Test all feature combinations** to ensure compatibility
4. **Run cross-compilation tests** for embedded and WASM targets
5. **Verify constant-time operations** for security-critical functions
6. **Include integration tests** to ensure components work together
7. **Use matrix strategies** for efficient parallel execution
8. **Leverage reusable actions** to eliminate duplication

## Troubleshooting

### Common Issues

1. **Build Failures**: Check that all dependencies are properly configured
2. **Test Failures**: Ensure test data and expected outputs are correct
3. **Performance Issues**: Verify that SIMD features are enabled for target platforms
4. **Cross-Compilation Issues**: Check that target toolchains are properly installed
5. **Matrix Failures**: Verify matrix configuration and input parameters

### Debugging

1. **Enable Verbose Output**: Add `--verbose` flags to cargo commands
2. **Check Feature Dependencies**: Verify that required features are enabled
3. **Validate Test Data**: Ensure test vectors match expected cryptographic outputs
4. **Review Security Audits**: Address any security warnings from cargo audit
5. **Check Action Inputs**: Verify all required inputs are provided correctly
