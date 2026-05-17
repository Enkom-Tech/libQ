# Test Scripts

This directory contains test scripts for validating the HQC implementation's DRBG interoperability and feature flag management.

## Scripts Overview

### 1. Feature Flag Validation
- **`test_feature_flag_validation.sh`** / **`test_feature_flag_validation.bat`**
- Validates that feature flag combinations work correctly
- Ensures invalid combinations are rejected with compile errors
- Tests all valid combinations compile successfully

### 2. Production Mode Tests
- **`test_production_modes.sh`** / **`test_production_modes.bat`**
- Tests each DRBG implementation in isolation
- Validates that single features work correctly
- Tests SHAKE256 fallback when no features are enabled

### 3. Diagnostic Mode Tests
- **`test_drbg_diagnostic.sh`** / **`test_drbg_diagnostic.bat`**
- Runs diagnostic mode with both DRBG implementations
- Captures and displays differences between implementations
- Provides detailed logging of DRBG output comparisons

### 4. Complete Test Suite
- **`run_all_tests.sh`** / **`run_all_tests.bat`**
- Runs all test suites in the correct order
- Includes additional validation (no_std, WASM compatibility)
- Provides comprehensive test coverage

## Usage

### Linux/macOS
```bash
# Run individual test suites
./scripts/test_feature_flag_validation.sh
./scripts/test_production_modes.sh
./scripts/test_drbg_diagnostic.sh

# Run complete test suite
./scripts/run_all_tests.sh
```

### Windows
```cmd
REM Run individual test suites
scripts\test_feature_flag_validation.bat
scripts\test_production_modes.bat
scripts\test_drbg_diagnostic.bat

REM Run complete test suite
scripts\run_all_tests.bat
```

## Prerequisites

- Rust toolchain installed
- Cargo available in PATH
- For BearSSL features: BearSSL library installed
- For WASM tests: `wasm32-unknown-unknown` target installed
- **Note**: HQC implementation requires `alloc` feature for all DRBG implementations

## Expected Results

### Feature Flag Validation
- ✅ Invalid combinations fail with compile errors
- ✅ Valid combinations compile successfully
- ✅ Single features work correctly
- ✅ No features fallback works

### Production Mode Tests
- ✅ Each DRBG implementation works in isolation (with `alloc` feature)
- ✅ All cryptographic operations succeed
- ✅ Performance is acceptable for each mode
- ⚠️ No features mode requires `alloc` feature (SHAKE256 fallback not available without alloc)

### Diagnostic Mode Tests
- ✅ Both DRBG implementations run side-by-side
- ✅ Differences are logged and displayed
- ✅ Diagnostic information is captured
- ⚠️ Output differences are expected and documented

## Troubleshooting

### Compilation Errors
- Ensure all dependencies are installed
- Check that feature flags are correctly specified
- Verify BearSSL is available for `bearssl-aes` feature

### Test Failures
- Review diagnostic output for specific failure points
- Check that test environment is properly configured
- Verify that all required features are enabled

### Performance Issues
- Diagnostic mode is slower due to dual execution
- Production mode should be used for performance testing
- Consider using single DRBG implementation for production

## Production Recommendations

1. **Choose a single DRBG implementation**:
   - Use `aes-drbg` for pure Rust (no external dependencies)
   - Use `bearssl-aes` for BearSSL-based implementation
   - **Note**: All modes require `alloc` feature (no pure no_std mode available)

2. **Avoid diagnostic mode in production**:
   - `debug-drbg-interop` is for testing only
   - Enables both DRBG implementations simultaneously
   - Slower and uses more memory

3. **Test your chosen configuration**:
   - Run production mode tests with your chosen feature
   - Verify all cryptographic operations work correctly
   - Test in your target environment (WASM compatibility may require additional configuration)

4. **Compatibility Notes**:
   - **no_std**: Requires `alloc` feature (not pure no_std)
   - **WASM**: May require additional getrandom configuration for proper random number generation
   - **Production**: Both DRBG implementations are cryptographically correct but produce different outputs

## Documentation

For detailed information about:
- Feature flag management: See `docs/features.md`
- DRBG interoperability: See `docs/drbg_interop_analysis.md`
- KAT compliance: See `docs/final-kat-compliance-analysis.md`
