# HQC Test Suite

This directory contains comprehensive tests for the HQC (Hamming Quasi-Cyclic) implementation in libQ.

## Test Categories

### 1. Edge Case Tests (`edge_case_tests.rs`)
Tests the implementation's robustness under various edge conditions:
- Empty input handling
- Maximum size input handling
- Invalid input sizes
- Boundary value inputs
- Memory allocation edge cases
- Security-related edge cases
- Constant-time behavior
- Error propagation
- Resource cleanup

### 2. Interoperability Tests (`interoperability_tests.rs`)
Tests compatibility across different configurations:
- Cross-security-level compatibility
- Feature combination compatibility
- Parameter validation across security levels
- Error handling consistency
- Performance consistency across security levels
- Memory usage consistency
- Cross-module integration
- Error correction consistency
- Security level progression

### 3. Security Validation Tests (`security_validation_tests.rs`)
Tests security requirements and best practices:
- Constant-time behavior
- Side-channel resistance
- Input validation security
- Error handling security
- Memory security
- Cryptographic strength
- Error correction security
- Parameter security
- Implementation consistency
- Resistance to known attacks

### 4. Integration Tests (`integration_tests.rs`)
Tests the full HQC KEM cycle:
- Full HQC-128 KEM cycle
- Full HQC-192 KEM cycle
- Full HQC-256 KEM cycle
- Cross-security-level interoperability
- Error handling in KEM operations
- Key pair generation consistency
- Shared secret generation consistency
- Ciphertext properties
- Performance under load
- Memory usage under load

### 5. Performance Tests (`performance_tests.rs`)
Tests performance characteristics:
- FFT performance improvements
- FFT correctness verification
- Performance scaling across security levels
- Memory efficiency
- FFT parameter validation

## Running Tests

### Run All Tests
```bash
cargo test --features alloc
```

### Run Specific Test Categories
```bash
# Edge case tests
cargo test edge_case_tests --features alloc

# Interoperability tests
cargo test interoperability_tests --features alloc

# Security validation tests
cargo test security_validation_tests --features alloc

# Integration tests
cargo test integration_tests --features alloc

# Performance tests
cargo test performance_tests --features alloc
```

### Run Tests for Specific Security Levels
```bash
# HQC-128 only
cargo test --features "alloc,hqc128"

# HQC-192 only
cargo test --features "alloc,hqc192"

# HQC-256 only
cargo test --features "alloc,hqc256"

# All security levels
cargo test --features "alloc,hqc"
```

### Run Benchmarks
```bash
# Run performance benchmarks
cargo bench --features alloc

# Run benchmarks for specific security levels
cargo bench --features "alloc,hqc128"
cargo bench --features "alloc,hqc192"
cargo bench --features "alloc,hqc256"
```

## Test Requirements

### Features Required
- `alloc`: Required for all tests (enables dynamic allocation)
- `hqc128`: Required for HQC-128 specific tests
- `hqc192`: Required for HQC-192 specific tests
- `hqc256`: Required for HQC-256 specific tests

### Dependencies
- `lib_q_core`: Core libQ types and traits
- `lib_q_hqc`: HQC implementation
- `lib_q_sha3`: SHA-3 implementation for shared secret generation
- `lib_q_random`: Secure random number generation

## Test Coverage

The test suite provides comprehensive coverage of:

### Functional Testing
- ✅ All HQC security levels (128, 192, 256)
- ✅ All KEM operations (keygen, enc, dec)
- ✅ All cryptographic primitives (BCH, repetition, tensor codes)
- ✅ All mathematical operations (polynomial, vector operations)
- ✅ All performance optimizations (FFT/NTT)

### Security Testing
- ✅ Constant-time operations
- ✅ Side-channel resistance
- ✅ Input validation
- ✅ Error handling
- ✅ Memory security
- ✅ Cryptographic strength

### Robustness Testing
- ✅ Edge cases
- ✅ Error conditions
- ✅ Resource limits
- ✅ Memory management
- ✅ Performance under load

### Interoperability Testing
- ✅ Cross-security-level compatibility
- ✅ Feature combination compatibility
- ✅ Parameter validation
- ✅ Error handling consistency

## Test Results

### Expected Outcomes
- All tests should pass
- No memory leaks
- No panics or crashes
- Consistent performance
- Proper error handling

### Performance Expectations
- HQC-128: ~1-5ms per operation
- HQC-192: ~2-10ms per operation
- HQC-256: ~5-20ms per operation
- FFT optimization: 20-50x speedup for large parameters

### Security Expectations
- Constant-time operations
- No timing-based information leakage
- Proper input validation
- Secure memory handling
- Resistance to known attacks

## Troubleshooting

### Common Issues

1. **Feature Not Enabled**
   ```
   error: could not find `hqc128` in `lib_q_hqc`
   ```
   Solution: Add the required feature flag: `--features "alloc,hqc128"`

2. **Memory Issues**
   ```
   error: process didn't exit successfully
   ```
   Solution: Ensure sufficient memory is available for large parameter tests

3. **Performance Issues**
   ```
   test timed out
   ```
   Solution: Increase timeout or optimize system performance

### Debug Mode
Run tests in debug mode for more detailed output:
```bash
RUST_LOG=debug cargo test --features alloc
```

### Verbose Output
Run tests with verbose output:
```bash
cargo test --features alloc -- --nocapture
```

## Contributing

When adding new tests:

1. **Follow the existing structure** - Use the same test organization
2. **Add comprehensive coverage** - Test edge cases and error conditions
3. **Include performance tests** - Measure and verify performance
4. **Document test purpose** - Add clear comments explaining what each test does
5. **Use proper feature gating** - Ensure tests work with appropriate feature combinations

### Test Naming Convention
- `test_<functionality>_<condition>`: Basic functionality tests
- `test_<functionality>_edge_cases`: Edge case tests
- `test_<functionality>_security`: Security-related tests
- `test_<functionality>_performance`: Performance tests
- `test_<functionality>_integration`: Integration tests

### Test Documentation
Each test should include:
- Clear description of what it tests
- Expected behavior
- Any special requirements
- Performance expectations (if applicable)
