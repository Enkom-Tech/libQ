# KangarooTwelve Testing Strategy

This document outlines the comprehensive testing strategy for the lib-q-k12 crate, ensuring cryptographic security, performance, and correctness.

## Test Structure

### 1. Unit Tests (`src/lib.rs`, `src/block_api.rs`)

**Location**: Inline tests in source files

**Purpose**: Test basic functionality and core components

**Coverage**:
- Length encoding function
- Core API functionality
- Basic state operations

**Example**:
```rust
#[test]
fn test_length_encode() {
    let mut buffer = [0u8; LENGTH_ENCODE_SIZE];
    assert_eq!(length_encode(0, &mut buffer), &[0x00]);
    assert_eq!(length_encode(12, &mut buffer), &[0x0C, 0x01]);
}
```

### 2. Known Answer Tests (KAT) (`tests/mod.rs`)

**Location**: `tests/mod.rs`

**Purpose**: Verify cryptographic correctness against official test vectors

**Coverage**:
- Empty input hashing
- Pattern-based message tests (pat_m)
- Pattern-based customization tests (pat_c)
- Chunk boundary edge cases
- Multiple chunk processing

**Test Vectors**:
- Reference implementation vectors from KangarooTwelve specification
- Python reference implementation vectors
- Edge cases around 8192-byte chunk boundaries

**Example**:
```rust
#[test]
fn empty() {
    // Source: reference paper
    assert_eq!(
        digest_and_box(b"", 32)[..],
        hex!("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")[..]
    );
}
```

### 3. Constant-Time Tests (`tests/constant_time.rs`)

**Location**: `tests/constant_time.rs`

**Purpose**: Ensure side-channel resistance through timing analysis

**Coverage**:
- Hash operation timing consistency across different inputs
- Customization processing timing
- Chunk boundary processing timing
- XOF output generation timing
- Reset operation timing
- Memory access pattern timing

**Security Critical**: These tests prevent timing-based side-channel attacks

**Example**:
```rust
#[test]
fn test_hash_constant_time() {
    // Test different input patterns: zeros, ones, alternating, random
    // Verify timing variance stays within acceptable tolerance
}
```

### 4. Security Tests (`tests/security.rs`)

**Location**: `tests/security.rs`

**Purpose**: Verify cryptographic security properties

**Coverage**:
- Determinism: identical inputs produce identical outputs
- Collision resistance: different inputs produce different outputs
- Customization separation: different customizations produce different outputs
- Avalanche effect: small input changes cause large output changes
- Output distribution: outputs appear uniformly random
- XOF consistency: longer outputs extend shorter ones correctly
- Reset security: reset completely clears state
- Edge case handling: various input sizes and patterns
- Large customization handling
- Incremental vs. batch update consistency
- Zero-length and very large output handling
- Cloning behavior verification
- Chunk independence verification

**Example**:
```rust
#[test]
fn test_avalanche_effect() {
    // Single bit flip should change ~50% of output bits
    let base_result = hash_data(&base_input);
    modify_single_bit(&mut input);
    let modified_result = hash_data(&input);
    assert_significant_difference(base_result, modified_result);
}
```

### 5. Performance Tests (`tests/performance.rs`)

**Location**: `tests/performance.rs`

**Purpose**: Monitor performance and detect regressions

**Coverage**:
- Small input baseline performance
- Input size scaling performance
- Output generation performance
- Customization processing performance
- Chunk boundary performance
- Incremental update performance
- Reset operation performance
- Memory allocation performance
- Cloning performance
- Performance consistency over multiple runs

**Baselines**:
- Small hash (1KB → 32 bytes): 500µs baseline
- Reset operations: <10µs
- Memory allocation: <500µs per operation

**Example**:
```rust
#[test]
fn test_input_scaling_performance() {
    // Verify performance scales sub-linearly or linearly with input size
    // Test 1KB, 4KB, 8KB, 16KB inputs
    // Assert time_ratio <= size_ratio * 2.0
}
```

## Test Categories

### Functional Tests
- **Unit Tests**: Core component functionality
- **KAT Tests**: Cryptographic correctness
- **Integration Tests**: Cross-component interaction

### Security Tests
- **Constant-Time Tests**: Side-channel resistance
- **Security Property Tests**: Cryptographic properties
- **Edge Case Tests**: Boundary condition handling

### Performance Tests
- **Regression Tests**: Performance monitoring
- **Scaling Tests**: Performance characteristics
- **Consistency Tests**: Stable performance

## Running Tests

### All Tests
```bash
cargo test
```

### Specific Test Categories
```bash
cargo test --test constant_time       # Constant-time verification
cargo test --test security            # Security properties
cargo test --test performance         # Performance regression
cargo test tests::mod                 # KAT tests
```

### Test Features
```bash
cargo test --all-features             # Test with all features enabled
cargo test --no-default-features      # Test minimal configuration
```

## CI/CD Integration

Tests are automatically run in GitHub Actions with:

- **Multiple Rust versions**: Stable, beta, nightly
- **Multiple platforms**: Linux, macOS, Windows
- **Feature combinations**: Default, all features, no features
- **Performance monitoring**: Regression detection
- **Security validation**: Constant-time verification

## Test Data

### KAT Test Vectors
- Official KangarooTwelve specification vectors
- Reference implementation compatibility vectors
- Edge case vectors for chunk boundaries
- Large input/output test cases

### Performance Baselines
- Calibrated for typical hardware
- Adjusted for real-world timing variations
- Tolerances account for CI/CD environment differences

## Security Considerations

### Constant-Time Requirements
- All cryptographic operations must be constant-time
- Timing tests verify no data-dependent branching
- Memory access patterns must be consistent

### Side-Channel Resistance
- No timing leaks based on input content
- No timing leaks based on customization strings
- Consistent processing across chunk boundaries

### Memory Safety
- All array accesses are bounds-checked
- Buffer overflows are prevented
- Sensitive data is properly zeroized

## Performance Benchmarks

### Baseline Expectations
- **1KB input**: ~500µs for 32-byte output
- **Chunk processing**: Linear scaling with input size
- **XOF output**: Linear scaling with output size
- **Reset operations**: <10µs
- **Memory allocation**: <500µs per hasher instance

### Scaling Characteristics
- Input scaling: Should not exceed 2x linear
- Output scaling: Should not exceed 3x linear
- Customization overhead: Should not exceed 5x base time

## Contributing

When adding new tests:

1. **Follow naming conventions**: `test_<functionality>_<aspect>`
2. **Include documentation**: Explain what the test verifies
3. **Use appropriate tolerances**: Account for real-world variations
4. **Test edge cases**: Boundary conditions and error cases
5. **Maintain performance**: Don't add unnecessarily slow tests

### Test Guidelines
- Constant-time tests should use realistic tolerances (20-50%)
- Performance tests should use achievable baselines
- Security tests should cover all cryptographic properties
- KAT tests should use official vectors when available

## Debugging Tests

### Common Issues
- **Timing test failures**: Adjust tolerances for CI environment
- **Performance regressions**: Check for algorithmic changes
- **KAT failures**: Verify test vector accuracy
- **Security test failures**: Review cryptographic properties

### Debugging Tools
```bash
cargo test -- --nocapture           # Show test output
cargo test --test performance -- --exact  # Run specific test
RUST_BACKTRACE=1 cargo test         # Show full backtraces
```
