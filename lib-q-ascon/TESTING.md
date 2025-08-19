# Ascon Testing Strategy

This document outlines the comprehensive testing strategy for the lib-q-ascon crate, ensuring cryptographic security, performance, and correctness.

## Test Structure

### 1. Unit Tests (`src/lib.rs`)

**Location**: `src/lib.rs` (inline tests)

**Purpose**: Test basic functionality and edge cases

**Coverage**:
- Round constant generation
- Pad function behavior
- Single round permutation
- State permutation (6, 8, 12 rounds)
- State conversion operations
- Basic state operations

**Example**:
```rust
#[test]
fn test_round_constants() {
    assert_eq!(round_constant(0), 0xf0);
    assert_eq!(round_constant(1), 0xe1);
    // ... more constants
}
```

### 2. KAT (Known Answer Tests) (`tests/kats_tests.rs`)

**Location**: `tests/kats_tests.rs`

**Purpose**: Verify cryptographic correctness against official test vectors

**Coverage**:
- AsconHash256 test vectors from NIST
- AsconXof128 test vectors from NIST
- Reset functionality
- XOF (Extendable Output Function) behavior

**Test Vectors**:
- `data/asconhash.txt` - Official Ascon-Hash test vectors
- `data/asconxof.txt` - Official Ascon-XOF test vectors

**Example**:
```rust
#[test]
fn test_vectors_asconhash256() {
    let tvs = parse_tvs(include_str!("data/asconhash.txt"));
    for tv in tvs {
        run_tv::<AsconHash256>(tv);
    }
}
```

### 3. Constant-Time Tests (`tests/constant_time.rs`)

**Location**: `tests/constant_time.rs`

**Purpose**: Ensure side-channel resistance through timing analysis

**Coverage**:
- Permutation timing consistency across different inputs
- Round count timing relationships
- State conversion timing
- TryFrom operation timing
- Invalid input handling timing
- Memory access pattern timing

**Security Critical**: These tests prevent timing-based side-channel attacks

**Example**:
```rust
#[test]
fn test_permutation_constant_time() {
    // Test multiple input patterns
    // Verify timing consistency within tolerance
    // Prevent compiler optimization with black_box
}
```

### 4. Security Tests (`tests/security.rs`)

**Location**: `tests/security.rs`

**Purpose**: Verify security-critical properties and error handling

**Coverage**:
- Input validation
- Bounds checking
- Memory safety
- Data integrity
- Deterministic behavior
- Avalanche effect
- Zeroization (when enabled)
- State independence
- Edge case handling

**Example**:
```rust
#[test]
fn test_avalanche_effect() {
    // Test that single-bit changes produce significant output differences
    // Verify avalanche effect (50%+ bit changes)
}
```

### 5. Performance Tests (`tests/performance.rs`)

**Location**: `tests/performance.rs`

**Purpose**: Detect performance regressions and verify scaling

**Coverage**:
- Baseline performance verification
- Round count scaling
- State operation performance
- Memory allocation performance
- Performance consistency
- Linear scaling verification

**Example**:
```rust
#[test]
fn test_12_round_performance() {
    // Measure performance against baseline
    // Verify within acceptable bounds
    // Prevent suspiciously fast results
}
```

### 6. Integration Tests (`lib-q-sponge/tests/integration_ascon.rs`)

**Location**: `lib-q-sponge/tests/integration_ascon.rs`

**Purpose**: Test Ascon integration within the larger lib-q-sponge crate

**Coverage**:
- Re-export functionality
- Cross-sponge compatibility
- Basic permutation functionality
- Avalanche effect verification
- Round difference validation

## Test Categories

### Cryptographic Correctness

1. **KAT Tests**: Official test vector verification
2. **Determinism**: Same input produces same output
3. **Avalanche Effect**: Small input changes produce large output changes
4. **Round Distinctness**: Different round counts produce different outputs

### Security Properties

1. **Constant-Time**: No timing side-channels
2. **Input Validation**: Proper error handling
3. **Memory Safety**: Bounds checking and safe operations
4. **Zeroization**: Secure memory clearing (when enabled)
5. **State Independence**: Operations don't interfere

### Performance Characteristics

1. **Baseline Performance**: Within acceptable bounds
2. **Scaling**: Linear performance with round count
3. **Consistency**: Stable performance across runs
4. **Memory Efficiency**: Fast allocation and conversion

## Running Tests

### All Tests
```bash
cargo test
```

### Specific Test Categories
```bash
# KAT tests only
cargo test --test kats_tests

# Constant-time tests only
cargo test --test constant_time

# Security tests only
cargo test --test security

# Performance tests only
cargo test --test performance
```

### With Features
```bash
# With zeroize feature
cargo test --features zeroize

# With no_unroll feature
cargo test --features no_unroll
```

### CI/CD Integration

The tests are integrated into the CI/CD pipeline through:
- `.github/actions/test-ascon/action.yml` - Ascon-specific testing
- `.github/workflows/ci.yml` - Main CI pipeline
- `.github/workflows/security.yml` - Security-focused testing

## Test Data

### Official Test Vectors

- **Ascon-Hash**: `data/asconhash.txt` (1.1MB)
- **Ascon-XOF**: `data/asconxof.txt` (1.1MB)

These files contain official NIST test vectors for cryptographic validation.

### Test Vector Format

```
Count = 0
Msg = 00
MD = 0e9bc6d80cdf0bca57d6d2acd0b1dcd6

Count = 1
Msg = 01
MD = 0e9bc6d80cdf0bca57d6d2acd0b1dcd6
```

## Security Considerations

### Constant-Time Requirements

All cryptographic operations must be constant-time to prevent timing attacks:

1. **No branching based on secret data**
2. **No early returns**
3. **Consistent memory access patterns**
4. **No data-dependent loops**

### Memory Safety

1. **Bounds checking on all array accesses**
2. **Proper error handling for invalid inputs**
3. **Secure memory zeroization when enabled**
4. **No buffer overflows or underflows**

### Input Validation

1. **Length validation for byte arrays**
2. **Range checking for round counts**
3. **Proper error propagation**
4. **No panics on invalid input (except in debug mode)**

## Performance Benchmarks

### Baseline Performance Targets

- **12-round permutation**: < 1μs per operation
- **State conversion**: < 100ns per operation
- **State creation**: < 50ns per operation
- **State cloning**: < 50ns per operation

### Performance Regression Detection

The performance tests detect:
1. **Performance degradation** beyond acceptable thresholds
2. **Suspiciously fast results** that might indicate optimization issues
3. **Inconsistent performance** across multiple runs
4. **Non-linear scaling** with round counts

## Continuous Integration

### Automated Testing

The CI pipeline runs:
1. **Security audits** with `cargo audit`
2. **Code formatting** with `cargo fmt`
3. **Linting** with `cargo clippy`
4. **Unit tests** with `cargo test`
5. **Constant-time verification**
6. **Cross-compilation tests**
7. **WASM compilation tests**

### Test Matrix

Tests run on:
- **Multiple Rust versions** (stable, nightly)
- **Different feature combinations**
- **Multiple platforms** (x86_64, ARM64)
- **WASM targets**

## Contributing

### Adding New Tests

When adding new functionality:

1. **Add unit tests** in `src/lib.rs`
2. **Add KAT tests** if applicable
3. **Add constant-time tests** for cryptographic operations
4. **Add security tests** for new edge cases
5. **Add performance tests** for new operations
6. **Update this documentation**

### Test Guidelines

1. **Use descriptive test names**
2. **Include comprehensive error messages**
3. **Test edge cases and error conditions**
4. **Verify security properties**
5. **Measure performance impact**
6. **Document test rationale**

### Test Maintenance

1. **Keep test vectors up to date**
2. **Monitor performance baselines**
3. **Update security tests for new threats**
4. **Verify constant-time properties**
5. **Maintain test documentation**

## References

- [Ascon Specification](https://ascon.iaik.tugraz.at/)
- [NIST Lightweight Cryptography](https://www.nist.gov/programs-projects/lightweight-cryptography)
- [RustCrypto Testing Guidelines](https://github.com/RustCrypto/utils)
- [Constant-Time Programming](https://www.bearssl.org/constanttime.html)
