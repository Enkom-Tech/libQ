# SHA3 Testing Strategy

This document outlines the comprehensive testing strategy for the lib-q-sha3 crate, ensuring cryptographic security, performance, and correctness.

## Test Structure

### 1. KAT (Known Answer Tests) (`tests/mod.rs`)

**Location**: `tests/mod.rs` (using digest crate test framework)

**Purpose**: Verify cryptographic correctness against official test vectors

**Coverage**:
- SHA3-224, SHA3-256, SHA3-384, SHA3-512 test vectors
- SHAKE128, SHAKE256 test vectors
- Keccak-224, Keccak-256, Keccak-384, Keccak-512 test vectors
- Keccak-256-Full test vectors

**Test Vectors**: Official NIST test vectors from `tests/data/` directory

**Example**:
```rust
new_test!(
    sha3_256_kat,
    "sha3_256_kat",
    lib_q_sha3::Sha3_256,
    fixed_reset_test
);
```

### 2. Basic Functionality Tests (`tests/basic_functionality.rs`)

**Location**: `tests/basic_functionality.rs`

**Purpose**: Test core functionality and edge cases

**Coverage**:
- Basic hash operations for all algorithms
- Output length verification
- Deterministic behavior
- Empty input handling
- Large input handling

**Example**:
```rust
#[test]
fn sha3_256_basic_functionality() {
    let mut hasher = lib_q_sha3::Sha3_256::new();
    hasher.update(b"test data");
    let result = hasher.finalize();
    assert_eq!(result.len(), 32); // SHA3-256 produces 256 bits = 32 bytes
}
```

### 3. CSHAKE Tests (`tests/cshake.rs`)

**Location**: `tests/cshake.rs`

**Purpose**: Test customizable SHAKE functionality

**Coverage**:
- CSHAKE128 and CSHAKE256 operations
- Reset functionality
- Customizable parameters

### 4. TurboSHAKE Tests (`tests/turboshake.rs`)

**Location**: `tests/turboshake.rs`

**Purpose**: Test TurboSHAKE variants

**Coverage**:
- TurboSHAKE128 and TurboSHAKE256
- Different domain separators
- Large output generation
- Consistency verification

### 5. Constant-Time Tests (`tests/constant_time.rs`)

**Location**: `tests/constant_time.rs`

**Purpose**: Ensure side-channel resistance through timing analysis

**Coverage**:
- Hash timing consistency across different inputs
- Algorithm timing relationships
- Input size timing relationships

**Security Critical**: These tests prevent timing-based side-channel attacks

**Example**:
```rust
#[test]
fn test_sha3_256_constant_time() {
    // Test timing consistency across various inputs
    // Verify no timing side-channels exist
}
```

### 6. Security Tests (`tests/security.rs`)

**Location**: `tests/security.rs`

**Purpose**: Verify security-critical properties

**Coverage**:
- Deterministic behavior
- Avalanche effect validation
- Algorithm distinctness
- Output length verification
- Empty input handling
- Large input handling
- Idempotency verification
- Pattern resistance

**Security Properties**:
1. **Deterministic**: Same input always produces same output
2. **Avalanche Effect**: Small input changes produce large output changes
3. **Algorithm Distinctness**: Different algorithms produce different outputs
4. **Pattern Resistance**: No predictable patterns in outputs

### 7. Performance Tests (`tests/performance.rs`)

**Location**: `tests/performance.rs`

**Purpose**: Detect performance regressions and verify scaling

**Coverage**:
- Baseline performance verification
- Algorithm performance relationships
- Input size scaling
- Performance consistency
- Cross-algorithm performance comparison

**Performance Characteristics**:
1. **Baseline Performance**: Within acceptable bounds
2. **Scaling**: Linear performance with input size
3. **Consistency**: Stable performance across runs
4. **Algorithm Relationships**: Expected performance ratios

## Running Tests

### All Tests
```bash
cargo test
```

### Specific Test Categories
```bash
# KAT tests only
cargo test --test mod

# Basic functionality tests only
cargo test --test basic_functionality

# Constant-time tests only
cargo test --test constant_time

# Security tests only
cargo test --test security

# Performance tests only
cargo test --test performance

# CSHAKE tests only
cargo test --test cshake

# TurboSHAKE tests only
cargo test --test turboshake
```

### With Features
```bash
# With default features
cargo test --features "alloc,oid"

# With all features
cargo test --all-features

# With specific features
cargo test --features "alloc,oid,zeroize"
```

### CI/CD Integration

The tests are integrated into the CI/CD pipeline through:
- `.github/actions/test-sha3/action.yml` - SHA3-specific testing
- `.github/workflows/ci.yml` - Main CI pipeline
- `.github/workflows/security.yml` - Security-focused testing

## Test Data

### Official Test Vectors

- **SHA3**: `data/sha3_*.blb` files containing official NIST test vectors
- **SHAKE**: `data/shake*.blb` files containing official NIST test vectors
- **Keccak**: `data/keccak_*.blb` files containing official test vectors
- **CSHAKE**: `data/cshake*.blb` files containing official test vectors
- **TurboSHAKE**: `data/turboshake*.blb` files containing official test vectors

These files contain official test vectors for cryptographic validation.

## Security Considerations

### Constant-Time Requirements

All cryptographic operations must be constant-time to prevent timing attacks:

1. **No branching based on secret data**
2. **No early returns**
3. **Consistent memory access patterns**
4. **No data-dependent loops**

### Cryptographic Properties

1. **Preimage Resistance**: Given a hash, it's computationally infeasible to find a preimage
2. **Second Preimage Resistance**: Given a message, it's computationally infeasible to find a second message with the same hash
3. **Collision Resistance**: It's computationally infeasible to find two different messages with the same hash
4. **Avalanche Effect**: Small changes in input produce large changes in output

### Memory Safety

1. **No buffer overflows**
2. **Proper bounds checking**
3. **Secure memory handling**
4. **No information leakage**

## Performance Benchmarks

### Baseline Performance

- **SHA3-256**: ~5 microseconds per operation
- **SHA3-224**: Similar to SHA3-256 (same rounds)
- **SHA3-384**: ~1.5x slower than SHA3-256
- **SHA3-512**: ~2x slower than SHA3-256
- **Keccak256**: Similar to SHA3-256

### Scaling Characteristics

- **Small inputs (< 1KB)**: Constant overhead dominates
- **Medium inputs (1KB - 1MB)**: Linear scaling with input size
- **Large inputs (> 1MB)**: Linear scaling with input size

### Performance Monitoring

1. **Regression Detection**: Tests fail if performance degrades significantly
2. **Consistency Verification**: Performance should be stable across runs
3. **Algorithm Comparison**: Verify expected performance relationships

## Test Maintenance

### Adding New Tests

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

- [SHA3 Specification (FIPS 202)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [NIST Cryptographic Standards](https://www.nist.gov/cryptography)
- [RustCrypto Testing Guidelines](https://github.com/RustCrypto/utils)
- [Constant-Time Programming](https://www.bearssl.org/constanttime.html)
- [CSHAKE Specification (NIST SP 800-185)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)
- [TurboSHAKE Specification](https://eprint.iacr.org/2022/1357)
