# Implementation Prompt for lib-Q Cryptographic Algorithms

## Context

You are implementing actual cryptographic algorithms for the lib-Q post-quantum cryptography library. The project has a complete architecture with placeholder implementations that need to be replaced with real, secure cryptographic code.

## Current State

- **Architecture**: Complete modular Rust workspace with unified API
- **Core Infrastructure**: All types, traits, and API definitions are complete
- **Placeholder Code**: All algorithms currently return dummy data
- **Quality Standards**: Code must pass rustfmt, clippy with -D warnings, and all tests
- **Security Requirements**: All implementations must be constant-time, memory-safe, and side-channel resistant

## Implementation Strategy

### Phase 1: SHAKE256 (Foundation)
**File**: `lib-q-hash/src/shake256.rs`
**Priority**: Highest - Required by all other algorithms

#### Requirements
1. **Implement SHAKE256 according to NIST FIPS 202**
   - Use the Keccak-f[1600] permutation
   - Implement proper padding (domain separation)
   - Support arbitrary output lengths
   - Constant-time operations throughout

2. **Memory Safety**
   - Use `zeroize` for sensitive data
   - No buffer overflows or use-after-free
   - Proper memory zeroing on drop

3. **Testing Requirements**
   - NIST Known Answer Tests (KATs)
   - Edge cases (empty input, large inputs)
   - Performance benchmarks
   - Constant-time verification

4. **Quality Gates**
   - `cargo fmt --all -- --check` passes
   - `cargo clippy --all-targets --all-features -- -D warnings` passes
   - All tests pass
   - Security audit passes

#### Implementation Steps
1. Read and understand NIST FIPS 202 specification
2. Implement Keccak-f[1600] permutation
3. Implement SHAKE256 with proper domain separation
4. Add comprehensive test vectors
5. Ensure constant-time operations
6. Add performance benchmarks
7. Document security considerations

### Phase 2: Kyber512 (Key Encapsulation)
**File**: `lib-q-kem/src/kyber.rs`
**Priority**: High - Primary KEM for most use cases
**Dependencies**: SHAKE256 (Phase 1)

#### Requirements
1. **Implement CRYSTALS-Kyber Level 1 according to NIST PQC specification**
   - Polynomial operations in R_q
   - NTT (Number Theoretic Transform) for efficiency
   - Proper sampling (binomial distribution)
   - Constant-time operations

2. **Security Requirements**
   - Side-channel resistant key generation
   - Constant-time polynomial operations
   - Proper error handling without information leakage
   - Memory-safe key storage with zeroization

3. **Testing Requirements**
   - NIST KATs for Kyber512
   - Round-trip tests (keygen → encapsulate → decapsulate)
   - Performance benchmarks
   - Constant-time verification

### Phase 3: Dilithium2 (Digital Signatures)
**File**: `lib-q-sig/src/dilithium.rs`
**Priority**: High - Primary signature scheme
**Dependencies**: SHAKE256 (Phase 1)

#### Requirements
1. **Implement CRYSTALS-Dilithium Level 2 according to NIST PQC specification**
   - Polynomial operations in R_q
   - Rejection sampling for security
   - Proper challenge generation
   - Constant-time signing and verification

2. **Security Requirements**
   - Constant-time operations
   - Proper rejection sampling
   - Secure key generation
   - Memory-safe signature storage

## Implementation Guidelines

### Security First
```rust
// Example: Constant-time polynomial comparison
pub fn constant_time_poly_compare(a: &[u32], b: &[u32]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u32;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
```

### Memory Safety
```rust
// Example: Secure key storage
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KyberSecretKey {
    s: [u8; KYBER_SECRET_KEY_SIZE],
    t: [u8; KYBER_PUBLIC_KEY_SIZE],
    rho: [u8; 32],
    h: [u8; 32],
}

impl Drop for KyberSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
```

### Error Handling
```rust
// Example: Secure error handling
pub fn kyber_encapsulate(
    public_key: &KyberPublicKey,
    shared_secret: &mut [u8],
    ciphertext: &mut [u8],
) -> Result<(), Error> {
    // Validate input sizes
    if shared_secret.len() != KYBER_SHARED_SECRET_SIZE {
        return Err(Error::InvalidSharedSecretSize);
    }
    if ciphertext.len() != KYBER_CIPHERTEXT_SIZE {
        return Err(Error::InvalidCiphertextSize);
    }
    
    // Implementation here - never reveal internal state
    Ok(())
}
```

### Testing Strategy
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kyber512_kat() {
        // Known Answer Tests from NIST
        let test_vectors = load_kat_vectors();
        for vector in test_vectors {
            let kem = Kyber::new();
            let (pk, sk) = kem.generate_keypair().unwrap();
            
            // Test encapsulation
            let (ss, ct) = kem.encapsulate(&pk).unwrap();
            assert_eq!(ss, vector.expected_shared_secret);
            assert_eq!(ct, vector.expected_ciphertext);
            
            // Test decapsulation
            let ss_dec = kem.decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss_dec, vector.expected_shared_secret);
        }
    }
    
    #[test]
    fn test_constant_time_operations() {
        // Verify constant-time behavior
        let kem = Kyber::new();
        let (pk, sk) = kem.generate_keypair().unwrap();
        
        // Test with different inputs but same timing
        let start = std::time::Instant::now();
        let _ = kem.encapsulate(&pk);
        let time1 = start.elapsed();
        
        let start = std::time::Instant::now();
        let _ = kem.encapsulate(&pk);
        let time2 = start.elapsed();
        
        // Times should be very close (within 10%)
        let ratio = time1.as_nanos() as f64 / time2.as_nanos() as f64;
        assert!(ratio > 0.9 && ratio < 1.1);
    }
}
```

## Quality Assurance Commands

### Before Each Implementation
```bash
# 1. Ensure clean state
cargo clean
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# 2. Run existing tests
cargo test --all-features

# 3. Check formatting
cargo fmt --all -- --check

# 4. Security audit
cargo audit
```

### After Each Implementation
```bash
# 1. Run all quality checks
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo audit

# 2. Run benchmarks
cargo bench

# 3. Check documentation
cargo doc --no-deps --open

# 4. Only proceed if ALL checks pass
```

## Implementation Order

1. **SHAKE256** (`lib-q-hash/src/shake256.rs`)
   - Foundation for all other algorithms
   - Must be implemented first
   - All quality gates must pass

2. **Kyber512** (`lib-q-kem/src/kyber.rs`)
   - Primary KEM algorithm
   - Depends on SHAKE256
   - All quality gates must pass

3. **Dilithium2** (`lib-q-sig/src/dilithium.rs`)
   - Primary signature algorithm
   - Depends on SHAKE256
   - All quality gates must pass

4. **Additional algorithms** (only after previous phases are complete)

## Success Criteria

### For Each Implementation
- [ ] All rustfmt checks pass
- [ ] All clippy checks pass with -D warnings
- [ ] All tests pass (unit, integration, doctests)
- [ ] Security audit passes
- [ ] Performance benchmarks within acceptable ranges
- [ ] Memory usage within acceptable bounds
- [ ] Documentation complete with security notes
- [ ] Constant-time operations verified
- [ ] Memory safety verified

### Overall Success
- [ ] Zero security vulnerabilities
- [ ] Production-ready code quality
- [ ] Comprehensive test coverage
- [ ] Performance meets requirements
- [ ] Documentation complete
- [ ] CI/CD pipeline passes

## Important Notes

1. **Security is Paramount**: Every implementation must be constant-time and side-channel resistant
2. **Quality Gates**: No implementation proceeds without passing all quality checks
3. **One at a Time**: Complete each algorithm fully before moving to the next
4. **Testing**: Comprehensive testing is required for each implementation
5. **Documentation**: All APIs must be fully documented with security considerations

## Resources

- NIST FIPS 202 (SHAKE256): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
- NIST PQC Kyber: https://pq-crystals.org/kyber/
- NIST PQC Dilithium: https://pq-crystals.org/dilithium/
- Rust Cryptography Guidelines: https://github.com/rust-lang/rfcs/blob/master/text/0235-unsafe-code-guidelines.md

Remember: This is production cryptography code. Every line must be written with security in mind. When in doubt, prioritize security over performance or convenience.
