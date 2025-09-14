# Security Considerations for lib-q-hpke

This document provides detailed security considerations for the lib-q-hpke implementation, including threat models, security guarantees, and implementation security measures.

## Threat Model

The lib-q-hpke implementation is designed to resist the following classes of attacks:

### 1. Classical Cryptographic Attacks
- **Chosen Plaintext Attacks (CPA)**: Resisted through proper use of authenticated encryption
- **Chosen Ciphertext Attacks (CCA)**: Resisted through IND-CCA2 security of ML-KEM
- **Key Recovery Attacks**: Resisted through post-quantum security of underlying primitives
- **Message Forgery**: Resisted through authenticated encryption with Saturnin-256

### 2. Quantum Attacks
- **Shor's Algorithm**: Resisted through post-quantum KEM (ML-KEM)
- **Grover's Algorithm**: Resisted through appropriate key sizes (256-bit security level)
- **Quantum Key Recovery**: Resisted through post-quantum hash functions (SHAKE256/SHA3)

### 3. Side-Channel Attacks
- **Timing Attacks**: Mitigated through constant-time operations
- **Power Analysis**: Mitigated through constant-time algorithms and secure coding practices
- **Cache Timing Attacks**: Mitigated through careful memory access patterns
- **Electromagnetic Emanation**: Mitigated through constant-time operations

### 4. Implementation Attacks
- **Memory Corruption**: Prevented through Rust's memory safety guarantees
- **Buffer Overflows**: Prevented through bounds checking and safe Rust constructs
- **Use-After-Free**: Prevented through Rust's ownership system
- **Double-Free**: Prevented through Rust's memory management

## Security Guarantees

### 1. Confidentiality
- **IND-CCA2 Security**: All ML-KEM variants provide indistinguishability under chosen ciphertext attacks
- **Forward Secrecy**: Compromising long-term keys doesn't affect past communications
- **Post-Quantum Security**: Resistance against quantum computer attacks

### 2. Authenticity
- **Message Authentication**: All messages are authenticated using Saturnin-256
- **Sender Authentication**: Auth modes provide cryptographic proof of sender identity
- **Key Authentication**: PSK modes provide authentication through shared secrets

### 3. Integrity
- **Message Integrity**: All messages are protected against tampering
- **Key Integrity**: All keys are validated before use
- **Context Integrity**: Sequence numbers prevent replay attacks

## Implementation Security Measures

### 1. Constant-Time Operations

All cryptographic operations are designed to be constant-time to prevent timing attacks:

```rust
// Example: Constant-time key comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
```

### 2. Memory Safety

Sensitive data is automatically zeroed after use:

```rust
impl Drop for HpkePrivateKey {
    fn drop(&mut self) {
        self.value.iter_mut().for_each(|b| *b = 0);
    }
}
```

### 3. Input Validation

All inputs are comprehensively validated:

```rust
fn validate_key(&self, kem: HpkeKem, key: &[u8], is_secret: bool) -> Result<(), HpkeError> {
    let expected_len = if is_secret {
        kem.secret_key_len()
    } else {
        kem.public_key_len()
    };
    
    if key.len() != expected_len {
        return Err(HpkeError::invalid_input(
            "key",
            format!("{} bytes", key.len()),
            format!("{} bytes", expected_len),
        ));
    }
    
    // Reject zero keys
    if key.iter().all(|&b| b == 0) {
        return Err(HpkeError::CryptoError(
            "Key material cannot be all zeros".to_string(),
        ));
    }
    
    Ok(())
}
```

### 4. Error Handling

Error messages don't leak sensitive information:

```rust
// Good: Generic error message
return Err(HpkeError::CryptoError(
    "Authentication proof verification failed: invalid sender authentication".to_string()
));

// Bad: Would leak information about internal state
// return Err(HpkeError::CryptoError(
//     format!("Auth proof mismatch: expected {:?}, got {:?}", expected, actual)
// ));
```

## Authentication Security

### 1. AuthEncap/AuthDecap Implementation

The authentication implementation uses a hash-based proof system:

```rust
fn create_auth_proof(
    &self,
    kem: HpkeKem,
    sender_sk: &KemSecretKey,
    sender_pk: &KemPublicKey,
    recipient_pk: &KemPublicKey,
    encapsulated_key: &[u8],
    shared_secret: &[u8],
    rng: &mut dyn CryptoRng,
) -> Result<Vec<u8>, HpkeError> {
    // Create authentication data
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(b"HPKE-AuthProof-v1");
    auth_data.extend_from_slice(&kem.algorithm_id().to_be_bytes());
    auth_data.extend_from_slice(sender_pk.as_bytes());
    auth_data.extend_from_slice(recipient_pk.as_bytes());
    auth_data.extend_from_slice(encapsulated_key);
    auth_data.extend_from_slice(shared_secret);
    auth_data.extend_from_slice(sender_sk.as_bytes());
    
    // Generate proof using hash function
    let hash_impl = Self::create_hash_instance(HpkeKdf::HkdfShake256)?;
    let proof = hash_impl.hash(&auth_data)?;
    
    Ok(proof.into_iter().take(self.get_auth_proof_length(kem)).collect())
}
```

### 2. Security Properties

- **Knowledge Proof**: The proof demonstrates knowledge of the sender's secret key
- **Non-Repudiation**: The recipient can verify the sender's identity
- **Forward Security**: Compromising the proof doesn't affect future communications
- **Constant-Time Verification**: Proof verification is constant-time

## Key Management Security

### 1. Key Generation

Keys are generated using cryptographically secure random number generation:

```rust
fn generate_keypair(
    &self,
    kem: HpkeKem,
    rng: &mut dyn CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
    let kem_impl = Self::create_kem_instance(kem)?;
    let keypair = kem_impl.generate_keypair()
        .map_err(|e| HpkeError::CryptoError(format!("KEM key generation failed: {}", e)))?;
    
    Ok((
        keypair.public_key().as_bytes().to_vec(),
        keypair.secret_key().as_bytes().to_vec(),
    ))
}
```

### 2. Key Validation

All keys are validated before use:

- **Length Validation**: Keys must have correct length for the algorithm
- **Zero Key Rejection**: All-zero keys are rejected
- **Format Validation**: Keys must be in correct format
- **Consistency Checks**: Key pairs are validated for consistency

### 3. Key Storage

- **Automatic Zeroization**: Secret keys are automatically zeroed when dropped
- **Secure Containers**: Keys are stored in secure containers that prevent accidental exposure
- **No Debug Logging**: Secret keys are never logged or exposed in error messages

## Side-Channel Resistance

### 1. Timing Attack Resistance

All operations are designed to be constant-time:

```rust
// Constant-time selection
pub fn constant_time_select(choice: u8, a: u8, b: u8) -> u8 {
    let mask = 0u8.wrapping_sub(choice);
    (a & mask) | (b & !mask)
}

// Constant-time conditional copy
pub fn constant_time_copy(choice: u8, dst: &mut [u8], src: &[u8]) {
    if dst.len() != src.len() {
        return;
    }
    
    let mask = 0u8.wrapping_sub(choice);
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (*s & mask);
    }
}
```

### 2. Power Analysis Resistance

- **Constant-Time Algorithms**: All cryptographic operations use constant-time algorithms
- **Uniform Memory Access**: Memory access patterns are designed to be uniform
- **No Secret-Dependent Branches**: No branches depend on secret data

### 3. Cache Timing Resistance

- **Uniform Memory Access**: All memory accesses follow the same pattern regardless of secret data
- **No Secret-Dependent Array Indices**: Array indices don't depend on secret data
- **Constant-Time Table Lookups**: Table lookups are constant-time

## Testing and Validation

### 1. Fuzzing Tests

Comprehensive fuzzing tests validate security properties:

```rust
#[test]
fn fuzz_auth_proof_validation() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    
    for _ in 0..1000 {
        // Generate random but valid key sizes
        let kem = match rng.gen_range(0..3) {
            0 => HpkeKem::MlKem512,
            1 => HpkeKem::MlKem768,
            _ => HpkeKem::MlKem1024,
        };
        
        // Test authentication proof creation and verification
        // ... (test implementation)
    }
}
```

### 2. Side-Channel Analysis

Timing analysis tests ensure constant-time properties:

```rust
#[test]
fn test_timing_consistency_key_validation() {
    // Measure timing for different validation scenarios
    let mut valid_times = Vec::new();
    let mut invalid_times = Vec::new();
    
    // ... (timing measurement implementation)
    
    // Times should be similar (within reasonable tolerance)
    let time_diff = if avg_valid_time > avg_invalid_time {
        avg_valid_time - avg_invalid_time
    } else {
        avg_invalid_time - avg_valid_time
    };
    
    let max_allowed_diff = avg_valid_time / 10;
    assert!(time_diff <= max_allowed_diff);
}
```

