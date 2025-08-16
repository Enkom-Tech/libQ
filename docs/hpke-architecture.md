# Hybrid Public Key Encryption (HPKE) Architecture

## Overview

libQ implements a three-tier Hybrid Public Key Encryption (HPKE) system that provides post-quantum security with different performance characteristics. HPKE combines post-quantum key encapsulation mechanisms (KEMs) with symmetric encryption to provide secure, authenticated encryption.

## Architecture Design

### Three-Tier System

```
libQ HPKE Architecture
├── Tier 1: Ultra-Secure (Pure Post-Quantum)
│   ├── KEM: CRYSTALS-Kyber (Level 5)
│   ├── AEAD: SHAKE256-based construction
│   └── Use Case: Maximum security, performance secondary
├── Tier 2: Balanced (Hybrid Post-Quantum)
│   ├── KEM: CRYSTALS-Kyber (Level 3)
│   ├── AEAD: AES-256-GCM
│   └── Use Case: Strong security with good performance
└── Tier 3: Performance (Post-Quantum + Optimized Classical)
    ├── KEM: CRYSTALS-Kyber (Level 1)
    ├── AEAD: ChaCha20-Poly1305
    └── Use Case: Maximum performance, strong security
```

### Core Components

```rust
/// HPKE security tiers
pub enum SecurityTier {
    /// Ultra-secure: Pure post-quantum with maximum security
    Ultra,
    /// Balanced: Hybrid post-quantum with good performance
    Balanced,
    /// Performance: Post-quantum + optimized classical
    Performance,
}

/// HPKE context for stateful operations
pub struct HpkeContext {
    /// The security tier
    pub tier: SecurityTier,
    /// The encapsulated key
    pub encapsulated_key: EncapsulatedKey,
    /// The derived encryption key
    pub encryption_key: EncryptionKey,
    /// The sequence number for ordered operations
    pub sequence_number: u64,
}

/// HPKE ciphertext containing encapsulated key and encrypted data
pub struct HpkeCiphertext {
    /// The encapsulated key
    pub encapsulated_key: EncapsulatedKey,
    /// The encrypted payload
    pub ciphertext: Vec<u8>,
    /// The authentication tag
    pub tag: [u8; 16],
}
```

## Tier 1: Ultra-Secure HPKE

### Design Philosophy

Tier 1 provides maximum security by using only post-quantum algorithms throughout the entire encryption chain. This eliminates any reliance on classical cryptographic assumptions.

### Implementation

```rust
/// Ultra-secure HPKE implementation
pub struct UltraHpke {
    kem: Kyber5,
    aead: Shake256Aead,
}

impl UltraHpke {
    /// Create a new ultra-secure HPKE instance
    pub fn new() -> Self {
        Self {
            kem: Kyber5::new(),
            aead: Shake256Aead::new(),
        }
    }
    
    /// Seal (encrypt) a message for a recipient
    pub fn seal(
        &self,
        recipient_pk: &PublicKey,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<HpkeCiphertext> {
        // 1. Generate ephemeral key pair
        let (ephemeral_sk, ephemeral_pk) = self.kem.generate_keypair()?;
        
        // 2. Encapsulate shared secret with recipient's public key
        let (shared_secret, encapsulated_key) = self.kem.encapsulate(recipient_pk)?;
        
        // 3. Derive encryption key using SHAKE256
        let encryption_key = self.derive_key(&shared_secret, &encapsulated_key)?;
        
        // 4. Encrypt with SHAKE256-based AEAD
        let (ciphertext, tag) = self.aead.encrypt(
            &encryption_key,
            plaintext,
            associated_data.unwrap_or(&[]),
        )?;
        
        // 5. Return encapsulated key + ciphertext + tag
        Ok(HpkeCiphertext {
            encapsulated_key,
            ciphertext,
            tag,
        })
    }
    
    /// Open (decrypt) a message using recipient's secret key
    pub fn open(
        &self,
        recipient_sk: &SecretKey,
        ciphertext: &HpkeCiphertext,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // 1. Decapsulate shared secret using recipient's secret key
        let shared_secret = self.kem.decapsulate(recipient_sk, &ciphertext.encapsulated_key)?;
        
        // 2. Derive encryption key using SHAKE256
        let encryption_key = self.derive_key(&shared_secret, &ciphertext.encapsulated_key)?;
        
        // 3. Decrypt with SHAKE256-based AEAD
        let plaintext = self.aead.decrypt(
            &encryption_key,
            &ciphertext.ciphertext,
            &ciphertext.tag,
            associated_data.unwrap_or(&[]),
        )?;
        
        Ok(plaintext)
    }
    
    /// Derive encryption key from shared secret
    fn derive_key(&self, shared_secret: &SharedSecret, encapsulated_key: &EncapsulatedKey) -> Result<EncryptionKey> {
        // Use SHAKE256 for key derivation
        let mut key = [0u8; 32];
        let mut hasher = Shake256::new();
        hasher.update(b"libQ-HPKE-Ultra-v1");
        hasher.update(shared_secret.as_ref());
        hasher.update(encapsulated_key.as_ref());
        hasher.finalize(&mut key);
        Ok(EncryptionKey(key))
    }
}
```

### SHAKE256-based AEAD

```rust
/// SHAKE256-based authenticated encryption
pub struct Shake256Aead {
    // Implementation details for SHAKE256-based AEAD
}

impl Shake256Aead {
    /// Encrypt with SHAKE256-based AEAD
    pub fn encrypt(
        &self,
        key: &EncryptionKey,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16])> {
        // 1. Generate nonce using SHAKE256
        let nonce = self.generate_nonce(key)?;
        
        // 2. Encrypt using SHAKE256 in counter mode
        let ciphertext = self.encrypt_shake256(key, &nonce, plaintext)?;
        
        // 3. Generate authentication tag using SHAKE256
        let tag = self.generate_tag(key, &nonce, &ciphertext, associated_data)?;
        
        Ok((ciphertext, tag))
    }
    
    /// Decrypt with SHAKE256-based AEAD
    pub fn decrypt(
        &self,
        key: &EncryptionKey,
        ciphertext: &[u8],
        tag: &[u8; 16],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Generate nonce using SHAKE256
        let nonce = self.generate_nonce(key)?;
        
        // 2. Verify authentication tag
        let expected_tag = self.generate_tag(key, &nonce, ciphertext, associated_data)?;
        if !constant_time_compare(tag, &expected_tag) {
            return Err(Error::VerificationFailed {
                operation: "HPKE tag verification".to_string(),
            });
        }
        
        // 3. Decrypt using SHAKE256 in counter mode
        let plaintext = self.decrypt_shake256(key, &nonce, ciphertext)?;
        
        Ok(plaintext)
    }
    
    /// Generate nonce for encryption
    fn generate_nonce(&self, key: &EncryptionKey) -> Result<[u8; 12]> {
        let mut nonce = [0u8; 12];
        let mut hasher = Shake256::new();
        hasher.update(b"libQ-HPKE-Nonce");
        hasher.update(key.as_ref());
        hasher.update(&random_bytes(16)?);
        hasher.finalize(&mut nonce);
        Ok(nonce)
    }
    
    /// Generate authentication tag
    fn generate_tag(
        &self,
        key: &EncryptionKey,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<[u8; 16]> {
        let mut tag = [0u8; 16];
        let mut hasher = Shake256::new();
        hasher.update(b"libQ-HPKE-Tag");
        hasher.update(key.as_ref());
        hasher.update(nonce);
        hasher.update(ciphertext);
        hasher.update(associated_data);
        hasher.finalize(&mut tag);
        Ok(tag)
    }
}
```

## Tier 2: Balanced HPKE

### Design Philosophy

Tier 2 provides strong security with good performance by combining post-quantum KEM with quantum-resistant classical AEAD. This tier is suitable for most applications requiring strong security.

### Implementation

```rust
/// Balanced HPKE implementation
pub struct BalancedHpke {
    kem: Kyber3,
    aead: Aes256Gcm,
}

impl BalancedHpke {
    /// Create a new balanced HPKE instance
    pub fn new() -> Self {
        Self {
            kem: Kyber3::new(),
            aead: Aes256Gcm::new(),
        }
    }
    
    /// Seal (encrypt) a message for a recipient
    pub fn seal(
        &self,
        recipient_pk: &PublicKey,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<HpkeCiphertext> {
        // 1. Generate ephemeral key pair
        let (ephemeral_sk, ephemeral_pk) = self.kem.generate_keypair()?;
        
        // 2. Encapsulate shared secret with recipient's public key
        let (shared_secret, encapsulated_key) = self.kem.encapsulate(recipient_pk)?;
        
        // 3. Derive encryption key using SHAKE256
        let encryption_key = self.derive_key(&shared_secret, &encapsulated_key)?;
        
        // 4. Encrypt with AES-256-GCM
        let (ciphertext, tag) = self.aead.encrypt(
            &encryption_key,
            plaintext,
            associated_data.unwrap_or(&[]),
        )?;
        
        // 5. Return encapsulated key + ciphertext + tag
        Ok(HpkeCiphertext {
            encapsulated_key,
            ciphertext,
            tag,
        })
    }
    
    /// Open (decrypt) a message using recipient's secret key
    pub fn open(
        &self,
        recipient_sk: &SecretKey,
        ciphertext: &HpkeCiphertext,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // 1. Decapsulate shared secret using recipient's secret key
        let shared_secret = self.kem.decapsulate(recipient_sk, &ciphertext.encapsulated_key)?;
        
        // 2. Derive encryption key using SHAKE256
        let encryption_key = self.derive_key(&shared_secret, &ciphertext.encapsulated_key)?;
        
        // 3. Decrypt with AES-256-GCM
        let plaintext = self.aead.decrypt(
            &encryption_key,
            &ciphertext.ciphertext,
            &ciphertext.tag,
            associated_data.unwrap_or(&[]),
        )?;
        
        Ok(plaintext)
    }
    
    /// Derive encryption key from shared secret
    fn derive_key(&self, shared_secret: &SharedSecret, encapsulated_key: &EncapsulatedKey) -> Result<EncryptionKey> {
        // Use SHAKE256 for key derivation
        let mut key = [0u8; 32];
        let mut hasher = Shake256::new();
        hasher.update(b"libQ-HPKE-Balanced-v1");
        hasher.update(shared_secret.as_ref());
        hasher.update(encapsulated_key.as_ref());
        hasher.finalize(&mut key);
        Ok(EncryptionKey(key))
    }
}
```

## Tier 3: Performance HPKE

### Design Philosophy

Tier 3 provides maximum performance while maintaining strong security by combining post-quantum KEM with optimized classical AEAD. This tier is suitable for high-performance applications.

### Implementation

```rust
/// Performance HPKE implementation
pub struct PerformanceHpke {
    kem: Kyber1,
    aead: ChaCha20Poly1305,
}

impl PerformanceHpke {
    /// Create a new performance HPKE instance
    pub fn new() -> Self {
        Self {
            kem: Kyber1::new(),
            aead: ChaCha20Poly1305::new(),
        }
    }
    
    /// Seal (encrypt) a message for a recipient
    pub fn seal(
        &self,
        recipient_pk: &PublicKey,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<HpkeCiphertext> {
        // 1. Generate ephemeral key pair
        let (ephemeral_sk, ephemeral_pk) = self.kem.generate_keypair()?;
        
        // 2. Encapsulate shared secret with recipient's public key
        let (shared_secret, encapsulated_key) = self.kem.encapsulate(recipient_pk)?;
        
        // 3. Derive encryption key using SHAKE256
        let encryption_key = self.derive_key(&shared_secret, &encapsulated_key)?;
        
        // 4. Encrypt with ChaCha20-Poly1305
        let (ciphertext, tag) = self.aead.encrypt(
            &encryption_key,
            plaintext,
            associated_data.unwrap_or(&[]),
        )?;
        
        // 5. Return encapsulated key + ciphertext + tag
        Ok(HpkeCiphertext {
            encapsulated_key,
            ciphertext,
            tag,
        })
    }
    
    /// Open (decrypt) a message using recipient's secret key
    pub fn open(
        &self,
        recipient_sk: &SecretKey,
        ciphertext: &HpkeCiphertext,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // 1. Decapsulate shared secret using recipient's secret key
        let shared_secret = self.kem.decapsulate(recipient_sk, &ciphertext.encapsulated_key)?;
        
        // 2. Derive encryption key using SHAKE256
        let encryption_key = self.derive_key(&shared_secret, &ciphertext.encapsulated_key)?;
        
        // 3. Decrypt with ChaCha20-Poly1305
        let plaintext = self.aead.decrypt(
            &encryption_key,
            &ciphertext.ciphertext,
            &ciphertext.tag,
            associated_data.unwrap_or(&[]),
        )?;
        
        Ok(plaintext)
    }
    
    /// Derive encryption key from shared secret
    fn derive_key(&self, shared_secret: &SharedSecret, encapsulated_key: &EncapsulatedKey) -> Result<EncryptionKey> {
        // Use SHAKE256 for key derivation
        let mut key = [0u8; 32];
        let mut hasher = Shake256::new();
        hasher.update(b"libQ-HPKE-Performance-v1");
        hasher.update(shared_secret.as_ref());
        hasher.update(encapsulated_key.as_ref());
        hasher.finalize(&mut key);
        Ok(EncryptionKey(key))
    }
}
```

## Unified HPKE Interface

### Factory Pattern

```rust
/// HPKE factory for creating instances based on security tier
pub struct HpkeFactory;

impl HpkeFactory {
    /// Create HPKE instance for the specified security tier
    pub fn create(tier: SecurityTier) -> Box<dyn Hpke> {
        match tier {
            SecurityTier::Ultra => Box::new(UltraHpke::new()),
            SecurityTier::Balanced => Box::new(BalancedHpke::new()),
            SecurityTier::Performance => Box::new(PerformanceHpke::new()),
        }
    }
}

/// Common HPKE trait
pub trait Hpke {
    /// Seal (encrypt) a message for a recipient
    fn seal(
        &self,
        recipient_pk: &PublicKey,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<HpkeCiphertext>;
    
    /// Open (decrypt) a message using recipient's secret key
    fn open(
        &self,
        recipient_sk: &SecretKey,
        ciphertext: &HpkeCiphertext,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    
    /// Get the security tier of this HPKE instance
    fn security_tier(&self) -> SecurityTier;
}
```

### High-Level API

```rust
/// High-level HPKE API
pub mod hpke {
    use super::*;
    
    /// Encrypt a message using HPKE
    pub fn encrypt(
        recipient_pk: &PublicKey,
        message: &[u8],
        associated_data: Option<&[u8]>,
        tier: SecurityTier,
    ) -> Result<HpkeCiphertext> {
        let hpke = HpkeFactory::create(tier);
        hpke.seal(recipient_pk, message, associated_data)
    }
    
    /// Decrypt a message using HPKE
    pub fn decrypt(
        recipient_sk: &SecretKey,
        ciphertext: &HpkeCiphertext,
        associated_data: Option<&[u8]>,
        tier: SecurityTier,
    ) -> Result<Vec<u8>> {
        let hpke = HpkeFactory::create(tier);
        hpke.open(recipient_sk, ciphertext, associated_data)
    }
    
    /// Create an HPKE context for stateful operations
    pub fn create_context(
        recipient_pk: &PublicKey,
        tier: SecurityTier,
    ) -> Result<HpkeContext> {
        let hpke = HpkeFactory::create(tier);
        let (shared_secret, encapsulated_key) = hpke.kem().encapsulate(recipient_pk)?;
        let encryption_key = hpke.derive_key(&shared_secret, &encapsulated_key)?;
        
        Ok(HpkeContext {
            tier,
            encapsulated_key,
            encryption_key,
            sequence_number: 0,
        })
    }
}
```

## Performance Characteristics

### Security vs Performance Trade-offs

| Tier | KEM Security | AEAD Performance | Overall Security | Use Case |
|------|-------------|------------------|------------------|----------|
| Ultra | Level 5 (256-bit) | SHAKE256 (slow) | Maximum | Critical systems |
| Balanced | Level 3 (192-bit) | AES-256-GCM (fast) | High | General purpose |
| Performance | Level 1 (128-bit) | ChaCha20-Poly1305 (fastest) | Strong | High throughput |

### Benchmark Targets

| Operation | Ultra | Balanced | Performance |
|-----------|-------|----------|-------------|
| Key Generation | < 50ms | < 15ms | < 5ms |
| Encryption | < 15ms | < 5ms | < 2ms |
| Decryption | < 15ms | < 5ms | < 2ms |
| Key Size | ~1.5KB | ~1.2KB | ~0.8KB |
| Ciphertext Overhead | ~1.5KB | ~1.2KB | ~0.8KB |

## Security Considerations

### Post-Quantum Security

- **KEM Security**: All tiers use post-quantum KEMs (CRYSTALS-Kyber)
- **Key Derivation**: SHAKE256 for all key derivation operations
- **Domain Separation**: Different derivation strings for each tier
- **Nonce Generation**: Cryptographically secure nonce generation

### Classical Security

- **Tier 2**: AES-256-GCM provides 256-bit classical security
- **Tier 3**: ChaCha20-Poly1305 provides 256-bit classical security
- **Authentication**: All tiers provide strong authentication
- **Confidentiality**: All tiers provide strong confidentiality

### Side-Channel Resistance

- **Constant-time operations**: All cryptographic operations are constant-time
- **Memory safety**: Secure memory management for sensitive data
- **Input validation**: Comprehensive validation of all inputs
- **Error handling**: Secure error handling without information leakage

## Testing Strategy

### Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ultra_hpke_encryption_decryption() {
        let hpke = UltraHpke::new();
        let (pk, sk) = Kyber5::new().generate_keypair().unwrap();
        let message = b"Hello, Post-Quantum World!";
        let ad = b"associated data";
        
        let ciphertext = hpke.seal(&pk, message, Some(ad)).unwrap();
        let decrypted = hpke.open(&sk, &ciphertext, Some(ad)).unwrap();
        
        assert_eq!(message, decrypted.as_slice());
    }
    
    #[test]
    fn test_balanced_hpke_encryption_decryption() {
        let hpke = BalancedHpke::new();
        let (pk, sk) = Kyber3::new().generate_keypair().unwrap();
        let message = b"Hello, Balanced World!";
        let ad = b"associated data";
        
        let ciphertext = hpke.seal(&pk, message, Some(ad)).unwrap();
        let decrypted = hpke.open(&sk, &ciphertext, Some(ad)).unwrap();
        
        assert_eq!(message, decrypted.as_slice());
    }
    
    #[test]
    fn test_performance_hpke_encryption_decryption() {
        let hpke = PerformanceHpke::new();
        let (pk, sk) = Kyber1::new().generate_keypair().unwrap();
        let message = b"Hello, Performance World!";
        let ad = b"associated data";
        
        let ciphertext = hpke.seal(&pk, message, Some(ad)).unwrap();
        let decrypted = hpke.open(&sk, &ciphertext, Some(ad)).unwrap();
        
        assert_eq!(message, decrypted.as_slice());
    }
}
```

### Integration Testing

```rust
#[test]
fn test_hpke_tier_interoperability() {
    let message = b"Test message";
    let ad = b"Test associated data";
    
    // Test all tiers
    for tier in &[SecurityTier::Ultra, SecurityTier::Balanced, SecurityTier::Performance] {
        let (pk, sk) = match tier {
            SecurityTier::Ultra => Kyber5::new().generate_keypair().unwrap(),
            SecurityTier::Balanced => Kyber3::new().generate_keypair().unwrap(),
            SecurityTier::Performance => Kyber1::new().generate_keypair().unwrap(),
        };
        
        let ciphertext = hpke::encrypt(&pk, message, Some(ad), *tier).unwrap();
        let decrypted = hpke::decrypt(&sk, &ciphertext, Some(ad), *tier).unwrap();
        
        assert_eq!(message, decrypted.as_slice());
    }
}
```

## Usage Examples

### Basic HPKE Usage

```rust
use libq::hpke::{SecurityTier, encrypt, decrypt};

// Generate keypair
let (pk, sk) = libq::simple::keygen(1)?;

// Encrypt message using balanced tier
let message = b"Secret message";
let ciphertext = encrypt(&pk, message, Some(b"metadata"), SecurityTier::Balanced)?;

// Decrypt message
let decrypted = decrypt(&sk, &ciphertext, Some(b"metadata"), SecurityTier::Balanced)?;
assert_eq!(message, decrypted.as_slice());
```

### Tier Selection Based on Use Case

```rust
fn encrypt_sensitive_data(recipient_pk: &PublicKey, data: &[u8]) -> Result<HpkeCiphertext> {
    // Use ultra-secure tier for sensitive data
    hpke::encrypt(recipient_pk, data, None, SecurityTier::Ultra)
}

fn encrypt_high_volume_data(recipient_pk: &PublicKey, data: &[u8]) -> Result<HpkeCiphertext> {
    // Use performance tier for high-volume data
    hpke::encrypt(recipient_pk, data, None, SecurityTier::Performance)
}

fn encrypt_general_data(recipient_pk: &PublicKey, data: &[u8]) -> Result<HpkeCiphertext> {
    // Use balanced tier for general data
    hpke::encrypt(recipient_pk, data, None, SecurityTier::Balanced)
}
```

### Stateful HPKE Context

```rust
use libq::hpke::create_context;

// Create HPKE context for multiple operations
let context = create_context(&recipient_pk, SecurityTier::Balanced)?;

// Use context for multiple encryptions
for (i, message) in messages.iter().enumerate() {
    let ciphertext = context.encrypt(message, Some(&i.to_le_bytes()))?;
    // Send ciphertext...
}
```

This HPKE architecture provides a complete, three-tier system for post-quantum public key encryption that balances security and performance for different use cases.
