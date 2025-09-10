# HPKE Architecture

lib-Q implements a four-tier Hybrid Public Key Encryption (HPKE) system that provides post-quantum security with different performance characteristics. HPKE combines post-quantum key encapsulation mechanisms (KEMs) with symmetric encryption to provide secure, authenticated encryption.

## Four-Tier System

```
lib-Q HPKE Architecture
├── Tier 1: Ultra-Secure (Pure Post-Quantum)
│   ├── KEM: ML-KEM (Level 5)
│   ├── AEAD: SHAKE256-based construction
│   └── Use Case: Maximum security, performance secondary
├── Tier 2: Balanced (Post-Quantum)
│   ├── KEM: ML-KEM (Level 3)
│   ├── AEAD: Saturnin (post-quantum symmetric)
│   └── Use Case: Balanced security and performance
├── Tier 3: Performance (Post-Quantum + Optimized)
│   ├── KEM: ML-KEM (Level 1) / DAWN
│   ├── AEAD: Saturnin (optimized modes)
│   └── Use Case: Maximum performance on constrained systems
└── Tier 4: Hybrid Security (RCPKC)
    ├── KEM: RCPKC (multiple algorithm combination)
    ├── AEAD: Multiple post-quantum algorithms
    └── Use Case: Maximum security through algorithm diversity
```

## Core Components

```rust
/// HPKE security tiers
pub enum SecurityTier {
    /// Ultra-secure: Pure post-quantum with maximum security
    Ultra,
    /// Balanced: Post-quantum with good performance
    Balanced,
    /// Performance: Post-quantum + optimized
    Performance,
    /// Hybrid: RCPKC-based with algorithm diversity
    Hybrid,
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

Tier 1 provides maximum security by using only post-quantum algorithms throughout the entire encryption chain. This eliminates any reliance on classical cryptographic assumptions.

### Implementation

```rust
/// Ultra-secure HPKE implementation
pub struct UltraHpke {
    kem: MlKem5,
    aead: Shake256Aead,
}

impl UltraHpke {
    /// Create a new ultra-secure HPKE instance
    pub fn new() -> Self {
        Self {
            kem: MlKem5::new(),
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
        hasher.update(b"lib-Q-HPKE-Ultra-v1");
        hasher.update(shared_secret.as_ref());
        hasher.update(encapsulated_key.as_ref());
        hasher.finalize(&mut key);
        Ok(EncryptionKey(key))
    }
}
```

## Tier 2: Balanced HPKE

Tier 2 provides balanced security and performance using Saturnin AEAD. Saturnin is a post-quantum symmetric algorithm suite designed for IoT and constrained devices, providing authenticated encryption and hashing modes with superior post-quantum security compared to classical alternatives.

### Implementation

```rust
/// Balanced HPKE implementation
pub struct BalancedHpke {
    kem: MlKem3,
    aead: SaturninAead,
}

impl BalancedHpke {
    /// Create a new balanced HPKE instance
    pub fn new() -> Self {
        Self {
            kem: MlKem3::new(),
            aead: SaturninAead::new(),
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
        
        // 4. Encrypt with Saturnin
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
        
        // 3. Decrypt with Saturnin
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
        hasher.update(b"lib-Q-HPKE-Balanced-v1");
        hasher.update(shared_secret.as_ref());
        hasher.update(encapsulated_key.as_ref());
        hasher.finalize(&mut key);
        Ok(EncryptionKey(key))
    }
}
```

## Tier 3: Performance HPKE

Tier 3 provides maximum performance on constrained systems using optimized Saturnin AEAD modes. This tier is optimized for ultra-lightweight applications on 8/16/32-bit MCUs and microcontrollers while maintaining post-quantum security.

### Implementation

```rust
/// Performance HPKE implementation
pub struct PerformanceHpke {
    kem: MlKem1,
    aead: SaturninAead,
}

impl PerformanceHpke {
    /// Create a new performance HPKE instance
    pub fn new() -> Self {
        Self {
            kem: MlKem1::new(),
            aead: SaturninAead::new(),
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
        
        // 4. Encrypt with Saturnin
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
        
        // 3. Decrypt with Saturnin
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
        hasher.update(b"lib-Q-HPKE-Performance-v1");
        hasher.update(shared_secret.as_ref());
        hasher.update(encapsulated_key.as_ref());
        hasher.finalize(&mut key);
        Ok(EncryptionKey(key))
    }
}
```

## Tier 4: Hybrid Security HPKE

Tier 4 provides maximum security through algorithm diversity using RCPKC (Randomized Concatenated Public Key Cryptography). This tier combines multiple post-quantum algorithms to provide defense in depth against algorithm-specific attacks.

### Implementation

```rust
/// Hybrid security HPKE implementation
pub struct HybridHpke {
    kem: RcpkcKem,
    aead: RcpkcAead,
}

impl HybridHpke {
    /// Create a new hybrid security HPKE instance
    pub fn new() -> Self {
        Self {
            kem: RcpkcKem::new(),
            aead: RcpkcAead::new(),
        }
    }
    
    /// Seal (encrypt) a message for a recipient
    pub fn seal(
        &self,
        recipient_pk: &PublicKey,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<HpkeCiphertext> {
        // 1. Generate ephemeral key pair using multiple algorithms
        let (ephemeral_sk, ephemeral_pk) = self.kem.generate_keypair()?;
        
        // 2. Encapsulate shared secret with recipient's public key
        let (shared_secret, encapsulated_key) = self.kem.encapsulate(recipient_pk)?;
        
        // 3. Derive encryption key using SHAKE256
        let encryption_key = self.derive_key(&shared_secret, &encapsulated_key)?;
        
        // 4. Encrypt with multiple post-quantum algorithms
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
        
        // 3. Decrypt with multiple post-quantum algorithms
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
        hasher.update(b"lib-Q-HPKE-Hybrid-v1");
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
            SecurityTier::Hybrid => Box::new(HybridHpke::new()),
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
| Balanced | Level 3 (192-bit) | Saturnin (fast) | High | General purpose |
| Performance | Level 1 (128-bit) | Saturnin (optimized) | Strong | High throughput |
| Hybrid | Multiple algorithms | Multiple algorithms | Maximum | Defense in depth |

### Benchmark Targets

| Operation | Ultra | Balanced | Performance | Hybrid |
|-----------|-------|----------|-------------|--------|
| Key Generation | < 50ms | < 15ms | < 5ms | < 100ms |
| Encryption | < 15ms | < 5ms | < 2ms | < 20ms |
| Decryption | < 15ms | < 5ms | < 2ms | < 20ms |
| Key Size | ~1.5KB | ~1.2KB | ~0.8KB | ~3KB |
| Ciphertext Overhead | ~1.5KB | ~1.2KB | ~0.8KB | ~2KB |

## Security Considerations

### Post-Quantum Security

- **KEM Security**: All tiers use post-quantum KEMs (ML-KEM)
- **Key Derivation**: SHAKE256 for all key derivation operations
- **Domain Separation**: Different derivation strings for each tier
- **Nonce Generation**: Cryptographically secure nonce generation

### Post-Quantum Security

- **Tier 2**: Saturnin provides strong post-quantum security
- **Tier 3**: Saturnin provides strong post-quantum security
- **Tier 4**: RCPKC provides maximum post-quantum security through algorithm diversity
- **Authentication**: All tiers provide strong authentication
- **Confidentiality**: All tiers provide strong confidentiality

### Side-Channel Resistance

- **Constant-time operations**: All cryptographic operations are constant-time
- **Memory safety**: Secure memory management for sensitive data
- **Input validation**: Comprehensive validation of all inputs
- **Error handling**: Secure error handling without information leakage

## Usage Examples

### Basic HPKE Usage

```rust
use lib-q::hpke::{SecurityTier, encrypt, decrypt};

// Generate keypair
let (pk, sk) = lib-q::simple::keygen(1)?;

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

fn encrypt_maximum_security_data(recipient_pk: &PublicKey, data: &[u8]) -> Result<HpkeCiphertext> {
    // Use hybrid tier for maximum security through algorithm diversity
    hpke::encrypt(recipient_pk, data, None, SecurityTier::Hybrid)
}
```

### Stateful HPKE Context

```rust
use lib-q::hpke::create_context;

// Create HPKE context for multiple operations
let context = create_context(&recipient_pk, SecurityTier::Balanced)?;

// Use context for multiple encryptions
for (i, message) in messages.iter().enumerate() {
    let ciphertext = context.encrypt(message, Some(&i.to_le_bytes()))?;
    // Send ciphertext...
}
```
