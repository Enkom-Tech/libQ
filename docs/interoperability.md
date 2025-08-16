# Interoperability & Networking Architecture

## Overview

lib-Q provides comprehensive interoperability with existing cryptographic libraries and networking protocols, enabling seamless integration into existing systems while maintaining post-quantum security. The architecture supports multiple formats, protocols, and integration patterns.

## Interoperability Strategy

### Core Principles

1. **Format Compatibility**: Support multiple serialization and encoding formats
2. **Protocol Integration**: Compatible with existing networking protocols
3. **Library Interop**: Easy integration with libsodium, OpenSSL, and other libraries
4. **Backward Compatibility**: Gradual migration path from classical to post-quantum
5. **Standards Compliance**: Follow established cryptographic standards and RFCs

### Interoperability Layers

```
lib-Q Interoperability Stack
├── Application Layer
│   ├── High-level APIs (libhydrogen-style)
│   ├── Protocol-specific bindings
│   └── Language-specific wrappers
├── Format Layer
│   ├── Binary formats (raw bytes)
│   ├── Text formats (Base64, Hex)
│   ├── Structured formats (JSON, CBOR)
│   └── Protocol formats (ASN.1, DER)
├── Protocol Layer
│   ├── TLS/DTLS integration
│   ├── SSH integration
│   ├── WireGuard integration
│   └── Custom protocols
└── Library Layer
    ├── libsodium compatibility
    ├── OpenSSL compatibility
    ├── BouncyCastle compatibility
    └── Platform-specific bindings
```

## Serialization & Encoding

### Binary Formats

```rust
/// Binary format traits for lib-Q types
pub trait BinaryFormat {
    /// Serialize to raw bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Deserialize from raw bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
    
    /// Get the size in bytes
    fn size(&self) -> usize;
}

/// Binary serialization for public keys
impl BinaryFormat for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KYBER5_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: KYBER5_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        
        let mut key = [0u8; KYBER5_PUBLIC_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(PublicKey(key))
    }
    
    fn size(&self) -> usize {
        KYBER5_PUBLIC_KEY_SIZE
    }
}

/// Binary serialization for signatures
impl BinaryFormat for Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DILITHIUM5_SIGNATURE_SIZE {
            return Err(Error::InvalidSignatureSize {
                expected: DILITHIUM5_SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        
        let mut sig = [0u8; DILITHIUM5_SIGNATURE_SIZE];
        sig.copy_from_slice(bytes);
        Ok(Signature(sig))
    }
    
    fn size(&self) -> usize {
        DILITHIUM5_SIGNATURE_SIZE
    }
}
```

### Text Formats

```rust
/// Text encoding formats
pub enum TextFormat {
    /// Base64 encoding (RFC 4648)
    Base64,
    /// Base64 URL-safe encoding (RFC 4648)
    Base64Url,
    /// Hexadecimal encoding
    Hex,
    /// PEM format (RFC 7468)
    Pem,
}

/// Text encoding trait
pub trait TextEncoding {
    /// Encode to text format
    fn encode(&self, format: TextFormat) -> String;
    
    /// Decode from text format
    fn decode(text: &str, format: TextFormat) -> Result<Self>
    where
        Self: Sized;
}

/// Base64 encoding implementation
impl TextEncoding for PublicKey {
    fn encode(&self, format: TextFormat) -> String {
        match format {
            TextFormat::Base64 => base64::encode(self.as_ref()),
            TextFormat::Base64Url => base64::encode_config(
                self.as_ref(),
                base64::URL_SAFE_NO_PAD,
            ),
            TextFormat::Hex => hex::encode(self.as_ref()),
            TextFormat::Pem => {
                format!(
                    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                    base64::encode(self.as_ref())
                )
            }
        }
    }
    
    fn decode(text: &str, format: TextFormat) -> Result<Self> {
        let bytes = match format {
            TextFormat::Base64 => base64::decode(text)?,
            TextFormat::Base64Url => base64::decode_config(
                text,
                base64::URL_SAFE_NO_PAD,
            )?,
            TextFormat::Hex => hex::decode(text)?,
            TextFormat::Pem => {
                // Extract base64 content from PEM
                let content = text
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>();
                base64::decode(&content)?
            }
        };
        
        Self::from_bytes(&bytes)
    }
}
```

### Structured Formats

```rust
use serde::{Deserialize, Serialize};

/// JSON serialization for lib-Q types
#[derive(Serialize, Deserialize)]
pub struct JsonPublicKey {
    /// Algorithm identifier
    pub algorithm: String,
    /// Security level
    pub security_level: u32,
    /// Key data (base64 encoded)
    pub key_data: String,
    /// Creation timestamp
    pub created_at: Option<String>,
}

/// CBOR serialization for lib-Q types
#[derive(Serialize, Deserialize)]
pub struct CborPublicKey {
    /// Algorithm identifier
    pub algorithm: u32,
    /// Security level
    pub security_level: u32,
    /// Key data (raw bytes)
    pub key_data: Vec<u8>,
    /// Creation timestamp
    pub created_at: Option<u64>,
}

/// Structured format serialization
impl PublicKey {
    /// Convert to JSON format
    pub fn to_json(&self) -> JsonPublicKey {
        JsonPublicKey {
            algorithm: "kyber5".to_string(),
            security_level: 5,
            key_data: self.encode(TextFormat::Base64),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
        }
    }
    
    /// Convert from JSON format
    pub fn from_json(json: &JsonPublicKey) -> Result<Self> {
        if json.algorithm != "kyber5" {
            return Err(Error::InvalidAlgorithm {
                algorithm: json.algorithm.clone(),
            });
        }
        
        Self::decode(&json.key_data, TextFormat::Base64)
    }
    
    /// Convert to CBOR format
    pub fn to_cbor(&self) -> CborPublicKey {
        CborPublicKey {
            algorithm: 1, // Kyber algorithm ID
            security_level: 5,
            key_data: self.to_bytes(),
            created_at: Some(chrono::Utc::now().timestamp()),
        }
    }
    
    /// Convert from CBOR format
    pub fn from_cbor(cbor: &CborPublicKey) -> Result<Self> {
        if cbor.algorithm != 1 {
            return Err(Error::InvalidAlgorithm {
                algorithm: format!("algorithm_{}", cbor.algorithm),
            });
        }
        
        Self::from_bytes(&cbor.key_data)
    }
}
```

## Library Integration

### libsodium Compatibility

```rust
/// libsodium compatibility layer
pub mod sodium {
    use super::*;
    
    /// libsodium-style key generation
    pub fn crypto_kx_keypair() -> (PublicKey, SecretKey) {
        simple::keygen(1).expect("Key generation failed")
    }
    
    /// libsodium-style key exchange
    pub fn crypto_kx_client_session_keys(
        client_pk: &PublicKey,
        client_sk: &SecretKey,
        server_pk: &PublicKey,
    ) -> Result<(SharedSecret, SharedSecret)> {
        let shared = simple::exchange(client_sk, server_pk)?;
        let rx = simple::derive_key(&shared, b"rx")?;
        let tx = simple::derive_key(&shared, b"tx")?;
        Ok((rx, tx))
    }
    
    /// libsodium-style box encryption
    pub fn crypto_box_easy(
        message: &[u8],
        nonce: &[u8; 24],
        recipient_pk: &PublicKey,
        sender_sk: &SecretKey,
    ) -> Result<Vec<u8>> {
        // Use HPKE instead of box
        let ciphertext = simple::hpke_encrypt(
            recipient_pk,
            message,
            Some(nonce),
            SecurityTier::Balanced,
        )?;
        Ok(ciphertext.to_bytes())
    }
    
    /// libsodium-style box decryption
    pub fn crypto_box_open_easy(
        ciphertext: &[u8],
        nonce: &[u8; 24],
        sender_pk: &PublicKey,
        recipient_sk: &SecretKey,
    ) -> Result<Vec<u8>> {
        let hpke_ciphertext = HpkeCiphertext::from_bytes(ciphertext)?;
        simple::hpke_decrypt(recipient_sk, &hpke_ciphertext, Some(nonce))
    }
    
    /// libsodium-style signature generation
    pub fn crypto_sign_detached(
        message: &[u8],
        secret_key: &SecretKey,
    ) -> Result<Signature> {
        simple::sign(secret_key, message)
    }
    
    /// libsodium-style signature verification
    pub fn crypto_sign_verify_detached(
        signature: &Signature,
        message: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool> {
        simple::verify(public_key, message, signature)
    }
}
```

### OpenSSL Compatibility

```rust
/// OpenSSL compatibility layer
pub mod openssl {
    use super::*;
    
    /// OpenSSL-style key generation
    pub fn evp_pkey_keygen(algorithm: &str) -> Result<(PublicKey, SecretKey)> {
        match algorithm {
            "kyber1" => simple::keygen(1),
            "kyber3" => simple::keygen(3),
            "kyber5" => simple::keygen(5),
            _ => Err(Error::InvalidAlgorithm {
                algorithm: algorithm.to_string(),
            }),
        }
    }
    
    /// OpenSSL-style encryption
    pub fn evp_seal_init(
        recipient_pk: &PublicKey,
        algorithm: &str,
    ) -> Result<HpkeContext> {
        let tier = match algorithm {
            "kyber1" => SecurityTier::Performance,
            "kyber3" => SecurityTier::Balanced,
            "kyber5" => SecurityTier::Ultra,
            _ => return Err(Error::InvalidAlgorithm {
                algorithm: algorithm.to_string(),
            }),
        };
        
        hpke::create_context(recipient_pk, tier)
    }
    
    /// OpenSSL-style decryption
    pub fn evp_open_init(
        recipient_sk: &SecretKey,
        algorithm: &str,
    ) -> Result<HpkeContext> {
        // Similar to seal_init but for decryption
        unimplemented!("OpenSSL-style decryption context")
    }
}
```

### Platform-Specific Bindings

```rust
/// C bindings for lib-Q
#[no_mangle]
pub extern "C" fn libq_keygen(
    security_level: u32,
    public_key: *mut u8,
    secret_key: *mut u8,
) -> i32 {
    let (pk, sk) = match simple::keygen(security_level) {
        Ok(keys) => keys,
        Err(_) => return -1,
    };
    
    unsafe {
        std::ptr::copy_nonoverlapping(
            pk.as_ref().as_ptr(),
            public_key,
            pk.size(),
        );
        std::ptr::copy_nonoverlapping(
            sk.as_ref().as_ptr(),
            secret_key,
            sk.size(),
        );
    }
    
    0
}

#[no_mangle]
pub extern "C" fn libq_exchange(
    my_secret: *const u8,
    their_public: *const u8,
    shared_secret: *mut u8,
) -> i32 {
    let my_sk = match SecretKey::from_bytes(unsafe {
        std::slice::from_raw_parts(my_secret, KYBER5_SECRET_KEY_SIZE)
    }) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    
    let their_pk = match PublicKey::from_bytes(unsafe {
        std::slice::from_raw_parts(their_public, KYBER5_PUBLIC_KEY_SIZE)
    }) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    
    let shared = match simple::exchange(&my_sk, &their_pk) {
        Ok(secret) => secret,
        Err(_) => return -1,
    };
    
    unsafe {
        std::ptr::copy_nonoverlapping(
            shared.as_ref().as_ptr(),
            shared_secret,
            shared.size(),
        );
    }
    
    0
}
```

## Networking Protocols

### TLS/DTLS Integration

```rust
/// TLS integration for lib-Q
pub mod tls {
    use super::*;
    
    /// TLS cipher suite for lib-Q
    pub const TLS_CIPHER_SUITE: u16 = 0x1301; // TLS_AES_256_GCM_SHA384
    
    /// TLS key exchange for lib-Q
    pub const TLS_KEY_EXCHANGE: u16 = 0x0016; // TLS_KEM_KYBER
    
    /// TLS signature algorithm for lib-Q
    pub const TLS_SIGNATURE_ALGORITHM: u16 = 0x0808; // TLS_SIG_DILITHIUM
    
    /// TLS extension for lib-Q support
    pub const TLS_EXTENSION: u16 = 0x0017; // lib-Q post-quantum extension
    
    /// TLS handshake message for lib-Q
    pub struct Lib-QTlsHandshake {
        /// Supported algorithms
        pub algorithms: Vec<u16>,
        /// Public key
        pub public_key: PublicKey,
        /// Signature
        pub signature: Signature,
    }
    
    /// Generate TLS key exchange message
    pub fn generate_key_exchange(
        algorithms: &[u16],
        secret_key: &SecretKey,
    ) -> Result<Lib-QTlsHandshake> {
        let public_key = PublicKey::from_secret_key(secret_key)?;
        let signature = simple::sign(secret_key, &public_key.to_bytes())?;
        
        Ok(Lib-QTlsHandshake {
            algorithms: algorithms.to_vec(),
            public_key,
            signature,
        })
    }
    
    /// Process TLS key exchange message
    pub fn process_key_exchange(
        handshake: &Lib-QTlsHandshake,
        peer_public_key: &PublicKey,
    ) -> Result<SharedSecret> {
        // Verify signature
        let is_valid = simple::verify(
            peer_public_key,
            &handshake.public_key.to_bytes(),
            &handshake.signature,
        )?;
        
        if !is_valid {
            return Err(Error::VerificationFailed {
                operation: "TLS handshake signature".to_string(),
            });
        }
        
        // Perform key exchange
        simple::exchange(secret_key, &handshake.public_key)
    }
}
```

### SSH Integration

```rust
/// SSH integration for lib-Q
pub mod ssh {
    use super::*;
    
    /// SSH key format for lib-Q
    pub const SSH_KEY_TYPE: &str = "ssh-lib-q-kyber5";
    
    /// SSH public key
    pub struct SshPublicKey {
        /// Key type
        pub key_type: String,
        /// Public key data
        pub public_key: PublicKey,
        /// Comment
        pub comment: String,
    }
    
    /// SSH private key
    pub struct SshPrivateKey {
        /// Key type
        pub key_type: String,
        /// Secret key data
        pub secret_key: SecretKey,
        /// Comment
        pub comment: String,
    }
    
    /// Generate SSH key pair
    pub fn generate_ssh_keypair(comment: &str) -> Result<(SshPublicKey, SshPrivateKey)> {
        let (pk, sk) = simple::keygen(5)?; // Use highest security level for SSH
        
        let public_key = SshPublicKey {
            key_type: SSH_KEY_TYPE.to_string(),
            public_key: pk,
            comment: comment.to_string(),
        };
        
        let private_key = SshPrivateKey {
            key_type: SSH_KEY_TYPE.to_string(),
            secret_key: sk,
            comment: comment.to_string(),
        };
        
        Ok((public_key, private_key))
    }
    
    /// Encode SSH public key
    pub fn encode_ssh_public_key(key: &SshPublicKey) -> String {
        let key_data = key.public_key.encode(TextFormat::Base64);
        format!("{} {} {}", key.key_type, key_data, key.comment)
    }
    
    /// Decode SSH public key
    pub fn decode_ssh_public_key(ssh_key: &str) -> Result<SshPublicKey> {
        let parts: Vec<&str> = ssh_key.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(Error::InvalidAlgorithm {
                algorithm: "SSH key format".to_string(),
            });
        }
        
        let key_type = parts[0];
        let key_data = parts[1];
        let comment = parts[2];
        
        if key_type != SSH_KEY_TYPE {
            return Err(Error::InvalidAlgorithm {
                algorithm: key_type.to_string(),
            });
        }
        
        let public_key = PublicKey::decode(key_data, TextFormat::Base64)?;
        
        Ok(SshPublicKey {
            key_type: key_type.to_string(),
            public_key,
            comment: comment.to_string(),
        })
    }
}
```

### WireGuard Integration

```rust
/// WireGuard integration for lib-Q
pub mod wireguard {
    use super::*;
    
    /// WireGuard key pair
    pub struct WireGuardKeyPair {
        /// Private key
        pub private_key: SecretKey,
        /// Public key
        pub public_key: PublicKey,
    }
    
    /// Generate WireGuard key pair
    pub fn generate_wireguard_keypair() -> Result<WireGuardKeyPair> {
        let (pk, sk) = simple::keygen(3)?; // Use balanced security level for WireGuard
        
        Ok(WireGuardKeyPair {
            private_key: sk,
            public_key: pk,
        })
    }
    
    /// WireGuard handshake
    pub struct WireGuardHandshake {
        /// Initiator's ephemeral public key
        pub initiator_ephemeral: PublicKey,
        /// Responder's ephemeral public key
        pub responder_ephemeral: PublicKey,
        /// Encrypted static key
        pub encrypted_static: Vec<u8>,
        /// Encrypted timestamp
        pub encrypted_timestamp: Vec<u8>,
    }
    
    /// Perform WireGuard handshake
    pub fn perform_wireguard_handshake(
        initiator_static: &SecretKey,
        responder_static: &PublicKey,
    ) -> Result<WireGuardHandshake> {
        // Generate ephemeral keys
        let (init_ephemeral_pk, init_ephemeral_sk) = simple::keygen(3)?;
        let (resp_ephemeral_pk, resp_ephemeral_sk) = simple::keygen(3)?;
        
        // Perform key exchange
        let shared1 = simple::exchange(&init_ephemeral_sk, &resp_ephemeral_pk)?;
        let shared2 = simple::exchange(&init_ephemeral_sk, responder_static)?;
        
        // Derive encryption keys
        let key1 = simple::derive_key(&shared1, b"wireguard-key1")?;
        let key2 = simple::derive_key(&shared2, b"wireguard-key2")?;
        
        // Encrypt static key and timestamp
        let encrypted_static = simple::encrypt(&key1, initiator_static.as_ref(), None)?;
        let timestamp = chrono::Utc::now().timestamp().to_le_bytes();
        let encrypted_timestamp = simple::encrypt(&key2, &timestamp, None)?;
        
        Ok(WireGuardHandshake {
            initiator_ephemeral: init_ephemeral_pk,
            responder_ephemeral: resp_ephemeral_pk,
            encrypted_static: encrypted_static.to_bytes(),
            encrypted_timestamp: encrypted_timestamp.to_bytes(),
        })
    }
}
```

## Migration Paths

### From libsodium

```rust
/// Migration utilities from libsodium
pub mod migration {
    use super::*;
    
    /// Convert libsodium key to lib-Q key
    pub fn sodium_to_libq_key(sodium_key: &[u8]) -> Result<PublicKey> {
        // libsodium keys are typically 32 bytes for X25519
        // lib-Q keys are larger, so we need to handle the conversion
        if sodium_key.len() == 32 {
            // Convert X25519 key to lib-Q key
            // This would require a conversion function
            unimplemented!("X25519 to lib-Q key conversion")
        } else {
            Err(Error::InvalidKeySize {
                expected: 32,
                actual: sodium_key.len(),
            })
        }
    }
    
    /// Convert lib-Q key to libsodium key
    pub fn libq_to_sodium_key(libq_key: &PublicKey) -> Result<Vec<u8>> {
        // Convert lib-Q key to libsodium-compatible format
        // This might involve key derivation or format conversion
        unimplemented!("lib-Q to libsodium key conversion")
    }
    
    /// Migration helper for applications
    pub struct MigrationHelper {
        /// Original libsodium keys
        pub sodium_keys: Vec<Vec<u8>>,
        /// New lib-Q keys
        pub libq_keys: Vec<PublicKey>,
    }
    
    impl MigrationHelper {
        /// Create migration helper
        pub fn new() -> Self {
            Self {
                sodium_keys: Vec::new(),
                libq_keys: Vec::new(),
            }
        }
        
        /// Add libsodium key for migration
        pub fn add_sodium_key(&mut self, key: Vec<u8>) {
            self.sodium_keys.push(key);
        }
        
        /// Migrate all keys to lib-Q
        pub fn migrate_keys(&mut self) -> Result<()> {
            for sodium_key in &self.sodium_keys {
                let libq_key = sodium_to_libq_key(sodium_key)?;
                self.libq_keys.push(libq_key);
            }
            Ok(())
        }
    }
}
```

### From OpenSSL

```rust
/// Migration utilities from OpenSSL
pub mod openssl_migration {
    use super::*;
    
    /// Convert OpenSSL key to lib-Q key
    pub fn openssl_to_libq_key(openssl_key: &[u8], key_type: &str) -> Result<PublicKey> {
        match key_type {
            "RSA" => {
                // Convert RSA key to lib-Q key
                unimplemented!("RSA to lib-Q key conversion")
            }
            "EC" => {
                // Convert EC key to lib-Q key
                unimplemented!("EC to lib-Q key conversion")
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: key_type.to_string(),
            }),
        }
    }
    
    /// Convert lib-Q key to OpenSSL key
    pub fn libq_to_openssl_key(libq_key: &PublicKey) -> Result<Vec<u8>> {
        // Convert lib-Q key to OpenSSL-compatible format
        unimplemented!("lib-Q to OpenSSL key conversion")
    }
}
```

## Testing & Validation

### Interoperability Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_libsodium_compatibility() {
        // Test libsodium-style API
        let (pk, sk) = sodium::crypto_kx_keypair();
        let message = b"Hello, libsodium!";
        
        let ciphertext = sodium::crypto_box_easy(
            message,
            &[0u8; 24],
            &pk,
            &sk,
        ).unwrap();
        
        let decrypted = sodium::crypto_box_open_easy(
            &ciphertext,
            &[0u8; 24],
            &pk,
            &sk,
        ).unwrap();
        
        assert_eq!(message, decrypted.as_slice());
    }
    
    #[test]
    fn test_format_roundtrip() {
        let (pk, sk) = simple::keygen(1).unwrap();
        
        // Test binary format
        let bytes = pk.to_bytes();
        let pk2 = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_ref(), pk2.as_ref());
        
        // Test text format
        let base64 = pk.encode(TextFormat::Base64);
        let pk3 = PublicKey::decode(&base64, TextFormat::Base64).unwrap();
        assert_eq!(pk.as_ref(), pk3.as_ref());
        
        // Test JSON format
        let json = pk.to_json();
        let pk4 = PublicKey::from_json(&json).unwrap();
        assert_eq!(pk.as_ref(), pk4.as_ref());
    }
    
    #[test]
    fn test_ssh_integration() {
        let (public_key, private_key) = ssh::generate_ssh_keypair("test@example.com").unwrap();
        
        let ssh_string = ssh::encode_ssh_public_key(&public_key);
        let decoded_key = ssh::decode_ssh_public_key(&ssh_string).unwrap();
        
        assert_eq!(public_key.public_key.as_ref(), decoded_key.public_key.as_ref());
        assert_eq!(public_key.comment, decoded_key.comment);
    }
}
```

This interoperability architecture ensures that lib-Q can seamlessly integrate with existing systems while providing post-quantum security. The comprehensive format support, library compatibility layers, and networking protocol integration make it easy to adopt lib-Q in existing applications.
