//! SHAKE256 AEAD implementation using lib-q-hash

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(feature = "alloc", feature = "shake256"))]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
    Result,
};
#[cfg(feature = "shake256")]
use lib_q_hash::{
    Shake256,
    digest::{
        ExtendableOutput,
        Update,
        XofReader,
    },
};

/// SHAKE256 AEAD implementation using lib-q-hash
#[derive(Debug, Clone)]
pub struct Shake256Aead;

impl Shake256Aead {
    /// Create a new SHAKE256 AEAD implementation
    pub fn new() -> Self {
        Self
    }

    /// Fill random bytes using a secure random number generator
    #[cfg(feature = "shake256")]
    pub(crate) fn fill_random_bytes(buf: &mut [u8]) -> Result<()> {
        use lib_q_random::new_secure_rng;
        let mut rng = new_secure_rng()?;
        rng.fill_bytes(buf);
        Ok(())
    }

}

impl Aead for Shake256Aead {
    #[cfg(feature = "shake256")]
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key_bytes = key.as_bytes();
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.unwrap_or(&[]);

        // Validate key length (SHAKE256 AEAD requires 32 bytes)
        if key_bytes.len() != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        // Validate nonce length (SHAKE256 AEAD requires 16 bytes)
        if nonce_bytes.len() != 16 {
            return Err(Error::InvalidNonceSize {
                expected: 16,
                actual: nonce_bytes.len(),
            });
        }

        // Security validation: reject zero keys
        if key_bytes.iter().all(|&b| b == 0) {
            return Err(Error::InvalidKeyFormat);
        }

        // Derive encryption key and MAC key using SHAKE256
        let mut encryption_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        // Derive encryption key
        let mut enc_key_hasher = Shake256::default();
        enc_key_hasher.update(b"LIBQ-SHAKE256-AEAD-ENC");
        enc_key_hasher.update(key_bytes);
        enc_key_hasher.update(nonce_bytes);
        let mut enc_key_reader = enc_key_hasher.finalize_xof();
        enc_key_reader.read(&mut encryption_key);

        // Derive MAC key
        let mut mac_key_hasher = Shake256::default();
        mac_key_hasher.update(b"LIBQ-SHAKE256-AEAD-MAC");
        mac_key_hasher.update(key_bytes);
        mac_key_hasher.update(nonce_bytes);
        let mut mac_key_reader = mac_key_hasher.finalize_xof();
        mac_key_reader.read(&mut mac_key);

        // Generate random IV for stream cipher (16 bytes)
        let mut iv = [0u8; 16];
        Self::fill_random_bytes(&mut iv)?;

        // Encrypt plaintext using SHAKE256 as stream cipher
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut stream_hasher = Shake256::default();
        stream_hasher.update(b"LIBQ-SHAKE256-AEAD-STREAM");
        stream_hasher.update(&encryption_key);
        stream_hasher.update(&iv);
        let mut stream_reader = stream_hasher.finalize_xof();

        let mut keystream = [0u8; 32];
        for (i, chunk) in plaintext.chunks(32).enumerate() {
            stream_reader.read(&mut keystream);
            for (j, &byte) in chunk.iter().enumerate() {
                ciphertext[i * 32 + j] = byte ^ keystream[j];
            }
        }

        // Compute MAC over nonce || aad || ciphertext
        let mut mac_hasher = Shake256::default();
        mac_hasher.update(b"LIBQ-SHAKE256-AEAD-MAC");
        mac_hasher.update(&mac_key);
        mac_hasher.update(nonce_bytes);
        mac_hasher.update(aad);
        mac_hasher.update(&ciphertext);
        let mut mac_reader = mac_hasher.finalize_xof();

        let mut mac_tag = [0u8; 32];
        mac_reader.read(&mut mac_tag);

        // Return: iv || ciphertext || mac_tag
        let mut result = Vec::new();
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&mac_tag);
        Ok(result)
    }

    #[cfg(not(feature = "shake256"))]
    fn encrypt(
        &self,
        _key: &AeadKey,
        _nonce: &Nonce,
        _plaintext: &[u8],
        _associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(Error::NotImplemented {
            feature: "SHAKE256 feature not enabled".to_string(),
        })
    }

    #[cfg(feature = "shake256")]
    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key_bytes = key.as_bytes();
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.unwrap_or(&[]);

        // Validate key length (SHAKE256 AEAD requires 32 bytes)
        if key_bytes.len() != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        // Validate nonce length (SHAKE256 AEAD requires 16 bytes)
        if nonce_bytes.len() != 16 {
            return Err(Error::InvalidNonceSize {
                expected: 16,
                actual: nonce_bytes.len(),
            });
        }

        // Check minimum ciphertext length (must have IV + MAC tag)
        if ciphertext.len() < 48 {
            // 16 (IV) + 32 (MAC)
            return Err(Error::InvalidCiphertextSize {
                expected: 48,
                actual: ciphertext.len(),
            });
        }

        // Security validation: reject zero keys
        if key_bytes.iter().all(|&b| b == 0) {
            return Err(Error::InvalidKeyFormat);
        }

        // Split: iv || encrypted_data || mac_tag
        let iv = &ciphertext[0..16];
        let encrypted_data = &ciphertext[16..ciphertext.len() - 32];
        let mac_tag = &ciphertext[ciphertext.len() - 32..];

        // Derive encryption key and MAC key (same as encrypt)
        let mut encryption_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        // Derive encryption key
        let mut enc_key_hasher = Shake256::default();
        enc_key_hasher.update(b"LIBQ-SHAKE256-AEAD-ENC");
        enc_key_hasher.update(key_bytes);
        enc_key_hasher.update(nonce_bytes);
        let mut enc_key_reader = enc_key_hasher.finalize_xof();
        enc_key_reader.read(&mut encryption_key);

        // Derive MAC key
        let mut mac_key_hasher = Shake256::default();
        mac_key_hasher.update(b"LIBQ-SHAKE256-AEAD-MAC");
        mac_key_hasher.update(key_bytes);
        mac_key_hasher.update(nonce_bytes);
        let mut mac_key_reader = mac_key_hasher.finalize_xof();
        mac_key_reader.read(&mut mac_key);

        // Compute MAC over nonce || aad || encrypted_data
        let mut mac_hasher = Shake256::default();
        mac_hasher.update(b"LIBQ-SHAKE256-AEAD-MAC");
        mac_hasher.update(&mac_key);
        mac_hasher.update(nonce_bytes);
        mac_hasher.update(aad);
        mac_hasher.update(encrypted_data);
        let mut mac_reader = mac_hasher.finalize_xof();

        let mut computed_mac = [0u8; 32];
        mac_reader.read(&mut computed_mac);

        // Verify MAC using constant-time comparison
        if !crate::security::constant_time::constant_time_eq(&computed_mac, mac_tag) {
            return Err(Error::VerificationFailed {
                operation: "SHAKE256 AEAD authentication failed".to_string(),
            });
        }

        // Decrypt using SHAKE256 as stream cipher
        let mut plaintext = vec![0u8; encrypted_data.len()];
        let mut stream_hasher = Shake256::default();
        stream_hasher.update(b"LIBQ-SHAKE256-AEAD-STREAM");
        stream_hasher.update(&encryption_key);
        stream_hasher.update(iv);
        let mut stream_reader = stream_hasher.finalize_xof();

        let mut keystream = [0u8; 32];
        for (i, chunk) in encrypted_data.chunks(32).enumerate() {
            stream_reader.read(&mut keystream);
            for (j, &byte) in chunk.iter().enumerate() {
                plaintext[i * 32 + j] = byte ^ keystream[j];
            }
        }

        Ok(plaintext)
    }

    #[cfg(not(feature = "shake256"))]
    fn decrypt(
        &self,
        _key: &AeadKey,
        _nonce: &Nonce,
        _ciphertext: &[u8],
        _associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(Error::NotImplemented {
            feature: "SHAKE256 feature not enabled".to_string(),
        })
    }
}

/// Check if SHAKE256 AEAD is available
///
/// This function returns `true` if the `shake256` feature is enabled,
/// allowing callers to check availability before attempting to use
/// SHAKE256 AEAD functionality.
#[allow(dead_code)] // Public API function - may be used by external crates
pub fn is_shake256_available() -> bool {
    #[cfg(feature = "shake256")]
    {
        true
    }
    #[cfg(not(feature = "shake256"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256_creation() {
        let _aead = Shake256Aead::new();
        // Always succeeds since it's just a struct
        assert!(true);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_constant_time_eq() {
        use crate::security::constant_time::constant_time_eq;

        let a = [1u8, 2u8, 3u8];
        let b = [1u8, 2u8, 3u8];
        let c = [1u8, 2u8, 4u8];
        let d = [1u8, 2u8];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
        assert!(!constant_time_eq(&d, &a));
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_fill_random_bytes() {
        let mut buf = [0u8; 16];
        let result = Shake256Aead::fill_random_bytes(&mut buf);
        assert!(result.is_ok());

        // Very unlikely that all bytes are zero
        assert!(buf.iter().any(|&b| b != 0));
    }
}
