//! Saturnin AEAD implementation
//!
//! Saturnin is a lightweight post-quantum symmetric algorithm suite designed
//! for IoT and constrained devices, providing authenticated encryption and
//! hashing modes with superior post-quantum security.
//!
//! ## Usage Example
//!
//! ```rust
//! use lib_q_saturnin::{
//!     Aead,
//!     AeadKey,
//!     Nonce,
//!     SaturninAead,
//! };
//!
//! // Create AEAD instance
//! let aead = SaturninAead::new();
//!
//! // Generate key and nonce (in practice, use secure random generation)
//! let key = AeadKey::new(vec![0u8; 32]);
//! let nonce = Nonce::new(vec![0u8; 16]);
//!
//! let plaintext = b"Secret message";
//! let associated_data = b"metadata";
//!
//! // Encrypt with associated data
//! let ciphertext = aead
//!     .encrypt(&key, &nonce, plaintext, Some(associated_data))
//!     .unwrap();
//!
//! // Decrypt and verify authenticity
//! let decrypted = aead
//!     .decrypt(&key, &nonce, &ciphertext, Some(associated_data))
//!     .unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! ## Performance Notes
//!
//! - **Key size**: 256 bits (32 bytes)
//! - **Nonce size**: 128 bits (16 bytes)  
//! - **Tag size**: 256 bits (32 bytes)
//! - **Throughput**: ~100-500 MB/s on modern hardware
//! - **Memory usage**: Small fixed state (pre-built cipher cores for domains 1–5); per-message
//!   key/nonce are staged in zeroizing buffers at the `Aead` boundary, and the cascade running tag
//!   plus per-iteration cascade blocks (`t`, `m`, and SIMD xor staging) are held in `Zeroizing`
//!   buffers so they are cleared on drop.
//!
//! ## Verification timing
//!
//! Decrypt computes the expected tag over AAD and ciphertext (cascade), compares it to the
//! appended tag with [`lib_q_core::Utils::constant_time_compare`](lib_q_core::Utils::constant_time_compare),
//! then **always** runs full CTR on the ciphertext body. Only after that does the API return
//! `Ok(plaintext)` versus `Err(Error::VerificationFailed)` (Layer A) for a failed tag after that
//! schedule, or `Ok(DecryptSemanticOutcome::AuthenticationFailed)` (Layer B). Ciphertext shorter
//! than the tag is rejected up front as `Err(Error::InvalidCiphertextSize)` (operational). Failed
//! plaintext buffers are zeroized. This matches the [`lib_q_core::Aead`] contract in
//! `lib-q-core`: bulk symmetric work is not skipped on auth failure; the public `Result` / outcome
//! still discriminates at the boundary. For semantic decrypt without plaintext on authentication
//! failure, see [`lib_q_core::AeadDecryptSemantic`]. See this crate’s
//! `SECURITY.md` for Saturnin-Short specifics.

#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
    Result,
};
use zeroize::{
    Zeroize,
    Zeroizing,
};

use crate::core::SaturninCore;
#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
use crate::simd::{
    encrypt_blocks8_dispatch,
    simd_xor,
};

/// Pre-built Saturnin cores for CTR-Cascade AEAD (10 super-rounds, domains 1–5).
///
/// Building these once per [`SaturninAead`] avoids repeated `Vec` allocation of round constants
/// on every encrypt/decrypt (domains 1–5 cover CTR and all cascade steps).
struct SaturninAeadCores {
    d1: SaturninCore,
    d2: SaturninCore,
    d3: SaturninCore,
    d4: SaturninCore,
    d5: SaturninCore,
}

impl SaturninAeadCores {
    fn new() -> Result<Self> {
        Ok(Self {
            d1: SaturninCore::new(10, 1)?,
            d2: SaturninCore::new(10, 2)?,
            d3: SaturninCore::new(10, 3)?,
            d4: SaturninCore::new(10, 4)?,
            d5: SaturninCore::new(10, 5)?,
        })
    }

    #[inline]
    fn domain(&self, d: u8) -> &SaturninCore {
        match d {
            1 => &self.d1,
            2 => &self.d2,
            3 => &self.d3,
            4 => &self.d4,
            5 => &self.d5,
            _ => unreachable!("AEAD CTR/cascade only uses domains 1–5"),
        }
    }
}

/// Saturnin AEAD implementation
///
/// Provides authenticated encryption using the Saturnin CTR-Cascade mode.
/// This is the full AEAD mode that supports associated data and arbitrary
/// length plaintexts.
pub struct SaturninAead {
    cores: SaturninAeadCores,
}

impl SaturninAead {
    /// Create a new Saturnin AEAD instance
    pub fn new() -> Self {
        Self {
            cores: SaturninAeadCores::new().expect("Saturnin AEAD uses fixed valid domains"),
        }
    }

    /// Get the key size in bytes (256 bits = 32 bytes)
    pub const fn key_size() -> usize {
        32
    }

    /// Get the nonce size in bytes (128 bits = 16 bytes)
    pub const fn nonce_size() -> usize {
        16
    }

    /// Get the tag size in bytes (256 bits = 32 bytes)
    pub const fn tag_size() -> usize {
        32
    }

    /// Initialize the cascade state
    fn cascade_init(&self, key: &[u8], nonce: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let key32: &[u8; 32] = key.try_into().map_err(|_| Error::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        })?;

        let mut r = Zeroizing::new([0u8; 32]);

        // Copy nonce to first 16 bytes
        r[0..16].copy_from_slice(nonce);
        r[16] = 0x80;
        // Remaining bytes are already zero

        // Encrypt with cascade parameters: 10 super-rounds, domain 2 (AAD1)
        self.cores.d2.encrypt_block_32(key32, &mut r)?;

        // XOR with nonce
        for i in 0..16 {
            r[i] ^= nonce[i];
        }
        r[16] ^= 0x80;

        Ok(r)
    }

    /// Apply cascade construction to data (optimized)
    fn cascade(&self, r: &mut [u8; 32], d1: u8, d2: u8, data: &[u8]) -> Result<()> {
        let core_d1 = self.cores.domain(d1);
        let core_d2 = self.cores.domain(d2);

        let mut offset = 0;

        loop {
            let mut t: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
            let mut m: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
            let remaining = data.len() - offset;

            if remaining >= 32 {
                t.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;

                // Use pre-allocated core for d1
                m.copy_from_slice(&*t);
                core_d1.encrypt_block_32(&*r, &mut m)?;
            } else {
                t[0..remaining].copy_from_slice(&data[offset..]);
                t[remaining] = 0x80;
                // Remaining bytes are already zero

                // Use pre-allocated core for d2
                m.copy_from_slice(&*t);
                core_d2.encrypt_block_32(&*r, &mut m)?;
            }

            #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
            {
                let mut out: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
                simd_xor::xor_blocks_32(&m, &t, &mut out);
                r.copy_from_slice(&*out);
            }

            #[cfg(not(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon")))]
            {
                for i in 0..32 {
                    r[i] = m[i] ^ t[i];
                }
            }

            if remaining < 32 {
                break;
            }
        }

        Ok(())
    }

    /// CTR encryption/decryption (optimized)
    fn ctr_encrypt(&self, key: &[u8], nonce: &[u8], data: &mut [u8]) -> Result<()> {
        let key32: &[u8; 32] = key.try_into().map_err(|_| Error::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        })?;

        let core = &self.cores.d1;

        let mut counter = 1u32; // Counter starts at 1
        let mut offset = 0;

        while offset < data.len() {
            #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
            if data.len() - offset >= 32 * 8 {
                let mut keystream_blocks = [[0u8; 32]; 8];
                for (lane, block) in keystream_blocks.iter_mut().enumerate() {
                    let c = counter.wrapping_add(lane as u32);
                    block[0..16].copy_from_slice(nonce);
                    block[16] = 0x80;
                    block[28] = (c >> 24) as u8;
                    block[29] = (c >> 16) as u8;
                    block[30] = (c >> 8) as u8;
                    block[31] = c as u8;
                }

                encrypt_blocks8_dispatch(10, 1, key, &mut keystream_blocks, Some(core))?;

                for (lane, ks) in keystream_blocks.iter().enumerate() {
                    let start = offset + (lane * 32);
                    let mut input = [0u8; 32];
                    input.copy_from_slice(&data[start..start + 32]);
                    let mut out = [0u8; 32];
                    simd_xor::xor_blocks_32(&input, ks, &mut out);
                    data[start..start + 32].copy_from_slice(&out);
                }

                offset += 32 * 8;
                let (next_counter, overflowed) = counter.overflowing_add(8);
                if overflowed {
                    return Err(Error::InvalidMessageSize {
                        max: usize::MAX,
                        actual: data.len(),
                    });
                }
                counter = next_counter;
                continue;
            }

            let mut keystream = [0u8; 32];

            // Build counter block efficiently
            keystream[0..16].copy_from_slice(nonce);
            keystream[16] = 0x80;
            // Bytes 17-27 are zero
            keystream[28] = (counter >> 24) as u8;
            keystream[29] = (counter >> 16) as u8;
            keystream[30] = (counter >> 8) as u8;
            keystream[31] = counter as u8;

            // Encrypt to get keystream
            core.encrypt_block_32(key32, &mut keystream)?;

            let remaining = data.len() - offset;
            let block_len = remaining.min(32);
            #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
            {
                if block_len == 32 {
                    let mut input = [0u8; 32];
                    input.copy_from_slice(&data[offset..offset + 32]);
                    let mut out = [0u8; 32];
                    simd_xor::xor_blocks_32(&input, &keystream, &mut out);
                    data[offset..offset + 32].copy_from_slice(&out);
                } else {
                    for i in 0..block_len {
                        data[offset + i] ^= keystream[i];
                    }
                }
            }

            #[cfg(not(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon")))]
            {
                for i in 0..block_len {
                    data[offset + i] ^= keystream[i];
                }
            }

            offset += block_len;
            counter = counter.wrapping_add(1);
        }

        Ok(())
    }

    /// Shared decrypt core for Layer A ([`Aead::decrypt`](lib_q_core::Aead::decrypt)) and Layer B
    /// ([`AeadDecryptSemantic::decrypt_semantic`](lib_q_core::AeadDecryptSemantic::decrypt_semantic)).
    fn decrypt_core(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        if key.as_bytes().len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.as_bytes().len(),
            });
        }

        if nonce.as_bytes().len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.as_bytes().len(),
            });
        }

        if (ciphertext.len() >> 5) >= 0xFFFFFFFE {
            return Err(Error::InvalidMessageSize {
                max: 0xFFFFFFFE << 5,
                actual: ciphertext.len(),
            });
        }

        if ciphertext.len() < Self::tag_size() {
            return Err(Error::aead_ciphertext_shorter_than_tag(
                Self::tag_size(),
                ciphertext.len(),
            ));
        }

        let ad = associated_data.unwrap_or(&[]);
        let plaintext_len = ciphertext.len() - 32;
        let ciphertext_data = &ciphertext[0..plaintext_len];
        let received_tag = &ciphertext[plaintext_len..];

        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key.as_bytes());
        let mut nonce_staged = Zeroizing::new([0u8; 16]);
        nonce_staged.copy_from_slice(nonce.as_bytes());
        let kb = key_staged.as_slice();
        let nb = nonce_staged.as_slice();

        let mut tag = self.cascade_init(kb, nb)?;
        self.cascade(&mut tag, 2, 3, ad)?;
        self.cascade(&mut tag, 4, 5, ciphertext_data)?;

        let tag_valid = lib_q_core::Utils::constant_time_compare(&*tag, received_tag);

        let mut plaintext = ciphertext_data.to_vec();
        if let Err(e) = self.ctr_encrypt(kb, nb, &mut plaintext) {
            plaintext.zeroize();
            return Err(e);
        }

        if tag_valid {
            Ok(DecryptSemanticOutcome::Success(Zeroizing::new(plaintext)))
        } else {
            plaintext.zeroize();
            Ok(DecryptSemanticOutcome::AuthenticationFailed)
        }
    }
}

impl Aead for SaturninAead {
    /// Encrypt data with authentication
    ///
    /// # Arguments
    /// * `key` - 256-bit encryption key
    /// * `nonce` - 128-bit nonce
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// Encrypted data with authentication tag appended
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.as_bytes().len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.as_bytes().len(),
            });
        }

        if nonce.as_bytes().len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.as_bytes().len(),
            });
        }

        // Check length limits (about 137.4 GB)
        if (plaintext.len() >> 5) >= 0xFFFFFFFD {
            return Err(Error::InvalidMessageSize {
                max: 0xFFFFFFFD << 5,
                actual: plaintext.len(),
            });
        }

        let ad = associated_data.unwrap_or(&[]);

        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key.as_bytes());
        let mut nonce_staged = Zeroizing::new([0u8; 16]);
        nonce_staged.copy_from_slice(nonce.as_bytes());
        let kb = key_staged.as_slice();
        let nb = nonce_staged.as_slice();

        // Initialize cascade state
        let mut tag = self.cascade_init(kb, nb)?;

        // Process associated data
        self.cascade(&mut tag, 2, 3, ad)?;

        // Encrypt plaintext with CTR
        let mut ciphertext = plaintext.to_vec();
        if let Err(e) = self.ctr_encrypt(kb, nb, &mut ciphertext) {
            ciphertext.zeroize();
            return Err(e);
        }

        // Continue cascade on ciphertext
        self.cascade(&mut tag, 4, 5, &ciphertext)?;

        // Append tag
        ciphertext.extend_from_slice(&*tag);

        Ok(ciphertext)
    }

    /// Decrypt and verify data (Layer A); shares one decrypt core with [`lib_q_core::AeadDecryptSemantic`].
    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.decrypt_core(key, nonce, ciphertext, associated_data) {
            Ok(DecryptSemanticOutcome::Success(p)) => Ok(Vec::clone(&*p)),
            Ok(DecryptSemanticOutcome::AuthenticationFailed) => Err(Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            }),
            Err(e) => Err(e),
        }
    }
}

impl AeadDecryptSemantic for SaturninAead {
    /// Layer B semantic decrypt; see `docs/adr/003-aead-decrypt-layers.md`.
    fn decrypt_semantic(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        self.decrypt_core(key, nonce, ciphertext, associated_data)
    }
}

impl Default for SaturninAead {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;

    use super::*;

    #[test]
    fn test_saturnin_creation() {
        let _aead = SaturninAead::new();
        // Saturnin implementation created successfully
        // Test passes if we reach this point without panicking
    }

    #[test]
    fn test_saturnin_constants() {
        assert_eq!(SaturninAead::key_size(), 32);
        assert_eq!(SaturninAead::nonce_size(), 16);
        assert_eq!(SaturninAead::tag_size(), 32);
    }

    #[test]
    fn test_saturnin_encrypt_decrypt_round_trip() -> Result<()> {
        let aead = SaturninAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let plaintext = b"test"; // 4 bytes
        let ad: Option<&[u8]> = None;

        // Test encryption
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, ad)?;
        assert_eq!(ciphertext.len(), plaintext.len() + 32); // plaintext + 32-byte tag

        // Test decryption
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, ad)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_saturnin_decrypt_semantic_bad_tag() -> Result<()> {
        use lib_q_core::AeadDecryptSemantic;

        let aead = SaturninAead::new();
        let key = AeadKey::new(vec![7u8; 32]);
        let nonce = Nonce::new(vec![8u8; 16]);
        let ad: Option<&[u8]> = Some(b"ad");
        let ct = aead.encrypt(&key, &nonce, b"m", ad)?;
        let mut bad = ct.clone();
        *bad.last_mut().expect("tag") ^= 0x40;
        let out = aead.decrypt_semantic(&key, &nonce, &bad, ad)?;
        assert_eq!(out, DecryptSemanticOutcome::AuthenticationFailed);
        assert!(matches!(
            aead.decrypt(&key, &nonce, &bad, ad),
            Err(Error::VerificationFailed { .. })
        ));
        match aead.decrypt_semantic(&key, &nonce, &ct, ad)? {
            DecryptSemanticOutcome::Success(pt) => assert_eq!(pt.as_slice(), b"m"),
            DecryptSemanticOutcome::AuthenticationFailed => {
                panic!("unexpected auth failure on good ciphertext")
            }
        }
        Ok(())
    }
}
