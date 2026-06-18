//! Rocca-S AEAD: `lib_q_core::Aead` + `AeadDecryptSemantic` implementation.
//!
//! ## Parameters
//! - **Key**: 256 bits (32 bytes)
//! - **Nonce**: 128 bits (16 bytes)
//! - **Tag**: 256 bits (32 bytes) — restores ~128-bit forgery resistance under a
//!   Grover-style quantum search (a 128-bit tag would give only ~64-bit).
//!
//! ## Verification timing
//!
//! Decrypt always runs the full bulk decryption over the ciphertext body and
//! recomputes the tag, then compares it to the received tag with
//! [`lib_q_core::Utils::constant_time_compare`] before discriminating success
//! from failure. Bulk symmetric work is not skipped on authentication failure,
//! matching the [`lib_q_core::Aead`] contract used by the other lib-Q AEADs. On
//! failure the recovered plaintext buffer is zeroized. Ciphertext shorter than the
//! tag is rejected up front. See [`lib_q_core::AeadDecryptSemantic`] for the
//! semantic (no-error) failure outcome.

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
use zeroize::Zeroizing;

use crate::simd;

/// Zeroizing staging buffers for a validated key and nonce.
type StagedKeyNonce = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 16]>);

/// Rocca-S AEAD instance.
///
/// Stateless; construction is free. The hot path selects a hardware AES backend
/// (AES-NI / ARMv8 crypto) at runtime when the `simd` features are enabled and the
/// CPU supports it, otherwise it uses the portable scalar AES round.
#[derive(Clone, Copy, Default)]
pub struct RoccaSAead;

impl RoccaSAead {
    /// Create a new Rocca-S AEAD instance.
    pub const fn new() -> Self {
        Self
    }

    /// Key size in bytes (256 bits).
    pub const fn key_size() -> usize {
        32
    }

    /// Nonce size in bytes (128 bits).
    pub const fn nonce_size() -> usize {
        16
    }

    /// Tag size in bytes (256 bits).
    pub const fn tag_size() -> usize {
        32
    }

    fn stage_key_nonce(key: &AeadKey, nonce: &Nonce) -> Result<StagedKeyNonce> {
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
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(key.as_bytes());
        let mut n = Zeroizing::new([0u8; 16]);
        n.copy_from_slice(nonce.as_bytes());
        Ok((k, n))
    }

    /// Shared decrypt core for Layer A ([`Aead::decrypt`]) and Layer B
    /// ([`AeadDecryptSemantic::decrypt_semantic`]).
    fn decrypt_core(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        let (k, n) = Self::stage_key_nonce(key, nonce)?;

        if ciphertext.len() < Self::tag_size() {
            return Err(Error::aead_ciphertext_shorter_than_tag(
                Self::tag_size(),
                ciphertext.len(),
            ));
        }

        let ad = associated_data.unwrap_or(&[]);
        let body_len = ciphertext.len() - Self::tag_size();
        let body = &ciphertext[..body_len];
        let received_tag = &ciphertext[body_len..];

        let mut plaintext = Zeroizing::new(alloc::vec![0u8; body_len]);
        let expected_tag = simd::decrypt(&k, &n, ad, body, &mut plaintext);

        let tag_valid = lib_q_core::Utils::constant_time_compare(&expected_tag, received_tag);

        if tag_valid {
            Ok(DecryptSemanticOutcome::Success(Zeroizing::new(
                plaintext.to_vec(),
            )))
        } else {
            Ok(DecryptSemanticOutcome::AuthenticationFailed)
        }
    }
}

impl Aead for RoccaSAead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let (k, n) = Self::stage_key_nonce(key, nonce)?;
        let ad = associated_data.unwrap_or(&[]);

        let mut out = alloc::vec![0u8; plaintext.len() + Self::tag_size()];
        let (body, tag_slot) = out.split_at_mut(plaintext.len());
        let tag = simd::encrypt(&k, &n, ad, plaintext, body);
        tag_slot.copy_from_slice(&tag);
        Ok(out)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.decrypt_core(key, nonce, ciphertext, associated_data) {
            Ok(DecryptSemanticOutcome::Success(p)) => Ok(p.to_vec()),
            Ok(DecryptSemanticOutcome::AuthenticationFailed) => Err(Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            }),
            Err(e) => Err(e),
        }
    }
}

impl AeadDecryptSemantic for RoccaSAead {
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn constants() {
        assert_eq!(RoccaSAead::key_size(), 32);
        assert_eq!(RoccaSAead::nonce_size(), 16);
        assert_eq!(RoccaSAead::tag_size(), 32);
    }

    #[test]
    fn round_trip() -> Result<()> {
        let aead = RoccaSAead::new();
        let key = AeadKey::new(vec![0x11; 32]);
        let nonce = Nonce::new(vec![0x22; 16]);
        let pt = b"the quick brown fox jumps over the lazy dog";
        let ad: Option<&[u8]> = Some(b"header");
        let ct = aead.encrypt(&key, &nonce, pt, ad)?;
        assert_eq!(ct.len(), pt.len() + 32);
        let back = aead.decrypt(&key, &nonce, &ct, ad)?;
        assert_eq!(back, pt);
        Ok(())
    }

    #[test]
    fn tamper_fails() -> Result<()> {
        let aead = RoccaSAead::new();
        let key = AeadKey::new(vec![7u8; 32]);
        let nonce = Nonce::new(vec![8u8; 16]);
        let ad: Option<&[u8]> = Some(b"ad");
        let ct = aead.encrypt(&key, &nonce, b"message", ad)?;
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 0x40;
        assert!(matches!(
            aead.decrypt(&key, &nonce, &bad, ad),
            Err(Error::VerificationFailed { .. })
        ));
        assert_eq!(
            aead.decrypt_semantic(&key, &nonce, &bad, ad)?,
            DecryptSemanticOutcome::AuthenticationFailed
        );
        Ok(())
    }
}
