//! Saturnin-Short AEAD implementation
//!
//! Saturnin-Short is the encode-then-encrypt mode from the Saturnin specification
//! (Section 2.3): a single `Saturnin^6` block cipher call over `pad(nonce || plaintext)`.
//! Confidentiality and integrity are provided together in one 32-byte ciphertext; there is
//! no separate tag and no associated data.
//!
//! ## Limits
//!
//! - **Plaintext**: strictly less than 128 bits (at most 15 bytes)
//! - **Nonce**: 128 bits (16 bytes)
//! - **Associated data**: not supported
//! - **Ciphertext**: always 32 bytes
//!
//! ## Side-channel and API contract
//!
//! Decrypt performs exactly one inverse block (`decrypt_block_32`) before any verification
//! outcome can influence returned plaintext. Nonce binding and padding checks walk fixed
//! layouts; the candidate plaintext is assembled in a fixed number of steps using masks
//! derived from an accumulated authentication byte (no early exit that skips that
//! assembly). As with the full Saturnin AEAD path in `aead.rs` (constant-time tag check over
//! the binding, then full CTR on the ciphertext, then map the outcome), the closing step maps
//! the verification result to `Ok` versus
//! `Err(Error::VerificationFailed)`; [`AeadDecryptSemantic`](lib_q_core::AeadDecryptSemantic)
//! exposes `Ok(AuthenticationFailed)` instead for Layer B. A public `Result` API cannot
//! expose both outcomes without that discriminant. Treat verification timing under the same
//! remote-adversary assumptions as full AEAD unless a higher layer enforces additional timing
//! mediation.
//!
//! ## Usage Example
//!
//! ```rust
//! use lib_q_saturnin::{
//!     Aead,
//!     AeadKey,
//!     Nonce,
//!     SaturninShortAead,
//! };
//!
//! let aead = SaturninShortAead::new();
//! let key = AeadKey::new(vec![0u8; 32]);
//! let nonce = Nonce::new(vec![0u8; 16]);
//! let plaintext = b"Quick";
//!
//! let ciphertext = aead.encrypt(&key, &nonce, plaintext, None).unwrap();
//! assert_eq!(ciphertext.len(), 32);
//!
//! let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

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

/// Maximum plaintext length in bytes (`< 128` bits per the Saturnin specification).
const MAX_PLAINTEXT_LEN: usize = 15;

/// Fixed ciphertext length: one 256-bit Saturnin block.
const CIPHERTEXT_LEN: usize = 32;

/// `0xff` if `x == 0`, else `0` (constant-time classification for an OR-reduced `u8` status).
#[inline]
fn ct_u8_is_zero(x: u8) -> u8 {
    (x.wrapping_sub(1) & !x) >> 7
}

/// `0xff` if `i < len`, else `0` (constant-time; `len` may be secret-derived).
#[inline]
fn ct_usize_lt(i: usize, len: usize) -> u8 {
    let x = i.wrapping_sub(len);
    ((x >> (usize::BITS - 1)) as u8).wrapping_neg()
}

/// Mask applied to candidate plaintext bytes when authentication succeeds (`auth_or == 0`).
const SHORT_AUTH_OK_MASK: u8 = 0xFF;

#[inline]
fn short_auth_ok_mask(auth_or: u8) -> u8 {
    ct_u8_is_zero(auth_or).wrapping_neg()
}

/// Nonce check and padding parse (reference `decrypt.c`); `auth_or == 0` iff valid under `nonce`.
fn short_parse_auth_and_padding(decrypted: &[u8; 32], nonce: &[u8; 16]) -> (u8, usize) {
    let mut auth_or = 0u8;

    for (stored, expected) in decrypted[..16].iter().zip(nonce.iter()) {
        auth_or |= stored ^ expected;
    }

    let mut notfound = 0xFFu8;
    let mut plaintext_len = 0usize;

    for i in (0..16).rev() {
        let byte = decrypted[16 + i];
        let hit = u16::from(byte ^ 0x80) + 0xFF;
        let is_pad_byte = 1u8.wrapping_sub((hit >> 8) as u8);
        let found = notfound & is_pad_byte.wrapping_neg();

        plaintext_len |= (found as usize) & i;
        notfound &= !found;
        let nonzero = u16::from(byte) + 0xFF;
        auth_or |= notfound & ((nonzero >> 8) as u8);
    }
    auth_or |= notfound;

    (auth_or, plaintext_len)
}

/// Fixed-length candidate plaintext (`<= MAX_PLAINTEXT_LEN` pushes); selection uses `auth_ok_mask` only.
fn short_materialize_plaintext_candidate(
    auth_ok_mask: u8,
    plaintext_len: usize,
    tail: &[u8; 16],
) -> Vec<u8> {
    let len_for_mask = plaintext_len.min(MAX_PLAINTEXT_LEN);
    let mut out = Vec::with_capacity(MAX_PLAINTEXT_LEN);
    for (i, &byte) in tail[..MAX_PLAINTEXT_LEN].iter().enumerate() {
        let take = auth_ok_mask & ct_usize_lt(i, len_for_mask);
        out.push(byte & take);
    }
    out
}

/// Saturnin-Short AEAD (`Saturnin^6`, 10 super-rounds).
pub struct SaturninShortAead {
    core: SaturninCore,
}

impl SaturninShortAead {
    /// Create a new Saturnin-Short AEAD instance.
    pub fn new() -> Self {
        let core = SaturninCore::new(10, 6).expect("Saturnin-Short uses domain 6");
        Self { core }
    }

    /// Key size in bytes.
    pub const fn key_size() -> usize {
        32
    }

    /// Nonce size in bytes.
    pub const fn nonce_size() -> usize {
        16
    }

    /// Authenticated ciphertext size in bytes (fixed 32-byte block).
    pub const fn tag_size() -> usize {
        CIPHERTEXT_LEN
    }

    /// Maximum supported plaintext length in bytes.
    pub const fn max_plaintext_len() -> usize {
        MAX_PLAINTEXT_LEN
    }

    fn validate_key(key: &[u8]) -> Result<[u8; 32]> {
        key.try_into().map_err(|_| Error::InvalidKeySize {
            expected: Self::key_size(),
            actual: key.len(),
        })
    }

    fn validate_nonce(nonce: &[u8]) -> Result<[u8; 16]> {
        nonce.try_into().map_err(|_| Error::InvalidNonceSize {
            expected: Self::nonce_size(),
            actual: nonce.len(),
        })
    }

    fn reject_associated_data(ad: Option<&[u8]>) -> Result<()> {
        if ad.is_some_and(|data| !data.is_empty()) {
            return Err(Error::InvalidAssociatedDataSize {
                max: 0,
                actual: ad.map_or(0, |data| data.len()),
            });
        }
        Ok(())
    }

    fn reject_plaintext_len(plaintext_len: usize) -> Result<()> {
        if plaintext_len > MAX_PLAINTEXT_LEN {
            return Err(Error::InvalidMessageSize {
                max: MAX_PLAINTEXT_LEN,
                actual: plaintext_len,
            });
        }
        Ok(())
    }

    /// Build `pad(nonce || plaintext)` into a 32-byte block (reference `encrypt.c`).
    fn encode_block(nonce: &[u8; 16], plaintext: &[u8]) -> [u8; 32] {
        let mut block = [0u8; 32];
        block[..16].copy_from_slice(nonce);
        let pt_len = plaintext.len();
        if pt_len > 0 {
            block[16..16 + pt_len].copy_from_slice(plaintext);
        }
        block[16 + pt_len] = 0x80;
        block
    }

    /// Semantic verify outcome for Saturnin-Short (no plaintext bytes on failure).
    fn short_decrypt_semantic_inner(
        decrypted: &[u8; 32],
        nonce: &[u8; 16],
    ) -> DecryptSemanticOutcome {
        let (auth_or, plaintext_len) = short_parse_auth_and_padding(decrypted, nonce);
        let auth_ok_mask = short_auth_ok_mask(auth_or);

        let mut tail = [0u8; 16];
        tail.copy_from_slice(&decrypted[16..32]);

        let mut candidate =
            short_materialize_plaintext_candidate(auth_ok_mask, plaintext_len, &tail);
        if auth_ok_mask != SHORT_AUTH_OK_MASK {
            candidate.zeroize();
            return DecryptSemanticOutcome::AuthenticationFailed;
        }
        candidate.truncate(plaintext_len.min(MAX_PLAINTEXT_LEN));
        DecryptSemanticOutcome::Success(Zeroizing::new(candidate))
    }

    fn decrypt_semantic_core(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        Self::reject_associated_data(ad)?;

        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(Error::InvalidCiphertextSize {
                expected: CIPHERTEXT_LEN,
                actual: ciphertext.len(),
            });
        }

        let key32 = Self::validate_key(key.as_bytes())?;
        let nonce16 = Self::validate_nonce(nonce.as_bytes())?;

        let mut block: [u8; 32] =
            ciphertext
                .try_into()
                .map_err(|_| Error::InvalidCiphertextSize {
                    expected: CIPHERTEXT_LEN,
                    actual: ciphertext.len(),
                })?;

        if let Err(e) = self.core.decrypt_block_32(&key32, &mut block) {
            block.zeroize();
            return Err(e);
        }

        let outcome = Self::short_decrypt_semantic_inner(&block, &nonce16);
        block.zeroize();
        Ok(outcome)
    }

    /// Encrypt plaintext with associated data.
    pub fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Self::reject_associated_data(ad)?;
        Self::reject_plaintext_len(plaintext.len())?;

        let key32 = Self::validate_key(key.as_bytes())?;
        let nonce16 = Self::validate_nonce(nonce.as_bytes())?;

        let mut block = Self::encode_block(&nonce16, plaintext);
        self.core.encrypt_block_32(&key32, &mut block)?;

        Ok(block.to_vec())
    }

    /// Decrypt ciphertext with associated data.
    pub fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.decrypt_semantic_core(key, nonce, ciphertext, ad)? {
            DecryptSemanticOutcome::Success(p) => Ok(Vec::clone(&*p)),
            DecryptSemanticOutcome::AuthenticationFailed => Err(Error::VerificationFailed {
                operation: "Saturnin-Short authentication".into(),
            }),
        }
    }
}

impl Aead for SaturninShortAead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.encrypt(key, nonce, plaintext, associated_data)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt(key, nonce, ciphertext, associated_data)
    }
}

impl AeadDecryptSemantic for SaturninShortAead {
    fn decrypt_semantic(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        self.decrypt_semantic_core(key, nonce, ciphertext, associated_data)
    }
}

impl Default for SaturninShortAead {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{
        Error,
        Result,
    };

    #[test]
    fn test_ct_u8_is_zero() {
        assert_eq!(ct_u8_is_zero(0), 1);
        assert_eq!(ct_u8_is_zero(1), 0);
        assert_eq!(ct_u8_is_zero(0xFF), 0);
    }

    #[test]
    fn test_ct_usize_lt() {
        assert_eq!(ct_usize_lt(0, 1), 0xFF);
        assert_eq!(ct_usize_lt(0, 0), 0);
        assert_eq!(ct_usize_lt(5, 5), 0);
        assert_eq!(ct_usize_lt(4, 5), 0xFF);
        assert_eq!(ct_usize_lt(14, 15), 0xFF);
    }

    #[test]
    fn test_saturnin_short_creation() {
        let _aead = SaturninShortAead::new();
        assert_eq!(SaturninShortAead::key_size(), 32);
        assert_eq!(SaturninShortAead::nonce_size(), 16);
        assert_eq!(SaturninShortAead::tag_size(), 32);
        assert_eq!(SaturninShortAead::max_plaintext_len(), 15);
    }

    #[test]
    fn test_saturnin_short_encrypt_decrypt_round_trip() -> Result<()> {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let plaintext = b"test";

        let ciphertext = aead.encrypt(&key, &nonce, plaintext, None)?;
        assert_eq!(ciphertext.len(), 32);

        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_saturnin_short_empty_plaintext() -> Result<()> {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![1u8; 32]);
        let nonce = Nonce::new(vec![2u8; 16]);

        let ciphertext = aead.encrypt(&key, &nonce, b"", None)?;
        assert_eq!(ciphertext.len(), 32);
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None)?;
        assert_eq!(decrypted, b"");

        Ok(())
    }

    #[test]
    fn test_saturnin_short_wrong_ciphertext_length_is_invalid_ciphertext_size() {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);

        let short = vec![0u8; 31];
        let err = aead
            .decrypt(&key, &nonce, &short, None)
            .expect_err("31-byte input must be rejected");
        assert!(matches!(
            err,
            Error::InvalidCiphertextSize {
                expected: 32,
                actual: 31
            }
        ));

        let long = vec![0u8; 33];
        let err = aead
            .decrypt(&key, &nonce, &long, None)
            .expect_err("33-byte input must be rejected");
        assert!(matches!(
            err,
            Error::InvalidCiphertextSize {
                expected: 32,
                actual: 33
            }
        ));
    }

    #[test]
    fn test_saturnin_short_integrity_failure_is_verification_failed() -> Result<()> {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![5u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let ct = aead.encrypt(&key, &nonce, b"hi", None)?;

        let mut tampered = ct;
        tampered[20] ^= 1;

        let err = aead
            .decrypt(&key, &nonce, &tampered, None)
            .expect_err("tampered ciphertext must fail authentication");
        assert!(matches!(
            &err,
            Error::VerificationFailed { operation }
                if operation == "Saturnin-Short authentication"
        ));
        Ok(())
    }

    #[test]
    fn test_saturnin_short_decrypt_semantic_auth_failure() -> Result<()> {
        use lib_q_core::AeadDecryptSemantic;

        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![5u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let ct = aead.encrypt(&key, &nonce, b"hi", None)?;

        let mut tampered = ct.clone();
        tampered[20] ^= 1;

        let out = aead.decrypt_semantic(&key, &nonce, &tampered, None)?;
        assert_eq!(out, DecryptSemanticOutcome::AuthenticationFailed);

        match aead.decrypt_semantic(&key, &nonce, &ct, None)? {
            DecryptSemanticOutcome::Success(pt) => assert_eq!(pt.as_slice(), b"hi"),
            DecryptSemanticOutcome::AuthenticationFailed => {
                panic!("unexpected auth failure on good ciphertext");
            }
        }
        Ok(())
    }

    #[test]
    fn test_saturnin_short_rejects_associated_data() {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);

        let result = aead.encrypt(&key, &nonce, b"x", Some(b"ad"));
        assert!(result.is_err());
    }

    #[test]
    fn test_saturnin_short_rejects_long_plaintext() {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let plaintext = vec![0xABu8; 16];

        let result = aead.encrypt(&key, &nonce, &plaintext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_saturnin_short_max_plaintext_round_trip() -> Result<()> {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![7u8; 32]);
        let nonce = Nonce::new(vec![3u8; 16]);
        let plaintext = vec![0xCDu8; 15];

        let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None)?;
        assert_eq!(ciphertext.len(), 32);
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_saturnin_short_binds_nonce_and_plaintext() -> Result<()> {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![9u8; 32]);
        let nonce = Nonce::new(vec![1u8; 16]);
        let wrong_nonce = Nonce::new(vec![2u8; 16]);
        let prefix = b"shared-prefix!";
        let mut msg_a = prefix.to_vec();
        msg_a.push(0x00);
        let mut msg_b = prefix.to_vec();
        msg_b.push(0x01);

        let ct_a = aead.encrypt(&key, &nonce, &msg_a, None)?;
        let ct_b = aead.encrypt(&key, &nonce, &msg_b, None)?;
        assert_ne!(ct_a, ct_b);
        assert_eq!(aead.decrypt(&key, &nonce, &ct_a, None)?, msg_a);
        assert_eq!(aead.decrypt(&key, &nonce, &ct_b, None)?, msg_b);
        assert!(aead.decrypt(&key, &wrong_nonce, &ct_a, None).is_err());

        let mut tampered = ct_a.clone();
        tampered[31] ^= 1;
        assert!(aead.decrypt(&key, &nonce, &tampered, None).is_err());

        Ok(())
    }

    #[test]
    fn test_saturnin_short_invalid_key_size() {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![0u8; 16]);
        let nonce = Nonce::new(vec![0u8; 16]);

        let result = aead.encrypt(&key, &nonce, b"test", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_saturnin_short_invalid_nonce_size() {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 8]);

        let result = aead.encrypt(&key, &nonce, b"test", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_saturnin_short_reference_kat_vectors() -> Result<()> {
        let aead = SaturninShortAead::new();
        let key = AeadKey::new(vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ]);
        let nonce = Nonce::new(vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);

        let cases: &[(&[u8], &[u8])] = &[
            (
                b"",
                &[
                    0xEF, 0x14, 0x2F, 0xC8, 0x10, 0xCE, 0x92, 0x83, 0x97, 0x26, 0xD6, 0x00, 0xFC,
                    0xCF, 0xD7, 0x11, 0x90, 0x50, 0xDA, 0x25, 0xA3, 0xEC, 0x55, 0x86, 0xC7, 0xC4,
                    0x3C, 0xA6, 0x68, 0xE3, 0xC8, 0xC0,
                ],
            ),
            (
                &[0x00],
                &[
                    0x1E, 0xFF, 0x91, 0x3C, 0x60, 0x7D, 0xB0, 0x32, 0xC8, 0xF1, 0x72, 0x6D, 0x51,
                    0x40, 0x1C, 0xA1, 0x3C, 0x54, 0x36, 0x5D, 0xBC, 0x40, 0x74, 0xEF, 0x81, 0x48,
                    0xE0, 0xC2, 0x16, 0x0A, 0xD6, 0x56,
                ],
            ),
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E,
                ],
                &[
                    0xF8, 0xB7, 0xDB, 0xF8, 0x0E, 0x51, 0x9C, 0xF8, 0x0E, 0x03, 0xA2, 0x07, 0xA4,
                    0x79, 0x8A, 0x5A, 0x01, 0x44, 0xF9, 0x39, 0x21, 0x69, 0xFA, 0xEB, 0xF7, 0x81,
                    0xBF, 0x4D, 0xA9, 0xBD, 0xB0, 0xE4,
                ],
            ),
        ];

        for (plaintext, expected_ct) in cases {
            let ciphertext = aead.encrypt(&key, &nonce, plaintext, None)?;
            assert_eq!(ciphertext.as_slice(), *expected_ct);
            let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None)?;
            assert_eq!(decrypted.as_slice(), *plaintext);
        }

        Ok(())
    }
}
