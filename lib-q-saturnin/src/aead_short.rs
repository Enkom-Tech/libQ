//! Saturnin-Short AEAD implementation
//!
//! Saturnin-Short is the encode-then-encrypt mode from the Saturnin specification
//! (Section 2.3): a single `Saturnin^6` block cipher call over `pad(nonce || plaintext)`.
//! Confidentiality and integrity are provided together in one 32-byte ciphertext; there is
//! no separate tag and no associated data.
//!
//! ## Limits
//!
//! - **Plaintext**: 0 to 15 bytes with the default 16-byte nonce; cannot equal 16. The padded
//!   tail reserves at least one byte for the `0x80` terminator, so plaintext is strictly under
//!   the tail length.
//! - **Nonce**: 128 bits (16 bytes) by default
//! - **Associated data**: not supported
//! - **Ciphertext**: always 32 bytes
//!
//! ## Shorter-nonce tweak (update note)
//!
//! "An Update on Saturnin" proposes, "should the need arise", a tweak of Saturnin-Short that
//! **decreases the nonce length in order to accommodate longer messages**. Since the 256-bit
//! block is split as `pad(nonce ‖ plaintext)`, every byte removed from the nonce becomes
//! available to the plaintext: with a nonce of `n` bytes the maximum plaintext length is
//! `31 - n` bytes. [`SaturninShortAead::with_nonce_len`] selects the nonce length (the default
//! [`SaturninShortAead::new`] keeps the 16-byte nonce, 15-byte plaintext limit). The shorter
//! nonce trades nonce space (and thus the number of distinct nonces usable under one key) for
//! message room, so callers must keep nonces unique within the reduced space.
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

/// Default nonce length in bytes (128 bits).
const DEFAULT_NONCE_LEN: usize = 16;

/// Fixed ciphertext length: one 256-bit Saturnin block.
const CIPHERTEXT_LEN: usize = 32;

/// Largest supported nonce length: leaves at least one tail byte for the `0x80` terminator.
const MAX_NONCE_LEN: usize = CIPHERTEXT_LEN - 1;

/// Maximum plaintext length for a given nonce length (`block - nonce - 1` for the terminator).
#[inline]
const fn max_plaintext_for_nonce(nonce_len: usize) -> usize {
    CIPHERTEXT_LEN - nonce_len - 1
}

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
///
/// Generalized over the nonce length: the first `nonce.len()` bytes bind the nonce and the
/// remaining `32 - nonce.len()` tail bytes carry `pad(plaintext)`.
fn short_parse_auth_and_padding(decrypted: &[u8; 32], nonce: &[u8]) -> (u8, usize) {
    let nonce_len = nonce.len();
    let tail_len = CIPHERTEXT_LEN - nonce_len;
    let mut auth_or = 0u8;

    for (stored, expected) in decrypted[..nonce_len].iter().zip(nonce.iter()) {
        auth_or |= stored ^ expected;
    }

    let mut notfound = 0xFFu8;
    let mut plaintext_len = 0usize;

    for i in (0..tail_len).rev() {
        let byte = decrypted[nonce_len + i];
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

/// Fixed-length candidate plaintext (`<= max_pt` pushes); selection uses `auth_ok_mask` only.
///
/// `tail` is the post-nonce region of the decrypted block and `max_pt` is `tail.len() - 1`
/// (the terminator byte can never be plaintext).
fn short_materialize_plaintext_candidate(
    auth_ok_mask: u8,
    plaintext_len: usize,
    tail: &[u8],
    max_pt: usize,
) -> Vec<u8> {
    let len_for_mask = plaintext_len.min(max_pt);
    let mut out = Vec::with_capacity(max_pt);
    for (i, &byte) in tail[..max_pt].iter().enumerate() {
        let take = auth_ok_mask & ct_usize_lt(i, len_for_mask);
        out.push(byte & take);
    }
    out
}

/// Saturnin-Short AEAD (`Saturnin^6`, 10 super-rounds).
///
/// The nonce length is configurable (see [`with_nonce_len`](Self::with_nonce_len)) per the
/// update note's shorter-nonce tweak; [`new`](Self::new) keeps the default 16-byte nonce.
pub struct SaturninShortAead {
    core: SaturninCore,
    nonce_len: usize,
}

impl SaturninShortAead {
    /// Create a new Saturnin-Short AEAD instance with the default 16-byte nonce.
    pub fn new() -> Self {
        Self::with_nonce_len(DEFAULT_NONCE_LEN).expect("default nonce length is valid")
    }

    /// Create a Saturnin-Short AEAD instance with a custom nonce length (update note's
    /// shorter-nonce tweak).
    ///
    /// A nonce of `nonce_len` bytes leaves `31 - nonce_len` bytes for plaintext. The block is
    /// always `pad(nonce ‖ plaintext)`, so at least one tail byte is reserved for the `0x80`
    /// terminator.
    ///
    /// # Errors
    /// Returns [`Error::InvalidNonceSize`] if `nonce_len` is `0` or greater than `31`.
    pub fn with_nonce_len(nonce_len: usize) -> Result<Self> {
        if nonce_len == 0 || nonce_len > MAX_NONCE_LEN {
            return Err(Error::InvalidNonceSize {
                expected: DEFAULT_NONCE_LEN,
                actual: nonce_len,
            });
        }
        let core = SaturninCore::new(10, 6).expect("Saturnin-Short uses domain 6");
        Ok(Self { core, nonce_len })
    }

    /// Key size in bytes.
    pub const fn key_size() -> usize {
        32
    }

    /// Nonce size in bytes (the configured nonce length).
    pub const fn nonce_size_default() -> usize {
        DEFAULT_NONCE_LEN
    }

    /// Nonce size in bytes for this instance.
    pub const fn nonce_size(&self) -> usize {
        self.nonce_len
    }

    /// Authenticated ciphertext size in bytes (fixed 32-byte block).
    pub const fn tag_size() -> usize {
        CIPHERTEXT_LEN
    }

    /// Maximum supported plaintext length in bytes for this instance's nonce length.
    pub const fn max_plaintext_len(&self) -> usize {
        max_plaintext_for_nonce(self.nonce_len)
    }

    fn validate_key(key: &[u8]) -> Result<[u8; 32]> {
        key.try_into().map_err(|_| Error::InvalidKeySize {
            expected: Self::key_size(),
            actual: key.len(),
        })
    }

    fn validate_nonce(&self, nonce: &[u8]) -> Result<()> {
        if nonce.len() != self.nonce_len {
            return Err(Error::InvalidNonceSize {
                expected: self.nonce_len,
                actual: nonce.len(),
            });
        }
        Ok(())
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

    fn reject_plaintext_len(&self, plaintext_len: usize) -> Result<()> {
        let max = self.max_plaintext_len();
        if plaintext_len > max {
            return Err(Error::InvalidMessageSize {
                max,
                actual: plaintext_len,
            });
        }
        Ok(())
    }

    /// Build `pad(nonce || plaintext)` into a 32-byte block (reference `encrypt.c`).
    fn encode_block(&self, nonce: &[u8], plaintext: &[u8]) -> [u8; 32] {
        let mut block = [0u8; 32];
        let nonce_len = self.nonce_len;
        block[..nonce_len].copy_from_slice(nonce);
        let pt_len = plaintext.len();
        if pt_len > 0 {
            block[nonce_len..nonce_len + pt_len].copy_from_slice(plaintext);
        }
        block[nonce_len + pt_len] = 0x80;
        block
    }

    /// Semantic verify outcome for Saturnin-Short (no plaintext bytes on failure).
    fn short_decrypt_semantic_inner(
        &self,
        decrypted: &[u8; 32],
        nonce: &[u8],
    ) -> DecryptSemanticOutcome {
        let nonce_len = self.nonce_len;
        let max_pt = self.max_plaintext_len();
        let (auth_or, plaintext_len) = short_parse_auth_and_padding(decrypted, nonce);
        let auth_ok_mask = short_auth_ok_mask(auth_or);

        let tail = &decrypted[nonce_len..CIPHERTEXT_LEN];

        let mut candidate =
            short_materialize_plaintext_candidate(auth_ok_mask, plaintext_len, tail, max_pt);
        if auth_ok_mask != SHORT_AUTH_OK_MASK {
            candidate.zeroize();
            return DecryptSemanticOutcome::AuthenticationFailed;
        }
        candidate.truncate(plaintext_len.min(max_pt));
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
        self.validate_nonce(nonce.as_bytes())?;

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

        let outcome = self.short_decrypt_semantic_inner(&block, nonce.as_bytes());
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
        self.reject_plaintext_len(plaintext.len())?;

        let key32 = Self::validate_key(key.as_bytes())?;
        self.validate_nonce(nonce.as_bytes())?;

        let mut block = self.encode_block(nonce.as_bytes(), plaintext);
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
        let aead = SaturninShortAead::new();
        assert_eq!(SaturninShortAead::key_size(), 32);
        assert_eq!(SaturninShortAead::nonce_size_default(), 16);
        assert_eq!(aead.nonce_size(), 16);
        assert_eq!(SaturninShortAead::tag_size(), 32);
        assert_eq!(aead.max_plaintext_len(), 15);
    }

    #[test]
    fn test_saturnin_short_shorter_nonce_tweak() -> Result<()> {
        // 8-byte nonce frees 8 extra plaintext bytes: max = 31 - 8 = 23.
        let aead = SaturninShortAead::with_nonce_len(8)?;
        assert_eq!(aead.nonce_size(), 8);
        assert_eq!(aead.max_plaintext_len(), 23);

        let key = AeadKey::new(vec![0x42u8; 32]);
        let nonce = Nonce::new(vec![0x11u8; 8]);
        let plaintext = vec![0xABu8; 23]; // longer than the 15-byte default-nonce limit

        let ct = aead.encrypt(&key, &nonce, &plaintext, None)?;
        assert_eq!(ct.len(), 32);
        assert_eq!(aead.decrypt(&key, &nonce, &ct, None)?, plaintext);

        // 24 bytes must be rejected (one over the limit for an 8-byte nonce).
        assert!(aead.encrypt(&key, &nonce, &[0u8; 24], None).is_err());
        // Wrong-length nonce rejected.
        assert!(
            aead.encrypt(&key, &Nonce::new(vec![0u8; 16]), &plaintext, None)
                .is_err()
        );
        // Tamper still caught.
        let mut bad = ct.clone();
        bad[30] ^= 1;
        assert!(aead.decrypt(&key, &nonce, &bad, None).is_err());
        Ok(())
    }

    #[test]
    fn test_saturnin_short_invalid_nonce_len_config() {
        assert!(SaturninShortAead::with_nonce_len(0).is_err());
        assert!(SaturninShortAead::with_nonce_len(32).is_err());
        assert!(SaturninShortAead::with_nonce_len(31).is_ok()); // degenerate: max_pt = 0
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
