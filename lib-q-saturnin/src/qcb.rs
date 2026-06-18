//! Saturnin-QCB authenticated encryption
//!
//! Saturnin-QCB is the one-pass, parallelizable AEAD proposed in "An Update on Saturnin". It is
//! a `ΘCB`/`TAE`-style mode built on the Saturnin [tweakable block cipher](crate::tbc): each
//! block of plaintext is encrypted by one TBC call whose tweak binds a domain separator, the
//! nonce, and the block number; the tag is produced by encrypting a checksum of the (padded)
//! message under a distinct domain. Because nonce + block-number give every TBC call a unique
//! tweak (when nonces are not reused), the mode achieves rate-one encryption with a tighter
//! quantum-security proof than Saturnin-CTR-Cascade, and every block can be processed
//! independently (parallelized).
//!
//! # ⚠️ Instantiation note — not validated against designer test vectors
//!
//! The update note gives only a **high-level** description of Saturnin-QCB (Section 5 and
//! Figure 1); the full mode definition lives in the separate QCB paper `[BBC+20]`, which is not
//! bundled with this repository, and **no official QCB known-answer test vectors are
//! published**. The construction below faithfully follows everything the update note specifies,
//! and fills the gaps it leaves open with explicit, documented choices:
//!
//! - **TBC** (unambiguous, from the note): `TBC_d(K,T)(M) = Saturnin16^d_{K⊕T}(M)`. See
//!   [`crate::tbc`].
//! - **Domains** (from Figure 1): message blocks use domain **9**, the tag uses domain **10**.
//!   Associated-data blocks use domain **11** (the note states AD blocks also cost 16
//!   super-rounds but Figure 1 omits AD layout — this domain choice is ours).
//! - **Tweak encoding** (ours): `T = N (16 bytes) ‖ 0x00·8 ‖ block_index_be_u64 (8 bytes)`, a
//!   256-bit value. AD-block tweaks use the same layout with the nonce field zeroed, so AD
//!   authentication is nonce-independent (OCB tradition).
//! - **Padding** (from the note: "the message is always padded with a 01* padding, so the
//!   ciphertext can be up to 512 bits longer than the plaintext"): `10*` padding (`0x80` then
//!   zeros) is **always** applied, adding a whole extra block when the input is already a block
//!   multiple. This trades a little length for a simple, unambiguous, invertible mode.
//! - **Checksum / AD folding** (ours): `checksum = ⊕ padded_message_blocks`;
//!   `tag = TBC_10(K, tweak(N, last)) (checksum) ⊕ ⊕_j TBC_11(K, tweak_ad(j)) (A_j)`.
//!
//! This module is therefore a **spec-faithful interpretation** suitable for experimentation and
//! cross-checking, not a byte-compatible reference for an external Saturnin-QCB. It is verified
//! by round-trip, tamper-detection, parallel-equivalence, and pinned self-consistency vectors —
//! not by designer KATs. If/when official QCB vectors are published, pin them here.
//!
//! ## Usage Example
//!
//! ```rust
//! # #[cfg(feature = "qcb")]
//! # {
//! use lib_q_saturnin::{
//!     Aead,
//!     AeadKey,
//!     Nonce,
//!     SaturninQcb,
//! };
//!
//! let aead = SaturninQcb::new();
//! let key = AeadKey::new(vec![0u8; 32]);
//! let nonce = Nonce::new(vec![0u8; 16]);
//!
//! let ciphertext = aead
//!     .encrypt(&key, &nonce, b"Secret message", Some(b"metadata"))
//!     .unwrap();
//! let decrypted = aead
//!     .decrypt(&key, &nonce, &ciphertext, Some(b"metadata"))
//!     .unwrap();
//! assert_eq!(decrypted, b"Secret message");
//! # }
//! ```

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

use crate::tbc::{
    SaturninTbc,
    TBC_BLOCK_BYTES,
};

/// Domain separator for message blocks (Figure 1).
const DOMAIN_MESSAGE: u8 = 9;
/// Domain separator for the tag / checksum block (Figure 1).
const DOMAIN_TAG: u8 = 10;
/// Domain separator for associated-data blocks (this instantiation's choice).
const DOMAIN_AD: u8 = 11;

/// Block size in bytes (256-bit Saturnin block).
const BLOCK: usize = TBC_BLOCK_BYTES;

/// Saturnin-QCB AEAD.
///
/// Holds pre-built tweakable block ciphers for the three domains used by the mode so that
/// per-message work allocates no round constants.
pub struct SaturninQcb {
    msg: SaturninTbc,
    tag: SaturninTbc,
    ad: SaturninTbc,
}

impl SaturninQcb {
    /// Create a new Saturnin-QCB instance.
    pub fn new() -> Self {
        Self {
            msg: SaturninTbc::new(DOMAIN_MESSAGE).expect("domain 9 is valid"),
            tag: SaturninTbc::new(DOMAIN_TAG).expect("domain 10 is valid"),
            ad: SaturninTbc::new(DOMAIN_AD).expect("domain 11 is valid"),
        }
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
        BLOCK
    }

    /// Build the 256-bit message/tag tweak `N ‖ 0·8 ‖ block_index_be`.
    fn tweak(nonce16: &[u8; 16], block_index: u64) -> [u8; BLOCK] {
        let mut t = [0u8; BLOCK];
        t[0..16].copy_from_slice(nonce16);
        t[24..32].copy_from_slice(&block_index.to_be_bytes());
        t
    }

    /// Build the 256-bit associated-data tweak (nonce field zeroed; AD is nonce-independent).
    fn ad_tweak(block_index: u64) -> [u8; BLOCK] {
        let mut t = [0u8; BLOCK];
        t[24..32].copy_from_slice(&block_index.to_be_bytes());
        t
    }

    /// `10*`-pad `data` to a positive multiple of [`BLOCK`], always appending at least the `0x80`
    /// marker (a whole extra block when `data` is already a block multiple, or when empty).
    fn pad(data: &[u8]) -> Zeroizing<Vec<u8>> {
        let padded_len = (data.len() / BLOCK + 1) * BLOCK;
        let mut out = Zeroizing::new(Vec::with_capacity(padded_len));
        out.extend_from_slice(data);
        out.push(0x80);
        out.resize(padded_len, 0u8);
        out
    }

    /// Authenticate associated data into a 256-bit accumulator (`0` when AD is empty).
    fn absorb_ad(&self, key: &[u8; 32], ad: &[u8]) -> Result<Zeroizing<[u8; BLOCK]>> {
        let mut auth = Zeroizing::new([0u8; BLOCK]);
        if ad.is_empty() {
            return Ok(auth);
        }
        let padded = Self::pad(ad);
        for (j, chunk) in padded.chunks_exact(BLOCK).enumerate() {
            let tweak = Self::ad_tweak(j as u64);
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(chunk);
            self.ad.encrypt_block(key, &tweak, &mut block)?;
            for i in 0..BLOCK {
                auth[i] ^= block[i];
            }
            block.zeroize();
        }
        Ok(auth)
    }

    /// Compute the 256-bit tag over the padded-message checksum and the AD accumulator.
    fn compute_tag(
        &self,
        key: &[u8; 32],
        nonce16: &[u8; 16],
        checksum: &[u8; BLOCK],
        last_index: u64,
        ad_auth: &[u8; BLOCK],
    ) -> Result<Zeroizing<[u8; BLOCK]>> {
        let mut tag = Zeroizing::new(*checksum);
        let tweak = Self::tweak(nonce16, last_index);
        self.tag.encrypt_block(key, &tweak, &mut tag)?;
        for i in 0..BLOCK {
            tag[i] ^= ad_auth[i];
        }
        Ok(tag)
    }

    fn validate_lengths(key: &AeadKey, nonce: &Nonce) -> Result<()> {
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
        Ok(())
    }

    /// Shared decrypt core for Layer A ([`Aead::decrypt`]) and Layer B
    /// ([`AeadDecryptSemantic::decrypt_semantic`]). Always decrypts the full ciphertext body
    /// before the authentication outcome is allowed to influence the returned plaintext.
    fn decrypt_core(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        Self::validate_lengths(key, nonce)?;

        // Need at least one message block plus the tag.
        if ciphertext.len() < 2 * BLOCK {
            return Err(Error::aead_ciphertext_shorter_than_tag(
                2 * BLOCK,
                ciphertext.len(),
            ));
        }
        // The body (ciphertext minus tag) must be block-aligned.
        if !ciphertext.len().is_multiple_of(BLOCK) {
            return Err(Error::InvalidCiphertextSize {
                expected: (ciphertext.len() / BLOCK + 1) * BLOCK,
                actual: ciphertext.len(),
            });
        }

        let body_len = ciphertext.len() - BLOCK;
        let body = &ciphertext[..body_len];
        let received_tag = &ciphertext[body_len..];
        let m = body_len / BLOCK;

        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key.as_bytes());
        let mut nonce16 = Zeroizing::new([0u8; 16]);
        nonce16.copy_from_slice(nonce.as_bytes());
        let ad = associated_data.unwrap_or(&[]);

        // Decrypt every block and accumulate the checksum (full work, no early exit).
        let mut plain = Zeroizing::new(Vec::with_capacity(body_len));
        let mut checksum = Zeroizing::new([0u8; BLOCK]);
        for (i, chunk) in body.chunks_exact(BLOCK).enumerate() {
            let tweak = Self::tweak(&nonce16, i as u64);
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(chunk);
            self.msg.decrypt_block(&key_staged, &tweak, &mut block)?;
            for k in 0..BLOCK {
                checksum[k] ^= block[k];
            }
            plain.extend_from_slice(&block);
            block.zeroize();
        }

        let ad_auth = self.absorb_ad(&key_staged, ad)?;
        let expected_tag =
            self.compute_tag(&key_staged, &nonce16, &checksum, (m - 1) as u64, &ad_auth)?;

        let tag_valid = lib_q_core::Utils::constant_time_compare(&*expected_tag, received_tag);

        if !tag_valid {
            return Ok(DecryptSemanticOutcome::AuthenticationFailed);
        }

        // Authenticated: strip 10* padding (the final block always carries the 0x80 marker).
        let plaintext_len = match unpad_len(&plain) {
            Some(len) => len,
            // Authentic ciphertext we produced always has well-formed padding; treat a malformed
            // (e.g. truncated/forged-yet-matching) layout as an authentication failure.
            None => return Ok(DecryptSemanticOutcome::AuthenticationFailed),
        };
        let mut out = Vec::with_capacity(plaintext_len);
        out.extend_from_slice(&plain[..plaintext_len]);
        Ok(DecryptSemanticOutcome::Success(Zeroizing::new(out)))
    }
}

/// Locate the `10*` padding marker; returns the unpadded length, or `None` if malformed.
fn unpad_len(padded: &[u8]) -> Option<usize> {
    let mut idx = padded.len();
    while idx > 0 && padded[idx - 1] == 0 {
        idx -= 1;
    }
    if idx == 0 || padded[idx - 1] != 0x80 {
        return None;
    }
    Some(idx - 1)
}

impl Aead for SaturninQcb {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Self::validate_lengths(key, nonce)?;

        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key.as_bytes());
        let mut nonce16 = Zeroizing::new([0u8; 16]);
        nonce16.copy_from_slice(nonce.as_bytes());
        let ad = associated_data.unwrap_or(&[]);

        let padded = Self::pad(plaintext);
        let m = padded.len() / BLOCK;

        let mut output = Vec::with_capacity(padded.len() + BLOCK);
        let mut checksum = Zeroizing::new([0u8; BLOCK]);
        for (i, chunk) in padded.chunks_exact(BLOCK).enumerate() {
            for k in 0..BLOCK {
                checksum[k] ^= chunk[k];
            }
            let tweak = Self::tweak(&nonce16, i as u64);
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(chunk);
            self.msg.encrypt_block(&key_staged, &tweak, &mut block)?;
            output.extend_from_slice(&block);
            block.zeroize();
        }

        let ad_auth = self.absorb_ad(&key_staged, ad)?;
        let tag = self.compute_tag(&key_staged, &nonce16, &checksum, (m - 1) as u64, &ad_auth)?;
        output.extend_from_slice(&*tag);
        Ok(output)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.decrypt_core(key, nonce, ciphertext, associated_data)? {
            DecryptSemanticOutcome::Success(p) => Ok(Vec::clone(&*p)),
            DecryptSemanticOutcome::AuthenticationFailed => Err(Error::VerificationFailed {
                operation: "Saturnin-QCB tag verification".to_string(),
            }),
        }
    }
}

impl AeadDecryptSemantic for SaturninQcb {
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

impl Default for SaturninQcb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn key() -> AeadKey {
        AeadKey::new((0..32u8).collect::<Vec<_>>())
    }

    fn nonce() -> Nonce {
        Nonce::new((0..16u8).collect::<Vec<_>>())
    }

    #[test]
    fn constants() {
        assert_eq!(SaturninQcb::key_size(), 32);
        assert_eq!(SaturninQcb::nonce_size(), 16);
        assert_eq!(SaturninQcb::tag_size(), 32);
    }

    #[test]
    fn round_trip_various_lengths() -> Result<()> {
        let aead = SaturninQcb::new();
        for len in [0usize, 1, 15, 31, 32, 33, 64, 100, 256] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = aead.encrypt(&key(), &nonce(), &pt, Some(b"hdr"))?;
            // Always-pad: body is padded message (multiple of 32) plus a 32-byte tag.
            let expected_body = (len / 32 + 1) * 32;
            assert_eq!(ct.len(), expected_body + 32, "len={len}");
            let dec = aead.decrypt(&key(), &nonce(), &ct, Some(b"hdr"))?;
            assert_eq!(dec, pt, "len={len}");
        }
        Ok(())
    }

    #[test]
    fn empty_message_and_ad() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"", None)?;
        assert_eq!(ct.len(), 64); // one padding block + tag
        assert_eq!(aead.decrypt(&key(), &nonce(), &ct, None)?, b"");
        Ok(())
    }

    #[test]
    fn tampered_tag_fails() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"hello world", Some(b"ad"))?;
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            aead.decrypt(&key(), &nonce(), &bad, Some(b"ad")),
            Err(Error::VerificationFailed { .. })
        ));
        assert_eq!(
            aead.decrypt_semantic(&key(), &nonce(), &bad, Some(b"ad"))?,
            DecryptSemanticOutcome::AuthenticationFailed
        );
        Ok(())
    }

    #[test]
    fn tampered_body_fails() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"hello world", None)?;
        let mut bad = ct.clone();
        bad[0] ^= 0x80;
        assert!(aead.decrypt(&key(), &nonce(), &bad, None).is_err());
        Ok(())
    }

    #[test]
    fn ad_is_authenticated() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"msg", Some(b"header-A"))?;
        // Wrong AD must fail.
        assert!(
            aead.decrypt(&key(), &nonce(), &ct, Some(b"header-B"))
                .is_err()
        );
        // Missing AD must fail.
        assert!(aead.decrypt(&key(), &nonce(), &ct, None).is_err());
        Ok(())
    }

    #[test]
    fn nonce_binding() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"msg", None)?;
        let other = Nonce::new(vec![0xFFu8; 16]);
        assert!(aead.decrypt(&key(), &other, &ct, None).is_err());
        Ok(())
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Pinned self-consistency vectors for this instantiation (key = 00..1f, nonce = 00..0f).
    ///
    /// These are **derived** from the construction in this module (Saturnin TBC + the documented
    /// QCB instantiation), not official designer KATs — see the module-level instantiation note.
    /// They lock the byte-level behavior so any accidental change to padding, tweak encoding,
    /// domains, or AD folding is caught.
    #[test]
    fn pinned_kat_vectors() -> Result<()> {
        let aead = SaturninQcb::new();
        let cases: &[(&str, &str, &str)] = &[
            (
                "",
                "",
                "bd0abd723c4149718b458ac68f3a0a1e9e84e1e33c830a5894e48e6591a43a33718cd938614ad4c64e971ae1df9a657e290f3d862e5429088a7066642b07b29a",
            ),
            (
                "",
                "6173736f636961746564",
                "bd0abd723c4149718b458ac68f3a0a1e9e84e1e33c830a5894e48e6591a43a33a40976d18060823323aa163b2ab7bf306cbbaff29aa86a0a31b6ba5d826c9dca",
            ),
            (
                "616263",
                "",
                "52d715efbd6e430e4be8c2b682527e349a26fa62c69de5da978299c475f41c6df4620482177e4946c61ae01ff424a467ab76d31a63e75d045d3daaad64909edf",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "686472",
                "16e51991ae3cb7cb92f3847c326188cb007267ece8153d03aeb98d4f161c84a730c8e81de51c9573d449dada58a211595a47a6f72f9776fd21347d45696e7f6743f9d93a4663c3f210ee1e99333007d9ceebd632ac2d5dacb2c9251499caddf2",
            ),
            (
                "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672121",
                "61642d31",
                "fe81caa8f1ee16e54fd7b3df31247e7ccd4295382cff4f9f7efefb5e970c6880c10b857de55d457eff7ea96f9e4c0dc2f30180b2c037d52565e8895d48ae701ebd4ceb39dbeece08aafae995d41998ea656e1cedb4326176717a42d8b92693e4",
            ),
        ];
        for (pt_hex, ad_hex, ct_hex) in cases {
            let pt = from_hex(pt_hex);
            let ad = from_hex(ad_hex);
            let ad_opt = if ad.is_empty() {
                None
            } else {
                Some(ad.as_slice())
            };
            let ct = aead.encrypt(&key(), &nonce(), &pt, ad_opt)?;
            assert_eq!(
                ct,
                from_hex(ct_hex),
                "encrypt mismatch for pt={pt_hex} ad={ad_hex}"
            );
            let dec = aead.decrypt(&key(), &nonce(), &ct, ad_opt)?;
            assert_eq!(dec, pt, "decrypt mismatch for pt={pt_hex} ad={ad_hex}");
        }
        Ok(())
    }

    #[test]
    fn parallel_block_independence() -> Result<()> {
        // QCB is rate-one and embarrassingly parallel: each ciphertext block depends only on its
        // own plaintext block, the key, the nonce, and its index. Changing one plaintext block
        // must change only that ciphertext block (the tag aside).
        let aead = SaturninQcb::new();
        let mut a = vec![0u8; 96]; // 3 blocks
        let mut b = a.clone();
        b[40] ^= 0xFF; // flip a byte in block 1
        let ca = aead.encrypt(&key(), &nonce(), &a, None)?;
        let cb = aead.encrypt(&key(), &nonce(), &b, None)?;
        // Block 0 (bytes 0..32) identical; block 1 (32..64) differs.
        assert_eq!(ca[0..32], cb[0..32]);
        assert_ne!(ca[32..64], cb[32..64]);
        assert_eq!(ca[64..96], cb[64..96]); // block 2 unchanged
        a.zeroize();
        b.zeroize();
        Ok(())
    }

    #[test]
    fn unpad_len_handles_valid_and_malformed() {
        // Valid 10* padding: marker then zeros.
        assert_eq!(unpad_len(&[1, 2, 3, 0x80, 0, 0]), Some(3));
        assert_eq!(unpad_len(&[0x80]), Some(0));
        // Malformed: no marker (all zeros, or trailing non-zero that isn't 0x80).
        assert_eq!(unpad_len(&[0, 0, 0]), None);
        assert_eq!(unpad_len(&[]), None);
        assert_eq!(unpad_len(&[1, 2, 3]), None);
    }

    #[test]
    fn default_matches_new() -> Result<()> {
        let a = SaturninQcb::default();
        let b = SaturninQcb::new();
        let pt = b"compare";
        assert_eq!(
            a.encrypt(&key(), &nonce(), pt, None)?,
            b.encrypt(&key(), &nonce(), pt, None)?
        );
        Ok(())
    }

    #[test]
    fn wrong_size_inputs_rejected() {
        let aead = SaturninQcb::new();
        assert!(
            aead.encrypt(&AeadKey::new(vec![0u8; 16]), &nonce(), b"x", None)
                .is_err()
        );
        assert!(
            aead.encrypt(&key(), &Nonce::new(vec![0u8; 8]), b"x", None)
                .is_err()
        );
        // Ciphertext shorter than one block + tag.
        assert!(aead.decrypt(&key(), &nonce(), &[0u8; 40], None).is_err());
        // Non block-aligned body.
        assert!(aead.decrypt(&key(), &nonce(), &[0u8; 65], None).is_err());
    }
}
