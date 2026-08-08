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
//!
//! ## Open obligation Q-2 — the spec's IND-qCCA claim for this mode rests on a disproved citation
//!
//! This mode's wire format is **frozen** and this note changes nothing about it; it exists so the
//! "superior post-quantum security" framing above is not read as a settled result. The Saturnin
//! LWC spec §4.3 says the modes "are intended to provide quantum security against chosen message
//! superposition attacks and superposition verification queries (IND-qCCA security)", and §4.3.1
//! supplies the load-bearing step: "Soukharev, Jao and Seshadri have revisited these results
//! \[SJS16\], and proved that the encrypt-then-MAC composition offers IND-qCCA security, assuming
//! that the encryption scheme is IND-qCPA, and the MAC is SUF-qCMA." IACR ePrint 2025/387
//! disproves exactly that claim ("we disprove a claim made by Soukharev et al. at PQCrypto 2016";
//! "\[SJS16, Theorem 3.6\] … is inconclusive"). The conclusion looks **repairable** — see the
//! **Q-2** bullet in `src/aead_ctx.rs` for the full statement, the proposed replacement chain
//! (2025/387 Thm 3 + Thm 4 + Cor 1, which need the MAC to be a *qPRF*, a hypothesis the spec
//! argues for Cascade in §4.3.3), and what a cryptographer would have to sign. Until then, do not
//! restate the spec's IND-qCCA claim for this mode without the footnote. Classical AE security is
//! unaffected; this is about the Q2 claim only. **Q-2 does not apply to `SaturninQcb`**, which is
//! an integrated TBC mode rather than a generic composition.

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

    /// Compute the raw CTR-Cascade tag `T` over associated data and a ciphertext body, without
    /// touching the ciphertext body itself (no CTR pass).
    ///
    /// `pub(crate)`: this is a pure extraction of the tag computation already present verbatim in
    /// [`Self::decrypt_core`] (`cascade_init` + `cascade(2,3,ad)` + `cascade(4,5,ct_body)`) and,
    /// interleaved with the CTR pass, in [`Self::encrypt_bytes`]. It exists so
    /// [`crate::aead_ctx::SaturninAeadCtx`] can recompute `T` on its decrypt path without
    /// duplicating the cascade construction. Adding this method changes no production bytes of
    /// `SaturninAead` itself — `decrypt_core`/`encrypt_bytes` are left untouched, and
    /// `tests/aead_kat_pin.rs` pins that `SaturninAead`'s own output is unaffected.
    ///
    /// Gated on `hash`: `aead_ctx` (the sole caller) is `all(aead, hash)`, and this method lives
    /// inside the `aead`-gated module, so `#[cfg(feature = "hash")]` here is exactly
    /// `all(aead, hash)`. Without the gate, a `--no-default-features --features std,alloc,aead`
    /// build compiles this method with nothing calling it — OBSERVED as
    /// `warning: method `base_tag_over` is never used`, which is a hard error under any
    /// `-D warnings` gate. (`ctr_encrypt` below needs no such gate: `encrypt_bytes` and
    /// `decrypt_core` in this same module call it regardless of `hash`.)
    #[cfg(feature = "hash")]
    pub(crate) fn base_tag_over(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ct_body: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut tag = self.cascade_init(key, nonce)?;
        self.cascade(&mut tag, 2, 3, ad)?;
        self.cascade(&mut tag, 4, 5, ct_body)?;
        Ok(tag)
    }

    /// CTR encryption/decryption (optimized).
    ///
    /// `pub(crate)` (widened from private) so [`crate::aead_ctx::SaturninAeadCtx`]'s decrypt path
    /// can run CTR without re-implementing it — see that module for why this stays deliberately
    /// pure delegation rather than a refactor of `encrypt_bytes`/`decrypt_core`.
    pub(crate) fn ctr_encrypt(&self, key: &[u8], nonce: &[u8], data: &mut [u8]) -> Result<()> {
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
    ///
    /// Takes key/nonce as byte slices: the `Aead`/`AeadDecryptSemantic` trait methods forward
    /// `key.as_bytes()`/`nonce.as_bytes()` here, and the allocation-free [`Self::decrypt_bytes`]
    /// passes its slices directly — neither path materializes an `AeadKey`/`Nonce` wrapper.
    fn decrypt_core(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }

        if nonce.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.len(),
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
        key_staged.copy_from_slice(key);
        let mut nonce_staged = Zeroizing::new([0u8; 16]);
        nonce_staged.copy_from_slice(nonce);
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

    /// Allocation-free encrypt: takes key/nonce as byte slices, avoiding the `AeadKey`/`Nonce`
    /// `Vec` wrappers that [`Aead::encrypt`] requires. Per-packet callers (e.g. per-packet record sealing)
    /// use this to skip two heap allocations on every record; the trait method forwards here.
    pub fn encrypt_bytes(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }

        if nonce.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.len(),
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
        key_staged.copy_from_slice(key);
        let mut nonce_staged = Zeroizing::new([0u8; 16]);
        nonce_staged.copy_from_slice(nonce);
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

    /// Allocation-free Layer A decrypt: byte-slice counterpart to [`Aead::decrypt`]. Returns the
    /// plaintext on success, or [`Error::VerificationFailed`] on tag mismatch.
    pub fn decrypt_bytes(
        &self,
        key: &[u8],
        nonce: &[u8],
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
        self.encrypt_bytes(key.as_bytes(), nonce.as_bytes(), plaintext, associated_data)
    }

    /// Decrypt and verify data (Layer A); shares one decrypt core with [`lib_q_core::AeadDecryptSemantic`].
    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt_bytes(
            key.as_bytes(),
            nonce.as_bytes(),
            ciphertext,
            associated_data,
        )
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
        self.decrypt_core(
            key.as_bytes(),
            nonce.as_bytes(),
            ciphertext,
            associated_data,
        )
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

    #[test]
    fn test_saturnin_default_matches_new() {
        // `Default` must produce a functioning instance, not merely compile — round-trip
        // through it end to end rather than only constructing it.
        let aead = SaturninAead::default();
        let key = AeadKey::new(vec![3u8; 32]);
        let nonce = Nonce::new(vec![4u8; 16]);
        let ct = aead
            .encrypt(&key, &nonce, b"via-default", None)
            .expect("default-constructed AEAD must encrypt");
        let pt = aead
            .decrypt(&key, &nonce, &ct, None)
            .expect("default-constructed AEAD must decrypt its own ciphertext");
        assert_eq!(pt, b"via-default");
    }

    #[test]
    fn test_encrypt_bytes_rejects_wrong_key_size() {
        let aead = SaturninAead::new();
        let err = aead
            .encrypt_bytes(&[0u8; 31], &[0u8; 16], b"m", None)
            .expect_err("31-byte key must be rejected");
        assert!(matches!(
            err,
            Error::InvalidKeySize {
                expected: 32,
                actual: 31
            }
        ));
    }

    #[test]
    fn test_encrypt_bytes_rejects_wrong_nonce_size() {
        let aead = SaturninAead::new();
        let err = aead
            .encrypt_bytes(&[0u8; 32], &[0u8; 15], b"m", None)
            .expect_err("15-byte nonce must be rejected");
        assert!(matches!(
            err,
            Error::InvalidNonceSize {
                expected: 16,
                actual: 15
            }
        ));
    }

    #[test]
    fn test_decrypt_bytes_rejects_wrong_key_size() {
        let aead = SaturninAead::new();
        let err = aead
            .decrypt_bytes(&[0u8; 20], &[0u8; 16], &[0u8; 32], None)
            .expect_err("20-byte key must be rejected");
        assert!(matches!(
            err,
            Error::InvalidKeySize {
                expected: 32,
                actual: 20
            }
        ));
    }

    #[test]
    fn test_decrypt_bytes_rejects_wrong_nonce_size() {
        let aead = SaturninAead::new();
        let err = aead
            .decrypt_bytes(&[0u8; 32], &[0u8; 4], &[0u8; 32], None)
            .expect_err("4-byte nonce must be rejected");
        assert!(matches!(
            err,
            Error::InvalidNonceSize {
                expected: 16,
                actual: 4
            }
        ));
    }

    #[test]
    fn test_decrypt_bytes_rejects_ciphertext_shorter_than_tag() {
        let aead = SaturninAead::new();
        // 10 bytes is shorter than the 32-byte tag alone.
        let err = aead
            .decrypt_bytes(&[0u8; 32], &[0u8; 16], &[0u8; 10], None)
            .expect_err("ciphertext shorter than the tag must be rejected");
        assert!(matches!(err, Error::InvalidCiphertextSize { .. }));
    }

    #[test]
    fn test_round_trip_across_block_boundary_sizes() -> Result<()> {
        // Exercises the CTR full-block path, the CTR partial-final-block path, and the
        // cascade's full-block vs. padded-tail branches together, for plaintext/AD sizes at
        // and around the 32-byte block boundary.
        let aead = SaturninAead::new();
        let key = AeadKey::new(vec![9u8; 32]);
        let nonce = Nonce::new(vec![5u8; 16]);
        for len in [0usize, 1, 31, 32, 33, 63, 64, 65] {
            let plaintext = vec![0xAAu8; len];
            for ad_len in [0usize, 32] {
                let ad = vec![0x55u8; ad_len];
                let ad_opt = Some(ad.as_slice());
                let ct = aead.encrypt(&key, &nonce, &plaintext, ad_opt)?;
                assert_eq!(ct.len(), len + 32);
                let pt = aead.decrypt(&key, &nonce, &ct, ad_opt)?;
                assert_eq!(
                    pt, plaintext,
                    "round trip failed for len={len}, ad_len={ad_len}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_round_trip_crosses_avx2_ctr_batch_threshold() -> Result<()> {
        // `ctr_encrypt`'s 8-lane AVX2 batch path only triggers once the remaining data is
        // >= 32*8 = 256 bytes; the block-boundary test above only goes up to 65 bytes, so
        // that batch path (and the loop continuing past more than one batch) is otherwise
        // never exercised. 600 bytes crosses two full batches plus a non-block-aligned tail.
        let aead = SaturninAead::new();
        let key = AeadKey::new(vec![0x71u8; 32]);
        let nonce = Nonce::new(vec![0x62u8; 16]);
        let plaintext = vec![0xC3u8; 600];
        let ad = vec![0x5Au8; 17];

        let ct = aead.encrypt(&key, &nonce, &plaintext, Some(&ad))?;
        assert_eq!(ct.len(), plaintext.len() + 32);
        let pt = aead.decrypt(&key, &nonce, &ct, Some(&ad))?;
        assert_eq!(pt, plaintext);
        Ok(())
    }
}
