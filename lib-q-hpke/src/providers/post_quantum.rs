//! Post-quantum provider implementation
//!
//! AEAD instances used internally by this provider are [`lib_q_core::Aead`] as `Box<dyn Aead>`
//! (Layer A only). For **Layer B** semantic decrypt (`decrypt_semantic`), use the concrete HPKE
//! AEAD modules where implemented ([`crate::aead::saturnin::SaturninAeadImpl`],
//! [`crate::aead::shake256::Shake256AeadImpl`]), or the concrete registry types in `lib-q-aead`
//! (including the duplex-sponge AEAD registered in `lib-q-aead` when the `duplex-sponge-aead`
//! feature is enabled).

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_aead::create_aead;
// Use lib-q abstractions instead of direct algorithm coupling
use lib_q_core::{
    Aead as CoreAead,
    AeadKey,
    Algorithm,
    Hash as CoreHash,
    KemOperations,
    Nonce,
};
use lib_q_hash::digest::Digest;
use lib_q_hash::{
    HashAlgorithm,
    create_hash,
};
use lib_q_kem::LibQKemProvider;
use zeroize::Zeroizing;

use crate::error::{
    AeadOperation,
    HpkeError,
};
use crate::kdf::hkdf::HkdfImpl;
use crate::providers::traits::*;
use crate::security::CryptoRng;
use crate::types::*;

/// Post-quantum provider implementation
pub struct PostQuantumProvider;

impl Default for PostQuantumProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PostQuantumProvider {
    /// Create a new post-quantum provider
    pub fn new() -> Self {
        Self
    }

    /// Convert HPKE KEM to lib-q-core Algorithm
    fn hpke_kem_to_algorithm(kem: HpkeKem) -> Result<Algorithm, HpkeError> {
        match kem {
            HpkeKem::MlKem512 => Ok(Algorithm::MlKem512),
            HpkeKem::MlKem768 => Ok(Algorithm::MlKem768),
            HpkeKem::MlKem1024 => Ok(Algorithm::MlKem1024),
        }
    }

    /// Create a KEM provider instance using lib-q-kem abstraction
    fn create_kem_provider() -> Result<LibQKemProvider, HpkeError> {
        LibQKemProvider::new()
            .map_err(|e| HpkeError::CryptoError(format!("Failed to create KEM provider: {}", e)))
    }

    /// Create hash instance using lib-q-hash abstraction
    fn create_hash_instance(kdf: HpkeKdf) -> Result<Box<dyn CoreHash>, HpkeError> {
        let algorithm = match kdf {
            HpkeKdf::HkdfShake128 => HashAlgorithm::Shake128,
            HpkeKdf::HkdfShake256 => HashAlgorithm::Shake256,
            HpkeKdf::HkdfSha3_256 => HashAlgorithm::Sha3_256,
            HpkeKdf::HkdfSha3_512 => HashAlgorithm::Sha3_512,
        };
        create_hash(algorithm)
            .map_err(|e| HpkeError::CryptoError(format!("Failed to create hash instance: {}", e)))
    }

    /// Create AEAD instance using lib-q-aead abstraction
    fn create_aead_instance(aead: HpkeAead) -> Result<Box<dyn CoreAead>, HpkeError> {
        let algorithm = match aead {
            HpkeAead::Saturnin256 => Algorithm::Saturnin,
            HpkeAead::Shake256 => Algorithm::Shake256Aead,
            HpkeAead::DuplexSpongeAead => {
                #[cfg(feature = "duplex-sponge-aead")]
                {
                    Algorithm::DuplexSpongeAead
                }
                #[cfg(not(feature = "duplex-sponge-aead"))]
                {
                    return Err(HpkeError::feature_not_enabled(
                        "duplex-sponge-aead (enable lib-q-hpke feature duplex-sponge-aead)",
                    ));
                }
            }
            HpkeAead::Export => return Err(HpkeError::not_implemented("Export-only AEAD")),
        };

        // AeadWithMetadata extends Aead (CoreAead), so we can return it directly
        let aead_instance: Box<dyn CoreAead> = create_aead(algorithm).map_err(|e| {
            HpkeError::CryptoError(format!("Failed to create AEAD instance: {}", e))
        })?;

        Ok(aead_instance)
    }
}

impl KemProvider for PostQuantumProvider {
    fn generate_keypair(
        &self,
        kem: HpkeKem,
        _rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError> {
        let provider = Self::create_kem_provider()?;
        let algorithm = Self::hpke_kem_to_algorithm(kem)?;
        let keypair = provider
            .generate_keypair(algorithm, None)
            .map_err(|e| HpkeError::CryptoError(format!("KEM key generation failed: {}", e)))?;
        Ok((
            keypair.public_key().as_bytes().to_vec(),
            Zeroizing::new(keypair.secret_key().as_bytes().to_vec()),
        ))
    }

    fn encapsulate(
        &self,
        kem: HpkeKem,
        public_key: &[u8],
        _rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError> {
        let provider = Self::create_kem_provider()?;
        let algorithm = Self::hpke_kem_to_algorithm(kem)?;
        let pk = lib_q_core::KemPublicKey::new(public_key.to_vec());
        let (ct, ss) = provider
            .encapsulate(algorithm, &pk, None)
            .map_err(|e| HpkeError::CryptoError(format!("KEM encapsulation failed: {}", e)))?;
        Ok((ct, Zeroizing::new(ss)))
    }

    fn decapsulate(
        &self,
        kem: HpkeKem,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
        let provider = Self::create_kem_provider()?;
        let algorithm = Self::hpke_kem_to_algorithm(kem)?;
        let sk = lib_q_core::KemSecretKey::new(secret_key.to_vec());
        let ss = provider
            .decapsulate(algorithm, &sk, ciphertext)
            .map_err(|e| HpkeError::CryptoError(format!("KEM decapsulation failed: {}", e)))?;
        Ok(Zeroizing::new(ss))
    }

    fn validate_key(&self, kem: HpkeKem, key: &[u8], is_secret: bool) -> Result<(), HpkeError> {
        let expected_len = if is_secret {
            kem.secret_key_len()
        } else {
            kem.public_key_len()
        };

        if key.len() != expected_len {
            return Err(HpkeError::invalid_input(
                "key",
                format!("{} bytes", key.len()),
                format!("{} bytes", expected_len),
            ));
        }

        if key.iter().all(|&b| b == 0) {
            return Err(HpkeError::CryptoError(
                "Key material cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }

    fn derive_public_key(&self, kem: HpkeKem, secret_key: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let provider = Self::create_kem_provider()?;
        let algorithm = Self::hpke_kem_to_algorithm(kem)?;
        let secret_key_obj = lib_q_core::KemSecretKey::new(secret_key.to_vec());
        let public_key_obj = provider
            .derive_public_key(algorithm, &secret_key_obj)
            .map_err(|e| HpkeError::CryptoError(format!("Failed to derive public key: {}", e)))?;
        Ok(public_key_obj.as_bytes().to_vec())
    }

    fn supports_kem(&self, kem: HpkeKem) -> bool {
        match kem {
            HpkeKem::MlKem512 | HpkeKem::MlKem768 | HpkeKem::MlKem1024 => {
                #[cfg(feature = "ml-kem")]
                {
                    crate::kem::ml_kem::is_ml_kem_available()
                }
                #[cfg(not(feature = "ml-kem"))]
                {
                    false
                }
            }
        }
    }

    fn auth_encapsulate(
        &self,
        _kem: HpkeKem,
        _sender_sk: &[u8],
        _recipient_pk: &[u8],
        _rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError> {
        // SECURITY (B14 interim fix) — see `Self::auth_mode_unavailable` for the full rationale.
        // This used to perform a real (non-authenticated) KEM encapsulation and attach a tag
        // computed only from public values, which looks like it "succeeds" while providing no
        // sender authentication whatsoever. Fail closed instead: no ciphertext, no shared secret,
        // just an explicit error.
        Err(Self::auth_mode_unavailable())
    }

    fn auth_decapsulate(
        &self,
        _kem: HpkeKem,
        _encapsulated_key: &[u8],
        _recipient_sk: &[u8],
        _sender_pk: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
        // SECURITY (B14 interim fix) — see `Self::auth_mode_unavailable`. Reject unconditionally:
        // the old verification recomputed the same public-values-only tag it checked against, so
        // it "verified" forged sender identities as long as the caller could reach the recipient's
        // public key (i.e. always). Fail closed rather than accept, or partially validate, input
        // for a scheme that authenticates nothing.
        Err(Self::auth_mode_unavailable())
    }
}

impl PostQuantumProvider {
    /// HPKE Auth / AuthPSK mode is disabled pending a cryptographer-reviewed redesign (tracked as
    /// **B14**).
    ///
    /// [`Self::auth_encapsulate`] / [`Self::auth_decapsulate`] used to implement "authentication"
    /// as `SHA3-256(shared_secret || sender_pk || encapsulated_key)` (see the retired
    /// [`Self::create_auth_tag`] / [`Self::verify_auth_tag`] below) — a value computable by
    /// **anyone** who can encapsulate to the recipient's (public, by definition) public key. No
    /// sender secret key was ever an input. So any party could encapsulate to the recipient, learn
    /// the shared secret, and forge a tag under an arbitrary claimed sender identity; the two
    /// commitments that DID hash the sender's secret key
    /// ([`Self::create_sender_commitment`] / [`Self::create_sender_commitment_with_pk`], now
    /// removed) were computed and immediately discarded — never transmitted, so they could not
    /// have contributed to verification either.
    ///
    /// A correct fix requires `AuthEncap`/`AuthDecap` that bind the sender's static secret key per
    /// RFC 9180 Section 5.1.3, and needs cryptographer sign-off before it ships. Until then, Auth
    /// and AuthPSK modes (both route through these two functions — see `hpke_core::setup_sender_with_mode`
    /// / `setup_receiver_with_mode`) fail closed: every call returns this error rather than
    /// silently producing output that provides no real sender authentication. A mode that quietly
    /// authenticates nothing is worse than one that errors.
    fn auth_mode_unavailable() -> HpkeError {
        HpkeError::not_implemented(
            "HPKE Auth/AuthPSK mode (B14): sender authentication is not soundly bound to the \
             sender's static secret key (RFC 9180 Section 5.1.3 AuthEncap/AuthDecap gap); disabled \
             pending a cryptographer-reviewed redesign — use Base or PSK mode instead",
        )
    }

    /// Retired B14 authentication tag scheme: `SHA3-256(shared_secret || sender_pk ||
    /// encapsulated_key)`. No longer called from [`Self::auth_encapsulate`] /
    /// [`Self::auth_decapsulate`] (both fail closed via [`Self::auth_mode_unavailable`]) because it
    /// does not bind any sender secret key — see that function's doc for the full gap. Kept,
    /// `#[allow(dead_code)]`, only as a paired reference alongside [`Self::verify_auth_tag`] for a
    /// future correct redesign; not reachable from any production path.
    #[allow(dead_code)]
    fn create_auth_tag(
        &self,
        shared_secret: &[u8],
        sender_pk: &[u8],
        encapsulated_key: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(shared_secret);
        auth_input.extend_from_slice(sender_pk);
        auth_input.extend_from_slice(encapsulated_key);

        let auth_tag = lib_q_hash::Sha3_256::digest(&auth_input);

        Ok(auth_tag.to_vec())
    }

    /// Retired B14 verification counterpart to [`Self::create_auth_tag`] — see that function's doc
    /// and [`Self::auth_mode_unavailable`] for why this is no longer called from production code.
    /// Kept only as a reference; not reachable from any production path.
    ///
    /// The tag comparison now goes through
    /// [`crate::security::side_channel_protection::verify_auth_tag_constant_time`] instead of a
    /// variable-time `!=`, as defence in depth in case this is ever revived directly (the
    /// verified-refuted framing for the prior variable-time compare was a leaked tag for a shared
    /// secret the attacker cannot use, not a byte-at-a-time forgery oracle — this is hardening, not
    /// a re-escalation of that finding).
    #[allow(dead_code)]
    fn verify_auth_tag(
        &self,
        shared_secret: &[u8],
        sender_pk: &[u8],
        encapsulated_key: &[u8],
        auth_tag: &[u8],
    ) -> Result<(), HpkeError> {
        if auth_tag.is_empty() {
            return Err(HpkeError::CryptoError(
                "Invalid authentication tag: empty tag".into(),
            ));
        }

        if auth_tag.len() != 32 {
            return Err(HpkeError::CryptoError(
                "Invalid authentication tag: wrong length".into(),
            ));
        }

        let expected_auth_tag = self.create_auth_tag(shared_secret, sender_pk, encapsulated_key)?;

        crate::security::side_channel_protection::verify_auth_tag_constant_time(
            &expected_auth_tag,
            auth_tag,
        )
        .map_err(|_| {
            HpkeError::CryptoError("Authentication failed: invalid authentication tag".into())
        })
    }
}

impl KdfProvider for PostQuantumProvider {
    fn extract(&self, kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HpkeError> {
        // Use the existing HKDF implementation which is already algorithm-agnostic
        // The HKDF implementation uses lib-q-hash internally
        let hkdf_impl = HkdfImpl::new(kdf);
        hkdf_impl.extract(salt, ikm)
    }

    fn expand(
        &self,
        kdf: HpkeKdf,
        prk: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, HpkeError> {
        // Use the existing HKDF implementation which is already algorithm-agnostic
        // The HKDF implementation uses lib-q-hash internally
        let hkdf_impl = HkdfImpl::new(kdf);
        hkdf_impl.expand(prk, info, output_len)
    }

    fn supports_kdf(&self, kdf: HpkeKdf) -> bool {
        match kdf {
            HpkeKdf::HkdfShake128 |
            HpkeKdf::HkdfShake256 |
            HpkeKdf::HkdfSha3_256 |
            HpkeKdf::HkdfSha3_512 => {
                // Check if we can create a hash instance for this KDF
                Self::create_hash_instance(kdf).is_ok()
            }
        }
    }
}

impl AeadProvider for PostQuantumProvider {
    fn seal(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        // Validate inputs
        <Self as AeadProvider>::validate_key(self, aead, key)?;
        self.validate_nonce(aead, nonce)?;

        match aead {
            HpkeAead::Export => Err(HpkeError::aead_error(
                HpkeAead::Export,
                AeadOperation::Seal,
                "Export-only AEAD (RFC 9180): no payload encryption; use HPKE export()",
            )),
            _ => {
                // Use lib-q-aead abstraction for AEAD operations
                let aead_impl = Self::create_aead_instance(aead)?;

                // Create key and nonce objects
                let aead_key = AeadKey::new(key.to_vec());
                let aead_nonce = Nonce::new(nonce.to_vec());

                // Perform encryption using the AEAD abstraction
                aead_impl
                    .encrypt(&aead_key, &aead_nonce, plaintext, Some(aad))
                    .map_err(|e| HpkeError::CryptoError(format!("AEAD encryption failed: {}", e)))
            }
        }
    }

    fn open(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        // Validate inputs
        <Self as AeadProvider>::validate_key(self, aead, key)?;
        self.validate_nonce(aead, nonce)?;

        match aead {
            HpkeAead::Export => Err(HpkeError::aead_error(
                HpkeAead::Export,
                AeadOperation::Open,
                "Export-only AEAD (RFC 9180): no payload decryption; use HPKE export()",
            )),
            _ => {
                // Use lib-q-aead abstraction for AEAD operations
                let aead_impl = Self::create_aead_instance(aead)?;

                // Create key and nonce objects
                let aead_key = AeadKey::new(key.to_vec());
                let aead_nonce = Nonce::new(nonce.to_vec());

                // Perform decryption using the AEAD abstraction
                aead_impl
                    .decrypt(&aead_key, &aead_nonce, ciphertext, Some(aad))
                    .map_err(|e| HpkeError::CryptoError(format!("AEAD decryption failed: {}", e)))
            }
        }
    }

    fn validate_key(&self, aead: HpkeAead, key: &[u8]) -> Result<(), HpkeError> {
        let expected_len = aead.key_len();
        if key.len() != expected_len {
            return Err(HpkeError::invalid_input(
                "key",
                format!("{} bytes", key.len()),
                format!("{} bytes", expected_len),
            ));
        }

        // Security check: reject zero keys (skip for empty keys, e.g. Export AEAD)
        if !key.is_empty() && key.iter().all(|&b| b == 0) {
            return Err(HpkeError::CryptoError(
                "Key material cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_nonce(&self, aead: HpkeAead, nonce: &[u8]) -> Result<(), HpkeError> {
        let expected_len = aead.nonce_len();
        if nonce.len() != expected_len {
            return Err(HpkeError::invalid_input(
                "nonce",
                format!("{} bytes", nonce.len()),
                format!("{} bytes", expected_len),
            ));
        }
        Ok(())
    }

    fn supports_aead(&self, aead: HpkeAead) -> bool {
        match aead {
            HpkeAead::Export => true, // Export mode is always supported (it's export-only)
            _ => Self::create_aead_instance(aead).is_ok(),
        }
    }
}

impl HpkeCryptoProvider for PostQuantumProvider {
    fn name(&self) -> &'static str {
        "PostQuantumProvider"
    }

    fn supported_algorithms(&self) -> SupportedAlgorithms {
        let mut kems = Vec::new();
        let mut kdfs = Vec::new();
        let mut aeads = Vec::new();

        // Check KEM support
        for kem in [HpkeKem::MlKem512, HpkeKem::MlKem768, HpkeKem::MlKem1024] {
            if self.supports_kem(kem) {
                kems.push(kem);
            }
        }

        // Check KDF support
        for kdf in [
            HpkeKdf::HkdfShake128,
            HpkeKdf::HkdfShake256,
            HpkeKdf::HkdfSha3_256,
            HpkeKdf::HkdfSha3_512,
        ] {
            if self.supports_kdf(kdf) {
                kdfs.push(kdf);
            }
        }

        // Check AEAD support
        for aead in [
            HpkeAead::Saturnin256,
            HpkeAead::Shake256,
            HpkeAead::DuplexSpongeAead,
            HpkeAead::Export,
        ] {
            if self.supports_aead(aead) {
                aeads.push(aead);
            }
        }

        SupportedAlgorithms::new(kems, kdfs, aeads)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = PostQuantumProvider::new();
        assert_eq!(provider.name(), "PostQuantumProvider");
    }

    #[test]
    fn test_supported_algorithms() {
        let provider = PostQuantumProvider::new();
        let algorithms = provider.supported_algorithms();

        // Should have some supported algorithms
        assert!(
            !algorithms.kems.is_empty() ||
                !algorithms.kdfs.is_empty() ||
                !algorithms.aeads.is_empty()
        );
    }

    #[test]
    fn test_kem_support() {
        let provider = PostQuantumProvider::new();

        // Test ML-KEM support
        let ml_kem_512_supported = provider.supports_kem(HpkeKem::MlKem512);
        let ml_kem_768_supported = provider.supports_kem(HpkeKem::MlKem768);
        let ml_kem_1024_supported = provider.supports_kem(HpkeKem::MlKem1024);

        // All should have the same support status (based on ml-kem feature)
        assert_eq!(ml_kem_512_supported, ml_kem_768_supported);
        assert_eq!(ml_kem_768_supported, ml_kem_1024_supported);
    }

    #[test]
    fn test_kdf_support() {
        let provider = PostQuantumProvider::new();

        // Test KDF support
        let shake128_supported = provider.supports_kdf(HpkeKdf::HkdfShake128);
        let shake256_supported = provider.supports_kdf(HpkeKdf::HkdfShake256);
        let sha3_256_supported = provider.supports_kdf(HpkeKdf::HkdfSha3_256);
        let sha3_512_supported = provider.supports_kdf(HpkeKdf::HkdfSha3_512);

        // All should have the same support status (based on hash feature)
        assert_eq!(shake128_supported, shake256_supported);
        assert_eq!(shake256_supported, sha3_256_supported);
        assert_eq!(sha3_256_supported, sha3_512_supported);
    }

    #[test]
    fn test_aead_support() {
        let provider = PostQuantumProvider::new();

        // Test AEAD support
        let saturnin_supported = provider.supports_aead(HpkeAead::Saturnin256);
        let shake256_supported = provider.supports_aead(HpkeAead::Shake256);
        let duplex_supported = provider.supports_aead(HpkeAead::DuplexSpongeAead);
        let export_supported = provider.supports_aead(HpkeAead::Export);

        // Export should always be supported
        assert!(export_supported);

        // Others depend on features
        #[cfg(feature = "saturnin")]
        assert!(saturnin_supported);
        #[cfg(not(feature = "saturnin"))]
        assert!(!saturnin_supported);

        // SHAKE256 AEAD is now implemented in lib-q-aead
        // This test reflects the current reality - SHAKE256 AEAD is supported
        assert!(
            shake256_supported,
            "SHAKE256 AEAD should be supported after migration to lib-q-aead"
        );

        #[cfg(feature = "duplex-sponge-aead")]
        assert!(
            duplex_supported,
            "Duplex-sponge AEAD should be supported when feature is enabled"
        );
        #[cfg(not(feature = "duplex-sponge-aead"))]
        assert!(!duplex_supported);
    }
}
