//! HKDF implementation using lib-q-hash

#[cfg(all(feature = "alloc", feature = "hash"))]
use alloc::format;
#[cfg(all(feature = "alloc", feature = "hash"))]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "hash")]
use lib_q_hash::{
    Sha3_256,
    Sha3_512,
    Shake128,
    Shake256,
    digest::{
        Digest,
        ExtendableOutput,
        Update,
        XofReader,
    },
};

use crate::error::HpkeError;
use crate::kdf::traits::Kdf;
use crate::types::*;

/// HKDF implementation using lib-q-hash
pub struct HkdfImpl {
    /// Selected KDF variant; only read when the `hash` feature is enabled.
    #[cfg_attr(not(feature = "hash"), allow(dead_code))]
    kdf: HpkeKdf,
}

impl HkdfImpl {
    /// Create a new HKDF implementation
    pub fn new(kdf: HpkeKdf) -> Self {
        Self { kdf }
    }

    /// Static HKDF-Extract function
    pub fn extract_static(kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HpkeError> {
        #[cfg(not(feature = "hash"))]
        {
            let _ = (kdf, salt, ikm);
            Err(HpkeError::feature_not_enabled("Hash support"))
        }

        #[cfg(feature = "hash")]
        {
            let output_len = kdf.extract_len();
            let mut prk = vec![0u8; output_len];

            match kdf {
                HpkeKdf::HkdfShake128 => {
                    let mut hasher = Shake128::default();
                    hasher.update(salt);
                    hasher.update(ikm);
                    let mut reader = hasher.finalize_xof();
                    reader.read(&mut prk);
                }
                HpkeKdf::HkdfShake256 => {
                    let mut hasher = Shake256::default();
                    hasher.update(salt);
                    hasher.update(ikm);
                    let mut reader = hasher.finalize_xof();
                    reader.read(&mut prk);
                }
                HpkeKdf::HkdfSha3_256 => {
                    let mut hasher = Sha3_256::new();
                    Update::update(&mut hasher, salt);
                    Update::update(&mut hasher, ikm);
                    let result = hasher.finalize();
                    prk.copy_from_slice(&result);
                }
                HpkeKdf::HkdfSha3_512 => {
                    let mut hasher = Sha3_512::new();
                    Update::update(&mut hasher, salt);
                    Update::update(&mut hasher, ikm);
                    let result = hasher.finalize();
                    prk.copy_from_slice(&result);
                }
            }

            Ok(prk)
        }
    }

    /// Static HKDF-Expand function
    pub fn expand_static(
        kdf: HpkeKdf,
        prk: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, HpkeError> {
        #[cfg(not(feature = "hash"))]
        {
            let _ = (kdf, prk, info, output_len);
            Err(HpkeError::feature_not_enabled("Hash support"))
        }

        #[cfg(feature = "hash")]
        {
            // RFC 5869 / RFC 9180 §5.3: the expanded length L MUST be at most 255*Nh.
            let max_l = kdf.extract_len().checked_mul(255).ok_or_else(|| {
                HpkeError::CryptoError("HKDF-Expand length bound (255*Nh) overflowed".into())
            })?;
            if output_len > max_l {
                return Err(HpkeError::CryptoError(format!(
                    "HKDF-Expand length {output_len} exceeds RFC maximum 255*Nh ({max_l})"
                )));
            }

            let mut output = vec![0u8; output_len];

            match kdf {
                HpkeKdf::HkdfShake128 => {
                    let mut hasher = Shake128::default();
                    hasher.update(prk);
                    hasher.update(info);
                    let mut reader = hasher.finalize_xof();
                    reader.read(&mut output);
                }
                HpkeKdf::HkdfShake256 => {
                    let mut hasher = Shake256::default();
                    hasher.update(prk);
                    hasher.update(info);
                    let mut reader = hasher.finalize_xof();
                    reader.read(&mut output);
                }
                HpkeKdf::HkdfSha3_256 => {
                    let mut hasher = Sha3_256::new();
                    Update::update(&mut hasher, prk);
                    Update::update(&mut hasher, info);
                    let result = hasher.finalize();
                    let copy_len = output_len.min(result.len());
                    output[..copy_len].copy_from_slice(&result[..copy_len]);
                }
                HpkeKdf::HkdfSha3_512 => {
                    let mut hasher = Sha3_512::new();
                    Update::update(&mut hasher, prk);
                    Update::update(&mut hasher, info);
                    let result = hasher.finalize();
                    let copy_len = output_len.min(result.len());
                    output[..copy_len].copy_from_slice(&result[..copy_len]);
                }
            }

            Ok(output)
        }
    }

    /// Extract a pseudorandom key from input key material
    pub fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HpkeError> {
        #[cfg(feature = "hash")]
        {
            let output_len = self.kdf.extract_len();
            let mut prk = vec![0u8; output_len];

            match self.kdf {
                HpkeKdf::HkdfShake128 => {
                    let mut hasher = Shake128::default();
                    hasher.update(salt);
                    hasher.update(ikm);
                    let mut reader = hasher.finalize_xof();
                    reader.read(&mut prk);
                }
                HpkeKdf::HkdfShake256 => {
                    let mut hasher = Shake256::default();
                    hasher.update(salt);
                    hasher.update(ikm);
                    let mut reader = hasher.finalize_xof();
                    reader.read(&mut prk);
                }
                HpkeKdf::HkdfSha3_256 => {
                    let mut hasher = Sha3_256::new();
                    Update::update(&mut hasher, salt);
                    Update::update(&mut hasher, ikm);
                    let hash = hasher.finalize();
                    prk.copy_from_slice(&hash[..output_len]);
                }
                HpkeKdf::HkdfSha3_512 => {
                    let mut hasher = Sha3_512::new();
                    Update::update(&mut hasher, salt);
                    Update::update(&mut hasher, ikm);
                    let hash = hasher.finalize();
                    prk.copy_from_slice(&hash[..output_len]);
                }
            }

            Ok(prk)
        }

        #[cfg(not(feature = "hash"))]
        {
            let _ = (salt, ikm);
            Err(HpkeError::feature_not_enabled("Hash feature not enabled"))
        }
    }

    /// Expand a pseudorandom key to the desired length
    pub fn expand(&self, prk: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, HpkeError> {
        #[cfg(feature = "hash")]
        {
            if output_len == 0 {
                return Ok(Vec::new());
            }

            // RFC 5869 / RFC 9180 §5.3: the expanded length L MUST be at most 255*Nh.
            let max_l = self.kdf.extract_len().checked_mul(255).ok_or_else(|| {
                HpkeError::CryptoError("HKDF-Expand length bound (255*Nh) overflowed".into())
            })?;
            if output_len > max_l {
                return Err(HpkeError::CryptoError(format!(
                    "HKDF-Expand length {output_len} exceeds RFC maximum 255*Nh ({max_l})"
                )));
            }

            let mut output = vec![0u8; output_len];

            match self.kdf {
                HpkeKdf::HkdfShake128 => {
                    let mut hasher = Shake128::default();
                    Update::update(&mut hasher, prk);
                    Update::update(&mut hasher, info);
                    Update::update(&mut hasher, &output_len.to_le_bytes());
                    let mut reader = hasher.finalize_xof();
                    reader.read(&mut output);
                }
                HpkeKdf::HkdfShake256 => {
                    let mut hasher = Shake256::default();
                    Update::update(&mut hasher, prk);
                    Update::update(&mut hasher, info);
                    Update::update(&mut hasher, &output_len.to_le_bytes());
                    let mut reader = hasher.finalize_xof();
                    reader.read(&mut output);
                }
                HpkeKdf::HkdfSha3_256 => {
                    let mut hasher = Sha3_256::new();
                    Update::update(&mut hasher, prk);
                    Update::update(&mut hasher, info);
                    Update::update(&mut hasher, &output_len.to_le_bytes());
                    let hash = hasher.finalize();
                    let copy_len = output_len.min(hash.len());
                    output[..copy_len].copy_from_slice(&hash[..copy_len]);

                    // If we need more bytes, continue with additional rounds
                    if output_len > hash.len() {
                        let mut round = 1u32;
                        let mut offset = hash.len();
                        while offset < output_len {
                            let mut round_hasher = Sha3_256::new();
                            Update::update(&mut round_hasher, &hash);
                            Update::update(&mut round_hasher, &round.to_le_bytes());
                            let round_hash = round_hasher.finalize();

                            let copy_len = (output_len - offset).min(round_hash.len());
                            output[offset..offset + copy_len]
                                .copy_from_slice(&round_hash[..copy_len]);
                            offset += copy_len;
                            round += 1;
                        }
                    }
                }
                HpkeKdf::HkdfSha3_512 => {
                    let mut hasher = Sha3_512::new();
                    Update::update(&mut hasher, prk);
                    Update::update(&mut hasher, info);
                    Update::update(&mut hasher, &output_len.to_le_bytes());
                    let hash = hasher.finalize();
                    let copy_len = output_len.min(hash.len());
                    output[..copy_len].copy_from_slice(&hash[..copy_len]);

                    // If we need more bytes, continue with additional rounds
                    if output_len > hash.len() {
                        let mut round = 1u32;
                        let mut offset = hash.len();
                        while offset < output_len {
                            let mut round_hasher = Sha3_512::new();
                            Update::update(&mut round_hasher, &hash);
                            Update::update(&mut round_hasher, &round.to_le_bytes());
                            let round_hash = round_hasher.finalize();

                            let copy_len = (output_len - offset).min(round_hash.len());
                            output[offset..offset + copy_len]
                                .copy_from_slice(&round_hash[..copy_len]);
                            offset += copy_len;
                            round += 1;
                        }
                    }
                }
            }

            Ok(output)
        }

        #[cfg(not(feature = "hash"))]
        {
            let _ = (prk, info, output_len);
            Err(HpkeError::feature_not_enabled("Hash feature not enabled"))
        }
    }
}

/// Create an HKDF implementation for the given KDF
pub fn create_hkdf(kdf: HpkeKdf) -> HkdfImpl {
    HkdfImpl::new(kdf)
}

/// Check if HKDF is available
pub fn is_hkdf_available() -> bool {
    #[cfg(feature = "hash")]
    {
        true
    }
    #[cfg(not(feature = "hash"))]
    {
        false
    }
}

impl Kdf for HkdfImpl {
    fn extract(&self, kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HpkeError> {
        Self::extract_static(kdf, salt, ikm)
    }

    fn expand(
        &self,
        kdf: HpkeKdf,
        prk: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, HpkeError> {
        Self::expand_static(kdf, prk, info, length)
    }

    fn extract_len(&self, kdf: HpkeKdf) -> usize {
        kdf.extract_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_availability() {
        let available = is_hkdf_available();
        #[cfg(feature = "hash")]
        assert!(available);
        #[cfg(not(feature = "hash"))]
        assert!(!available);
    }

    #[test]
    fn test_hkdf_creation() {
        let _hkdf = create_hkdf(HpkeKdf::HkdfShake256);
        // Always succeeds since it's just a struct
        // This assertion is intentionally left as a placeholder
        // The test always passes since it's just creating a struct
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_hkdf_operations() {
        let _hkdf = create_hkdf(HpkeKdf::HkdfShake256);

        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";

        // Extract
        let prk = _hkdf.extract(salt, ikm).unwrap();
        assert_eq!(prk.len(), 32); // SHAKE256 extract length

        // Expand
        let output = _hkdf.expand(&prk, info, 64).unwrap();
        assert_eq!(output.len(), 64);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_hkdf_determinism() {
        let _hkdf = create_hkdf(HpkeKdf::HkdfShake256);

        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";

        // Extract twice
        let prk1 = _hkdf.extract(salt, ikm).unwrap();
        let prk2 = _hkdf.extract(salt, ikm).unwrap();
        assert_eq!(prk1, prk2);

        // Expand twice
        let output1 = _hkdf.expand(&prk1, info, 32).unwrap();
        let output2 = _hkdf.expand(&prk2, info, 32).unwrap();
        assert_eq!(output1, output2);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_hkdf_different_inputs() {
        let _hkdf = create_hkdf(HpkeKdf::HkdfShake256);

        let salt = b"salt";
        let ikm1 = b"input key material 1";
        let ikm2 = b"input key material 2";

        let prk1 = _hkdf.extract(salt, ikm1).unwrap();
        let prk2 = _hkdf.extract(salt, ikm2).unwrap();
        assert_ne!(prk1, prk2);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_hkdf_empty_info() {
        let _hkdf = create_hkdf(HpkeKdf::HkdfShake256);

        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"";

        let prk = _hkdf.extract(salt, ikm).unwrap();
        let output = _hkdf.expand(&prk, info, 32).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_hkdf_zero_length_output() {
        let _hkdf = create_hkdf(HpkeKdf::HkdfShake256);

        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";

        let prk = _hkdf.extract(salt, ikm).unwrap();
        let output = _hkdf.expand(&prk, info, 0).unwrap();
        assert_eq!(output.len(), 0);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_hkdf_large_output() {
        let _hkdf = create_hkdf(HpkeKdf::HkdfShake256);

        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";

        let prk = _hkdf.extract(salt, ikm).unwrap();
        let output = _hkdf.expand(&prk, info, 1024).unwrap();
        assert_eq!(output.len(), 1024);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_static_extract_expand_for_all_kdfs() {
        let salt = b"salt";
        let ikm = b"ikm";
        let info = b"info";

        for kdf in [
            HpkeKdf::HkdfShake128,
            HpkeKdf::HkdfShake256,
            HpkeKdf::HkdfSha3_256,
            HpkeKdf::HkdfSha3_512,
        ] {
            let prk = HkdfImpl::extract_static(kdf, salt, ikm).unwrap();
            assert_eq!(prk.len(), kdf.extract_len());

            let out = HkdfImpl::expand_static(kdf, &prk, info, 48).unwrap();
            assert_eq!(out.len(), 48);
            assert!(out.iter().any(|b| *b != 0));
        }
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_sha3_expand_rounds_beyond_digest_length() {
        let hkdf_256 = create_hkdf(HpkeKdf::HkdfSha3_256);
        let hkdf_512 = create_hkdf(HpkeKdf::HkdfSha3_512);
        let salt = b"salt";
        let ikm = b"material";
        let info = b"rounds";

        let prk256 = hkdf_256.extract(salt, ikm).unwrap();
        let out256 = hkdf_256.expand(&prk256, info, 96).unwrap();
        assert_eq!(out256.len(), 96);

        let prk512 = hkdf_512.extract(salt, ikm).unwrap();
        let out512 = hkdf_512.expand(&prk512, info, 160).unwrap();
        assert_eq!(out512.len(), 160);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_kdf_trait_methods_delegate_correctly() {
        let hkdf = create_hkdf(HpkeKdf::HkdfShake128);
        let kdf_trait: &dyn Kdf = &hkdf;
        let salt = b"s";
        let ikm = b"i";
        let info = b"x";

        let prk = kdf_trait.extract(HpkeKdf::HkdfShake128, salt, ikm).unwrap();
        assert_eq!(prk.len(), 16);

        let out = kdf_trait
            .expand(HpkeKdf::HkdfShake128, &prk, info, 24)
            .unwrap();
        assert_eq!(out.len(), 24);
        assert_eq!(kdf_trait.extract_len(HpkeKdf::HkdfShake128), 16);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_expand_static_zero_length_output() {
        let out = HkdfImpl::expand_static(HpkeKdf::HkdfSha3_256, &[1u8; 32], b"i", 0).unwrap();
        assert!(out.is_empty());
    }
}
