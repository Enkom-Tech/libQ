//! `lib_q_core::Aead` implementation.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

#[cfg(feature = "alloc")]
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

use crate::crypto::{
    decrypt as tweak_decrypt,
    decrypt_semantic_outcome,
    encrypt as tweak_encrypt,
};
use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
};

/// Tweakable-block CTR AEAD (32-byte blocks, Keccak-f\[1600\] keystream, 32-byte tag).
pub struct TweakAead;

impl TweakAead {
    pub const fn new() -> Self {
        Self
    }

    pub const fn key_size() -> usize {
        KEY_BYTES
    }

    pub const fn nonce_size() -> usize {
        NONCE_BYTES
    }

    pub const fn tag_size() -> usize {
        TAG_BYTES
    }
}

impl Default for TweakAead {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl Aead for TweakAead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let kb = key.as_bytes();
        if kb.len() != KEY_BYTES {
            return Err(Error::InvalidKeySize {
                expected: KEY_BYTES,
                actual: kb.len(),
            });
        }
        let nb = nonce.as_bytes();
        if nb.len() != NONCE_BYTES {
            return Err(Error::InvalidNonceSize {
                expected: NONCE_BYTES,
                actual: nb.len(),
            });
        }
        let key_arr = {
            let mut k = Zeroizing::new([0u8; KEY_BYTES]);
            k.copy_from_slice(kb);
            k
        };
        let nonce_arr = {
            let mut n = Zeroizing::new([0u8; NONCE_BYTES]);
            n.copy_from_slice(nb);
            n
        };

        let ad = associated_data.unwrap_or(&[]);
        let mut out = alloc::vec![0u8; plaintext.len() + TAG_BYTES];
        tweak_encrypt(&key_arr, &nonce_arr, ad, plaintext, &mut out).map_err(|_| {
            Error::InvalidMessageSize {
                max: usize::MAX,
                actual: plaintext.len(),
            }
        })?;
        Ok(out)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let kb = key.as_bytes();
        if kb.len() != KEY_BYTES {
            return Err(Error::InvalidKeySize {
                expected: KEY_BYTES,
                actual: kb.len(),
            });
        }
        let nb = nonce.as_bytes();
        if nb.len() != NONCE_BYTES {
            return Err(Error::InvalidNonceSize {
                expected: NONCE_BYTES,
                actual: nb.len(),
            });
        }
        if ciphertext.len() < TAG_BYTES {
            return Err(Error::aead_ciphertext_shorter_than_tag(
                TAG_BYTES,
                ciphertext.len(),
            ));
        }
        let key_arr = {
            let mut k = Zeroizing::new([0u8; KEY_BYTES]);
            k.copy_from_slice(kb);
            k
        };
        let nonce_arr = {
            let mut n = Zeroizing::new([0u8; NONCE_BYTES]);
            n.copy_from_slice(nb);
            n
        };

        let ad = associated_data.unwrap_or(&[]);
        let body_len = ciphertext.len() - TAG_BYTES;
        let mut pt = alloc::vec![0u8; body_len];
        tweak_decrypt(&key_arr, &nonce_arr, ad, ciphertext, &mut pt).map_err(|_| {
            Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            }
        })?;
        Ok(pt)
    }
}

#[cfg(feature = "alloc")]
impl AeadDecryptSemantic for TweakAead {
    fn decrypt_semantic(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        let kb = key.as_bytes();
        if kb.len() != KEY_BYTES {
            return Err(Error::InvalidKeySize {
                expected: KEY_BYTES,
                actual: kb.len(),
            });
        }
        let nb = nonce.as_bytes();
        if nb.len() != NONCE_BYTES {
            return Err(Error::InvalidNonceSize {
                expected: NONCE_BYTES,
                actual: nb.len(),
            });
        }
        if ciphertext.len() < TAG_BYTES {
            return Err(Error::aead_ciphertext_shorter_than_tag(
                TAG_BYTES,
                ciphertext.len(),
            ));
        }
        let key_arr = {
            let mut k = Zeroizing::new([0u8; KEY_BYTES]);
            k.copy_from_slice(kb);
            k
        };
        let nonce_arr = {
            let mut n = Zeroizing::new([0u8; NONCE_BYTES]);
            n.copy_from_slice(nb);
            n
        };

        let ad = associated_data.unwrap_or(&[]);
        decrypt_semantic_outcome(&key_arr, &nonce_arr, ad, ciphertext).map_err(|_| {
            Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            }
        })
    }
}
