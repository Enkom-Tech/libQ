//! `lib_q_core::Aead` wrappers (allocating API) for registry integration.

#![deny(unsafe_code)]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use aead::consts::U16;
use aead::generic_array::GenericArray;
use aead::{
    AeadInPlace,
    KeyInit,
};
use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
    Result,
};

use crate::{
    RomulusM,
    RomulusN,
};

/// Stateless Romulus-N facade using [`lib_q_core::Aead`].
pub struct RomulusNAead;

impl RomulusNAead {
    pub const fn new() -> Self {
        Self
    }

    pub const fn key_size() -> usize {
        16
    }

    pub const fn nonce_size() -> usize {
        16
    }

    pub const fn tag_size() -> usize {
        16
    }
}

impl Default for RomulusNAead {
    fn default() -> Self {
        Self::new()
    }
}

impl Aead for RomulusNAead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let kb = key.as_bytes();
        if kb.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: kb.len(),
            });
        }
        let nb = nonce.as_bytes();
        if nb.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nb.len(),
            });
        }
        let ad = associated_data.unwrap_or(&[]);
        let key_arr: GenericArray<u8, U16> = *GenericArray::from_slice(kb);
        let nonce_arr: GenericArray<u8, U16> = *GenericArray::from_slice(nb);
        let cipher = RomulusN::new(&key_arr);
        let mut buf = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce_arr, ad, &mut buf)
            .map_err(|_| Error::EncryptionFailed {
                operation: "Romulus-N encrypt".to_string(),
            })?;
        buf.extend_from_slice(tag.as_slice());
        Ok(buf)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let kb = key.as_bytes();
        if kb.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: kb.len(),
            });
        }
        let nb = nonce.as_bytes();
        if nb.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nb.len(),
            });
        }
        if ciphertext.len() < Self::tag_size() {
            return Err(Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            });
        }
        let ad = associated_data.unwrap_or(&[]);
        let body_len = ciphertext.len() - Self::tag_size();
        let key_arr: GenericArray<u8, U16> = *GenericArray::from_slice(kb);
        let nonce_arr: GenericArray<u8, U16> = *GenericArray::from_slice(nb);
        let cipher = RomulusN::new(&key_arr);
        let tag = GenericArray::clone_from_slice(&ciphertext[body_len..]);
        let mut buf = ciphertext[..body_len].to_vec();
        cipher
            .decrypt_in_place_detached(&nonce_arr, ad, &mut buf, &tag)
            .map_err(|_| Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            })?;
        Ok(buf)
    }
}

/// Stateless Romulus-M facade using [`lib_q_core::Aead`].
pub struct RomulusMAead;

impl RomulusMAead {
    pub const fn new() -> Self {
        Self
    }

    pub const fn key_size() -> usize {
        16
    }

    pub const fn nonce_size() -> usize {
        16
    }

    pub const fn tag_size() -> usize {
        16
    }
}

impl Default for RomulusMAead {
    fn default() -> Self {
        Self::new()
    }
}

impl Aead for RomulusMAead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let kb = key.as_bytes();
        if kb.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: kb.len(),
            });
        }
        let nb = nonce.as_bytes();
        if nb.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nb.len(),
            });
        }
        let ad = associated_data.unwrap_or(&[]);
        let key_arr: GenericArray<u8, U16> = *GenericArray::from_slice(kb);
        let nonce_arr: GenericArray<u8, U16> = *GenericArray::from_slice(nb);
        let cipher = RomulusM::new(&key_arr);
        let mut buf = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce_arr, ad, &mut buf)
            .map_err(|_| Error::EncryptionFailed {
                operation: "Romulus-M encrypt".to_string(),
            })?;
        buf.extend_from_slice(tag.as_slice());
        Ok(buf)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let kb = key.as_bytes();
        if kb.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: kb.len(),
            });
        }
        let nb = nonce.as_bytes();
        if nb.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nb.len(),
            });
        }
        if ciphertext.len() < Self::tag_size() {
            return Err(Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            });
        }
        let ad = associated_data.unwrap_or(&[]);
        let body_len = ciphertext.len() - Self::tag_size();
        let key_arr: GenericArray<u8, U16> = *GenericArray::from_slice(kb);
        let nonce_arr: GenericArray<u8, U16> = *GenericArray::from_slice(nb);
        let cipher = RomulusM::new(&key_arr);
        let tag = GenericArray::clone_from_slice(&ciphertext[body_len..]);
        let mut buf = ciphertext[..body_len].to_vec();
        cipher
            .decrypt_in_place_detached(&nonce_arr, ad, &mut buf, &tag)
            .map_err(|_| Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            })?;
        Ok(buf)
    }
}
