//! JavaScript/WASM bindings for ML-KEM (FIPS 203).
//!
//! ML-KEM parameter sets are selected with `variant`: **0** = ML-KEM-512, **1** = ML-KEM-768,
//! **2** = ML-KEM-1024.
//!
//! All exported functions return [`Result<_, JsError>`]: invalid inputs, RNG setup failures, and KEM
//! operation errors surface as JavaScript exceptions via `wasm-bindgen`, rather than aborting the
//! module with a Rust panic.

#![allow(missing_docs)]
#![allow(
    clippy::wildcard_imports,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use wasm_bindgen::prelude::*;

use crate::kem::{
    DecapsulationKey,
    EncapsulationKey,
};
use crate::{
    Ciphertext,
    Decapsulate,
    Encapsulate,
    Encoded,
    EncodedSizeUser,
    KemCore,
    MlKem512,
    MlKem512Params,
    MlKem768,
    MlKem768Params,
    MlKem1024,
    MlKem1024Params,
};

#[wasm_bindgen]
pub struct MlKemKeypair {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl MlKemKeypair {
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[wasm_bindgen]
pub struct MlKemEncapsulationResult {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl MlKemEncapsulationResult {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

fn variant_err() -> JsError {
    JsError::new("invalid ML-KEM variant: use 0=MlKem512, 1=MlKem768, 2=MlKem1024")
}

fn rng_err(e: lib_q_random::Error) -> JsError {
    JsError::new(&e.to_string())
}

/// Maps a KEM encapsulate/decapsulate failure into [`JsError`] for the JS boundary.
fn kem_err(op: &'static str, e: impl core::fmt::Debug) -> JsError {
    JsError::new(&alloc::format!("{op} failed: {e:?}"))
}

/// Generate an ML-KEM keypair (`variant`: 0 / 1 / 2).
#[wasm_bindgen]
pub fn ml_kem_generate_keypair(variant: u8) -> Result<MlKemKeypair, JsError> {
    let mut rng = lib_q_random::new_secure_rng().map_err(rng_err)?;
    match variant {
        0 => {
            let (dk, ek) = MlKem512::generate(&mut rng);
            Ok(MlKemKeypair {
                secret_key: dk.as_bytes().as_slice().to_vec(),
                public_key: ek.as_bytes().as_slice().to_vec(),
            })
        }
        1 => {
            let (dk, ek) = MlKem768::generate(&mut rng);
            Ok(MlKemKeypair {
                secret_key: dk.as_bytes().as_slice().to_vec(),
                public_key: ek.as_bytes().as_slice().to_vec(),
            })
        }
        2 => {
            let (dk, ek) = MlKem1024::generate(&mut rng);
            Ok(MlKemKeypair {
                secret_key: dk.as_bytes().as_slice().to_vec(),
                public_key: ek.as_bytes().as_slice().to_vec(),
            })
        }
        _ => Err(variant_err()),
    }
}

/// Encapsulate to `public_key` (`variant` must match the key's parameter set).
#[wasm_bindgen]
pub fn ml_kem_encapsulate(
    variant: u8,
    public_key: &[u8],
) -> Result<MlKemEncapsulationResult, JsError> {
    let mut rng = lib_q_random::new_secure_rng().map_err(rng_err)?;
    match variant {
        0 => {
            let ek_enc = Encoded::<EncapsulationKey<MlKem512Params>>::try_from(public_key)
                .map_err(|_| JsError::new("invalid ML-KEM-512 public key length"))?;
            let ek = EncapsulationKey::<MlKem512Params>::from_bytes(&ek_enc);
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|e| kem_err("ML-KEM encapsulate", e))?;
            Ok(MlKemEncapsulationResult {
                ciphertext: ct.as_slice().to_vec(),
                shared_secret: ss.as_slice().to_vec(),
            })
        }
        1 => {
            let ek_enc = Encoded::<EncapsulationKey<MlKem768Params>>::try_from(public_key)
                .map_err(|_| JsError::new("invalid ML-KEM-768 public key length"))?;
            let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_enc);
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|e| kem_err("ML-KEM encapsulate", e))?;
            Ok(MlKemEncapsulationResult {
                ciphertext: ct.as_slice().to_vec(),
                shared_secret: ss.as_slice().to_vec(),
            })
        }
        2 => {
            let ek_enc = Encoded::<EncapsulationKey<MlKem1024Params>>::try_from(public_key)
                .map_err(|_| JsError::new("invalid ML-KEM-1024 public key length"))?;
            let ek = EncapsulationKey::<MlKem1024Params>::from_bytes(&ek_enc);
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|e| kem_err("ML-KEM encapsulate", e))?;
            Ok(MlKemEncapsulationResult {
                ciphertext: ct.as_slice().to_vec(),
                shared_secret: ss.as_slice().to_vec(),
            })
        }
        _ => Err(variant_err()),
    }
}

/// Decapsulate `ciphertext` with `secret_key` (`variant` must match both keys' parameter set).
#[wasm_bindgen]
pub fn ml_kem_decapsulate(
    variant: u8,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsError> {
    match variant {
        0 => {
            let dk_enc = Encoded::<DecapsulationKey<MlKem512Params>>::try_from(secret_key)
                .map_err(|_| JsError::new("invalid ML-KEM-512 secret key length"))?;
            let dk = DecapsulationKey::<MlKem512Params>::from_bytes(&dk_enc);
            let ct_enc = Ciphertext::<MlKem512>::try_from(ciphertext)
                .map_err(|_| JsError::new("invalid ML-KEM-512 ciphertext length"))?;
            let ss = dk
                .decapsulate(&ct_enc)
                .map_err(|e| kem_err("ML-KEM decapsulate", e))?;
            Ok(ss.as_slice().to_vec())
        }
        1 => {
            let dk_enc = Encoded::<DecapsulationKey<MlKem768Params>>::try_from(secret_key)
                .map_err(|_| JsError::new("invalid ML-KEM-768 secret key length"))?;
            let dk = DecapsulationKey::<MlKem768Params>::from_bytes(&dk_enc);
            let ct_enc = Ciphertext::<MlKem768>::try_from(ciphertext)
                .map_err(|_| JsError::new("invalid ML-KEM-768 ciphertext length"))?;
            let ss = dk
                .decapsulate(&ct_enc)
                .map_err(|e| kem_err("ML-KEM decapsulate", e))?;
            Ok(ss.as_slice().to_vec())
        }
        2 => {
            let dk_enc = Encoded::<DecapsulationKey<MlKem1024Params>>::try_from(secret_key)
                .map_err(|_| JsError::new("invalid ML-KEM-1024 secret key length"))?;
            let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&dk_enc);
            let ct_enc = Ciphertext::<MlKem1024>::try_from(ciphertext)
                .map_err(|_| JsError::new("invalid ML-KEM-1024 ciphertext length"))?;
            let ss = dk
                .decapsulate(&ct_enc)
                .map_err(|e| kem_err("ML-KEM decapsulate", e))?;
            Ok(ss.as_slice().to_vec())
        }
        _ => Err(variant_err()),
    }
}
