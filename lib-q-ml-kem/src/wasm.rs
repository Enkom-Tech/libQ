//! `JavaScript` / WASM bindings for ML-KEM (FIPS 203).
//!
//! ML-KEM parameter sets are selected with `variant`: **0** = ML-KEM-512, **1** = ML-KEM-768,
//! **2** = ML-KEM-1024.
//!
//! All exported functions return [`Result<_, JsError>`]: invalid inputs, RNG setup failures, and KEM
//! operation errors surface as `JavaScript` exceptions via `wasm-bindgen`, rather than aborting the
//! module with a Rust panic.
//!
//! # Secret material and memory hygiene
//!
//! Decapsulation keys and shared secrets are stored in [`zeroize::Zeroizing`] buffers so they are
//! cleared on drop when WASM objects are garbage-collected on the Rust side. Serialized key bytes
//! from [`EncodedSizeUser::as_bytes`](crate::EncodedSizeUser::as_bytes) use the same `Zeroizing`
//! pattern.
//!
//! Secret bytes are copied to `JavaScript` as [`js_sys::Uint8Array`] via `copy_from` (not as an owned
//! non-zeroizing [`alloc::vec::Vec`] return), which avoids an extra full-size plaintext `Vec` in
//! Rust linear memory for each getter or decapsulate call.
//!
//! **`JavaScript` callers** must still treat returned `Uint8Array` values as sensitive: Rust cannot
//! erase copies on the JS heap, in `ArrayBuffer` views, or in engine internals. After use, overwrite
//! buffers (for example `buf.fill(0)` on a mutable view, or discard references and avoid retaining
//! slices) following your application's key-handling policy.

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

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

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
    Seed,
};

/// Copy `secret` into a new `Uint8Array` for the JS boundary without returning an owned `Vec<u8>`.
fn secret_bytes_to_uint8_array(secret: &[u8]) -> Uint8Array {
    let n = u32::try_from(secret.len()).expect("secret length exceeds Uint8Array maximum");
    let out = Uint8Array::new_with_length(n);
    out.copy_from(secret);
    out
}

#[wasm_bindgen]
pub struct MlKemKeypair {
    secret_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl MlKemKeypair {
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Uint8Array {
        secret_bytes_to_uint8_array(self.secret_key.as_slice())
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// An ML-KEM key pair plus the 64-byte key-generation seed (`d ‖ z`) that produced it.
///
/// Persisting `seed` (64 bytes) instead of the larger `secret_key` is the recommended compact key
/// representation; pass it to [`ml_kem_keypair_from_seed`] to reconstruct the same pair.
#[wasm_bindgen]
pub struct MlKemKeypairWithSeed {
    secret_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
    seed: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl MlKemKeypairWithSeed {
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Uint8Array {
        secret_bytes_to_uint8_array(self.secret_key.as_slice())
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// The 64-byte key-generation seed (`d ‖ z`). Treat it as secret key material.
    #[wasm_bindgen(getter)]
    pub fn seed(&self) -> Uint8Array {
        secret_bytes_to_uint8_array(self.seed.as_slice())
    }
}

#[wasm_bindgen]
pub struct MlKemEncapsulationResult {
    ciphertext: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl MlKemEncapsulationResult {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Uint8Array {
        secret_bytes_to_uint8_array(self.shared_secret.as_slice())
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
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
                public_key: ek.as_bytes().as_slice().to_vec(),
            })
        }
        1 => {
            let (dk, ek) = MlKem768::generate(&mut rng);
            Ok(MlKemKeypair {
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
                public_key: ek.as_bytes().as_slice().to_vec(),
            })
        }
        2 => {
            let (dk, ek) = MlKem1024::generate(&mut rng);
            Ok(MlKemKeypair {
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
                public_key: ek.as_bytes().as_slice().to_vec(),
            })
        }
        _ => Err(variant_err()),
    }
}

/// Generate an ML-KEM keypair (`variant`: 0 / 1 / 2) and also return the 64-byte seed (`d ‖ z`).
///
/// Store the returned `seed` (64 bytes) as a compact alternative to the full secret key and
/// reconstruct the pair later with [`ml_kem_keypair_from_seed`].
#[wasm_bindgen]
pub fn ml_kem_generate_keypair_with_seed(variant: u8) -> Result<MlKemKeypairWithSeed, JsError> {
    let mut rng = lib_q_random::new_secure_rng().map_err(rng_err)?;
    match variant {
        0 => {
            let (seed, dk, ek) = MlKem512::generate_with_seed(&mut rng);
            Ok(MlKemKeypairWithSeed {
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
                public_key: ek.as_bytes().as_slice().to_vec(),
                seed: Zeroizing::new(seed.as_slice().to_vec()),
            })
        }
        1 => {
            let (seed, dk, ek) = MlKem768::generate_with_seed(&mut rng);
            Ok(MlKemKeypairWithSeed {
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
                public_key: ek.as_bytes().as_slice().to_vec(),
                seed: Zeroizing::new(seed.as_slice().to_vec()),
            })
        }
        2 => {
            let (seed, dk, ek) = MlKem1024::generate_with_seed(&mut rng);
            Ok(MlKemKeypairWithSeed {
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
                public_key: ek.as_bytes().as_slice().to_vec(),
                seed: Zeroizing::new(seed.as_slice().to_vec()),
            })
        }
        _ => Err(variant_err()),
    }
}

/// Reconstruct an ML-KEM keypair from a 64-byte seed (`d ‖ z`); `variant` selects the parameter set.
///
/// The reconstructed pair is byte-identical to the one originally produced from the seed.
#[wasm_bindgen]
pub fn ml_kem_keypair_from_seed(variant: u8, seed: &[u8]) -> Result<MlKemKeypair, JsError> {
    let seed = Seed::try_from(seed)
        .map_err(|_| JsError::new("invalid ML-KEM seed length: expected 64 bytes"))?;
    match variant {
        0 => {
            let (dk, ek) = MlKem512::generate_from_seed(&seed);
            Ok(MlKemKeypair {
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
                public_key: ek.as_bytes().as_slice().to_vec(),
            })
        }
        1 => {
            let (dk, ek) = MlKem768::generate_from_seed(&seed);
            Ok(MlKemKeypair {
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
                public_key: ek.as_bytes().as_slice().to_vec(),
            })
        }
        2 => {
            let (dk, ek) = MlKem1024::generate_from_seed(&seed);
            Ok(MlKemKeypair {
                secret_key: Zeroizing::new(dk.as_bytes().as_slice().to_vec()),
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
            let ek = EncapsulationKey::<MlKem512Params>::try_from_bytes(&ek_enc)
                .map_err(|_| JsError::new("invalid ML-KEM-512 public key"))?;
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|e| kem_err("ML-KEM encapsulate", e))?;
            Ok(MlKemEncapsulationResult {
                ciphertext: ct.as_slice().to_vec(),
                shared_secret: Zeroizing::new(ss.as_slice().to_vec()),
            })
        }
        1 => {
            let ek_enc = Encoded::<EncapsulationKey<MlKem768Params>>::try_from(public_key)
                .map_err(|_| JsError::new("invalid ML-KEM-768 public key length"))?;
            let ek = EncapsulationKey::<MlKem768Params>::try_from_bytes(&ek_enc)
                .map_err(|_| JsError::new("invalid ML-KEM-768 public key"))?;
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|e| kem_err("ML-KEM encapsulate", e))?;
            Ok(MlKemEncapsulationResult {
                ciphertext: ct.as_slice().to_vec(),
                shared_secret: Zeroizing::new(ss.as_slice().to_vec()),
            })
        }
        2 => {
            let ek_enc = Encoded::<EncapsulationKey<MlKem1024Params>>::try_from(public_key)
                .map_err(|_| JsError::new("invalid ML-KEM-1024 public key length"))?;
            let ek = EncapsulationKey::<MlKem1024Params>::try_from_bytes(&ek_enc)
                .map_err(|_| JsError::new("invalid ML-KEM-1024 public key"))?;
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|e| kem_err("ML-KEM encapsulate", e))?;
            Ok(MlKemEncapsulationResult {
                ciphertext: ct.as_slice().to_vec(),
                shared_secret: Zeroizing::new(ss.as_slice().to_vec()),
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
) -> Result<Uint8Array, JsError> {
    match variant {
        0 => {
            let dk_enc = Encoded::<DecapsulationKey<MlKem512Params>>::try_from(secret_key)
                .map_err(|_| JsError::new("invalid ML-KEM-512 secret key length"))?;
            let dk = DecapsulationKey::<MlKem512Params>::try_from_bytes(&dk_enc)
                .map_err(|_| JsError::new("invalid ML-KEM-512 secret key"))?;
            let ct_enc = Ciphertext::<MlKem512>::try_from(ciphertext)
                .map_err(|_| JsError::new("invalid ML-KEM-512 ciphertext length"))?;
            let ss = dk
                .decapsulate(&ct_enc)
                .map_err(|e| kem_err("ML-KEM decapsulate", e))?;
            let bytes = Zeroizing::new(ss.as_slice().to_vec());
            Ok(secret_bytes_to_uint8_array(bytes.as_slice()))
        }
        1 => {
            let dk_enc = Encoded::<DecapsulationKey<MlKem768Params>>::try_from(secret_key)
                .map_err(|_| JsError::new("invalid ML-KEM-768 secret key length"))?;
            let dk = DecapsulationKey::<MlKem768Params>::try_from_bytes(&dk_enc)
                .map_err(|_| JsError::new("invalid ML-KEM-768 secret key"))?;
            let ct_enc = Ciphertext::<MlKem768>::try_from(ciphertext)
                .map_err(|_| JsError::new("invalid ML-KEM-768 ciphertext length"))?;
            let ss = dk
                .decapsulate(&ct_enc)
                .map_err(|e| kem_err("ML-KEM decapsulate", e))?;
            let bytes = Zeroizing::new(ss.as_slice().to_vec());
            Ok(secret_bytes_to_uint8_array(bytes.as_slice()))
        }
        2 => {
            let dk_enc = Encoded::<DecapsulationKey<MlKem1024Params>>::try_from(secret_key)
                .map_err(|_| JsError::new("invalid ML-KEM-1024 secret key length"))?;
            let dk = DecapsulationKey::<MlKem1024Params>::try_from_bytes(&dk_enc)
                .map_err(|_| JsError::new("invalid ML-KEM-1024 secret key"))?;
            let ct_enc = Ciphertext::<MlKem1024>::try_from(ciphertext)
                .map_err(|_| JsError::new("invalid ML-KEM-1024 ciphertext length"))?;
            let ss = dk
                .decapsulate(&ct_enc)
                .map_err(|e| kem_err("ML-KEM decapsulate", e))?;
            let bytes = Zeroizing::new(ss.as_slice().to_vec());
            Ok(secret_bytes_to_uint8_array(bytes.as_slice()))
        }
        _ => Err(variant_err()),
    }
}
