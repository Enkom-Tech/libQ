//! WASM bindings for ML-DSA-65 (FIPS 204) — the Grid PQ suite's standard signature scheme
//! (ML-KEM-768 + ML-DSA-65 + Saturnin).
//!
//! Exposes `generate_key_pair` / `sign` / `verify`, mirroring the native
//! [`crate::ml_dsa_65`] API one-for-one: `generate_key_pair` and `sign` draw their FIPS 204
//! randomness from the platform's secure RNG ([`lib_q_random::new_secure_rng`]), never a fixed
//! seed. All exported functions return `Result<_, JsError>`: invalid input lengths, RNG setup
//! failures, and signing/verification errors surface as `JavaScript` exceptions rather than
//! aborting the module with a Rust panic.
//!
//! # Secret material and memory hygiene
//!
//! The signing key is stored in a [`zeroize::Zeroizing`] buffer inside [`MlDsa65Keypair`] so it
//! is cleared on drop when the WASM object is garbage-collected on the Rust side. It is copied to
//! `JavaScript` as a [`js_sys::Uint8Array`] via `copy_from` (not as an owned, non-zeroizing
//! `alloc::vec::Vec` return), which avoids an extra full-size plaintext `Vec` in Rust linear
//! memory for each getter call. The key-generation seed and per-signature randomness are held in
//! `Zeroizing` stack buffers and cleared immediately after use.
//!
//! **`JavaScript` callers** must still treat the returned signing-key `Uint8Array` and the
//! `signingKey` argument to [`sign`] as sensitive: Rust cannot erase copies on the JS heap, in
//! `ArrayBuffer` views, or in engine internals. After use, overwrite buffers (for example
//! `buf.fill(0)` on a mutable view, or discard references) following your application's
//! key-handling policy.

#![allow(missing_docs)]
#![allow(
    clippy::wildcard_imports,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use js_sys::Uint8Array;
use rand_core::Rng;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::constants::ml_dsa_65::{
    SIGNATURE_SIZE,
    SIGNING_KEY_SIZE,
    VERIFICATION_KEY_SIZE,
};
use crate::ml_dsa_65::{
    MLDSA65Signature,
    MLDSA65SigningKey,
    MLDSA65VerificationKey,
    generate_key_pair_from_seed as mldsa65_generate_key_pair_from_seed,
    sign as mldsa65_sign,
    verify as mldsa65_verify,
};
use crate::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};

fn rng_err(e: lib_q_random::Error) -> JsError {
    JsError::new(&e.to_string())
}

/// Copy `secret` into a new `Uint8Array` for the JS boundary without returning an owned `Vec<u8>`.
fn secret_bytes_to_uint8_array(secret: &[u8]) -> Uint8Array {
    let n = u32::try_from(secret.len()).expect("secret length exceeds Uint8Array maximum");
    let out = Uint8Array::new_with_length(n);
    out.copy_from(secret);
    out
}

fn fixed_len_array<const N: usize>(what: &'static str, bytes: &[u8]) -> Result<[u8; N], JsError> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        JsError::new(&format!(
            "invalid {what} length: expected {N} bytes, got {}",
            bytes.len()
        ))
    })
}

/// An ML-DSA-65 key pair. `secretKey` copies the zeroizing signing-key buffer out as a
/// `Uint8Array` on demand; `publicKey` is not secret.
#[wasm_bindgen]
pub struct MlDsa65Keypair {
    signing_key: Zeroizing<Vec<u8>>,
    verifying_key: Vec<u8>,
}

#[wasm_bindgen]
impl MlDsa65Keypair {
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> Uint8Array {
        secret_bytes_to_uint8_array(self.signing_key.as_slice())
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.verifying_key.clone()
    }
}

/// Generate an ML-DSA-65 key pair using the platform's secure RNG.
#[wasm_bindgen(js_name = generateKeyPair)]
pub fn generate_key_pair() -> Result<MlDsa65Keypair, JsError> {
    let mut rng = lib_q_random::new_secure_rng().map_err(rng_err)?;
    let mut seed = Zeroizing::new([0u8; KEY_GENERATION_RANDOMNESS_SIZE]);
    rng.fill_bytes(seed.as_mut_slice());
    let kp = mldsa65_generate_key_pair_from_seed(&seed);
    Ok(MlDsa65Keypair {
        signing_key: Zeroizing::new(kp.signing_key.as_slice().to_vec()),
        verifying_key: kp.verification_key.as_slice().to_vec(),
    })
}

/// Sign `message` with a raw ML-DSA-65 signing key (`secretKey`'s encoding), using the platform's
/// secure RNG for the per-signature randomness required by FIPS 204. `context` is the signature's
/// domain-separation context; it may be empty and must be at most 255 bytes.
#[wasm_bindgen]
pub fn sign(signing_key: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>, JsError> {
    let sk_bytes: Zeroizing<[u8; SIGNING_KEY_SIZE]> =
        Zeroizing::new(fixed_len_array("ML-DSA-65 signing key", signing_key)?);
    let sk = MLDSA65SigningKey::new(*sk_bytes);

    let mut rng = lib_q_random::new_secure_rng().map_err(rng_err)?;
    let mut randomness = Zeroizing::new([0u8; SIGNING_RANDOMNESS_SIZE]);
    rng.fill_bytes(randomness.as_mut_slice());

    let signature = mldsa65_sign(&sk, message, context, *randomness)
        .map_err(|e| JsError::new(&format!("ML-DSA-65 sign failed: {e:?}")))?;
    Ok(signature.as_slice().to_vec())
}

/// Verify an ML-DSA-65 `signature` over `message` under `verifying_key` (`publicKey`'s encoding)
/// and `context`. Returns `false` — never an error — for a well-formed but invalid signature;
/// malformed key/signature encodings are errors.
#[wasm_bindgen]
pub fn verify(
    verifying_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    let vk_bytes: [u8; VERIFICATION_KEY_SIZE] =
        fixed_len_array("ML-DSA-65 verification key", verifying_key)?;
    let vk = MLDSA65VerificationKey::new(vk_bytes);

    let sig_bytes: [u8; SIGNATURE_SIZE] = fixed_len_array("ML-DSA-65 signature", signature)?;
    let sig = MLDSA65Signature::new(sig_bytes);

    Ok(mldsa65_verify(&vk, message, context, &sig).is_ok())
}
