//! WASM bindings for SLH-DSA (FIPS 205) — parameter set selected by string id.

#![allow(missing_docs)]

extern crate alloc;

use alloc::format;
use alloc::string::String;

use lib_q_random::new_secure_rng;
use rand_core::CryptoRng;
use serde::Serialize;
use signature::{
    Keypair,
    Signer,
    Verifier,
};
use wasm_bindgen::prelude::{
    JsValue,
    wasm_bindgen,
};
use zeroize::Zeroizing;

use crate::{
    ParameterSet,
    Sha2_128f,
    Sha2_128s,
    Sha2_192f,
    Sha2_192s,
    Sha2_256f,
    Sha2_256s,
    Shake128f,
    Shake128s,
    Shake192f,
    Shake192s,
    Shake256f,
    Shake256s,
    Signature,
    SigningKey,
    VerifyingKey,
    VerifyingKeyLen,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_SLH_DSA", e)
}

fn normalize_alg(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn rng() -> Result<impl CryptoRng, JsValue> {
    new_secure_rng().map_err(js_err)
}

#[derive(Serialize)]
struct KeypairOut {
    algorithm: &'static str,
    signing_key_hex: String,
    verifying_key_hex: String,
}

fn keygen_for<P: ParameterSet + VerifyingKeyLen>(
    rng: &mut impl CryptoRng,
    name: &'static str,
) -> Result<JsValue, JsValue> {
    let sk = SigningKey::<P>::new(rng);
    let vk = sk.verifying_key();
    let out = KeypairOut {
        algorithm: name,
        signing_key_hex: hex::encode(sk.to_vec().as_slice()),
        verifying_key_hex: hex::encode(vk.to_vec()),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Generate a signing key and verifying key for the given FIPS 205 parameter set id.
///
/// `algorithm` is case-insensitive; hyphens/underscores are ignored, e.g. `SHAKE128f`, `sha2-128f`.
#[wasm_bindgen(js_name = slhDsaKeygen)]
pub fn slh_dsa_keygen(algorithm: &str) -> Result<JsValue, JsValue> {
    let mut rng = rng()?;
    let n = normalize_alg(algorithm);
    match n.as_str() {
        "shake128f" => keygen_for::<Shake128f>(&mut rng, "shake128f"),
        "shake128s" => keygen_for::<Shake128s>(&mut rng, "shake128s"),
        "shake192f" => keygen_for::<Shake192f>(&mut rng, "shake192f"),
        "shake192s" => keygen_for::<Shake192s>(&mut rng, "shake192s"),
        "shake256f" => keygen_for::<Shake256f>(&mut rng, "shake256f"),
        "shake256s" => keygen_for::<Shake256s>(&mut rng, "shake256s"),
        "sha2128f" => keygen_for::<Sha2_128f>(&mut rng, "sha2_128f"),
        "sha2128s" => keygen_for::<Sha2_128s>(&mut rng, "sha2_128s"),
        "sha2192f" => keygen_for::<Sha2_192f>(&mut rng, "sha2_192f"),
        "sha2192s" => keygen_for::<Sha2_192s>(&mut rng, "sha2_192s"),
        "sha2256f" => keygen_for::<Sha2_256f>(&mut rng, "sha2_256f"),
        "sha2256s" => keygen_for::<Sha2_256s>(&mut rng, "sha2_256s"),
        _ => Err(js_err(format!(
            "unknown SLH-DSA parameter set: {algorithm}"
        ))),
    }
}

fn sign_for<P: ParameterSet>(signing_key_hex: &str, message: &[u8]) -> Result<String, JsValue> {
    let sk_bytes = Zeroizing::new(hex::decode(signing_key_hex.trim()).map_err(js_err)?);
    let sk = SigningKey::<P>::try_from(sk_bytes.as_slice())
        .map_err(|_| js_err("invalid signing key encoding or length"))?;
    let sig = sk
        .try_sign(message)
        .map_err(|e| js_err(format!("sign error: {e:?}")))?;
    Ok(hex::encode(sig.to_vec()))
}

/// Sign `message` with a hex-encoded raw signing key (`to_bytes` format).
#[wasm_bindgen(js_name = slhDsaSign)]
pub fn slh_dsa_sign(
    algorithm: &str,
    signing_key_hex: &str,
    message: &[u8],
) -> Result<String, JsValue> {
    let n = normalize_alg(algorithm);
    match n.as_str() {
        "shake128f" => sign_for::<Shake128f>(signing_key_hex, message),
        "shake128s" => sign_for::<Shake128s>(signing_key_hex, message),
        "shake192f" => sign_for::<Shake192f>(signing_key_hex, message),
        "shake192s" => sign_for::<Shake192s>(signing_key_hex, message),
        "shake256f" => sign_for::<Shake256f>(signing_key_hex, message),
        "shake256s" => sign_for::<Shake256s>(signing_key_hex, message),
        "sha2128f" => sign_for::<Sha2_128f>(signing_key_hex, message),
        "sha2128s" => sign_for::<Sha2_128s>(signing_key_hex, message),
        "sha2192f" => sign_for::<Sha2_192f>(signing_key_hex, message),
        "sha2192s" => sign_for::<Sha2_192s>(signing_key_hex, message),
        "sha2256f" => sign_for::<Sha2_256f>(signing_key_hex, message),
        "sha2256s" => sign_for::<Sha2_256s>(signing_key_hex, message),
        _ => Err(js_err(format!(
            "unknown SLH-DSA parameter set: {algorithm}"
        ))),
    }
}

fn verify_for<P: ParameterSet + VerifyingKeyLen>(
    verifying_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<bool, JsValue> {
    let vk_bytes = hex::decode(verifying_key_hex.trim()).map_err(js_err)?;
    let vk = VerifyingKey::<P>::try_from(vk_bytes.as_slice())
        .map_err(|_| js_err("invalid verifying key encoding or length"))?;
    let sig_bytes = hex::decode(signature_hex.trim()).map_err(js_err)?;
    let sig = Signature::<P>::try_from(sig_bytes.as_slice())
        .map_err(|_| js_err("invalid signature encoding or length"))?;
    Ok(vk.verify(message, &sig).is_ok())
}

/// Verify a hex-encoded signature over `message` with a hex-encoded raw verifying key.
#[wasm_bindgen(js_name = slhDsaVerify)]
pub fn slh_dsa_verify(
    algorithm: &str,
    verifying_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<bool, JsValue> {
    let n = normalize_alg(algorithm);
    match n.as_str() {
        "shake128f" => verify_for::<Shake128f>(verifying_key_hex, message, signature_hex),
        "shake128s" => verify_for::<Shake128s>(verifying_key_hex, message, signature_hex),
        "shake192f" => verify_for::<Shake192f>(verifying_key_hex, message, signature_hex),
        "shake192s" => verify_for::<Shake192s>(verifying_key_hex, message, signature_hex),
        "shake256f" => verify_for::<Shake256f>(verifying_key_hex, message, signature_hex),
        "shake256s" => verify_for::<Shake256s>(verifying_key_hex, message, signature_hex),
        "sha2128f" => verify_for::<Sha2_128f>(verifying_key_hex, message, signature_hex),
        "sha2128s" => verify_for::<Sha2_128s>(verifying_key_hex, message, signature_hex),
        "sha2192f" => verify_for::<Sha2_192f>(verifying_key_hex, message, signature_hex),
        "sha2192s" => verify_for::<Sha2_192s>(verifying_key_hex, message, signature_hex),
        "sha2256f" => verify_for::<Sha2_256f>(verifying_key_hex, message, signature_hex),
        "sha2256s" => verify_for::<Sha2_256s>(verifying_key_hex, message, signature_hex),
        _ => Err(js_err(format!(
            "unknown SLH-DSA parameter set: {algorithm}"
        ))),
    }
}
