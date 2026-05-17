//! wasm-bindgen API for HQC KEM (requires `alloc`, `random`, and `hqc*` features).

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use core::mem;

use lib_q_core::{
    Algorithm,
    AlgorithmCategory,
    CryptoProvider,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::LibQHqcProvider;

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_HQC", e)
}

fn parse_hqc_param(p: &str) -> Result<Algorithm, JsValue> {
    match p.trim() {
        "HQC-128" | "hqc128" | "128" | "level1" => Ok(Algorithm::Hqc128),
        "HQC-192" | "hqc192" | "192" | "level3" => Ok(Algorithm::Hqc192),
        "HQC-256" | "hqc256" | "256" | "level5" => Ok(Algorithm::Hqc256),
        other => Err(lib_q_core::wasm_common::wasm_js_error(
            "LIB_Q_HQC_UNKNOWN_PARAM",
            format!("unknown HQC parameter set '{other}'; use HQC-128, HQC-192, or HQC-256"),
        )),
    }
}

fn kem_ctx() -> Result<KemContext, JsValue> {
    let p = LibQHqcProvider::new().map_err(js_err)?;
    Ok(KemContext::with_provider(
        Box::new(p) as Box<dyn CryptoProvider>
    ))
}

/// Object `{"publicKey":"hex","secretKey":"hex"}`.
#[wasm_bindgen]
pub fn hqc_keygen(param: &str) -> Result<JsValue, JsValue> {
    let alg = parse_hqc_param(param)?;
    if alg.category() != AlgorithmCategory::Kem {
        return Err(js_err("not a KEM algorithm"));
    }
    let mut ctx = kem_ctx()?;
    let kp = ctx
        .generate_keypair(alg, None)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let out = serde_json::json!({
        "publicKey": hex::encode(kp.public_key().as_bytes()),
        "secretKey": hex::encode(kp.secret_key().as_bytes()),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Object `{"ciphertext":"hex","sharedSecret":"hex"}`.
#[wasm_bindgen]
pub fn hqc_encapsulate(public_key_hex: &str, param: &str) -> Result<JsValue, JsValue> {
    let alg = parse_hqc_param(param)?;
    let pk_bytes = hex::decode(public_key_hex.trim()).map_err(js_err)?;
    let pk = KemPublicKey::new(pk_bytes);
    let ctx = kem_ctx()?;
    let (ct, ss) = ctx
        .encapsulate(alg, &pk, None)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let out = serde_json::json!({
        "ciphertext": hex::encode(&ct),
        "sharedSecret": hex::encode(&ss),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Object `{ "sharedSecretHex": "..." }` with hex-encoded shared secret bytes.
#[wasm_bindgen]
pub fn hqc_decapsulate(
    secret_key_hex: &str,
    ciphertext_hex: &str,
    param: &str,
) -> Result<JsValue, JsValue> {
    let alg = parse_hqc_param(param)?;
    let mut sk_z = Zeroizing::new(hex::decode(secret_key_hex.trim()).map_err(js_err)?);
    let ct_bytes = hex::decode(ciphertext_hex.trim()).map_err(js_err)?;
    let sk = KemSecretKey::new(mem::take(&mut *sk_z));
    let ctx = kem_ctx()?;
    let ss = ctx
        .decapsulate(alg, &sk, &ct_bytes)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let out = serde_json::json!({ "sharedSecretHex": hex::encode(ss) });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}
