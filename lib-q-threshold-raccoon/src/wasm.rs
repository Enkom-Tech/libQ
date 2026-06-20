//! WASM bindings for the provisional lattice threshold signature (`@lib-q/threshold-raccoon`).
//!
//! Minimal JS surface: setup, centralized keygen, and a self-contained sign+verify demo (keygen →
//! combine a threshold of shares → sign → verify). The dealerless keygen path is `@lib-q/dkg`.

#![allow(missing_docs)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use lib_q_random::new_secure_rng;
use wasm_bindgen::prelude::*;

use crate::{
    combine_opening,
    encode_signature,
    keygen_shares,
    setup,
    sign,
    verify,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_THRESHOLD_RACCOON", e)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `raccoonSetup()` → `{ profileId, maxParties }`.
#[wasm_bindgen(js_name = raccoonSetup)]
pub fn raccoon_setup_wasm() -> Result<JsValue, JsValue> {
    let p = setup();
    let out = serde_json::json!({ "profileId": p.id, "maxParties": p.max_parties });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// `raccoonKeygen(parties, threshold)` → `{ publicKey, secretShares }` (centralized reference).
#[wasm_bindgen(js_name = raccoonKeygen)]
pub fn raccoon_keygen_wasm(parties: u8, threshold: u8) -> Result<JsValue, JsValue> {
    let profile = setup();
    let mut rng = new_secure_rng().map_err(js_err)?;
    let kg = keygen_shares(&profile, threshold, parties, &mut rng).map_err(js_err)?;
    let out = serde_json::json!({
        "publicKey": {
            "threshold": kg.public_key.threshold,
            "groupKeyHex": hex_encode(&kg.public_key.group_key),
            "shareVerifiers": kg
                .public_key
                .share_verifiers
                .iter()
                .map(|v| serde_json::json!({ "index": v.index, "verifyingKeyHex": hex_encode(&v.verifying_key) }))
                .collect::<Vec<_>>(),
        },
        "secretShares": kg
            .secret_shares
            .iter()
            .map(|s| serde_json::json!({
                "index": s.index,
                "threshold": s.threshold,
                "shareBytesHex": hex_encode(s.share_bytes.as_slice()),
            }))
            .collect::<Vec<_>>(),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// `raccoonSignVerifyDemo(parties, threshold, message)` → `{ verified, signatureHex }`.
///
/// Self-contained: keygen, combine the first `threshold` shares, sign, and verify.
#[wasm_bindgen(js_name = raccoonSignVerifyDemo)]
pub fn raccoon_sign_verify_demo_wasm(
    parties: u8,
    threshold: u8,
    message: &[u8],
) -> Result<JsValue, JsValue> {
    let profile = setup();
    let mut rng = new_secure_rng().map_err(js_err)?;
    let kg = keygen_shares(&profile, threshold, parties, &mut rng).map_err(js_err)?;
    let subset: Vec<_> = kg
        .secret_shares
        .iter()
        .take(usize::from(threshold))
        .cloned()
        .collect();
    let opening = combine_opening(&subset).map_err(js_err)?;
    let sig = sign(&mut rng, &kg.public_key, &opening, message).map_err(js_err)?;
    let verified = verify(&kg.public_key, message, &sig);
    let sig_bytes = encode_signature(&sig).map_err(js_err)?;
    let out = serde_json::json!({
        "verified": verified,
        "signatureHex": hex_encode(&sig_bytes),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}
