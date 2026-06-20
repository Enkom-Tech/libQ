//! WASM bindings for the provisional dealerless DKG (`@lib-q/dkg`).
//!
//! A minimal JS surface: run an honest `t`-of-`n` DKG (returning the group key, per-party
//! verification keys, and the finalized signing shares), and a decoder for the round-1 commitment
//! broadcast (so untrusted wire input can be parsed safely). The full multi-round protocol with
//! complaints/resharing is exercised from Rust; see the crate `LIBQ_API.md`.

#![allow(missing_docs)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use lib_q_random::new_secure_rng;
use wasm_bindgen::prelude::*;

use crate::{
    decode_round1_commitments,
    dkg_run_honest,
    setup,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_DKG", e)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `dkgSetup()` → `{ profileId, maxParties }`.
#[wasm_bindgen(js_name = dkgSetup)]
pub fn dkg_setup_wasm() -> Result<JsValue, JsValue> {
    let p = setup();
    let out = serde_json::json!({ "profileId": p.id, "maxParties": p.max_parties });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// `dkgKeygen(parties, threshold)` → `{ publicKey, secretShares }`.
///
/// Runs the full honest protocol with a fresh secure RNG. `secretShares[i].shareBytesHex` is the
/// canonical `value ‖ rand` encoding; treat it as a secret.
#[wasm_bindgen(js_name = dkgKeygen)]
pub fn dkg_keygen_wasm(parties: u8, threshold: u8) -> Result<JsValue, JsValue> {
    let profile = setup();
    let mut rng = new_secure_rng().map_err(js_err)?;
    let kg = dkg_run_honest(&profile, parties, threshold, &mut rng).map_err(js_err)?;
    let out = serde_json::json!({
        "publicKey": {
            "threshold": kg.public_key.threshold,
            "groupKeyHex": hex_encode(&kg.public_key.group_key),
            "shareVerifiers": kg
                .public_key
                .share_verifiers
                .iter()
                .map(|v| serde_json::json!({
                    "index": v.index,
                    "verifyingKeyHex": hex_encode(&v.verifying_key),
                }))
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

/// `dkgDecodeRound1(wire: Uint8Array)` → `{ party, threshold, commitmentCount }`.
#[wasm_bindgen(js_name = dkgDecodeRound1)]
pub fn dkg_decode_round1_wasm(wire: &[u8]) -> Result<JsValue, JsValue> {
    let c = decode_round1_commitments(wire).map_err(js_err)?;
    let out = serde_json::json!({
        "party": c.party,
        "threshold": c.threshold,
        "commitmentCount": c.commitments.len(),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}
