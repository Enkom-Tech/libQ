//! WASM bindings for the provisional lattice threshold KEM (`@lib-q/threshold-kem-lattice`).
//!
//! Minimal JS surface: setup, centralized keygen, and a self-contained encaps+decaps demo (keygen →
//! encapsulate → threshold of partial decapsulations → combine, FO⊥ checked). The dealerless keygen
//! path is `@lib-q/dkg`.

#![allow(missing_docs)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use lib_q_random::new_secure_rng;
use wasm_bindgen::prelude::*;

use crate::{
    combine,
    encapsulate,
    keygen_shares,
    partial_decap,
    setup,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_THRESHOLD_KEM_LATTICE", e)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `tkemSetup()` → `{ profileId, maxParties }`.
#[wasm_bindgen(js_name = tkemSetup)]
pub fn tkem_setup_wasm() -> Result<JsValue, JsValue> {
    let p = setup();
    let out = serde_json::json!({ "profileId": p.id, "maxParties": p.max_parties });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// `tkemKeygen(parties, threshold)` → `{ publicKey, secretShares }` (centralized reference).
#[wasm_bindgen(js_name = tkemKeygen)]
pub fn tkem_keygen_wasm(parties: u8, threshold: u8) -> Result<JsValue, JsValue> {
    let profile = setup();
    let mut rng = new_secure_rng().map_err(js_err)?;
    let kg = keygen_shares(&profile, threshold, parties, &mut rng).map_err(js_err)?;
    let out = serde_json::json!({
        "publicKey": {
            "threshold": kg.public_key.threshold,
            "t0Hex": hex_encode(&kg.public_key.t0_bytes),
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

/// `tkemEncapsDecapsDemo(parties, threshold)` → `{ match, ciphertextBytes, sharedSecretHex }`.
///
/// Self-contained: keygen, encapsulate, partially decapsulate with the first `threshold` shares,
/// combine (FO⊥-checked), and compare with the encapsulated secret.
#[wasm_bindgen(js_name = tkemEncapsDecapsDemo)]
pub fn tkem_encaps_decaps_demo_wasm(parties: u8, threshold: u8) -> Result<JsValue, JsValue> {
    let profile = setup();
    let mut rng = new_secure_rng().map_err(js_err)?;
    let kg = keygen_shares(&profile, threshold, parties, &mut rng).map_err(js_err)?;

    let (ss_encap, ct) = encapsulate(&kg.public_key, &mut rng).map_err(js_err)?;

    let chosen = &kg.secret_shares[..usize::from(threshold)];
    let subset: Vec<u8> = chosen.iter().map(|s| s.index).collect();
    let partials: Vec<_> = chosen
        .iter()
        .map(|s| partial_decap(s, &subset, &ct))
        .collect::<Result<_, _>>()
        .map_err(js_err)?;
    let ss_decap = combine(&kg.public_key, &partials, &ct).map_err(js_err)?;

    let out = serde_json::json!({
        "match": ss_encap == ss_decap,
        "ciphertextBytes": ct.to_bytes().len(),
        "sharedSecretHex": hex_encode(&ss_decap),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}
