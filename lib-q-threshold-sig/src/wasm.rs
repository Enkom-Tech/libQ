//! WASM bindings for `@lib-q/threshold-sig` — **WITHDRAWN, every export fails closed.**
//!
//! The scheme this package exposed is not a signature scheme and provides no security; see the
//! crate-level documentation for the analysis. Every binding below throws instead of running.
//!
//! The JavaScript surface was additionally the most damaging way to reach the defect: the old
//! `thresholdSigKeygenShares` serialized each party's raw secret share to the host twice — once
//! as `secretShares[].shareBytes` and again, as supposedly public data, in the returned public
//! key's `shareVerifiers[].verifyingKeyHex`.
//!
//! Unlike the Rust API, the wire codecs are **also** withdrawn here. On the Rust side those
//! codecs are retained for legacy blob triage and parser fuzzing; this package is a product
//! surface, where leaving part of a withdrawn scheme callable invites the conclusion that the
//! rest still works. A JavaScript caller therefore cannot reach any code path at all.

#![allow(missing_docs)]

use wasm_bindgen::prelude::*;

/// Text delivered to JavaScript callers on every entry point.
const WITHDRAWN: &str = "lib-q-threshold-sig / @lib-q/threshold-sig is WITHDRAWN as \
                         cryptographically unsound: its published key material was the private \
                         key and its verification relation contained no secret, so it \
                         authenticated nothing. Every binding in this package is disabled and \
                         cannot be re-enabled. Any key or signature it previously produced must \
                         be treated as compromised, and any decision made on its output must be \
                         re-evaluated as unauthenticated.";

fn withdrawn() -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_THRESHOLD_SIG", WITHDRAWN)
}

/// **WITHDRAWN — always throws.**
#[wasm_bindgen(js_name = thresholdSigSetup)]
pub fn threshold_sig_setup_wasm() -> Result<JsValue, JsValue> {
    Err(withdrawn())
}

/// **WITHDRAWN — always throws.** Never returns key material.
#[wasm_bindgen(js_name = thresholdSigKeygenShares)]
pub fn threshold_sig_keygen_shares_wasm(
    _threshold: u8,
    _share_count: u8,
) -> Result<JsValue, JsValue> {
    Err(withdrawn())
}

/// **WITHDRAWN — always throws.**
#[wasm_bindgen(js_name = thresholdSigSignRound1)]
pub fn threshold_sig_sign_round1_wasm(
    _share_bytes: &[u8],
    _index: u8,
    _threshold: u8,
    _message: &[u8],
) -> Result<JsValue, JsValue> {
    Err(withdrawn())
}

/// **WITHDRAWN — always throws.**
#[wasm_bindgen(js_name = thresholdSigSignRound2)]
pub fn threshold_sig_sign_round2_wasm(
    _handle: JsValue,
    _public_key_json: JsValue,
    _message: &[u8],
    _share_bytes: &[u8],
    _index: u8,
    _threshold: u8,
    _commitments_json: JsValue,
) -> Result<JsValue, JsValue> {
    Err(withdrawn())
}

/// **WITHDRAWN — always throws.**
#[wasm_bindgen(js_name = thresholdSigAggregate)]
pub fn threshold_sig_aggregate_wasm(
    _public_key_json: JsValue,
    _message: &[u8],
    _commitments_json: JsValue,
    _partials_json: JsValue,
) -> Result<JsValue, JsValue> {
    Err(withdrawn())
}

/// **WITHDRAWN — always throws.** Cannot return `true`; it cannot return at all.
#[wasm_bindgen(js_name = thresholdSigVerify)]
pub fn threshold_sig_verify_wasm(
    _public_key_json: JsValue,
    _message: &[u8],
    _signature_json: JsValue,
) -> Result<bool, JsValue> {
    Err(withdrawn())
}

/// **WITHDRAWN — always throws.**
#[wasm_bindgen(js_name = thresholdSigIdentifyAbort)]
pub fn threshold_sig_identify_abort_wasm(
    _public_key_json: JsValue,
    _message: &[u8],
    _commitments_json: JsValue,
    _partials_json: JsValue,
) -> Result<JsValue, JsValue> {
    Err(withdrawn())
}

/// **WITHDRAWN — always throws.**
#[wasm_bindgen(js_name = thresholdSigEncodeWireV1)]
pub fn threshold_sig_encode_wire_v1_wasm(
    _signature_hex: &str,
    _meta_hex: &str,
) -> Result<JsValue, JsValue> {
    Err(withdrawn())
}

/// **WITHDRAWN — always throws.**
#[wasm_bindgen(js_name = thresholdSigDecodeWireV1)]
pub fn threshold_sig_decode_wire_v1_wasm(_wire: &[u8]) -> Result<JsValue, JsValue> {
    Err(withdrawn())
}
