//! WASM bindings for provisional threshold KEM (`@lib-q/threshold-kem`).

#![allow(missing_docs)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use js_sys::{
    Array,
    Object,
    Reflect,
    Uint8Array,
};
use lib_q_random::new_secure_rng;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    PartialDecapShare,
    SecretShare,
    ShareVerifier,
    ThresholdKemPublicKey,
    combine_decap,
    decode_threshold_kem_wire_v1,
    encap,
    encode_threshold_kem_wire_v1,
    keygen_shares,
    partial_decap,
    setup,
    verify_share,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_THRESHOLD_KEM", e)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, JsValue> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(js_err("hex string length must be even"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(js_err))
        .collect()
}

fn set_prop(obj: &Object, key: &str, val: &JsValue) -> Result<(), JsValue> {
    Reflect::set(obj, &JsValue::from_str(key), val)
        .map_err(|_| js_err("failed to set JS object property"))?;
    Ok(())
}

fn bytes_to_uint8_array(secret: &[u8]) -> Uint8Array {
    let n = u32::try_from(secret.len()).expect("length exceeds Uint8Array maximum");
    let out = Uint8Array::new_with_length(n);
    out.copy_from(secret);
    out
}

fn public_key_to_json(pk: &ThresholdKemPublicKey) -> serde_json::Value {
    serde_json::json!({
        "profileId": pk.profile_id,
        "threshold": pk.threshold,
        "mlKemPublicKeyHex": hex_encode(&pk.ml_kem_public_key),
        "shareVerifiers": pk.share_verifiers.iter().map(|v| serde_json::json!({
            "index": v.index,
            "commitmentHex": hex_encode(&v.commitment),
        })).collect::<Vec<_>>(),
    })
}

fn public_key_from_json(value: &serde_json::Value) -> Result<ThresholdKemPublicKey, JsValue> {
    let profile_id = value["profileId"]
        .as_u64()
        .ok_or_else(|| js_err("missing profileId"))? as u8;
    let threshold = value["threshold"]
        .as_u64()
        .ok_or_else(|| js_err("missing threshold"))? as u8;
    let ml_kem_public_key = hex_decode(
        value["mlKemPublicKeyHex"]
            .as_str()
            .ok_or_else(|| js_err("missing mlKemPublicKeyHex"))?,
    )?;
    let verifiers = value["shareVerifiers"]
        .as_array()
        .ok_or_else(|| js_err("missing shareVerifiers"))?;
    let mut share_verifiers = Vec::with_capacity(verifiers.len());
    for v in verifiers {
        let index = v["index"]
            .as_u64()
            .ok_or_else(|| js_err("verifier missing index"))? as u8;
        let commitment_hex = v["commitmentHex"]
            .as_str()
            .ok_or_else(|| js_err("verifier missing commitmentHex"))?;
        let commitment_bytes = hex_decode(commitment_hex)?;
        if commitment_bytes.len() != 32 {
            return Err(js_err("commitment must be 32 bytes"));
        }
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&commitment_bytes);
        share_verifiers.push(ShareVerifier { index, commitment });
    }
    Ok(ThresholdKemPublicKey {
        profile_id,
        threshold,
        ml_kem_public_key,
        share_verifiers,
    })
}

fn secret_share_from_parts(
    index: u8,
    threshold: u8,
    commitment_hex: &str,
    share_bytes: &[u8],
) -> Result<SecretShare, JsValue> {
    let commitment_bytes = hex_decode(commitment_hex)?;
    if commitment_bytes.len() != 32 {
        return Err(js_err("commitment must be 32 bytes"));
    }
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&commitment_bytes);
    Ok(SecretShare {
        index,
        threshold,
        verifier_commitment: commitment,
        share_bytes: Zeroizing::new(share_bytes.to_vec()),
    })
}

fn partials_from_json(value: &serde_json::Value) -> Result<Vec<PartialDecapShare>, JsValue> {
    let arr = value
        .as_array()
        .ok_or_else(|| js_err("partials must be a JSON array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let index = item["index"]
            .as_u64()
            .ok_or_else(|| js_err("partial missing index"))? as u8;
        let share_hex = item["shareBytesHex"]
            .as_str()
            .ok_or_else(|| js_err("partial missing shareBytesHex"))?;
        let tag_hex = item["tagHex"]
            .as_str()
            .ok_or_else(|| js_err("partial missing tagHex"))?;
        let share_bytes = hex_decode(share_hex)?;
        let tag_bytes = hex_decode(tag_hex)?;
        if tag_bytes.len() != 32 {
            return Err(js_err("tag must be 32 bytes"));
        }
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&tag_bytes);
        out.push(PartialDecapShare {
            index,
            share_bytes,
            tag,
        });
    }
    Ok(out)
}

fn partial_to_json(p: &PartialDecapShare) -> serde_json::Value {
    serde_json::json!({
        "index": p.index,
        "shareBytesHex": hex_encode(&p.share_bytes),
        "tagHex": hex_encode(&p.tag),
    })
}

/// Return default profile metadata as JSON.
#[wasm_bindgen(js_name = thresholdKemSetup)]
pub fn threshold_kem_setup_wasm() -> Result<JsValue, JsValue> {
    let profile = setup();
    let out = serde_json::json!({
        "profileId": profile.id,
        "maxThreshold": profile.max_threshold,
        "parameterSetDigestHex": hex_encode(&profile.parameter_set_digest),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Generate threshold shares; secret material returned as `Uint8Array` entries.
#[wasm_bindgen(js_name = thresholdKemKeygenShares)]
pub fn threshold_kem_keygen_shares_wasm(
    threshold: u8,
    share_count: u16,
) -> Result<JsValue, JsValue> {
    let profile = setup();
    let mut rng = new_secure_rng().map_err(js_err)?;
    let out = keygen_shares(&profile, threshold, share_count, &mut rng).map_err(js_err)?;
    let shares_arr = Array::new();
    for s in &out.secret_shares {
        let share_obj = Object::new();
        set_prop(&share_obj, "index", &JsValue::from(s.index))?;
        set_prop(&share_obj, "threshold", &JsValue::from(s.threshold))?;
        set_prop(
            &share_obj,
            "commitmentHex",
            &JsValue::from_str(&hex_encode(&s.verifier_commitment)),
        )?;
        set_prop(
            &share_obj,
            "shareBytes",
            &bytes_to_uint8_array(s.share_bytes.as_slice()).into(),
        )?;
        shares_arr.push(&share_obj);
    }
    let result = Object::new();
    set_prop(
        &result,
        "publicKey",
        &serde_wasm_bindgen::to_value(&public_key_to_json(&out.public_key)).map_err(js_err)?,
    )?;
    set_prop(&result, "secretShares", &shares_arr.into())?;
    Ok(result.into())
}

/// Encapsulate to a threshold public key; shared secret as `Uint8Array`, wire as `Uint8Array`.
#[wasm_bindgen(js_name = thresholdKemEncap)]
pub fn threshold_kem_encap_wasm(public_key_json: JsValue) -> Result<JsValue, JsValue> {
    let profile = setup();
    let pk_value: serde_json::Value =
        serde_wasm_bindgen::from_value(public_key_json).map_err(js_err)?;
    let pk = public_key_from_json(&pk_value)?;
    let mut rng = new_secure_rng().map_err(js_err)?;
    let enc = encap(&profile, &pk, &mut rng).map_err(js_err)?;
    let result = Object::new();
    set_prop(
        &result,
        "sharedSecret",
        &bytes_to_uint8_array(&enc.shared_secret).into(),
    )?;
    set_prop(
        &result,
        "ciphertextHex",
        &JsValue::from_str(&hex_encode(&enc.ciphertext)),
    )?;
    set_prop(&result, "wire", &bytes_to_uint8_array(&enc.wire).into())?;
    Ok(result.into())
}

/// Produce a partial decap share from secret share bytes and ciphertext hex.
#[wasm_bindgen(js_name = thresholdKemPartialDecap)]
pub fn threshold_kem_partial_decap_wasm(
    share_bytes: &[u8],
    index: u8,
    threshold: u8,
    commitment_hex: &str,
    ciphertext_hex: &str,
) -> Result<JsValue, JsValue> {
    let share = secret_share_from_parts(index, threshold, commitment_hex, share_bytes)?;
    let ciphertext = hex_decode(ciphertext_hex)?;
    let partial = partial_decap(&share, &ciphertext).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&partial_to_json(&partial)).map_err(js_err)
}

/// Combine partial shares into shared secret (`Uint8Array`, 32 bytes).
#[wasm_bindgen(js_name = thresholdKemCombineDecap)]
pub fn threshold_kem_combine_decap_wasm(
    ciphertext_hex: &str,
    partials_json: JsValue,
    public_key_json: JsValue,
    threshold: u8,
) -> Result<Uint8Array, JsValue> {
    let profile = setup();
    let ciphertext = hex_decode(ciphertext_hex)?;
    let partials_value: serde_json::Value =
        serde_wasm_bindgen::from_value(partials_json).map_err(js_err)?;
    let partials = partials_from_json(&partials_value)?;
    let pk_value: serde_json::Value =
        serde_wasm_bindgen::from_value(public_key_json).map_err(js_err)?;
    let pk = public_key_from_json(&pk_value)?;
    let shared = combine_decap(
        &profile,
        &ciphertext,
        &partials,
        &pk.share_verifiers,
        threshold,
    )
    .map_err(js_err)?;
    Ok(bytes_to_uint8_array(&shared))
}

/// Verify a partial share against a verifier commitment.
#[wasm_bindgen(js_name = thresholdKemVerifyShare)]
pub fn threshold_kem_verify_share_wasm(
    verifier_index: u8,
    commitment_hex: &str,
    ciphertext_hex: &str,
    partial_json: JsValue,
) -> Result<bool, JsValue> {
    let commitment_bytes = hex_decode(commitment_hex)?;
    if commitment_bytes.len() != 32 {
        return Err(js_err("commitment must be 32 bytes"));
    }
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&commitment_bytes);
    let verifier = ShareVerifier {
        index: verifier_index,
        commitment,
    };
    let partial_value: serde_json::Value =
        serde_wasm_bindgen::from_value(partial_json).map_err(js_err)?;
    let partials = partials_from_json(&serde_json::Value::Array(vec![partial_value]))?;
    let ciphertext = hex_decode(ciphertext_hex)?;
    Ok(verify_share(&verifier, &ciphertext, &partials[0]))
}

/// Encode canonical threshold KEM wire v1 (`Uint8Array`).
#[wasm_bindgen(js_name = thresholdKemEncodeWireV1)]
pub fn threshold_kem_encode_wire_v1_wasm(
    ciphertext_hex: &str,
    partials_json: JsValue,
) -> Result<Uint8Array, JsValue> {
    let profile = setup();
    let ciphertext = hex_decode(ciphertext_hex)?;
    let partials_value: serde_json::Value =
        serde_wasm_bindgen::from_value(partials_json).map_err(js_err)?;
    let partials = partials_from_json(&partials_value)?;
    let wire = encode_threshold_kem_wire_v1(&profile, &ciphertext, &partials).map_err(js_err)?;
    Ok(bytes_to_uint8_array(&wire))
}

/// Decode canonical threshold KEM wire v1 from `Uint8Array` to JSON.
#[wasm_bindgen(js_name = thresholdKemDecodeWireV1)]
pub fn threshold_kem_decode_wire_v1_wasm(wire: &[u8]) -> Result<JsValue, JsValue> {
    let profile = setup();
    let decoded = decode_threshold_kem_wire_v1(&profile, wire).map_err(js_err)?;
    let partials: Vec<serde_json::Value> = decoded.shares.iter().map(partial_to_json).collect();
    let out = serde_json::json!({
        "ciphertextHex": hex_encode(&decoded.ciphertext),
        "partials": partials,
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}
