//! WASM bindings for provisional threshold signatures (`@lib-q/threshold-sig`).

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
    Round1Commitment,
    Round1State,
    Round2Partial,
    SecretShare,
    ShareVerifier,
    ThresholdSigPublicKey,
    ThresholdSignature,
    aggregate,
    decode_signature,
    decode_threshold_sig_wire_v1,
    encode_threshold_sig_wire_v1,
    identify_abort,
    keygen_shares,
    setup,
    sign_round1,
    sign_round2,
    verify,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_THRESHOLD_SIG", e)
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

fn public_key_to_json(pk: &ThresholdSigPublicKey) -> serde_json::Value {
    serde_json::json!({
        "profileId": pk.profile_id,
        "threshold": pk.threshold,
        "groupKeyHex": hex_encode(&pk.group_key),
        "shareVerifiers": pk.share_verifiers.iter().map(|v| serde_json::json!({
            "index": v.index,
            "verifyingKeyHex": hex_encode(&v.verifying_key),
            "commitmentHex": hex_encode(&v.commitment),
        })).collect::<Vec<_>>(),
    })
}

fn public_key_from_json(value: &serde_json::Value) -> Result<ThresholdSigPublicKey, JsValue> {
    let profile_id = value["profileId"]
        .as_u64()
        .ok_or_else(|| js_err("missing profileId"))? as u8;
    let threshold = value["threshold"]
        .as_u64()
        .ok_or_else(|| js_err("missing threshold"))? as u8;
    let group_key_bytes = hex_decode(
        value["groupKeyHex"]
            .as_str()
            .ok_or_else(|| js_err("missing groupKeyHex"))?,
    )?;
    if group_key_bytes.len() != 32 {
        return Err(js_err("group key must be 32 bytes"));
    }
    let mut group_key = [0u8; 32];
    group_key.copy_from_slice(&group_key_bytes);
    let verifiers = value["shareVerifiers"]
        .as_array()
        .ok_or_else(|| js_err("missing shareVerifiers"))?;
    let mut share_verifiers = Vec::with_capacity(verifiers.len());
    for v in verifiers {
        let index = v["index"]
            .as_u64()
            .ok_or_else(|| js_err("verifier missing index"))? as u8;
        let vk_bytes = hex_decode(
            v["verifyingKeyHex"]
                .as_str()
                .ok_or_else(|| js_err("verifier missing verifyingKeyHex"))?,
        )?;
        let commitment_bytes = hex_decode(
            v["commitmentHex"]
                .as_str()
                .ok_or_else(|| js_err("verifier missing commitmentHex"))?,
        )?;
        if vk_bytes.len() != 32 || commitment_bytes.len() != 32 {
            return Err(js_err("verifier keys must be 32 bytes"));
        }
        let mut verifying_key = [0u8; 32];
        let mut commitment = [0u8; 32];
        verifying_key.copy_from_slice(&vk_bytes);
        commitment.copy_from_slice(&commitment_bytes);
        share_verifiers.push(ShareVerifier {
            index,
            verifying_key,
            commitment,
        });
    }
    Ok(ThresholdSigPublicKey {
        profile_id,
        threshold,
        group_key,
        share_verifiers,
    })
}

fn secret_share_from_parts(
    index: u8,
    threshold: u8,
    share_bytes: &[u8],
) -> Result<SecretShare, JsValue> {
    if share_bytes.len() != 32 {
        return Err(js_err("secret share must be 32 bytes"));
    }
    Ok(SecretShare {
        index,
        threshold,
        share_bytes: Zeroizing::new(share_bytes.to_vec()),
    })
}

fn commitments_from_json(value: &serde_json::Value) -> Result<Vec<Round1Commitment>, JsValue> {
    let arr = value
        .as_array()
        .ok_or_else(|| js_err("commitments must be a JSON array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let index = item["index"]
            .as_u64()
            .ok_or_else(|| js_err("commitment missing index"))? as u8;
        let nonce_hex = item["nonceCommitmentHex"]
            .as_str()
            .ok_or_else(|| js_err("commitment missing nonceCommitmentHex"))?;
        let binding_hex = item["bindingHex"]
            .as_str()
            .ok_or_else(|| js_err("commitment missing bindingHex"))?;
        let nonce_bytes = hex_decode(nonce_hex)?;
        let binding_bytes = hex_decode(binding_hex)?;
        if nonce_bytes.len() != 32 || binding_bytes.len() != 32 {
            return Err(js_err("commitment fields must be 32 bytes"));
        }
        let mut nonce_commitment = [0u8; 32];
        let mut binding = [0u8; 32];
        nonce_commitment.copy_from_slice(&nonce_bytes);
        binding.copy_from_slice(&binding_bytes);
        out.push(Round1Commitment {
            index,
            nonce_commitment,
            binding,
        });
    }
    Ok(out)
}

fn commitment_to_json(c: &Round1Commitment) -> serde_json::Value {
    serde_json::json!({
        "index": c.index,
        "nonceCommitmentHex": hex_encode(&c.nonce_commitment),
        "bindingHex": hex_encode(&c.binding),
    })
}

fn partials_from_json(value: &serde_json::Value) -> Result<Vec<Round2Partial>, JsValue> {
    let arr = value
        .as_array()
        .ok_or_else(|| js_err("partials must be a JSON array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let index = item["index"]
            .as_u64()
            .ok_or_else(|| js_err("partial missing index"))? as u8;
        let z_hex = item["zHex"]
            .as_str()
            .ok_or_else(|| js_err("partial missing zHex"))?;
        let proof_hex = item["proofHex"]
            .as_str()
            .ok_or_else(|| js_err("partial missing proofHex"))?;
        let z_bytes = hex_decode(z_hex)?;
        let proof_bytes = hex_decode(proof_hex)?;
        if z_bytes.len() != 32 || proof_bytes.len() != 32 {
            return Err(js_err("partial fields must be 32 bytes"));
        }
        let mut z = [0u8; 32];
        let mut proof = [0u8; 32];
        z.copy_from_slice(&z_bytes);
        proof.copy_from_slice(&proof_bytes);
        out.push(Round2Partial { index, z, proof });
    }
    Ok(out)
}

fn partial_to_json(p: &Round2Partial) -> serde_json::Value {
    serde_json::json!({
        "index": p.index,
        "zHex": hex_encode(&p.z),
        "proofHex": hex_encode(&p.proof),
    })
}

fn signature_from_json(value: &serde_json::Value) -> Result<ThresholdSignature, JsValue> {
    let r_hex = value["rAggHex"]
        .as_str()
        .ok_or_else(|| js_err("missing rAggHex"))?;
    let z_hex = value["zHex"]
        .as_str()
        .ok_or_else(|| js_err("missing zHex"))?;
    let signers = value["signers"]
        .as_array()
        .ok_or_else(|| js_err("missing signers"))?
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| js_err("invalid signer id"))
        })
        .collect::<Result<Vec<u8>, JsValue>>()?;
    let r_bytes = hex_decode(r_hex)?;
    let z_bytes = hex_decode(z_hex)?;
    if r_bytes.len() != 32 || z_bytes.len() != 32 {
        return Err(js_err("signature scalars must be 32 bytes"));
    }
    let mut r_agg = [0u8; 32];
    let mut z = [0u8; 32];
    r_agg.copy_from_slice(&r_bytes);
    z.copy_from_slice(&z_bytes);
    Ok(ThresholdSignature { r_agg, z, signers })
}

/// Opaque handle holding round-1 nonce state (must call `free()` when done).
#[wasm_bindgen]
pub struct ThresholdSigRound1Handle {
    state: Round1State,
}

#[wasm_bindgen]
impl ThresholdSigRound1Handle {
    /// Release round-1 nonce state.
    pub fn free(self) {}

    #[wasm_bindgen(getter, js_name = commitmentJson)]
    pub fn commitment_json(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&commitment_to_json(&self.state.commitment)).map_err(js_err)
    }
}

/// Return default profile metadata as JSON.
#[wasm_bindgen(js_name = thresholdSigSetup)]
pub fn threshold_sig_setup_wasm() -> Result<JsValue, JsValue> {
    let profile = setup();
    let out = serde_json::json!({
        "profileId": profile.id,
        "maxParties": profile.max_parties,
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Generate threshold signing shares; secrets as `Uint8Array`.
#[wasm_bindgen(js_name = thresholdSigKeygenShares)]
pub fn threshold_sig_keygen_shares_wasm(
    threshold: u8,
    share_count: u8,
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

/// Round 1: create opaque handle with nonce-bearing state.
#[wasm_bindgen(js_name = thresholdSigSignRound1)]
pub fn threshold_sig_sign_round1_wasm(
    share_bytes: &[u8],
    index: u8,
    threshold: u8,
    message: &[u8],
) -> Result<ThresholdSigRound1Handle, JsValue> {
    let profile = setup();
    let share = secret_share_from_parts(index, threshold, share_bytes)?;
    let mut rng = new_secure_rng().map_err(js_err)?;
    let state = sign_round1(&profile, &share, message, &mut rng).map_err(js_err)?;
    Ok(ThresholdSigRound1Handle { state })
}

/// Round 2: produce partial signature from round-1 handle.
#[wasm_bindgen(js_name = thresholdSigSignRound2)]
pub fn threshold_sig_sign_round2_wasm(
    handle: &ThresholdSigRound1Handle,
    public_key_json: JsValue,
    message: &[u8],
    share_bytes: &[u8],
    index: u8,
    threshold: u8,
    commitments_json: JsValue,
) -> Result<JsValue, JsValue> {
    let profile = setup();
    let pk_value: serde_json::Value =
        serde_wasm_bindgen::from_value(public_key_json).map_err(js_err)?;
    let pk = public_key_from_json(&pk_value)?;
    let share = secret_share_from_parts(index, threshold, share_bytes)?;
    let commitments_value: serde_json::Value =
        serde_wasm_bindgen::from_value(commitments_json).map_err(js_err)?;
    let commitments = commitments_from_json(&commitments_value)?;
    let partial =
        sign_round2(&profile, &pk, message, &share, &handle.state, &commitments).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&partial_to_json(&partial)).map_err(js_err)
}

/// Aggregate round-2 partials into threshold signature wire JSON.
#[wasm_bindgen(js_name = thresholdSigAggregate)]
pub fn threshold_sig_aggregate_wasm(
    public_key_json: JsValue,
    message: &[u8],
    commitments_json: JsValue,
    partials_json: JsValue,
) -> Result<JsValue, JsValue> {
    let profile = setup();
    let pk_value: serde_json::Value =
        serde_wasm_bindgen::from_value(public_key_json).map_err(js_err)?;
    let pk = public_key_from_json(&pk_value)?;
    let commitments_value: serde_json::Value =
        serde_wasm_bindgen::from_value(commitments_json).map_err(js_err)?;
    let partials_value: serde_json::Value =
        serde_wasm_bindgen::from_value(partials_json).map_err(js_err)?;
    let commitments = commitments_from_json(&commitments_value)?;
    let partials = partials_from_json(&partials_value)?;
    let agg = aggregate(&profile, &pk, message, &commitments, &partials).map_err(js_err)?;
    let sig_json = serde_json::json!({
        "rAggHex": hex_encode(&agg.signature.r_agg),
        "zHex": hex_encode(&agg.signature.z),
        "signers": agg.signature.signers,
    });
    let out = Object::new();
    set_prop(
        &out,
        "signature",
        &serde_wasm_bindgen::to_value(&sig_json).map_err(js_err)?,
    )?;
    set_prop(
        &out,
        "signatureBytesHex",
        &JsValue::from_str(&hex_encode(&agg.signature_bytes)),
    )?;
    set_prop(&out, "wire", &bytes_to_uint8_array(&agg.wire).into())?;
    Ok(out.into())
}

/// Verify threshold signature JSON against message and public key JSON.
#[wasm_bindgen(js_name = thresholdSigVerify)]
pub fn threshold_sig_verify_wasm(
    public_key_json: JsValue,
    message: &[u8],
    signature_json: JsValue,
) -> Result<bool, JsValue> {
    let profile = setup();
    let pk_value: serde_json::Value =
        serde_wasm_bindgen::from_value(public_key_json).map_err(js_err)?;
    let pk = public_key_from_json(&pk_value)?;
    let sig_value: serde_json::Value =
        serde_wasm_bindgen::from_value(signature_json).map_err(js_err)?;
    let signature = signature_from_json(&sig_value)?;
    verify(&profile, &pk, message, &signature).map_err(js_err)
}

/// Identify aborting signer indices from commitments and partials.
#[wasm_bindgen(js_name = thresholdSigIdentifyAbort)]
pub fn threshold_sig_identify_abort_wasm(
    public_key_json: JsValue,
    message: &[u8],
    commitments_json: JsValue,
    partials_json: JsValue,
) -> Result<JsValue, JsValue> {
    let profile = setup();
    let pk_value: serde_json::Value =
        serde_wasm_bindgen::from_value(public_key_json).map_err(js_err)?;
    let pk = public_key_from_json(&pk_value)?;
    let commitments_value: serde_json::Value =
        serde_wasm_bindgen::from_value(commitments_json).map_err(js_err)?;
    let partials_value: serde_json::Value =
        serde_wasm_bindgen::from_value(partials_json).map_err(js_err)?;
    let commitments = commitments_from_json(&commitments_value)?;
    let partials = partials_from_json(&partials_value)?;
    let bad = identify_abort(&profile, &pk, message, &commitments, &partials).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&bad).map_err(js_err)
}

/// Encode threshold signature wire v1 (`Uint8Array`).
#[wasm_bindgen(js_name = thresholdSigEncodeWireV1)]
pub fn threshold_sig_encode_wire_v1_wasm(
    signature_hex: &str,
    meta_hex: &str,
) -> Result<Uint8Array, JsValue> {
    let profile = setup();
    let signature = hex_decode(signature_hex)?;
    let meta = hex_decode(meta_hex)?;
    let wire = encode_threshold_sig_wire_v1(&profile, &signature, &meta).map_err(js_err)?;
    Ok(bytes_to_uint8_array(&wire))
}

/// Decode threshold signature wire v1 from `Uint8Array` to JSON.
#[wasm_bindgen(js_name = thresholdSigDecodeWireV1)]
pub fn threshold_sig_decode_wire_v1_wasm(wire: &[u8]) -> Result<JsValue, JsValue> {
    let profile = setup();
    let decoded = decode_threshold_sig_wire_v1(&profile, wire).map_err(js_err)?;
    let sig = decode_signature(&decoded.signature).map_err(js_err)?;
    let out = serde_json::json!({
        "signatureHex": hex_encode(&decoded.signature),
        "metaHex": hex_encode(&decoded.meta),
        "signature": {
            "rAggHex": hex_encode(&sig.r_agg),
            "zHex": hex_encode(&sig.z),
            "signers": sig.signers,
        },
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}
