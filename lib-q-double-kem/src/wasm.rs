//! WASM bindings for MAUL v1 double ML-KEM (`@lib-q/double-kem`).

#![allow(missing_docs)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use js_sys::Uint8Array;
use lib_q_ml_kem::{
    Encoded,
    EncodedSizeUser,
    KemCore,
    MlKem768,
};
use lib_q_random::new_secure_rng;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    DoubleKemError,
    MaulEncapWire,
    MaulProfileV1,
    WIRE_BUDGET_MAUL_ENCAP_BYTES,
    ck_fo_upgrade,
    double_decap,
    double_encap,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_DOUBLE_KEM", e)
}

fn bytes_to_uint8_array(secret: &[u8]) -> Uint8Array {
    let n = u32::try_from(secret.len()).expect("length exceeds Uint8Array maximum");
    let out = Uint8Array::new_with_length(n);
    out.copy_from(secret);
    out
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

fn decode_ek(bytes: &[u8]) -> Result<<MlKem768 as KemCore>::EncapsulationKey, JsValue> {
    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    let encoded =
        Encoded::<Ek>::try_from(bytes).map_err(|_| js_err(DoubleKemError::InvalidWireEncoding))?;
    Ok(Ek::from_bytes(&encoded))
}

fn decode_dk(bytes: &[u8]) -> Result<<MlKem768 as KemCore>::DecapsulationKey, JsValue> {
    type Dk = <MlKem768 as KemCore>::DecapsulationKey;
    let encoded =
        Encoded::<Dk>::try_from(bytes).map_err(|_| js_err(DoubleKemError::InvalidWireEncoding))?;
    Ok(Dk::from_bytes(&encoded))
}

/// Fixed MAUL wire size in bytes (1260).
#[wasm_bindgen(js_name = doubleKemWireBytes)]
pub fn double_kem_wire_bytes() -> u32 {
    WIRE_BUDGET_MAUL_ENCAP_BYTES as u32
}

/// Domain-separated CK/FO upgrade of two 32-byte shared secrets.
#[wasm_bindgen(js_name = doubleKemCkFoUpgrade)]
pub fn double_kem_ck_fo_upgrade(ss_a: &[u8], ss_b: &[u8]) -> Result<Uint8Array, JsValue> {
    if ss_a.len() != 32 || ss_b.len() != 32 {
        return Err(js_err("shared secrets must be exactly 32 bytes"));
    }
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(ss_a);
    b.copy_from_slice(ss_b);
    let upgraded = ck_fo_upgrade(&a, &b);
    Ok(bytes_to_uint8_array(&upgraded))
}

/// Parse fixed-size MAUL wire from `Uint8Array` (1260 bytes).
#[wasm_bindgen(js_name = doubleKemWireFromBytes)]
pub fn double_kem_wire_from_bytes(wire: &[u8]) -> Result<Uint8Array, JsValue> {
    let parsed = MaulEncapWire::from_bytes(wire).map_err(js_err)?;
    Ok(bytes_to_uint8_array(&parsed.to_bytes()))
}

/// Serialize MAUL wire to canonical 1260-byte `Uint8Array`.
#[wasm_bindgen(js_name = doubleKemWireToBytes)]
pub fn double_kem_wire_to_bytes(wire: &[u8]) -> Result<Uint8Array, JsValue> {
    double_kem_wire_from_bytes(wire)
}

/// Double encapsulation using hex-encoded ML-KEM-768 public keys.
/// Returns JSON `{ wireHex, sharedSecretHex }`.
#[wasm_bindgen(js_name = doubleKemEncapHex)]
pub fn double_kem_encap_hex(ek_a_hex: &str, ek_b_hex: &str) -> Result<JsValue, JsValue> {
    let ek_a = decode_ek(&hex_decode(ek_a_hex)?)?;
    let ek_b = decode_ek(&hex_decode(ek_b_hex)?)?;
    let mut rng = new_secure_rng().map_err(js_err)?;
    let (wire, shared) = double_encap(MaulProfileV1, &ek_a, &ek_b, &mut rng).map_err(js_err)?;
    let wire_bytes = wire.to_bytes();
    let out = serde_json::json!({
        "wireHex": hex_encode(&wire_bytes),
        "sharedSecretHex": hex_encode(&shared),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Double decapsulation using hex-encoded ML-KEM-768 secret keys and wire bytes.
/// Returns upgraded shared secret as `Uint8Array` (32 bytes).
#[wasm_bindgen(js_name = doubleKemDecap)]
pub fn double_kem_decap(
    wire: &[u8],
    dk_a_hex: &str,
    dk_b_hex: &str,
) -> Result<Uint8Array, JsValue> {
    let parsed = MaulEncapWire::from_bytes(wire).map_err(js_err)?;
    let dk_a = decode_dk(&hex_decode(dk_a_hex)?)?;
    let dk_b = decode_dk(&hex_decode(dk_b_hex)?)?;
    let shared = double_decap(MaulProfileV1, &parsed, &dk_a, &dk_b).map_err(js_err)?;
    Ok(bytes_to_uint8_array(Zeroizing::new(shared).as_ref()))
}
