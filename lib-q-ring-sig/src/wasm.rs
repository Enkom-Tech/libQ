//! WASM bindings: pilot DualRing-LB singleton (fixed CRS, ring of one) for integration smoke tests.

#![allow(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::{
    format,
    vec,
};

use lib_q_lattice_zkp::serialize::{
    read_module_vec,
    write_module_vec,
};
use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
    OpeningProof,
    commit,
};
use lib_q_random::new_secure_rng;
use lib_q_ring::{
    ModuleVec,
    Poly,
};
use serde::{
    Deserialize,
    Serialize,
};
use wasm_bindgen::prelude::*;

use crate::dualring_lb::{
    DualRingLbSignature,
    sign_dualring_lb,
    verify_dualring_lb,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_RING_SIG", e)
}

fn pilot_crs() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: [0x5Du8; 32],
        params: AjtaiParameters::new(2, 1),
    }
}

fn pilot_opening() -> AjtaiOpening {
    AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    }
}

const PILOT_TAU: usize = 39;
const PILOT_Z_INF: i32 = 20_000_000;
const PILOT_MAX_ATTEMPTS: usize = 512;

#[derive(Serialize, Deserialize)]
struct PilotProofWire {
    w_hex: String,
    z_hex: String,
}

fn encode_sig(sig: &DualRingLbSignature) -> Result<JsValue, JsValue> {
    let w = write_module_vec(&sig.opening_proof.w.0);
    let z = write_module_vec(&sig.opening_proof.z.0);
    let wire = PilotProofWire {
        w_hex: hex::encode(w),
        z_hex: hex::encode(z),
    };
    serde_wasm_bindgen::to_value(&wire).map_err(js_err)
}

fn decode_sig_from_wire(wire: PilotProofWire) -> Result<DualRingLbSignature, JsValue> {
    let wb = hex::decode(wire.w_hex.trim()).map_err(js_err)?;
    let zb = hex::decode(wire.z_hex.trim()).map_err(js_err)?;
    let w = ModuleVec(read_module_vec(&wb).map_err(|e| js_err(format!("{e:?}")))?);
    let z = ModuleVec(read_module_vec(&zb).map_err(|e| js_err(format!("{e:?}")))?);
    Ok(DualRingLbSignature {
        opening_proof: OpeningProof { w, z },
    })
}

/// Sign a message with a **fixed pilot** CRS and singleton ring (same layout as crate unit tests).
///
/// This is intended for wasm-bindgen smoke tests and tooling, not general-purpose federation APIs.
#[wasm_bindgen(js_name = ringSigPilotSingletonSign)]
pub fn ring_sig_pilot_singleton_sign(message: &[u8]) -> Result<JsValue, JsValue> {
    let key = pilot_crs();
    let o = pilot_opening();
    let com = commit(&key, &o);
    let ring = [com.clone()];
    let mut rng = new_secure_rng().map_err(js_err)?;
    let sig = sign_dualring_lb(
        &mut rng,
        &key,
        &o,
        &com,
        &ring,
        message,
        PILOT_TAU,
        PILOT_Z_INF,
        PILOT_MAX_ATTEMPTS,
    )
    .map_err(|e| js_err(format!("{e:?}")))?;
    encode_sig(&sig)
}

/// Verify a proof from [`ring_sig_pilot_singleton_sign`] for the same pilot singleton ring.
#[wasm_bindgen(js_name = ringSigPilotSingletonVerify)]
pub fn ring_sig_pilot_singleton_verify(message: &[u8], proof: JsValue) -> Result<bool, JsValue> {
    let key = pilot_crs();
    let o = pilot_opening();
    let com = commit(&key, &o);
    let ring = [com];
    let wire: PilotProofWire = serde_wasm_bindgen::from_value(proof).map_err(js_err)?;
    let sig = decode_sig_from_wire(wire)?;
    Ok(verify_dualring_lb(&key, &ring, message, &sig, PILOT_TAU, PILOT_Z_INF).is_ok())
}
