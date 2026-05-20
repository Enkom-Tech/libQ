//! WASM bindings: pilot Ajtai commitment smoke (fixed CRS) for integration tests.

#![allow(missing_docs)]

extern crate alloc;

use alloc::vec;

use lib_q_ring::{
    ModuleVec,
    Poly,
};
use wasm_bindgen::prelude::*;

use crate::serialize::write_module_vec;
use crate::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
    commit,
};

fn pilot_crs() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: [0xA1u8; 32],
        params: AjtaiParameters::new(2, 1),
    }
}

fn pilot_opening() -> AjtaiOpening {
    AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    }
}

/// Hex-encoded Ajtai commitment for a zero pilot opening (smoke / wiring check).
#[wasm_bindgen(js_name = latticeZkpPilotCommitHex)]
pub fn lattice_zkp_pilot_commit_hex() -> Result<JsValue, JsValue> {
    let crs = pilot_crs();
    let opening = pilot_opening();
    let com = commit(&crs, &opening);
    let bytes = write_module_vec(&com.value.0);
    Ok(JsValue::from_str(&hex::encode(bytes)))
}
