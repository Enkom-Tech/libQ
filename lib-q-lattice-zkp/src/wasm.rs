//! WASM bindings: fixed-seed Ajtai commitment smoke test for integration wiring.

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

fn smoke_commitment_key() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: [0xA1u8; 32],
        params: AjtaiParameters::new(2, 1),
    }
}

fn smoke_opening() -> AjtaiOpening {
    AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    }
}

/// Hex-encoded Ajtai commitment for a zero opening (smoke / wiring check).
#[wasm_bindgen(js_name = latticeZkpPilotCommitHex)]
pub fn lattice_zkp_pilot_commit_hex() -> Result<JsValue, JsValue> {
    let key = smoke_commitment_key();
    let opening = smoke_opening();
    let com = commit(&key, &opening);
    let bytes = write_module_vec(&com.value.0);
    Ok(JsValue::from_str(&hex::encode(bytes)))
}
