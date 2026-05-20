//! WASM bindings: ring constants and ML-DSA–compatible dimension metadata.

#![allow(missing_docs)]

use wasm_bindgen::prelude::*;

use crate::constants::{
    COEFFICIENTS_IN_RING_ELEMENT,
    FIELD_MODULUS,
};

/// Ring dimension `N` (coefficients per polynomial), matching FIPS 204 ML-DSA.
#[wasm_bindgen(js_name = ringCoefficientCount)]
pub fn ring_coefficient_count() -> u32 {
    COEFFICIENTS_IN_RING_ELEMENT as u32
}

/// Modulus `q` for \(R_q = Z_q[X]/(X^{256}+1)\).
#[wasm_bindgen(js_name = ringModulusQ)]
pub fn ring_modulus_q() -> u32 {
    FIELD_MODULUS as u32
}
