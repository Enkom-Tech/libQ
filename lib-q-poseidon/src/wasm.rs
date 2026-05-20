//! WASM bindings: Poseidon-128 sponge smoke over the STARK field.

#![allow(missing_docs)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_stark_field::PrimeField32;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;
use wasm_bindgen::prelude::*;

use crate::{
    Poseidon,
    Poseidon128,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_POSEIDON", e)
}

type Val = Complex<Mersenne31>;

fn m31(u: u32) -> Mersenne31 {
    Mersenne31::new(u)
}

/// Poseidon-128 hash of `[1, 2]` field elements; returns hex of the first output limb (real||imag canonical u32).
#[wasm_bindgen(js_name = poseidon128Hash12Hex)]
pub fn poseidon128_hash_12_hex() -> Result<JsValue, JsValue> {
    let input: Vec<Val> = vec![Val::from(m31(1)), Val::from(m31(2))];
    let out = Poseidon128.hash(&input);
    let first = out.first().ok_or_else(|| js_err("empty hash output"))?;
    let hex_out = alloc::format!(
        "{:08x}{:08x}",
        first.real().as_canonical_u32(),
        first.imag().as_canonical_u32()
    );
    Ok(JsValue::from_str(&hex_out))
}
