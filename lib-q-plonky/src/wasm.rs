//! WASM bindings: Plonky3-derived STARK component metadata.

#![allow(missing_docs)]

use wasm_bindgen::prelude::*;

/// Crate version string for integration checks.
#[wasm_bindgen(js_name = plonkyPackageVersion)]
pub fn plonky_package_version() -> JsValue {
    JsValue::from_str(env!("CARGO_PKG_VERSION"))
}
