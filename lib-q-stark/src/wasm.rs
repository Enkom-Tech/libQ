//! WASM bindings: STARK framework metadata (full prove/verify via `@lib-q/zkp`).

#![allow(missing_docs)]

use wasm_bindgen::prelude::*;

/// Crate version string for integration checks.
#[wasm_bindgen(js_name = starkPackageVersion)]
pub fn stark_package_version() -> JsValue {
    JsValue::from_str(env!("CARGO_PKG_VERSION"))
}
