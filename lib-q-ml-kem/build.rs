//! Select `cdylib` only for WebAssembly so host and `#![no_std]` dependents can link `rlib`
//! without a global allocator. `wasm-pack` / npm builds target `wasm32-unknown-unknown`.

#![allow(clippy::disallowed_methods)] // `std::env::var("TARGET")` is the supported Cargo build-script API.

fn main() {
    let target = std::env::var("TARGET").expect("TARGET must be set by Cargo");
    println!("cargo:rerun-if-env-changed=TARGET");
    if target.contains("wasm32") {
        println!("cargo:rustc-crate-type=cdylib,rlib");
    }
}
