#![allow(clippy::disallowed_methods)]

use std::env;
use std::process::Command;

/// Match `lib-q-keccak`'s `keccak_portable_simd` gating: portable SIMD Keccak batch paths need
/// nightly. Dependent crates do not inherit that cfg, so we mirror the same `rustc -vV` check here
/// for call sites that use `lib_q_keccak::advanced::parallel`.
fn rustc_release_is_nightly() -> bool {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = match Command::new(rustc).args(["-vV"]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return false,
    };
    let stdout = String::from_utf8_lossy(&output);
    stdout
        .lines()
        .find(|line| line.starts_with("release:"))
        .is_some_and(|line| line.contains("nightly"))
}

fn main() {
    // Set custom cfg flags to help IDE understand conditional compilation
    if cfg!(feature = "simd256") {
        println!("cargo:rustc-cfg=feature=\"simd256\"");
    }
    if cfg!(feature = "simd128") {
        println!("cargo:rustc-cfg=feature=\"simd128\"");
    }

    // Add check-cfg for eurydice to suppress warnings
    println!("cargo:rustc-check-cfg=cfg(eurydice)");
    println!("cargo:rustc-check-cfg=cfg(ml_dsa_keccak_portable_simd)");

    if rustc_release_is_nightly() {
        println!("cargo:rustc-cfg=ml_dsa_keccak_portable_simd");
    }

    // Re-run if any of these files change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
