#![allow(clippy::disallowed_methods)]
// Allow use of std::env::var for reading Cargo-set environment variables
// This is safe because we only read variables set by Cargo itself

//! Build script for lib-q-keccak
//!
//! This build script provides configuration for conditional compilation.

use std::env;
use std::process::Command;

/// `core::simd` / `#![feature(portable_simd)]` are only available on nightly. CI uses stable with
/// `--all-features`, so we only enable the portable-SIMD cfg when the `simd` feature is on *and* the
/// active `rustc` reports a nightly `release:` line in `rustc -vV`.
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
    // Get build configuration from environment
    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();

    // Emit configuration for conditional compilation
    println!("cargo:rustc-check-cfg=cfg(target_arch, values(\"x86_64\", \"aarch64\", \"arm\"))");
    println!("cargo:rustc-check-cfg=cfg(target_os, values(\"linux\", \"windows\", \"macos\"))");
    println!("cargo:rustc-check-cfg=cfg(build_profile, values(\"debug\", \"release\"))");
    println!("cargo:rustc-check-cfg=cfg(keccak_portable_simd)");
    println!("cargo:rustc-check-cfg=cfg(cross_compile)");

    // Detect cross-compilation: host and target triples differ.
    // Used to gate platform-specific asm paths (x86 AVX2/AVX-512) that require
    // native hardware for runtime feature detection.
    if host != target {
        println!("cargo:rustc-cfg=cross_compile");
    }

    let simd_requested = env::var_os("CARGO_FEATURE_SIMD").is_some();
    if simd_requested && rustc_release_is_nightly() {
        println!("cargo:rustc-cfg=keccak_portable_simd");
    }

    // Set build profile configuration
    println!("cargo:rustc-cfg=build_profile=\"{profile}\"");

    // Additional build information for debugging
    println!("cargo:rustc-env=BUILD_TARGET={target}");
    println!("cargo:rustc-env=BUILD_PROFILE={profile}");

    // Ensure rebuild when build script changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=HOST");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=PROFILE");
}
