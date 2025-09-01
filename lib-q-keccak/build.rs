#![allow(clippy::disallowed_methods)]
// Allow use of std::env::var for reading Cargo-set environment variables
// This is safe because we only read variables set by Cargo itself

//! Build script for lib-q-keccak
//!
//! This build script ensures proper conditional compilation for no_std environments.
//! It provides additional configuration options beyond what Cargo features can handle.

use std::env;
fn main() {
    // Get build configuration from environment
    // These are Cargo-set environment variables and are safe to read
    let target = env::var("TARGET").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();

    // Check if we should enable the panic handler
    // Only enable for pure no_std builds to avoid CI conflicts
    let should_enable_panic_handler = {
        // Check if std feature is disabled
        let std_enabled = env::var("CARGO_FEATURE_STD").is_ok();

        // Check if we're in test mode
        let is_test = env::var("CARGO_CFG_TEST").is_ok();

        // Check if we're in doctest mode
        let is_doctest = env::var("CARGO_CFG_DOCTEST").is_ok();

        // Check if we're building docs
        let is_docsrs = env::var("DOCS_RS").is_ok();

        // Check if the no_std_panic_handler feature is explicitly enabled
        let panic_handler_requested = env::var("CARGO_FEATURE_NO_STD_PANIC_HANDLER").is_ok();

        // Enable panic handler only if:
        // 1. std is disabled (no_std build)
        // 2. Not in test mode
        // 3. Not in doctest mode
        // 4. Not building docs
        // 5. Panic handler is explicitly requested (for CI no_std tests)
        !std_enabled && !is_test && !is_doctest && !is_docsrs && panic_handler_requested
    };

    if should_enable_panic_handler {
        println!("cargo:rustc-cfg=panic_handler_enabled");
    }

    // Emit configuration for conditional compilation
    println!("cargo:rustc-check-cfg=cfg(target_arch, values(\"x86_64\", \"aarch64\", \"arm\"))");
    println!("cargo:rustc-check-cfg=cfg(target_os, values(\"linux\", \"windows\", \"macos\"))");
    println!("cargo:rustc-check-cfg=cfg(build_profile, values(\"debug\", \"release\"))");
    println!("cargo:rustc-check-cfg=cfg(panic_handler_enabled)");

    // Set build profile configuration
    println!("cargo:rustc-cfg=build_profile=\"{}\"", profile);

    // Additional build information for debugging
    println!("cargo:rustc-env=BUILD_TARGET={}", target);
    println!("cargo:rustc-env=BUILD_PROFILE={}", profile);

    // Ensure rebuild when build script changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=PROFILE");
}
