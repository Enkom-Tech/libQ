#![allow(clippy::disallowed_methods)]
// Allow use of std::env::var for reading Cargo-set environment variables
// This is safe because we only read variables set by Cargo itself

//! Build script for lib-q-ascon
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
        // CARGO_CFG_TEST is set when building test binaries, but may not be set during lib compilation
        let is_test = env::var("CARGO_CFG_TEST").is_ok();

        // Also check for other test-related environment variables
        let is_test_profile = env::var("PROFILE").unwrap_or_default() == "test";

        // Check if we're building with test dependencies (common test libraries)
        let has_test_deps =
            env::var("CARGO_FEATURE_TEST").is_ok() || env::var("CARGO_FEATURE_PROC_MACRO").is_ok();

        // Check if we're in doctest mode
        let is_doctest = env::var("CARGO_CFG_DOCTEST").is_ok();

        // Check if the no_std_panic_handler feature is explicitly enabled
        let panic_handler_requested = env::var("CARGO_FEATURE_NO_STD_PANIC_HANDLER").is_ok();

        // Combine test detection methods
        let in_test_mode = is_test || is_test_profile || has_test_deps;

        // Enable panic handler for no_std builds, with some exceptions
        // 1. std is disabled (no_std build) OR panic handler is explicitly requested
        // 2. Not in doctest mode (doctests use std)
        (!std_enabled || panic_handler_requested) && !is_doctest
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
