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

        // Check if alloc feature is enabled (problematic for panic strategy)
        let _alloc_enabled = env::var("CARGO_FEATURE_ALLOC").is_ok();

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

        // Check if we're in CI environment
        let is_ci = env::var("CI").is_ok() || env::var("GITHUB_ACTIONS").is_ok();

        // Additional CI detection for various CI systems
        let is_ci_additional = env::var("BUILD_NUMBER").is_ok()  // Jenkins, TeamCity
            || env::var("TRAVIS").is_ok()  // Travis CI
            || env::var("CIRCLECI").is_ok()  // CircleCI
            || env::var("GITLAB_CI").is_ok()  // GitLab CI
            || env::var("AZURE_HTTP_USER_AGENT").is_ok(); // Azure Pipelines

        let is_ci_combined = is_ci || is_ci_additional;

        // Check if the no_std_panic_handler feature is explicitly enabled (not used in simplified logic)
        let _panic_handler_requested = env::var("CARGO_FEATURE_NO_STD_PANIC_HANDLER").is_ok();

        // Combine test detection methods (not used in simplified logic)
        let _in_test_mode = is_test || is_test_profile || has_test_deps;

        // Enable panic handler for no_std builds (including with alloc feature)
        // 1. std must be disabled (pure no_std build)
        // 2. Not in doctest mode (doctests use std)
        // Note: We enable panic handler for all no_std builds, but handle CI differently
        let is_no_std_build = !std_enabled && !is_doctest;

        // For CI environments, we need to be more careful about panic strategy
        if is_ci_combined {
            // In CI, disable panic handler entirely to avoid conflicts
            // RUSTFLAGS will handle panic strategy via -C panic=abort
            is_no_std_build
        } else {
            // For local builds, enable panic handler for all no_std builds
            is_no_std_build
        }
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
