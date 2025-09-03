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

        // Check if alloc feature is enabled (problematic for panic strategy)
        let _alloc_enabled = env::var("CARGO_FEATURE_ALLOC").is_ok();

        // Enhanced test mode detection
        let is_test = env::var("CARGO_CFG_TEST").is_ok();
        let is_test_profile = env::var("PROFILE").unwrap_or_default() == "test";
        let is_doctest = env::var("CARGO_CFG_DOCTEST").is_ok();
        
        // Check for test-related Cargo commands and environment variables
        let has_test_deps = env::var("CARGO_FEATURE_TEST").is_ok() 
            || env::var("CARGO_FEATURE_PROC_MACRO").is_ok();
        
        // Detect when building for tests by checking command line arguments
        let cargo_args: Vec<String> = env::args().collect();
        let is_cargo_test = cargo_args.iter().any(|arg| 
            arg.contains("test") || 
            arg.contains("--test") || 
            arg.contains("lib test") ||
            arg.contains("bin test")
        );

        // Check for testing environment indicators
        let is_testing_env = env::var("RUST_TEST_NOCAPTURE").is_ok() 
            || env::var("RUST_TEST_THREADS").is_ok()
            || env::var("CARGO_TARGET_DIR").unwrap_or_default().contains("test");

        // Check the Cargo primary package to see if it's in test mode
        let cargo_primary_package = env::var("CARGO_PRIMARY_PACKAGE").is_ok();
        let is_building_tests = cargo_primary_package && (
            env::var("CARGO_CRATE_NAME").unwrap_or_default().contains("test") ||
            env::var("CARGO_BIN_NAME").unwrap_or_default().contains("test")
        );

        // CI environment detection  
        let is_ci = env::var("CI").is_ok() || env::var("GITHUB_ACTIONS").is_ok();
        let is_ci_additional = env::var("BUILD_NUMBER").is_ok()  // Jenkins, TeamCity
            || env::var("TRAVIS").is_ok()  // Travis CI
            || env::var("CIRCLECI").is_ok()  // CircleCI
            || env::var("GITLAB_CI").is_ok()  // GitLab CI
            || env::var("AZURE_HTTP_USER_AGENT").is_ok(); // Azure Pipelines
        let _is_ci_combined = is_ci || is_ci_additional;

        // Comprehensive test mode detection
        let in_test_mode = is_test 
            || is_test_profile 
            || is_doctest 
            || has_test_deps 
            || is_cargo_test 
            || is_testing_env
            || is_building_tests;

        // Clean up unused variables - keeping the comprehensive detection for future use
        let _is_pure_no_std_build = !std_enabled && !in_test_mode;

        // Detect if we're building for tests by checking the target directory or build context  
        // This is a more reliable approach than trying to detect cargo test command
        let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_default();
        let out_dir = env::var("OUT_DIR").unwrap_or_default();
        let _is_test_build = target_dir.contains("test") || out_dir.contains("test") || 
                           env::var("CARGO_PKG_NAME").unwrap_or_default() == "lib-q-keccak";

        // Enable panic handler for legitimate no_std builds, but be conservative about tests
        let result = if !std_enabled {
            // For no_std builds: only enable panic handler when explicitly requested
            // This prevents conflicts with test harness which always uses std
            env::var("CARGO_FEATURE_NO_STD_PANIC_HANDLER").is_ok()
        } else {
            // For std builds, never enable custom panic handler
            false
        };

        // Optional debug output (uncomment for troubleshooting)
        // println!("cargo:warning=std_enabled: {}", std_enabled);
        // println!("cargo:warning=in_test_mode: {}", in_test_mode);
        // println!("cargo:warning=should_enable_panic_handler: {}", result);
        
        result
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
