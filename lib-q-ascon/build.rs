/// Build script for lib-q-ascon
///
/// This build script ensures proper conditional compilation for no_std environments.
/// It provides additional configuration options beyond what Cargo features can handle.
use std::env;

fn main() {
    // Get build configuration from environment
    let target = env::var("TARGET").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();

    // Emit configuration for conditional compilation
    println!("cargo:rustc-check-cfg=cfg(target_arch, values(\"x86_64\", \"aarch64\", \"arm\"))");
    println!("cargo:rustc-check-cfg=cfg(target_os, values(\"linux\", \"windows\", \"macos\"))");
    println!("cargo:rustc-check-cfg=cfg(build_profile, values(\"debug\", \"release\"))");

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
