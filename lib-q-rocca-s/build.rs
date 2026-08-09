#![allow(clippy::disallowed_methods)]
// Allow use of std::env::var for reading Cargo-set environment variables: this build
// script only reads `CARGO_CFG_TARGET_ARCH` / `CARGO_FEATURE_*`, both set by Cargo
// itself (not attacker/user-controlled), and `cfg!(...)` cannot see the TARGET arch
// during cross-compilation (it reflects the build script's own HOST compile), so the
// env vars are the only correct way to ask "what is this build actually targeting".

//! Build-time signal for the constant-time AES-backend wiring (finding F4 / card
//! t_3d6e8d50): the scalar AES round in `src/round.rs` is a table-based S-box and is
//! NOT constant-time; the `simd-aesni`/`simd-neon` backends are, but both require
//! `std` (they use `is_x86_feature_detected!` / `std::arch::is_aarch64_feature_detected!`).
//!
//! `simd` is in this crate's Cargo `default` (see `Cargo.toml`), so a normal `std`
//! build already gets the constant-time backend without needing this script. This
//! build script exists for the two cases where a consumer overrides that:
//!   1. `std` enabled but `simd-aesni`/`simd-neon` explicitly stripped on a target
//!      that could use them — a real (if unusual) regression of the wiring this crate
//!      ships by default.
//!   2. genuine `no_std` (`std` feature absent) — the hardware backends are
//!      *structurally impossible* here (they need `std::arch`), so the scalar,
//!      not-constant-time path is unconditional. This is an inherent limitation, not
//!      a wiring bug, but it must not be silent.
//!
//! Neither case can fail the build (a build script cannot fail a downstream
//! consumer's compile just because it made a feature choice), so both are surfaced
//! as `cargo:warning=` lines, which `cargo build`/`cargo test` print unconditionally.

fn has_env(name: &str) -> bool {
    std::env::var(name).is_ok()
}

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let hw_capable_target = matches!(target_arch.as_str(), "x86" | "x86_64" | "aarch64");

    if !hw_capable_target {
        // No hardware AES backend exists for this architecture at all (e.g. RISC-V,
        // wasm32): the scalar path is the only option regardless of features. Not a
        // wiring defect — nothing to warn about beyond the in-source doc comment.
        return;
    }

    let std_enabled = has_env("CARGO_FEATURE_STD");
    let simd_enabled = has_env("CARGO_FEATURE_SIMD_AESNI") || has_env("CARGO_FEATURE_SIMD_NEON");

    if !std_enabled {
        println!(
            "cargo:warning=lib-q-rocca-s: building WITHOUT the `std` feature on {target_arch}. \
             The hardware AES backends (AES-NI / ARMv8 AES) require `std` for CPU feature \
             detection and cannot be built here, so this build uses the scalar, table-based \
             AES S-box unconditionally, which is NOT constant-time (see src/round.rs). This is \
             an inherent no_std limitation, not a feature-wiring bug — if this build must be \
             constant-time on this hardware, it needs a `std` environment."
        );
    } else if !simd_enabled {
        println!(
            "cargo:warning=lib-q-rocca-s: building on {target_arch} WITH `std` but WITHOUT the \
             `simd` feature (or its `simd-aesni`/`simd-neon` components). This crate's own \
             `default` feature set includes `simd`; a consumer depending on it with \
             `default-features = false` and not re-adding `simd` will run the scalar, \
             table-based AES S-box, which is NOT constant-time (see src/round.rs, finding F4 / \
             card t_3d6e8d50)."
        );
    }
}
