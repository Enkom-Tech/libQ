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

    // Re-run if any of these files change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
