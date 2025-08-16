fn main() {
    // Set getrandom configuration for WASM targets
    #[allow(clippy::disallowed_methods)]
    let target = std::env::var("TARGET").unwrap_or_default();
    
    if target.contains("wasm32") {
        println!("cargo:rustc-cfg=getrandom_backend=\"wasm_js\"");
        println!("cargo:rerun-if-env-changed=TARGET");
    }
}
