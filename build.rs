fn main() {
    // Set getrandom configuration for WASM targets
    #[allow(clippy::disallowed_methods)]
    if std::env::var("TARGET")
        .unwrap_or_default()
        .contains("wasm32")
    {
        println!("cargo:rustc-cfg=getrandom_wasm_js");
    }
}
