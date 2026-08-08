// PLANTED 6: build.rs compiles against the same feature set and is easy to forget.
fn main() {
    if cfg!(feature = "ghost_buildrs") {
        println!("cargo:rerun-if-changed=build.rs");
    }
}
