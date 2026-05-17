//! Dev-only: print hex for KAT (`cargo run -p lib-q-tweak-aead --example dump_tweak_kat`).
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    let mut out = [0u8; 4 + 32];
    lib_q_tweak_aead::crypto::encrypt(&key, &nonce, b"", b"libQ", &mut out).unwrap();
    println!("{}", to_hex(&out));
}
