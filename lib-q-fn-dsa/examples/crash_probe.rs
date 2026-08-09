// Subprocess harness for the RED/GREEN check of the FnDsa512::sign type-confusion fix.
// Run as a separate process (not a #[test]) because the PRE-FIX behavior can abort the
// process (observed here as a clean panic+exit(101), but the audit finding describes a
// stack-overflow abort on some configurations) -- isolating it in its own process means a
// crash here cannot take down the enclosing `cargo test` harness.
use lib_q_fn_dsa::{
    FnDsa512,
    FnDsa1024,
    Signature,
};

fn main() {
    let fn_dsa_1024 = FnDsa1024::new();
    let keypair_1024 = fn_dsa_1024.generate_keypair().expect("1024 keygen");
    assert_eq!(
        keypair_1024.secret_key.as_bytes().len(),
        2305,
        "sanity: FN-DSA-1024 sk length"
    );

    // Feed the FN-DSA-1024 secret key into the FN-DSA-512 API.
    let fn_dsa_512 = FnDsa512::new();
    match fn_dsa_512.sign(&keypair_1024.secret_key, b"crash probe message") {
        Err(e) => {
            println!("OK_CLEAN_ERR: {e:?}");
            std::process::exit(0);
        }
        Ok(_) => {
            println!("BUG: sign() succeeded on a mismatched-degree key");
            std::process::exit(1);
        }
    }
}
