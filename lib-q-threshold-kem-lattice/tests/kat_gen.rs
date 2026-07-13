//! Fixture generator for the pinned KATs in `kat.rs` (kept in a separate test binary so it
//! compiles even when `tests/data/` does not exist yet).
//!
//! Run explicitly (release; only after an INTENTIONAL wire break — regenerating invalidates the
//! frozen v1 vectors):
//!
//! ```text
//! cargo test -p lib-q-threshold-kem-lattice --release --test kat_gen -- --ignored --nocapture
//! ```
//!
//! It rewrites `tests/data/kat_*.bin` and prints the digest pins to paste into `kat.rs`.

use lib_q_random::new_deterministic_rng;
use lib_q_threshold_kem_lattice::{
    keygen_shares,
    setup,
};

const THRESHOLD: u8 = 3;
const PARTIES: u8 = 5;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "regenerates the frozen v1 KAT fixtures — run only on an intentional wire break"]
fn regenerate_fixtures_and_print_pins() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");
    std::fs::create_dir_all(dir).expect("create tests/data");

    let profile = setup();
    let mut rng = new_deterministic_rng([0xC7u8; 32]);
    let kg = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");

    std::fs::write(format!("{dir}/kat_pk_v1.bin"), &kg.public_key.t0_bytes).expect("write pk");
    for share in kg.secret_shares.iter().take(usize::from(THRESHOLD)) {
        std::fs::write(
            format!("{dir}/kat_share_{}_v1.bin", share.index),
            share.share_bytes.as_slice(),
        )
        .expect("write share");
    }

    // Pins for kat.rs (the KAT itself recomputes these on the integer-only FO path).
    let t0 = kg.public_key.t0().expect("t0");
    let mu: [u8; 32] = core::array::from_fn(|i| i as u8);
    let ct = lib_q_threshold_kem_lattice::kem::encapsulate_derand(&t0, &mu);
    let ss = lib_q_threshold_kem_lattice::kem::kdf(&t0, &mu, &ct);
    println!("profile digest : {}", hex(&profile.parameter_set_digest));
    println!(
        "ct sha3-256    : {}",
        hex(&lib_q_sha3::sha3_256(&ct.to_bytes()))
    );
    println!("shared secret  : {}", hex(&ss));
}
