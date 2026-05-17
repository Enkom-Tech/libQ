#[cfg(feature = "random")]
use lib_q_ml_dsa::ml_dsa_44::*;
#[cfg(feature = "random")]
use lib_q_random::LibQRng;
#[cfg(feature = "random")]
use rand_core::Rng;

#[cfg(feature = "random")]
fn random_array<const L: usize>() -> [u8; L] {
    let mut rng = LibQRng::new_secure().expect("Failed to create secure RNG");
    let mut seed = [0; L];
    rng.fill_bytes(&mut seed);
    seed
}

#[cfg(feature = "random")]
fn main() {
    let key_generation_seed = random_array();
    let signing_randomness = random_array();
    let message = random_array::<1023>();

    let keypair = generate_key_pair(key_generation_seed);

    for _i in 0..100_000 {
        let _ = core::hint::black_box(sign(
            &keypair.signing_key,
            &message,
            b"",
            signing_randomness,
        ));
    }
}

#[cfg(not(feature = "random"))]
fn main() {
    println!("This example requires the 'random' feature to be enabled");
    println!("Run with: cargo run --example sign_44 --features random");
}
