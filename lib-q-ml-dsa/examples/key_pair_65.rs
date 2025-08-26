use lib_q_ml_dsa::ml_dsa_65;
use rand::TryRngCore;
use rand::rngs::OsRng;

fn random_array<const L: usize>() -> [u8; L] {
    let mut rng = OsRng;
    let mut seed = [0; L];
    rng.try_fill_bytes(&mut seed).unwrap();
    seed
}

fn main() {
    let key_generation_seed = random_array();

    for _i in 0..10 {
        let keypair = ml_dsa_65::generate_key_pair(key_generation_seed);
        println!(
            "Generated keypair {}: verification key len = {}, signing key len = {}",
            _i,
            keypair.verification_key.as_slice().len(),
            keypair.signing_key.as_slice().len()
        );
    }
}
