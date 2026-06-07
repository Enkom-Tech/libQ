#![no_main]

use lib_q_threshold_sig::{
    Round1Commitment,
    Round2Partial,
    identify_abort,
    keygen_shares,
    setup,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let profile = setup();
    let mut rng = lib_q_random::new_deterministic_rng([0xA5; 32]);
    let keygen = match keygen_shares(&profile, 3, 5, &mut rng) {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut commitments = Vec::<Round1Commitment>::new();
    let mut partials = Vec::<Round2Partial>::new();

    let chunk = 1 + 32 + 32 + 32;
    let mut cursor = 0usize;
    while cursor + chunk <= data.len() && commitments.len() < 5 {
        let index = (data[cursor] % 5) + 1;
        cursor += 1;

        let mut nonce_commitment = [0u8; 32];
        nonce_commitment.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;

        let mut binding = [0u8; 32];
        binding.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;

        let mut z = [0u8; 32];
        z.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;

        commitments.push(Round1Commitment {
            index,
            nonce_commitment,
            binding,
        });
        partials.push(Round2Partial {
            index,
            z,
            proof: [0u8; 32],
        });
    }

    let _ = identify_abort(
        &profile,
        &keygen.public_key,
        b"fuzz-identify-abort",
        commitments.as_slice(),
        partials.as_slice(),
    );
});
