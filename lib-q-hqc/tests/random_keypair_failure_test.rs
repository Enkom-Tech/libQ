//! Test to reproduce the 1-2% HQC decapsulation failure with random keypairs
//! as reported by the user.

use lib_q_hqc::Hqc128Kem;
use lib_q_hqc::concatenated_code::ConcatenatedCode;
use lib_q_hqc::hqc_pke::schoolbook_vect_mul_mod_xnm1;
use lib_q_hqc::params_correct::{
    Hqc1Params,
    HqcParams,
};
use lib_q_random::LibQRng;
use rand_core::Rng;

#[test]
#[ignore]
fn test_random_keypair_failures_hqc128() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    let concat_code: ConcatenatedCode<Hqc1Params> = ConcatenatedCode::new().unwrap();

    const N: usize = Hqc1Params::N;
    const VEC_N_SIZE_64: usize = Hqc1Params::VEC_N_SIZE_64;
    const VEC_N1N2_SIZE_64: usize = Hqc1Params::VEC_N1N2_SIZE_64;
    const N1N2: usize = Hqc1Params::N1N2;

    let mut rng = LibQRng::new_secure().expect("RNG");

    let total_trials = 500;
    let mut failures = 0;
    let mut failure_noise_weights = Vec::new();
    let mut success_noise_weights = Vec::new();

    for trial in 0..total_trials {
        // Generate a RANDOM keypair each time (like the user's reproduction)
        let mut key_seed = [0u8; 32];
        rng.fill_bytes(&mut key_seed);
        let (pk, sk) = pke.keygen_with_seed(&key_seed).unwrap();
        let y = sk.parse(pke).unwrap();

        // Random message
        let mut message = [0u64; 2];
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        message[0] = u64::from_le_bytes(bytes);
        rng.fill_bytes(&mut bytes);
        message[1] = u64::from_le_bytes(bytes);

        // Random theta
        let mut theta = [0u8; 32];
        rng.fill_bytes(&mut theta);

        // Encrypt
        let ciphertext = pke.encrypt(&pk, &message, &theta).unwrap();

        // Compute noise weight for diagnosis
        let (u, v_bytes) = ciphertext.parse().unwrap();
        let mut v = vec![0u64; VEC_N1N2_SIZE_64];
        for (i, chunk) in v_bytes.chunks(8).enumerate() {
            if i >= VEC_N1N2_SIZE_64 {
                break;
            }
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            v[i] = u64::from_le_bytes(buf);
        }

        let mut yu = vec![0u64; VEC_N_SIZE_64];
        schoolbook_vect_mul_mod_xnm1(&mut yu, &y, &u, VEC_N_SIZE_64, N).unwrap();
        // Truncate
        for i in (N1N2 / 64)..yu.len() {
            yu[i] = 0;
        }

        let mut decoder_input = vec![0u64; VEC_N1N2_SIZE_64];
        for i in 0..VEC_N1N2_SIZE_64 {
            decoder_input[i] = v[i] ^ yu[i];
        }

        let mut encoded = vec![0u64; VEC_N1N2_SIZE_64];
        concat_code.code_encode(&mut encoded, &message).unwrap();

        let noise_weight: u32 = (0..VEC_N1N2_SIZE_64)
            .map(|i| (decoder_input[i] ^ encoded[i]).count_ones())
            .sum();

        // Decrypt to check correctness
        let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();
        let success = message.as_slice() == decrypted.as_slice();

        if !success {
            failures += 1;
            failure_noise_weights.push(noise_weight);
            if failures <= 10 {
                println!(
                    "FAILURE trial {}: noise_weight={} ({:.1}%)",
                    trial,
                    noise_weight,
                    noise_weight as f64 / N1N2 as f64 * 100.0
                );
                println!("  key_seed: {:02x?}", &key_seed[..8]);
                println!("  Original:  {:016x} {:016x}", message[0], message[1]);
                println!("  Decrypted: {:016x} {:016x}", decrypted[0], decrypted[1]);
            }
        } else {
            success_noise_weights.push(noise_weight);
        }
    }

    println!("\n=== RANDOM KEYPAIR TEST RESULTS (HQC-128) ===");
    println!(
        "Total: {}, Successes: {}, Failures: {}",
        total_trials,
        total_trials - failures,
        failures
    );
    println!(
        "Failure rate: {:.2}%",
        failures as f64 / total_trials as f64 * 100.0
    );

    if !success_noise_weights.is_empty() {
        let avg: f64 = success_noise_weights.iter().map(|&w| w as f64).sum::<f64>() /
            success_noise_weights.len() as f64;
        println!(
            "\nSuccess noise: avg={:.1} ({:.1}%), min={}, max={}",
            avg,
            avg / N1N2 as f64 * 100.0,
            success_noise_weights.iter().min().unwrap(),
            success_noise_weights.iter().max().unwrap()
        );
    }
    if !failure_noise_weights.is_empty() {
        let avg: f64 = failure_noise_weights.iter().map(|&w| w as f64).sum::<f64>() /
            failure_noise_weights.len() as f64;
        println!(
            "Failure noise: avg={:.1} ({:.1}%), min={}, max={}",
            avg,
            avg / N1N2 as f64 * 100.0,
            failure_noise_weights.iter().min().unwrap(),
            failure_noise_weights.iter().max().unwrap()
        );
    }

    // The test should have 0 failures if the implementation is correct
    assert_eq!(
        failures,
        0,
        "HQC-128 had {} failures out of {} trials ({:.2}%)",
        failures,
        total_trials,
        failures as f64 / total_trials as f64 * 100.0
    );
}
