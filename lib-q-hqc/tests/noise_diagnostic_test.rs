//! Diagnostic test to measure actual noise levels in HQC PKE decrypt
//!
//! This test measures the Hamming weight of the noise vector that the
//! RM decoder must handle, both for successful and failed decryptions.

use lib_q_hqc::Hqc128Kem;
use lib_q_hqc::concatenated_code::ConcatenatedCode;
use lib_q_hqc::hqc_pke::schoolbook_vect_mul_mod_xnm1;
use lib_q_hqc::params_correct::{
    Hqc1Params,
    HqcParams,
};
use lib_q_random::LibQRng;
use rand_core::Rng;

fn hamming_weight_u64(v: &[u64]) -> u32 {
    v.iter().map(|w| w.count_ones()).sum()
}

fn bytes_to_u64_vec(bytes: &[u8], num_words: usize) -> Vec<u64> {
    let mut result = vec![0u64; num_words];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        if i >= num_words {
            break;
        }
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        result[i] = u64::from_le_bytes(buf);
    }
    result
}

#[test]
#[ignore]
fn test_noise_level_diagnostic() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    let seed = [0x42u8; 32];
    let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

    let y = sk.parse(pke).unwrap();

    let concat_code: ConcatenatedCode<Hqc1Params> = ConcatenatedCode::new().unwrap();

    const N: usize = Hqc1Params::N;
    const VEC_N_SIZE_64: usize = Hqc1Params::VEC_N_SIZE_64;
    const VEC_N1N2_SIZE_64: usize = Hqc1Params::VEC_N1N2_SIZE_64;
    const N1N2: usize = Hqc1Params::N1N2;

    let mut rng = LibQRng::new_secure().expect("RNG");

    let mut success_weights = Vec::new();
    let mut failure_weights = Vec::new();
    let mut failure_details = Vec::new();

    for trial in 0..200 {
        let mut message = [0u64; 2];
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        message[0] = u64::from_le_bytes(bytes);
        rng.fill_bytes(&mut bytes);
        message[1] = u64::from_le_bytes(bytes);

        let mut theta = [0u8; 32];
        rng.fill_bytes(&mut theta);

        let ciphertext = pke.encrypt(&pk, &message, &theta).unwrap();

        // Parse ciphertext to get u and v
        let (u, v_bytes) = ciphertext.parse().unwrap();
        let v = bytes_to_u64_vec(&v_bytes, VEC_N1N2_SIZE_64);

        // Compute y*u mod X^N-1
        let mut yu = vec![0u64; VEC_N_SIZE_64];
        schoolbook_vect_mul_mod_xnm1(&mut yu, &y, &u, VEC_N_SIZE_64, N).unwrap();

        // Truncate y*u to N1N2 bits
        let n1n2_full_words = N1N2 / 64;
        let n1n2_rem = N1N2 % 64;
        if n1n2_rem > 0 {
            yu[n1n2_full_words] &= (1u64 << n1n2_rem) - 1;
            for i in (n1n2_full_words + 1)..yu.len() {
                yu[i] = 0;
            }
        } else {
            for i in n1n2_full_words..yu.len() {
                yu[i] = 0;
            }
        }

        // Compute decoder input: v XOR Truncate(y*u)
        let mut decoder_input = vec![0u64; VEC_N1N2_SIZE_64];
        for i in 0..VEC_N1N2_SIZE_64 {
            decoder_input[i] = v[i] ^ yu[i];
        }

        // Encode the original message to get the expected codeword
        let mut encoded = vec![0u64; VEC_N1N2_SIZE_64];
        concat_code.code_encode(&mut encoded, &message).unwrap();

        // The noise = decoder_input XOR encoded
        let mut noise = vec![0u64; VEC_N1N2_SIZE_64];
        for i in 0..VEC_N1N2_SIZE_64 {
            noise[i] = decoder_input[i] ^ encoded[i];
        }

        let noise_weight = hamming_weight_u64(&noise);

        // Decrypt to check correctness
        let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();
        let success = message.as_slice() == decrypted.as_slice();

        if success {
            success_weights.push(noise_weight);
        } else {
            failure_weights.push(noise_weight);
            failure_details.push((trial, noise_weight, message, decrypted.clone()));
        }
    }

    // Report statistics
    let avg_success: f64 = if success_weights.is_empty() {
        0.0
    } else {
        success_weights.iter().map(|&w| w as f64).sum::<f64>() / success_weights.len() as f64
    };
    let max_success = success_weights.iter().copied().max().unwrap_or(0);
    let min_success = success_weights.iter().copied().min().unwrap_or(0);

    println!("\n=== NOISE DIAGNOSTIC RESULTS ===");
    println!("Total trials: 200");
    println!(
        "Successes: {}, Failures: {}",
        success_weights.len(),
        failure_weights.len()
    );
    println!("\nSuccess noise weights:");
    println!(
        "  Average: {:.1} ({:.1}% of {} bits)",
        avg_success,
        avg_success / N1N2 as f64 * 100.0,
        N1N2
    );
    println!(
        "  Min: {} ({:.1}%)",
        min_success,
        min_success as f64 / N1N2 as f64 * 100.0
    );
    println!(
        "  Max: {} ({:.1}%)",
        max_success,
        max_success as f64 / N1N2 as f64 * 100.0
    );

    if !failure_weights.is_empty() {
        let avg_failure: f64 =
            failure_weights.iter().map(|&w| w as f64).sum::<f64>() / failure_weights.len() as f64;
        let max_failure = failure_weights.iter().copied().max().unwrap_or(0);
        let min_failure = failure_weights.iter().copied().min().unwrap_or(0);

        println!("\nFailure noise weights:");
        println!(
            "  Average: {:.1} ({:.1}% of {} bits)",
            avg_failure,
            avg_failure / N1N2 as f64 * 100.0,
            N1N2
        );
        println!(
            "  Min: {} ({:.1}%)",
            min_failure,
            min_failure as f64 / N1N2 as f64 * 100.0
        );
        println!(
            "  Max: {} ({:.1}%)",
            max_failure,
            max_failure as f64 / N1N2 as f64 * 100.0
        );

        println!("\nFailure details:");
        for (trial, weight, msg, dec) in &failure_details {
            println!(
                "  Trial {}: noise_weight={} ({:.1}%)",
                trial,
                weight,
                *weight as f64 / N1N2 as f64 * 100.0
            );
            println!("    Original:  {:016x} {:016x}", msg[0], msg[1]);
            println!("    Decrypted: {:016x} {:016x}", dec[0], dec[1]);
        }
    }

    println!(
        "\nExpected noise weight: ~{} ({:.1}% of {} bits)",
        (N1N2 as f64 * 0.34) as u32,
        34.0,
        N1N2
    );
}
