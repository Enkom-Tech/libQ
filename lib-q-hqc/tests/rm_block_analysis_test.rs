//! Per-block Reed-Muller failure analysis
//!
//! Measures how many RM blocks fail per trial and the RS correction load.

use lib_q_hqc::Hqc128Kem;
use lib_q_hqc::concatenated_code::ConcatenatedCode;
use lib_q_hqc::hqc_pke::schoolbook_vect_mul_mod_xnm1;
use lib_q_hqc::params_correct::{
    Hqc1Params,
    HqcParams,
};
use lib_q_hqc::reed_muller::ReedMuller;
use lib_q_hqc::reed_solomon::ReedSolomon;
use lib_q_random::LibQRng;
use rand_core::Rng;

#[test]
#[ignore]
fn test_rm_block_failure_analysis() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    let concat_code: ConcatenatedCode<Hqc1Params> = ConcatenatedCode::new().unwrap();
    let rm: ReedMuller<Hqc1Params> = ReedMuller::new();
    let rs: ReedSolomon<Hqc1Params> = ReedSolomon::new().unwrap();

    const N: usize = Hqc1Params::N;
    const N1: usize = Hqc1Params::N1;
    const N2: usize = Hqc1Params::N2;
    const K: usize = Hqc1Params::K;
    const VEC_N_SIZE_64: usize = Hqc1Params::VEC_N_SIZE_64;
    const VEC_N1N2_SIZE_64: usize = Hqc1Params::VEC_N1N2_SIZE_64;
    const N1N2: usize = Hqc1Params::N1N2;

    let mut rng = LibQRng::new_secure().expect("RNG");

    let mut total_trials = 0;
    let mut total_failures = 0;
    let mut block_error_counts = Vec::new();

    // Run until we get at least 3 failures or 2000 trials
    while total_failures < 3 && total_trials < 2000 {
        total_trials += 1;

        // Random keypair
        let mut key_seed = [0u8; 32];
        rng.fill_bytes(&mut key_seed);
        let (pk, sk) = pke.keygen_with_seed(&key_seed).unwrap();
        let y = sk.parse(pke).unwrap();

        // Random message and theta
        let mut message = [0u64; 2];
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        message[0] = u64::from_le_bytes(bytes);
        rng.fill_bytes(&mut bytes);
        message[1] = u64::from_le_bytes(bytes);
        let mut theta = [0u8; 32];
        rng.fill_bytes(&mut theta);

        // Encrypt
        let ciphertext = pke.encrypt(&pk, &message, &theta).unwrap();

        // Decrypt and check
        let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();
        if message.as_slice() == decrypted.as_slice() {
            continue;
        }

        total_failures += 1;
        println!(
            "\n=== FAILURE #{} (trial {}) ===",
            total_failures, total_trials
        );
        println!("Original:  {:016x} {:016x}", message[0], message[1]);
        println!("Decrypted: {:016x} {:016x}", decrypted[0], decrypted[1]);

        // Compute the decoder input (noisy codeword)
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
        for i in (N1N2 / 64)..yu.len() {
            yu[i] = 0;
        }

        // decoder_input = v XOR Truncate(y*u) — this is what the decoder sees
        let mut decoder_input_u64 = vec![0u64; VEC_N1N2_SIZE_64];
        for i in 0..VEC_N1N2_SIZE_64 {
            decoder_input_u64[i] = v[i] ^ yu[i];
        }

        // Convert to bytes for RM decode
        let mut decoder_input_bytes = vec![0u8; N1N2 / 8];
        for (i, word) in decoder_input_u64.iter().enumerate() {
            let start = i * 8;
            if start + 8 <= decoder_input_bytes.len() {
                decoder_input_bytes[start..start + 8].copy_from_slice(&word.to_le_bytes());
            }
        }

        // Compute the expected RS codeword (encode message with RS only)
        let mut message_bytes = vec![0u8; K];
        message_bytes[0..8].copy_from_slice(&message[0].to_le_bytes());
        message_bytes[8..16].copy_from_slice(&message[1].to_le_bytes());
        let mut expected_rs_codeword = vec![0u8; N1];
        rs.encode(&message_bytes, &mut expected_rs_codeword)
            .unwrap();

        // RM decode each block and compare to expected
        let mut rm_decoded = vec![0u8; N1];
        rm.decode(&decoder_input_bytes, &mut rm_decoded).unwrap();

        let mut wrong_blocks = 0;
        let mut wrong_positions = Vec::new();
        for i in 0..N1 {
            if rm_decoded[i] != expected_rs_codeword[i] {
                wrong_blocks += 1;
                wrong_positions.push(i);
            }
        }

        block_error_counts.push(wrong_blocks);

        println!(
            "RM decode errors: {}/46 blocks wrong (RS can correct up to 15)",
            wrong_blocks
        );
        if wrong_blocks <= 20 {
            println!("Wrong positions: {:?}", wrong_positions);
            for &pos in &wrong_positions {
                println!(
                    "  Block {}: expected 0x{:02x}, got 0x{:02x}",
                    pos, expected_rs_codeword[pos], rm_decoded[pos]
                );
            }
        }

        // Count per-block noise (bit errors in each 384-bit RM block)
        let mut encoded = vec![0u64; VEC_N1N2_SIZE_64];
        concat_code.code_encode(&mut encoded, &message).unwrap();
        let mut encoded_bytes = vec![0u8; N1N2 / 8];
        for (i, word) in encoded.iter().enumerate() {
            let start = i * 8;
            if start + 8 <= encoded_bytes.len() {
                encoded_bytes[start..start + 8].copy_from_slice(&word.to_le_bytes());
            }
        }

        println!("\nPer-block noise (errors per 384 bits):");
        let n2_bytes = N2 / 8; // 48 bytes per block
        for i in 0..N1 {
            let start = i * n2_bytes;
            let end = start + n2_bytes;
            let block_errors: u32 = decoder_input_bytes[start..end]
                .iter()
                .zip(&encoded_bytes[start..end])
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();
            if wrong_positions.contains(&i) {
                println!("  Block {:2}: {} errors (WRONG)", i, block_errors);
            }
        }
    }

    println!("\n=== SUMMARY ===");
    println!(
        "Total trials: {}, Failures: {}",
        total_trials, total_failures
    );
    if !block_error_counts.is_empty() {
        println!("RM errors per failure: {:?}", block_error_counts);
    }
}
