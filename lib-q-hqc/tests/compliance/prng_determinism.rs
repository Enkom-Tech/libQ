use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
use rand_core::Rng;

/// PRNG determinism tests to ensure reproducible random number generation
///
/// This test verifies that our SHAKE256-based PRNG produces deterministic
/// output for the same seed, which is critical for KAT compatibility.

#[test]
fn test_prng_determinism_basic() {
    println!("=== PRNG Basic Determinism Test ===");

    let seed = [0u8; 48];
    let mut rng1 = create_shake256_prng_rng(seed);
    let mut rng2 = create_shake256_prng_rng(seed);

    // Generate 1000 bytes from each PRNG
    let mut output1 = vec![0u8; 1000];
    let mut output2 = vec![0u8; 1000];

    rng1.fill_bytes(&mut output1);
    rng2.fill_bytes(&mut output2);

    assert_eq!(
        output1, output2,
        "PRNG should be deterministic with same seed"
    );
    println!("✅ PRNG is deterministic - same seed produces same output");
}

#[test]
fn test_prng_determinism_kat_entropy() {
    println!("=== PRNG KAT Entropy Determinism Test ===");

    // Use the exact entropy input from reference main_kat.c
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }

    let mut rng1 = create_shake256_prng_rng(entropy_input);
    let mut rng2 = create_shake256_prng_rng(entropy_input);

    // Generate first 10 seeds (48 bytes each)
    for i in 0..10 {
        let mut seed1 = [0u8; 48];
        let mut seed2 = [0u8; 48];

        rng1.fill_bytes(&mut seed1);
        rng2.fill_bytes(&mut seed2);

        assert_eq!(seed1, seed2, "PRNG should be deterministic for seed {}", i);
    }

    println!("✅ PRNG is deterministic with KAT entropy input");
}

#[test]
fn test_prng_state_independence() {
    println!("=== PRNG State Independence Test ===");

    let seed = [0u8; 48];

    // Create multiple independent PRNG instances
    let mut rngs = Vec::new();
    for _ in 0..5 {
        rngs.push(create_shake256_prng_rng(seed));
    }

    // Generate output from each PRNG
    let mut outputs = Vec::new();
    for mut rng in rngs {
        let mut output = vec![0u8; 100];
        rng.fill_bytes(&mut output);
        outputs.push(output);
    }

    // All outputs should be identical
    for i in 1..outputs.len() {
        assert_eq!(
            outputs[0], outputs[i],
            "Independent PRNG instances should produce same output"
        );
    }

    println!("✅ PRNG state independence verified");
}

#[test]
fn test_prng_kat_seed_sequence() {
    println!("=== PRNG KAT Seed Sequence Test ===");

    // Use the exact entropy input from reference
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }

    let mut rng = create_shake256_prng_rng(entropy_input);

    // Generate first 5 KAT seeds and verify they match expected values
    let expected_seeds = [
        "9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505",
        "AAF9BAF4AE72C4C9B48EFD574140A7BC837D57C773B47A547A56BD45578C1D9B98150F639A680625ACD3DD6214575FB3",
        "AA7F02A633C9C3038536529A67B7C14CB92F286F4D77A981F787A63BD2FA901923A9C5B696E3005D91C6259D29BFB1F5",
        "4740A0583CB0D8E59FB531E2D8F9B22A6FBFB72C532FBFFFD77C9192830325CE28BFDBAFB599D076C5DE2B26AD6C3BEB",
        "842BB517D6C066CDFC4427EB5B8DD2646D23B36894F7CD5F52C33A8F676D8E406C8029A24FBC38F77ED15757D1095584",
    ];

    for (i, expected_hex) in expected_seeds.iter().enumerate() {
        let mut seed = [0u8; 48];
        rng.fill_bytes(&mut seed);

        let expected_bytes = hex::decode(expected_hex).unwrap();
        assert_eq!(
            seed,
            expected_bytes.as_slice(),
            "KAT seed {} should match expected value",
            i
        );
        println!("✅ KAT seed {} matches expected value", i);
    }
}

#[test]
fn test_prng_byte_distribution() {
    println!("=== PRNG Byte Distribution Test ===");

    let seed = [0u8; 48];
    let mut rng = create_shake256_prng_rng(seed);

    // Generate a large sample for statistical analysis
    let sample_size = 100000;
    let mut sample = vec![0u8; sample_size];
    rng.fill_bytes(&mut sample);

    // Count byte frequencies
    let mut byte_counts = [0u32; 256];
    for &byte in &sample {
        byte_counts[byte as usize] += 1;
    }

    // Calculate statistics
    let expected_count = sample_size as f32 / 256.0;
    let mut chi_square = 0.0;

    for &count in &byte_counts {
        let diff = count as f32 - expected_count;
        chi_square += (diff * diff) / expected_count;
    }

    println!("Byte distribution statistics:");
    println!("  Sample size: {}", sample_size);
    println!("  Expected count per byte: {:.2}", expected_count);
    println!("  Chi-square statistic: {:.2}", chi_square);

    // Chi-square critical value for 255 degrees of freedom at 95% confidence is ~293
    // We'll use a more lenient threshold for this test
    assert!(
        chi_square < 400.0,
        "Chi-square test failed - distribution may not be uniform"
    );

    // Check for obvious biases
    let min_count = byte_counts.iter().min().unwrap();
    let max_count = byte_counts.iter().max().unwrap();
    let max_deviation =
        (*max_count as f32 - expected_count).max(expected_count - *min_count as f32);
    let max_deviation_pct = max_deviation / expected_count * 100.0;

    println!("  Min count: {}", min_count);
    println!("  Max count: {}", max_count);
    println!("  Max deviation: {:.1}%", max_deviation_pct);

    // Allow for some statistical variation
    assert!(
        max_deviation_pct < 20.0,
        "Maximum deviation from uniform distribution too high"
    );

    println!("✅ PRNG byte distribution appears uniform");
}

#[test]
fn test_prng_entropy_consumption() {
    println!("=== PRNG Entropy Consumption Test ===");

    // Test that PRNG consumes entropy correctly
    let seed = [0u8; 48];
    let mut rng = create_shake256_prng_rng(seed);

    // Generate small amounts of data and verify they're different
    let mut outputs = Vec::new();
    for _ in 0..10 {
        let mut output = [0u8; 4];
        rng.fill_bytes(&mut output);
        outputs.push(output);
    }

    // All outputs should be different (very high probability)
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i], outputs[j],
                "PRNG should produce different outputs"
            );
        }
    }

    println!("✅ PRNG entropy consumption verified");
}

#[test]
fn test_prng_reproducibility_across_runs() {
    println!("=== PRNG Reproducibility Across Runs Test ===");

    // This test verifies that the same seed produces the same output
    // even when the PRNG is recreated multiple times
    let seed = [0u8; 48];

    let mut all_outputs = Vec::new();

    // Generate output from 10 different PRNG instances with the same seed
    for _ in 0..10 {
        let mut rng = create_shake256_prng_rng(seed);
        let mut output = vec![0u8; 100];
        rng.fill_bytes(&mut output);
        all_outputs.push(output);
    }

    // All outputs should be identical
    for i in 1..all_outputs.len() {
        assert_eq!(
            all_outputs[0], all_outputs[i],
            "PRNG should be reproducible across runs"
        );
    }

    println!("✅ PRNG reproducibility across runs verified");
}
