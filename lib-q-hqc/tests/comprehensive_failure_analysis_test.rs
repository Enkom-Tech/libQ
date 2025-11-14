#[cfg(feature = "alloc")]
use lib_q_hqc::{
    HqcParams,
    hqc_kem::HqcKem,
    params_correct::{
        Hqc1Params,
        Hqc3Params,
        Hqc5Params,
    },
};
use lib_q_random::LibQRng;

#[cfg(feature = "alloc")]
#[test]
fn test_comprehensive_failure_analysis() {
    println!("=== COMPREHENSIVE HQC FAILURE RATE ANALYSIS ===");

    // Test with larger sample sizes for better statistics
    let sample_sizes = [100, 500, 1000];

    for &sample_size in &sample_sizes {
        println!("\n--- Testing with {} samples ---", sample_size);

        // Test HQC-1
        println!("\nHQC-1 Analysis:");
        analyze_failure_rate::<Hqc1Params>("HQC-1", sample_size, 2.0_f64.powi(-128));

        // Test HQC-3
        println!("\nHQC-3 Analysis:");
        analyze_failure_rate::<Hqc3Params>("HQC-3", sample_size, 2.0_f64.powi(-192));

        // Test HQC-5
        println!("\nHQC-5 Analysis:");
        analyze_failure_rate::<Hqc5Params>("HQC-5", sample_size, 2.0_f64.powi(-256));
    }
}

#[cfg(feature = "alloc")]
fn analyze_failure_rate<P: HqcParams>(
    name: &str,
    num_tests: usize,
    expected_max_failure_rate: f64,
) {
    let kem = HqcKem::<P>::new().unwrap();

    let mut failures = 0;
    let mut total_attempts = 0;
    let mut bit_similarities = Vec::new();

    for i in 0..num_tests {
        // Generate key pair
        let mut rng = LibQRng::new_nist_drbg([i as u8; 48]);
        let (public_key, secret_key) = kem.keygen(&mut rng).unwrap();

        // Encapsulation
        let mut rng_encap = LibQRng::new_nist_drbg([(i + 1000) as u8; 48]);
        let (ciphertext, shared_secret1) = kem.encapsulate(&public_key, &mut rng_encap).unwrap();

        // Decapsulation
        let shared_secret2 = kem.decapsulate(&secret_key, &ciphertext).unwrap();

        total_attempts += 1;

        // Calculate bit-level similarity
        let secret1_bytes = shared_secret1.as_bytes();
        let secret2_bytes = shared_secret2.as_bytes();

        let mut matching_bits = 0;
        let total_bits = secret1_bytes.len() * 8;

        for (byte1, byte2) in secret1_bytes.iter().zip(secret2_bytes.iter()) {
            let xor_result = byte1 ^ byte2;
            for bit in 0..8 {
                if (xor_result >> bit) & 1 == 0 {
                    matching_bits += 1;
                }
            }
        }

        let similarity = (matching_bits as f64 / total_bits as f64) * 100.0;
        bit_similarities.push(similarity);

        if shared_secret1.as_bytes() != shared_secret2.as_bytes() {
            failures += 1;
        }

        // Progress indicator
        if (i + 1) % 50 == 0 {
            println!("  Progress: {}/{} tests completed", i + 1, num_tests);
        }
    }

    // Calculate statistics
    let observed_failure_rate = failures as f64 / total_attempts as f64;
    let expected_failure_rate_percent = expected_max_failure_rate * 100.0;
    let observed_failure_rate_percent = observed_failure_rate * 100.0;

    // Bit similarity statistics
    let avg_similarity = bit_similarities.iter().sum::<f64>() / bit_similarities.len() as f64;
    let min_similarity = bit_similarities
        .iter()
        .fold(f64::INFINITY, |a, &b| a.min(b));
    let max_similarity = bit_similarities
        .iter()
        .fold(f64::NEG_INFINITY, |a, &b| a.max(b));

    // Calculate standard deviation
    let variance = bit_similarities
        .iter()
        .map(|&x| (x - avg_similarity).powi(2))
        .sum::<f64>() /
        bit_similarities.len() as f64;
    let std_dev = variance.sqrt();

    println!("  Results for {} ({} samples):", name, num_tests);
    println!("    Total tests: {}", total_attempts);
    println!("    Failures: {}", failures);
    println!(
        "    Observed failure rate: {:.2e} ({:.6}%)",
        observed_failure_rate, observed_failure_rate_percent
    );
    println!(
        "    Expected max failure rate: {:.2e} ({:.6}%)",
        expected_max_failure_rate, expected_failure_rate_percent
    );

    println!("    Bit-level similarity statistics:");
    println!("      Average: {:.2}%", avg_similarity);
    println!("      Min: {:.2}%", min_similarity);
    println!("      Max: {:.2}%", max_similarity);
    println!("      Std Dev: {:.2}%", std_dev);

    // Noise analysis
    let noise_analysis = analyze_noise_characteristics::<P>();
    println!(
        "    Noise analysis: Expected noise {:.2}%, Correction capacity {:.2}%",
        noise_analysis.expected_noise_percent, noise_analysis.correction_capacity_percent
    );

    // Determine if failure rate is within expected bounds
    if observed_failure_rate <= expected_max_failure_rate {
        println!("    ✅ {} failure rate is within expected bounds", name);
    } else {
        println!("    ❌ {} failure rate exceeds expected bounds", name);
    }

    // Analyze consistency
    if std_dev < 5.0 {
        println!("    ✅ Bit similarity is consistent (low variance)");
    } else {
        println!("    ⚠️  Bit similarity has high variance");
    }
}

#[cfg(feature = "alloc")]
fn analyze_noise_characteristics<P: HqcParams>() -> NoiseAnalysis {
    let total_bits = P::N;
    let expected_noise_bits = P::OMEGA_E + P::OMEGA_R;
    let correction_capacity = P::DELTA;

    let expected_noise_percent = (expected_noise_bits as f64 / total_bits as f64) * 100.0;
    let correction_capacity_percent = (correction_capacity as f64 / total_bits as f64) * 100.0;

    NoiseAnalysis {
        expected_noise_percent,
        correction_capacity_percent,
    }
}

#[cfg(feature = "alloc")]
struct NoiseAnalysis {
    expected_noise_percent: f64,
    correction_capacity_percent: f64,
}

#[cfg(feature = "alloc")]
#[test]
fn test_consistency_across_parameter_sets() {
    println!("\n=== CONSISTENCY ANALYSIS ACROSS PARAMETER SETS ===");

    let sample_size = 100;

    // Test all parameter sets with same sample size
    let hqc1_results = test_parameter_set::<Hqc1Params>("HQC-1", sample_size);
    let hqc3_results = test_parameter_set::<Hqc3Params>("HQC-3", sample_size);
    let hqc5_results = test_parameter_set::<Hqc5Params>("HQC-5", sample_size);

    println!("\n--- Comparative Analysis ---");
    println!("Parameter Set | Failure Rate | Avg Similarity | Noise vs Capacity");
    println!("-------------|--------------|----------------|------------------");
    println!(
        "HQC-1        | {:.1}%        | {:.1}%          | {:.1}x",
        hqc1_results.failure_rate * 100.0,
        hqc1_results.avg_similarity,
        hqc1_results.noise_ratio
    );
    println!(
        "HQC-3        | {:.1}%        | {:.1}%          | {:.1}x",
        hqc3_results.failure_rate * 100.0,
        hqc3_results.avg_similarity,
        hqc3_results.noise_ratio
    );
    println!(
        "HQC-5        | {:.1}%        | {:.1}%          | {:.1}x",
        hqc5_results.failure_rate * 100.0,
        hqc5_results.avg_similarity,
        hqc5_results.noise_ratio
    );

    // Analyze trends
    println!("\n--- Trend Analysis ---");
    if hqc1_results.failure_rate > hqc3_results.failure_rate &&
        hqc3_results.failure_rate > hqc5_results.failure_rate
    {
        println!("✅ Failure rate decreases with higher security levels (as expected)");
    } else {
        println!("⚠️  Failure rate trend is not as expected");
    }

    if hqc1_results.avg_similarity < hqc3_results.avg_similarity &&
        hqc3_results.avg_similarity < hqc5_results.avg_similarity
    {
        println!("✅ Bit similarity increases with higher security levels (as expected)");
    } else {
        println!("⚠️  Bit similarity trend is not as expected");
    }
}

#[cfg(feature = "alloc")]
fn test_parameter_set<P: HqcParams>(_name: &str, num_tests: usize) -> ParameterSetResults {
    let kem = HqcKem::<P>::new().unwrap();

    let mut failures = 0;
    let mut bit_similarities = Vec::new();

    for i in 0..num_tests {
        // Generate key pair
        let mut rng = LibQRng::new_nist_drbg([i as u8; 48]);
        let (public_key, secret_key) = kem.keygen(&mut rng).unwrap();

        // Encapsulation
        let mut rng_encap = LibQRng::new_nist_drbg([(i + 1000) as u8; 48]);
        let (ciphertext, shared_secret1) = kem.encapsulate(&public_key, &mut rng_encap).unwrap();

        // Decapsulation
        let shared_secret2 = kem.decapsulate(&secret_key, &ciphertext).unwrap();

        // Calculate bit-level similarity
        let secret1_bytes = shared_secret1.as_bytes();
        let secret2_bytes = shared_secret2.as_bytes();

        let mut matching_bits = 0;
        let total_bits = secret1_bytes.len() * 8;

        for (byte1, byte2) in secret1_bytes.iter().zip(secret2_bytes.iter()) {
            let xor_result = byte1 ^ byte2;
            for bit in 0..8 {
                if (xor_result >> bit) & 1 == 0 {
                    matching_bits += 1;
                }
            }
        }

        let similarity = (matching_bits as f64 / total_bits as f64) * 100.0;
        bit_similarities.push(similarity);

        if shared_secret1.as_bytes() != shared_secret2.as_bytes() {
            failures += 1;
        }
    }

    let failure_rate = failures as f64 / num_tests as f64;
    let avg_similarity = bit_similarities.iter().sum::<f64>() / bit_similarities.len() as f64;

    // Calculate noise ratio
    let noise_analysis = analyze_noise_characteristics::<P>();
    let noise_ratio =
        noise_analysis.expected_noise_percent / noise_analysis.correction_capacity_percent;

    ParameterSetResults {
        failure_rate,
        avg_similarity,
        noise_ratio,
    }
}

#[cfg(feature = "alloc")]
struct ParameterSetResults {
    failure_rate: f64,
    avg_similarity: f64,
    noise_ratio: f64,
}
