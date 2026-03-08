//! Alpha512 parameter grid sweep: PKE bit-error histogram and 10k KEM mismatch count per candidate.
//! Run with: cargo test -p lib-q-dawn --features random --test parameter_sweep -- --ignored --nocapture
//! Results are logged to stderr and optionally to docs/parameter_tuning_log.md when run.

use lib_q_core::Kem;
use lib_q_dawn::DawnKem;
use lib_q_dawn::encoding::{
    pke_failure_rate_histogram,
    pke_failure_rate_histogram_majority_reliability,
    pke_failure_rate_histogram_reliability,
};
use lib_q_dawn::keygen::{
    DeterministicKeyGenerator,
    KeyGenParams,
};

const PKE_SAMPLES: usize = 10_000;
const KEM_CYCLES: usize = 10_000;
const PKE_SAMPLES_QUICK: usize = 1_000;
const KEM_CYCLES_QUICK: usize = 1_000;

fn keypair_for_sweep(
    params: &KeyGenParams,
    k_s: usize,
    k_e: usize,
) -> lib_q_dawn::keygen::DawnKeyPair {
    let seed = lib_q_dawn::security::generate_deterministic_high_entropy_data(
        &[
            b"sweep_keygen".as_ref(),
            &(k_s as u64).to_le_bytes(),
            &(k_e as u64).to_le_bytes(),
        ]
        .concat(),
        64,
    );
    let key_gen = DeterministicKeyGenerator::new(params.clone(), seed);
    key_gen
        .generate_keypair()
        .expect("keygen must succeed for sweep params")
}

fn keypair_for_sweep_alpha1024(
    params: &KeyGenParams,
    k_s: usize,
    k_e: usize,
) -> lib_q_dawn::keygen::DawnKeyPair {
    let seed = lib_q_dawn::security::generate_deterministic_high_entropy_data(
        &[
            b"sweep_alpha1024_keygen".as_ref(),
            &(k_s as u64).to_le_bytes(),
            &(k_e as u64).to_le_bytes(),
        ]
        .concat(),
        64,
    );
    let key_gen = DeterministicKeyGenerator::new(params.clone(), seed);
    key_gen
        .generate_keypair()
        .expect("keygen must succeed for Alpha1024 sweep params")
}

fn keypair_for_sweep_beta512(
    params: &KeyGenParams,
    k_s: usize,
    k_e: usize,
) -> lib_q_dawn::keygen::DawnKeyPair {
    let seed = lib_q_dawn::security::generate_deterministic_high_entropy_data(
        &[
            b"sweep_beta512_keygen".as_ref(),
            &(k_s as u64).to_le_bytes(),
            &(k_e as u64).to_le_bytes(),
        ]
        .concat(),
        64,
    );
    let key_gen = DeterministicKeyGenerator::new(params.clone(), seed);
    key_gen
        .generate_keypair()
        .expect("keygen must succeed for Beta512 sweep params")
}

fn keypair_for_spec_params(params: &KeyGenParams) -> lib_q_dawn::keygen::DawnKeyPair {
    let seed =
        lib_q_dawn::security::generate_deterministic_high_entropy_data(b"sweep_spec_pke", 64);
    let key_gen = DeterministicKeyGenerator::new(params.clone(), seed);
    key_gen
        .generate_keypair()
        .expect("keygen must succeed for spec params")
}

/// Spec-parameter PKE histogram (Phase 1.1): exact paper params d_c=7, k_s=96, k_e=160, baseline decoder.
/// Run with: cargo test -p lib-q-dawn --features random --test parameter_sweep test_alpha512_spec_params_histogram -- --ignored --nocapture
#[test]
#[ignore = "Phase 1.1 diagnostic; run with --ignored --nocapture"]
fn test_alpha512_spec_params_histogram() {
    let params = KeyGenParams::dawn_alpha_512_spec();
    let keypair = keypair_for_spec_params(&params);
    let mut rng_seed = [0u8; 64];
    rng_seed.copy_from_slice(
        &lib_q_dawn::security::generate_deterministic_high_entropy_data(
            b"sweep_spec_pke_histogram",
            64,
        ),
    );
    let (b0, b1, b2_4, b_gt4) =
        pke_failure_rate_histogram(&keypair, &params, PKE_SAMPLES_QUICK, &rng_seed);
    eprintln!(
        "--- Alpha512 spec params (d_c=7, k_s=96, k_e=160) PKE histogram (1k samples, baseline decoder) ---"
    );
    eprintln!(
        "  0 err={}  1 err={}  2-4 err={}  >4 err={}",
        b0, b1, b2_4, b_gt4
    );
    // No assert: diagnostic only; success criteria in plan (any in 0/1/2-4 vs 100% in >4).
}

/// One candidate: run PKE histogram then KEM cycles; return (b0, b1, b2_4, b_gt4, kem_mismatches).
fn run_candidate_with_counts(
    k_s: usize,
    k_e: usize,
    pke_samples: usize,
    kem_cycles: usize,
) -> (usize, usize, usize, usize, u64) {
    let params = KeyGenParams::dawn_alpha_512_custom(k_s, k_e, 1);
    let keypair = keypair_for_sweep(&params, k_s, k_e);

    let mut rng_seed = [0u8; 64];
    let seed_material = lib_q_dawn::security::generate_deterministic_high_entropy_data(
        &[
            b"sweep_pke".as_ref(),
            &(k_s as u64).to_le_bytes(),
            &(k_e as u64).to_le_bytes(),
        ]
        .concat(),
        64,
    );
    rng_seed.copy_from_slice(&seed_material);

    let (b0, b1, b2_4, b_gt4) =
        pke_failure_rate_histogram_reliability(&keypair, &params, pke_samples, &rng_seed);

    let kem = DawnKem::new_with_params_and_reliability_decoder(params);
    let mut mismatches = 0u64;
    for i in 0..kem_cycles {
        let kp = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ct, ss1) = match kem.encapsulate(&kp.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ss2 = match kem.decapsulate(&kp.secret_key, &ct) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                break;
            }
        };
        if ss1 != ss2 {
            mismatches += 1;
            break;
        }
        if kem_cycles >= 100 && (i + 1) % 100 == 0 {
            eprintln!(
                "progress k_s={} k_e={} kem_cycle={}/{} mismatches={}",
                k_s,
                k_e,
                i + 1,
                kem_cycles,
                mismatches
            );
        }
    }
    (b0, b1, b2_4, b_gt4, mismatches)
}

/// Path B (majority-reliability decoder): one candidate, return (b0, b1, b2_4, b_gt4, kem_mismatches).
fn run_alpha512_path_b_candidate_with_counts(
    k_s: usize,
    k_e: usize,
    pke_samples: usize,
    kem_cycles: usize,
) -> (usize, usize, usize, usize, u64) {
    let params = KeyGenParams::dawn_alpha_512_custom(k_s, k_e, 1);
    let keypair = keypair_for_sweep(&params, k_s, k_e);

    let mut rng_seed = [0u8; 64];
    let seed_material = lib_q_dawn::security::generate_deterministic_high_entropy_data(
        &[
            b"sweep_pathb_pke".as_ref(),
            &(k_s as u64).to_le_bytes(),
            &(k_e as u64).to_le_bytes(),
        ]
        .concat(),
        64,
    );
    rng_seed.copy_from_slice(&seed_material);

    let (b0, b1, b2_4, b_gt4) =
        pke_failure_rate_histogram_majority_reliability(&keypair, &params, pke_samples, &rng_seed);

    let kem = DawnKem::new_with_params_and_majority_reliability_decoder(params);
    let mut mismatches = 0u64;
    for i in 0..kem_cycles {
        let kp = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ct, ss1) = match kem.encapsulate(&kp.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ss2 = match kem.decapsulate(&kp.secret_key, &ct) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                break;
            }
        };
        if ss1 != ss2 {
            mismatches += 1;
            break;
        }
        if kem_cycles >= 100 && (i + 1) % 100 == 0 {
            eprintln!(
                "path_b progress k_s={} k_e={} kem_cycle={}/{} mismatches={}",
                k_s,
                k_e,
                i + 1,
                kem_cycles,
                mismatches
            );
        }
    }
    (b0, b1, b2_4, b_gt4, mismatches)
}

fn run_candidate(k_s: usize, k_e: usize) -> (usize, usize, usize, usize, u64) {
    run_candidate_with_counts(k_s, k_e, PKE_SAMPLES, KEM_CYCLES)
}

fn run_candidate_exploratory(k_s: usize, k_e: usize) -> (usize, usize, usize, usize, u64) {
    run_candidate_with_counts(k_s, k_e, 200, 200)
}

/// Quick grid (1k PKE, 1k KEM per candidate) to find promising (k_s, k_e). Run with --ignored --nocapture.
#[test]
#[ignore = "quick sweep to shortlist candidates"]
fn test_alpha512_parameter_sweep_quick() {
    let k_s_values = [24usize, 32, 40, 48];
    let k_e_values = [32usize, 48, 64, 80];
    eprintln!("--- Alpha512 quick sweep (d_c=1, 1k PKE, 1k KEM per candidate) ---");
    for &k_s in &k_s_values {
        for &k_e in &k_e_values {
            let (b0, b1, b2_4, b_gt4, mismatches) =
                run_candidate_with_counts(k_s, k_e, PKE_SAMPLES_QUICK, KEM_CYCLES_QUICK);
            eprintln!(
                "k_s={} k_e={}  PKE: 0={} 1={} 2-4={} >4={}  KEM_mismatches={}",
                k_s, k_e, b0, b1, b2_4, b_gt4, mismatches
            );
        }
    }
}

/// Path B quick sweep: Alpha512 with majority-reliability decoder (1k PKE, 1k KEM per candidate).
#[test]
#[ignore = "Path B quick sweep; run with cargo test -p lib-q-dawn --features random --test parameter_sweep test_alpha512_path_b_sweep_quick -- --ignored --nocapture"]
fn test_alpha512_path_b_sweep_quick() {
    let k_s_values = [24usize, 32, 40, 48];
    let k_e_values = [32usize, 48, 64, 80];
    eprintln!(
        "--- Alpha512 Path B (majority-reliability decoder) quick sweep (1k PKE, 1k KEM) ---"
    );
    for &k_s in &k_s_values {
        for &k_e in &k_e_values {
            let (b0, b1, b2_4, b_gt4, mismatches) = run_alpha512_path_b_candidate_with_counts(
                k_s,
                k_e,
                PKE_SAMPLES_QUICK,
                KEM_CYCLES_QUICK,
            );
            eprintln!(
                "path_b k_s={} k_e={}  PKE: 0={} 1={} 2-4={} >4={}  KEM_mismatches={}",
                k_s, k_e, b0, b1, b2_4, b_gt4, mismatches
            );
        }
    }
}

/// Exploratory wide sweep over low-noise region to check if any parameter-only regime is viable.
#[test]
#[ignore = "exploratory low-noise sweep; for diagnostics only"]
fn test_alpha512_parameter_sweep_wide_low_noise() {
    let k_s_values = [1usize, 2, 4, 8, 12, 16, 24, 32];
    let k_e_values = [1usize, 2, 4, 8, 12, 16, 24, 32, 48];
    eprintln!("--- Alpha512 exploratory sweep (d_c=1, 200 PKE, 200 KEM per candidate) ---");
    for &k_s in &k_s_values {
        for &k_e in &k_e_values {
            let (b0, b1, b2_4, b_gt4, mismatches) = run_candidate_exploratory(k_s, k_e);
            eprintln!(
                "explore k_s={} k_e={}  PKE: 0={} 1={} 2-4={} >4={}  KEM_mismatches={}",
                k_s, k_e, b0, b1, b2_4, b_gt4, mismatches
            );
        }
    }
}

/// Full grid: k_s in {24, 32, 40, 48}, k_e in {32, 48, 64, 80}, d_c=1.
#[test]
#[ignore = "parameter sweep; run with cargo test -p lib-q-dawn --features random --test parameter_sweep -- --ignored --nocapture"]
fn test_alpha512_parameter_sweep_grid() {
    let k_s_values = [24usize, 32, 40, 48];
    let k_e_values = [32usize, 48, 64, 80];

    let mut lines: Vec<String> = vec![
        "# Alpha512 parameter sweep (d_c=1)".to_string(),
        "".to_string(),
        format!("PKE samples: {}, KEM cycles: {}", PKE_SAMPLES, KEM_CYCLES),
        "".to_string(),
        "| k_s | k_e | 0 err | 1 err | 2-4 err | >4 err | KEM mismatches |".to_string(),
        "|-----|-----|-------|-------|---------|--------|----------------|".to_string(),
    ];

    eprintln!("--- Alpha512 parameter sweep (d_c=1) ---");
    eprintln!("PKE samples = {}, KEM cycles = {}", PKE_SAMPLES, KEM_CYCLES);
    eprintln!();

    for &k_s in &k_s_values {
        for &k_e in &k_e_values {
            let (b0, b1, b2_4, b_gt4, mismatches) = run_candidate(k_s, k_e);
            let row = format!(
                "| {} | {} | {} | {} | {} | {} | {} |",
                k_s, k_e, b0, b1, b2_4, b_gt4, mismatches
            );
            lines.push(row.clone());
            eprintln!(
                "k_s={} k_e={}  PKE: 0={} 1={} 2-4={} >4={}  KEM_mismatches={}",
                k_s, k_e, b0, b1, b2_4, b_gt4, mismatches
            );
        }
    }

    let log_content = lines.join("\n");
    if let Ok(path) = std::env::var("DAWN_TUNING_LOG") {
        let _ = std::fs::write(path, &log_content);
    }
    let _ = std::fs::create_dir_all("docs");
    let _ = std::fs::write("docs/parameter_tuning_log.md", &log_content);
}

/// Deep stress for one candidate: 100k or 1e6 cycles. Set DAWN_STRESS_KS, DAWN_STRESS_KE (e.g. 24, 32)
/// and optionally DAWN_STRESS_CYCLES=1000000. Default cycles 100_000.
#[test]
#[ignore = "deep stress for shortlisted candidate; run with --ignored and env DAWN_STRESS_KS, DAWN_STRESS_KE"]
fn test_alpha512_deep_stress_candidate() {
    let k_s: usize = std::env::var("DAWN_STRESS_KS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);
    let k_e: usize = std::env::var("DAWN_STRESS_KE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    let cycles: usize = std::env::var("DAWN_STRESS_CYCLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    let params = KeyGenParams::dawn_alpha_512_custom(k_s, k_e, 1);
    let kem = DawnKem::new_with_params(params);

    let mut mismatches = 0u64;
    for i in 0..cycles {
        let kp = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ct, ss1) = match kem.encapsulate(&kp.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ss2 = match kem.decapsulate(&kp.secret_key, &ct) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                continue;
            }
        };
        if ss1 != ss2 {
            mismatches += 1;
        }
        if (i + 1) % 10_000 == 0 {
            eprintln!(
                "deep_stress k_s={} k_e={} cycles={} mismatches={}",
                k_s,
                k_e,
                i + 1,
                mismatches
            );
        }
    }
    eprintln!(
        "deep_stress k_s={} k_e={} total_cycles={} total_mismatches={}",
        k_s, k_e, cycles, mismatches
    );
    assert_eq!(
        mismatches, 0,
        "k_s={} k_e={}: {} mismatches in {} cycles",
        k_s, k_e, mismatches, cycles
    );
}

// --- Alpha1024 Path A: baseline decoder sweep and deep stress ---

/// Alpha1024 one candidate: PKE histogram (baseline) + KEM cycles (baseline). Returns (b0, b1, b2_4, b_gt4, kem_mismatches).
fn run_alpha1024_candidate_with_counts(
    k_s: usize,
    k_e: usize,
    d_c: u32,
    pke_samples: usize,
    kem_cycles: usize,
) -> (usize, usize, usize, usize, u64) {
    let params = KeyGenParams::dawn_alpha_1024_custom(k_s, k_e, d_c);
    let keypair = keypair_for_sweep_alpha1024(&params, k_s, k_e);

    let mut rng_seed = [0u8; 64];
    let seed_material = lib_q_dawn::security::generate_deterministic_high_entropy_data(
        &[
            b"sweep_alpha1024_pke".as_ref(),
            &(k_s as u64).to_le_bytes(),
            &(k_e as u64).to_le_bytes(),
        ]
        .concat(),
        64,
    );
    rng_seed.copy_from_slice(&seed_material);

    let (b0, b1, b2_4, b_gt4) =
        pke_failure_rate_histogram(&keypair, &params, pke_samples, &rng_seed);

    let kem = DawnKem::new_with_params(params);
    let mut mismatches = 0u64;
    for i in 0..kem_cycles {
        let kp = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ct, ss1) = match kem.encapsulate(&kp.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ss2 = match kem.decapsulate(&kp.secret_key, &ct) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                break;
            }
        };
        if ss1 != ss2 {
            mismatches += 1;
            break;
        }
        if kem_cycles >= 100 && (i + 1) % 100 == 0 {
            eprintln!(
                "alpha1024 progress k_s={} k_e={} kem_cycle={}/{} mismatches={}",
                k_s,
                k_e,
                i + 1,
                kem_cycles,
                mismatches
            );
        }
    }
    (b0, b1, b2_4, b_gt4, mismatches)
}

/// Quick grid for Alpha1024 (baseline decoder). Run with --ignored --nocapture.
#[test]
#[ignore = "Alpha1024 quick sweep for Path A; run with --ignored --nocapture"]
fn test_alpha1024_parameter_sweep_quick() {
    let k_s_values = [96usize, 128, 160, 192];
    let k_e_values = [128usize, 192, 256, 320];
    let d_c = 4u32;
    eprintln!(
        "--- Alpha1024 quick sweep (d_c={}, 1k PKE, 1k KEM per candidate, baseline decoder) ---",
        d_c
    );
    for &k_s in &k_s_values {
        for &k_e in &k_e_values {
            let (b0, b1, b2_4, b_gt4, mismatches) = run_alpha1024_candidate_with_counts(
                k_s,
                k_e,
                d_c,
                PKE_SAMPLES_QUICK,
                KEM_CYCLES_QUICK,
            );
            eprintln!(
                "alpha1024 k_s={} k_e={}  PKE: 0={} 1={} 2-4={} >4={}  KEM_mismatches={}",
                k_s, k_e, b0, b1, b2_4, b_gt4, mismatches
            );
        }
    }
}

/// Deep stress for one Alpha1024 candidate. Set DAWN_STRESS_KS, DAWN_STRESS_KE, DAWN_STRESS_DC, DAWN_STRESS_CYCLES.
#[test]
#[ignore = "Alpha1024 deep stress for shortlisted candidate; run with --ignored and env vars"]
fn test_alpha1024_deep_stress_candidate() {
    let k_s: usize = std::env::var("DAWN_STRESS_KS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(192);
    let k_e: usize = std::env::var("DAWN_STRESS_KE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);
    let d_c: u32 = std::env::var("DAWN_STRESS_DC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let cycles: usize = std::env::var("DAWN_STRESS_CYCLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    let params = KeyGenParams::dawn_alpha_1024_custom(k_s, k_e, d_c);
    let kem = DawnKem::new_with_params(params);

    let mut mismatches = 0u64;
    for i in 0..cycles {
        let kp = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ct, ss1) = match kem.encapsulate(&kp.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ss2 = match kem.decapsulate(&kp.secret_key, &ct) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                continue;
            }
        };
        if ss1 != ss2 {
            mismatches += 1;
        }
        if (i + 1) % 10_000 == 0 {
            eprintln!(
                "alpha1024 deep_stress k_s={} k_e={} d_c={} cycles={} mismatches={}",
                k_s,
                k_e,
                d_c,
                i + 1,
                mismatches
            );
        }
    }
    eprintln!(
        "alpha1024 deep_stress k_s={} k_e={} d_c={} total_cycles={} total_mismatches={}",
        k_s, k_e, d_c, cycles, mismatches
    );
    assert_eq!(
        mismatches, 0,
        "Alpha1024 k_s={} k_e={} d_c={}: {} mismatches in {} cycles",
        k_s, k_e, d_c, mismatches, cycles
    );
}

// --- Beta512 Path A fallback: baseline decoder sweep and deep stress ---

/// Beta512 one candidate: PKE histogram (baseline) + KEM cycles (baseline).
fn run_beta512_candidate_with_counts(
    k_s: usize,
    k_e: usize,
    d_c: u32,
    pke_samples: usize,
    kem_cycles: usize,
) -> (usize, usize, usize, usize, u64) {
    let params = KeyGenParams::dawn_beta_512_custom(k_s, k_e, d_c);
    let keypair = keypair_for_sweep_beta512(&params, k_s, k_e);

    let mut rng_seed = [0u8; 64];
    let seed_material = lib_q_dawn::security::generate_deterministic_high_entropy_data(
        &[
            b"sweep_beta512_pke".as_ref(),
            &(k_s as u64).to_le_bytes(),
            &(k_e as u64).to_le_bytes(),
        ]
        .concat(),
        64,
    );
    rng_seed.copy_from_slice(&seed_material);

    let (b0, b1, b2_4, b_gt4) =
        pke_failure_rate_histogram(&keypair, &params, pke_samples, &rng_seed);

    let kem = DawnKem::new_with_params(params);
    let mut mismatches = 0u64;
    for i in 0..kem_cycles {
        let kp = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ct, ss1) = match kem.encapsulate(&kp.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ss2 = match kem.decapsulate(&kp.secret_key, &ct) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                break;
            }
        };
        if ss1 != ss2 {
            mismatches += 1;
            break;
        }
        if kem_cycles >= 100 && (i + 1) % 100 == 0 {
            eprintln!(
                "beta512 progress k_s={} k_e={} kem_cycle={}/{} mismatches={}",
                k_s,
                k_e,
                i + 1,
                kem_cycles,
                mismatches
            );
        }
    }
    (b0, b1, b2_4, b_gt4, mismatches)
}

/// Quick grid for Beta512 (baseline decoder). Run with --ignored --nocapture.
#[test]
#[ignore = "Beta512 quick sweep for Path A fallback; run with --ignored --nocapture"]
fn test_beta512_parameter_sweep_quick() {
    let k_s_values = [24usize, 32, 40, 48];
    let k_e_values = [32usize, 48, 64, 80];
    let d_c = 2u32;
    eprintln!(
        "--- Beta512 quick sweep (d_c={}, 1k PKE, 1k KEM per candidate, baseline decoder) ---",
        d_c
    );
    for &k_s in &k_s_values {
        for &k_e in &k_e_values {
            let (b0, b1, b2_4, b_gt4, mismatches) = run_beta512_candidate_with_counts(
                k_s,
                k_e,
                d_c,
                PKE_SAMPLES_QUICK,
                KEM_CYCLES_QUICK,
            );
            eprintln!(
                "beta512 k_s={} k_e={}  PKE: 0={} 1={} 2-4={} >4={}  KEM_mismatches={}",
                k_s, k_e, b0, b1, b2_4, b_gt4, mismatches
            );
        }
    }
}

/// Deep stress for one Beta512 candidate. Set DAWN_STRESS_KS, DAWN_STRESS_KE, DAWN_STRESS_DC, DAWN_STRESS_CYCLES.
#[test]
#[ignore = "Beta512 deep stress for shortlisted candidate; run with --ignored and env vars"]
fn test_beta512_deep_stress_candidate() {
    let k_s: usize = std::env::var("DAWN_STRESS_KS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(48);
    let k_e: usize = std::env::var("DAWN_STRESS_KE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let d_c: u32 = std::env::var("DAWN_STRESS_DC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let cycles: usize = std::env::var("DAWN_STRESS_CYCLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    let params = KeyGenParams::dawn_beta_512_custom(k_s, k_e, d_c);
    let kem = DawnKem::new_with_params(params);

    let mut mismatches = 0u64;
    for i in 0..cycles {
        let kp = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ct, ss1) = match kem.encapsulate(&kp.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ss2 = match kem.decapsulate(&kp.secret_key, &ct) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                continue;
            }
        };
        if ss1 != ss2 {
            mismatches += 1;
        }
        if (i + 1) % 10_000 == 0 {
            eprintln!(
                "beta512 deep_stress k_s={} k_e={} d_c={} cycles={} mismatches={}",
                k_s,
                k_e,
                d_c,
                i + 1,
                mismatches
            );
        }
    }
    eprintln!(
        "beta512 deep_stress k_s={} k_e={} d_c={} total_cycles={} total_mismatches={}",
        k_s, k_e, d_c, cycles, mismatches
    );
    assert_eq!(
        mismatches, 0,
        "Beta512 k_s={} k_e={} d_c={}: {} mismatches in {} cycles",
        k_s, k_e, d_c, mismatches, cycles
    );
}
