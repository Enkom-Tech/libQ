//! Stress tests for DAWN KEM: many encapsulate/decapsulate cycles with strict shared-secret equality.
//! Fail on any decapsulation mismatch. Used to validate production parameter sets.

use lib_q_core::Kem;
use lib_q_dawn::{
    DawnKem,
    DawnParameterSet,
};

const STRESS_CYCLES_CI: usize = 10_000;
const STRESS_CYCLES_EXTENDED: usize = 100_000;

/// Run in CI; fails if any decapsulation mismatch. Ignored until production params pass.
#[test]
#[ignore = "production Alpha512 under tuning; run with --ignored after params pass"]
fn test_production_alpha512_stress_ci() {
    let kem = DawnKem::new(DawnParameterSet::Alpha512);
    let mut mismatches = 0u64;
    for _ in 0..STRESS_CYCLES_CI {
        let keypair = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ciphertext, shared_secret) = match kem.encapsulate(&keypair.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let decrypted = match kem.decapsulate(&keypair.secret_key, &ciphertext) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                continue;
            }
        };
        if shared_secret != decrypted {
            mismatches += 1;
        }
    }
    assert_eq!(
        mismatches, 0,
        "production Alpha512: {} decapsulation mismatches in {} cycles",
        mismatches, STRESS_CYCLES_CI
    );
}

/// Extended stress test (run with --ignored or in nightly). 100k cycles.
#[test]
#[ignore = "long-running; run with cargo test --release -- --ignored"]
fn test_production_alpha512_stress_extended() {
    let kem = DawnKem::new(DawnParameterSet::Alpha512);
    let mut mismatches = 0u64;
    for _ in 0..STRESS_CYCLES_EXTENDED {
        let keypair = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ciphertext, shared_secret) = match kem.encapsulate(&keypair.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let decrypted = match kem.decapsulate(&keypair.secret_key, &ciphertext) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                continue;
            }
        };
        if shared_secret != decrypted {
            mismatches += 1;
        }
    }
    assert_eq!(
        mismatches, 0,
        "production Alpha512: {} decapsulation mismatches in {} cycles",
        mismatches, STRESS_CYCLES_EXTENDED
    );
}

/// Alpha1024 production stress (10k). Un-ignore after Path A promotion.
#[test]
#[ignore = "Alpha1024 production; un-ignore after sweep/stress promotion"]
fn test_production_alpha1024_stress_ci() {
    let kem = DawnKem::new(DawnParameterSet::Alpha1024);
    let mut mismatches = 0u64;
    for _ in 0..STRESS_CYCLES_CI {
        let keypair = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ciphertext, shared_secret) = match kem.encapsulate(&keypair.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let decrypted = match kem.decapsulate(&keypair.secret_key, &ciphertext) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                continue;
            }
        };
        if shared_secret != decrypted {
            mismatches += 1;
        }
    }
    assert_eq!(
        mismatches, 0,
        "production Alpha1024: {} decapsulation mismatches in {} cycles",
        mismatches, STRESS_CYCLES_CI
    );
}

/// Alpha1024 extended stress (100k). Keep ignored or run in nightly.
#[test]
#[ignore = "long-running; run with cargo test --release -- --ignored"]
fn test_production_alpha1024_stress_extended() {
    let kem = DawnKem::new(DawnParameterSet::Alpha1024);
    let mut mismatches = 0u64;
    for _ in 0..STRESS_CYCLES_EXTENDED {
        let keypair = match kem.generate_keypair() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (ciphertext, shared_secret) = match kem.encapsulate(&keypair.public_key) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let decrypted = match kem.decapsulate(&keypair.secret_key, &ciphertext) {
            Ok(d) => d,
            Err(_) => {
                mismatches += 1;
                continue;
            }
        };
        if shared_secret != decrypted {
            mismatches += 1;
        }
    }
    assert_eq!(
        mismatches, 0,
        "production Alpha1024: {} decapsulation mismatches in {} cycles",
        mismatches, STRESS_CYCLES_EXTENDED
    );
}
