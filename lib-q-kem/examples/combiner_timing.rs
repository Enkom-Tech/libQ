//! Rough wall-clock timing of the ML-KEM-1024 + HQC-256 combiner against its components.
//!
//! `cargo run --release -p lib-q-kem --features combiner --example combiner_timing [iters]`
//!
//! Median of `iters` runs (default 200). One machine, no isolation: a data point for sizing, not
//! a benchmark. Use it to compare the combiner to ML-KEM-1024 alone on the target device.

use std::hint::black_box;
use std::time::Instant;

use lib_q_core::{Algorithm, KemOperations};
use lib_q_hqc::LibQHqcProvider;
use lib_q_kem::combiner;
use lib_q_ml_kem::{Decapsulate, Encapsulate, KemCore, MlKem1024};

fn median_us<T>(mut f: impl FnMut() -> T, iters: usize) -> f64 {
    let mut v: Vec<f64> = (0..iters)
        .map(|_| {
            let t = Instant::now();
            black_box(f());
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let mut rng = lib_q_random::new_secure_rng().unwrap();

    let (dk, ek) = MlKem1024::generate(&mut rng);
    let (ct_m, _) = ek.encapsulate(&mut rng).unwrap();
    let ml_kg = median_us(|| MlKem1024::generate(&mut rng), iters);
    let ml_en = median_us(|| ek.encapsulate(&mut rng).unwrap(), iters);
    let ml_de = median_us(|| dk.decapsulate(&ct_m).unwrap(), iters);

    let hqc = LibQHqcProvider::new().unwrap();
    let seed = [7u8; 48];
    let hkp = hqc
        .generate_keypair(Algorithm::Hqc256, Some(&seed))
        .unwrap();
    let (hct, _) = hqc
        .encapsulate(Algorithm::Hqc256, &hkp.public_key, Some(&seed))
        .unwrap();
    let hq_kg = median_us(
        || {
            hqc.generate_keypair(Algorithm::Hqc256, Some(&seed))
                .unwrap()
        },
        iters,
    );
    let hq_en = median_us(
        || {
            hqc.encapsulate(Algorithm::Hqc256, &hkp.public_key, Some(&seed))
                .unwrap()
        },
        iters,
    );
    let hq_de = median_us(
        || {
            hqc.decapsulate(Algorithm::Hqc256, &hkp.secret_key, &hct)
                .unwrap()
        },
        iters,
    );

    let kp = combiner::generate_keypair().unwrap();
    let (ct, _) = combiner::encapsulate(&kp.public_key).unwrap();
    let c_kg = median_us(|| combiner::generate_keypair().unwrap(), iters);
    let c_en = median_us(|| combiner::encapsulate(&kp.public_key).unwrap(), iters);
    let c_de = median_us(
        || combiner::decapsulate(&kp.secret_key, &ct).unwrap(),
        iters,
    );

    println!("median of {iters} runs, microseconds");
    println!("{:<22}{:>10}{:>10}{:>10}", "", "keygen", "encaps", "decaps");
    println!(
        "{:<22}{ml_kg:>10.0}{ml_en:>10.0}{ml_de:>10.0}",
        "ML-KEM-1024"
    );
    println!("{:<22}{hq_kg:>10.0}{hq_en:>10.0}{hq_de:>10.0}", "HQC-256");
    println!(
        "{:<22}{c_kg:>10.0}{c_en:>10.0}{c_de:>10.0}",
        "combiner (both + KDF)"
    );
    println!(
        "sizes: pk {} B, ct {} B, sk {} B (ML-KEM-1024 alone: pk 1568, ct 1568)",
        combiner::PUBLIC_KEY_SIZE,
        combiner::CIPHERTEXT_SIZE,
        combiner::SECRET_KEY_SIZE
    );
}
