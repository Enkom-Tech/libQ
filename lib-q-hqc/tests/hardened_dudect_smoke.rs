//! Dudect-style timing smoke for `hardened` HQC KEM decapsulation.

use lib_q_hqc::hqc_kem::HqcKem;
use lib_q_hqc::params_correct::Hqc1Params;
use lib_q_random::new_secure_rng;
use lib_q_sca_test::dudect::timing_passes_loose;

#[test]
fn hardened_dudect_smoke_decapsulate() {
    let kem = HqcKem::<Hqc1Params>::new().expect("HqcKem::new");
    let mut rng = new_secure_rng().expect("secure rng");
    let (pk, sk) = kem.keygen(&mut rng).expect("keygen");
    let (ct, _) = kem.encapsulate(&pk, &mut rng).expect("encap");

    // Keep iteration count low: HQC decaps is much slower than ML-KEM on CI runners.
    const SMOKE_ITERS: u8 = 24;
    let mut fast_path = Vec::with_capacity(SMOKE_ITERS as usize * 2);
    let mut slow_path = Vec::with_capacity(SMOKE_ITERS as usize * 2);
    for i in 0..SMOKE_ITERS {
        let start = std::time::Instant::now();
        let _ = kem.decapsulate(&sk, &ct);
        fast_path.push(start.elapsed().as_secs_f64());

        let (c_pke, salt) = ct.parse();
        let mut c_data = c_pke.data.clone();
        c_data[0] ^= i.wrapping_add(1);
        let bad = lib_q_hqc::hqc_kem::HqcKemCiphertext::new(
            lib_q_hqc::hqc_pke::HqcPkeCiphertext::new(c_data),
            salt,
        );
        let start = std::time::Instant::now();
        let _ = kem.decapsulate(&sk, &bad);
        slow_path.push(start.elapsed().as_secs_f64());
    }
    let mut samples = fast_path;
    samples.extend(slow_path);
    assert!(
        timing_passes_loose(6.0, &samples),
        "hardened HQC decapsulate timing smoke failed (loose gate)"
    );
}
