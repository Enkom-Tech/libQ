//! Dudect-style timing smoke for `hardened` ML-KEM decapsulation.

use lib_q_ml_kem::{
    Decapsulate,
    Encapsulate,
    KemCore,
    MlKem768,
};
use lib_q_random::new_secure_rng;
use lib_q_sca_test::dudect::timing_passes_loose;

#[test]
fn hardened_dudect_smoke_decapsulate() {
    let mut rng = new_secure_rng().expect("secure rng");
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, _) = ek.encapsulate(&mut rng).expect("encap");

    let mut fast_path = Vec::with_capacity(200);
    let mut slow_path = Vec::with_capacity(200);
    for i in 0..100u8 {
        let start = std::time::Instant::now();
        let _ = dk.decapsulate(&ct);
        fast_path.push(start.elapsed().as_secs_f64());

        let mut bad = ct.clone();
        bad[0] ^= i.wrapping_add(1);
        let start = std::time::Instant::now();
        let _ = dk.decapsulate(&bad);
        slow_path.push(start.elapsed().as_secs_f64());
    }
    let mut samples = fast_path;
    samples.extend(slow_path);
    assert!(
        timing_passes_loose(6.0, &samples),
        "hardened decapsulate timing smoke failed (loose gate)"
    );
}
