//! ML-KEM (FIPS 203) shared secret used as witness for a small STARK (`ArithmeticAir`).
//!
//! This ties NIST PQC KEM output to the default STARK stack used elsewhere in `lib-q-zkp` tests.
//! A full prove/verify pipeline for [`SessionKeyDerivationAir`](lib_q_zkp::air::SessionKeyDerivationAir)
//! is not yet wired to the same constraint system as trace generation; that AIR is covered by
//! trace-generation unit tests in `session_key.rs`.

#![cfg(feature = "zkp")]

use lib_q_ml_kem::{
    Decapsulate,
    Encapsulate,
    KemCore,
    MlKem768,
};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::{
    ArithmeticAir,
    TraceGenerator,
};
use lib_q_zkp::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
};

type Val = Complex<Mersenne31>;

const MIN_TRACE_ROWS: usize = 64;

fn padded_arithmetic_trace(
    a: u32,
    b: u32,
) -> (lib_q_stark_matrix::dense::RowMajorMatrix<Val>, Vec<Val>) {
    let air = ArithmeticAir::new(1).expect("air");
    let product = a * b;
    let inputs = vec![(Val::from(Mersenne31::new(a)), Val::from(Mersenne31::new(b)))];
    let trace = air.generate_trace(&inputs).expect("trace");
    let width = trace.width();
    let h = trace.height();
    let mut padded_values = trace.values.clone();
    if h < MIN_TRACE_ROWS {
        let row: Vec<Val> = (0..width)
            .map(|i| {
                if i % 3 == 0 {
                    Val::from(Mersenne31::new(a))
                } else if i % 3 == 1 {
                    Val::from(Mersenne31::new(b))
                } else {
                    Val::from(Mersenne31::new(product))
                }
            })
            .collect();
        for _ in h..MIN_TRACE_ROWS {
            padded_values.extend_from_slice(&row);
        }
    }
    let trace = lib_q_stark_matrix::dense::RowMajorMatrix::new(padded_values, width);
    let pv = vec![Val::from(Mersenne31::new(product))];
    (trace, pv)
}

#[test]
fn ml_kem_shared_secret_arithmetic_air_prove_verify() {
    let mut rng = lib_q_random::new_secure_rng().expect("secure rng");
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, k_send) = ek.encapsulate(&mut rng).expect("encapsulate");
    let k_recv = dk.decapsulate(&ct).expect("decapsulate");
    assert_eq!(k_send, k_recv, "ML-KEM shared secrets must match");

    let ss = k_send.as_slice();
    let a = ss[0] as u32;
    let b = ss[1] as u32;

    let air = ArithmeticAir::new(1).expect("air");
    let (trace, public_values) = padded_arithmetic_trace(a, b);

    let config = default_config();
    let proof = StarkProver::new(config.clone())
        .prove(&air, trace, &public_values)
        .expect("prove");
    StarkVerifier::new(config)
        .verify(&air, &proof, &public_values)
        .expect("verify");
}
