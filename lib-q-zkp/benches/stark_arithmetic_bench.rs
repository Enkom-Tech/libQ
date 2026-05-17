//! Criterion benchmarks: small `ArithmeticAir` STARK prove + verify (regression guard).

use criterion::{
    BatchSize,
    Criterion,
    criterion_group,
    criterion_main,
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

fn bench_stark_arithmetic_prove_verify(c: &mut Criterion) {
    let air = ArithmeticAir::new(1).expect("air");
    let (trace, public_values) = padded_arithmetic_trace(3, 4);

    let config = default_config();

    c.bench_function("stark_arithmetic_prove", |b| {
        b.iter_batched(
            || (trace.clone(), public_values.clone()),
            |(tr, pv)| {
                StarkProver::new(config.clone())
                    .prove(&air, tr, &pv)
                    .expect("prove")
            },
            BatchSize::SmallInput,
        );
    });

    let proof = StarkProver::new(config.clone())
        .prove(&air, trace.clone(), &public_values)
        .expect("setup prove");

    c.bench_function("stark_arithmetic_verify", |b| {
        b.iter(|| {
            StarkVerifier::new(config.clone())
                .verify(&air, &proof, &public_values)
                .expect("verify");
        });
    });
}

criterion_group!(benches, bench_stark_arithmetic_prove_verify);
criterion_main!(benches);
