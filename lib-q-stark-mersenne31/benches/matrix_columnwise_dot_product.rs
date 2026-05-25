use criterion::{
    BatchSize,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_stark_field::extension::{
    BinomialExtensionField,
    Complex,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use rand::SeedableRng;
use rand::rngs::SmallRng;

fn columnwise_dot_product(c: &mut Criterion) {
    let mut rng = SmallRng::seed_from_u64(0);

    // Use Complex<Mersenne31> as the base field since EF extends it, not Mersenne31 directly
    type F = Complex<Mersenne31>;
    // Mersenne31 doesn't support direct degree 4 extensions. Use Complex<Mersenne31> with degree 2.
    type EF = BinomialExtensionField<Complex<Mersenne31>, 2>;
    let log_rows = 16;

    c.benchmark_group("Mersenne31")
        .sample_size(10)
        .bench_function("columnwise_dot_product", |b| {
            b.iter_batched(
                || {
                    (
                        RowMajorMatrix::<F>::rand_nonzero(&mut rng, 1 << log_rows, 1 << 12),
                        RowMajorMatrix::<EF>::rand_nonzero(&mut rng, 1 << log_rows, 1).values,
                    )
                },
                |(m, v)| m.columnwise_dot_product(&v),
                BatchSize::PerIteration,
            );
        });
}

criterion_group!(benches, columnwise_dot_product);
criterion_main!(benches);
