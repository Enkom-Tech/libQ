//! FRI even/odd fold benchmarks.
//!
//! Base [`Mersenne31`] has `TWO_ADICITY = 1`; [`TwoAdicFriFolding::fold_matrix`] needs
//! `log2(height) + 1` two-adic bits. Benchmark only [`Complex<Mersenne31>`] (see
//! `lib-q-stark-dft/benches/fft.rs`).

use core::marker::PhantomData;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_random::DeterministicRng;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    ExtensionField,
    TwoAdicField,
};
use lib_q_stark_fri::{
    FriFoldingStrategy,
    TwoAdicFriFolding,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_stark_util::pretty_name;
use rand::RngExt;
// Goldilocks field not integrated
// use p3_goldilocks::Goldilocks;
use rand::distr::{
    Distribution,
    StandardUniform,
};

fn bench<F: TwoAdicField, EF: ExtensionField<F>>(c: &mut Criterion, log_sizes: &[usize])
where
    StandardUniform: Distribution<EF>,
{
    let name = format!("fold_matrix::<{}>", pretty_name::<EF>(),);
    let mut group = c.benchmark_group(&name);
    group.sample_size(10);
    let folding = TwoAdicFriFolding::<(), ()>(PhantomData);

    for log_size in log_sizes {
        let n = 1 << log_size;

        let mut rng = DeterministicRng::seed_from_u64(n as u64);
        let beta = rng.sample(StandardUniform);
        let mat = RowMajorMatrix::<EF>::rand(&mut rng, n, 2);

        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                folding.fold_matrix(beta, mat.clone());
            });
        });
    }
}

fn bench_fold_even_odd(c: &mut Criterion) {
    let log_sizes = [12, 14, 16, 18, 20, 22];

    bench::<Complex<Mersenne31>, Complex<Mersenne31>>(c, &log_sizes);
}

criterion_group!(benches, bench_fold_even_odd);
criterion_main!(benches);
