//! FFT benchmarks for STARK-scale fields.
//!
//! Base [`Mersenne31`] has `TWO_ADICITY = 1` (subgroup order 2 only). Do not benchmark
//! generic [`TwoAdicSubgroupDft`] on raw `Mersenne31`; use [`Complex<Mersenne31>`] or
//! [`Mersenne31Dft`] instead (see `lib-q-stark-mersenne31::dft`).

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_stark_dft::{
    Radix2Bowers,
    Radix2Dit,
    Radix2DitParallel,
    TwoAdicSubgroupDft,
};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    Algebra,
    BasedVectorSpace,
    TwoAdicField,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::{
    Mersenne31,
    Mersenne31ComplexRadix2Dit,
    Mersenne31Dft,
};
use lib_q_stark_util::pretty_name;
use rand::SeedableRng;
use rand::distr::{
    Distribution,
    StandardUniform,
};
use rand::rngs::SmallRng;

fn bench_fft(c: &mut Criterion) {
    // log_sizes for Mersenne31Dft (real input, complex-packed FFT).
    let log_sizes = &[14, 16, 18, 20, 22];
    // Half exponents for direct Complex<Mersenne31> FFT (same evaluation count as m31_fft).
    let log_half_sizes = &[13, 15, 17];

    const BATCH_SIZE: usize = 256;

    fft::<Complex<Mersenne31>, Radix2Dit<_>, BATCH_SIZE>(c, log_half_sizes);
    fft::<Complex<Mersenne31>, Radix2Bowers, BATCH_SIZE>(c, log_half_sizes);
    fft::<Complex<Mersenne31>, Radix2DitParallel<_>, BATCH_SIZE>(c, log_half_sizes);
    fft::<Complex<Mersenne31>, Mersenne31ComplexRadix2Dit, BATCH_SIZE>(c, log_half_sizes);

    coset_lde::<Complex<Mersenne31>, Radix2Dit<_>, BATCH_SIZE>(c, log_half_sizes);
    coset_lde::<Complex<Mersenne31>, Radix2Bowers, BATCH_SIZE>(c, log_half_sizes);
    coset_lde::<Complex<Mersenne31>, Radix2DitParallel<_>, BATCH_SIZE>(c, log_half_sizes);

    m31_fft::<Radix2Dit<_>, BATCH_SIZE>(c, log_sizes);
    m31_fft::<Mersenne31ComplexRadix2Dit, BATCH_SIZE>(c, log_sizes);
}

fn fft<F, Dft, const BATCH_SIZE: usize>(c: &mut Criterion, log_sizes: &[usize])
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    StandardUniform: Distribution<F>,
{
    let mut group = c.benchmark_group(format!(
        "fft/{}/{}/ncols={}",
        pretty_name::<F>(),
        pretty_name::<Dft>(),
        BATCH_SIZE
    ));
    group.sample_size(10);

    let mut rng = SmallRng::seed_from_u64(1);
    for n_log in log_sizes {
        let n = 1 << n_log;

        let messages = RowMajorMatrix::rand(&mut rng, n, BATCH_SIZE);

        let dft = Dft::default();
        group.bench_with_input(BenchmarkId::from_parameter(n), &dft, |b, dft| {
            b.iter(|| {
                dft.dft_batch(messages.clone());
            });
        });
    }
}

#[allow(dead_code)]
fn fft_algebra<F, V, Dft, const BATCH_SIZE: usize>(c: &mut Criterion, log_sizes: &[usize])
where
    F: TwoAdicField,
    V: Algebra<F> + BasedVectorSpace<F> + Clone + Default + Send + Sync,
    Dft: TwoAdicSubgroupDft<F>,
    StandardUniform: Distribution<V>,
{
    let mut group = c.benchmark_group(format!(
        "fft_algebra/{}/{}/{}/ncols={}",
        pretty_name::<F>(),
        pretty_name::<Dft>(),
        pretty_name::<V>(),
        BATCH_SIZE
    ));
    group.sample_size(10);

    let mut rng = SmallRng::seed_from_u64(1);
    for n_log in log_sizes {
        let n = 1 << n_log;

        let messages = RowMajorMatrix::<V>::rand(&mut rng, n, BATCH_SIZE);

        let dft = Dft::default();
        group.bench_with_input(BenchmarkId::from_parameter(n), &dft, |b, dft| {
            b.iter(|| {
                dft.dft_algebra_batch(messages.clone());
            });
        });
    }
}

fn m31_fft<Dft, const BATCH_SIZE: usize>(c: &mut Criterion, log_sizes: &[usize])
where
    Dft: TwoAdicSubgroupDft<Complex<Mersenne31>>,
    StandardUniform: Distribution<Mersenne31>,
{
    let mut group = c.benchmark_group(format!(
        "m31_fft::<{}, {}>",
        pretty_name::<Dft>(),
        BATCH_SIZE
    ));
    group.sample_size(10);

    let mut rng = SmallRng::seed_from_u64(1);
    for n_log in log_sizes {
        let n = 1 << n_log;

        let messages = RowMajorMatrix::rand(&mut rng, n, BATCH_SIZE);

        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                Mersenne31Dft::dft_batch::<Dft>(&messages);
            });
        });
    }
}

fn coset_lde<F, Dft, const BATCH_SIZE: usize>(c: &mut Criterion, log_sizes: &[usize])
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    StandardUniform: Distribution<F>,
{
    let mut group = c.benchmark_group(format!(
        "coset_lde/{}/{}/ncols={}",
        pretty_name::<F>(),
        pretty_name::<Dft>(),
        BATCH_SIZE
    ));
    group.sample_size(10);

    let mut rng = SmallRng::seed_from_u64(1);
    for n_log in log_sizes {
        let n = 1 << n_log;

        let messages = RowMajorMatrix::rand(&mut rng, n, BATCH_SIZE);

        let dft = Dft::default();
        group.bench_with_input(BenchmarkId::from_parameter(n), &dft, |b, dft| {
            b.iter(|| {
                dft.coset_lde_batch(messages.clone(), 1, F::GENERATOR);
            });
        });
    }
}

criterion_group!(benches, bench_fft);
criterion_main!(benches);
