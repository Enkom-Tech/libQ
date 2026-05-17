use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_stark_dft::{
    Radix2Bowers,
    Radix2DFTSmallBatch,
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
// RecursiveDft only supports MontyField31, not Mersenne31
// use lib_q_stark_monty31::dft::RecursiveDft;
use lib_q_stark_util::pretty_name;
// Goldilocks field not integrated
// use p3_goldilocks::Goldilocks;
use rand::SeedableRng;
use rand::distr::{
    Distribution,
    StandardUniform,
};
use rand::rngs::SmallRng;

fn bench_fft(c: &mut Criterion) {
    // log_sizes correspond to the sizes of DFT we want to benchmark;
    // for the DFT over the quadratic extension "Mersenne31Complex" a
    // fairer comparison is to use half sizes, which is the log minus 1.
    let log_sizes = &[14, 16, 18, 20, 22];
    let log_half_sizes = &[13, 15, 17];

    const BATCH_SIZE: usize = 256;
    // Mersenne31 doesn't support degree 5 extensions - use degree 3 instead
    // Extension field type alias commented out until needed
    // type BBExt = BinomialExtensionField<Mersenne31, 5>;
    // type BBExt = BinomialExtensionField<Mersenne31, 3>;

    fft::<Mersenne31, Radix2DFTSmallBatch<_>, BATCH_SIZE>(c, log_sizes);
    fft::<Mersenne31, Radix2Dit<_>, BATCH_SIZE>(c, log_sizes);
    // RecursiveDft only supports MontyField31, not Mersenne31
    // fft::<Mersenne31, RecursiveDft<_>, BATCH_SIZE>(c, log_sizes);
    fft::<Mersenne31, Radix2Bowers, BATCH_SIZE>(c, log_sizes);
    fft::<Mersenne31, Radix2DitParallel<_>, BATCH_SIZE>(c, log_sizes);
    // Goldilocks field not integrated - benchmarks removed
    // fft::<Goldilocks, Radix2Dit<_>, BATCH_SIZE>(c, log_sizes);
    // fft::<Goldilocks, Radix2Bowers, BATCH_SIZE>(c, log_sizes);
    // fft::<Goldilocks, Radix2DitParallel<_>, BATCH_SIZE>(c, log_sizes);
    fft::<Complex<Mersenne31>, Radix2Dit<_>, BATCH_SIZE>(c, log_half_sizes);
    fft::<Complex<Mersenne31>, Radix2Bowers, BATCH_SIZE>(c, log_half_sizes);
    fft::<Complex<Mersenne31>, Radix2DitParallel<_>, BATCH_SIZE>(c, log_half_sizes);

    fft::<Complex<Mersenne31>, Mersenne31ComplexRadix2Dit, BATCH_SIZE>(c, log_half_sizes);
    m31_fft::<Radix2Dit<_>, BATCH_SIZE>(c, log_sizes);
    m31_fft::<Mersenne31ComplexRadix2Dit, BATCH_SIZE>(c, log_sizes);

    // Goldilocks field not integrated - benchmarks removed
    // ifft::<Goldilocks, Radix2Dit<_>, BATCH_SIZE>(c, log_sizes);

    // RecursiveDft only supports MontyField31, not Mersenne31
    // coset_lde::<Mersenne31, RecursiveDft<_>, BATCH_SIZE>(c, log_sizes);
    coset_lde::<Mersenne31, Radix2Dit<_>, BATCH_SIZE>(c, log_sizes);
    coset_lde::<Mersenne31, Radix2Bowers, BATCH_SIZE>(c, log_sizes);
    coset_lde::<Mersenne31, Radix2DitParallel<_>, BATCH_SIZE>(c, log_sizes);
    // Goldilocks field not integrated - benchmarks removed
    // coset_lde::<Goldilocks, Radix2Bowers, BATCH_SIZE>(c, log_sizes);

    // The FFT is much slower when handling extension fields so we use smaller sizes:
    // Mersenne31 only supports degree 2 and 3 extensions, not degree 5
    // Extension field benchmarks commented out until needed
    // let ext_log_sizes = &[10, 12, 14];
    // const EXT_BATCH_SIZE: usize = 50;
    // fft::<BBExt, Radix2Dit<_>, EXT_BATCH_SIZE>(c, ext_log_sizes);
    // fft::<BBExt, Radix2DitParallel<_>, EXT_BATCH_SIZE>(c, ext_log_sizes);
    // fft_algebra::<Mersenne31, BBExt, Radix2DFTSmallBatch<_>, EXT_BATCH_SIZE>(c, ext_log_sizes);
    // fft_algebra::<Mersenne31, BBExt, Radix2Dit<_>, EXT_BATCH_SIZE>(c, ext_log_sizes);
    // fft_algebra::<Mersenne31, BBExt, Radix2DitParallel<_>, EXT_BATCH_SIZE>(c, ext_log_sizes);
    // fft_algebra::<Mersenne31, BBExt, RecursiveDft<_>, EXT_BATCH_SIZE>(c, ext_log_sizes);
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

// Kept for future use when extension field benchmarks are re-enabled
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

// Kept for future use when Goldilocks field benchmarks are re-enabled
#[allow(dead_code)]
fn ifft<F, Dft, const BATCH_SIZE: usize>(c: &mut Criterion, log_sizes: &[usize])
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    StandardUniform: Distribution<F>,
{
    let mut group = c.benchmark_group(format!(
        "ifft/{}/{}/ncols={}",
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
                dft.idft_batch(messages.clone());
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
