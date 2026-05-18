//! MDS permutation benchmarks.
//!
//! [`CosetMds`] and [`IntegratedCosetMds`] build FFT twiddles via
//! [`TwoAdicField::two_adic_generator`]. Base [`Mersenne31`] has `TWO_ADICITY = 1`, so
//! coset MDS at width 16 is benchmarked on [`Complex<Mersenne31>`] only. Static
//! [`MdsMatrixMersenne31`] benches remain on the base field.

use core::any::type_name;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
// Goldilocks field not integrated - commenting out
// use p3_goldilocks::{
//     Goldilocks,
//     MdsMatrixGoldilocks,
// };
use lib_q_stark_mds::MdsPermutation;
use lib_q_stark_mds::coset_mds::CosetMds;
use lib_q_stark_mds::integrated_coset_mds::IntegratedCosetMds;
use lib_q_stark_mersenne31::{
    MdsMatrixMersenne31,
    Mersenne31,
};
use rand::distr::{
    Distribution,
    StandardUniform,
};
use rand::rngs::SmallRng;
use rand::{
    RngExt,
    SeedableRng,
};

fn bench_all_mds(c: &mut Criterion) {
    type F = Complex<Mersenne31>;

    bench_mds::<F, IntegratedCosetMds<F, 16>, 16>(c);
    bench_mds::<<F as Field>::Packing, IntegratedCosetMds<F, 16>, 16>(c);
    bench_mds::<F, CosetMds<F, 16>, 16>(c);
    bench_mds::<<F as Field>::Packing, CosetMds<F, 16>, 16>(c);

    bench_mds::<Mersenne31, MdsMatrixMersenne31, 8>(c);
    bench_mds::<Mersenne31, MdsMatrixMersenne31, 12>(c);
    bench_mds::<Mersenne31, MdsMatrixMersenne31, 16>(c);
    bench_mds::<Mersenne31, MdsMatrixMersenne31, 32>(c);
    bench_mds::<Mersenne31, MdsMatrixMersenne31, 64>(c);

    // Goldilocks field not integrated - commenting out benchmarks
    // bench_mds::<Goldilocks, MdsMatrixGoldilocks, 8>(c);
    // bench_mds::<Goldilocks, MdsMatrixGoldilocks, 12>(c);
    // bench_mds::<Goldilocks, MdsMatrixGoldilocks, 16>(c);
    // bench_mds::<Goldilocks, MdsMatrixGoldilocks, 32>(c);
    // bench_mds::<Goldilocks, MdsMatrixGoldilocks, 64>(c);
}

fn bench_mds<R, Mds, const WIDTH: usize>(c: &mut Criterion)
where
    R: PrimeCharacteristicRing,
    StandardUniform: Distribution<R>,
    Mds: MdsPermutation<R, WIDTH> + Default,
{
    let mds = Mds::default();

    let mut rng = SmallRng::seed_from_u64(1);
    let input = rng.random::<[R; WIDTH]>();
    let id = BenchmarkId::new(type_name::<Mds>(), WIDTH);
    c.bench_with_input(id, &input, |b, input: &[R; WIDTH]| {
        b.iter(|| mds.permute(input.clone()))
    });
}

criterion_group!(benches, bench_all_mds);
criterion_main!(benches);
