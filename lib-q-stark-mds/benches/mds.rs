use core::any::type_name;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
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
    Rng,
    SeedableRng,
};

fn bench_all_mds(c: &mut Criterion) {
    bench_mds::<Mersenne31, IntegratedCosetMds<Mersenne31, 16>, 16>(c);
    bench_mds::<<Mersenne31 as Field>::Packing, IntegratedCosetMds<Mersenne31, 16>, 16>(c);
    bench_mds::<Mersenne31, CosetMds<Mersenne31, 16>, 16>(c);
    bench_mds::<<Mersenne31 as Field>::Packing, CosetMds<Mersenne31, 16>, 16>(c);

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
    c.bench_with_input(id, &input, |b, input| b.iter(|| mds.permute(input.clone())));
}

criterion_group!(benches, bench_all_mds);
criterion_main!(benches);
