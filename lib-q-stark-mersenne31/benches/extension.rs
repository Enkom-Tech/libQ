use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_stark_field::extension::{
    BinomialExtensionField,
    Complex,
};
use lib_q_stark_field_testing::bench_func::{
    benchmark_inv,
    benchmark_mul_latency,
    benchmark_mul_throughput,
    benchmark_square,
};
use lib_q_stark_mersenne31::Mersenne31;

type EF2 = BinomialExtensionField<Complex<Mersenne31>, 2>;
type EF3 = BinomialExtensionField<Complex<Mersenne31>, 3>;

const REPS: usize = 100;
const L_REPS: usize = 10 * REPS;

fn bench_quadratic_extension(c: &mut Criterion) {
    let name = "BinomialExtensionField<Mersenne31Complex<Mersenne31>, 2>";
    benchmark_square::<EF2>(c, name);
    benchmark_inv::<EF2>(c, name);
    benchmark_mul_throughput::<EF2, REPS>(c, name);
    benchmark_mul_latency::<EF2, L_REPS>(c, name);
}

fn bench_cubic_extension(c: &mut Criterion) {
    let name = "BinomialExtensionField<Mersenne31Complex<Mersenne31>, 3>";
    benchmark_square::<EF3>(c, name);
    benchmark_inv::<EF3>(c, name);
    benchmark_mul_throughput::<EF3, REPS>(c, name);
    benchmark_mul_latency::<EF3, L_REPS>(c, name);
}

criterion_group!(bench_mersennecomplex_ef2, bench_quadratic_extension);
criterion_group!(bench_mersennecomplex_ef3, bench_cubic_extension);

criterion_main!(bench_mersennecomplex_ef2, bench_mersennecomplex_ef3);
