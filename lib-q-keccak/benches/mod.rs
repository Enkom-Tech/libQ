#![cfg_attr(all(test, feature = "nightly"), feature(test))]
#![cfg_attr(feature = "simd", feature(portable_simd))]

#[cfg(all(test, feature = "nightly"))]
extern crate test;

use lib_q_keccak::*;

#[cfg(all(test, feature = "nightly"))]
macro_rules! impl_bench {
    ($name:ident, $fn:ident, $type:expr) => {
        #[bench]
        fn $name(b: &mut test::Bencher) {
            let mut data = [$type; 25];
            b.iter(|| $fn(&mut data));
        }
    };
}

#[cfg(all(test, feature = "nightly"))]
impl_bench!(b_f1600, f1600, 0u64);

#[cfg(all(test, feature = "nightly"))]
#[bench]
fn b_p1600_24(b: &mut test::Bencher) {
    let mut data = [0u64; 25];
    b.iter(|| p1600(&mut data, 24));
}

#[cfg(all(test, feature = "nightly"))]
#[bench]
fn b_p1600_16(b: &mut test::Bencher) {
    let mut data = [0u64; 25];
    b.iter(|| p1600(&mut data, 16));
}

#[cfg(all(test, feature = "nightly", feature = "simd"))]
mod simd {
    use lib_q_keccak::simd_parallel::{
        p1600_parallel_2x,
        p1600_parallel_4x,
        p1600_parallel_8x,
    };

    #[bench]
    fn b_p1600_parallel_2x(b: &mut test::Bencher) {
        let mut data = [[0u64; 25]; 2];
        b.iter(|| p1600_parallel_2x(&mut data));
    }

    #[bench]
    fn b_p1600_parallel_4x(b: &mut test::Bencher) {
        let mut data = [[0u64; 25]; 4];
        b.iter(|| p1600_parallel_4x(&mut data));
    }

    #[bench]
    fn b_p1600_parallel_8x(b: &mut test::Bencher) {
        let mut data = [[0u64; 25]; 8];
        b.iter(|| p1600_parallel_8x(&mut data));
    }
}
