#![cfg_attr(all(test, feature = "nightly"), feature(test))]
#![cfg_attr(feature = "simd", feature(portable_simd))]

extern crate lib_q_keccak;
#[cfg(all(test, feature = "nightly"))]
extern crate test;

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
impl_bench!(b_f200, f200, 0u8);
#[cfg(all(test, feature = "nightly"))]
impl_bench!(b_f400, f400, 0u16);
#[cfg(all(test, feature = "nightly"))]
impl_bench!(b_f800, f800, 0u32);
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
    use lib_q_keccak::simd::{f1600x2, f1600x4, f1600x8, u64x2, u64x4, u64x8};

    impl_bench!(b_f1600x2, f1600x2, u64x2::splat(0));
    impl_bench!(b_f1600x4, f1600x4, u64x4::splat(0));
    impl_bench!(b_f1600x8, f1600x8, u64x8::splat(0));
}
