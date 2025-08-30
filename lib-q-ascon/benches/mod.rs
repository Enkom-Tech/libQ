#![cfg_attr(all(test, feature = "nightly"), feature(test))]

extern crate lib_q_ascon;
#[cfg(all(test, feature = "nightly"))]
extern crate test;

#[cfg(all(test, feature = "nightly"))]
#[bench]
fn bench_permute_1(b: &mut test::Bencher) {
    let mut state = lib_q_ascon::State::new(0x1234567890ABCDEF, 0xFEDCBA0987654321, 0, 0, 0);
    b.iter(|| {
        state.permute_1();
    });
}

#[cfg(all(test, feature = "nightly"))]
#[bench]
fn bench_permute_6(b: &mut test::Bencher) {
    let mut state = lib_q_ascon::State::new(0x1234567890ABCDEF, 0xFEDCBA0987654321, 0, 0, 0);
    b.iter(|| {
        state.permute_6();
    });
}

#[cfg(all(test, feature = "nightly"))]
#[bench]
fn bench_permute_8(b: &mut test::Bencher) {
    let mut state = lib_q_ascon::State::new(0x1234567890ABCDEF, 0xFEDCBA0987654321, 0, 0, 0);
    b.iter(|| {
        state.permute_8();
    });
}

#[cfg(all(test, feature = "nightly"))]
#[bench]
fn bench_permute_12(b: &mut test::Bencher) {
    let mut state = lib_q_ascon::State::new(0x1234567890ABCDEF, 0xFEDCBA0987654321, 0, 0, 0);
    b.iter(|| {
        state.permute_12();
    });
}

#[cfg(all(test, feature = "nightly"))]
#[bench]
fn bench_state_creation(b: &mut test::Bencher) {
    b.iter(|| {
        lib_q_ascon::State::new(
            0x1234567890ABCDEF,
            0xFEDCBA0987654321,
            0xDEADBEEFCAFEBABE,
            0xBEBAFECAEFBEADDE,
            0x0123456789ABCDEF,
        );
    });
}

#[cfg(all(test, feature = "nightly"))]
#[bench]
fn bench_as_bytes(b: &mut test::Bencher) {
    let state = lib_q_ascon::State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );
    b.iter(|| {
        state.as_bytes();
    });
}
