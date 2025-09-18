#![feature(test)]
extern crate test;

use digest::bench_update;
use lib_q_sha2::{
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
};
use test::Bencher;

bench_update!(
    Sha224::default();
    sha224_10 10;
    sha224_100 100;
    sha224_1000 1000;
    sha224_10000 10000;
);

bench_update!(
    Sha256::default();
    sha256_10 10;
    sha256_100 100;
    sha256_1000 1000;
    sha256_10000 10000;
);

bench_update!(
    Sha384::default();
    sha384_10 10;
    sha384_100 100;
    sha384_1000 1000;
    sha384_10000 10000;
);

bench_update!(
    Sha512::default();
    sha512_10 10;
    sha512_100 100;
    sha512_1000 1000;
    sha512_10000 10000;
);

bench_update!(
    Sha512_224::default();
    sha512_224_10 10;
    sha512_224_100 100;
    sha512_224_1000 1000;
    sha512_224_10000 10000;
);

bench_update!(
    Sha512_256::default();
    sha512_256_10 10;
    sha512_256_100 100;
    sha512_256_1000 1000;
    sha512_256_10000 10000;
);
