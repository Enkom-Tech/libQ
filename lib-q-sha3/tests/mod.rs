use digest::dev::{fixed_reset_test, xof_reset_test};
use digest::new_test;

// Known Answer Tests (KAT) using official test vectors
new_test!(
    sha3_224_kat,
    "sha3_224_kat",
    lib_q_sha3::Sha3_224,
    fixed_reset_test
);
new_test!(
    sha3_256_kat,
    "sha3_256_kat",
    lib_q_sha3::Sha3_256,
    fixed_reset_test
);
new_test!(
    sha3_384_kat,
    "sha3_384_kat",
    lib_q_sha3::Sha3_384,
    fixed_reset_test
);
new_test!(
    sha3_512_kat,
    "sha3_512_kat",
    lib_q_sha3::Sha3_512,
    fixed_reset_test
);

new_test!(
    shake128_kat,
    "shake128_kat",
    lib_q_sha3::Shake128,
    xof_reset_test
);
new_test!(
    shake256_kat,
    "shake256_kat",
    lib_q_sha3::Shake256,
    xof_reset_test
);

// Test vectors from https://github.com/kazcw/yellowsun/blob/test-keccak/src/lib.rs#L171
new_test!(
    keccak_224_kat,
    "keccak_224_kat",
    lib_q_sha3::Keccak224,
    fixed_reset_test
);
new_test!(
    keccak_256_kat,
    "keccak_256_kat",
    lib_q_sha3::Keccak256,
    fixed_reset_test
);
new_test!(
    keccak_384_kat,
    "keccak_384_kat",
    lib_q_sha3::Keccak384,
    fixed_reset_test
);
new_test!(
    keccak_512_kat,
    "keccak_512_kat",
    lib_q_sha3::Keccak512,
    fixed_reset_test
);

new_test!(
    keccak_256_full_kat,
    "keccak_256_full_kat",
    lib_q_sha3::Keccak256Full,
    fixed_reset_test
);

// Additional test modules
mod basic_functionality;
mod cshake;
mod turboshake;
