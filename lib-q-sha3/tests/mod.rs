use blobby::parse_into_vec;
use digest::{
    Digest,
    ExtendableOutput,
    Update,
};

// Test vector structure for runtime parsing
#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    pub input: &'static [u8],
    pub output: &'static [u8],
}

// Known Answer Tests (KAT) using official test vectors
#[test]
fn sha3_224_kat() {
    let data = include_bytes!("data/sha3_224_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_sha3::Sha3_224::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn sha3_256_kat() {
    let data = include_bytes!("data/sha3_256_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_sha3::Sha3_256::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn sha3_384_kat() {
    let data = include_bytes!("data/sha3_384_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_sha3::Sha3_384::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn sha3_512_kat() {
    let data = include_bytes!("data/sha3_512_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_sha3::Sha3_512::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn shake128_kat() {
    let data = include_bytes!("data/shake128_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_sha3::Shake128::default();
            Update::update(&mut hasher, input);
            let mut output = vec![0u8; expected.len()];
            hasher.finalize_xof_into(&mut output);

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn shake256_kat() {
    let data = include_bytes!("data/shake256_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_sha3::Shake256::default();
            Update::update(&mut hasher, input);
            let mut output = vec![0u8; expected.len()];
            hasher.finalize_xof_into(&mut output);

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

// Other integration tests live in `tests/*.rs` (one crate per file). Do not `mod` them here:
// Cargo already builds each as its own test binary; declaring them again would run every test twice.
