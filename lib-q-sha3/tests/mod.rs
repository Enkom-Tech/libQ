use blobby::Blob2Iterator;
use digest::{
    Digest,
    ExtendableOutput,
    Update,
};

// Known Answer Tests (KAT) using official test vectors
#[test]
fn sha3_224_kat() {
    let data = include_bytes!("data/sha3_224_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Sha3_224::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn sha3_256_kat() {
    let data = include_bytes!("data/sha3_256_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Sha3_256::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn sha3_384_kat() {
    let data = include_bytes!("data/sha3_384_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Sha3_384::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn sha3_512_kat() {
    let data = include_bytes!("data/sha3_512_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Sha3_512::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn shake128_kat() {
    let data = include_bytes!("data/shake128_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Shake128::default();
        Update::update(&mut hasher, input);
        let mut output = vec![0u8; expected.len()];
        hasher.finalize_xof_into(&mut output);

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn shake256_kat() {
    let data = include_bytes!("data/shake256_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Shake256::default();
        Update::update(&mut hasher, input);
        let mut output = vec![0u8; expected.len()];
        hasher.finalize_xof_into(&mut output);

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

// Test vectors from https://github.com/kazcw/yellowsun/blob/test-keccak/src/lib.rs#L171
#[test]
fn keccak_224_kat() {
    let data = include_bytes!("data/keccak_224_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Keccak224::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn keccak_256_kat() {
    let data = include_bytes!("data/keccak_256_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Keccak256::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn keccak_384_kat() {
    let data = include_bytes!("data/keccak_384_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Keccak384::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn keccak_512_kat() {
    let data = include_bytes!("data/keccak_512_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Keccak512::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

#[test]
fn keccak_256_full_kat() {
    let data = include_bytes!("data/keccak_256_full_kat.blb");
    for (i, result) in Blob2Iterator::new(data).unwrap().enumerate() {
        let result = result.unwrap();
        let input = result[0];
        let expected = result[1];

        let mut hasher = lib_q_sha3::Keccak256Full::new();
        Digest::update(&mut hasher, input);
        let output = hasher.finalize();

        assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
    }
}

// Additional test modules
mod basic_functionality;
mod constant_time;
mod cshake;
mod performance;
mod security;
mod turboshake;
