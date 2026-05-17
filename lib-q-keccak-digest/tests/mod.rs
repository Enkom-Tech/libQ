//! Keccak fixed-digest KATs (moved from `lib-q-sha3` with Option B split).

use blobby::parse_into_vec;
use digest::Digest;

#[test]
fn keccak_224_kat() {
    let data = include_bytes!("data/keccak_224_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_keccak_digest::Keccak224::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn keccak_256_kat() {
    let data = include_bytes!("data/keccak_256_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_keccak_digest::Keccak256::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn keccak_384_kat() {
    let data = include_bytes!("data/keccak_384_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_keccak_digest::Keccak384::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn keccak_512_kat() {
    let data = include_bytes!("data/keccak_512_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_keccak_digest::Keccak512::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}

#[test]
fn keccak_256_full_kat() {
    let data = include_bytes!("data/keccak_256_full_kat.blb");
    let blobs = parse_into_vec(data).unwrap();

    for (i, chunk) in blobs.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let input = chunk[0];
            let expected = chunk[1];

            let mut hasher = lib_q_keccak_digest::Keccak256Full::new();
            Digest::update(&mut hasher, input);
            let output = hasher.finalize();

            assert_eq!(output[..], expected[..], "Failed test vector #{}", i);
        }
    }
}
