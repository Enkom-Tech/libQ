use digest::dev::feed_rand_16mib;
use digest::hash_serialization_test;
use hex_literal::hex;
use lib_q_sha2::{
    Digest,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
};

// Simple test for SHA-256
#[test]
fn test_sha256_basic() {
    let data = b"hello world";
    let expected = hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    let result = Sha256::digest(data);
    assert_eq!(result.as_slice(), expected.as_slice());
}

// Simple test for SHA-224
#[test]
fn test_sha224_basic() {
    let data = b"hello world";
    let expected = hex!("2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b");
    let result = Sha224::digest(data);
    assert_eq!(result.as_slice(), expected.as_slice());
}

// Simple test for SHA-384
#[test]
fn test_sha384_basic() {
    let data = b"hello world";
    let expected = hex!(
        "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
    );
    let result = Sha384::digest(data);
    assert_eq!(result.as_slice(), expected.as_slice());
}

// Simple test for SHA-512
#[test]
fn test_sha512_basic() {
    let data = b"hello world";
    let expected = hex!(
        "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
    );
    let result = Sha512::digest(data);
    assert_eq!(result.as_slice(), expected.as_slice());
}

// Simple test for SHA-512/224
#[test]
fn test_sha512_224_basic() {
    let data = b"hello world";
    let expected = hex!("22e0d52336f64a998085078b05a6e37b26f8120f43bf4db4c43a64ee");
    let result = Sha512_224::digest(data);
    assert_eq!(result.as_slice(), expected.as_slice());
}

// Simple test for SHA-512/256
#[test]
fn test_sha512_256_basic() {
    let data = b"hello world";
    let expected = hex!("0ac561fac838104e3f2e4ad107b4bee3e938bf15f2b15f009ccccd61a913f017");
    let result = Sha512_256::digest(data);
    assert_eq!(result.as_slice(), expected.as_slice());
}

hash_serialization_test!(sha224_serialization, Sha224);
hash_serialization_test!(sha256_serialization, Sha256);
hash_serialization_test!(sha384_serialization, Sha384);
hash_serialization_test!(sha512_serialization, Sha512);
hash_serialization_test!(sha512_224_serialization, Sha512_224);
hash_serialization_test!(sha512_256_serialization, Sha512_256);

#[test]
fn sha256_rand() {
    let mut h = Sha256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("45f51fead87328fe837a86f4f1ac0eb15116ab1473adc0423ef86c62eb2320c7"),
    );
}

#[test]
fn sha512_rand() {
    let mut h = Sha512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "9084d75a7c0721541d737b6171eb465dc9ba08a119a182a8508484aa27a176cd"
            "e7c2103b108393eb024493ced4aac56be6f57222cac41b801f11494886264997"
        ),
    );
}
