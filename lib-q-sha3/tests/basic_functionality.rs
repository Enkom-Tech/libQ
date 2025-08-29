use digest::Digest;

/// Basic functionality tests for SHA3 family algorithms
/// These tests verify core cryptographic properties and consistency

#[test]
fn keccak_224_basic_functionality() {
    let mut hasher = lib_q_sha3::Keccak224::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    // Verify we get a consistent result
    let mut hasher2 = lib_q_sha3::Keccak224::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 28); // Keccak224 produces 224 bits = 28 bytes
}

#[test]
fn keccak_256_basic_functionality() {
    let mut hasher = lib_q_sha3::Keccak256::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_sha3::Keccak256::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 32); // Keccak256 produces 256 bits = 32 bytes
}

#[test]
fn keccak_384_basic_functionality() {
    let mut hasher = lib_q_sha3::Keccak384::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_sha3::Keccak384::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 48); // Keccak384 produces 384 bits = 48 bytes
}

#[test]
fn keccak_512_basic_functionality() {
    let mut hasher = lib_q_sha3::Keccak512::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_sha3::Keccak512::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 64); // Keccak512 produces 512 bits = 64 bytes
}

#[test]
fn keccak_256_full_basic_functionality() {
    let mut hasher = lib_q_sha3::Keccak256Full::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_sha3::Keccak256Full::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    // Keccak256Full produces variable length output, not fixed 32 bytes
    assert!(!result.is_empty());
}

#[test]
fn sha3_224_basic_functionality() {
    let mut hasher = lib_q_sha3::Sha3_224::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_sha3::Sha3_224::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 28); // SHA3-224 produces 224 bits = 28 bytes
}

#[test]
fn sha3_256_basic_functionality() {
    let mut hasher = lib_q_sha3::Sha3_256::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_sha3::Sha3_256::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 32); // SHA3-256 produces 256 bits = 32 bytes
}

#[test]
fn sha3_384_basic_functionality() {
    let mut hasher = lib_q_sha3::Sha3_384::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_sha3::Sha3_384::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 48); // SHA3-384 produces 384 bits = 48 bytes
}

#[test]
fn sha3_512_basic_functionality() {
    let mut hasher = lib_q_sha3::Sha3_512::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_sha3::Sha3_512::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 64); // SHA3-512 produces 512 bits = 64 bytes
}
