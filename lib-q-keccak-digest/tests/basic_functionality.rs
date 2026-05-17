use digest::Digest;

#[test]
fn keccak_224_basic_functionality() {
    let mut hasher = lib_q_keccak_digest::Keccak224::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_keccak_digest::Keccak224::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 28);
}

#[test]
fn keccak_256_basic_functionality() {
    let mut hasher = lib_q_keccak_digest::Keccak256::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_keccak_digest::Keccak256::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 32);
}

#[test]
fn keccak_384_basic_functionality() {
    let mut hasher = lib_q_keccak_digest::Keccak384::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_keccak_digest::Keccak384::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 48);
}

#[test]
fn keccak_512_basic_functionality() {
    let mut hasher = lib_q_keccak_digest::Keccak512::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_keccak_digest::Keccak512::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert_eq!(result.len(), 64);
}

#[test]
fn keccak_256_full_basic_functionality() {
    let mut hasher = lib_q_keccak_digest::Keccak256Full::new();
    hasher.update(b"test data");
    let result = hasher.finalize();

    let mut hasher2 = lib_q_keccak_digest::Keccak256Full::new();
    hasher2.update(b"test data");
    let result2 = hasher2.finalize();

    assert_eq!(result, result2);
    assert!(!result.is_empty());
}
