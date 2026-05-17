//! Public `DomainSeparationContext` API (used by pre-hash / external callers).

use lib_q_ml_dsa::DomainSeparationContext;

/// SHAKE-128 with 256-byte output (same OID as internal `pre_hash::SHAKE128_OID`).
const SHAKE128_256_OID: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
];

#[test]
fn new_rejects_context_over_255_bytes() {
    let too_long = vec![0xABu8; 256];
    assert!(DomainSeparationContext::new(&too_long, None).is_err());
}

#[test]
fn new_accepts_max_length_context_and_oid_accessor() {
    let ctx = vec![0xCDu8; 255];
    let dsc = match DomainSeparationContext::new(&ctx, Some(SHAKE128_256_OID)) {
        Ok(d) => d,
        Err(_) => panic!("255-byte context must be accepted"),
    };
    assert_eq!(dsc.context().len(), 255);
    assert_eq!(dsc.pre_hash_oid(), &Some(SHAKE128_256_OID));
}

#[test]
fn new_without_prehash_oid() {
    let dsc = match DomainSeparationContext::new(b"ctx", None) {
        Ok(d) => d,
        Err(_) => panic!("short context must be accepted"),
    };
    assert_eq!(dsc.context(), b"ctx");
    assert_eq!(dsc.pre_hash_oid(), &None);
}
