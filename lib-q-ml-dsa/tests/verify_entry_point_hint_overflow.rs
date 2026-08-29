//! ENK-240 regression test: `verify` must REJECT a hint block whose row counter overflows the
//! hint buffer, not panic.
//!
//! FIPS 204 Algorithm 21 (HintBitUnpack) rejects when `y[omega + i] < Index` OR
//! `y[omega + i] > omega` -- both bounds are on the CURRENT row's counter. The defect (fixed at
//! `2bd658c`) bounded the PREVIOUS row's counter instead, one iteration stale, so the largest
//! counter was never checked; it then drove `for j in previous..current`, indexing
//! `hint_serialized[j]` (a byte, so up to 254) into a buffer only `omega + k` bytes long.
//! Reproduced in release against the public `verify` entry point with a 3309-byte crafted
//! ML-DSA-65 signature and an all-zero verification key:
//!
//!   thread 'main' panicked at lib-q-ml-dsa/src/encoding/signature.rs:105:48:
//!   index out of bounds: the len is 61 but the index is 61
//!
//! `src/encoding/signature.rs` already carries a `malformed_hint_coverage_for!` macro that
//! proves this at the crate-internal `deserialize` function, for all three parameter sets, and
//! is mutation-verified there. This file is a DIFFERENT, narrower claim: that the defect is
//! unreachable through the actual PUBLIC `verify` entry point that attacker-supplied signatures
//! arrive through, not merely through the internal decoder called directly. It deliberately
//! does not import anything from this crate except the public `ml_dsa_44`/`ml_dsa_65`/
//! `ml_dsa_87` modules, so it cannot accidentally exercise a shortcut the real entry point
//! skips.
//!
//! `omega` (MAX_ONES_IN_HINT) and `k` (ROWS_IN_A, the number of rows in the public matrix A) are
//! hardcoded here from FIPS 204 Table 1 (Security Categories 2/3/5) -- not read from this
//! crate's internals, which are `pub(crate)` and unreachable from an external integration test
//! -- and cross-checked below against the sizes the crate DOES export publicly
//! (`MLDSAxxSignature::len()`), which only agree with the standard if both this test's
//! constants and the crate's implementation are FIPS-204-conformant.

use lib_q_ml_dsa::ml_dsa_44::{
    self,
    MLDSA44Signature,
    MLDSA44VerificationKey,
};
use lib_q_ml_dsa::ml_dsa_65::{
    self,
    MLDSA65Signature,
    MLDSA65VerificationKey,
};
use lib_q_ml_dsa::ml_dsa_87::{
    self,
    MLDSA87Signature,
    MLDSA87VerificationKey,
};

/// Overwrite `buf`'s trailing `omega + rows` bytes (the hint block, per the wire layout
/// `commitment_hash || signer_response || hint`) with a crafted hint that overflows on the
/// LAST row:
///
/// - The `omega` index bytes are strictly increasing (`0, 1, 2, ...`), so the per-element
///   monotonicity check (`signature.rs:113`) cannot reject first and mask the defect this test
///   targets -- see that file's own regression tests for why a flat/zero fill there is vacuous.
/// - Rows `0..rows-1` carry a valid, strictly-increasing counter sequence ending exactly at
///   `omega` on the second-to-last row, so the decoder reaches the attacked row in a
///   legitimately-accepted state.
/// - The LAST row's counter is set to `omega + rows + 1`, one past the whole hint buffer, the
///   exact shape that walked off the end before the fix.
fn apply_hint_overflow(buf: &mut [u8], omega: usize, rows: usize) {
    let h0 = buf.len() - (omega + rows);
    for (j, slot) in buf.iter_mut().skip(h0).take(omega).enumerate() {
        *slot = j as u8;
    }
    for (i, slot) in buf.iter_mut().skip(h0 + omega).take(rows - 1).enumerate() {
        *slot = (omega - (rows - 2 - i)) as u8;
    }
    buf[h0 + omega + rows - 1] = (omega + rows + 1) as u8;
}

#[test]
fn verify_rejects_hint_overflow_instead_of_panicking_44() {
    // FIPS 204 Table 1, ML-DSA-44 (Security Category 2): k = 4, omega = 80.
    const OMEGA: usize = 80;
    const ROWS: usize = 4;
    assert_eq!(
        MLDSA44Signature::len(),
        2420,
        "ML-DSA-44 signature size is FIPS-204-fixed"
    );

    let vk = MLDSA44VerificationKey::new([0u8; MLDSA44VerificationKey::len()]);
    let mut sig_bytes = [0u8; MLDSA44Signature::len()];
    apply_hint_overflow(&mut sig_bytes, OMEGA, ROWS);
    let sig = MLDSA44Signature::new(sig_bytes);

    assert!(
        ml_dsa_44::verify(&vk, b"ENK-240 crafted hint overflow", b"", &sig).is_err(),
        "verify() must reject an overflowing hint row counter through the public entry point, \
         not panic"
    );
}

#[test]
fn verify_rejects_hint_overflow_instead_of_panicking_65() {
    // FIPS 204 Table 1, ML-DSA-65 (Security Category 3): k = 6, omega = 55. This is the exact
    // parameter set and 3309-byte signature size from the original crafted proof-of-concept.
    const OMEGA: usize = 55;
    const ROWS: usize = 6;
    assert_eq!(
        MLDSA65Signature::len(),
        3309,
        "ML-DSA-65 signature size is FIPS-204-fixed"
    );

    let vk = MLDSA65VerificationKey::new([0u8; MLDSA65VerificationKey::len()]);
    let mut sig_bytes = [0u8; MLDSA65Signature::len()];
    apply_hint_overflow(&mut sig_bytes, OMEGA, ROWS);
    let sig = MLDSA65Signature::new(sig_bytes);

    assert!(
        ml_dsa_65::verify(&vk, b"ENK-240 crafted hint overflow", b"", &sig).is_err(),
        "verify() must reject an overflowing hint row counter through the public entry point, \
         not panic"
    );
}

#[test]
fn verify_rejects_hint_overflow_instead_of_panicking_87() {
    // FIPS 204 Table 1, ML-DSA-87 (Security Category 5): k = 8, omega = 75.
    const OMEGA: usize = 75;
    const ROWS: usize = 8;
    assert_eq!(
        MLDSA87Signature::len(),
        4627,
        "ML-DSA-87 signature size is FIPS-204-fixed"
    );

    let vk = MLDSA87VerificationKey::new([0u8; MLDSA87VerificationKey::len()]);
    let mut sig_bytes = [0u8; MLDSA87Signature::len()];
    apply_hint_overflow(&mut sig_bytes, OMEGA, ROWS);
    let sig = MLDSA87Signature::new(sig_bytes);

    assert!(
        ml_dsa_87::verify(&vk, b"ENK-240 crafted hint overflow", b"", &sig).is_err(),
        "verify() must reject an overflowing hint row counter through the public entry point, \
         not panic"
    );
}
