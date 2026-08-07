//! Declared-count validation in the wire decoders.
//!
//! Companion to `tests/wire_alloc_bounds.rs`, which owns the allocation bound (and therefore owns
//! the global allocator, which is why these live in a separate binary). Here the subject is the
//! *rejection*: a count that exceeds the protocol maximum must be refused by the named bound, with
//! the error variant that says so, and a count inconsistent with the bytes present must be refused
//! as truncation.

use lib_q_dkg::lattice::bdlop::{
    Commitment,
    MU,
};
use lib_q_dkg::lattice::ring::{
    RQ_BYTES,
    Rq,
};
use lib_q_dkg::{
    CoeffCommitments,
    DkgError,
    MAX_ROUND1_COMMITMENTS,
    MAX_WIRE_RQ_VEC_LEN,
    decode_complaint,
    decode_round1_commitments,
    decode_share_evaluation,
    encode_round1_commitments,
};

/// Header of every V1 payload: version, profile.
const HDR: [u8; 2] = [1, 1];

fn round1_declaring(n: u16) -> Vec<u8> {
    let mut w = Vec::from(HDR);
    w.extend_from_slice(&[1, 1]); // party, threshold
    w.extend_from_slice(&n.to_le_bytes());
    w
}

fn share_declaring_rand(n: u32) -> Vec<u8> {
    let mut w = Vec::from(HDR);
    w.extend_from_slice(&[1, 2, 2]); // dealer, recipient, threshold
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES)); // value: the zero ring element
    w.extend_from_slice(&n.to_le_bytes());
    w
}

/// Well-formed through `value`, `rand` and the challenge `c`; then declares `z_len` response
/// elements and supplies `z_supplied` of them.
fn share_declaring_z(z_len: u32, z_supplied: usize) -> Vec<u8> {
    let mut w = Vec::from(HDR);
    w.extend_from_slice(&[1, 2, 2]); // dealer, recipient, threshold
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES)); // value
    w.extend_from_slice(&9u32.to_le_bytes()); // rand_len = KAPPA
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES * 9)); // rand
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES)); // challenge c
    w.extend_from_slice(&z_len.to_le_bytes());
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES * z_supplied));
    w
}

fn complaint_declaring_rand(n: u32) -> Vec<u8> {
    let mut w = Vec::from(HDR);
    w.extend_from_slice(&[1, 2]); // outer dealer, recipient
    w.extend_from_slice(&[1, 2, 2]); // inner dealer, recipient, threshold
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES));
    w.extend_from_slice(&n.to_le_bytes());
    w
}

/// A declared commitment count above `MAX_ROUND1_COMMITMENTS` is rejected by the protocol-maximum
/// bound -- not incidentally, later, as a truncation.
#[test]
fn round1_count_above_protocol_max_is_rejected_by_the_bound() {
    for n in [17u16, 255, 4096, u16::MAX] {
        let err = decode_round1_commitments(&round1_declaring(n)).expect_err("must reject");
        assert!(
            matches!(err, DkgError::InvalidThreshold),
            "n={n} must be rejected by the protocol-maximum bound, got {err:?}"
        );
    }
}

/// A count within the protocol maximum but unsupported by the bytes present is truncation.
#[test]
fn round1_count_inconsistent_with_input_is_rejected() {
    for n in [1u16, 2, 16] {
        let err = decode_round1_commitments(&round1_declaring(n)).expect_err("must reject");
        assert!(
            matches!(err, DkgError::WireTruncated),
            "n={n} with an empty body must be truncation, got {err:?}"
        );
    }
}

/// Trailing bytes beyond the declared commitments are still rejected.
#[test]
fn round1_trailing_bytes_are_rejected() {
    let honest = honest_broadcast(3);
    let mut w = encode_round1_commitments(&honest).expect("encode");
    w.push(0);
    let err = decode_round1_commitments(&w).expect_err("must reject");
    assert!(matches!(err, DkgError::WireTruncated), "got {err:?}");
}

/// The randomness vector is exactly `KAPPA` elements; larger declared counts are refused.
#[test]
fn share_rand_count_above_protocol_max_is_rejected() {
    for n in [10u32, 170, 1_000, u32::MAX] {
        let err = decode_share_evaluation(&share_declaring_rand(n)).expect_err("must reject");
        assert!(
            matches!(err, DkgError::Encoding),
            "rand_len={n} must be rejected by the field bound, got {err:?}"
        );
    }
}

/// Same field, reached through the complaint decoder. `Complaint` is not `Debug` (it holds secret
/// openings), so match rather than `expect_err`.
#[test]
fn complaint_rand_count_above_protocol_max_is_rejected() {
    for n in [10u32, 170, 1_000, u32::MAX] {
        match decode_complaint(&complaint_declaring_rand(n)) {
            Err(DkgError::Encoding) => {}
            Err(other) => panic!("rand_len={n}: wrong error {other:?}"),
            Ok(_) => panic!("rand_len={n} must be rejected"),
        }
    }
}

/// A count of zero must not slip past the field check: `rand` is exactly `KAPPA` elements, so an
/// empty declaration is as invalid as an oversized one.
#[test]
fn share_rand_count_of_zero_is_rejected() {
    let err = decode_share_evaluation(&share_declaring_rand(0)).expect_err("must reject");
    assert!(matches!(err, DkgError::Encoding), "got {err:?}");
}

/// A count exactly AT the protocol maximum clears the named-constant check, so the reconciliation
/// against bytes actually present is the only thing left to catch it. Both wire vectors, both
/// arities: one element short and none at all.
#[test]
fn counts_at_the_protocol_maximum_still_need_the_bytes() {
    // `rand`: exactly KAPPA declared, nothing supplied.
    let err = decode_share_evaluation(&share_declaring_rand(9)).expect_err("must reject");
    assert!(
        matches!(err, DkgError::WireTruncated),
        "rand_len=KAPPA with no body must be truncation, got {err:?}"
    );

    // `z`: exactly MAX_WIRE_RQ_VEC_LEN declared, nothing supplied, then all-but-one supplied.
    let max_z = u32::try_from(MAX_WIRE_RQ_VEC_LEN).expect("fits");
    for supplied in [0usize, MAX_WIRE_RQ_VEC_LEN - 1] {
        let err =
            decode_share_evaluation(&share_declaring_z(max_z, supplied)).expect_err("must reject");
        assert!(
            matches!(err, DkgError::WireTruncated),
            "z_len=max with {supplied} elements must be truncation, got {err:?}"
        );
    }

    // One past the maximum is refused by the bound itself, not by truncation.
    let err = decode_share_evaluation(&share_declaring_z(max_z + 1, 0)).expect_err("must reject");
    assert!(
        matches!(err, DkgError::Encoding),
        "z_len=max+1 must be rejected by the field bound, got {err:?}"
    );
}

/// A well-formed maximum-size broadcast followed by garbage is rejected, and a body one byte short
/// of the declared count is truncation -- the two ends of the "count clears the ceiling" bypass.
#[test]
fn round1_at_the_protocol_maximum_still_needs_exact_bytes() {
    let w = encode_round1_commitments(&honest_broadcast(MAX_ROUND1_COMMITMENTS)).expect("encode");

    let mut short = w.clone();
    short.pop();
    let err = decode_round1_commitments(&short).expect_err("must reject");
    assert!(
        matches!(err, DkgError::WireTruncated),
        "n=max one byte short must be truncation, got {err:?}"
    );

    let mut long = w.clone();
    long.push(0);
    let err = decode_round1_commitments(&long).expect_err("must reject");
    assert!(
        matches!(err, DkgError::WireTruncated),
        "n=max plus a trailing byte must be rejected, got {err:?}"
    );

    // ...and the exact-length payload in between still decodes.
    assert_eq!(
        decode_round1_commitments(&w)
            .expect("exact max-size broadcast must decode")
            .commitments
            .len(),
        MAX_ROUND1_COMMITMENTS
    );
}

/// POSITIVE CONTROL: every count at or below the protocol maximum still round-trips.
#[test]
fn honest_counts_up_to_the_protocol_max_still_round_trip() {
    for t in [0usize, 1, 3, 16] {
        let honest = honest_broadcast(t);
        let w = encode_round1_commitments(&honest).expect("encode");
        let decoded = decode_round1_commitments(&w).expect("honest broadcast must decode");
        assert_eq!(decoded.commitments.len(), t);
        assert_eq!(decoded, honest);
    }
}

fn honest_broadcast(t: usize) -> CoeffCommitments {
    CoeffCommitments {
        party: 1,
        threshold: u8::try_from(t).expect("t fits u8"),
        commitments: (0..t)
            .map(|_| Commitment {
                t0: (0..MU).map(|_| Rq::zero()).collect(),
                t1: Rq::zero(),
            })
            .collect(),
    }
}
