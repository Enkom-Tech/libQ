//! Pinned commitment values — the detector this crate did not have.
//!
//! Every other test here commits and verifies **in the same process**, so it stays green across
//! any change to the hash, the domain label, or the absorb order. That is exactly how `df33c57`
//! changed every commitment byte (SHA-256 -> SHA3-256) without moving the `-v1` label and without
//! a single test going red. See board card `t_a8f6abd8`.
//!
//! # These values are not this crate's own output
//!
//! Each expected digest below was computed with **Python's `hashlib.sha3_256`**, from the
//! construction as documented, not by running `blind_commit` and recording what came back. That
//! distinction is the entire value of the file: a KAT regenerated from the implementation pins
//! whatever the implementation currently does, including its bugs, and cannot detect a change —
//! the trap already recorded for HQC in `lib-q-hqc/kats/README.md`.
//!
//! Reproduce independently (no libQ code involved):
//!
//! ```python
//! import hashlib, struct
//! def commit(msg, blind):
//!     h = hashlib.sha3_256()
//!     h.update(b"lib-q-blind-pcs-v2")
//!     h.update(struct.pack('<Q', len(msg)));   h.update(msg)
//!     h.update(struct.pack('<Q', len(blind))); h.update(blind)
//!     return h.hexdigest()
//! ```
//!
//! A failure here means the commitment format moved. If that was deliberate, the domain label in
//! `src/blind_pcs.rs` must move with it and these vectors must be recomputed with the script
//! above — never by pasting in whatever the new implementation emits.

#![cfg(feature = "blind-pcs")]

use lib_q_blind_pcs::{
    blind_commit,
    blind_open,
    verify,
};

/// `(message, blind, expected_commitment_hex)`.
const VECTORS: [(&[u8], &[u8], &str); 3] = [
    // Empty message and empty blind: pins the length-prefix encoding at the boundary where a
    // missing or big-endian length would still produce a well-formed-looking digest.
    (
        b"",
        b"",
        "c30043ae166ccc1801cbec0bc554653e8e5287f79f2c5d52c8ca61608251f368",
    ),
    // Short message, 32 zero bytes of blind.
    (
        b"abc",
        &[0u8; 32],
        "7126d78592376f399854f22f15ba8e16251435036e277ea4a9c419f519ee71df",
    ),
    // 64-byte message 0x00..0x3F with a 64-byte descending blind 0xFF..0xC0 — distinct lengths and
    // contents on both sides, so swapping the two absorb slots changes the digest.
    (
        &[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ],
        &[
            255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239,
            238, 237, 236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224, 223, 222,
            221, 220, 219, 218, 217, 216, 215, 214, 213, 212, 211, 210, 209, 208, 207, 206, 205,
            204, 203, 202, 201, 200, 199, 198, 197, 196, 195, 194, 193, 192,
        ],
        "a77a6b84a4301292d34c0c389a3b70dbab77103f41f892589e681ab36bf211ec",
    ),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn commitments_match_independently_derived_vectors() {
    for (message, blind, expected) in VECTORS {
        let got = blind_commit(message, blind);
        assert_eq!(
            hex(&got),
            expected,
            "commitment format changed for message of {} bytes / blind of {} bytes. \
             If deliberate, move the domain label in src/blind_pcs.rs and recompute these \
             vectors with the Python snippet in this file's header.",
            message.len(),
            blind.len()
        );
    }
}

/// The pinned commitments must also be the ones `verify` accepts — otherwise the vectors could
/// pin a value the rest of the API disagrees with.
#[test]
fn pinned_commitments_verify_against_their_openings() {
    for (message, blind, expected) in VECTORS {
        let commitment = blind_commit(message, blind);
        assert_eq!(hex(&commitment), expected);
        assert!(
            verify(&commitment, &blind_open(message, blind)),
            "pinned commitment did not verify against its own opening"
        );
    }
}

/// The length prefixes exist so that `(message, blind)` cannot be re-split. Without them,
/// `("ab", "c")` and `("a", "bc")` would collide. This asserts the separation actually holds
/// rather than trusting that the prefixes are present.
#[test]
fn length_prefixes_prevent_reassociation() {
    let a = blind_commit(b"ab", b"c");
    let b = blind_commit(b"a", b"bc");
    assert_ne!(
        hex(&a),
        hex(&b),
        "message/blind boundary is not bound: a re-split of the same concatenation collides"
    );
}
