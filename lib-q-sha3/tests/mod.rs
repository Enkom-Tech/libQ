//! Known-answer tests for SHA-3 and SHAKE.
//!
//! Two vector sets run for every algorithm and both are load-bearing:
//!
//! * `data/*.blb` — the small curated pair `("", H(""))` / `("abc", H("abc"))`. These are the
//!   FIPS 202 worked examples; the empty-input case in particular is *absent* from the upstream
//!   SHA3-384/512 files, so this set is not redundant.
//! * `data/upstream/*.blb` — RustCrypto's full vector sets, vendored byte-for-byte. Provenance,
//!   SHA-256 digests and the independent cross-check are recorded in
//!   `tests/data/upstream/PROVENANCE.md`.
//!
//! Every test states the exact number of vectors its file holds. That count is the guard against
//! the failure mode this suite used to have: with no count assertion and a `if chunk.len() == 2`
//! skip, an empty or truncated `.blb` made the test pass while checking nothing.

mod common;

use common::{
    kat_blobs,
    kat_vectors,
    leak_blob_container,
    xof_kat_vectors,
};
use digest::{
    Digest,
    ExtendableOutput,
    Update,
};

/// A fixed-output-size KAT: `$file` holds exactly `$count` `(input, digest)` pairs.
macro_rules! fixed_kat {
    ($name:ident, $hasher:ty, $file:literal, $count:literal $(,)?) => {
        #[test]
        fn $name() {
            let vectors = kat_vectors($file, include_bytes!($file), $count);
            for (i, (input, expected)) in vectors.iter().enumerate() {
                let mut hasher = <$hasher>::new();
                Digest::update(&mut hasher, input);
                let output = hasher.finalize();
                assert_eq!(output[..], expected[..], "{}: failed vector #{i}", $file);
            }
        }
    };
}

/// An XOF KAT: the expected blob's length is the number of output bytes to squeeze.
///
/// Uses `xof_kat_vectors`, not `kat_vectors`: because the squeeze length comes from the expected
/// blob, a zero-length expected output would squeeze nothing and compare two empty slices, so it
/// has to be rejected per vector as well as counted.
macro_rules! xof_kat {
    ($name:ident, $hasher:ty, $file:literal, $count:literal $(,)?) => {
        #[test]
        fn $name() {
            let vectors = xof_kat_vectors($file, include_bytes!($file), $count);
            for (i, (input, expected)) in vectors.iter().enumerate() {
                let mut hasher = <$hasher>::default();
                Update::update(&mut hasher, input);
                let mut output = vec![0u8; expected.len()];
                hasher.finalize_xof_into(&mut output);
                assert_eq!(output[..], expected[..], "{}: failed vector #{i}", $file);
            }
        }
    };
}

// --- curated FIPS 202 worked examples: ("", H("")) and ("abc", H("abc")) -------------------
fixed_kat!(
    sha3_224_kat,
    lib_q_sha3::Sha3_224,
    "data/sha3_224_kat.blb",
    2
);
fixed_kat!(
    sha3_256_kat,
    lib_q_sha3::Sha3_256,
    "data/sha3_256_kat.blb",
    2
);
fixed_kat!(
    sha3_384_kat,
    lib_q_sha3::Sha3_384,
    "data/sha3_384_kat.blb",
    2
);
fixed_kat!(
    sha3_512_kat,
    lib_q_sha3::Sha3_512,
    "data/sha3_512_kat.blb",
    2
);
xof_kat!(
    shake128_kat,
    lib_q_sha3::Shake128,
    "data/shake128_kat.blb",
    2
);
xof_kat!(
    shake256_kat,
    lib_q_sha3::Shake256,
    "data/shake256_kat.blb",
    2
);

// --- full upstream vector sets (see tests/data/upstream/PROVENANCE.md) ---------------------
// Inputs run from 0 to ~255 bytes, so these cross the 72/104/136/168-byte rate boundaries and
// exercise multi-block absorb; the SHAKE files squeeze 512 bytes each, exercising multi-squeeze.
fixed_kat!(
    sha3_224_kat_upstream,
    lib_q_sha3::Sha3_224,
    "data/upstream/sha3_224_kat.blb",
    256,
);
fixed_kat!(
    sha3_256_kat_upstream,
    lib_q_sha3::Sha3_256,
    "data/upstream/sha3_256_kat.blb",
    256,
);
// 255, not 256: the upstream SHA3-384/512 files have no empty-input vector.
fixed_kat!(
    sha3_384_kat_upstream,
    lib_q_sha3::Sha3_384,
    "data/upstream/sha3_384_kat.blb",
    255,
);
fixed_kat!(
    sha3_512_kat_upstream,
    lib_q_sha3::Sha3_512,
    "data/upstream/sha3_512_kat.blb",
    255,
);
xof_kat!(
    shake128_kat_upstream,
    lib_q_sha3::Shake128,
    "data/upstream/shake128_kat.blb",
    256,
);
xof_kat!(
    shake256_kat_upstream,
    lib_q_sha3::Shake256,
    "data/upstream/shake256_kat.blb",
    256,
);

// --- the guards above are proven to fire, not merely to exist ------------------------------
// An assertion nobody has watched fail is not evidence. These drive the real `kat_vectors` used
// by every test above with the three degenerate containers a committed `.blb` must never become.
// If someone weakens the helper back into "silently skip", these turn red.

#[test]
#[should_panic(expected = "decoded to zero vectors")]
fn kat_vectors_rejects_empty_container() {
    let _ = kat_vectors("<synthetic empty>", leak_blob_container(&[]), 2);
}

#[test]
#[should_panic(expected = "an odd count")]
fn kat_vectors_rejects_odd_trailing_blob() {
    // input / expected / input-with-no-expected: the case `if chunk.len() == 2` used to drop.
    let container =
        leak_blob_container(&[b"".as_slice(), b"\x01\x02".as_slice(), b"abc".as_slice()]);
    let _ = kat_vectors("<synthetic odd>", container, 2);
}

#[test]
#[should_panic(expected = "zero-length expected output")]
fn xof_kat_vectors_rejects_zero_length_expected_output() {
    // Counted, present, and completely vacuous: squeezing `expected.len()` == 0 bytes compares
    // two empty slices. `kat_vectors` alone accepts this (the count is right), which is why the
    // XOF path needs its own per-vector guard.
    let container = leak_blob_container(&[b"abc".as_slice(), b"".as_slice()]);
    let _ = xof_kat_vectors("<synthetic zero-length XOF output>", container, 1);
}

#[test]
#[should_panic(expected = "expected 2 KAT vectors, decoded 1")]
fn kat_vectors_rejects_truncated_container() {
    // The real committed SHA3-256 file with its second vector cut off. The committed file itself
    // is not touched: it is decoded, sliced in memory and re-encoded.
    let full = kat_blobs(include_bytes!("data/sha3_256_kat.blb"));
    let truncated = leak_blob_container(&full[..2]);
    let _ = kat_vectors("data/sha3_256_kat.blb <truncated>", truncated, 2);
}

// Other integration tests live in `tests/*.rs` (one crate per file). Do not `mod` them here:
// Cargo already builds each as its own test binary; declaring them again would run every test twice.
