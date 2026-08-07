//! Keccak fixed-digest KATs (moved from `lib-q-sha3` with Option B split).
//!
//! Two vector sets run for every algorithm and both are load-bearing:
//!
//! * `data/*.blb` — the curated pair `("", H(""))` / `("abc", H("abc"))`. The `"abc"` case is in
//!   no upstream file, and for Keccak-256-Full the empty-input case is not upstream either, so
//!   this set is not redundant.
//! * `data/upstream/*.blb` — RustCrypto's vector sets, vendored byte-for-byte. Provenance,
//!   SHA-256 digests and the independent cross-check are recorded in
//!   `tests/data/upstream/PROVENANCE.md`.
//!
//! Every test states the exact number of vectors its file holds. That count is the guard against
//! the failure mode this suite used to have: with no count assertion and a `if chunk.len() == 2`
//! skip, an empty or truncated `.blb` made the test pass while checking nothing.

use blobby::parse_into_vec;
use digest::Digest;

/// Decode a blobby KAT container into `(input, expected)` pairs, refusing the two shapes in which
/// a KAT file proves nothing while still passing: zero vectors (the caller's loop never runs) and
/// an odd trailing blob (an input with no expected output, previously skipped silently).
///
/// `expected_vectors` is the exact count the committed file is known to hold, so a regenerated,
/// truncated or swapped file cannot quietly shrink the suite.
fn kat_vectors(
    name: &str,
    data: &'static [u8],
    expected_vectors: usize,
) -> Vec<(&'static [u8], &'static [u8])> {
    assert!(
        expected_vectors > 0,
        "{name}: a KAT test must expect at least one vector"
    );
    let blobs = match parse_into_vec(data) {
        Ok(blobs) => blobs,
        Err(err) => panic!("{name}: failed to parse KAT blob: {err:?}"),
    };
    let (pairs, rest) = blobs.as_chunks::<2>();
    assert!(
        rest.is_empty(),
        "{name}: KAT container decoded to {} blobs, an odd count — the trailing input has no \
         expected output. Repair the .blb; do not skip the dangling blob.",
        blobs.len()
    );
    let vectors: Vec<(&'static [u8], &'static [u8])> = pairs
        .iter()
        .map(|&[input, expected]| (input, expected))
        .collect();
    assert!(
        !vectors.is_empty(),
        "{name}: KAT container decoded to zero vectors; this test would otherwise pass vacuously"
    );
    assert_eq!(
        vectors.len(),
        expected_vectors,
        "{name}: expected {expected_vectors} KAT vectors, decoded {}",
        vectors.len()
    );
    vectors
}

/// Build a `blobby` container in memory and leak it, so it satisfies the `&'static [u8]` that
/// `include_bytes!` would normally supply. Test-only; the leak is deliberate and lets
/// [`kat_vectors`]'s guards be driven with degenerate containers without editing a committed file.
fn leak_blob_container(blobs: &[&[u8]]) -> &'static [u8] {
    let (encoded, _) = blobby::encode_blobs(blobs);
    Box::leak(encoded.into_boxed_slice())
}

macro_rules! keccak_kat {
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

// --- curated: ("", H("")) and ("abc", H("abc")) --------------------------------------------
keccak_kat!(
    keccak_224_kat,
    lib_q_keccak_digest::Keccak224,
    "data/keccak_224_kat.blb",
    2,
);
keccak_kat!(
    keccak_256_kat,
    lib_q_keccak_digest::Keccak256,
    "data/keccak_256_kat.blb",
    2,
);
keccak_kat!(
    keccak_384_kat,
    lib_q_keccak_digest::Keccak384,
    "data/keccak_384_kat.blb",
    2,
);
keccak_kat!(
    keccak_512_kat,
    lib_q_keccak_digest::Keccak512,
    "data/keccak_512_kat.blb",
    2,
);
keccak_kat!(
    keccak_256_full_kat,
    lib_q_keccak_digest::Keccak256Full,
    "data/keccak_256_full_kat.blb",
    2,
);

// --- upstream (see tests/data/upstream/PROVENANCE.md) --------------------------------------
// Upstream's Keccak-224/384/512 files hold a single vector each (the empty string), which the
// curated files already cover; they are vendored anyway so the whole upstream set is present and
// hash-checkable in one place. Keccak-256 (3 vectors) and Keccak-256-Full (14) add real inputs.
keccak_kat!(
    keccak_224_kat_upstream,
    lib_q_keccak_digest::Keccak224,
    "data/upstream/keccak_224_kat.blb",
    1,
);
keccak_kat!(
    keccak_256_kat_upstream,
    lib_q_keccak_digest::Keccak256,
    "data/upstream/keccak_256_kat.blb",
    3,
);
keccak_kat!(
    keccak_384_kat_upstream,
    lib_q_keccak_digest::Keccak384,
    "data/upstream/keccak_384_kat.blb",
    1,
);
keccak_kat!(
    keccak_512_kat_upstream,
    lib_q_keccak_digest::Keccak512,
    "data/upstream/keccak_512_kat.blb",
    1,
);
keccak_kat!(
    keccak_256_full_kat_upstream,
    lib_q_keccak_digest::Keccak256Full,
    "data/upstream/keccak_256_full_kat.blb",
    14,
);

// --- the guards above are proven to fire, not merely to exist ------------------------------
// An assertion nobody has watched fail is not evidence. These drive the real `kat_vectors` used
// by every test above with the three degenerate containers a committed `.blb` must never become.

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
#[should_panic(expected = "expected 2 KAT vectors, decoded 1")]
fn kat_vectors_rejects_truncated_container() {
    // The real committed Keccak-256 file with its second vector cut off. The committed file itself
    // is not touched: it is decoded, sliced in memory and re-encoded.
    let full = match parse_into_vec(include_bytes!("data/keccak_256_kat.blb")) {
        Ok(blobs) => blobs,
        Err(err) => panic!("failed to parse KAT blob: {err:?}"),
    };
    let truncated = leak_blob_container(&full[..2]);
    let _ = kat_vectors("data/keccak_256_kat.blb <truncated>", truncated, 2);
}
