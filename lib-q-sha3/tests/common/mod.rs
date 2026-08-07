//! Shared helpers for integration tests (avoids `unwrap` / `expect` under strict Clippy).
//!
//! Each integration test binary compiles only the helpers it imports; allow dead code here so
//! strict `-D warnings` does not fail on unused items in other test targets.

#![allow(dead_code)]

use std::time::Duration;

use blobby::parse_into_vec;
use digest::common::hazmat::{
    SerializableState,
    SerializedState,
};

pub fn kat_blobs(data: &'static [u8]) -> Vec<&'static [u8]> {
    match parse_into_vec(data) {
        Ok(blobs) => blobs,
        Err(err) => panic!("failed to parse KAT blob: {err:?}"),
    }
}

/// Decode a blobby KAT container into `(input, expected)` pairs, refusing the two shapes in which
/// a KAT file proves nothing while still passing:
///
/// * **zero vectors** — the caller's `for` loop simply does not execute, so an empty or
///   accidentally-emptied `.blb` is indistinguishable from a full one;
/// * **an odd trailing blob** — an input with no expected output. The previous
///   `if chunk.len() == 2 { .. }` guard silently discarded it.
///
/// `expected_vectors` is the exact count the committed file is known to hold (see
/// `tests/data/upstream/PROVENANCE.md`), so a file that is regenerated, truncated or swapped
/// cannot quietly shrink the suite: the count has to be updated deliberately, in the diff.
pub fn kat_vectors(
    name: &str,
    data: &'static [u8],
    expected_vectors: usize,
) -> Vec<(&'static [u8], &'static [u8])> {
    assert!(
        expected_vectors > 0,
        "{name}: a KAT test must expect at least one vector"
    );
    let blobs = kat_blobs(data);
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

/// Like [`kat_vectors`], but for XOF files, where the expected blob's length doubles as the
/// number of bytes to squeeze.
///
/// That coupling adds a third way to pass vacuously that [`kat_vectors`] cannot see: a vector
/// whose expected output is zero bytes squeezes zero bytes and then compares two empty slices.
/// The count assertion does not catch it — the vector is present and counted, it just tests
/// nothing. Reject it per vector.
pub fn xof_kat_vectors(
    name: &str,
    data: &'static [u8],
    expected_vectors: usize,
) -> Vec<(&'static [u8], &'static [u8])> {
    let vectors = kat_vectors(name, data, expected_vectors);
    for (i, (_, expected)) in vectors.iter().enumerate() {
        assert!(
            !expected.is_empty(),
            "{name}: XOF vector #{i} has a zero-length expected output. The squeeze length is \
             taken from it, so this vector would compare two empty slices and pass without \
             running the XOF at all."
        );
    }
    vectors
}

/// Build a `blobby` container in memory and leak it, so it satisfies the `&'static [u8]` that
/// `include_bytes!` would normally supply.
///
/// Test-only, and the leak is deliberate: it exists so [`kat_vectors`]'s guards can be driven with
/// the degenerate containers a committed `.blb` must never be allowed to become, without editing
/// any committed file.
pub fn leak_blob_container(blobs: &[&[u8]]) -> &'static [u8] {
    let (encoded, _) = blobby::encode_blobs(blobs);
    Box::leak(encoded.into_boxed_slice())
}

pub fn deserialize_state<T>(state: &SerializedState<T>) -> T
where
    T: SerializableState,
{
    match T::deserialize(state) {
        Ok(value) => value,
        Err(err) => panic!("state deserialize failed: {err:?}"),
    }
}

pub fn duration_min_max_nanos(timings: &[Duration]) -> Option<(u128, u128)> {
    if timings.is_empty() {
        return None;
    }
    let mut min_ns = u128::MAX;
    let mut max_ns = 0;
    for duration in timings {
        let ns = duration.as_nanos();
        min_ns = min_ns.min(ns);
        max_ns = max_ns.max(ns);
    }
    Some((min_ns, max_ns))
}
