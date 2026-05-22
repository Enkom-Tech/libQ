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
