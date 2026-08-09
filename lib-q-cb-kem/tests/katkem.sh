#!/bin/bash
# Runs the Classic McEliece KAT harness (tests/katkem.rs) for the one parameter
# set currently wired up: mceliece348864 (crate feature `cbkem348864`).
#
# NOTE on history: earlier revisions of this script passed
# `--features mceliece348864...` (and friends) — those feature names never
# existed in this crate's Cargo.toml (the real names are `cbkem348864...`), and
# there was no `test_katkem` entry point for `cargo test --lib` to find, so this
# script could not have passed. It has been rewritten to match the crate as it
# actually exists.
#
# Only mceliece348864/cbkem348864 is covered today. The other 9 parameter sets
# (348864f, 460896, 460896f, 6688128, 6688128f, 6960119, 6960119f, 8192128,
# 8192128f) are NOT exercised by this script; extending it is mechanical
# (repeat the same `--features cbkemNNN,...` swap) but keygen cost for the
# larger parameter sets is significant, so they were deliberately left for a
# follow-up rather than spreading this pass thin.
#
# This script runs the SELF-CONSISTENCY check only (see tests/katkem.rs module
# docs for exactly what that does and does not prove). It does NOT compare
# against a genuine external NIST vector file, because none was obtainable in
# this environment — see tests/katkem.rs's `official_kat_348864` test (run with
# `--ignored`) for the harness that does that once a real .rsp file is supplied
# via CBKEM348864_KAT_RSP.
set -euo pipefail

cargo test --release \
    --package lib-q-cb-kem \
    --features "cbkem348864,nist-aes-rng,alloc,std" \
    --test katkem
