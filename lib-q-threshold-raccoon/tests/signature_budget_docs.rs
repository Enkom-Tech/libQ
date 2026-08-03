//! CI guard for M0 item 4 (design §6.5 / §7 M0.3): `MAX_SIGNATURES_PER_KEY` bounds a Rényi flooding
//! budget spent by every round-3 broadcast, not only by *completed* signatures — an aborted or
//! retried run still emits a real flooded `z_r` sample (`sign_round2`'s output) that consumes the
//! budget whether or not the aggregate that follows verifies. The three places that document this
//! constant must say "round-3 broadcast", not "signatures produced", or the certified `2^20` bound
//! is not the bound the documented policy actually enforces.
//!
//! `src/signer.rs` is part of this crate and always present. `SECURITY_ANALYSIS.md` / `LIBQ_API.md`
//! live in the monorepo's `dev/conformance/integration/lib-q-threshold-raccoon/` — outside this
//! crate's package directory, and (per `cargo package --list`) **not** shipped with the crate. Read
//! them at runtime, not via `include_str!`, and skip that half of the check gracefully if the
//! monorepo checkout isn't present — an `include_str!` on a path that can be absent outside the
//! monorepo would turn a doc-consistency test into a hard compile failure for anyone building just
//! this crate in isolation.

use std::fs;
use std::path::Path;

fn read_repo_file(relative_to_crate: &str) -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_to_crate);
    fs::read_to_string(path).ok()
}

#[test]
fn signature_budget_contract_counts_round3_broadcasts() {
    let signer_src = read_repo_file("src/signer.rs").expect("src/signer.rs is part of this crate");
    assert!(
        signer_src.contains("round-3 broadcast"),
        "src/signer.rs must document MAX_SIGNATURES_PER_KEY as bounding round-3 broadcasts (an \
         aborted run still leaks flooded samples), not only completed signatures"
    );

    let Some(security_analysis) = read_repo_file(
        "../dev/conformance/integration/lib-q-threshold-raccoon/SECURITY_ANALYSIS.md",
    ) else {
        eprintln!(
            "skipping SECURITY_ANALYSIS.md / LIBQ_API.md cross-check: not running inside the \
             monorepo checkout (these files are not packaged with the crate)"
        );
        return;
    };
    assert!(
        security_analysis.contains("round-3 broadcast"),
        "SECURITY_ANALYSIS.md §4 must document the same round-3-broadcast accounting"
    );

    let libq_api =
        read_repo_file("../dev/conformance/integration/lib-q-threshold-raccoon/LIBQ_API.md")
            .expect("LIBQ_API.md sits alongside SECURITY_ANALYSIS.md, which was just found");
    assert!(
        libq_api.contains("round-3 broadcast"),
        "LIBQ_API.md §7.1 must document the same round-3-broadcast accounting"
    );
}
