//! CI guard for M0 item 5 (design §2.5 / §7 M0.5): the four absences (no identifiable abort, no
//! accountability, no robustness, no proactive refresh) must be named in the docs a crates.io/docs.rs
//! reader actually receives — `README.md` and the crate-level `//!` doc (`src/lib.rs`) — not only in
//! `LIBQ_API.md` / `SECURITY_ANALYSIS.md`, which `cargo package --list` shows are **not** packaged.

const README: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));
const LIB_RS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
const THRESHOLD_RS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/threshold.rs"));

const ABSENCES: [&str; 4] = [
    "identifiable abort",
    "accountability",
    "robustness",
    "proactive refresh",
];

#[test]
fn readme_names_all_four_absences() {
    for phrase in ABSENCES {
        assert!(
            README.contains(phrase),
            "README.md (packaged) must name the absence: {phrase}"
        );
    }
}

#[test]
fn crate_level_doc_names_all_four_absences() {
    for phrase in ABSENCES {
        assert!(
            LIB_RS.contains(phrase),
            "src/lib.rs's crate-level //! doc (packaged, reaches docs.rs) must name the absence: \
             {phrase}"
        );
    }
}

/// Commit 285366a added this exact assertion while its own stated intent was "attribute, don't
/// assert" a claim about a paper nobody in this chain has read (design §1.2/§2.5).
#[test]
fn threshold_module_does_not_assert_paper_fidelity() {
    assert!(
        !THRESHOLD_RS.contains("Faithful to Threshold-Raccoon"),
        "threshold.rs must not assert conformance to an external paper nobody in this chain has \
         read -- attribute the construction to its citation, don't assert the paper lacks these \
         properties too"
    );
}
