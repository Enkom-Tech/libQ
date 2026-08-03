//! CI guard for M0 item 4 (design §6.5 / §7 M0.3): `MAX_SIGNATURES_PER_KEY` bounds a Rényi flooding
//! budget spent by every round-3 broadcast, not only by *completed* signatures — an aborted or
//! retried run still emits a real flooded `z_r` sample (`sign_round2`'s output) that consumes the
//! budget whether or not the aggregate that follows verifies. The three places that document this
//! constant must say "round-3 broadcast", not "signatures produced", or the certified `2^20` bound
//! is not the bound the documented policy actually enforces.

const SIGNER_SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/signer.rs"));
const SECURITY_ANALYSIS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../dev/conformance/integration/lib-q-threshold-raccoon/SECURITY_ANALYSIS.md"
));
const LIBQ_API: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../dev/conformance/integration/lib-q-threshold-raccoon/LIBQ_API.md"
));

#[test]
fn signature_budget_contract_counts_round3_broadcasts() {
    assert!(
        SIGNER_SRC.contains("round-3 broadcast"),
        "src/signer.rs must document MAX_SIGNATURES_PER_KEY as bounding round-3 broadcasts (an \
         aborted run still leaks flooded samples), not only completed signatures"
    );
    assert!(
        SECURITY_ANALYSIS.contains("round-3 broadcast"),
        "SECURITY_ANALYSIS.md §4 must document the same round-3-broadcast accounting"
    );
    assert!(
        LIBQ_API.contains("round-3 broadcast"),
        "LIBQ_API.md §7.1 must document the same round-3-broadcast accounting"
    );
}
