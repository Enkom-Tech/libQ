//! Layer results, the nine-class verdict taxonomy and the default-deny aggregation.
//!
//! Provenance of the labels: `robust`, `varlat-secret-risk`, `accepted-variable-time` and
//! `needs-analysis` are the four classes named in the CT-KAT abstract (ePrint 2026/1418). The
//! paper's full nine-class list could not be fetched when this was written, so the other five
//! (`secret-branch-risk`, `secret-index-risk`, `timing-leak-suspected`, `build-sensitive`,
//! `invalid-target`) are this tool's own labels and may not match the paper's names.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Pass,
    /// The layer ran and found something.
    Fail,
    /// The layer could not produce a result (tool missing, timeout, crash, ...). Never a pass.
    Error,
    /// Switched off in the configuration.
    Disabled,
    /// Not attempted because a prerequisite (build/KAT) did not succeed.
    NotRun,
}

#[derive(Debug, Clone, Serialize)]
pub struct LayerResult {
    pub layer: String,
    pub status: Status,
    /// For `Error`: tool-missing | timeout | target-crash | tool-error | unsupported | no-data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// For `Fail`: finding classes (secret-branch, secret-index, uninit-other, varlat, timing,
    /// build-sensitive).
    pub classes: Vec<String>,
    pub detail: String,
    /// Triage justification that accepted this failing layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<String>,
}

impl LayerResult {
    fn new(layer: &str, status: Status, detail: String) -> Self {
        Self {
            layer: layer.into(),
            status,
            error_kind: None,
            classes: vec![],
            detail,
            accepted: None,
        }
    }
    pub fn pass(layer: &str, detail: impl Into<String>) -> Self {
        Self::new(layer, Status::Pass, detail.into())
    }
    pub fn fail(layer: &str, classes: Vec<String>, detail: impl Into<String>) -> Self {
        let mut r = Self::new(layer, Status::Fail, detail.into());
        r.classes = classes;
        r
    }
    pub fn error(layer: &str, kind: &str, detail: impl Into<String>) -> Self {
        let mut r = Self::new(layer, Status::Error, detail.into());
        r.error_kind = Some(kind.into());
        r
    }
    pub fn disabled(layer: &str) -> Self {
        Self::new(layer, Status::Disabled, "disabled in configuration".into())
    }
    pub fn not_run(layer: &str, why: &str) -> Self {
        Self::new(layer, Status::NotRun, why.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Robust,
    AcceptedVariableTime,
    NeedsAnalysis,
    SecretBranchRisk,
    SecretIndexRisk,
    VarlatSecretRisk,
    TimingLeakSuspected,
    BuildSensitive,
    InvalidTarget,
}

impl Verdict {
    pub const ALL: [Verdict; 9] = [
        Self::Robust,
        Self::AcceptedVariableTime,
        Self::NeedsAnalysis,
        Self::SecretBranchRisk,
        Self::SecretIndexRisk,
        Self::VarlatSecretRisk,
        Self::TimingLeakSuspected,
        Self::BuildSensitive,
        Self::InvalidTarget,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Robust => "robust",
            Self::AcceptedVariableTime => "accepted-variable-time",
            Self::NeedsAnalysis => "needs-analysis",
            Self::SecretBranchRisk => "secret-branch-risk",
            Self::SecretIndexRisk => "secret-index-risk",
            Self::VarlatSecretRisk => "varlat-secret-risk",
            Self::TimingLeakSuspected => "timing-leak-suspected",
            Self::BuildSensitive => "build-sensitive",
            Self::InvalidTarget => "invalid-target",
        }
    }
    /// Only these two clear a CI gate. Everything else, including `needs-analysis`, blocks it.
    pub fn passes_gate(self) -> bool {
        matches!(self, Self::Robust | Self::AcceptedVariableTime)
    }
}

/// Finding class -> verdict, ordered by severity (first match wins in `worst`).
fn class_verdict(c: &str) -> Verdict {
    match c {
        "secret-branch" => Verdict::SecretBranchRisk,
        "secret-index" => Verdict::SecretIndexRisk,
        "varlat" => Verdict::VarlatSecretRisk,
        "timing" => Verdict::TimingLeakSuspected,
        "build-sensitive" => Verdict::BuildSensitive,
        _ => Verdict::NeedsAnalysis, // uninit-other and anything unknown: default deny
    }
}

const SEVERITY: [Verdict; 6] = [
    Verdict::SecretBranchRisk,
    Verdict::SecretIndexRisk,
    Verdict::VarlatSecretRisk,
    Verdict::TimingLeakSuspected,
    Verdict::BuildSensitive,
    Verdict::NeedsAnalysis,
];

pub const REQUIRED: [&str; 3] = ["memcheck", "ct_matrix", "asm_scan"];

/// Applies triage to failing layers (in place) and returns the aggregate verdict.
///
/// Default-deny: `robust` is reachable only if every required layer passed (or failed with a
/// written triage justification). An `Error` in any layer, or a disabled/not-run required layer,
/// yields `needs-analysis`; it can never be accepted by triage.
pub fn aggregate(layers: &mut [LayerResult], triage: &BTreeMap<String, String>) -> Verdict {
    for l in layers.iter_mut() {
        if l.status == Status::Fail {
            l.accepted = triage.get(&l.layer).cloned();
        }
    }
    let status = |name: &str| layers.iter().find(|l| l.layer == name).map(|l| l.status);
    if status("build_kat") == Some(Status::Fail) {
        return Verdict::InvalidTarget;
    }
    if layers.iter().any(|l| l.status == Status::Error) {
        return Verdict::NeedsAnalysis;
    }
    let unaccepted: Vec<Verdict> = layers
        .iter()
        .filter(|l| l.status == Status::Fail && l.accepted.is_none())
        .flat_map(|l| {
            if l.classes.is_empty() {
                vec![Verdict::NeedsAnalysis]
            } else {
                l.classes.iter().map(|c| class_verdict(c)).collect()
            }
        })
        .collect();
    if let Some(w) = SEVERITY.iter().find(|v| unaccepted.contains(v)) {
        return *w;
    }
    let settled = |l: &LayerResult| {
        l.status == Status::Pass || (l.status == Status::Fail && l.accepted.is_some())
    };
    let required_ok = REQUIRED
        .iter()
        .all(|n| layers.iter().find(|l| l.layer == *n).is_some_and(settled));
    let dudect_ok = layers
        .iter()
        .find(|l| l.layer == "dudect")
        .is_none_or(|l| settled(l) || l.status == Status::Disabled);
    let build_ok = layers
        .iter()
        .find(|l| l.layer == "build_kat")
        .is_some_and(settled);
    if !(required_ok && dudect_ok && build_ok) {
        return Verdict::NeedsAnalysis;
    }
    if layers.iter().any(|l| l.status == Status::Fail) {
        Verdict::AcceptedVariableTime
    } else {
        Verdict::Robust
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_pass() -> Vec<LayerResult> {
        let mut v = vec![LayerResult::pass("build_kat", "")];
        for n in REQUIRED {
            v.push(LayerResult::pass(n, ""));
        }
        v.push(LayerResult::disabled("dudect"));
        v
    }
    fn set(v: &mut [LayerResult], name: &str, r: LayerResult) {
        *v.iter_mut().find(|l| l.layer == name).unwrap() = r;
    }
    fn none() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn robust_only_when_everything_passed() {
        assert_eq!(aggregate(&mut all_pass(), &none()), Verdict::Robust);
    }

    #[test]
    fn errored_layer_never_reads_as_robust() {
        for layer in REQUIRED {
            let mut v = all_pass();
            set(
                &mut v,
                layer,
                LayerResult::error(layer, "tool-missing", "no valgrind"),
            );
            assert_eq!(
                aggregate(&mut v, &none()),
                Verdict::NeedsAnalysis,
                "{layer}"
            );
        }
    }

    #[test]
    fn triage_cannot_accept_an_error() {
        let mut v = all_pass();
        set(
            &mut v,
            "memcheck",
            LayerResult::error("memcheck", "timeout", ""),
        );
        let t = BTreeMap::from([("memcheck".to_string(), "fine".to_string())]);
        assert_eq!(aggregate(&mut v, &t), Verdict::NeedsAnalysis);
    }

    #[test]
    fn disabled_or_not_run_required_layer_blocks_robust() {
        for l in [
            LayerResult::disabled("asm_scan"),
            LayerResult::not_run("asm_scan", "x"),
        ] {
            let mut v = all_pass();
            set(&mut v, "asm_scan", l);
            assert_eq!(aggregate(&mut v, &none()), Verdict::NeedsAnalysis);
        }
    }

    #[test]
    fn findings_map_to_classes_by_severity() {
        let mut v = all_pass();
        set(
            &mut v,
            "asm_scan",
            LayerResult::fail("asm_scan", vec!["varlat".into()], ""),
        );
        assert_eq!(aggregate(&mut v, &none()), Verdict::VarlatSecretRisk);
        set(
            &mut v,
            "memcheck",
            LayerResult::fail("memcheck", vec!["secret-branch".into()], ""),
        );
        assert_eq!(aggregate(&mut v, &none()), Verdict::SecretBranchRisk);
        let mut v = all_pass();
        set(
            &mut v,
            "ct_matrix",
            LayerResult::fail("ct_matrix", vec!["build-sensitive".into()], ""),
        );
        assert_eq!(aggregate(&mut v, &none()), Verdict::BuildSensitive);
        let mut v = all_pass();
        set(
            &mut v,
            "dudect",
            LayerResult::fail("dudect", vec!["timing".into()], ""),
        );
        assert_eq!(aggregate(&mut v, &none()), Verdict::TimingLeakSuspected);
    }

    #[test]
    fn triaged_failure_is_accepted_variable_time() {
        let mut v = all_pass();
        set(
            &mut v,
            "memcheck",
            LayerResult::fail("memcheck", vec!["secret-branch".into()], ""),
        );
        let t = BTreeMap::from([("memcheck".to_string(), "rejection sampling".to_string())]);
        assert_eq!(aggregate(&mut v, &t), Verdict::AcceptedVariableTime);
    }

    #[test]
    fn build_failure_is_invalid_target() {
        let mut v = all_pass();
        set(
            &mut v,
            "build_kat",
            LayerResult::fail("build_kat", vec![], "compile error"),
        );
        assert_eq!(aggregate(&mut v, &none()), Verdict::InvalidTarget);
    }

    #[test]
    fn only_robust_and_accepted_pass_the_gate() {
        let passing: Vec<_> = Verdict::ALL.iter().filter(|v| v.passes_gate()).collect();
        assert_eq!(passing, [&Verdict::Robust, &Verdict::AcceptedVariableTime]);
        assert_eq!(Verdict::ALL.len(), 9);
    }
}
