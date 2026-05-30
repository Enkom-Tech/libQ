//! Structured evaluation reports for side-channel self-certification.
//!
//! A self-certification run produces an auditable artifact: a set of
//! [`EvaluationReport`] entries (one per screened path) wrapped in a
//! [`SelfCertReport`] that records the capture [`EnvironmentInfo`]. Both serialize
//! to JSON (machine-readable evidence) and Markdown (human review).
//!
//! This module records measurements and verdicts; it does not assert
//! certification-grade resistance. See [`docs/sca-self-certification.md`] for the
//! methodology, gates, and the boundary between self-certification and accredited
//! laboratory evaluation.
//!
//! [`docs/sca-self-certification.md`]: ../../docs/sca-self-certification.md

use std::time::{
    SystemTime,
    UNIX_EPOCH,
};

/// Outcome of a single leakage screen against the configured threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Test statistic is finite and below the absolute threshold.
    Pass,
    /// Test statistic is finite and at or above the absolute threshold.
    Fail,
    /// Statistic could not be computed (too few samples, zero variance, non-finite).
    Inconclusive,
}

impl Verdict {
    /// Lowercase identifier used in JSON and Markdown output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Inconclusive => "inconclusive",
        }
    }

    /// Derive a verdict from an optional test statistic and an absolute threshold.
    #[must_use]
    pub fn from_statistic(statistic: Option<f64>, abs_threshold: f64) -> Self {
        match statistic {
            Some(t) if t.is_finite() => {
                if t.abs() < abs_threshold {
                    Verdict::Pass
                } else {
                    Verdict::Fail
                }
            }
            _ => Verdict::Inconclusive,
        }
    }
}

/// Measurement channel that produced a screen's samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Software wall-clock timing (`std::time::Instant`); subject to scheduler noise.
    WallClockTiming,
    /// Externally acquired traces (power, EM, or cycle counts) ingested from files.
    IngestedTrace,
}

impl Channel {
    /// Lowercase identifier used in JSON and Markdown output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Channel::WallClockTiming => "wall_clock_timing",
            Channel::IngestedTrace => "ingested_trace",
        }
    }
}

/// Capture-time environment metadata recorded alongside every report.
///
/// Fields are limited to values obtainable without `unsafe` or external crates so
/// the harness keeps `#![forbid(unsafe_code)]`. High-fidelity CPU/microarchitecture
/// identification belongs in the acquisition rig that feeds the
/// [`Channel::IngestedTrace`] path.
#[derive(Clone, Debug)]
pub struct EnvironmentInfo {
    /// Target operating system (`std::env::consts::OS`).
    pub os: &'static str,
    /// Target architecture (`std::env::consts::ARCH`).
    pub arch: &'static str,
    /// Target pointer width in bits.
    pub pointer_width: u32,
    /// `lib-q-sca-test` crate version.
    pub harness_version: &'static str,
    /// Seconds since the Unix epoch at capture time (`0` if the clock is before epoch).
    pub timestamp_unix: u64,
}

impl EnvironmentInfo {
    /// Capture the current build/runtime environment.
    #[must_use]
    pub fn capture() -> Self {
        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            pointer_width: (usize::BITS),
            harness_version: env!("CARGO_PKG_VERSION"),
            timestamp_unix,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"os\":{},\"arch\":{},\"pointer_width\":{},\"harness_version\":{},\"timestamp_unix\":{}}}",
            json_string(self.os),
            json_string(self.arch),
            self.pointer_width,
            json_string(self.harness_version),
            self.timestamp_unix,
        )
    }
}

/// A single leakage screen result.
#[derive(Clone, Debug)]
pub struct EvaluationReport {
    /// Identifier of the path under test (e.g. `"lib-q-ml-kem:decapsulate"`).
    pub target: String,
    /// Measurement channel.
    pub channel: Channel,
    /// Samples per class (fixed and random each contribute this many).
    pub samples_per_class: usize,
    /// Welch *t*-statistic, if computable.
    pub t_statistic: Option<f64>,
    /// Absolute threshold applied to `|t|` (TVLA default `4.5`).
    pub abs_t_threshold: f64,
    /// Verdict derived from `t_statistic` and `abs_t_threshold`.
    pub verdict: Verdict,
    /// Free-form notes (methodology caveats, class construction, etc.).
    pub notes: String,
}

impl EvaluationReport {
    /// Build a report, deriving the [`Verdict`] from the statistic and threshold.
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        channel: Channel,
        samples_per_class: usize,
        t_statistic: Option<f64>,
        abs_t_threshold: f64,
        notes: impl Into<String>,
    ) -> Self {
        let verdict = Verdict::from_statistic(t_statistic, abs_t_threshold);
        Self {
            target: target.into(),
            channel,
            samples_per_class,
            t_statistic,
            abs_t_threshold,
            verdict,
            notes: notes.into(),
        }
    }

    /// Serialize this entry to a single-line JSON object.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            "{{\"target\":{},\"channel\":{},\"samples_per_class\":{},\"t_statistic\":{},\"abs_t_threshold\":{},\"verdict\":{},\"notes\":{}}}",
            json_string(&self.target),
            json_string(self.channel.as_str()),
            self.samples_per_class,
            json_number(self.t_statistic),
            json_f64(self.abs_t_threshold),
            json_string(self.verdict.as_str()),
            json_string(&self.notes),
        )
    }

    /// Render this entry as a Markdown table row (matching [`SelfCertReport::to_markdown`]).
    #[must_use]
    pub fn to_markdown_row(&self) -> String {
        let t = match self.t_statistic {
            Some(v) if v.is_finite() => format!("{v:.4}"),
            _ => "n/a".to_string(),
        };
        format!(
            "| `{}` | {} | {} | {} | {:.2} | {} |",
            self.target,
            self.channel.as_str(),
            self.samples_per_class,
            t,
            self.abs_t_threshold,
            self.verdict.as_str(),
        )
    }
}

/// A battery of [`EvaluationReport`] entries with shared capture environment.
#[derive(Clone, Debug)]
pub struct SelfCertReport {
    /// Capture environment shared by every entry.
    pub environment: EnvironmentInfo,
    /// Individual screen results.
    pub reports: Vec<EvaluationReport>,
}

impl SelfCertReport {
    /// Create an empty battery capturing the current environment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            environment: EnvironmentInfo::capture(),
            reports: Vec::new(),
        }
    }

    /// Append a screen result.
    pub fn push(&mut self, report: EvaluationReport) {
        self.reports.push(report);
    }

    /// `true` only if every entry returned [`Verdict::Pass`].
    ///
    /// An [`Verdict::Inconclusive`] entry is **not** a pass: a self-certification run
    /// that could not compute a statistic has not demonstrated the property.
    #[must_use]
    pub fn all_pass(&self) -> bool {
        !self.reports.is_empty() && self.reports.iter().all(|r| r.verdict == Verdict::Pass)
    }

    /// Number of entries with the given verdict.
    #[must_use]
    pub fn count(&self, verdict: Verdict) -> usize {
        self.reports.iter().filter(|r| r.verdict == verdict).count()
    }

    /// Serialize the battery to a single-line JSON object.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut entries = String::new();
        for (idx, report) in self.reports.iter().enumerate() {
            if idx > 0 {
                entries.push(',');
            }
            entries.push_str(&report.to_json());
        }
        format!(
            "{{\"schema\":\"libq.sca.self-cert.v1\",\"environment\":{},\"reports\":[{}]}}",
            self.environment.to_json(),
            entries,
        )
    }

    /// Serialize the battery to a human-readable Markdown summary.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# libQ side-channel self-certification report\n\n");
        out.push_str(&format!(
            "- Schema: `libq.sca.self-cert.v1`\n- OS/arch: `{}`/`{}` ({}-bit)\n- Harness: `lib-q-sca-test {}`\n- Timestamp (Unix): `{}`\n\n",
            self.environment.os,
            self.environment.arch,
            self.environment.pointer_width,
            self.environment.harness_version,
            self.environment.timestamp_unix,
        ));
        out.push_str(&format!(
            "Summary: {} pass, {} fail, {} inconclusive ({} total).\n\n",
            self.count(Verdict::Pass),
            self.count(Verdict::Fail),
            self.count(Verdict::Inconclusive),
            self.reports.len(),
        ));
        out.push_str("| Target | Channel | Samples/class | \\|t\\| stat | Threshold | Verdict |\n");
        out.push_str("|--------|---------|--------------:|----------:|----------:|---------|\n");
        for report in &self.reports {
            out.push_str(&report.to_markdown_row());
            out.push('\n');
        }
        out.push_str(
            "\nWall-clock timing screens are pre-laboratory regression evidence, not an \
             independent side-channel evaluation. See `docs/sca-self-certification.md`.\n",
        );
        out
    }
}

impl Default for SelfCertReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape and quote a string for JSON output.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render an `f64` as a JSON number, or `null` when non-finite.
fn json_f64(value: f64) -> String {
    if value.is_finite() {
        format!("{value}")
    } else {
        "null".to_string()
    }
}

/// Render an optional `f64` as a JSON number, or `null` when absent/non-finite.
fn json_number(value: Option<f64>) -> String {
    match value {
        Some(v) => json_f64(v),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_thresholding() {
        assert_eq!(Verdict::from_statistic(Some(1.0), 4.5), Verdict::Pass);
        assert_eq!(Verdict::from_statistic(Some(-1.0), 4.5), Verdict::Pass);
        assert_eq!(Verdict::from_statistic(Some(4.5), 4.5), Verdict::Fail);
        assert_eq!(Verdict::from_statistic(Some(9.0), 4.5), Verdict::Fail);
        assert_eq!(Verdict::from_statistic(None, 4.5), Verdict::Inconclusive);
        assert_eq!(
            Verdict::from_statistic(Some(f64::NAN), 4.5),
            Verdict::Inconclusive
        );
    }

    #[test]
    fn report_json_is_well_formed_single_line() {
        let r = EvaluationReport::new(
            "lib-q-ml-kem:decapsulate",
            Channel::WallClockTiming,
            1024,
            Some(2.5),
            4.5,
            "fixed vs random dk/ct",
        );
        let json = r.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(!json.contains('\n'));
        assert!(json.contains("\"verdict\":\"pass\""));
        assert!(json.contains("\"channel\":\"wall_clock_timing\""));
    }

    #[test]
    fn non_finite_statistic_serializes_as_null() {
        let r = EvaluationReport::new("x", Channel::IngestedTrace, 0, Some(f64::INFINITY), 4.5, "");
        assert!(r.to_json().contains("\"t_statistic\":null"));
        assert_eq!(r.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn json_string_escapes_control_and_quotes() {
        let s = json_string("a\"b\\c\nd\te");
        assert_eq!(s, "\"a\\\"b\\\\c\\nd\\te\"");
    }

    #[test]
    fn battery_all_pass_requires_nonempty_and_all_pass() {
        let mut battery = SelfCertReport::new();
        assert!(!battery.all_pass(), "empty battery is not a pass");
        battery.push(EvaluationReport::new(
            "a",
            Channel::WallClockTiming,
            8,
            Some(1.0),
            4.5,
            "",
        ));
        assert!(battery.all_pass());
        battery.push(EvaluationReport::new(
            "b",
            Channel::WallClockTiming,
            8,
            None,
            4.5,
            "",
        ));
        assert!(!battery.all_pass(), "inconclusive entry blocks all_pass");
        assert_eq!(battery.count(Verdict::Inconclusive), 1);
    }

    #[test]
    fn battery_markdown_and_json_render() {
        let mut battery = SelfCertReport::new();
        battery.push(EvaluationReport::new(
            "lib-q-ml-dsa:sign",
            Channel::WallClockTiming,
            512,
            Some(3.1),
            4.5,
            "fixed vs random signing key",
        ));
        let md = battery.to_markdown();
        assert!(md.contains("self-certification report"));
        assert!(md.contains("lib-q-ml-dsa:sign"));
        let json = battery.to_json();
        assert!(json.contains("\"schema\":\"libq.sca.self-cert.v1\""));
        assert!(json.contains("\"reports\":["));
    }
}
