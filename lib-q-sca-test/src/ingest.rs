//! Ingestion of externally acquired traces into the TVLA pipeline.
//!
//! Wall-clock timing (see [`crate::evaluation`]) is what the harness can produce
//! unattended, but it cannot characterise power or electromagnetic leakage. Those
//! channels require an acquisition rig (oscilloscope / EM probe, trigger, alignment,
//! preprocessing) outside this crate. This module is the documented hand-off point:
//! acquired per-class scalar measurements (e.g. a leakage point of interest, a
//! point-wise *t* maximum, or cycle counts) are read from files and fed through the
//! same [`crate::welch_t_statistic`] gate, producing an [`EvaluationReport`] with
//! [`Channel::IngestedTrace`].
//!
//! ## File format
//!
//! One numeric measurement per token, separated by ASCII whitespace or newlines.
//! Blank lines and `#`-prefixed comment lines are ignored. Each class (fixed and
//! random) is a separate file.

use std::fs;
use std::path::Path;

use crate::report::{
    Channel,
    EvaluationReport,
};

/// Errors raised while ingesting external trace files.
#[derive(Debug)]
pub enum IngestError {
    /// The file could not be read.
    Io(String),
    /// A token could not be parsed as a finite `f64`.
    Parse(String),
    /// The file contained no usable measurements.
    Empty(String),
}

impl core::fmt::Display for IngestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IngestError::Io(msg) => write!(f, "trace ingest I/O error: {msg}"),
            IngestError::Parse(msg) => write!(f, "trace ingest parse error: {msg}"),
            IngestError::Empty(msg) => write!(f, "trace ingest empty input: {msg}"),
        }
    }
}

impl std::error::Error for IngestError {}

/// Parse whitespace/newline-separated scalar measurements from `text`.
///
/// Lines whose first non-whitespace character is `#` are treated as comments.
pub fn parse_scalars(text: &str) -> Result<Vec<f64>, IngestError> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for token in line.split_whitespace() {
            let value: f64 = token
                .parse()
                .map_err(|_| IngestError::Parse(format!("invalid measurement token: {token:?}")))?;
            if !value.is_finite() {
                return Err(IngestError::Parse(format!(
                    "non-finite measurement token: {token:?}"
                )));
            }
            out.push(value);
        }
    }
    if out.is_empty() {
        return Err(IngestError::Empty(
            "no numeric measurements parsed".to_string(),
        ));
    }
    Ok(out)
}

/// Read and parse a scalar measurement file.
pub fn parse_scalar_file(path: &Path) -> Result<Vec<f64>, IngestError> {
    let text = fs::read_to_string(path)
        .map_err(|e| IngestError::Io(format!("{}: {e}", path.display())))?;
    parse_scalars(&text)
}

/// Run a fixed-vs-random screen over two already-parsed measurement classes.
///
/// `samples_per_class` in the resulting report is the smaller of the two class
/// sizes, matching the count actually compared by the *t*-test.
#[must_use]
pub fn screen_classes(
    target: impl Into<String>,
    fixed: &[f64],
    random: &[f64],
    abs_t_threshold: f64,
) -> EvaluationReport {
    let t = crate::welch_t_statistic(fixed, random);
    let samples_per_class = fixed.len().min(random.len());
    EvaluationReport::new(
        target,
        Channel::IngestedTrace,
        samples_per_class,
        t,
        abs_t_threshold,
        "externally acquired traces ingested via lib-q-sca-test::ingest",
    )
}

/// Read two per-class trace files and produce a fixed-vs-random screen report.
pub fn screen_trace_files(
    target: impl Into<String>,
    fixed_path: &Path,
    random_path: &Path,
    abs_t_threshold: f64,
) -> Result<EvaluationReport, IngestError> {
    let fixed = parse_scalar_file(fixed_path)?;
    let random = parse_scalar_file(random_path)?;
    Ok(screen_classes(target, &fixed, &random, abs_t_threshold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Verdict;

    #[test]
    fn parse_skips_comments_and_blank_lines() {
        let text = "# header\n1.0 2.0\n\n  3.5  \n# trailing\n";
        let v = parse_scalars(text).expect("parse");
        assert_eq!(v, vec![1.0, 2.0, 3.5]);
    }

    #[test]
    fn parse_rejects_non_numeric_and_non_finite() {
        assert!(matches!(
            parse_scalars("1.0 abc"),
            Err(IngestError::Parse(_))
        ));
        assert!(matches!(parse_scalars("inf"), Err(IngestError::Parse(_))));
        assert!(matches!(
            parse_scalars("# only comments\n"),
            Err(IngestError::Empty(_))
        ));
    }

    #[test]
    fn separated_means_fail_the_screen() {
        let fixed: Vec<f64> = (0..256).map(|_| 10.0).collect();
        let random: Vec<f64> = (0..256)
            .map(|i| 10.0 + (i % 2) as f64 * 0.0001 + 5.0)
            .collect();
        let report = screen_classes("test:separated", &fixed, &random, 4.5);
        assert_eq!(report.verdict, Verdict::Fail);
        assert_eq!(report.samples_per_class, 256);
    }

    #[test]
    fn overlapping_distributions_pass_the_screen() {
        let fixed: Vec<f64> = (0..256).map(|i| (i % 7) as f64).collect();
        let random: Vec<f64> = (0..256).map(|i| (i % 7) as f64).collect();
        let report = screen_classes("test:overlap", &fixed, &random, 4.5);
        // Identical distributions yield zero variance in the difference; either Pass
        // (t ~ 0) or Inconclusive (se == 0) is acceptable, but never Fail.
        assert_ne!(report.verdict, Verdict::Fail);
    }
}
