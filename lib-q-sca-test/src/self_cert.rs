//! Self-certification battery over hardened libQ paths (timing channel).
//!
//! [`run_timing_battery`] drives every hardened path enabled by the active feature
//! set, computes a fixed-vs-random Welch *t*-statistic per path, and records the
//! results in a [`SelfCertReport`]. [`write_evidence_package`] serializes that report
//! to JSON and Markdown for archival.
//!
//! Timing screens are software regression evidence collected to surface issues
//! before an accredited laboratory engagement; they are not a substitute for
//! instrumented power/EM evaluation. External traces enter the same statistical gate
//! through [`crate::ingest`]. The full methodology, gates, and the
//! self-certification-versus-accredited-certification boundary are documented in
//! [`docs/sca-self-certification.md`].
//!
//! [`docs/sca-self-certification.md`]: ../../docs/sca-self-certification.md

use std::path::{
    Path,
    PathBuf,
};
use std::{
    fs,
    io,
};

use crate::report::SelfCertReport;
#[cfg(any(
    feature = "mlkem",
    feature = "mldsa",
    feature = "lattice-zkp-hardened",
    feature = "hqc-hardened"
))]
use crate::report::{
    Channel,
    EvaluationReport,
};

/// Configuration for a self-certification timing battery.
#[derive(Clone, Copy, Debug)]
pub struct BatteryConfig {
    /// Samples collected per class (fixed and random each).
    ///
    /// Self-certification confidence scales with sample count. ISO 17825-style
    /// non-specific TVLA targets on the order of `1_000_000` traces per class for an
    /// instrumented channel; software timing batteries use smaller counts and are
    /// reported as pre-laboratory screening.
    pub samples_per_class: usize,
    /// Absolute `|t|` threshold (TVLA first-order default `4.5`).
    pub abs_t_threshold: f64,
    /// When false, HQC smoke collects HQC-128 targets only (CI budget).
    pub hqc_all_parameter_sets: bool,
}

impl Default for BatteryConfig {
    fn default() -> Self {
        Self {
            samples_per_class: 10_000,
            abs_t_threshold: crate::evaluation::DEFAULT_TVLA_ABS_T,
            hqc_all_parameter_sets: true,
        }
    }
}

impl BatteryConfig {
    /// Reduced-sample configuration for CI smoke runs.
    ///
    /// Kept small because the hardened lattice-ZKP prover runs a fixed `max_attempts`
    /// rejection loop per sample; the smoke run validates plumbing, not a leakage bound.
    #[must_use]
    pub fn smoke() -> Self {
        Self {
            // Small count: CI runs many hardened paths; HQC keygen/encaps/decaps are costly.
            samples_per_class: 4,
            abs_t_threshold: crate::evaluation::DEFAULT_TVLA_ABS_T,
            hqc_all_parameter_sets: false,
        }
    }
}

/// Run the timing self-certification battery for all hardened paths in the active
/// feature set and return the collected [`SelfCertReport`].
///
/// The battery is intentionally additive: each target is gated by the feature that
/// brings its crate into scope, so a build with only `mlkem` reports the ML-KEM path
/// and omits the others. A build with no hardened features produces an empty battery.
#[cfg(any(
    feature = "mlkem",
    feature = "mldsa",
    feature = "lattice-zkp-hardened",
    feature = "hqc-hardened"
))]
#[must_use]
pub fn run_timing_battery(config: BatteryConfig) -> SelfCertReport {
    let mut report = SelfCertReport::new();

    #[cfg(feature = "mlkem")]
    {
        let (fixed, random) =
            crate::evaluation::mlkem_decaps_tvla_timings(config.samples_per_class);
        report.push(EvaluationReport::new(
            "lib-q-ml-kem:decapsulate",
            Channel::WallClockTiming,
            config.samples_per_class,
            crate::welch_t_statistic(&fixed, &random),
            config.abs_t_threshold,
            "fixed dk/ct vs rotated dk/ct; MlKem768 hardened decapsulation",
        ));
    }

    #[cfg(feature = "mldsa")]
    {
        let (fixed, random) = crate::evaluation::mldsa_sign_tvla_timings(config.samples_per_class);
        report.push(EvaluationReport::new(
            "lib-q-ml-dsa:sign",
            Channel::WallClockTiming,
            config.samples_per_class,
            crate::welch_t_statistic(&fixed, &random),
            config.abs_t_threshold,
            "fixed signing key vs rotated signing key; ML-DSA-44 hardened signing",
        ));
    }

    #[cfg(feature = "lattice-zkp-hardened")]
    {
        let (fixed, random) =
            crate::evaluation::lattice_zkp_prove_opening_tvla_timings(config.samples_per_class);
        report.push(EvaluationReport::new(
            "lib-q-lattice-zkp:prove_opening",
            Channel::WallClockTiming,
            config.samples_per_class,
            crate::welch_t_statistic(&fixed, &random),
            config.abs_t_threshold,
            "fixed token opening vs rotated token header; hardened fixed-iteration prover",
        ));
    }

    #[cfg(feature = "hqc-hardened")]
    {
        use lib_q_hqc::{
            Hqc1Params,
            Hqc3Params,
            Hqc5Params,
        };

        macro_rules! push_hqc_target {
            ($id:literal, $params:ty, $timings:ident, $notes:literal) => {{
                let (fixed, random) =
                    crate::evaluation::$timings::<$params>(config.samples_per_class);
                report.push(EvaluationReport::new(
                    $id,
                    Channel::WallClockTiming,
                    config.samples_per_class,
                    crate::welch_t_statistic(&fixed, &random),
                    config.abs_t_threshold,
                    $notes,
                ));
            }};
        }

        push_hqc_target!(
            "lib-q-hqc:hqc128_keygen",
            Hqc1Params,
            hqc_keygen_tvla_timings,
            "fixed 48-byte KEM seed vs rotated seed; HQC-128 keygen (hardened)"
        );
        push_hqc_target!(
            "lib-q-hqc:hqc128_encapsulate",
            Hqc1Params,
            hqc_encapsulate_tvla_timings,
            "fixed pk/SHAKE PRNG vs rotated pk/PRNG; HQC-128 encapsulation (hardened)"
        );
        push_hqc_target!(
            "lib-q-hqc:hqc128_decapsulate",
            Hqc1Params,
            hqc_decapsulate_tvla_timings,
            "fixed sk/ct vs rotated sk/ct; HQC-128 decapsulation (hardened)"
        );

        if config.hqc_all_parameter_sets {
            push_hqc_target!(
                "lib-q-hqc:hqc192_keygen",
                Hqc3Params,
                hqc_keygen_tvla_timings,
                "fixed 48-byte KEM seed vs rotated seed; HQC-192 keygen (hardened)"
            );
            push_hqc_target!(
                "lib-q-hqc:hqc256_keygen",
                Hqc5Params,
                hqc_keygen_tvla_timings,
                "fixed 48-byte KEM seed vs rotated seed; HQC-256 keygen (hardened)"
            );
            push_hqc_target!(
                "lib-q-hqc:hqc192_encapsulate",
                Hqc3Params,
                hqc_encapsulate_tvla_timings,
                "fixed pk/SHAKE PRNG vs rotated pk/PRNG; HQC-192 encapsulation (hardened)"
            );
            push_hqc_target!(
                "lib-q-hqc:hqc256_encapsulate",
                Hqc5Params,
                hqc_encapsulate_tvla_timings,
                "fixed pk/SHAKE PRNG vs rotated pk/PRNG; HQC-256 encapsulation (hardened)"
            );
            push_hqc_target!(
                "lib-q-hqc:hqc192_decapsulate",
                Hqc3Params,
                hqc_decapsulate_tvla_timings,
                "fixed sk/ct vs rotated sk/ct; HQC-192 decapsulation (hardened)"
            );
            push_hqc_target!(
                "lib-q-hqc:hqc256_decapsulate",
                Hqc5Params,
                hqc_decapsulate_tvla_timings,
                "fixed sk/ct vs rotated sk/ct; HQC-256 decapsulation (hardened)"
            );
        }
    }

    report
}

/// Empty battery when no timing targets are enabled in the active feature set.
#[cfg(not(any(
    feature = "mlkem",
    feature = "mldsa",
    feature = "lattice-zkp-hardened",
    feature = "hqc-hardened"
)))]
#[must_use]
pub fn run_timing_battery(_config: BatteryConfig) -> SelfCertReport {
    SelfCertReport::new()
}

/// Write a [`SelfCertReport`] to `dir` as `report.json` and `report.md`.
///
/// Creates `dir` (and parents) if needed. Returns the JSON and Markdown paths.
pub fn write_evidence_package(
    dir: &Path,
    report: &SelfCertReport,
) -> io::Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(dir)?;
    let json_path = dir.join("report.json");
    let md_path = dir.join("report.md");
    fs::write(&json_path, report.to_json())?;
    fs::write(&md_path, report.to_markdown())?;
    Ok((json_path, md_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Channel;

    #[test]
    fn battery_runs_for_active_features() {
        // Smoke counts keep this fast; we assert the harness plumbing, not a leakage bound.
        let report = run_timing_battery(BatteryConfig::smoke());
        // At least the default-feature targets (mlkem, mldsa) should be present.
        #[cfg(any(
            feature = "mlkem",
            feature = "mldsa",
            feature = "lattice-zkp-hardened",
            feature = "hqc-hardened"
        ))]
        assert!(
            !report.reports.is_empty(),
            "expected at least one hardened target in the battery"
        );
        // Every entry carries the wall-clock channel and the configured threshold.
        for entry in &report.reports {
            assert_eq!(entry.channel, Channel::WallClockTiming);
            assert!((entry.abs_t_threshold - 4.5).abs() < f64::EPSILON);
        }
        let _ = report.to_json();
        let _ = report.to_markdown();
    }

    #[test]
    fn evidence_package_round_trips_to_disk() {
        let report = run_timing_battery(BatteryConfig::smoke());
        let mut dir = std::env::temp_dir();
        dir.push(format!("libq-sca-self-cert-test-{}", std::process::id()));
        let (json_path, md_path) =
            write_evidence_package(&dir, &report).expect("write evidence package");
        let json = fs::read_to_string(&json_path).expect("read json");
        let md = fs::read_to_string(&md_path).expect("read md");
        assert!(json.contains("\"schema\":\"libq.sca.self-cert.v1\""));
        assert!(md.contains("self-certification report"));
        let _ = fs::remove_dir_all(&dir);
    }
}
