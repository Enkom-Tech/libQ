//! Security validation utilities for lib-Q
//!
//! This module provides shared security validation functions that can be used
//! across different parts of the codebase to ensure consistent security checks.

#[cfg(feature = "std")]
#[allow(clippy::disallowed_types)]
use std::collections::HashMap;

/// Security validation result
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityValidationResult {
    Pass,
    Fail(String),
    Warning(String),
}

/// Security validation report
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "std",
    doc = "Security validation report with HashMap results"
)]
#[cfg_attr(
    not(feature = "std"),
    doc = "Security validation report (minimal version)"
)]
pub struct SecurityValidationReport {
    #[cfg(feature = "std")]
    #[allow(clippy::disallowed_types)]
    pub results: HashMap<String, SecurityValidationResult>,
    #[cfg(not(feature = "std"))]
    pub results: &'static [(&'static str, SecurityValidationResult)],
    pub summary: SecurityValidationSummary,
}

/// Security validation summary
#[derive(Debug, Clone)]
pub struct SecurityValidationSummary {
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
}

impl Default for SecurityValidationSummary {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityValidationSummary {
    pub fn new() -> Self {
        Self {
            total_checks: 0,
            passed: 0,
            failed: 0,
            warnings: 0,
        }
    }

    pub fn add_result(&mut self, result: &SecurityValidationResult) {
        self.total_checks += 1;
        match result {
            SecurityValidationResult::Pass => self.passed += 1,
            SecurityValidationResult::Fail(_) => self.failed += 1,
            SecurityValidationResult::Warning(_) => self.warnings += 1,
        }
    }

    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    pub fn has_warnings(&self) -> bool {
        self.warnings > 0
    }
}

/// Security validator
pub struct SecurityValidator {
    source_paths: Vec<String>,
    exclude_paths: Vec<String>,
}

impl SecurityValidator {
    /// Create a new security validator
    pub fn new() -> Self {
        Self {
            source_paths: vec!["src/".to_string()],
            exclude_paths: vec!["target/".to_string(), ".git/".to_string()],
        }
    }

    /// Add source paths to check
    pub fn with_source_paths(mut self, paths: Vec<String>) -> Self {
        self.source_paths = paths;
        self
    }

    /// Add paths to exclude from checks
    pub fn with_exclude_paths(mut self, paths: Vec<String>) -> Self {
        self.exclude_paths = paths;
        self
    }

    /// Run all security validations
    #[cfg(feature = "std")]
    pub fn validate(&self) -> SecurityValidationReport {
        let mut report = SecurityValidationReport {
            #[allow(clippy::disallowed_types)]
            results: HashMap::new(),
            summary: SecurityValidationSummary::new(),
        };

        // Run all validation checks
        self.check_classical_crypto(&mut report);
        self.check_sha3_compliance(&mut report);
        self.check_unsafe_code(&mut report);
        self.check_zeroize_usage(&mut report);
        self.check_timing_vulnerabilities(&mut report);
        self.check_error_handling(&mut report);
        self.check_input_validation(&mut report);
        self.check_random_generation(&mut report);

        report
    }

    /// Run all security validations (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn validate(&self) -> SecurityValidationReport {
        // no_std stub: real file-scanning requires std I/O and is not
        // implemented in no_std mode.  Return an explicit failure (failed=1)
        // so CI cannot mistake this stub for a passing security gate.
        // NOTE: SecurityValidationResult::Fail holds a String which requires
        // alloc; in no_std we express the failure through the summary counters
        // directly rather than placing a Fail variant in the static slice.
        let summary = SecurityValidationSummary {
            total_checks: 1,
            passed: 0,
            failed: 1,
            warnings: 0,
        };

        SecurityValidationReport {
            results: &[],
            summary,
        }
    }

    /// Check for classical cryptographic algorithms
    fn check_classical_crypto(&self, report: &mut SecurityValidationReport) {
        let check_name = "classical_crypto_detection";

        // TODO: scan self.source_paths for classical crypto usage.
        // Until real scanning is implemented, fail loudly so CI is not misled.
        report.results.insert(
            check_name.to_string(),
            SecurityValidationResult::Fail(
                "not implemented: classical crypto scan requires real file analysis".to_string(),
            ),
        );

        report
            .summary
            .add_result(report.results.get(check_name).unwrap());
    }

    /// Check for SHA-3 family compliance
    fn check_sha3_compliance(&self, report: &mut SecurityValidationReport) {
        let check_name = "sha3_compliance";

        // TODO: scan self.source_paths for non-SHA-3 hash usage.
        // Until real scanning is implemented, fail loudly so CI is not misled.
        report.results.insert(
            check_name.to_string(),
            SecurityValidationResult::Fail(
                "not implemented: SHA-3 compliance scan requires real file analysis".to_string(),
            ),
        );

        report
            .summary
            .add_result(report.results.get(check_name).unwrap());
    }

    /// Check for unsafe code usage
    fn check_unsafe_code(&self, report: &mut SecurityValidationReport) {
        let check_name = "unsafe_code_usage";

        // TODO: count unsafe blocks via real file scanning.
        // Until real scanning is implemented, fail loudly so CI is not misled.
        report.results.insert(
            check_name.to_string(),
            SecurityValidationResult::Fail(
                "not implemented: unsafe code scan requires real file analysis".to_string(),
            ),
        );

        report
            .summary
            .add_result(report.results.get(check_name).unwrap());
    }

    /// Check for memory zeroization
    fn check_zeroize_usage(&self, report: &mut SecurityValidationReport) {
        let check_name = "memory_zeroization";

        // TODO: verify zeroize crate usage via real file scanning.
        // Until real scanning is implemented, fail loudly so CI is not misled.
        report.results.insert(
            check_name.to_string(),
            SecurityValidationResult::Fail(
                "not implemented: zeroize usage scan requires real file analysis".to_string(),
            ),
        );

        report
            .summary
            .add_result(report.results.get(check_name).unwrap());
    }

    /// Check for potential timing vulnerabilities
    fn check_timing_vulnerabilities(&self, report: &mut SecurityValidationReport) {
        let check_name = "timing_vulnerabilities";

        // TODO: detect branching on secret data via real file scanning.
        // Until real scanning is implemented, fail loudly so CI is not misled.
        report.results.insert(
            check_name.to_string(),
            SecurityValidationResult::Fail(
                "not implemented: timing vulnerability scan requires real file analysis"
                    .to_string(),
            ),
        );

        report
            .summary
            .add_result(report.results.get(check_name).unwrap());
    }

    /// Check for proper error handling
    fn check_error_handling(&self, report: &mut SecurityValidationReport) {
        let check_name = "error_handling";

        // TODO: detect unwrap/expect usage in production code via real file scanning.
        // Until real scanning is implemented, fail loudly so CI is not misled.
        report.results.insert(
            check_name.to_string(),
            SecurityValidationResult::Fail(
                "not implemented: error handling scan requires real file analysis".to_string(),
            ),
        );

        report
            .summary
            .add_result(report.results.get(check_name).unwrap());
    }

    /// Check for input validation
    fn check_input_validation(&self, report: &mut SecurityValidationReport) {
        let check_name = "input_validation";

        // TODO: detect input validation patterns via real file scanning.
        // Until real scanning is implemented, fail loudly so CI is not misled.
        report.results.insert(
            check_name.to_string(),
            SecurityValidationResult::Fail(
                "not implemented: input validation scan requires real file analysis".to_string(),
            ),
        );

        report
            .summary
            .add_result(report.results.get(check_name).unwrap());
    }

    /// Check for random number generation
    fn check_random_generation(&self, report: &mut SecurityValidationReport) {
        let check_name = "random_generation";

        // TODO: verify random number generation usage via real file scanning.
        // Until real scanning is implemented, fail loudly so CI is not misled.
        report.results.insert(
            check_name.to_string(),
            SecurityValidationResult::Fail(
                "not implemented: random generation scan requires real file analysis".to_string(),
            ),
        );

        report
            .summary
            .add_result(report.results.get(check_name).unwrap());
    }
}

impl Default for SecurityValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Print security validation report
#[cfg(feature = "std")]
pub fn print_report(report: &SecurityValidationReport) {
    println!("🔒 lib-Q Security Validation Report");
    println!("=====================================");

    for (check_name, result) in &report.results {
        match result {
            SecurityValidationResult::Pass => {
                println!("✅ {}: PASS", check_name);
            }
            SecurityValidationResult::Fail(message) => {
                println!("❌ {}: FAIL - {}", check_name, message);
            }
            SecurityValidationResult::Warning(message) => {
                println!("⚠️  {}: WARNING - {}", check_name, message);
            }
        }
    }

    println!("\nSummary:");
    println!("  Total checks: {}", report.summary.total_checks);
    println!("  Passed: {}", report.summary.passed);
    println!("  Failed: {}", report.summary.failed);
    println!("  Warnings: {}", report.summary.warnings);

    if report.summary.is_success() {
        println!("🎉 All security checks passed!");
    } else {
        println!("🚨 Security validation failed!");
    }
}

/// Print security validation report (no_std version, minimal output)
#[cfg(not(feature = "std"))]
pub fn print_report(_report: &SecurityValidationReport) {
    // No-op for no_std environments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_validator() {
        let validator = SecurityValidator::new();
        let report = validator.validate();

        // All checks are stub-only — they must fail loudly rather than silently pass.
        assert!(report.summary.total_checks > 0);
        assert!(
            !report.summary.is_success(),
            "stub validator must not report success"
        );
        assert!(report.summary.failed > 0);
    }

    #[test]
    fn test_security_summary() {
        let mut summary = SecurityValidationSummary::new();

        summary.add_result(&SecurityValidationResult::Pass);
        summary.add_result(&SecurityValidationResult::Warning("test".to_string()));

        assert_eq!(summary.total_checks, 2);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.failed, 0);
        assert!(summary.is_success());
        assert!(summary.has_warnings());
    }

    #[test]
    fn test_security_summary_fail_branch() {
        let mut summary = SecurityValidationSummary::new();
        summary.add_result(&SecurityValidationResult::Fail("x".into()));
        assert!(!summary.is_success());
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_validator_builder() {
        let v = SecurityValidator::new()
            .with_source_paths(vec!["a/".into()])
            .with_exclude_paths(vec!["b/".into()]);
        let r = v.validate();
        assert!(r.summary.total_checks > 0);
        // Stub checks must signal failure, not silently pass.
        assert!(
            !r.summary.is_success(),
            "stub validator must not report success"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    #[allow(clippy::disallowed_types)]
    fn test_print_report_all_result_kinds() {
        use std::collections::HashMap;
        let mut results = HashMap::new();
        results.insert("a".into(), SecurityValidationResult::Pass);
        results.insert("b".into(), SecurityValidationResult::Fail("boom".into()));
        results.insert("c".into(), SecurityValidationResult::Warning("w".into()));
        let mut summary = SecurityValidationSummary::new();
        for r in results.values() {
            summary.add_result(r);
        }
        let report = SecurityValidationReport { results, summary };
        print_report(&report);
    }
}
