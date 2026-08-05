//! Security validator binary for lib-Q
//!
//! This binary provides command-line tools for security validation
//! that can be used in CI/CD workflows. Each subcommand now runs exactly the
//! checks its name promises (previously every subcommand ran all eight checks
//! identically — see t_4d2dc427).

// Provide a no_std fallback main for environments without std support
#[cfg(not(feature = "std"))]
fn main() {
    // Empty implementation for no_std environments
}

#[cfg(feature = "std")]
use std::env;

#[cfg(feature = "std")]
use lib_q_utils::security_validation::{
    SecurityCheck,
    SecurityValidator,
    print_report,
};

#[cfg(feature = "std")]
fn print_usage() {
    println!("Usage: security-validator <command>");
    println!("Commands:");
    println!(
        "  validate-nist     - Validate NIST-mandated primitive compliance (classical crypto + SHA-3)"
    );
    println!("  validate-timing   - Validate constant-time AEAD/MAC comparisons");
    println!("  validate-memory   - Validate secret-key-material zeroization");
    println!("  validate-classical - Validate no non-allowlisted classical crypto");
    println!("  validate-sha3     - Validate no external SHA-3/Keccak duplication");
    println!("  validate-all      - Run all eight checks");
}

/// The checks each subcommand runs. Previously every subcommand ran the identical set of all
/// eight stub checks regardless of name; now `validate-timing` really only runs
/// `timing_vulnerabilities`, etc.
#[cfg(feature = "std")]
fn checks_for(command: &str) -> Option<&'static [SecurityCheck]> {
    match command {
        "validate-nist" => Some(&[
            SecurityCheck::ClassicalCrypto,
            SecurityCheck::Sha3Compliance,
        ]),
        "validate-timing" => Some(&[SecurityCheck::TimingVulnerabilities]),
        "validate-memory" => Some(&[SecurityCheck::MemoryZeroization]),
        "validate-classical" => Some(&[SecurityCheck::ClassicalCrypto]),
        "validate-sha3" => Some(&[SecurityCheck::Sha3Compliance]),
        "validate-all" => Some(&SecurityCheck::ALL),
        _ => None,
    }
}

#[cfg(feature = "std")]
fn banner_for(command: &str) -> &'static str {
    match command {
        "validate-nist" => "🔒 Running NIST compliance validation...",
        "validate-timing" => "⏱️  Running timing vulnerability validation...",
        "validate-memory" => "🧠 Running memory safety validation...",
        "validate-classical" => "🔐 Running classical crypto validation...",
        "validate-sha3" => "📊 Running SHA-3 compliance validation...",
        "validate-all" => "🔒 Running comprehensive security validation...",
        _ => "",
    }
}

#[cfg(feature = "std")]
fn run_command(command: &str) -> i32 {
    let Some(checks) = checks_for(command) else {
        println!("Unknown command: {}", command);
        return 1;
    };
    println!("{}", banner_for(command));

    let validator = SecurityValidator::new();
    let report = validator.validate_only(checks);
    print_report(&report);

    if !report.summary.is_success() {
        return 1;
    }

    println!("✅ Security validation completed successfully");
    0
}

#[cfg(feature = "std")]
fn run_with_args(args: &[String]) -> i32 {
    if args.len() < 2 {
        print_usage();
        return 1;
    }

    run_command(&args[1])
}

// Main entry point for the security validator binary
#[cfg(feature = "std")]
fn main() {
    let args: Vec<String> = env::args().collect();
    let exit_code = run_with_args(&args);
    std::process::exit(exit_code);
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{
        run_command,
        run_with_args,
    };

    #[test]
    fn run_with_args_requires_command() {
        let args = vec!["security-validator".to_string()];
        assert_eq!(run_with_args(&args), 1);
    }

    #[test]
    fn run_command_unknown_returns_error() {
        assert_eq!(run_command("not-a-real-command"), 1);
    }

    // The following six assert against the REAL libQ workspace (SecurityValidator::new() has
    // no fixture override here) — they are watching a real, current invariant of this repo, not
    // a synthetic one. If one of them flips, either a real regression was introduced, or (for
    // validate_all) a previously-known cross-crate finding was fixed. See out-of-scope.md.

    #[test]
    fn run_command_validate_nist_passes_on_clean_tree() {
        // classical_crypto_detection + sha3_compliance: both pass today (sha2/aes are
        // allowlisted NIST mandates; no external sha3/tiny-keccak dependency exists).
        assert_eq!(run_command("validate-nist"), 0);
    }

    #[test]
    fn run_command_validate_timing_passes_on_clean_tree() {
        // Every AEAD/MAC crate (lib-q-mac, lib-q-aead, lib-q-duplex-aead, lib-q-tweak-aead,
        // lib-q-rocca-s, lib-q-romulus, lib-q-saturnin, lib-q-hpke) references a constant-time
        // comparison primitive somewhere in its source today.
        assert_eq!(run_command("validate-timing"), 0);
    }

    #[test]
    fn run_command_validate_memory_passes_on_clean_tree() {
        // Every key-material crate on the list declares and uses `zeroize` today.
        assert_eq!(run_command("validate-memory"), 0);
    }

    #[test]
    fn run_command_validate_classical_passes_on_clean_tree() {
        assert_eq!(run_command("validate-classical"), 0);
    }

    #[test]
    fn run_command_validate_sha3_passes_on_clean_tree() {
        assert_eq!(run_command("validate-sha3"), 0);
    }

    #[test]
    fn run_command_validate_all_fails_on_a_real_cross_crate_finding() {
        // validate-all runs input_validation too, which flags a REAL, currently-unfixed issue
        // outside this crate's scope: lib-q-hpke's `HpkePublicKey::from_bytes`/
        // `HpkePrivateKey::from_bytes` (lib-q-hpke/src/types.rs:275,298) are infallible
        // constructors that accept an unchecked, variable-length `Vec<u8>`. That is a genuine
        // finding (see out-of-scope.md), not a bug in this checker — the whole point of
        // fixing this gate was to let it report a real failure instead of a manufactured
        // "All security checks passed!". If lib-q-hpke's constructors are fixed to validate
        // length (or return Result), this assertion should flip to `== 0` in the same change.
        assert_eq!(run_command("validate-all"), 1);
    }
}
