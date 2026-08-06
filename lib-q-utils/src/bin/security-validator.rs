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
    println!("Usage: security-validator <command> [source-dir]");
    println!("Commands:");
    println!(
        "  validate-nist     - Validate NIST-mandated primitive compliance (classical crypto + SHA-3)"
    );
    println!("  validate-timing   - Validate constant-time AEAD/MAC comparisons");
    println!("  validate-memory   - Validate secret-key-material zeroization");
    println!("  validate-classical - Validate no non-allowlisted classical crypto");
    println!("  validate-sha3     - Validate no external SHA-3/Keccak duplication");
    println!("  validate-all      - Run all eight checks");
    println!(
        "  [source-dir]      - optional: scan this single crate directory instead of the real \
         libQ workspace (used by this crate's own test suite; a real invocation should omit it)"
    );
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

/// Run `command`. When `source_override` is `Some`, the validator scans exactly that one crate
/// directory (via [`SecurityValidator::with_source_paths`]) instead of discovering the real libQ
/// workspace — this is a testing hook (see `print_usage`'s `[source-dir]` line) so the CLI's own
/// integration tests can plant a deterministic violation and watch the compiled binary itself
/// fail, without depending on the ambient state of unrelated crates.
#[cfg(feature = "std")]
fn run_command(command: &str, source_override: Option<&str>) -> i32 {
    let Some(checks) = checks_for(command) else {
        println!("Unknown command: {}", command);
        return 1;
    };
    println!("{}", banner_for(command));

    let validator = match source_override {
        Some(dir) => {
            // Without this line a clean synthetic directory yields a report that is textually
            // identical to a real workspace certification — "🎉 All security checks passed!" —
            // which is precisely the false-green failure mode t_4d2dc427 was filed about. Say
            // out loud that nothing about libQ was read.
            println!(
                "⚠️  [source-dir] override in effect: scanning ONLY `{}`. This report does NOT \
                 certify the libQ workspace.",
                dir
            );
            SecurityValidator::new().with_source_paths(vec![dir.to_string()])
        }
        None => SecurityValidator::new(),
    };
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

    let source_override = args.get(2).map(String::as_str);
    run_command(&args[1], source_override)
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
        assert_eq!(run_command("not-a-real-command", None), 1);
    }

    // The following six assert against the REAL libQ workspace (SecurityValidator::new() has
    // no fixture override here) — they are watching a real, current invariant of this repo, not
    // a synthetic one. If one of them flips, either a real regression was introduced, or (for
    // validate_all) a previously-known cross-crate finding was fixed. See out-of-scope.md.

    #[test]
    fn run_command_validate_nist_passes_on_clean_tree() {
        // classical_crypto_detection + sha3_compliance: both pass today (sha2/aes are
        // allowlisted NIST mandates; no external sha3/tiny-keccak dependency exists).
        assert_eq!(run_command("validate-nist", None), 0);
    }

    #[test]
    fn run_command_validate_timing_passes_on_clean_tree() {
        // Every AEAD/MAC crate (lib-q-mac, lib-q-aead, lib-q-duplex-aead, lib-q-tweak-aead,
        // lib-q-rocca-s, lib-q-romulus, lib-q-saturnin, lib-q-hpke) references a constant-time
        // comparison primitive somewhere in its source today.
        assert_eq!(run_command("validate-timing", None), 0);
    }

    #[test]
    fn run_command_validate_memory_passes_on_clean_tree() {
        // Every key-material crate on the list declares and uses `zeroize` today.
        assert_eq!(run_command("validate-memory", None), 0);
    }

    #[test]
    fn run_command_validate_classical_passes_on_clean_tree() {
        assert_eq!(run_command("validate-classical", None), 0);
    }

    #[test]
    fn run_command_validate_sha3_passes_on_clean_tree() {
        assert_eq!(run_command("validate-sha3", None), 0);
    }

    #[test]
    fn run_command_validate_all_passes_now_that_the_hpke_finding_is_fixed() {
        // validate-all runs input_validation too, which used to flag a real cross-crate
        // finding: lib-q-hpke's `HpkePublicKey::from_bytes`/`HpkePrivateKey::from_bytes`
        // (formerly lib-q-hpke/src/types.rs:275,298) were infallible constructors that
        // accepted an unchecked, variable-length `Vec<u8>`. Those types were dead API — zero
        // consumers outside their own unit test workspace-wide; every real entry point takes
        // `lib_q_core::KemPublicKey`, which is validated at each call site — and have been
        // deleted (card t_f3ea6b2a). This assertion is flipped to `== 0` in the same change,
        // per the instruction this comment used to carry.
        assert_eq!(run_command("validate-all", None), 0);
    }

    #[test]
    fn run_with_args_plumbs_a_third_arg_as_the_source_override() {
        // A source-dir override that contains no crate at all must trip
        // `SecurityValidationResult::Fail("... scanned 0 ...")` (see security_validation.rs's
        // `scanning_zero_files_is_a_hard_failure_not_a_pass`) rather than trivially passing —
        // proving `run_with_args` actually forwards `args[2]` into the validator instead of
        // silently ignoring it.
        let dir = std::env::temp_dir();
        let empty = dir.join("lib-q-utils-secval-bin-test-empty-override");
        let _ = std::fs::create_dir_all(&empty);
        let args = vec![
            "security-validator".to_string(),
            "validate-classical".to_string(),
            empty.to_string_lossy().into_owned(),
        ];
        assert_eq!(
            run_with_args(&args),
            1,
            "an override dir with no Cargo.toml must fail, not silently pass"
        );
        let _ = std::fs::remove_dir_all(&empty);
    }
}
