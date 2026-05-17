//! Security validator binary for lib-Q
//!
//! This binary provides command-line tools for security validation
//! that can be used in CI/CD workflows.

// Provide a no_std fallback main for environments without std support
#[cfg(not(feature = "std"))]
fn main() {
    // Empty implementation for no_std environments
}

#[cfg(feature = "std")]
use std::env;

#[cfg(feature = "std")]
use lib_q_utils::security_validation::{
    SecurityValidator,
    print_report,
};

#[cfg(feature = "std")]
fn print_usage() {
    println!("Usage: security-validator <command>");
    println!("Commands:");
    println!("  validate-nist     - Validate NIST compliance");
    println!("  validate-timing   - Validate constant-time operations");
    println!("  validate-memory   - Validate memory safety");
    println!("  validate-classical - Validate no classical crypto");
    println!("  validate-sha3     - Validate SHA-3 compliance");
    println!("  validate-all      - Run all validations");
}

#[cfg(feature = "std")]
fn run_command(command: &str) -> i32 {
    let validator = SecurityValidator::new();

    match command {
        "validate-nist" => {
            println!("🔒 Running NIST compliance validation...");
        }
        "validate-timing" => {
            println!("⏱️  Running timing vulnerability validation...");
        }
        "validate-memory" => {
            println!("🧠 Running memory safety validation...");
        }
        "validate-classical" => {
            println!("🔐 Running classical crypto validation...");
        }
        "validate-sha3" => {
            println!("📊 Running SHA-3 compliance validation...");
        }
        "validate-all" => {
            println!("🔒 Running comprehensive security validation...");
        }
        _ => {
            println!("Unknown command: {}", command);
            return 1;
        }
    }

    let report = validator.validate();
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

    #[test]
    fn run_command_validate_nist_returns_success() {
        assert_eq!(run_command("validate-nist"), 0);
    }

    #[test]
    fn run_command_validate_timing_returns_success() {
        assert_eq!(run_command("validate-timing"), 0);
    }

    #[test]
    fn run_command_validate_memory_returns_success() {
        assert_eq!(run_command("validate-memory"), 0);
    }

    #[test]
    fn run_command_validate_classical_returns_success() {
        assert_eq!(run_command("validate-classical"), 0);
    }

    #[test]
    fn run_command_validate_sha3_returns_success() {
        assert_eq!(run_command("validate-sha3"), 0);
    }

    #[test]
    fn run_command_validate_all_returns_success() {
        assert_eq!(run_command("validate-all"), 0);
    }
}
