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

// Main entry point for the security validator binary
#[cfg(feature = "std")]
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: security-validator <command>");
        println!("Commands:");
        println!("  validate-nist     - Validate NIST compliance");
        println!("  validate-timing   - Validate constant-time operations");
        println!("  validate-memory   - Validate memory safety");
        println!("  validate-classical - Validate no classical crypto");
        println!("  validate-sha3     - Validate SHA-3 compliance");
        println!("  validate-all      - Run all validations");
        std::process::exit(1);
    }

    let command = &args[1];
    let validator = SecurityValidator::new();

    match command.as_str() {
        "validate-nist" => {
            println!("🔒 Running NIST compliance validation...");
            let report = validator.validate();
            print_report(&report);

            if !report.summary.is_success() {
                std::process::exit(1);
            }
        }
        "validate-timing" => {
            println!("⏱️  Running timing vulnerability validation...");
            let report = validator.validate();
            print_report(&report);

            if !report.summary.is_success() {
                std::process::exit(1);
            }
        }
        "validate-memory" => {
            println!("🧠 Running memory safety validation...");
            let report = validator.validate();
            print_report(&report);

            if !report.summary.is_success() {
                std::process::exit(1);
            }
        }
        "validate-classical" => {
            println!("🔐 Running classical crypto validation...");
            let report = validator.validate();
            print_report(&report);

            if !report.summary.is_success() {
                std::process::exit(1);
            }
        }
        "validate-sha3" => {
            println!("📊 Running SHA-3 compliance validation...");
            let report = validator.validate();
            print_report(&report);

            if !report.summary.is_success() {
                std::process::exit(1);
            }
        }
        "validate-all" => {
            println!("🔒 Running comprehensive security validation...");
            let report = validator.validate();
            print_report(&report);

            if !report.summary.is_success() {
                std::process::exit(1);
            }
        }
        _ => {
            println!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }

    println!("✅ Security validation completed successfully");
}
