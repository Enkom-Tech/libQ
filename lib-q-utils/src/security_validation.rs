//! Security validation utilities for lib-Q
//!
//! This module runs real, file-system-backed security checks over the libQ cargo
//! workspace (or, via [`SecurityValidator::with_source_paths`], over a synthetic
//! directory tree for testing). Every check is a documented, mechanical policy —
//! see [`SecurityCheck::rule`] — that is designed to actually pass on a compliant
//! tree and actually fail on a violating one. None of the eight checks are stubs.
//!
//! # Design notes (why these particular rules)
//!
//! A generic, semantically-aware "is this code secure" scanner does not exist and
//! is out of scope for a CI gate. Each check below was chosen because it is:
//! 1. mechanical (a file-system / textual scan, no dataflow analysis needed),
//! 2. currently satisfied by the real libQ workspace (verified before landing), and
//! 3. falsifiable — a synthetic violation makes it fail, and removing the
//!    violation makes it pass again (see the `tests` module).
//!
//! Two of the checks (`unsafe_code_usage`'s crate allowlist, `classical_crypto_detection`'s
//! primitive allowlist) exist because a naive "zero unsafe" or "zero classical-crypto-dependency"
//! rule would hard-fail this repo: SIMD intrinsics are load-bearing (1000+ `unsafe` sites across
//! 20+ crates), and `sha2`/`aes` are NIST-mandated building blocks inside SLH-DSA (FIPS 205), HQC's
//! AES-CTR DRBG, and MAYO. A policy check must therefore be an allowlist with a recorded rationale,
//! not a bare count.

#[cfg(feature = "std")]
#[allow(clippy::disallowed_types)]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::{
    fs,
    path::{
        Path,
        PathBuf,
    },
};

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

    /// `true` only when every check that ran was a genuine `Pass`.
    ///
    /// A `Warning` (or a `Fail`) blocks success, and — critically — so does having run
    /// zero checks: `total_checks == 0` can never report success. This was previously
    /// `self.failed == 0`, which let a report of eight `Warning`s (and even a report of
    /// zero performed checks) print "All security checks passed!". See the crate's
    /// `security-validator` binary history (commit `05606e1`) for how that happened.
    pub fn is_success(&self) -> bool {
        self.total_checks > 0 && self.passed == self.total_checks
    }

    pub fn has_warnings(&self) -> bool {
        self.warnings > 0
    }
}

/// The eight security checks this validator can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityCheck {
    ClassicalCrypto,
    Sha3Compliance,
    UnsafeCodeUsage,
    MemoryZeroization,
    TimingVulnerabilities,
    ErrorHandling,
    InputValidation,
    RandomGeneration,
}

impl SecurityCheck {
    /// All eight checks, in the order `validate()` runs them.
    pub const ALL: [SecurityCheck; 8] = [
        SecurityCheck::ClassicalCrypto,
        SecurityCheck::Sha3Compliance,
        SecurityCheck::UnsafeCodeUsage,
        SecurityCheck::MemoryZeroization,
        SecurityCheck::TimingVulnerabilities,
        SecurityCheck::ErrorHandling,
        SecurityCheck::InputValidation,
        SecurityCheck::RandomGeneration,
    ];

    /// The stable, machine-readable check name used as the report's map key.
    pub fn name(self) -> &'static str {
        match self {
            SecurityCheck::ClassicalCrypto => "classical_crypto_detection",
            SecurityCheck::Sha3Compliance => "sha3_compliance",
            SecurityCheck::UnsafeCodeUsage => "unsafe_code_usage",
            SecurityCheck::MemoryZeroization => "memory_zeroization",
            SecurityCheck::TimingVulnerabilities => "timing_vulnerabilities",
            SecurityCheck::ErrorHandling => "error_handling",
            SecurityCheck::InputValidation => "input_validation",
            SecurityCheck::RandomGeneration => "random_generation",
        }
    }

    /// A human-readable statement of exactly what this check enforces. Printed for every
    /// check, pass or fail, so nobody has to read the source to know what "PASS" means here.
    pub fn rule(self) -> &'static str {
        match self {
            SecurityCheck::ClassicalCrypto => {
                "every classical/legacy crypto crate dependency must be on the NIST-mandated \
                 allowlist (sha2, aes are allowed: SLH-DSA/HQC/MAYO mandate them); anything else fails"
            }
            SecurityCheck::Sha3Compliance => {
                "no crate may depend on an external `sha3`/`tiny-keccak` implementation; the \
                 workspace's own audited lib-q-keccak/lib-q-sha3 is mandatory"
            }
            SecurityCheck::UnsafeCodeUsage => {
                "`unsafe` code may only appear in the reviewed SIMD/FFI crate allowlist (a \
                 zero-unsafe policy is not viable here: SIMD is load-bearing)"
            }
            SecurityCheck::MemoryZeroization => {
                "every crate that generates or holds secret key material must depend on and \
                 actually reference `zeroize` in its own source"
            }
            SecurityCheck::TimingVulnerabilities => {
                "every AEAD/MAC crate must use a constant-time comparison primitive \
                 (ct_eq/ConstantTimeEq/constant_time_compare/subtle) somewhere in its source"
            }
            SecurityCheck::ErrorHandling => {
                "no source file may carry a whole-file blanket \
                 `#![allow(clippy::unwrap_used | expect_used | panic)]`"
            }
            SecurityCheck::InputValidation => {
                "an infallible `from_bytes`/`decode` constructor (returning `-> Self`) must not \
                 accept unchecked variable-length input (`Vec<u8>` / `&[u8]` / `&mut [u8]`)"
            }
            SecurityCheck::RandomGeneration => {
                "library source must not call `thread_rng()` / `rand::random()` directly; use \
                 the workspace's vetted RNG path instead"
            }
        }
    }
}

/// One entry per crate allowed to contain reviewed `unsafe` code.
///
/// `allowed_file_scope`: empty = whole-crate exemption, reserved for crates independently
/// verified (2026-08 allowlist audit) to ship real arch-dispatch SIMD/intrinsics code spanning
/// many files — see `tests::empty_scope_entries_are_exactly_the_reviewed_simd_set` for the
/// pinned set. Non-empty = the exemption is narrowed to exactly these crate-relative,
/// forward-slash file suffixes (e.g. `"src/foo.rs"`, matched against the end of the real path
/// with `\` normalized to `/`); real `unsafe` anywhere else in that crate is a violation.
#[cfg(feature = "std")]
struct UnsafeAllowlistEntry {
    crate_name: &'static str,
    justification: &'static str,
    allowed_file_scope: &'static [&'static str],
}

/// Crates in which `unsafe` code is reviewed and permitted, with the reason it is there.
/// This is a per-crate allowlist, not a count: `unsafe` usage totals ~1000+ sites across the
/// workspace (AVX2/ARMv8 SIMD is load-bearing for performance), so "unsafe count == 0" fails
/// every real build and "unsafe count > 0" passes trivially. The allowlist is the actual policy.
///
/// Every entry below was re-verified against the crate's real `src/` during the 2026-08
/// allowlist audit (grep for genuine `unsafe` constructs + arch-dispatch markers, plus a manual
/// read of every non-SIMD site). 10 entries ship real, multi-file arch-dispatch SIMD and keep a
/// whole-crate exemption (`allowed_file_scope: &[]`); the other 13 do not — their `unsafe` is
/// something else entirely (zeroization fallbacks, unchecked-bounds fast paths, raw-pointer
/// transmutes, FFI callback registration, hardware-RNG intrinsics) and their exemption is now
/// narrowed to exactly the files that actually contain it. `lib-q-mayo`'s prior justification —
/// "AVX2 matrix/vector arithmetic" — was fabricated: the crate ships zero SIMD; its only
/// `unsafe` is two `write_volatile` zeroization-fallback calls. That single fabricated entry was
/// load-bearing on a whole-crate scan skip, and it was not alone. Of the 13 now-scoped entries:
/// 10 (including `lib-q-mayo`) claimed SIMD/AVX/AES-NI/ARMv8/NEON/intrinsics while their crate's
/// `src/` contains no arch-dispatch marker at all — that exact set is enumerated by
/// `tests::allowlist_simd_justifications_have_a_matching_arch_dispatch_marker`, which fails and
/// names them if the claim is reintroduced; 2 more (`lib-q-slh-dsa`, `lib-q-stark-util`) claimed
/// SIMD while their only arch marker is non-vectorized (an `is_x86_feature_detected` batching
/// heuristic, and a `core::arch::asm!` optimizer barrier respectively); and 1 (`lib-q-random`)
/// had a non-SIMD justification that was merely incomplete. Each replacement justification below
/// names the construct actually present at the scoped path.
#[cfg(feature = "std")]
const ALLOWED_UNSAFE_CRATES: &[UnsafeAllowlistEntry] = &[
    UnsafeAllowlistEntry {
        crate_name: "lib-q-intrinsics",
        justification: "runtime CPU-feature dispatch / raw SIMD intrinsics wrappers",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-keccak",
        justification: "AVX2/ARMv8 SIMD Keccak-f[1600] permutation",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-aead",
        justification: "raw-pointer secure-memory zeroization/allocation and a MaybeUninit \
                        stack-buffer transmute; scalar code, not vectorized",
        allowed_file_scope: &["src/security/memory.rs", "src/security/stack_buffer.rs"],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-rocca-s",
        justification: "AES-NI/SIMD ROCCA-S permutation",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-saturnin",
        justification: "SIMD SATURNIN block-cipher paths",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-tweak-aead",
        justification: "SIMD tweakable-block-cipher paths",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-ml-dsa",
        justification: "AVX2 NTT / rejection-sampling fast paths",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-ml-kem",
        justification: "raw-pointer array-splitting transmutes in array utilities; scalar \
                        code, not vectorized",
        allowed_file_scope: &["src/util.rs"],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-mayo",
        justification: "write_volatile zeroization fallback (2 sites); scalar code, not \
                        vectorized",
        allowed_file_scope: &["src/mayo_core.rs"],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-slh-dsa",
        justification: "repr(C) pointer-cast for an address-word byte view (1 site); a \
                        runtime x86-feature-detection call elsewhere (wots.rs) is only a \
                        chunked-vs-scalar batching heuristic and does not itself gate any \
                        unsafe vectorized code",
        allowed_file_scope: &["src/address.rs"],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-hqc",
        justification: "AVX2 polynomial arithmetic",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-random",
        justification: "x86 RDRAND hardware-RNG intrinsics (hardware_rng.rs), \
                        custom-entropy-callback FFI registration (custom_entropy.rs, and its \
                        public re-export in lib.rs), and a raw-pointer byte-to-numeric-type \
                        copy in provider.rs; the OS entropy source itself is reached through \
                        the safe `getrandom` crate",
        allowed_file_scope: &[
            "src/hardware_rng.rs",
            "src/custom_entropy.rs",
            "src/lib.rs",
            "src/provider.rs",
        ],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark",
        justification: "unchecked-bounds row-slice access in the one function the crate's \
                        otherwise-`#![deny(unsafe_code)]` lib.rs locally allows it for; \
                        scalar code, not vectorized",
        allowed_file_scope: &["src/check_constraints.rs"],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-challenger",
        justification: "unchecked-precondition field-element construction \
                        (`from_canonical_unchecked`) in PoW witness search and rejection \
                        sampling; scalar code, not vectorized",
        allowed_file_scope: &[
            "src/grinding_challenger.rs",
            "src/serializing_challenger.rs",
        ],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-commit",
        justification: "unchecked-bounds row-slice access (1 site); scalar code, not \
                        vectorized",
        allowed_file_scope: &["src/domain.rs"],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-dft",
        justification: "repr(transparent) slice reinterpretation and raw-pointer buffer \
                        splitting for radix-2 DFT butterflies; scalar code, not vectorized",
        allowed_file_scope: &[
            "src/radix_2_bowers.rs",
            "src/radix_2_dit_parallel.rs",
            "src/radix_2_small_batch.rs",
        ],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-field",
        justification: "SIMD Montgomery field-arithmetic fast paths",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-field-testing",
        justification: "unchecked-precondition field construction (`from_canonical_unchecked`) \
                        in a shared test harness; scalar code, not vectorized",
        allowed_file_scope: &["src/from_integer_tests.rs", "src/lib.rs"],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-matrix",
        justification: "unchecked-bounds matrix indexing and a raw-pointer row swap \
                        (`util.rs`); scalar code, not vectorized",
        allowed_file_scope: &[
            "src/dense.rs",
            "src/extension.rs",
            "src/horizontally_truncated.rs",
            "src/lib.rs",
            "src/row_index_mapped.rs",
            "src/stack.rs",
            "src/util.rs",
        ],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-merkle",
        justification: "unchecked-bounds row access in the leftover (non-batch) tail of \
                        Merkle leaf hashing; this crate's own code is scalar, not vectorized",
        allowed_file_scope: &["src/merkle_tree.rs"],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-mersenne31",
        justification: "SIMD Mersenne31 field fast paths",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-monty31",
        justification: "SIMD Montgomery31 field fast paths",
        allowed_file_scope: &[],
    },
    UnsafeAllowlistEntry {
        crate_name: "lib-q-stark-util",
        justification: "raw-pointer/transmute slice reinterpretation, uninitialized-memory \
                        helpers, and an `asm!` optimizer-barrier; scalar code, not vectorized",
        allowed_file_scope: &["src/lib.rs", "src/transpose.rs"],
    },
];

/// Classical/legacy crypto crate names that are permitted, with the NIST mandate that requires
/// them. Anything else matching [`CLASSICAL_CRYPTO_DENYLIST`] fails the check.
#[cfg(feature = "std")]
const CLASSICAL_CRYPTO_ALLOWLIST: &[(&str, &str)] = &[
    (
        "sha2",
        "NIST-mandated: SLH-DSA (FIPS 205) SHA2 parameter sets and FN-DSA keygen specify SHA-2 \
         directly in their standards",
    ),
    (
        "aes",
        "NIST-mandated: HQC's FIPS-approved AES-256-CTR DRBG, MAYO, and SLH-DSA's SHA2 parameter \
         sets specify AES directly in their standards",
    ),
];

/// Classical/legacy primitive crate names that are never allowed as a dependency.
#[cfg(feature = "std")]
const CLASSICAL_CRYPTO_DENYLIST: &[&str] = &[
    "rsa",
    "md5",
    "md-5", // crates.io package name of the RustCrypto MD5 crate
    "sha1",
    "sha-1", // former crates.io package name of the RustCrypto SHA-1 crate
    "des",
    "3des",
    "rc4",
    "rc2",
    "blowfish",
    "twofish",
    "ring",
    "openssl",
    "ed25519-dalek",
    "curve25519-dalek",
    "x25519-dalek",
    "p256",
    "p384",
    "k256",
    "secp256k1",
    "dsa",
];

/// External SHA-3/Keccak implementations that duplicate the workspace's own audited one.
#[cfg(feature = "std")]
const SHA3_COMPLIANCE_DENYLIST: &[&str] = &["sha3", "tiny-keccak", "tiny_keccak"];

/// Crates whose public API generates, transports, or stores secret key/seed material as their
/// primary function. Each must depend on and actually reference `zeroize`.
#[cfg(feature = "std")]
const KEY_MATERIAL_CRATES: &[&str] = &[
    "lib-q-aead",
    "lib-q-cb-kem",
    "lib-q-dkg",
    "lib-q-duplex-aead",
    "lib-q-hpke",
    "lib-q-hqc",
    "lib-q-k12",
    "lib-q-mac",
    "lib-q-mayo",
    "lib-q-ml-dsa",
    "lib-q-ml-kem",
    "lib-q-prf",
    "lib-q-random",
    "lib-q-ring",
    "lib-q-rocca-s",
    "lib-q-romulus",
    "lib-q-saturnin",
    "lib-q-sig",
    "lib-q-slh-dsa",
    "lib-q-threshold-kem-lattice",
    "lib-q-threshold-raccoon",
    "lib-q-tweak-aead",
    "lib-q-zk-encryption-proof",
];

/// Crates implementing AEAD or MAC tag verification; each must use a constant-time comparison.
#[cfg(feature = "std")]
const AEAD_MAC_CRATES: &[&str] = &[
    "lib-q-mac",
    "lib-q-aead",
    "lib-q-duplex-aead",
    "lib-q-tweak-aead",
    "lib-q-rocca-s",
    "lib-q-romulus",
    "lib-q-saturnin",
    "lib-q-hpke",
];

/// Security validator
pub struct SecurityValidator {
    /// Crate ROOT directories to scan (each expected to contain a `Cargo.toml`, and usually a
    /// `src/`). Populated by [`Self::new`] with every real libQ workspace member; override with
    /// [`Self::with_source_paths`] to point the scanner at a synthetic tree for testing.
    source_paths: Vec<String>,
    exclude_paths: Vec<String>,
}

impl SecurityValidator {
    /// Create a new security validator, scanning the real libQ cargo workspace.
    ///
    /// Discovery is anchored on `CARGO_MANIFEST_DIR` (this crate's own manifest directory,
    /// baked in at compile time), not on the process's current working directory — the
    /// previous default of `source_paths: vec!["src/"]` silently scanned zero files whenever
    /// the binary was run from the workspace root (there is no top-level `src/`), which made
    /// every check trivially "pass" over an empty file set.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            source_paths: Self::discover_workspace_crate_dirs(),
            #[cfg(not(feature = "std"))]
            source_paths: Vec::new(),
            exclude_paths: vec!["target".to_string(), ".git".to_string()],
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

    /// Discover every real workspace member declared in the root `Cargo.toml`'s
    /// `[workspace] members = [...]` list, plus the workspace root itself (its manifest
    /// carries the `[workspace.dependencies]` version pins every member inherits).
    ///
    /// Nested path-only crates that the workspace explicitly excludes (e.g.
    /// `lib-q-fn-dsa/fn-dsa-*`, see the root `Cargo.toml`'s trailing comment) are intentionally
    /// not included: they are not workspace members, so no other workspace-wide tool
    /// (`cargo clippy --workspace`, `cargo test --workspace`, ...) reaches them either.
    #[cfg(feature = "std")]
    fn discover_workspace_crate_dirs() -> Vec<String> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap_or(manifest_dir);

        let mut dirs = vec![workspace_root.to_path_buf()];
        let root_manifest = workspace_root.join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(&root_manifest) {
            for member in Self::parse_workspace_members(&text) {
                let path = workspace_root.join(&member);
                if path.join("Cargo.toml").is_file() {
                    dirs.push(path);
                }
            }
        }

        dirs.sort();
        dirs.dedup();
        dirs.into_iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }

    /// Extract the quoted entries of a TOML `members = [ "a", "b", ... ]` array. Line-based and
    /// deliberately simple (this crate does not depend on a TOML parser); it stops at the first
    /// line containing `]` after the array opens, which matches the root manifest's layout.
    #[cfg(feature = "std")]
    fn parse_workspace_members(toml_text: &str) -> Vec<String> {
        let mut members = Vec::new();
        let mut in_members = false;
        for line in toml_text.lines() {
            let trimmed = line.trim();
            if !in_members {
                if trimmed.starts_with("members") && trimmed.contains('[') {
                    in_members = true;
                } else {
                    continue;
                }
            }
            let content = match trimmed.find('#') {
                Some(idx) => &trimmed[..idx],
                None => trimmed,
            };
            let parts: Vec<&str> = content.split('"').collect();
            let mut i = 1;
            while i < parts.len() {
                if !parts[i].is_empty() {
                    members.push(parts[i].to_string());
                }
                i += 2;
            }
            if content.contains(']') {
                break;
            }
        }
        members
    }

    #[cfg(feature = "std")]
    fn crate_dirs(&self) -> Vec<PathBuf> {
        self.source_paths.iter().map(PathBuf::from).collect()
    }

    #[cfg(feature = "std")]
    fn dir_name(dir: &Path) -> String {
        dir.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Read every `.rs` file under `<dir>/src`, recursively.
    #[cfg(feature = "std")]
    fn rs_files_in(&self, dir: &Path) -> Vec<(PathBuf, String)> {
        let mut out = Vec::new();
        Self::walk_rs(&dir.join("src"), &self.exclude_paths, &mut out);
        out
    }

    #[cfg(feature = "std")]
    fn rs_files(&self) -> Vec<(PathBuf, String)> {
        self.crate_dirs()
            .iter()
            .flat_map(|d| self.rs_files_in(d))
            .collect()
    }

    #[cfg(feature = "std")]
    fn walk_rs(dir: &Path, excludes: &[String], out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy();
            if excludes.iter().any(|ex| path_str.contains(ex.as_str())) {
                continue;
            }
            if path.is_dir() {
                Self::walk_rs(&path, excludes, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let Ok(content) = fs::read_to_string(&path) else {
                    continue;
                };
                let shipped = Self::strip_trailing_test_module(&content).to_string();
                out.push((path, shipped));
            }
        }
    }

    /// Truncate `content` immediately before its trailing `#[cfg(test)]` (or
    /// `#[cfg(all(test, ...))]`) module, by the near-universal Rust/this-repo convention that
    /// test modules sit at the end of the file. This scopes the source-scanning checks
    /// (`unsafe_code_usage`, `random_generation`, `input_validation`, `error_handling`'s
    /// per-line scan is unaffected since it already requires column 0) to *shipped* code, so a
    /// check does not trip over a violation-shaped string literal inside its own test fixtures
    /// (this file's `tests` module intentionally contains strings like `"unsafe { ... }"` and
    /// `"thread_rng()"` to test the checks that look for exactly those). Known limitation: a
    /// file with more than one `#[cfg(test)]` block, or one that isn't last, only has the
    /// portion before the first match scanned.
    #[cfg(feature = "std")]
    fn strip_trailing_test_module(content: &str) -> &str {
        const MARKERS: [&str; 2] = ["\n#[cfg(test)]", "\n#[cfg(all(test"];
        let mut cut = content.len();
        for marker in MARKERS {
            if let Some(idx) = content.find(marker) {
                cut = cut.min(idx);
            }
        }
        &content[..cut]
    }

    /// `security_validation.rs` (this file) and its CLI wrapper are the checker's own
    /// implementation. `check_unsafe_code`/`check_random_generation` search for literal
    /// substrings (`"unsafe"` followed by `fn`/`impl`/`trait`/`extern`/`{`; `"thread_rng()"`;
    /// `"rand::random("`) using free substring matching, and this file's own rule descriptions,
    /// doc comments, and the search patterns themselves necessarily contain those substrings —
    /// without this exclusion the checker would fail on describing what it checks for, which is
    /// exactly the false-positive class RULES.md warns about (the guard-script precedent that
    /// excluded this same file from its own "not implemented" sweep). Every OTHER file in
    /// lib-q-utils — and every file in every other crate — is still scanned normally; this crate
    /// ships no unsafe code and calls neither RNG function anywhere outside this exclusion.
    #[cfg(feature = "std")]
    fn is_checker_implementation_file(path: &Path) -> bool {
        matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("security_validation.rs") | Some("security-validator.rs")
        )
    }

    /// Read every discovered crate's own `Cargo.toml`.
    #[cfg(feature = "std")]
    fn cargo_tomls(&self) -> Vec<(PathBuf, String)> {
        self.crate_dirs()
            .iter()
            .filter_map(|d| {
                let manifest = d.join("Cargo.toml");
                fs::read_to_string(&manifest)
                    .ok()
                    .map(|content| (manifest, content))
            })
            .collect()
    }

    /// `true` if `trimmed_line` opens a TOML key exactly equal to `name` (`name = ...` or
    /// `name.workspace = ...`), not merely containing `name` as a substring elsewhere (e.g. in a
    /// `features = [...]` list, or as a prefix of a longer identifier like `lib-q-ml-dsa`).
    #[cfg(feature = "std")]
    fn is_dependency_decl(trimmed_line: &str, name: &str) -> bool {
        match trimmed_line.strip_prefix(name) {
            Some(rest) => {
                let rest = rest.trim_start();
                rest.starts_with('=') || rest.starts_with('.')
            }
            None => false,
        }
    }

    /// Run all eight security validations
    #[cfg(feature = "std")]
    pub fn validate(&self) -> SecurityValidationReport {
        self.validate_only(&SecurityCheck::ALL)
    }

    /// Run exactly the requested subset of checks. Used by the CLI so that, e.g.,
    /// `validate-memory` actually only runs `memory_zeroization` instead of all eight.
    #[cfg(feature = "std")]
    pub fn validate_only(&self, checks: &[SecurityCheck]) -> SecurityValidationReport {
        let mut report = SecurityValidationReport {
            #[allow(clippy::disallowed_types)]
            results: HashMap::new(),
            summary: SecurityValidationSummary::new(),
        };

        for check in checks {
            let result = match check {
                SecurityCheck::ClassicalCrypto => self.check_classical_crypto(),
                SecurityCheck::Sha3Compliance => self.check_sha3_compliance(),
                SecurityCheck::UnsafeCodeUsage => self.check_unsafe_code(),
                SecurityCheck::MemoryZeroization => self.check_zeroize_usage(),
                SecurityCheck::TimingVulnerabilities => self.check_timing_vulnerabilities(),
                SecurityCheck::ErrorHandling => self.check_error_handling(),
                SecurityCheck::InputValidation => self.check_input_validation(),
                SecurityCheck::RandomGeneration => self.check_random_generation(),
            };
            report.summary.add_result(&result);
            report.results.insert(check.name().to_string(), result);
        }

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

    /// Check for classical cryptographic algorithms (see [`SecurityCheck::ClassicalCrypto::rule`]).
    #[cfg(feature = "std")]
    fn check_classical_crypto(&self) -> SecurityValidationResult {
        let manifests = self.cargo_tomls();
        if manifests.is_empty() {
            return SecurityValidationResult::Fail(
                "classical_crypto_detection scanned 0 Cargo.toml files — cannot certify a \
                 workspace that was never read"
                    .to_string(),
            );
        }

        let mut violations = Vec::new();
        for (path, content) in &manifests {
            for (lineno, line) in content.lines().enumerate() {
                let trimmed = line.trim_start();
                for denied in CLASSICAL_CRYPTO_DENYLIST {
                    if Self::is_dependency_decl(trimmed, denied) {
                        violations.push(format!(
                            "{}:{}: `{}` is a classical/legacy primitive not on the NIST-mandated \
                             allowlist",
                            path.display(),
                            lineno + 1,
                            denied
                        ));
                    }
                }
            }
        }

        if violations.is_empty() {
            SecurityValidationResult::Pass
        } else {
            SecurityValidationResult::Fail(format!(
                "policy: classical crypto deps must be on the allowlist ({}). Violations: {}",
                CLASSICAL_CRYPTO_ALLOWLIST
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", "),
                violations.join("; ")
            ))
        }
    }

    /// Check for SHA-3 family compliance (see [`SecurityCheck::Sha3Compliance::rule`]).
    #[cfg(feature = "std")]
    fn check_sha3_compliance(&self) -> SecurityValidationResult {
        let manifests = self.cargo_tomls();
        if manifests.is_empty() {
            return SecurityValidationResult::Fail(
                "sha3_compliance scanned 0 Cargo.toml files — cannot certify a workspace that \
                 was never read"
                    .to_string(),
            );
        }

        let mut violations = Vec::new();
        for (path, content) in &manifests {
            for (lineno, line) in content.lines().enumerate() {
                let trimmed = line.trim_start();
                for denied in SHA3_COMPLIANCE_DENYLIST {
                    if Self::is_dependency_decl(trimmed, denied) {
                        violations.push(format!(
                            "{}:{}: depends on external `{}` instead of the workspace's own \
                             audited Keccak/SHA-3 implementation",
                            path.display(),
                            lineno + 1,
                            denied
                        ));
                    }
                }
            }
        }

        if violations.is_empty() {
            SecurityValidationResult::Pass
        } else {
            SecurityValidationResult::Fail(violations.join("; "))
        }
    }

    /// Check for unsafe code usage outside the reviewed allowlist (see
    /// [`SecurityCheck::UnsafeCodeUsage::rule`]).
    #[cfg(feature = "std")]
    fn check_unsafe_code(&self) -> SecurityValidationResult {
        let crate_dirs = self.crate_dirs();
        if crate_dirs.is_empty() {
            return SecurityValidationResult::Fail(
                "unsafe_code_usage scanned 0 crate directories — cannot certify a workspace \
                 that was never read"
                    .to_string(),
            );
        }

        let mut total_files = 0usize;
        let mut violations = Vec::new();
        for dir in &crate_dirs {
            let name = Self::dir_name(dir);
            let files = self.rs_files_in(dir);
            total_files += files.len();
            let entry = ALLOWED_UNSAFE_CRATES.iter().find(|e| e.crate_name == name);
            // A whole-crate exemption (empty scope) skips the crate entirely, exactly as
            // before. A *scoped* entry (non-empty `allowed_file_scope`) does NOT skip the
            // crate: every file is still scanned, and real `unsafe` is only permitted inside
            // the reviewed files — anywhere else in that same crate it is a violation, same as
            // if the crate were not on the allowlist at all.
            if entry.is_some_and(|e| e.allowed_file_scope.is_empty()) {
                continue;
            }
            let scope: &[&str] = entry.map(|e| e.allowed_file_scope).unwrap_or(&[]);
            for (path, content) in &files {
                if Self::is_checker_implementation_file(path) {
                    continue;
                }
                if !Self::contains_real_unsafe(content) {
                    continue;
                }
                if Self::path_in_scope(path, scope) {
                    continue;
                }
                let reviewed_elsewhere = entry.map_or(
                    "this crate has no allowlist entry at all".to_string(),
                    |e| format!("its reviewed unsafe here is: {}", e.justification),
                );
                violations.push(format!(
                    "{}: unsafe code in crate `{}` outside its reviewed allowlist file scope \
                     {scope:?} ({reviewed_elsewhere})",
                    path.display(),
                    name
                ));
            }
        }

        if total_files == 0 {
            return SecurityValidationResult::Fail(
                "unsafe_code_usage scanned 0 .rs files — cannot certify a workspace that was \
                 never read"
                    .to_string(),
            );
        }

        if violations.is_empty() {
            SecurityValidationResult::Pass
        } else {
            SecurityValidationResult::Fail(violations.join("; "))
        }
    }

    /// `true` if `path` ends with one of `scope`'s crate-relative file suffixes (e.g.
    /// `"src/mayo_core.rs"`), after normalizing Windows `\` separators to `/` so the same scope
    /// literal matches on every platform this checker runs on. An empty `scope` never matches
    /// anything (callers use an empty scope to mean "no per-file exemption").
    #[cfg(feature = "std")]
    fn path_in_scope(path: &Path, scope: &[&str]) -> bool {
        let normalized = path.to_string_lossy().replace('\\', "/");
        scope.iter().any(|s| normalized.ends_with(s))
    }

    /// `true` if `content` contains a genuine `unsafe` construct (`fn`/`impl`/`trait`/`extern`/
    /// a block), as opposed to a textual mention of the word "unsafe" in a comment, string, or
    /// identifier (e.g. this very module's `check_name = "unsafe_code_usage"`).
    #[cfg(feature = "std")]
    fn contains_real_unsafe(content: &str) -> bool {
        let bytes = content.as_bytes();
        for (i, _) in content.match_indices("unsafe") {
            let before_ok =
                i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let after = &content[i + "unsafe".len()..];
            let after_ok = after
                .chars()
                .next()
                .map(|c| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(true);
            if !before_ok || !after_ok {
                continue;
            }
            let rest = after.trim_start();
            if rest.starts_with("fn") ||
                rest.starts_with("impl") ||
                rest.starts_with("trait") ||
                rest.starts_with("extern") ||
                rest.starts_with('{')
            {
                return true;
            }
        }
        false
    }

    /// Check for memory zeroization of secret key material (see
    /// [`SecurityCheck::MemoryZeroization::rule`]).
    #[cfg(feature = "std")]
    fn check_zeroize_usage(&self) -> SecurityValidationResult {
        let crate_dirs = self.crate_dirs();
        if crate_dirs.is_empty() {
            return SecurityValidationResult::Fail(
                "memory_zeroization scanned 0 crate directories — cannot certify a workspace \
                 that was never read"
                    .to_string(),
            );
        }

        let mut checked = 0usize;
        let mut violations = Vec::new();
        for dir in &crate_dirs {
            let name = Self::dir_name(dir);
            if !KEY_MATERIAL_CRATES.contains(&name.as_str()) {
                continue;
            }
            checked += 1;

            let manifest_path = dir.join("Cargo.toml");
            let manifest = fs::read_to_string(&manifest_path).unwrap_or_default();
            let declares_zeroize = manifest.lines().any(|l| {
                let t = l.trim_start();
                Self::is_dependency_decl(t, "zeroize") && !t.contains("optional = true")
            });
            if !declares_zeroize {
                violations.push(format!(
                    "{}: key-material crate `{}` does not declare a non-optional `zeroize` \
                     dependency",
                    manifest_path.display(),
                    name
                ));
                continue;
            }

            let uses_zeroize = self
                .rs_files_in(dir)
                .iter()
                .any(|(_, content)| content.to_lowercase().contains("zeroize"));
            if !uses_zeroize {
                violations.push(format!(
                    "{}: crate `{}` declares `zeroize` but no source file references it (dead \
                     dependency, not actually zeroizing anything)",
                    dir.display(),
                    name
                ));
            }
        }

        if checked == 0 {
            return SecurityValidationResult::Fail(
                "memory_zeroization matched 0 of its known key-material crates in the scanned \
                 source paths — path discovery is broken or the crate list is stale"
                    .to_string(),
            );
        }

        if violations.is_empty() {
            SecurityValidationResult::Pass
        } else {
            SecurityValidationResult::Fail(violations.join("; "))
        }
    }

    /// Check for constant-time comparison in AEAD/MAC tag verification (see
    /// [`SecurityCheck::TimingVulnerabilities::rule`]).
    #[cfg(feature = "std")]
    fn check_timing_vulnerabilities(&self) -> SecurityValidationResult {
        let crate_dirs = self.crate_dirs();
        if crate_dirs.is_empty() {
            return SecurityValidationResult::Fail(
                "timing_vulnerabilities scanned 0 crate directories — cannot certify a \
                 workspace that was never read"
                    .to_string(),
            );
        }

        let mut checked = 0usize;
        let mut violations = Vec::new();
        for dir in &crate_dirs {
            let name = Self::dir_name(dir);
            if !AEAD_MAC_CRATES.contains(&name.as_str()) {
                continue;
            }
            checked += 1;

            let has_constant_time = self.rs_files_in(dir).iter().any(|(_, content)| {
                content.contains("ct_eq") ||
                    content.contains("ConstantTimeEq") ||
                    content.contains("constant_time_compare") ||
                    content.contains("subtle::")
            });
            if !has_constant_time {
                violations.push(format!(
                    "{}: AEAD/MAC crate `{}` has no constant-time comparison primitive \
                     (ct_eq/ConstantTimeEq/constant_time_compare/subtle) anywhere in its source",
                    dir.display(),
                    name
                ));
            }
        }

        if checked == 0 {
            return SecurityValidationResult::Fail(
                "timing_vulnerabilities matched 0 of its known AEAD/MAC crates in the scanned \
                 source paths — path discovery is broken or the crate list is stale"
                    .to_string(),
            );
        }

        if violations.is_empty() {
            SecurityValidationResult::Pass
        } else {
            SecurityValidationResult::Fail(violations.join("; "))
        }
    }

    /// Check for proper error handling (see [`SecurityCheck::ErrorHandling::rule`]).
    #[cfg(feature = "std")]
    fn check_error_handling(&self) -> SecurityValidationResult {
        let files = self.rs_files();
        if files.is_empty() {
            return SecurityValidationResult::Fail(
                "error_handling scanned 0 .rs files — cannot certify a workspace that was \
                 never read"
                    .to_string(),
            );
        }

        const BANNED: &[&str] = &[
            "#![allow(clippy::unwrap_used)]",
            "#![allow(clippy::expect_used)]",
            "#![allow(clippy::panic)]",
        ];

        let mut violations = Vec::new();
        for (path, content) in &files {
            for (lineno, line) in content.lines().enumerate() {
                if line.starts_with(char::is_whitespace) {
                    // Indented -> scoped to an inner item (e.g. `#[cfg(test)] mod tests { ... }`),
                    // not a whole-file blanket suppression.
                    continue;
                }
                let trimmed_end = line.trim_end();
                if BANNED.iter().any(|b| trimmed_end.starts_with(b)) {
                    violations.push(format!(
                        "{}:{}: whole-file blanket `{}` suppresses an error-handling lint \
                         repo-wide",
                        path.display(),
                        lineno + 1,
                        trimmed_end
                    ));
                }
            }
        }

        if violations.is_empty() {
            SecurityValidationResult::Pass
        } else {
            SecurityValidationResult::Fail(violations.join("; "))
        }
    }

    /// Check for input validation on infallible byte-decoding constructors (see
    /// [`SecurityCheck::InputValidation::rule`]).
    #[cfg(feature = "std")]
    fn check_input_validation(&self) -> SecurityValidationResult {
        let files = self.rs_files();
        if files.is_empty() {
            return SecurityValidationResult::Fail(
                "input_validation scanned 0 .rs files — cannot certify a workspace that was \
                 never read"
                    .to_string(),
            );
        }

        let mut violations = Vec::new();
        for (path, content) in &files {
            for (lineno, line) in content.lines().enumerate() {
                let t = line.trim_start();
                let is_infallible_ctor = t.starts_with("pub fn from_bytes") ||
                    t.starts_with("pub fn decode") ||
                    t.starts_with("pub fn deserialize");
                if !is_infallible_ctor {
                    continue;
                }
                let returns_bare_self = t.contains("-> Self");
                let takes_unchecked_len =
                    t.contains("Vec<u8>") || t.contains("&[u8]") || t.contains("&mut [u8]");
                if returns_bare_self && takes_unchecked_len {
                    violations.push(format!(
                        "{}:{}: infallible constructor from unchecked variable-length input: `{}`",
                        path.display(),
                        lineno + 1,
                        t.trim()
                    ));
                }
            }
        }

        if violations.is_empty() {
            SecurityValidationResult::Pass
        } else {
            SecurityValidationResult::Fail(violations.join("; "))
        }
    }

    /// Check for weak random number generation sources (see
    /// [`SecurityCheck::RandomGeneration::rule`]).
    #[cfg(feature = "std")]
    fn check_random_generation(&self) -> SecurityValidationResult {
        let files = self.rs_files();
        if files.is_empty() {
            return SecurityValidationResult::Fail(
                "random_generation scanned 0 .rs files — cannot certify a workspace that was \
                 never read"
                    .to_string(),
            );
        }

        let mut violations = Vec::new();
        for (path, content) in &files {
            if Self::is_checker_implementation_file(path) {
                continue;
            }
            for (lineno, line) in content.lines().enumerate() {
                if line.contains("thread_rng()") || line.contains("rand::random(") {
                    violations.push(format!(
                        "{}:{}: uses a non-workspace-vetted RNG source directly in library \
                         source",
                        path.display(),
                        lineno + 1
                    ));
                }
            }
        }

        if violations.is_empty() {
            SecurityValidationResult::Pass
        } else {
            SecurityValidationResult::Fail(violations.join("; "))
        }
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

    let mut names: Vec<&String> = report.results.keys().collect();
    names.sort();
    for check_name in names {
        let result = &report.results[check_name];
        let rule = SecurityCheck::ALL
            .iter()
            .find(|c| c.name() == check_name.as_str())
            .map(|c| c.rule())
            .unwrap_or("(no rule text registered)");
        println!("    policy: {}", rule);
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::sync::atomic::{
        AtomicU64,
        Ordering,
    };

    use super::*;

    /// A throwaway directory tree under `std::env::temp_dir()`, removed on drop, used to give
    /// each check a synthetic crate tree so its red/green behaviour can be tested without
    /// touching any real crate in this repo.
    struct TempWorkspace {
        root: PathBuf,
    }

    impl TempWorkspace {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let root = std::env::temp_dir().join(format!("lib-q-utils-secval-test-{pid}-{n}"));
            fs::create_dir_all(&root).expect("create temp workspace root");
            Self { root }
        }

        /// Create `<root>/<crate_name>/{Cargo.toml, src/lib.rs}` and return its path.
        fn crate_dir(&self, crate_name: &str, cargo_toml: &str, lib_rs: &str) -> PathBuf {
            let dir = self.root.join(crate_name);
            let src = dir.join("src");
            fs::create_dir_all(&src).expect("create crate src dir");
            fs::write(dir.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");
            fs::write(src.join("lib.rs"), lib_rs).expect("write lib.rs");
            dir
        }

        fn path_string(&self, dir: &Path) -> String {
            let _ = &self.root;
            dir.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    // ---- foundational fixes -------------------------------------------------------------

    #[test]
    fn is_success_requires_every_check_to_pass_not_just_zero_failures() {
        let mut summary = SecurityValidationSummary::new();
        summary.add_result(&SecurityValidationResult::Pass);
        summary.add_result(&SecurityValidationResult::Warning("w".to_string()));
        // failed == 0 here, but is_success must still be false: a warning is not a pass.
        assert_eq!(summary.failed, 0);
        assert!(!summary.is_success(), "a Warning must not count as success");
    }

    #[test]
    fn is_success_is_false_on_zero_checks() {
        let summary = SecurityValidationSummary::new();
        assert_eq!(summary.total_checks, 0);
        assert!(
            !summary.is_success(),
            "a report of zero performed checks must never be 'success'"
        );
    }

    #[test]
    fn is_success_true_only_when_all_passed() {
        let mut summary = SecurityValidationSummary::new();
        summary.add_result(&SecurityValidationResult::Pass);
        summary.add_result(&SecurityValidationResult::Pass);
        assert!(summary.is_success());
    }

    #[test]
    fn scanning_zero_files_is_a_hard_failure_not_a_pass() {
        let ws = TempWorkspace::new();
        // An empty directory: no crates, no Cargo.toml, no .rs files.
        let empty = ws.root.join("empty");
        fs::create_dir_all(&empty).unwrap();
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&empty)]);
        for check in SecurityCheck::ALL {
            let report = validator.validate_only(&[check]);
            let result = &report.results[check.name()];
            assert!(
                matches!(result, SecurityValidationResult::Fail(_)),
                "{:?} scanned zero files and must Fail, got {:?}",
                check,
                result
            );
        }
    }

    // ---- classical_crypto_detection ------------------------------------------------------

    #[test]
    fn classical_crypto_detection_fails_on_denylisted_dependency_then_passes_once_removed() {
        let ws = TempWorkspace::new();
        let bad = ws.crate_dir(
            "lib-q-fake",
            "[package]\nname = \"lib-q-fake\"\n[dependencies]\nmd5 = \"0.7\"\n",
            "pub fn f() {}\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&bad)]);
        let report = validator.validate_only(&[SecurityCheck::ClassicalCrypto]);
        assert!(
            matches!(
                report.results[SecurityCheck::ClassicalCrypto.name()],
                SecurityValidationResult::Fail(_)
            ),
            "planted `md5` dependency must be rejected"
        );

        // Remove the violation: rewrite the manifest without it.
        fs::write(
            bad.join("Cargo.toml"),
            "[package]\nname = \"lib-q-fake\"\n[dependencies]\n",
        )
        .unwrap();
        let report = validator.validate_only(&[SecurityCheck::ClassicalCrypto]);
        assert_eq!(
            report.results[SecurityCheck::ClassicalCrypto.name()],
            SecurityValidationResult::Pass
        );
    }

    #[test]
    fn classical_crypto_detection_allows_nist_mandated_sha2_and_aes() {
        let ws = TempWorkspace::new();
        let ok = ws.crate_dir(
            "lib-q-fake-ok",
            "[package]\nname = \"lib-q-fake-ok\"\n[dependencies]\nsha2 = \"0.11\"\naes = \"0.9\"\n",
            "pub fn f() {}\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&ok)]);
        let report = validator.validate_only(&[SecurityCheck::ClassicalCrypto]);
        assert_eq!(
            report.results[SecurityCheck::ClassicalCrypto.name()],
            SecurityValidationResult::Pass
        );
    }

    // ---- sha3_compliance -------------------------------------------------------------------

    #[test]
    fn sha3_compliance_fails_on_external_sha3_dependency_then_passes_once_removed() {
        let ws = TempWorkspace::new();
        let bad = ws.crate_dir(
            "lib-q-fake",
            "[package]\nname = \"lib-q-fake\"\n[dependencies]\nsha3 = \"0.10\"\n",
            "pub fn f() {}\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&bad)]);
        let report = validator.validate_only(&[SecurityCheck::Sha3Compliance]);
        assert!(matches!(
            report.results[SecurityCheck::Sha3Compliance.name()],
            SecurityValidationResult::Fail(_)
        ));

        fs::write(
            bad.join("Cargo.toml"),
            "[package]\nname = \"lib-q-fake\"\n[dependencies]\n",
        )
        .unwrap();
        let report = validator.validate_only(&[SecurityCheck::Sha3Compliance]);
        assert_eq!(
            report.results[SecurityCheck::Sha3Compliance.name()],
            SecurityValidationResult::Pass
        );
    }

    // ---- unsafe_code_usage -----------------------------------------------------------------

    #[test]
    fn unsafe_code_usage_fails_outside_allowlist_then_passes_once_removed() {
        let ws = TempWorkspace::new();
        let bad = ws.crate_dir(
            "lib-q-totally-not-allowlisted",
            "[package]\nname = \"x\"\n",
            "pub fn f() { unsafe { core::ptr::null::<u8>(); } }\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&bad)]);
        let report = validator.validate_only(&[SecurityCheck::UnsafeCodeUsage]);
        assert!(matches!(
            report.results[SecurityCheck::UnsafeCodeUsage.name()],
            SecurityValidationResult::Fail(_)
        ));

        fs::write(bad.join("src").join("lib.rs"), "pub fn f() {}\n").unwrap();
        let report = validator.validate_only(&[SecurityCheck::UnsafeCodeUsage]);
        assert_eq!(
            report.results[SecurityCheck::UnsafeCodeUsage.name()],
            SecurityValidationResult::Pass
        );
    }

    #[test]
    fn unsafe_code_usage_allows_reviewed_allowlisted_crate() {
        let ws = TempWorkspace::new();
        // lib-q-intrinsics is on the allowlist.
        let ok = ws.crate_dir(
            "lib-q-intrinsics",
            "[package]\nname = \"lib-q-intrinsics\"\n",
            "pub fn f() { unsafe { core::ptr::null::<u8>(); } }\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&ok)]);
        let report = validator.validate_only(&[SecurityCheck::UnsafeCodeUsage]);
        assert_eq!(
            report.results[SecurityCheck::UnsafeCodeUsage.name()],
            SecurityValidationResult::Pass
        );
    }

    #[test]
    fn unsafe_code_usage_ignores_textual_mentions_of_the_word_unsafe() {
        let ws = TempWorkspace::new();
        let dir = ws.crate_dir(
            "lib-q-totally-not-allowlisted",
            "[package]\nname = \"x\"\n",
            "// this crate must never use unsafe code\nlet check_name = \"unsafe_code_usage\";\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::UnsafeCodeUsage]);
        assert_eq!(
            report.results[SecurityCheck::UnsafeCodeUsage.name()],
            SecurityValidationResult::Pass,
            "a comment/string mentioning the word 'unsafe' must not trip the scanner"
        );
    }

    // ---- memory_zeroization ----------------------------------------------------------------

    #[test]
    fn memory_zeroization_fails_when_dependency_missing_then_passes_once_added_and_used() {
        let ws = TempWorkspace::new();
        let dir = ws.crate_dir(
            "lib-q-mac",
            "[package]\nname = \"lib-q-mac\"\n[dependencies]\n",
            "pub struct Key([u8; 32]);\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::MemoryZeroization]);
        assert!(matches!(
            report.results[SecurityCheck::MemoryZeroization.name()],
            SecurityValidationResult::Fail(_)
        ));

        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"lib-q-mac\"\n[dependencies]\nzeroize = \"1\"\n",
        )
        .unwrap();
        // Declared but unused — still must fail.
        let report = validator.validate_only(&[SecurityCheck::MemoryZeroization]);
        assert!(matches!(
            report.results[SecurityCheck::MemoryZeroization.name()],
            SecurityValidationResult::Fail(_)
        ));

        fs::write(
            dir.join("src").join("lib.rs"),
            "use zeroize::Zeroize;\npub struct Key([u8; 32]);\nimpl Drop for Key { fn drop(&mut self) { self.0.zeroize(); } }\n",
        )
        .unwrap();
        let report = validator.validate_only(&[SecurityCheck::MemoryZeroization]);
        assert_eq!(
            report.results[SecurityCheck::MemoryZeroization.name()],
            SecurityValidationResult::Pass
        );
    }

    #[test]
    fn memory_zeroization_skips_crates_not_on_the_key_material_list() {
        let ws = TempWorkspace::new();
        // Not in KEY_MATERIAL_CRATES: nothing to check, "checked == 0" -> Fail (guard fires),
        // which correctly signals "this scan proved nothing" rather than a silent pass.
        let dir = ws.crate_dir(
            "lib-q-not-a-key-material-crate",
            "[package]\nname = \"x\"\n",
            "pub fn f() {}\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::MemoryZeroization]);
        assert!(matches!(
            report.results[SecurityCheck::MemoryZeroization.name()],
            SecurityValidationResult::Fail(_)
        ));
    }

    // ---- timing_vulnerabilities ------------------------------------------------------------

    #[test]
    fn timing_vulnerabilities_fails_without_constant_time_compare_then_passes_with_it() {
        let ws = TempWorkspace::new();
        let dir = ws.crate_dir(
            "lib-q-mac",
            "[package]\nname = \"lib-q-mac\"\n",
            "pub fn verify(a: &[u8], b: &[u8]) -> bool { a == b }\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::TimingVulnerabilities]);
        assert!(matches!(
            report.results[SecurityCheck::TimingVulnerabilities.name()],
            SecurityValidationResult::Fail(_)
        ));

        fs::write(
            dir.join("src").join("lib.rs"),
            "pub fn verify(a: &[u8], b: &[u8]) -> bool { lib_q_utils::constant_time_compare(a, b) }\n",
        )
        .unwrap();
        let report = validator.validate_only(&[SecurityCheck::TimingVulnerabilities]);
        assert_eq!(
            report.results[SecurityCheck::TimingVulnerabilities.name()],
            SecurityValidationResult::Pass
        );
    }

    // ---- error_handling --------------------------------------------------------------------

    #[test]
    fn error_handling_fails_on_column_zero_blanket_allow_then_passes_once_scoped() {
        let ws = TempWorkspace::new();
        let dir = ws.crate_dir(
            "lib-q-fake",
            "[package]\nname = \"x\"\n",
            "#![allow(clippy::unwrap_used)]\npub fn f() {}\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::ErrorHandling]);
        assert!(matches!(
            report.results[SecurityCheck::ErrorHandling.name()],
            SecurityValidationResult::Fail(_)
        ));

        // Scoping the same allow to a test module (indented) is fine.
        fs::write(
            dir.join("src").join("lib.rs"),
            "pub fn f() {}\n#[cfg(test)]\nmod tests {\n    #![allow(clippy::unwrap_used)]\n}\n",
        )
        .unwrap();
        let report = validator.validate_only(&[SecurityCheck::ErrorHandling]);
        assert_eq!(
            report.results[SecurityCheck::ErrorHandling.name()],
            SecurityValidationResult::Pass
        );
    }

    // ---- input_validation ------------------------------------------------------------------

    #[test]
    fn input_validation_fails_on_infallible_vec_constructor_then_passes_with_result() {
        let ws = TempWorkspace::new();
        let dir = ws.crate_dir(
            "lib-q-fake",
            "[package]\nname = \"x\"\n",
            "pub struct K(Vec<u8>);\nimpl K {\n    pub fn from_bytes(bytes: Vec<u8>) -> Self { Self(bytes) }\n}\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::InputValidation]);
        assert!(matches!(
            report.results[SecurityCheck::InputValidation.name()],
            SecurityValidationResult::Fail(_)
        ));

        fs::write(
            dir.join("src").join("lib.rs"),
            "pub struct K(Vec<u8>);\nimpl K {\n    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ()> { Ok(Self(bytes)) }\n}\n",
        )
        .unwrap();
        let report = validator.validate_only(&[SecurityCheck::InputValidation]);
        assert_eq!(
            report.results[SecurityCheck::InputValidation.name()],
            SecurityValidationResult::Pass
        );
    }

    #[test]
    fn input_validation_allows_fixed_size_array_constructor() {
        let ws = TempWorkspace::new();
        let dir = ws.crate_dir(
            "lib-q-fake",
            "[package]\nname = \"x\"\n",
            "pub struct K([u8; 32]);\nimpl K {\n    pub fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }\n}\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::InputValidation]);
        assert_eq!(
            report.results[SecurityCheck::InputValidation.name()],
            SecurityValidationResult::Pass,
            "a fixed-size array parameter is type-checked by the compiler; no runtime check needed"
        );
    }

    // ---- random_generation -----------------------------------------------------------------

    #[test]
    fn random_generation_fails_on_thread_rng_then_passes_once_removed() {
        let ws = TempWorkspace::new();
        let dir = ws.crate_dir(
            "lib-q-fake",
            "[package]\nname = \"x\"\n",
            "pub fn key() -> u64 { rand::thread_rng().gen() }\n",
        );
        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::RandomGeneration]);
        assert!(matches!(
            report.results[SecurityCheck::RandomGeneration.name()],
            SecurityValidationResult::Fail(_)
        ));

        fs::write(
            dir.join("src").join("lib.rs"),
            "pub fn key() -> u64 { lib_q_random::os_rng() }\n",
        )
        .unwrap();
        let report = validator.validate_only(&[SecurityCheck::RandomGeneration]);
        assert_eq!(
            report.results[SecurityCheck::RandomGeneration.name()],
            SecurityValidationResult::Pass
        );
    }

    // ---- allowlist audit (2026-08): justification-vs-contents + scope enforcement ---------

    /// Substrings that make an allowlist justification an *arch-dispatch* claim (SIMD, AES-NI,
    /// AVX2, ARMv8/NEON, "intrinsics"). Case-insensitive.
    const SIMD_JUSTIFICATION_TERMS: [&str; 6] =
        ["simd", "avx", "aes-ni", "armv8", "neon", "intrinsics"];

    /// Literal markers that indicate real arch-conditional dispatch code somewhere in a crate's
    /// shipped source (as opposed to a comment merely using the word "SIMD").
    fn has_arch_dispatch_marker(content: &str) -> bool {
        content.contains("core::arch") ||
            content.contains("std::arch") ||
            content.contains("target_feature") ||
            content.contains("is_x86_feature_detected") ||
            content.contains("is_aarch64_feature_detected")
    }

    /// Mechanical check: any allowlist entry whose justification claims SIMD/AVX/AES-NI/ARMv8/
    /// NEON/intrinsics must be backed by an actual arch-dispatch marker somewhere in that
    /// crate's real `src/` on disk. This is deliberately run against the *real* workspace (not a
    /// synthetic fixture) — it is exactly the mechanism that should have caught the 2026-08
    /// allowlist audit's fabricated-SIMD entries (`lib-q-mayo` claimed "AVX2 matrix/vector
    /// arithmetic" while shipping zero SIMD) before they ever landed.
    #[test]
    fn allowlist_simd_justifications_have_a_matching_arch_dispatch_marker() {
        let validator = SecurityValidator::new();
        let dirs = validator.crate_dirs();

        let mut failing: Vec<&str> = Vec::new();
        for entry in ALLOWED_UNSAFE_CRATES {
            let lower = entry.justification.to_lowercase();
            let claims_simd = SIMD_JUSTIFICATION_TERMS.iter().any(|t| lower.contains(t));
            if !claims_simd {
                continue;
            }
            let dir = dirs
                .iter()
                .find(|d| SecurityValidator::dir_name(d) == entry.crate_name);
            let has_marker = match dir {
                Some(dir) => validator
                    .rs_files_in(dir)
                    .iter()
                    .any(|(_, content)| has_arch_dispatch_marker(content)),
                None => false,
            };
            if !has_marker {
                failing.push(entry.crate_name);
            }
        }

        assert!(
            failing.is_empty(),
            "allowlist entries claim a SIMD/AVX/AES-NI/ARMv8/NEON/intrinsics justification but \
             their crate's src/ has no arch-dispatch marker anywhere (core::arch / std::arch / \
             target_feature / is_{{x86,aarch64}}_feature_detected): {failing:?}"
        );
    }

    /// A crate on the allowlist with a *non-empty* `allowed_file_scope` must not get a
    /// whole-crate bypass: real `unsafe` planted in a file outside that scope must still fail.
    /// Run BEFORE `check_unsafe_code` had scope enforcement, this fails (the crate is skipped
    /// wholesale on name match alone) — that Pass-when-it-should-Fail is exactly the defect
    /// class this test exists to close.
    #[test]
    fn unsafe_code_usage_denies_unsafe_outside_an_allowlisted_crates_reviewed_scope() {
        let ws = TempWorkspace::new();
        // "lib-q-mayo" matches a real allowlist entry name (scope = ["src/mayo_core.rs"]).
        // Plant real unsafe in a *different* file inside that same crate name.
        let dir = ws.crate_dir(
            "lib-q-mayo",
            "[package]\nname = \"lib-q-mayo\"\n",
            "pub fn f() {}\n",
        );
        fs::write(
            dir.join("src").join("unrelated.rs"),
            "pub fn g() { unsafe { core::ptr::null::<u8>(); } }\n",
        )
        .expect("write unrelated.rs");

        let validator = SecurityValidator::new().with_source_paths(vec![ws.path_string(&dir)]);
        let report = validator.validate_only(&[SecurityCheck::UnsafeCodeUsage]);
        assert!(
            matches!(
                report.results[SecurityCheck::UnsafeCodeUsage.name()],
                SecurityValidationResult::Fail(_)
            ),
            "unsafe planted outside lib-q-mayo's reviewed file scope (src/mayo_core.rs) must \
             fail the check, not be silently skipped because the crate NAME matches an \
             allowlist entry"
        );
    }

    /// Pins the exact set of crates that get a *whole-crate* unsafe-scan exemption (empty
    /// `allowed_file_scope`). A silent new whole-crate exemption — the same failure mode as the
    /// fabricated `lib-q-mayo` entry, just via an empty scope instead of a wrong justification —
    /// must show up here as a test diff, not slip in unnoticed.
    #[test]
    fn empty_scope_entries_are_exactly_the_reviewed_simd_set() {
        let mut whole_crate: Vec<&str> = ALLOWED_UNSAFE_CRATES
            .iter()
            .filter(|e| e.allowed_file_scope.is_empty())
            .map(|e| e.crate_name)
            .collect();
        whole_crate.sort_unstable();

        let mut expected = vec![
            "lib-q-hqc",
            "lib-q-intrinsics",
            "lib-q-keccak",
            "lib-q-ml-dsa",
            "lib-q-rocca-s",
            "lib-q-saturnin",
            "lib-q-stark-field",
            "lib-q-stark-mersenne31",
            "lib-q-stark-monty31",
            "lib-q-tweak-aead",
        ];
        expected.sort_unstable();

        assert_eq!(
            whole_crate, expected,
            "the set of crates with a whole-crate unsafe-scan exemption changed; each of these \
             10 was independently re-verified (2026-08 audit) to ship real arch-dispatch SIMD \
             across many files — any addition/removal must be a deliberate, reviewed edit to \
             this test, not a silent table change"
        );
    }

    /// Every scoped file listed in the allowlist must still exist and still contain real
    /// `unsafe` — a scope entry that has gone stale (file deleted, or the unsafe removed) is
    /// dead weight that should be noticed, not silently carried forward forever.
    #[test]
    fn scoped_allowlist_files_exist_and_still_contain_real_unsafe() {
        let validator = SecurityValidator::new();
        let dirs = validator.crate_dirs();
        let mut stale: Vec<String> = Vec::new();

        for entry in ALLOWED_UNSAFE_CRATES {
            if entry.allowed_file_scope.is_empty() {
                continue;
            }
            let Some(dir) = dirs
                .iter()
                .find(|d| SecurityValidator::dir_name(d) == entry.crate_name)
            else {
                stale.push(format!("{}: crate directory not found", entry.crate_name));
                continue;
            };
            let files = validator.rs_files_in(dir);
            for scoped in entry.allowed_file_scope {
                let found = files
                    .iter()
                    .find(|(path, _)| path.to_string_lossy().replace('\\', "/").ends_with(scoped));
                match found {
                    None => stale.push(format!(
                        "{}: scoped file `{}` does not exist under src/",
                        entry.crate_name, scoped
                    )),
                    Some((_, content)) => {
                        if !SecurityValidator::contains_real_unsafe(content) {
                            stale.push(format!(
                                "{}: scoped file `{}` no longer contains real unsafe code — \
                                 scope entry is stale",
                                entry.crate_name, scoped
                            ));
                        }
                    }
                }
            }
        }

        assert!(stale.is_empty(), "stale allowlist file scopes: {stale:?}");
    }

    // ---- live-repo smoke test (real workspace, not a fixture) -------------------------------

    #[test]
    fn default_validator_discovers_a_real_multi_crate_workspace() {
        let validator = SecurityValidator::new();
        // The real libQ workspace has 80+ members; this is a coarse sanity bound, not a
        // brittle exact count.
        assert!(
            validator.source_paths.len() > 10,
            "expected real workspace discovery to find many crate dirs, found {}",
            validator.source_paths.len()
        );
    }

    #[test]
    fn print_report_all_result_kinds_does_not_panic() {
        #[allow(clippy::disallowed_types)]
        let mut results = HashMap::new();
        results.insert("a".to_string(), SecurityValidationResult::Pass);
        results.insert(
            "classical_crypto_detection".to_string(),
            SecurityValidationResult::Fail("boom".into()),
        );
        results.insert(
            "c".to_string(),
            SecurityValidationResult::Warning("w".into()),
        );
        let mut summary = SecurityValidationSummary::new();
        for r in results.values() {
            summary.add_result(r);
        }
        let report = SecurityValidationReport { results, summary };
        print_report(&report);
    }
}
