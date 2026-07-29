//! Guard: every FN-DSA crate that declares `shake256x4` must forward it to the dependency
//! that *defines* the gated type.
//!
//! WHY THIS EXISTS
//!
//! `fn_dsa_comm::shake::SHAKE256x4` — the PRNG that `-kgen` and `-sign` switch to under
//! `--features shake256x4` — is itself `#[cfg(feature = "shake256x4")]` inside `-comm`.
//! `-kgen` and `-sign` declared the feature as an empty list (`shake256x4 = []`), exactly as
//! upstream fn-dsa 0.3.0 does, so enabling it flipped their own call sites onto a type that
//! was never compiled:
//!
//! ```text
//! $ cargo check -p lib-q-fn-dsa-kgen --features shake256x4
//! error[E0433]: cannot find `SHAKE256x4` in `shake`
//!    --> lib-q-fn-dsa/fn-dsa-kgen/src/lib.rs:328:26
//!    note: found an item that was configured out
//!       --> lib-q-fn-dsa/fn-dsa-comm/src/shake.rs:809:12
//! ```
//!
//! Nothing caught it because feature coverage in CI is workspace-wide (`--all-features`):
//! there, the `lib-q-fn-dsa` facade — which *does* forward — turns the flag on for `-comm`,
//! feature unification hands that same `-comm` build to `-kgen`/`-sign`, and the missing
//! forward becomes invisible. Only per-crate selection (`-p <leaf> --features shake256x4`,
//! or `-p <leaf> --all-features`) exposes it, and no CI row did that.
//!
//! This test reads the manifests as data, so it fails on the broken wiring *without* having
//! to build the broken configuration — a plain `cargo test -p lib-q-fn-dsa-kgen` catches it.
//! The compile-level counterpart (`cargo check -p <leaf> --features shake256x4`) lives in
//! `.github/actions/test-fn-dsa/action.yml`.
//!
//! WHAT THIS TEST DOES AND DOES NOT ESTABLISH
//!
//! It resolves feature entries the way cargo does — transitively within each manifest, since a
//! bare entry names another feature of the *same* crate — and asserts that the forward is
//! reachable from `shake256x4`. Indirect wiring (`shake256x4 = ["_x"]`, `_x = ["dep/x4"]`) is
//! therefore accepted, because cargo accepts it. It runs no compiler, so it must never claim a
//! build outcome: on failure it reports the resolved entry set it actually inspected and names
//! the compile check it did *not* perform. A guard that misstates why it failed gets disabled.
//!
//! SCOPE: deliberately limited to `shake256x4`. `no_avx2` has the same missing forward in
//! `-kgen`/`-sign`/`-vrfy`, but it gates only internal dispatch, not a cross-crate item, so
//! it builds today; adding the forward there would change which SHAKE code path existing
//! builds select and is tracked separately.

use std::collections::BTreeSet;
use std::fs;
use std::path::{
    Path,
    PathBuf,
};

/// The feature under guard.
const FEATURE: &str = "shake256x4";

/// Pairs (`dependent`, `dependency`) that MUST be evaluated by this test. If a manifest is
/// reshaped so the parser stops seeing them, the test fails as loudly as a real regression
/// instead of silently passing on an empty set.
const REQUIRED_PAIRS: [(&str, &str); 6] = [
    ("lib-q-fn-dsa-kgen", "lib-q-fn-dsa-comm"),
    ("lib-q-fn-dsa-sign", "lib-q-fn-dsa-comm"),
    ("lib-q-fn-dsa-alg", "lib-q-fn-dsa-comm"),
    ("lib-q-fn-dsa-alg", "lib-q-fn-dsa-kgen"),
    ("lib-q-fn-dsa-alg", "lib-q-fn-dsa-sign"),
    // The outermost link: `lib-q-fn-dsa` (the published facade) -> `-alg`. Every crate named
    // in the `cargo check -p <crate> --features shake256x4` sweep is now pinned here.
    ("lib-q-fn-dsa", "lib-q-fn-dsa-alg"),
];

#[derive(Debug, Default)]
struct Manifest {
    name: String,
    dir: PathBuf,
    /// (dependency key as written in the manifest, resolved directory) for path deps only.
    path_deps: Vec<(String, PathBuf)>,
    /// (feature name, the list it enables)
    features: Vec<(String, Vec<String>)>,
}

impl Manifest {
    fn feature(&self, name: &str) -> Option<&[String]> {
        self.features
            .iter()
            .find(|(f, _)| f == name)
            .map(|(_, v)| v.as_slice())
    }
}

#[test]
fn shake256x4_is_forwarded_to_the_crate_that_defines_it() {
    let mut problems: Vec<String> = Vec::new();

    // `.../lib-q-fn-dsa/fn-dsa-kgen` -> `.../lib-q-fn-dsa`
    let kgen_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let family_root = match kgen_dir.parent() {
        Some(p) => p.to_path_buf(),
        None => {
            problems.push(format!("no parent directory for {}", kgen_dir.display()));
            PathBuf::new()
        }
    };

    let manifests = collect_manifests(&family_root, &mut problems);

    let mut evaluated: BTreeSet<(String, String)> = BTreeSet::new();
    for m in &manifests {
        let Some(enabled) = resolve_feature(m, FEATURE) else {
            continue;
        };
        for (dep_key, dep_dir) in &m.path_deps {
            let Some(dep) = manifests.iter().find(|d| same_dir(&d.dir, dep_dir)) else {
                continue;
            };
            if dep.feature(FEATURE).is_none() {
                continue; // dependency does not gate anything on this feature
            }
            evaluated.insert((m.name.clone(), dep.name.clone()));

            // Cargo's two spellings: unconditional and "only if the optional dep is enabled".
            let want = format!("{dep_key}/{FEATURE}");
            let want_weak = format!("{dep_key}?/{FEATURE}");
            if !enabled.contains(&want) && !enabled.contains(&want_weak) {
                // Register discipline: state only what was inspected. No compiler ran here,
                // so this must not predict a build outcome — see the module header.
                problems.push(format!(
                    "{dependent}: `{FEATURE}` does not forward to `{dep_name}`.\n      \
                     Checked: the entries reachable from `{FEATURE}` in {manifest} — direct \
                     entries plus the same-crate features they enable, resolved transitively \
                     — are {enabled:?}; none of them is `{want}` or `{want_weak}`.\n      \
                     NOT checked: whether anything compiles. This test runs no build; the \
                     `cargo check -p {dependent} --features {FEATURE}` counterpart lives in \
                     .github/actions/test-fn-dsa/action.yml.\n      \
                     Why the forward is required: `{dep_name}` declares `{FEATURE}` and gates \
                     items on it, so `--features {FEATURE}` on `{dependent}` alone turns on \
                     this crate's own `#[cfg(feature = \"{FEATURE}\")]` code while `{dep_name}` \
                     is still built without the feature — anything that code reaches for \
                     behind that gate is configured out (E0433/E0425).\n      \
                     Fix: add \"{want}\" to `{FEATURE}`, or to a feature `{FEATURE}` enables, \
                     in {manifest}.",
                    dependent = m.name,
                    dep_name = dep.name,
                    manifest = m.dir.join("Cargo.toml").display(),
                ));
            }
        }
    }

    for (dependent, dependency) in REQUIRED_PAIRS {
        let pair = (dependent.to_string(), dependency.to_string());
        if !evaluated.contains(&pair) {
            problems.push(format!(
                "guard is not wired up: expected to check that `{dependent}` forwards \
                 `{FEATURE}` to `{dependency}`, but that pair was never evaluated \
                 (manifest not found, feature no longer declared, or the parser did not \
                 recognise the manifest layout). Evaluated pairs: {evaluated:?}"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "`{FEATURE}` feature wiring is broken:\n  - {}",
        problems.join("\n  - ")
    );
}

/// Everything `--features <feature>` turns on for this crate, resolved the way cargo resolves
/// it: an entry with no `/` and no `dep:` prefix names ANOTHER feature of the SAME crate, which
/// cargo expands in turn. So `shake256x4 = ["_x"]` + `_x = ["lib-q-fn-dsa-comm/shake256x4"]`
/// forwards exactly as the directly-written form does, and a guard that inspected only direct
/// entries would report that manifest as broken when `cargo check` proves it is not.
///
/// Entries naming another crate (`dep/feat`, `dep?/feat`) or an optional dependency (`dep:name`)
/// are collected but not followed — they are not features of this crate. `seen` makes a cyclic
/// or self-referential manifest terminate rather than hang; cargo rejects feature cycles itself,
/// so diagnosing one is not this guard's job.
///
/// `None` when the crate does not declare `feature` at all.
fn resolve_feature(m: &Manifest, feature: &str) -> Option<BTreeSet<String>> {
    let direct = m.feature(feature)?;

    let mut enabled = BTreeSet::new();
    let mut seen: BTreeSet<String> = BTreeSet::from([feature.to_string()]);
    let mut queue: Vec<String> = direct.to_vec();

    while let Some(entry) = queue.pop() {
        if entry.contains('/') || entry.starts_with("dep:") {
            enabled.insert(entry);
            continue;
        }
        if !seen.insert(entry.clone()) {
            continue;
        }
        if let Some(next) = m.feature(&entry) {
            queue.extend(next.iter().cloned());
        }
        enabled.insert(entry);
    }
    Some(enabled)
}

/// Read `<root>/Cargo.toml` plus every `<root>/*/Cargo.toml`.
fn collect_manifests(root: &Path, problems: &mut Vec<String>) -> Vec<Manifest> {
    let mut out = Vec::new();
    let mut dirs = vec![root.to_path_buf()];

    match fs::read_dir(root) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() && p.join("Cargo.toml").is_file() {
                    dirs.push(p);
                }
            }
        }
        Err(e) => problems.push(format!("cannot list {}: {e}", root.display())),
    }

    for dir in dirs {
        let manifest_path = dir.join("Cargo.toml");
        match fs::read_to_string(&manifest_path) {
            Ok(text) => out.push(parse_manifest(&dir, &text)),
            Err(e) => problems.push(format!("cannot read {}: {e}", manifest_path.display())),
        }
    }
    out
}

fn parse_manifest(dir: &Path, text: &str) -> Manifest {
    let mut m = Manifest {
        dir: dir.to_path_buf(),
        ..Manifest::default()
    };
    let mut section = String::new();
    let mut features_src = String::new();

    for raw in text.lines() {
        let line = strip_comment(raw).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_string();
            continue;
        }
        if section == "package" && line.starts_with("name") {
            if let Some(v) = quoted_after(&line, "name") {
                m.name = v;
            }
        } else if is_dependency_section(&section) {
            if let (Some(key), Some(rel)) = (key_of(&line), quoted_after(&line, "path")) {
                m.path_deps.push((key, dir.join(rel)));
            }
        } else if section == "features" {
            features_src.push_str(&line);
            features_src.push('\n');
        }
    }
    m.features = parse_features(&features_src);
    m
}

/// `[dependencies]`, `[build-dependencies]`, `[target.'cfg(..)'.dependencies]` — but not
/// dev-dependencies, which cannot carry feature forwarding for downstream builds.
fn is_dependency_section(section: &str) -> bool {
    section.ends_with("dependencies") && !section.contains("dev-dependencies")
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// `foo = { .. }` -> `foo`
fn key_of(line: &str) -> Option<String> {
    let eq = line.find('=')?;
    let key = line[..eq].trim();
    if key.is_empty() || key.contains('.') {
        return None;
    }
    Some(key.trim_matches('"').to_string())
}

/// The first quoted value after `key` on the line: `path = "../x"` -> `../x`
fn quoted_after(line: &str, key: &str) -> Option<String> {
    let i = line.find(key)?;
    let rest = &line[i + key.len()..];
    let j = rest.find('"')?;
    let rest = &rest[j + 1..];
    let k = rest.find('"')?;
    Some(rest[..k].to_string())
}

/// Parse a `[features]` section body into (name, entries). Feature values are always arrays
/// of strings, so a bracket scan is sufficient and needs no TOML dependency.
fn parse_features(section: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut rest = section;
    while let Some(eq) = rest.find('=') {
        let name = rest[..eq].trim().trim_matches('"').to_string();
        let after = &rest[eq + 1..];
        let Some(open) = after.find('[') else { break };
        let Some(close_rel) = after[open..].find(']') else {
            break;
        };
        let close = open + close_rel;
        let entries = after[open + 1..close]
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !name.is_empty() {
            out.push((name, entries));
        }
        rest = &after[close + 1..];
    }
    out
}

/// Compare directories through the filesystem so `../fn-dsa-comm` matches the scanned
/// `<root>/fn-dsa-comm` (and `\\?\` prefixes on Windows do not defeat the match).
fn same_dir(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Both directions of the guard, pinned against synthetic manifests so they hold without
/// hand-editing (and hand-restoring) the real ones.
///
/// The guard's value is entirely in the gap between these two: it must fail on the wiring that
/// really was broken on main, and pass on wiring cargo really does accept. A regression in
/// either direction — a guard that stops catching the defect, or one that cries wolf until
/// someone deletes it — is a guard that is not doing its job.
#[cfg(test)]
mod resolution {
    use super::*;

    /// Minimal manifest text; `$X4` is the `[features]` body under test.
    fn manifest(features: &str) -> Manifest {
        let text = format!(
            "[package]\nname = \"probe\"\n\n\
             [dependencies]\ncomm = {{ version = \"0.0.9\", path = \"../comm\" }}\n\n\
             [features]\ndefault = []\n{features}\n"
        );
        parse_manifest(Path::new("."), &text)
    }

    fn forwards(features: &str) -> bool {
        let m = manifest(features);
        let enabled = resolve_feature(&m, FEATURE).expect("feature is declared");
        enabled.contains(&format!("comm/{FEATURE}")) ||
            enabled.contains(&format!("comm?/{FEATURE}"))
    }

    /// The defect that was live on main: declared, forwards nothing. MUST still be caught.
    #[test]
    fn empty_feature_list_is_rejected() {
        assert!(!forwards("shake256x4 = []"));
    }

    /// A forward to some *other* feature of the dependency is not the forward we need.
    #[test]
    fn wrong_target_feature_is_rejected() {
        assert!(!forwards("shake256x4 = [\"comm/no_avx2\"]"));
    }

    /// A same-crate feature that does not exist resolves to nothing useful — still rejected.
    #[test]
    fn dangling_indirection_is_rejected() {
        assert!(!forwards("shake256x4 = [\"_typo\"]"));
    }

    #[test]
    fn direct_forward_is_accepted() {
        assert!(forwards("shake256x4 = [\"comm/shake256x4\"]"));
    }

    /// The false positive this module exists to prevent: `cargo check` accepts this wiring
    /// (verified out of band, exit 0), so the guard must accept it too.
    #[test]
    fn indirect_forward_is_accepted() {
        assert!(forwards(
            "_comm_x4 = [\"comm/shake256x4\"]\nshake256x4 = [\"_comm_x4\"]"
        ));
    }

    #[test]
    fn multi_hop_and_weak_forward_are_accepted() {
        assert!(forwards(
            "shake256x4 = [\"a\"]\na = [\"b\"]\nb = [\"comm/shake256x4\"]"
        ));
        assert!(forwards("shake256x4 = [\"a\"]\na = [\"comm?/shake256x4\"]"));
    }

    /// A cyclic manifest must terminate rather than hang the test suite. Cargo rejects cycles
    /// itself; the guard only has to not spin.
    #[test]
    fn cycles_terminate() {
        assert!(!forwards(
            "shake256x4 = [\"a\"]\na = [\"b\"]\nb = [\"a\", \"shake256x4\"]"
        ));
        assert!(forwards(
            "shake256x4 = [\"a\"]\na = [\"shake256x4\", \"comm/shake256x4\"]"
        ));
    }

    /// An undeclared feature is not a violation — nothing to forward.
    #[test]
    fn undeclared_feature_resolves_to_none() {
        assert!(resolve_feature(&manifest("no_avx2 = []"), FEATURE).is_none());
    }
}
