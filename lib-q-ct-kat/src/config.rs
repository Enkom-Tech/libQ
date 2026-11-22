//! YAML configuration: parsing and validation. Every failure here is a usage error (exit code 2),
//! reported before any build or tool is started.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Layer names usable as `triage` keys and in reports.
pub const LAYER_NAMES: [&str; 5] = ["build_kat", "memcheck", "ct_matrix", "asm_scan", "dudect"];

#[derive(Debug)]
pub enum ConfigError {
    Unreadable(PathBuf, String),
    Syntax(String),
    Invalid(String),
    MissingPath(PathBuf),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(p, e) => write!(f, "cannot read config {}: {e}", p.display()),
            Self::Syntax(e) => write!(f, "invalid YAML: {e}"),
            Self::Invalid(e) => write!(f, "invalid config: {e}"),
            Self::MissingPath(p) => write!(f, "referenced path does not exist: {}", p.display()),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgKind {
    /// Pointer to a secret buffer: tainted for memcheck, varied between dudect classes.
    Secret,
    /// Pointer to a public input buffer.
    Public,
    /// Pointer to an output buffer.
    Out,
    /// `size_t` holding the length of the argument at index `of`.
    Len,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arg {
    pub kind: ArgKind,
    /// Buffer length in bytes (not used for `len`).
    #[serde(default)]
    pub len: usize,
    /// For `len`: index of the buffer argument whose length is passed.
    #[serde(default)]
    pub of: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ret {
    #[default]
    Void,
    Int,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub name: String,
    /// C sources, relative to the config file.
    pub sources: Vec<PathBuf>,
    #[serde(default)]
    pub include_dirs: Vec<PathBuf>,
    /// Extra linker arguments (for example `-lm`, or a prebuilt static library path).
    #[serde(default)]
    pub link_args: Vec<String>,
    /// Function under analysis.
    pub function: String,
    pub args: Vec<Arg>,
    #[serde(default, rename = "return")]
    pub ret: Ret,
    /// Optional known answer: concatenated lowercase hex of all `out` buffers.
    #[serde(default)]
    pub expected_out_hex: Option<String>,
    /// Layer name -> written justification. A failing layer with a justification is accepted
    /// (verdict `accepted-variable-time`); an errored layer can never be accepted.
    #[serde(default)]
    pub triage: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layers {
    #[serde(default = "yes")]
    pub memcheck: bool,
    #[serde(default = "yes")]
    pub ct_matrix: bool,
    #[serde(default = "yes")]
    pub asm_scan: bool,
    #[serde(default)]
    pub dudect: bool,
}

impl Default for Layers {
    fn default() -> Self {
        Self {
            memcheck: true,
            ct_matrix: true,
            asm_scan: true,
            dudect: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dudect {
    #[serde(default = "default_measurements")]
    pub measurements: usize,
    #[serde(default = "default_t")]
    pub t_threshold: f64,
}

impl Default for Dudect {
    fn default() -> Self {
        Self {
            measurements: default_measurements(),
            t_threshold: default_t(),
        }
    }
}

fn yes() -> bool {
    true
}
fn default_measurements() -> usize {
    20_000
}
fn default_t() -> f64 {
    4.5
}
fn default_compilers() -> Vec<String> {
    vec!["gcc".into(), "clang".into()]
}
fn default_opts() -> Vec<String> {
    ["-O0", "-O1", "-O2", "-O3", "-Os"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}
fn default_timeout() -> u64 {
    120
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_compilers")]
    pub compilers: Vec<String>,
    #[serde(default = "default_opts")]
    pub opt_levels: Vec<String>,
    /// Per external command timeout.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub layers: Layers,
    #[serde(default)]
    pub dudect: Dudect,
    pub targets: Vec<Target>,
    /// Directory of the config file; set by `load`, used to resolve relative paths.
    #[serde(skip)]
    pub base_dir: PathBuf,
}

/// Accepts `-O0..-O3`, `-Os`, `-Og`, `-Oz`, `-Ofast`. Anything else is rejected up front rather
/// than being passed to a compiler that may silently ignore it.
pub fn valid_opt_level(s: &str) -> bool {
    matches!(
        s,
        "-O0" | "-O1" | "-O2" | "-O3" | "-Os" | "-Og" | "-Oz" | "-Ofast"
    )
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Unreadable(path.to_path_buf(), e.to_string()))?;
        let mut cfg = Self::parse(&text)?;
        let abs = std::path::absolute(path)
            .map_err(|e| ConfigError::Unreadable(path.to_path_buf(), e.to_string()))?;
        cfg.base_dir = abs.parent().map(Path::to_path_buf).unwrap_or_default();
        cfg.check_paths()?;
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self =
            serde_yaml_ng::from_str(text).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let bad = |m: String| Err(ConfigError::Invalid(m));
        if self.targets.is_empty() {
            return bad("no targets".into());
        }
        if self.compilers.is_empty() || self.opt_levels.is_empty() {
            return bad("compilers and opt_levels must be non-empty".into());
        }
        for c in &self.compilers {
            if c.is_empty() || c.starts_with('-') || c.contains(char::is_whitespace) {
                return bad(format!("bad compiler name {c:?}"));
            }
        }
        for o in &self.opt_levels {
            if !valid_opt_level(o) {
                return bad(format!(
                    "unsupported optimization level {o:?} (use -O0 -O1 -O2 -O3 -Os -Og -Oz -Ofast)"
                ));
            }
        }
        if self.timeout_secs == 0 {
            return bad("timeout_secs must be > 0".into());
        }
        if self.layers.dudect && self.dudect.measurements < 2_000 {
            return bad("dudect.measurements must be >= 2000".into());
        }
        if !(self.dudect.t_threshold.is_finite() && self.dudect.t_threshold > 0.0) {
            return bad("dudect.t_threshold must be positive".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for t in &self.targets {
            if !seen.insert(&t.name) {
                return bad(format!("duplicate target name {:?}", t.name));
            }
            if t.name.is_empty()
                || !t
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            {
                return bad(format!("target name {:?} must be [A-Za-z0-9._-]+", t.name));
            }
            if !is_c_ident(&t.function) {
                return bad(format!(
                    "{}: {:?} is not a C identifier",
                    t.name, t.function
                ));
            }
            if t.sources.is_empty() {
                return bad(format!("{}: no sources", t.name));
            }
            if !t.args.iter().any(|a| a.kind == ArgKind::Secret) {
                return bad(format!("{}: needs at least one secret argument", t.name));
            }
            if !t.args.iter().any(|a| a.kind == ArgKind::Out) {
                return bad(format!(
                    "{}: needs at least one out argument (KAT output)",
                    t.name
                ));
            }
            for (i, a) in t.args.iter().enumerate() {
                match a.kind {
                    ArgKind::Len => match a.of {
                        Some(j) if j < t.args.len() && t.args[j].kind != ArgKind::Len => {}
                        _ => {
                            return bad(format!(
                                "{}: arg {i}: `of` must index a buffer arg",
                                t.name
                            ));
                        }
                    },
                    _ if a.len == 0 => return bad(format!("{}: arg {i}: len must be > 0", t.name)),
                    _ => {}
                }
            }
            if let Some(h) = &t.expected_out_hex
                && (h.len() % 2 != 0 || !h.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return bad(format!("{}: expected_out_hex is not hex", t.name));
            }
            for (layer, why) in &t.triage {
                if !LAYER_NAMES.contains(&layer.as_str()) {
                    return bad(format!("{}: triage names unknown layer {layer:?}", t.name));
                }
                if why.trim().is_empty() {
                    return bad(format!(
                        "{}: triage for {layer} needs a justification",
                        t.name
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_paths(&self) -> Result<(), ConfigError> {
        for t in &self.targets {
            for p in t.sources.iter() {
                let full = self.resolve(p);
                if !full.is_file() {
                    return Err(ConfigError::MissingPath(full));
                }
            }
            for p in &t.include_dirs {
                let full = self.resolve(p);
                if !full.is_dir() {
                    return Err(ConfigError::MissingPath(full));
                }
            }
        }
        Ok(())
    }

    pub fn resolve(&self, p: &Path) -> PathBuf {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base_dir.join(p)
        }
    }
}

fn is_c_ident(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(f) if f.is_ascii_alphabetic() || f == '_')
        && c.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
