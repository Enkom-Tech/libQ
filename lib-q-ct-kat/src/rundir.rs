//! Per-run isolated directories under `<target>/ct-kat/` and cleanup of stale ones.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const PREFIX: &str = "run-";
/// A directory younger than this is never reaped (its owner may not have written its pid yet).
const GRACE: Duration = Duration::from_secs(60);
/// Even with a live-looking pid, a directory older than this is abandoned (pid reuse).
const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

// A CLI reads its environment by design (same scoped allow as lib-q/build.rs).
#[allow(clippy::disallowed_methods)]
pub fn base_dir(override_dir: Option<&Path>) -> PathBuf {
    if let Some(d) = override_dir {
        return d.join("ct-kat");
    }
    let t = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| "target".into());
    t.join("ct-kat")
}

/// Unpredictable 64-bit id: per-process random hasher keys mixed with pid and clock.
pub fn new_id() -> String {
    let mut h = RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    h.write_u128(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    format!("{:016x}", h.finish())
}

pub struct RunDir {
    pub path: PathBuf,
    pub id: String,
    keep: bool,
}

impl RunDir {
    /// `create_dir_all` on the base is idempotent and safe against a concurrent creator; the run
    /// directory itself uses `create_dir` so an id collision is detected and retried.
    pub fn create(base: &Path, keep: bool) -> io::Result<Self> {
        // Absolute: compilers run with the run directory as cwd, so relative paths would double up.
        let base = &std::path::absolute(base)?;
        std::fs::create_dir_all(base)?;
        for _ in 0..16 {
            let id = new_id();
            let path = base.join(format!("{PREFIX}{id}"));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    std::fs::write(path.join("pid"), std::process::id().to_string())?;
                    return Ok(Self { path, id, keep });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique run directory",
        ))
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn pid_alive(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        Path::new(&format!("/proc/{pid}")).exists()
    } else {
        true // cannot tell; fall back on MAX_AGE
    }
}

/// Removes `run-*` directories left by interrupted runs. Returns the removed paths.
pub fn gc(base: &Path) -> Vec<PathBuf> {
    let mut removed = vec![];
    let Ok(rd) = std::fs::read_dir(base) else {
        return removed;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with(PREFIX) || !e.path().is_dir() {
            continue;
        }
        let age = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .unwrap_or(Duration::MAX);
        let pid = std::fs::read_to_string(e.path().join("pid"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        let stale = age > MAX_AGE || (age > GRACE && !pid.is_some_and(pid_alive));
        if stale && std::fs::remove_dir_all(e.path()).is_ok() {
            removed.push(e.path());
        }
    }
    removed
}
