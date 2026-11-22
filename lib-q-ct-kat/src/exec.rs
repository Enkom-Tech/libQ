//! Bounded external command execution: timeout, capped output capture, and a clear split between
//! "tool not installed", "ran and exited", "killed by a signal" and "timed out".

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Exited(i32),
    /// Terminated by a signal (a target crash such as SIGSEGV, not a tool error).
    Signaled(i32),
    TimedOut,
    /// Program not found in PATH.
    NotFound,
    SpawnError(String),
}

#[derive(Debug)]
pub struct CmdResult {
    pub outcome: Outcome,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Output beyond the cap was discarded.
    pub truncated: bool,
}

impl CmdResult {
    pub fn ok(&self) -> bool {
        self.outcome == Outcome::Exited(0)
    }
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

fn drain<R: Read + Send + 'static>(
    mut r: R,
    cap: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let (mut out, mut trunc, mut buf) = (Vec::new(), false, [0u8; 8192]);
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(out.len());
                    out.extend_from_slice(&buf[..n.min(room)]);
                    trunc |= n > room; // keep draining so the child never blocks on a full pipe
                }
            }
        }
        (out, trunc)
    })
}

pub fn run(
    program: &str,
    args: &[String],
    cwd: Option<&std::path::Path>,
    timeout: Duration,
    cap: usize,
) -> CmdResult {
    let fail = |outcome| CmdResult {
        outcome,
        stdout: vec![],
        stderr: vec![],
        truncated: false,
    };
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return fail(Outcome::NotFound),
        Err(e) => return fail(Outcome::SpawnError(e.to_string())),
    };
    let out_h = drain(child.stdout.take().expect("piped"), cap);
    let err_h = drain(child.stderr.take().expect("piped"), cap);
    let start = Instant::now();
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(st)) => break status_outcome(st),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break Outcome::TimedOut;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => break Outcome::SpawnError(e.to_string()),
        }
    };
    let (stdout, t1) = out_h.join().unwrap_or_default();
    let (stderr, t2) = err_h.join().unwrap_or_default();
    CmdResult {
        outcome,
        stdout,
        stderr,
        truncated: t1 || t2,
    }
}

#[cfg(unix)]
fn status_outcome(st: std::process::ExitStatus) -> Outcome {
    use std::os::unix::process::ExitStatusExt;
    match (st.code(), st.signal()) {
        (Some(c), _) => Outcome::Exited(c),
        (None, Some(s)) => Outcome::Signaled(s),
        _ => Outcome::Exited(-1),
    }
}

#[cfg(not(unix))]
fn status_outcome(st: std::process::ExitStatus) -> Outcome {
    Outcome::Exited(st.code().unwrap_or(-1))
}
