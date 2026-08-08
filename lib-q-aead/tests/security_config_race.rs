//! T4 — `set_security_config` must never discard the caller's config to an initialisation
//! race (card `t_8f408920`, defect D1 second half).
//!
//! The pre-fix setter was:
//!
//! ```ignore
//! if let Some(global) = GLOBAL_SECURITY_CONFIG.get() { .. } else {
//!     let _ = GLOBAL_SECURITY_CONFIG.set(Arc::new(RwLock::new(config)));  // loser: dropped
//! }
//! ```
//!
//! If a concurrent `get_security_config()` won the `OnceLock` initialisation between this
//! thread's `.get()` returning `None` and its `.set(..)`, the `set` failed and the caller's
//! configuration was silently thrown away.
//!
//! **Why this test spawns subprocesses.** The "`OnceLock` still empty" state exists exactly
//! **once per process**. It cannot be re-entered in-process, and the public API exposes no
//! seam to wedge a thread inside `get_or_init`, so there is no deterministic in-process
//! reproduction. Each child process therefore gets one shot at the window: 32 reader threads
//! and 1 writer thread released from a `Barrier` onto the first-ever touch of the global.
//!
//! This is a **probabilistic** detector, but not a weak one. Measured against the pre-fix
//! code on 2026-08-08: **218 of 300** children lost their configuration. After the fix the
//! global is a `LazyLock<RwLock<..>>`, the losing branch does not exist, and the test is
//! deterministically green — cheap enough (~6 s) to keep as regression scaffolding.

/// Reader threads racing the single writer for initialisation of the global.
const GETTERS: usize = 32;

/// Child processes spawned by [`race_loser_is_never_discarded`].
const CHILDREN: usize = 300;

/// The race itself. `#[ignore]` because it is only meaningful in a process whose global
/// security config has never been touched, so it must be the *only* test in its process — see
/// [`race_loser_is_never_discarded`], which runs it in children via `--ignored --exact`.
/// (Signalling child mode this way rather than through an environment variable is deliberate:
/// `clippy.toml` disallows `std::env::var`/`var_os`.)
#[test]
#[ignore = "driven as a subprocess by race_loser_is_never_discarded; needs a virgin process"]
fn race_child() {
    use lib_q_aead::{
        SecurityConfig,
        get_security_config,
        set_security_config,
    };

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(GETTERS + 1));
    let mut handles = Vec::with_capacity(GETTERS + 1);

    for _ in 0..GETTERS {
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let _ = get_security_config();
        }));
    }

    {
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            set_security_config(SecurityConfig::permissive());
        }));
    }

    for handle in handles {
        handle.join().expect("racing thread panicked");
    }

    // The writer is the only writer in this process, so whatever it wrote must still be
    // there. If it lost the initialisation race and its config was discarded, the global
    // still holds `SecurityConfig::default()`.
    assert_eq!(
        get_security_config(),
        SecurityConfig::permissive(),
        "set_security_config lost the initialisation race and its config was discarded"
    );
}

#[test]
fn race_loser_is_never_discarded() {
    let exe = std::env::current_exe().expect("current_exe");
    let mut failures = 0usize;
    let mut first_failure = String::new();

    for i in 0..CHILDREN {
        let output = std::process::Command::new(&exe)
            .args([
                "race_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("failed to spawn child test process");

        // A child that ran zero tests would make this loop vacuous, so check that the filter
        // actually selected `race_child` rather than silently matching nothing.
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("running 1 test"),
            "child #{i} ran no test — the `--exact --ignored` filter selected nothing, so this \
             test would prove nothing\n--- child stdout ---\n{stdout}"
        );

        if !output.status.success() {
            failures += 1;
            if first_failure.is_empty() {
                first_failure = format!(
                    "child #{i} exited with {:?}\n--- child stdout ---\n{stdout}\n--- child \
                     stderr ---\n{}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
        }
    }

    // Scope the claim to what a non-zero exit actually proves. The expected cause is the
    // initialisation race, but a child can also die for an unrelated reason (a thread that
    // fails to spawn, for instance), and this counter cannot tell the two apart — so the
    // message points at the captured output rather than asserting the cause.
    assert_eq!(
        failures, 0,
        "{failures} of {CHILDREN} child processes failed `race_child`. Expected cause: the \
         initialisation race silently discarded the writer's config (the assertion inside the \
         child says so explicitly). A child can also exit non-zero for an unrelated reason, so \
         read the captured output below before reporting the cause.\n{first_failure}"
    );
}
