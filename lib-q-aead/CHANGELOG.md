# Changelog

Crate-local changelog for `lib-q-aead`. The workspace-wide `CHANGELOG.md` at the repo root is
authoritative for cross-crate and release-level entries; this file tracks changes scoped to this
crate in more detail than the root file carries.

## Unreleased

### Fixed — `set_security_config` could silently not apply (card `t_8f408920`)

**No API change. No signature, type or re-export changed; external callers recompile unchanged.
The behaviour changes are listed below and arrive only with this version.**

`set_security_config` returns `()` and had two paths on which it silently did nothing, neither
of them observable by the caller:

1. **Initialisation race.** The global was a `OnceLock<Arc<RwLock<SecurityConfig>>>`. A setter
   that found the cell empty built its own `Arc` and called `OnceLock::set`, discarding the
   result with `let _ =`. If a concurrent `get_security_config()` won the initialisation in
   that window, the caller's configuration was thrown away. This was not a narrow window:
   measured against the pre-fix code, **218 of 300** child processes lost the configuration
   when 32 readers and 1 writer were released from a barrier onto the first-ever touch of the
   global (`tests/security_config_race.rs`, which now guards it).
2. **Poisoned lock.** A panic in another thread while the config write guard was held poisoned
   the `RwLock`; the setter's `if let Ok(..)` arm was then skipped and the previous value
   stayed in place.

Both are gone. The global is now a `LazyLock<RwLock<SecurityConfig>>` — initialisation is
race-free *by construction*, so the discarding branch no longer exists — and both the getter
and the setter recover a poisoned guard with `PoisonError::into_inner`. The invariant is now
stated on the static and holds on both `cfg` branches:

> After `set_security_config(c)` returns, `get_security_config()` returns `c` until the next
> `set_security_config` call, on every target and regardless of any prior panic in any thread.

The `no_std` branch (`spin::LazyLock<spin::Mutex<..>>`) is unchanged: `spin` locks cannot
poison and `spin::LazyLock` is already race-free, so it always met the invariant.

**Behaviour change — `get_security_config` under a poisoned lock.** It previously returned
`SecurityConfig::default()`; it now returns the last-set value. This affects exactly one
scenario: an application that had set `permissive()` and then panicked while writing the
config would previously read back `default()` (which is byte-identical to `strict()`, so the
old fallback happened to be the hardened one); it now reads back `permissive()` — that is,
what it actually configured. Nothing else observes a difference, because on every
non-poisoned read the stored value was already what was returned.

### Fixed — the same two paths in the validator and timing-protection globals

`security::validation::{get,set}_input_validator` and
`security::timing::{get,set}_timing_protection` were the same construct as
`{get,set}_security_config`, character for character: `OnceLock<Arc<RwLock<..>>>`, a
`let _ =`'d `OnceLock::set` on the initialisation path, an `if let Ok(..)` write that skips
silently on a poisoned lock, and a getter that substitutes a freshly built value for the
stored one. All three now use `LazyLock<RwLock<..>>` with `PoisonError::into_inner` recovery
and carry the same invariant.

`GLOBAL_VALIDATOR` was the load-bearing one of the three, for two reasons that do **not**
apply to `GLOBAL_SECURITY_CONFIG`:

- It is on the live path. Every AEAD module validates through `validate_key`,
  `validate_nonce`, `validate_plaintext`, `validate_ciphertext` and
  `validate_associated_data` during encrypt and decrypt, and all of them read the global.
- `ValidationConfig::default()` is *not* `ValidationConfig::strict()` — the defaults are the
  looser of the two (for instance `validate_nonce_uniqueness` is `false` by default and
  `true` under `strict()`, and every size cap is larger). So where the security-config
  getter's old fallback happened to be the hardened value, this one's would have *loosened*
  validation relative to what the application had configured.

`security::timing::GLOBAL_TIMING_PROTECTION` gets the same treatment for the same reasons.

### Documented — the security config is process-global and last-writer-wins

Pre-existing behaviour, previously implicit, now stated in the rustdoc of
`set_security_config`, `get_security_config` and `SecurityContext::new`: there is exactly one
`SecurityConfig` per process, shared by every crate that links `lib-q-aead`, and the last
writer wins. A **library** should not use it to protect its own operations, since any other
dependency may overwrite it; libraries should use `SecurityContext::with_config`, which is
unaffected by the global. The setter is for the *application* to establish a process-wide
default, which is consumed by `SecurityContext::new()`.

Keeping the global (rather than removing or deprecating it) is a deliberate, recorded decision
on card `t_8f408920`: no AEAD operation in this crate currently consumes the configuration —
`SecurityContext::new()` is its only non-test reader — so removing it would churn a published
API without changing any cryptographic behaviour. Deprecation is deferred until an AEAD
operation takes per-operation configuration.

### Added — tests

- `src/security/mod.rs`: `set_applies_even_after_poison` and
  `get_returns_last_set_even_after_poison` (std-only; `spin` has no poison state, so there is
  nothing to test on `no_std`). Both were landed red against the pre-fix code and observed
  failing before the fix was written.
- `tests/security_config_race.rs`: `race_loser_is_never_discarded` drives 300 child processes,
  each racing 32 readers against 1 writer on a virgin global. Observed 218/300 failures
  pre-fix, 0/300 post-fix.
- `src/security/validation.rs`: `validator_survives_a_poisoned_lock`, and
  `src/security/timing.rs`: `timing_protection_survives_a_poisoned_lock` — the same pair of
  assertions for the two globals above.
- Unit tests that touch any of the three process-global values now serialise behind
  `security::TEST_CONFIG_LOCK`, mirroring the `lock_security_config()` helper already used by
  `tests/security_tests.rs`. This includes `test_security_context_creation`, which only
  *reads* the global but asserts on it: without the guard it failed 10 of 60 runs of the
  `--lib` binary at `--test-threads=64`; with it, 0 of 60.
- `test_global_timing_protection_config` asserts the global still holds its default on entry
  but never restored it, so it depended on running before anything that wrote it. It now
  takes the shared lock and restores the default on exit.
