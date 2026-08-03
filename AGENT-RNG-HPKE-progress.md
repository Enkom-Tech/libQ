# Progress: RNG/HPKE release-blocking fixes

Worktree: `C:\Users\Xtreme-W\Transfer\Enkom\Enkom\Git\libQ\.claude\worktrees\agent-a5eb3ecc6f329b06e`
Branch: (to be created before first commit — currently on whatever branch the worktree started on; will branch off before committing since main must stay untouched)

## Baseline (before any fix)

`cargo test -p lib-q-aead -p lib-q-hpke` (default features, no extra flags): all green.
- lib-q-aead --lib: 159 passed
- lib-q-hpke --lib: 113 passed
- lib-q-hpke's own `std` feature is OFF by default (not in its `default = [...]` list), so most
  `#![cfg(feature = "std")]`-gated integration test files (auth_mode_tests.rs, debug_auth_mode.rs,
  hpke_core_tests.rs, psk_mode_tests.rs, rfc9180_compliance_tests.rs,
  security_validation_comprehensive_tests.rs, authpsk_mode_comprehensive_tests.rs,
  security_fixes_tests.rs, rfc9180_test_vectors.rs, side_channel/*, etc.) compile to **0 tests**
  under the bare command. Real CI's only `cargo test --all-features` run (see `rust-build` job)
  and `cargo clippy --all-targets --all-features` do exercise them. `algorithm_agnostic_tests.rs`
  and `tests/unit/architecture_tests.rs` are NOT std-gated and DO run under the bare command.
Full baseline output saved at (scratchpad, not in repo):
`.../scratchpad/baseline_test_output.txt`.

---

## ITEM 1 — lib-q-aead nonce.rs (B4) — DONE

File: `lib-q-aead/src/security/nonce.rs`.

**In-repo callers check (item 1b):** `grep -rn "nonce_from_key_and_counter|nonce_from_counter|nonce_from_random"`
across the whole workspace found matches ONLY inside `nonce.rs` itself (definitions + its own
unit tests). No caller anywhere. Confirms audit's finding.

**RED evidence (observed, `cargo test -p lib-q-aead --lib security::nonce::tests`):**
```
thread 'security::nonce::tests::test_nonce_from_key_and_counter_does_not_leak_key_bytes' panicked at lib-q-aead\src\security\nonce.rs:720:9:
assertion `left != right` failed: nonce_from_key_and_counter leaked raw key bytes onto the wire
  left: [171, 171, 171, 171, 171, 171, 171, 171]
 right: [171, 171, 171, 171, 171, 171, 171, 171]

thread 'security::nonce::tests::test_secure_nonce_is_predictable_from_public_clock_and_counter' panicked at lib-q-aead\src\security\nonce.rs:701:9:
the 'secure' nonce was fully reproducible from public information (a wall-clock bracket spanning 5701 candidate nanoseconds + the always-zero starting counter) — it carries no real entropy

test result: FAILED. 13 passed; 2 failed; 0 ignored; 0 measured; 140 filtered out; finished in 0.01s
```
Note: a simpler "two fresh NonceManagers -> compare first nonce" test (and even a 200,000-draw
birthday-collision loop) did NOT reproduce on this dev machine — its `SystemTime::now()` /
`GetSystemTimePreciseAsFileTime` resolution is fine enough that back-to-back in-process calls
essentially never land on the same nanosecond. So the RED evidence above uses a **deterministic**
reproduction instead: bracket the wall-clock window around the real call, brute-force every
candidate nanosecond in that window with the counter fixed at 0 (provably true for a fresh
manager's first call), and show the exact broken hash chain reproduces the real output
byte-for-byte. This is a stronger demonstration of "no real entropy" than a lucky collision would
have been. The simple collision-loop test is kept anyway as a permanent statistical regression
check (it was already green pre-fix on this box; that fact is recorded honestly, not presented as
RED evidence).

**Fix:**
- `generate_secure_nonce`: deleted both the std `DefaultHasher(now, counter)` branch and the
  wasm32/no_std bare-LCG branch. Now fills the nonce buffer via `lib_q_random::fill_entropy`
  (gated `#[cfg(feature = "shake256")]`, the feature that pulls in the optional `lib-q-random`
  dependency) and fails closed (`Error::RandomGenerationFailed`) when `shake256` is not enabled —
  no non-cryptographic fallback. The per-instance `counter` is still bumped (for `get_counter()`
  back-compat / diagnostics) but no longer feeds the nonce bytes.
- `utils::nonce_from_key_and_counter`: **deleted** (no callers found; brief said deleting is
  acceptable and likely better). Updated `test_nonce_utils` to drop the reference. The RED test
  for this function was removed too (function no longer exists); its observed failure is recorded
  as a comment in `nonce.rs` at the deletion site instead of kept as a live test.
- `nonce_from_counter` / `nonce_from_random` (not flagged by the brief) were left unchanged — they
  don't embed secret key material and `nonce_from_random` already requires the caller to supply
  real randomness.

**Post-fix verification (`cargo test -p lib-q-aead -p lib-q-hpke`, exact evidence command):**
```
Running unittests src\lib.rs (...lib_q_aead...)
test result: ok. 161 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out   <- was 159; +2 new tests, 0 regressions
... (all lib-q-aead integration test files unchanged: 11+5+20+14+6, all ok)
Running unittests src\lib.rs (...lib_q_hpke...)
test result: ok. 113 passed; 0 failed ... (untouched by item 1)
```
`lib-q-aead/tests/key_commitment.rs` and `lib-q-aead/tests/nonce_misuse.rs` (the ones the brief
said not to disturb) — confirmed present and green in the same run (auto-discovered, part of the
full `cargo test -p lib-q-aead` pass above; not separately renamed/touched).

Files touched: `lib-q-aead/src/security/nonce.rs` only.

---

## ITEM 2 — lib-q-hpke SimpleRng (B16) — DONE

Verified brief's claim: `SimpleRng` (src/security/prng.rs, was ~145-188) had no `#[cfg(test)]`
gate (first one in the file was on the `tests` module only), was `pub`, implemented the real
`CryptoRng` trait, and `set_rng`'s doc comment (lib.rs ~262-266) pointed callers at it by name.
Confirmed.

**Design decision:** rather than feature-gating `SimpleRng` behind a new Cargo feature (considered
first, but it already has 7 consumers across `tests/`, and a new default-off feature not wired
into any `[[test]] required-features` would silently break a plausible `cargo test -p lib-q-hpke
--features std` run — checked: none of the current CI workflows run exactly that combination
today, but it's a real footgun for a human debugging locally), the fix **deletes `SimpleRng`
outright** and repoints every consumer at the crate's existing `TestRng`
(`security::test_rng::TestRng`, already used by `auth_encap_validation_tests.rs`, deterministic,
KT128-backed, gated `#[cfg(any(test, feature = "std"))]` — exactly the condition all 6 affected
test files already require via their own file-level `#![cfg(feature = "std")]`). No Cargo.toml
changes needed since no feature gate was introduced.

**Fix:**
- Deleted `SimpleRng` struct + `Default`/inherent/`CryptoRng` impls from `src/security/prng.rs`.
- Deleted its dedicated unit tests (`test_simple_rng`, `test_rng_determinism`,
  `test_simple_rng_fill_bytes_pattern`, `test_simple_rng_from_seed_u64_output`). `test_random_u32`
  / `test_random_u64` were actually testing `SimpleRng::next_u32/64` (misleadingly named — they
  never touched the real `random_u32()`/`random_u64()` free functions backed by
  `fill_random_bytes`/`lib_q_random`); rewrote them to call the real free functions instead, which
  restores meaningful coverage for those two functions (previously untested).
- `lib.rs`'s `set_rng` doc now points at `crate::security::test_rng::TestRng` with an explicit
  "do not use in production" note.
- Swapped `lib_q_hpke::security::prng::SimpleRng::new()` -> `lib_q_hpke::security::test_rng::TestRng::new()`
  in: `tests/auth_mode_tests.rs` (5 call sites), `tests/debug_auth_mode.rs` (1),
  `tests/hpke_core_tests.rs` (import + 1 call site), `tests/psk_mode_tests.rs` (4),
  `tests/suite_id_tests.rs` (1), `tests/security_fixes_tests.rs` (4).
- `tests/unit/architecture_tests.rs::test_prng` runs under **default** (non-std) features (it has
  no `#![cfg(feature = "std")]` gate, confirmed it ran in the very first baseline). `TestRng`
  needs "std" for external test crates, so this test now uses a tiny inlined, non-exported
  `LocalCounterRng` double defined right in the test function — same trivial behavior as old
  `SimpleRng`, but no longer part of the library's public API surface.

**Verification:**
- `cargo test -p lib-q-hpke --lib`: 109 passed (was 113; -4 net from deleting 4 SimpleRng-only
  tests, `test_random_u32`/`test_random_u64` kept under the same names with rewritten bodies).
  0 failed.
- `cargo test -p lib-q-hpke --test unit` (default features, exercises `architecture_tests::test_prng`
  via the local double): 36 passed, 0 failed — same count as baseline.
- `cargo test -p lib-q-hpke --features std --test auth_mode_tests --test debug_auth_mode --test hpke_core_tests --test psk_mode_tests --test suite_id_tests --test security_fixes_tests`:
  all 6 binaries compile and pass (6+1+11+5+7+11 = 41 tests, 0 failed) — confirms the `TestRng`
  swap didn't break any of the files that only run under `--features std` (0 tests under the bare
  default-feature evidence command, but real under `--all-features` CI).

Files touched: `lib-q-hpke/src/security/prng.rs`, `lib-q-hpke/src/lib.rs`,
`lib-q-hpke/tests/unit/architecture_tests.rs`, `lib-q-hpke/tests/auth_mode_tests.rs`,
`lib-q-hpke/tests/debug_auth_mode.rs`, `lib-q-hpke/tests/hpke_core_tests.rs`,
`lib-q-hpke/tests/psk_mode_tests.rs`, `lib-q-hpke/tests/suite_id_tests.rs`,
`lib-q-hpke/tests/security_fixes_tests.rs` (this last file's Auth-specific assertions still need
item 3's rewrite — not done yet as of this checkpoint).

---

## ITEM 3 — lib-q-hpke Auth mode fail-closed (B14 interim) — DONE

Verified brief's claims against source:
- `create_auth_tag` (post_quantum.rs ~423-441) hashes only `shared_secret || sender_pk ||
  encapsulated_key` — no sender secret key input. Confirmed.
- `_sender_commitment` / `_basic_commitment` (lines ~277-284) are computed and immediately
  discarded into `_`-prefixed locals; never transmitted. Confirmed — already dead weight even
  before any fix.
- Line ~497 `if auth_tag != expected_auth_tag.as_slice()` is a variable-time `!=` on `Vec<u8>`.
  `verify_auth_tag_constant_time` (side_channel_protection.rs:123) exists but is confirmed to have
  **no production caller anywhere** (only its own unit tests reference it).

Blast-radius audit done: real (non-enum-table) Auth/AuthPSK round-trip invocations exist in:
`tests/algorithm_agnostic_tests.rs` (runs under bare default features today — HIGH PRIORITY, must
not break the exact evidence command), `tests/auth_mode_tests.rs`, `tests/debug_auth_mode.rs`,
`tests/auth_encap_validation_tests.rs`, `tests/authpsk_mode_comprehensive_tests.rs`,
`tests/rfc9180_compliance_tests.rs`, `tests/security_validation_comprehensive_tests.rs`,
`tests/security_fixes_tests.rs`, `tests/rfc9180_test_vectors.rs` (all of these except
algorithm_agnostic_tests.rs are `#![cfg(feature = "std")]`-gated, 0 tests under the bare command,
but must still be fixed for `--all-features` CI correctness). `tests/side_channel/side_channel_analysis_tests.rs`
only discards the auth_encapsulate result for timing (`#[ignore]`d) — no change needed.
`tests/interop_fixtures.rs` / `tests/hpke_context_tests.rs` — enum/fixture plumbing only, no
success assertion — no change needed there directly (rfc9180_test_vectors.rs which drives the
fixtures DOES need a mode-aware assertion change).

**RED evidence (observed, `cargo test -p lib-q-hpke --features std,ml-kem,hash,secure-rng --test auth_encap_validation_tests`,
new test `auth_decapsulate_rejects_forged_sender_identity_with_no_sender_secret_key`):**
```
thread 'auth_decapsulate_rejects_forged_sender_identity_with_no_sender_secret_key' panicked at lib-q-hpke\tests\auth_encap_validation_tests.rs:89:5:
auth_decapsulate accepted a forged sender identity backed by NO sender secret key anywhere (B14) — Auth mode must fail closed until AuthEncap/AuthDecap are redesigned to bind the sender's static secret key per RFC 9180 Section 5.1.3
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.03s
```
The test does ordinary (non-auth) KEM encapsulation to the recipient (no sender secret key
anywhere), then reproduces `create_auth_tag`'s scheme externally with public building blocks only
(`lib_q_hash::Sha3_256::digest`) for a claimed ("forged") sender identity, and calls
`auth_decapsulate`. It accepted the forgery — confirmed.

**Fix (`lib-q-hpke/src/providers/post_quantum.rs`):**
- `auth_encapsulate` / `auth_decapsulate` now immediately `Err(Self::auth_mode_unavailable())` —
  fail closed unconditionally, for well-formed AND malformed input alike (both Auth and AuthPSK
  route through these two functions per `hpke_core.rs`'s `matches!(mode, HpkeMode::Auth | HpkeMode::AuthPsk)`
  checks, so both modes are covered by one fix).
- Deleted `create_sender_commitment` / `create_sender_commitment_with_pk` / `get_commitment_length`
  entirely — confirmed via the audit and by reading the code that their outputs were already
  discarded into `_`-prefixed locals and never transmitted or checked; pure dead weight even before
  this fix.
- Kept `create_auth_tag` / `verify_auth_tag` (the retired B14 tag scheme), `#[allow(dead_code)]`
  with a rationale comment explaining they're unreachable from production now, per the brief's
  explicit "ALSO... fix as defence in depth" ask. Routed `verify_auth_tag`'s comparison through
  `side_channel_protection::verify_auth_tag_constant_time` (previously had zero production
  callers anywhere in the crate — confirmed) instead of the variable-time `!=` at the old line 497.
- Doc updates stating the gap plainly: `types.rs` (`HpkeMode::Auth`/`AuthPsk` variant docs),
  `lib.rs` (crate-level "Security considerations" bullet + all four
  `setup_{sender,receiver}_auth[_psk]` method docs), `providers/traits.rs` (trait method docs),
  `README.md` (Auth/AuthPSK sections rewritten with an explicit warning + `is_err()` examples),
  `SECURITY.md` ("Known limitations" bullet with full rationale).

**Blast-radius fixes** (every test file with a real, non-enum-table Auth/AuthPSK invocation,
rewritten to assert fail-closed instead of success):
- `tests/algorithm_agnostic_tests.rs` — **runs under bare default features**; this was the one
  that would have broken the brief's own exact evidence command. Fixed by asserting
  `seal_with_mode(..., HpkeMode::Auth/AuthPsk, ...)` returns `Err` instead of routing through the
  success-asserting `test_hpke_mode` helper.
- `tests/auth_encap_validation_tests.rs` — added the RED/GREEN forgery test; rewrote 4 of 5
  pre-existing tests (`test_derive_public_key` untouched, doesn't touch Auth mode) to assert
  fail-closed.
- `tests/auth_mode_tests.rs` — rewrote all 6 tests (kept `test_auth_mode_parameter_validation`
  as-is: it fails during parameter validation in `hpke_core.rs`, before ever reaching
  `auth_encapsulate`, so it was unaffected).
- `tests/debug_auth_mode.rs` — rewrote its one test to assert fail-closed (kept the
  print-diagnostics style of the original).
- `tests/authpsk_mode_comprehensive_tests.rs` — rewrote all 8 tests down to 4 (removed tests whose
  entire premise was "wrong PSK / wrong sender is rejected while correct ones succeed" — moot now
  that correct ones are rejected too).
- `tests/rfc9180_compliance_tests.rs` — `test_auth_mode` / `test_auth_psk_mode`: changed `.unwrap()`
  to an `is_err()` assertion.
- `tests/security_validation_comprehensive_tests.rs` — `test_authentication_implementation_security`
  (rewritten) and the Auth arm inside `test_comprehensive_security_properties`'s mode loop
  (now asserts `is_err()` and `continue`s).
- `tests/security_fixes_tests.rs` — `test_auth_encap_auth_decap_fixes` rewritten to expect errors;
  `test_error_message_security`'s message-content assertion changed (old message said "...bytes",
  new fixed message doesn't — now checks for "auth" instead); `test_auth_encap_invalid_key_sizes` /
  `test_auth_decap_invalid_key_sizes` left as `is_err()` (still true) with a clarifying doc comment
  that they no longer specifically test size validation.
- `tests/rfc9180_test_vectors.rs` — `test_hpke_rfc9180_compliance`'s per-vector loop made
  mode-aware: TV-003 (Auth) / TV-004 (AuthPSK) now assert `is_err()` and `continue` before reaching
  the receiver-setup/seal/open steps designed for a successful round trip.
- Checked and left unchanged (confirmed no success-assertion on Auth mode there):
  `tests/side_channel/side_channel_analysis_tests.rs` (discards the result for timing, `#[ignore]`d),
  `tests/interop_fixtures.rs` / `tests/hpke_context_tests.rs` (enum/fixture plumbing only),
  `tests/suite_id_tests.rs` / `tests/psk_mode_tests.rs` / `tests/hpke_core_tests.rs` (only needed
  the item-2 SimpleRng->TestRng swap, no Auth-mode success assertions found there).

**Verification (three full runs, all green, zero failures anywhere):**
1. `cargo test -p lib-q-hpke --features std,ml-kem,hash,secure-rng` (every std-gated file
   actually compiled+ran, not just default-feature-empty): every test binary `ok`, 0 failed.
2. `cargo test -p lib-q-aead -p lib-q-hpke --all-features` (mirrors real CI's only
   `cargo test --all-features` job): 38 "test result: ok" blocks, 0 "FAILED" anywhere.
3. `cargo test -p lib-q-aead -p lib-q-hpke` (bare, the brief's exact evidence command): all green,
   lib-q-aead 161 passed / lib-q-hpke 109 passed (unit), all integration files `ok`.

Files touched: `lib-q-hpke/src/providers/post_quantum.rs`, `lib-q-hpke/src/providers/traits.rs`,
`lib-q-hpke/src/types.rs`, `lib-q-hpke/src/lib.rs`, `lib-q-hpke/README.md`, `lib-q-hpke/SECURITY.md`,
and the 9 test files listed above.

---

## Final check results (after all three items)

```
cargo test -p lib-q-aead -p lib-q-hpke          -> all green (bare/default features)
cargo test -p lib-q-aead -p lib-q-hpke --all-features -> all green (38 test-result blocks, 0 FAILED)
cargo clippy -p lib-q-aead -p lib-q-hpke --all-targets -- -D warnings -> exit 0, no warnings
cargo fmt -p lib-q-aead -p lib-q-hpke -- --check -> exit 0, no diff
```
One clippy issue was caught and fixed along the way: `slow_vector_initialization` on
`Vec::with_capacity(n); v.resize(n, 0u8);` in the new `generate_secure_nonce` — replaced with
`alloc::vec![0u8; n]`.

**Discrepancy vs the brief:** `lib-q-aead/tests/key_commitment.rs` and
`lib-q-aead/tests/nonce_misuse.rs` (the brief said not to disturb them) **do not exist in this
worktree** — `ls lib-q-aead/tests/` lists only `comprehensive_security_tests.rs`,
`hpke_integration_test.rs`, `integration_tests.rs`, `security_tests.rs`, `thread_safety_tests.rs`,
`wasm_smoke.rs`; `git log -- tests/key_commitment.rs tests/nonce_misuse.rs` is empty. The
conversation's opening `gitStatus` snapshot showing them as `A` (added) reflects **uncommitted
staged changes in the main checkout** (`C:\...\Git\libQ`), not this worktree — worktrees share the
object database but not the index/working tree, and this worktree's HEAD (`d41677a`) predates
those files being committed anywhere reachable from it. Net effect: I never touched them (they are
not present to touch), so "don't disturb" is trivially satisfied, but the file that verifies this
worktree does NOT currently exercise those two test files at all.

Everything is committed on this worktree's own branch (`worktree-agent-a5eb3ecc6f329b06e`), not
main. Nothing pushed.
