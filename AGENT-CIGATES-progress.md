# CI gates that structurally cannot fail — progress log (COMPLETE)

Branch: fix/ci-gates-cannot-fail, worktree wt-cigates.

All 6 work items done, verified green, and one previously-unknown extra bug found and fixed
along the way (see item 2). Every claim below was reproduced locally with `cargo +stable`
(matching the CI toolchain input) from this worktree; raw output is not reproduced here in full
(see the final report for the guard demonstrations) but every pass/fail count quoted was observed,
not assumed.

## 1. Bogus `--features "all-algorithms"` on lib-q-sha3 / lib-q-k12 `--test constant_time`

Neither crate declares that feature (only the umbrella `lib-q` crate does); combined with `-p`,
cargo hard-errors: `error: the package 'lib-q-sha3' does not contain this feature: all-algorithms`
(exit 101, reproduced). Dropped the flag in security.yml (x2 jobs, 4 lines) and cd.yml (2 lines).
ci.yml's constant-time job already omitted it (confirmed correct by local build) -- copied that
form, per the brief.

## 2. Phantom test targets

- `lib-q-random --test constant_time`: file did not exist. CREATED
  `lib-q-random/tests/constant_time.rs` -- 2 real tests timing `Kt128Expander::from_seed_32` /
  `fill_bytes` (the crate's own secret-seed-to-output bookkeeping; the heavier primitives it wraps
  already have their own constant-time suites in lib-q-k12/lib-q-saturnin). Builds/passes under
  `--features "std,secure,zeroize"` (the CI default), clean under both stable and the pinned
  nightly-2026-07-24 clippy (`--all-targets --all-features -- -D warnings`), clean `cargo fmt --check`.
- `lib-q-random --test entropy_validation`: file did not exist. DELETED the line
  (test-rng/action.yml). The same step already runs two real unit tests
  (`entropy::tests::test_entropy_quality_assessment`, `validation::tests::test_entropy_validation`)
  immediately after -- a deleted redundant phantom line, not a coverage gap.
  **EXTRA BUG FOUND HERE, not in the brief's site list**: running those two "real" lines for real
  showed the FIRST one scores 0 passed across every test binary in the crate (8 summary lines, all
  "0 passed"). The test actually lives in `validation.rs`
  (`validation::tests::test_entropy_quality_assessment`), not `entropy::tests::...` -- there is no
  `entropy::tests` module by that name anywhere in the crate. A cargo test name filter that
  matches nothing is not an error, so this had been silently running 0 tests with no `|| echo`
  needed to hide it (none of the 20-site grep would have found it -- it isn't suppressed, it just
  never mattered because it never failed). Fixed the module path in BOTH places this exact
  two-line block appears: test-rng/action.yml and security.yml's "Validate RNG systems" step.
  Verified: wrong path = 0 passed (8 lines) under the guard -> FAIL; corrected path = 1 passed
  under the guard -> OK. The second line (`validation::tests::test_entropy_validation`) already
  matched 2 real tests by substring PREFIX (`test_entropy_validation_empty_data` +
  `..._insufficient_data`) -- verified, left as is, documented why it works.
- `lib-q-cb-kem --test constant_time`: file did not exist. CREATED
  `lib-q-cb-kem/tests/constant_time.rs` -- 1 real test comparing decapsulation timing for a valid
  vs. bit-flipped ciphertext under the same keypair, exercising the FO implicit-rejection bitmask
  in `operations::crypto_kem_dec`. Builds/passes under `--features "cbkem348864"` (CI default +
  crate defaults), clean clippy (stable + nightly), clean fmt.
- `lib-q-stark-mersenne31 --test field_constant_time_tests` (ci.yml): file EXISTS, 4 real tests,
  builds and passes with no features needed -- not phantom, just needlessly wrapped in `|| echo`.
- **EXTRA FOUND, not in the brief's site list**: test-sha3/action.yml's "Run algorithm-specific
  tests" step looped `cargo test --features ... --test "*$alg*" || true` over 10 algorithm names.
  `cargo test --test` takes an exact target name, not a glob. Reproduced: `cargo test --test
  "*sha3-224*"` -> `error: no test target matches pattern` (exit 101) -- true for every one of the
  10 names, unconditionally, always. DELETED the step; annotated the now-unused `test-algorithms`
  input (matches the existing "Unused (reserved for workflow matrix compatibility)" pattern
  test-fn-dsa already uses for the same input). Every algorithm it named is covered by the crate's
  real per-file tests (cshake.rs, cshake_blobby_kats.rs, turboshake.rs, basic_functionality.rs,
  security.rs).

## 3. fn-dsa filter fix

`-- memory_safety` matched 0 of 7 tests in security_tests.rs (no test is named `memory_safety*`).
Changed to `-- memory`, which matches `test_memory_optimization_security` +
`test_memory_zeroization` (2 tests). Reproduced before (0 passed, 7 filtered, exit 0) and after (2
passed) locally.

## 4. Removed all `|| echo` / `|| true` suppressions

`rg 'cargo (test|nextest)[^\n|]*\|\|' .github/` now returns 0 matches (was 20; one of the 20 was
actually `|| true` at test-sha3/action.yml:104, not `|| echo` as the brief's evidence text said --
minor imprecision, that site is the glob-loop step deleted in item 2, so it's gone either way).
2 of the 20 sites are gone because their steps were deleted (test-sha3 glob loop,
test-rng/action.yml's entropy_validation line); the other 18 are fixed in place and wrapped by the
new guard (item 6).

## 5. Unconditional summary / "passed" writes

test-rng/action.yml:225-233 (RNG test summary -> `$GITHUB_STEP_SUMMARY`) and security.yml's PR
comment ("Security validation passed!") were investigated for whether they needed their own
conditional logic added. Conclusion: NO extra code change needed, and I want to be explicit that
this is a reasoned inference about GitHub Actions semantics I could not execute against real
GitHub infrastructure from this worktree:
  - test-rng/action.yml's summary step has no `if:` of its own, so it inherits the default
    `if: success()` -- both for job steps AND composite-action steps (composite actions fail the
    whole action and skip remaining steps when an inner step fails, same as a job). Once item 4
    lets a real test failure actually exit non-zero, this step stops running on failure, same as
    any other step. It never needed a bespoke edit; it needed its upstream steps to be able to
    fail, which they now can.
  - security.yml's PR comment already computes `securityPassed` from `needs.*.result` (JS) and
    the report file's PASSED/FAILED banner already checks the same `needs.*.result` (bash) -- both
    were ALREADY conditional in the source; the bug was that the underlying jobs' steps swallowed
    real failures via `|| echo`, so the jobs kept reporting `success` regardless. Fixed by item 4.
  - Item 6's guard is what closes the remaining gap plain exit-code propagation cannot: a step
    that runs a test binary, matches 0 tests, and exits 0 anyway. That's exactly the case where
    "conditional on the steps actually succeeding" would otherwise still be lying.

## 6. New guard: scripts/ci-guard-no-vacuous-tests.sh

Wraps a cargo test/nextest invocation; if the wrapped command exits 0 but sums to 0 "passed"
across every `test result:` (or nextest summary) line, exits 1. Propagates the wrapped command's
own exit code untouched on a real failure. `--allow "reason"` opt-out for genuine 0-test
invocations (not needed anywhere in this branch's 23 call sites -- all real).

Applied to all 18 repaired `|| echo`/`|| true` sites, the 2 newly created real constant-time
tests' invocation lines, the entropy-path fix's 4 lines (2 files x 2 lines), and (bonus, cheap,
same theme) test-sha3's already-correct "Constant-time operation verification" step which had no
suppression to remove but also no protection against a future dead filter. 23 guard-wrapped call
sites total.

Verified against the brief's own proof case:
  `cargo test -q -p lib-q-fn-dsa-comm zzz_no_such_test_name` -> 0 passed; 8 filtered out; exit 0
  (bare). Guard-wrapped: exit 1 (FAIL). Guard-wrapped real run (`cargo test -q -p
  lib-q-fn-dsa-comm`, no filter): 8 passed; guard exit 0 (OK).
  Also checked: guard-wrapped genuinely-nonexistent package -> propagates cargo's real exit 101
  unchanged (does not reinterpret a real error as a vacuity failure).

## RED -> GREEN proof (constant-time assertion)

lib-q-random/tests/constant_time.rs, `test_seed_expansion_constant_time`: temporarily set
tolerance to `avg_time * 0 / 100` (was `* 60 / 100`). Guard-wrapped run: FAILED (exit 101,
"seed 0 expansion timing ... differs too much from average ... tolerance 0ns"), guard propagated
it. Reverted (diffed byte-identical against the pre-mutation copy). Re-ran: 2 passed, guard exit 0.

## Files changed

- scripts/ci-guard-no-vacuous-tests.sh (new)
- lib-q-random/tests/constant_time.rs (new)
- lib-q-cb-kem/tests/constant_time.rs (new)
- .github/workflows/security.yml
- .github/workflows/cd.yml
- .github/workflows/ci.yml
- .github/actions/test-rng/action.yml
- .github/actions/test-fn-dsa/action.yml
- .github/actions/test-cb-kem/action.yml
- .github/actions/test-sha3/action.yml

## Sanity: existing repo guards still pass after these edits

- scripts/ci-guard-publish-order.sh . -> OK (cd.yml touched but publish list/order untouched)
- scripts/ci-guard-coverage-honesty.sh . -> OK
- scripts/ci-guard-primitive-banned-terms.sh . -> OK
- All 7 touched YAML files parse clean (PyYAML safe_load).

## Findings that don't match the brief (report these, don't silently "correct" the brief)

- cd.yml:1311-1317 ("Run security tests" in the `security-verification` job) is NOT on the
  pre-publish path despite being in cd.yml. `security-verification` runs after `post-release`,
  which runs after every `publish-rust-*` / `publish-wasm-packages` / `publish-npm-types` job --
  i.e. after crates.io already has the release (crates.io versions are immutable, per this repo's
  own ci-guard-publish-order.sh comments). The real pre-publish constant-time coverage is
  `pre-release-validation`'s `rust-test` action, which runs `cargo test --workspace --features
  "std,all-algorithms"` -- workspace-wide feature resolution tolerates a feature only some members
  declare, so it never hit the per-package `all-algorithms` error this task is about. Fixed the
  named site regardless (a security gate lying about its own pass/fail is worth fixing wherever it
  sits), but the "a release can currently be cut with the gate reporting success having executed
  zero assertions" framing is about a post-hoc verification job, not something that would have
  blocked the 0.0.10 publish itself.
- The `entropy-validation` Cargo feature on lib-q-random (`entropy-validation = []`) gates nothing
  in source -- it's a no-op feature flag, separate from the CI bug above. Not fixed (crate-internal
  design, not a CI-gate honesty issue); flagged for awareness only.
