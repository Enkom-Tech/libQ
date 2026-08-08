# Fixture: always-false feature gates

The failure proof for `scripts/ci-guard-nonexistent-feature-gates.sh`.

`scripts/ci_guard_nonexistent_feature_gates.py --self-test` materialises this tree into a temp
directory, renaming `Cargo.toml.fixture` → `Cargo.toml`, runs the guard against it, and requires
the output to equal `EXPECTED.txt` exactly. The wrapper runs the self-test before every real scan,
so CI re-proves on every push that the guard can fail. Exit 1 on any mismatch.

The manifests are named `.fixture` so cargo never treats this tree as a package — it is not a
workspace member and must not become one. The temp copy is also not a git work tree, which
incidentally exercises the guard's `tracked_paths() -> None` fallback.

## Why a committed fixture and not a one-time manual check

The repo's card contract is explicit: *a check you have not seen fail is not evidence.* Satisfying
that once, by hand, at authoring time is weaker than it looks — the next refactor can silently
kill detection and the guard then reports OK forever. That is the exact failure mode this whole
family of guards exists to prevent, so the proof belongs in CI rather than in a commit message.

No other guard in `scripts/` ships one. This is the first.

## Every construct here is load-bearing

A control that cannot fail is decoration, and decoration in a test that exists to catch soundness
bugs is worse than nothing — it reads as coverage. Each row below was verified by mutating the
guard and observing the self-test react:

| # | Mutation applied to the guard | Fixture construct that catches it | Self-test reports |
|---|---|---|---|
| R1 | `CFG_TOKEN` loses its `!?` | `cfg!(feature = ...)` in `src/lib.rs` and `build.rs` | MISSED ×2 |
| R2 | `SCAN_DIRS` narrowed to `("src",)` | gate under `crate-a/tests/` | MISSED |
| R3 | identifier guard dropped from `FEATURE_KV` | `#[cfg(target_feature = "avx2")]` control | UNEXPECTED |
| R4 | `// feature-gate-ok:` exemption ignored | the exempted gate | UNEXPECTED |
| R5 | char-literal handling broken | commented-out gate after `'"'` | UNEXPECTED |
| R6 | `dep:` suppression ignored | `serde`, optional but named `dep:serde` | MISSED |
| R7 | `_balanced` stops spanning newlines | the multi-line `#[cfg(…)]` attribute | MISSED |
| R8 | `_first_argument` disabled | `cfg_attr` raw-string payload | UNEXPECTED |
| — | none (control) | — | passes |

9/9 rows behaved as expected on 2026-08-08.

Two of these controls were dead when first written, and both were only found by running the
battery rather than by reading the fixture:

- The char-literal control (R5) had a `"` in its own explanatory comment, which re-synchronised
  the very scanner it was meant to desynchronise. Keep the region between the char literal and
  the construct that follows it free of double quotes.
- The `cfg_attr` control (R8) escaped its inner quotes (`doc = "feature = \"x\""`), so the payload
  could not match the feature pattern under *any* implementation. It is a raw string now.

R5 also corrected a wrong assumption about the failure direction: strings are deliberately
preserved rather than blanked (the guard needs the feature name out of them), so mishandling a
char literal causes **false positives** — comments stop being stripped — not missed gates.

## Changing this fixture

Adding or moving a line shifts the line numbers `EXPECTED.txt` asserts. Regenerate it in the same
commit, and only ever deliberately: a `MISSED` line means detection regressed and the fix belongs
in the guard, not in the expectations.
