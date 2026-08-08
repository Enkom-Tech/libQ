# Fixture: always-false feature gates

The failure proof for `scripts/ci-guard-nonexistent-feature-gates.sh`.

`scripts/ci_guard_nonexistent_feature_gates.py --self-test` materialises this tree into a temp
directory, renaming `Cargo.toml.fixture` → `Cargo.toml`, runs the guard against it, and requires
the output to equal `EXPECTED.txt` exactly — **including the verdict text**, not just which lines
fire. The wrapper runs the self-test before every real scan, so CI re-proves detection on every
push. Exit 1 on any mismatch.

The manifests are named `.fixture` so cargo never treats this tree as a package — it is not a
workspace member and must not become one. The temp copy is also not a git work tree, which
incidentally exercises the guard's `tracked_paths() -> None` fallback.

## Why a committed fixture and not a one-time manual check

The repo's card contract is explicit: *a check you have not seen fail is not evidence.* Satisfying
that once, by hand, at authoring time is weaker than it looks — the next refactor can silently
kill detection and the guard then reports OK forever.

That is not hypothetical here. The **first shipped version of this guard was wrong**, passed CI,
and was caught only by an adversarial sweep afterwards: it reported `#[cfg(not(feature = "X"))]`
with X undefined as ALWAYS-FALSE. It is always **TRUE**. The real scan could never expose it,
because this tree contains no undefined features at all — the guard was green and inverted at the
same time. A fixture that asserts verdicts is the only thing that catches that class.

No other guard in `scripts/` ships a failure proof. This is the first.

## Three verdict classes

An undefined feature does not always mean dead code. What it means depends on polarity, and
conflating them is the bug above:

| Condition | Verdict | Why it matters |
|---|---|---|
| `feature = "X"`, `all(…, feature = "X")` | ALWAYS-FALSE | the item compiles in no configuration |
| `not(feature = "X")` | ALWAYS-TRUE | fail-**open**: the item is unconditionally live. Renaming a feature out of existence silently makes a `not()`-gated fallback permanent. 588 such sites in this repo. |
| `any(feature = "real", feature = "X")` | DEAD-ARM | the condition is still satisfiable; that arm just never contributes |

The guard evaluates the parsed cfg tree in three-valued logic (undefined feature → FALSE, defined
feature → UNKNOWN, every non-feature predicate → UNKNOWN). A condition it cannot parse yields
UNKNOWN throughout, so it can never be reported as dead — it fails safe toward silence rather than
toward a wrong verdict on code someone then deletes.

## Every construct here is load-bearing

A control that cannot fail is decoration, and decoration in a guard's own test reads as coverage.
Each row was verified by mutating the guard and observing the self-test react:

| # | Mutation applied to the guard | Construct that catches it | Self-test reports |
|---|---|---|---|
| R1 | `CFG_TOKEN` loses its `!?` | `cfg!(…)` in `src/lib.rs` and `build.rs` | MISSED ×2 |
| R2 | `SCAN_DIRS` narrowed to `("src",)` | gate under `crate-a/tests/` | MISSED |
| R3 | **both** key checks made lax | `#[cfg(target_feature = "avx2")]` | UNEXPECTED |
| R4 | `// feature-gate-ok:` ignored | the exempted gate | UNEXPECTED |
| R5 | char-literal handling broken | commented-out gate after `'"'` | UNEXPECTED |
| R6 | `dep:` suppression ignored | `serde`, optional but named `dep:serde` | MISSED |
| R7 | `_balanced` stops spanning newlines | the multi-line `#[cfg(…)]` | MISSED |
| R8 | `_first_argument` split removed | `cfg_attr` with an always-false condition | MISSED |
| R9 | polarity ignored (**the shipped bug**) | `not()` and `any()` plants | wrong verdicts |
| R10 | all verdicts collapsed to one string | same | wrong verdicts |
| — | none (control) | — | passes |

R3 is deliberately listed as "both": the feature-key check exists in the regex pre-filter *and* in
the parser predicate, and breaking either alone is masked by the other. Verified — single
mutations exit 0, the pair exits 1. That is real redundancy, not a dead control, but it does mean
no single-point regression in key matching is caught.

## Controls that were dead when first written

Both were found by running the mutation battery, not by reading the fixture:

- The char-literal control (R5) had a `"` in its own explanatory comment, which re-synchronised
  the very scanner it was meant to desynchronise. Keep the region between the char literal and the
  construct after it free of double quotes.
- The `cfg_attr` control (R8) escaped its inner quotes (`doc = "feature = \"x\""`), so the payload
  could not match the feature pattern under *any* implementation. It is a raw string now, and a
  separate planted gate covers the first-argument direction.

R5 also corrected a wrong assumption about failure direction: strings are deliberately preserved
rather than blanked (the guard needs the feature name out of them), so mishandling a char literal
causes **false positives** — comments stop being stripped — not missed gates.

## Changing this fixture

Adding or moving a line shifts the line numbers `EXPECTED.txt` asserts. Regenerate it in the same
commit, and only ever deliberately: a MISSED line means detection regressed and the fix belongs in
the guard, not in the expectations.
