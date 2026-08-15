# Anon-cred wire size spike: the parameterised harness and a spread table

Board card `ENK-266`. Companion to `anon-cred-wire-fork-recommendation.md`, which recorded the
one-shot FRI-vs-LNP22 comparison. This doc records the *harness* that was built so the comparison
re-runs the moment the two missing human inputs (below) are supplied, plus the spread it produces
today with plausible stand-in numbers.

Nothing here is a security claim. Every construction named is RED until a cryptographer reviews
it. Every row below is tagged `OBSERVED` or `SUSPECTED` per this repo's register rule; treat the
tag, not the prose around it, as authoritative.

## 1. The harness

`lib-q-zkp/src/stark_baby_bear.rs`, `mod tests`:

- `lnp22_abdlop_presentation_size_model(attribute_count: u32) -> usize` — the LNP22/ABDLOP
  analytic size model (see §3).
- `lnp22_size_model_matches_calibration_point` — ordinary (non-`#[ignore]`) unit test; runs in
  every default `cargo test -p lib-q-zkp` and pins the model's base term to the one measured
  point.
- `anon_cred_wire_size_spike` — the deliverable. `#[ignore]`d (it takes real prove/verify time,
  so it does not run in CI or default `cargo test`). Invocation:

  ```
  cargo test -p lib-q-zkp --release --lib stark_baby_bear::tests::anon_cred_wire_size_spike -- --ignored --nocapture
  ```

  It prints one CSV-ish table for each candidate wire, with an explicit `register` column
  (`OBSERVED` / `SUSPECTED`) on every row — the harness itself enforces the register rule, not
  just this doc. `ATTRIBUTE_COUNTS` and `PREDICATE_COUNTS` are two `const` arrays at the top of
  the function; the moment the human inputs land, edit those two arrays (or extend them) and
  re-run the same command — no other code changes needed.

## 2. FRI/STARK (Arm B) — MEASURED, and a caveat about what it measures

Re-run today at HEAD `fd561d5`, via the harness's own live call to `prove_membership_bb` /
`verify_membership_bb` (the same entry point `measure_arm_b` uses):

OBSERVED. ev: `cargo test -p lib-q-zkp --release --lib stark_baby_bear::tests::anon_cred_wire_size_spike -- --ignored --nocapture` (`CARGO_TARGET_DIR` pointed at an isolated `scratchpad/target-anoncred`), tool's own reported total `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 435 filtered out; finished in 24.46s`.

| depth | trace width | total cells | proof bytes | register |
|---:|---:|---:|---:|---|
| 4 | 1661 | 6 644 | 947 600 | OBSERVED |
| 8 | 1661 | 13 288 | 974 371 | OBSERVED |
| 16 | 1661 | 26 576 | 1 004 502 | OBSERVED |
| 32 | 1661 | 53 152 | 1 038 028 | OBSERVED |

(A separate, wider re-run of `measure_arm_b` itself the same session reproduced the same range
including the ZK variant, 947,600–1,211,498 B — matching `anon-cred-wire-fork-recommendation.md`
§1.)

**The important caveat, stated plainly and not smoothed over:** `MEMBERSHIP_ROW_WIDTH` is a fixed
constant, `1661` (`lib-q-zkp/src/air/unlinkable_membership_baby_bear.rs:86`), independent of any
attribute or predicate parameter. OBSERVED from the trace: proof size above tracks `depth`
(6,644→53,152 cells as depth goes 4→32) one-for-one with `total_cells = MEMBERSHIP_ROW_WIDTH *
depth`, not with anything attribute-shaped — because there is nothing attribute-shaped in the
statement. **The committed AIR proves Merkle-path set membership only.** It does not yet encode
attribute values or predicates over them at all.

That means the usual framing of this fork — "FRI arm vs. LNP22 arm, same statement, different
size" — is not apples-to-apples *today*. LNP22's 29,093 B figure (§3) proves knowledge of a
signature on a committed attribute vector with 3-of-8 (or 0-of-8) attributes revealed — an
attribute-bearing statement. The FRI arm as currently built proves a strictly smaller statement
(membership only) that happens to cost ~1 MB regardless. Card items 1–2 (express + size *libQ's
own* anon-cred relation) are what would put both arms on the same statement; until then, the
"~1 MB vs ~20–40 KB" comparison compares a membership-only proof against an attribute+predicate
proof, and the size gap likely understates how much a predicate-carrying FRI/STARK statement would
actually cost (SUSPECTED — no attribute-bearing FRI AIR has been built or measured).

## 3. LNP22/ABDLOP — MODELLED, one calibration point, no fitted slope

SUSPECTED throughout this section, except where marked otherwise. The LaZer working tree that
produced the one real measurement (`anon-cred-wire-fork-recommendation.md` §1: 29,093 B at 8
message polynomials, `pub_mvec=[0,4,5]`, Zen 3 host) no longer exists on any host reachable from
this harness — OBSERVED, the doc itself records "The LaZer working tree used for these
measurements no longer exists on this host" (§5). So LNP22 cannot be re-measured here; only a
model is possible.

`lnp22_abdlop_presentation_size_model(n)`:

```
size(n) = BASE_BYTES + PER_ATTR_BYTES * max(0, n - 8)
BASE_BYTES     = 29_093   (OBSERVED: the measured point itself)
PER_ATTR_BYTES = 64 * ceil(41/8) = 64 * 6 = 384
```

- `BASE_BYTES = 29_093` is OBSERVED — the calibration point, reproduced exactly by the model at
  `n = 8` (`lnp22_size_model_matches_calibration_point`, residual 0 B). This is validation of the
  *base term only*, not the slope.
- `PER_ATTR_BYTES = 384` is SUSPECTED, not fit — **one measured point cannot determine a slope**,
  and the harness does not pretend otherwise. It is instead an analytic hypothesis: ring degree
  `d = 64` and modulus `q = 2199023255717` (`log2 q ≈ 41.0`) are quoted directly from the
  `anon_cred_params.h` dump in `anon-cred-wire-fork-recommendation.md` §4 (OBSERVED, that doc's own
  output). The hypothesis that each attribute beyond the calibration point costs one serialized
  ring element (`d` coefficients × `ceil(41/8) = 6` bytes) in the ABDLOP opening response is
  sourced to LNP22 (eprint 2022/284) §4's commitment construction, where each committed message
  polynomial contributes one element to the response vector `z1` — SUSPECTED, because this repo
  has not re-derived that section's exact accounting, and the model does not account for possible
  per-polynomial packing (would lower the true marginal cost) or `t_B` commitment-term growth
  (would raise it).
- The companion measured point (0-of-8 revealed, 29,107 B vs. 3-of-8's 29,093 B) shows disclosure
  count is near-flat at fixed `n = 8` — OBSERVED — which is why the model puts no separate term on
  revealed-vs-hidden count, only on total `n`.
- **No sourced per-predicate cost exists.** The spread table below reports every
  `predicate_count` at the same modelled byte figure, with the register field itself stating the
  gap (`"...; predicate cost unmodelled"`) rather than fabricating a constant. Predicate *kind*
  (equality vs. range vs. set-membership) prices differently in LNP22-style protocols and no
  source for any of those constants exists in this repo yet.

## 4. Full spread, as produced by `anon_cred_wire_size_spike` today

```
FRI_ARM,depth,trace_width,total_cells,prove_ms_median,proof_bytes,attribute_count_dependence,register
FRI_ARM,4,1661,6644,1082.0,947600,CONSTANT (AIR has no attribute/predicate input),OBSERVED
FRI_ARM,8,1661,13288,3543.9,974371,CONSTANT (AIR has no attribute/predicate input),OBSERVED
FRI_ARM,16,1661,26576,442.8,1004502,CONSTANT (AIR has no attribute/predicate input),OBSERVED
FRI_ARM,32,1661,53152,2130.5,1038028,CONSTANT (AIR has no attribute/predicate input),OBSERVED

LNP22_MODEL,attribute_count,predicate_count,modelled_presentation_bytes,register
LNP22_MODEL,4,0,29093,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
LNP22_MODEL,4,1,29093,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
LNP22_MODEL,4,4,29093,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
LNP22_MODEL,8,0,29093,SUSPECTED (base = exact calibration point; predicate cost unmodelled)
LNP22_MODEL,8,1,29093,SUSPECTED (base = exact calibration point; predicate cost unmodelled)
LNP22_MODEL,8,4,29093,SUSPECTED (base = exact calibration point; predicate cost unmodelled)
LNP22_MODEL,16,0,32165,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
LNP22_MODEL,16,1,32165,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
LNP22_MODEL,16,4,32165,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
LNP22_MODEL,32,0,38309,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
LNP22_MODEL,32,1,38309,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
LNP22_MODEL,32,4,38309,SUSPECTED (extrapolated from single n=8 point; predicate cost unmodelled)
```

ev: same invocation as §2 (`anon_cred_wire_size_spike`, full stdout captured; tool's own reported
total `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 435 filtered out; finished in
24.46s`).

Reading it: FRI arm holds at ~948 KB–1.04 MB across the whole attribute/predicate spread (it does
not see that axis at all, §2). LNP22 model spans ~29.1–38.3 KB across attribute_count 4→32 — still
roughly two orders of magnitude below FRI at every point in the spread, consistent with the fork
doc's headline, but the LNP22 side of that gap is a one-point extrapolation, not four independent
measurements.

## 5. Do not conflate with PVTN Construction-7

`lib-q-lattice-zkp`'s Construction-7 spike work (see memory `pvtn-v1-impl-status.md`) separately
arrived at ~600 KB–1.4 MB, depending on ZK-hiding/param choices, for its own exact-binary +
Gaussian-masked one-out-of-many relation. That is a **different relation** (PVTN membership +
range-clearance, not a signature-on-committed-attributes credential presentation) measured with a
different in-house harness, RED/uncommitted, unrelated to the LaZer `anon_cred.py` demo this doc's
§3 model is calibrated against. Do not add, average, or otherwise combine that number with either
column above.

## 6. What is still missing — the two questions for the human

The apparatus is ready; the answer is not, because these two inputs are still open:

1. **libQ's own anon-cred `attribute_count`.** How many attribute fields does a real presentation
   carry (age/tier/realm/expiry/... — whatever the deployed credential schema turns out to be)?
   Edit `ATTRIBUTE_COUNTS` in `anon_cred_wire_size_spike` to the real number(s) and re-run.
2. **The `predicate_set`, not just a count.** Which predicates does verification actually need —
   equality (reveal), range (e.g. "clearance ≥ min"), or set-membership (e.g. "realm ∈ {...}")?
   Each costs differently in an LNP22-style protocol and no sourced per-predicate byte constant
   exists yet (§3). Once the kind mix is known, the model in `lnp22_abdlop_presentation_size_model`
   needs a second term for it — currently it charges 0 marginal bytes per predicate, which is
   known to be wrong, not merely conservative.
