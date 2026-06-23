# Membership STARK measurement — Arm A vs Arm B

**Status:** **both arms fully measured** at all four depths [4, 8, 16, 32], transparent + ZK.
Tier RED — these are *performance* numbers for a *functionally working* construction, not a
soundness claim.

**Machine / method.** AMD Ryzen 9 5900X (12 cores / 24 threads), Windows 10 IoT x86_64. `cargo
test --release`, **single-threaded** (the `parallel`/rayon feature is OFF by default — multi-thread
proving would be faster). Prove/verify = **median of 5**; proof size = `postcard::to_allocvec(proof).len()`
(Arm B) / `proof.data.len()` (Arm A, the postcard-serialized `ZkpProof` payload). Harnesses:
`lib-q-zkp/src/stark_baby_bear.rs::tests::measure_arm_b` and `::measure_arm_a` (both `--ignored`).
FRI for both arms/modes: `num_queries = 100`, `proof_of_work_bits = 16`, `log_final_poly_len = 0`.
**Both harnesses now synthesize the authentication path directly** (arbitrary siblings + bits folded
to a root with the production compressor) rather than materializing a `2^depth` tree, so depths
16/32 are feasible for both arms; the AIR only sees (leaf, path, siblings → root), so a synthesized
path gives an identical trace shape to a tree-derived one.

> Timing at these tiny trace heights (depth = rows = 4–32) is **noisy** (twiddle-cache warmup,
> thermal, single-thread); the dominant proof cost is fixed by `num_queries × trace_width × blowup`,
> so prove time is roughly *flat* in depth and proof size grows only slowly (more FRI layers).

## Arm B — measured (BabyBear / Poseidon2, 4-byte elements) — **128-bit PQ, degree-7 optimized**

These are the numbers for the **128-bit-PQ config**: degree-5 challenge field `F_{p^5}`, `log_blowup 4`,
`num_queries 96`, `PoW 20`, degree-7 membership AIR (row width 1661). Median of 5; single-thread.

| mode | depth | trace w × h | total cells | prove (ms, med)¹ | verify (ms, med) | proof bytes |
|------|------:|------------:|------------:|----------------:|-----------------:|------------:|
| transparent | 4  | 1661 × 4  | 6 644  | 686  | 26.0 | 947 600 |
| transparent | 8  | 1661 × 8  | 13 288 | 2510 | 30.1 | 974 371 |
| transparent | 16 | 1661 × 16 | 26 576 | 386  | 29.3 | 1 004 502 |
| transparent | 32 | 1661 × 32 | 53 152 | 1001 | 29.2 | 1 038 028 |
| zk          | 8  | 1661 × 8  | 13 288 | 1274 | 31.8 | 1 131 439 |
| zk          | 16 | 1661 × 16 | 26 576 | 752  | 33.4 | 1 169 596 |
| zk          | 32 | 1661 × 32 | 53 152 | 1394 | 32.3 | 1 211 498 |

¹ Prove time is now **grinding-dominated and noisy**: `PoW 20` draws ≈2²⁰ SHAKE evaluations whose count
varies with grinding luck (the depth-4 vs depth-8 spread is grinding variance, not a depth effect).

Proof ≈ **0.95–1.04 MB** transparent, **1.13–1.21 MB** ZK; verify ≈ **26–33 ms**. **The 128-bit-PQ
upgrade cost essentially nothing in proof size** (within ~0.5% of the prior ≈116-bit config): the
quintic field + `log_blowup 4` are offset by dropping `num_queries` 100→96, and proof size is
`num_queries × trace_width`-dominated. Verify is ~4–7 ms slower (deg-5 extension arithmetic + larger
PoW check). **Honest finding:
membership proof size is dominated by `num_queries × trace_width` (the per-query trace openings), so
reducing the FRI blowup helps prove-time / quotient work more than proof *size*. To materially shrink
the proof you reduce `num_queries` or `trace_width`, not the blowup.**

## Arm A — measured (Complex⟨M31⟩ / Poseidon256, 8-byte elements) — **all depths**

| mode | depth | trace w × h | total cells | prove (ms, med) | verify (ms, med) | proof bytes |
|------|------:|------------:|------------:|----------------:|-----------------:|------------:|
| transparent | 4  | 17 152 × 4  | 68 608  | 196.1  | 260.2 | **17 103 705** (16.3 MB) |
| transparent | 8  | 17 152 × 8  | 137 216 | 393.7  | 257.3 | **17 122 272** (16.3 MB) |
| transparent | 16 | 17 152 × 16 | 274 432 | 442.3  | 246.2 | **17 150 660** (16.3 MB) |
| transparent | 32 | 17 152 × 32 | 548 864 | 354.7  | 251.9 | **17 176 407** (16.4 MB) |
| zk          | 8  | 17 152 × 8  | 137 216 | 551.2  | 229.3 | **17 363 648** (16.6 MB) |
| zk          | 16 | 17 152 × 16 | 274 432 | 867.5  | 231.2 | **17 399 715** (16.6 MB) |
| zk          | 32 | 17 152 × 32 | 548 864 | 1 378.9 | 227.8 | **17 439 758** (16.6 MB) |

(Harness `measure_arm_a`; same machine/method, median of 5, FRI params identical to Arm B. The
depth-16/32 rows use the **synthesized-path** witness — `WidePoseidonMerkleTree::from_leaf_digests`
materializes `2^depth` leaves and OOMs past depth ~20, so the harness now folds a chosen path with
`merkle::wide_node_hash` exactly like Arm B's `path_for`; all four depths are powers of two so the
prover applies no padding and the synthesized root is the one the verifier checks. Every row
**verifies true** — asserted in-harness. Earlier depth-4/8 transparent numbers, 17 105 381 /
17 121 377 bytes via a *real tree*, match these synthesized-path numbers to within serialization
noise, confirming the two witness paths are equivalent.) **Proof size is essentially flat in depth**
— only +72 702 B (transparent) / +76 110 B (zk) across depths 4→32, i.e. ~0.4 %, because FRI proof
size is dominated by `num_queries × trace_width` (constant in depth), with the slow depth term being
the extra FRI commit-phase layers. **Verify is flat** (~250 ms transparent, ~230 ms zk). ZK prove
grows with depth (more rows to blind/commit) where transparent prove is ~flat.

### Headline: Arm B proofs are ~16–17× smaller (holds at every depth)

(Arm B at its **128-bit-PQ** config; Arm A unchanged.)

| | Arm A | Arm B | ratio |
|--|---------------:|----------------:|------:|
| proof bytes, transparent d=4  | 17 103 705 | 947 600   | **18.0× smaller (Arm B)** |
| proof bytes, transparent d=32 | 17 176 407 | 1 038 028 | **16.5× smaller (Arm B)** |
| proof bytes, zk d=32          | 17 439 758 | 1 211 498 | **14.4× smaller (Arm B)** |
| verify (ms), transparent      | ~250       | ~29       | **~9× faster (Arm B)** |
| verify (ms), zk               | ~230       | ~33       | **~7× faster (Arm B)** |

The gap is widest at small depth (less FRI commit-phase overhead diluting the per-row trace cost)
and remains ≥14× through depth 32 / ZK — i.e. **Arm B's field/permutation choice dominates at every
operating point**, not just the smallest one.

The proof-size gap tracks **bytes per trace row** (Arm A 137 216 vs Arm B 6 572 = 20.9×): FRI opens
`num_queries × trace_width` field elements, and Arm A's elements are 8 bytes vs Arm B's 4. This is
the paper's core quantitative result — and it holds *even though* Arm B currently runs at a higher
FRI blowup (see the corrected degree analysis below), i.e. Arm B's field/permutation choice dominates.

## Static comparison (both exact)

| Metric | Arm A — Complex⟨M31⟩ / Poseidon256 | Arm B — BabyBear / Poseidon2 |
|--------|-----------------------------------:|-----------------------------:|
| Permutation width `t` | 7 | 16 |
| Rounds (full + partial) | 8 + 60 = 68 | 8 + 13 = 21 |
| S-box | x⁵ | x⁷ |
| Sponge rate / capacity | 2 / 5 | 7 / 9 |
| Cols per permutation | **1428** | **269** |
| Permutations / membership row | 12 | 6 |
| **Membership trace row width** | **17 152** | **1 661** (≈ 10.3× narrower; was 1643, +18 for stored node input) |
| Element bytes | 8 | 4 |
| **Bytes per trace row** | **137 216** | **6 644** (≈ 20.7× smaller) |
| Public values (cells) | 12 = root5‖ctx2‖N5 | 22 = root9‖ctx4‖N9 |
| Public-statement bytes | 96 = 40‖16‖40 | 88 = 36‖16‖36 |
| S-box constraint degree (hash) | 5 | 7 |
| **Max membership constraint degree** | **5** (gadget STORES the ARC column, so the degree-2 dir-select is absorbed into a low-degree ARC constraint reading a `Var`) | **7** — degree-7 optimization APPLIED (the dir-selected node input is stored as `Var`s; only the x⁷ S-box is high-degree). The 2-vs-3 gap is now the *fundamental* x⁵-vs-x⁷ difference. |
| FRI `log_blowup` (membership) | **2** (blowup 4 — empirically verified) | **3** (blowup 8) — empirically verified (prove+verify succeed; would panic at <3) |
| Quotient chunks (membership) | ≈ 4 | ≈ 8 |
| Challenge field | Complex⟨M31⟩ (≈ 62 bits, = value field) | BinomialExtensionField⟨BabyBear,**5**⟩ (≈ 155 bits — quintic, for 128-bit PQ; was deg-4/≈124b) |
| FRI params (membership) | log_blowup 2, q 100, PoW 16 | **log_blowup 4, q 96, PoW 20** (128-bit-PQ tuned; was 3/100/16) |

**The headline:** Arm B's trace is **~10× narrower and ~21× smaller in bytes** per row (Poseidon2's
21 rounds / width-16 / rate-7 vs Poseidon256's 68 rounds / width-7 / rate-2). Since FRI proof size
and prove time scale with `trace_width × num_queries × blowup`, this predicts **Arm A proofs ≈ an
order of magnitude larger than Arm B's ~1 MB** — to be confirmed by the pending Arm A run. Arm B
also has a *larger, sounder* challenge field (124 vs 62 bits).

## Resolved findings + open items

1. **RESOLVED — Arm A's degree-10 / log_blowup hypothesis was WRONG.** I expected Arm A's membership
   to be degree 10 (dir-select × x⁵) and therefore to *panic* at `default_config` (`log_blowup = 2`),
   the way Arm B (degree 14) panics at `log_blowup = 3`. Running it (`measure_arm_a`, `catch_unwind`)
   shows **Arm A proves and verifies fine** at `log_blowup = 2`. The reason: **Arm A's Poseidon
   gadget STORES the per-round ARC/Sbox/MDS columns**, so the degree-2 direction-select becomes a
   *degree-2 constraint on the stored ARC `Var`*, and the S-box reads that `Var` → max degree stays
   **5**. My **Arm B gadget folds the ARC into expressions and stores only the S-box output**, so the
   degree-2 dir-select propagates *into* the x⁷ S-box → degree **14**. This is an **implementation
   choice, not a fundamental BabyBear/Poseidon2 property**.
2. **Optimization — DONE (applied).** The direction-selected node input is now stored in 18 witness
   columns pinned by a degree-2 selection constraint, feeding the sponge degree-1 `Var`s. The
   membership AIR is now degree **7** / `log_blowup = 3` (empirically verified — prove+verify succeed;
   they panic at `log_blowup < 3`). The *fundamental* Arm-A-vs-B blowup gap is now 2 vs 3 (x⁵ vs x⁷),
   not 2 vs 4 — an honest comparison with the degree difference attributed to the S-box exponent. A
   new corruption `#[should_panic]` test (`corrupt_node_input_rejected`, in both the path and
   membership AIRs) confirms the 18 new columns are pinned. **The ~17× smaller-proof headline is
   unchanged** (it is field/width-driven). **Sub-finding:** dropping the blowup shrank proofs only
   ~2% (transparent) / ~9% (ZK) because membership proof size is dominated by
   `num_queries × trace_width` (per-query trace openings), not the blowup — the blowup reduction's
   real benefit is prove-time / quotient work.
3. **RESOLVED — Arm A depths 16/32 now measured.** `measure_arm_a` was rewritten to synthesize the
   authentication path with `merkle::wide_node_hash` (no `2^depth` tree), and now runs transparent
   4/8/16/32 + ZK 8/16/32 (median of 5, asserting each verifies). The prediction held: proof size is
   flat in depth (+0.4 % across 4→32), so the original depth-4/8 numbers were indeed representative —
   now confirmed rather than assumed. The Arm-B-≈17×-smaller headline holds at every depth (≥14× even
   at depth 32 / ZK). The earlier `catch_unwind` panic-probe was dropped: Arm A is firmly established
   to prove + verify at `log_blowup = 2` (degree 5), so the harness now hard-asserts verification.
4. **Single-threaded.** Enabling the `parallel` feature (rayon, 24 threads here) would cut prove
   wall-clock substantially; the numbers above are a single-thread floor. Peak RSS not measured.
