# Membership STARK measurement — Arm A vs Arm B

**Status:** Arm B **measured**; Arm A dynamic numbers **pending** (static metrics below are exact).
Tier RED — these are *performance* numbers for a *functionally working* construction, not a
soundness claim.

**Machine / method.** AMD Ryzen 9 5900X (12 cores / 24 threads), Windows 10 IoT x86_64. `cargo
test --release`, **single-threaded** (the `parallel`/rayon feature is OFF by default — multi-thread
proving would be faster). Prove/verify = **median of 5**; proof size = `postcard::to_allocvec(proof).len()`.
Harness: `lib-q-zkp/src/stark_baby_bear.rs::tests::measure_arm_b` (`--ignored`). FRI for both modes:
`num_queries = 100`, `proof_of_work_bits = 16`, `log_final_poly_len = 0`.

> Timing at these tiny trace heights (depth = rows = 4–32) is **noisy** (twiddle-cache warmup,
> thermal, single-thread); the dominant proof cost is fixed by `num_queries × trace_width × blowup`,
> so prove time is roughly *flat* in depth and proof size grows only slowly (more FRI layers).

## Arm B — measured (BabyBear / Poseidon2, 4-byte elements)

| mode | depth | trace w × h | total cells | prove (ms, med) | verify (ms, med) | proof bytes |
|------|------:|------------:|------------:|----------------:|-----------------:|------------:|
| transparent | 4  | 1643 × 4  | 6 572  | 63.4  | 22.8 | 969 588 |
| transparent | 8  | 1643 × 8  | 13 144 | 167.3 | 22.7 | 997 310 |
| transparent | 16 | 1643 × 16 | 26 288 | 119.4 | 23.3 | 1 028 157 |
| transparent | 32 | 1643 × 32 | 52 576 | 70.0  | 24.0 | 1 062 202 |
| zk          | 8  | 1643 × 8  | 13 144 | 83.7  | 26.6 | 1 237 703 |
| zk          | 16 | 1643 × 16 | 26 288 | 102.8 | 26.7 | 1 277 224 |
| zk          | 32 | 1643 × 32 | 52 576 | 242.5 | 27.2 | 1 319 483 |

Proof size ≈ **0.95–1.06 MB** transparent, **1.18–1.26 MB** ZK. Verify ≈ **23–27 ms**. (Peak RSS not
measured — Windows process-memory sampling from inside the test harness is out of scope here.)

## Arm A — measured (Complex⟨M31⟩ / Poseidon256, 8-byte elements)

| mode | depth | trace w × h | prove (ms) | verify (ms) | proof bytes |
|------|------:|------------:|-----------:|------------:|------------:|
| transparent | 4 | 17 152 × 4 | 199.7 | 313.2 | **17 105 381** (16.3 MB) |
| transparent | 8 | 17 152 × 8 | 247.2 | 235.3 | **17 121 377** (16.3 MB) |

(Harness `measure_arm_a`; same machine/method. Built a real Arm A witness via
`WidePoseidonMerkleTree::from_leaf_digests` + `.path()`; depths capped at 8 because the tree
materializes `2^depth` leaves. Arm A's prove was wrapped in `catch_unwind` — **it did NOT panic**;
both proofs **verify true**.)

### Headline: Arm B proofs are ~17× smaller

| | Arm A (depth 4) | Arm B (depth 4) | ratio |
|--|---------------:|----------------:|------:|
| proof bytes | 17 105 381 | 969 588 | **17.6× smaller (Arm B)** |
| verify (ms) | 313 | 23 | **~13× faster (Arm B)** |

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
| **Membership trace row width** | **17 152** | **1 643** (≈ 10.4× narrower) |
| Element bytes | 8 | 4 |
| **Bytes per trace row** | **137 216** | **6 572** (≈ 20.9× smaller) |
| Public values (cells) | 12 = root5‖ctx2‖N5 | 22 = root9‖ctx4‖N9 |
| Public-statement bytes | 96 = 40‖16‖40 | 88 = 36‖16‖36 |
| S-box constraint degree (hash) | 5 | 7 |
| **Max membership constraint degree** | **5** (gadget STORES the ARC column, so the degree-2 dir-select is absorbed into a low-degree ARC constraint reading a `Var`) | **14** as built (gadget FOLDS ARC, so the degree-2 dir-select propagates into the x⁷ S-box); **7** if optimized (store ARC / the selected node input) |
| FRI `log_blowup` (membership) | **2** (blowup 4 — empirically verified: Arm A proves+verifies) | **4** (blowup 16) as built; **3** (blowup 8) optimized |
| Quotient chunks (membership) | ≈ 4 | ≈ 16 as built / ≈ 8 optimized |
| Challenge field | Complex⟨M31⟩ (≈ 62 bits, = value field) | BinomialExtensionField⟨BabyBear,4⟩ (≈ 124 bits) |

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
2. **Optimization (for a fair comparison).** Storing the direction-selected node input in witness
   columns (a degree-2 *selection* constraint feeding a degree-1 `Var` into the sponge) — or storing
   the ARC column like Arm A — drops Arm B's membership AIR to degree **7** → `log_blowup = 3`
   (blowup 8). The *fundamental* Arm-A-vs-B blowup gap is then 2 vs 3 (x⁵ vs x⁷), not 2 vs 4. **This
   does NOT change the headline**: Arm B's ~17× smaller proof comes from the 21× smaller bytes-per-row
   (field width × element size), which dwarfs the blowup factor. Recommended before the paper's final
   table so Arm B is shown at its best, with the degree difference attributed correctly (x⁷ vs x⁵).
3. **Arm A depths 16/32 not run.** `WidePoseidonMerkleTree` materializes `2^depth` leaves; depths
   16/32 would need a synthesized path (like Arm B's harness) with Arm A's `poseidon256_wide_hash`
   compressor. Proof size is ~flat in depth (dominated by `num_queries × width`), so the depth-4/8
   numbers are representative.
4. **Single-threaded.** Enabling the `parallel` feature (rayon, 24 threads here) would cut prove
   wall-clock substantially; the numbers above are a single-thread floor. Peak RSS not measured.
