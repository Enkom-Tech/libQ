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
| **Max membership constraint degree** | **10** (dir-select deg-2 × x⁵) | **14** (dir-select deg-2 × x⁷) |
| FRI `log_blowup` (membership) | see ⚠ below | **4** (blowup 16) |
| Quotient chunks (membership) | ≈ 16 | ≈ 16 |
| Challenge field | Complex⟨M31⟩ (≈ 62 bits, = value field) | BinomialExtensionField⟨BabyBear,4⟩ (≈ 124 bits) |

**The headline:** Arm B's trace is **~10× narrower and ~21× smaller in bytes** per row (Poseidon2's
21 rounds / width-16 / rate-7 vs Poseidon256's 68 rounds / width-7 / rate-2). Since FRI proof size
and prove time scale with `trace_width × num_queries × blowup`, this predicts **Arm A proofs ≈ an
order of magnitude larger than Arm B's ~1 MB** — to be confirmed by the pending Arm A run. Arm B
also has a *larger, sounder* challenge field (124 vs 62 bits).

## ⚠ Open / to verify

1. **Arm A dynamic numbers pending.** Running `lib_q_zkp::membership::prove_unlinkable_membership[_zk]`
   (witness via `WidePoseidonMerkleTree`) at depths 4/8/16 for prove/verify/size — next pass. (Arm A's
   `WidePoseidonMerkleTree::from_leaf_digests` materializes `2^depth` leaves, so depth 32 needs a
   synthesized path like Arm B's harness uses.)
2. **Arm A `log_blowup` discrepancy (red-team).** `stark.rs::default_config()` sets `log_blowup = 2`
   (blowup 4), but the Arm A membership AIR has **max constraint degree 10** (the same Merkle
   direction-select × x⁵ that gives Arm B degree 14). A degree-10 constraint needs blowup ≥ 16
   (`log_blowup ≥ 4`) — exactly the panic Arm B hit at `log_blowup = 3`. So **either** Arm A's
   membership prover uses a config other than `default_config`, **or** its full-membership transparent
   proof does not actually run at `log_blowup = 2`. The pending Arm A run resolves this; flagged for
   the red-team list.
3. **Proof size is degree-driven, not field-driven.** Arm B's ~1 MB proof is dominated by
   `log_blowup = 4` (forced by the degree-14 direction-select × x⁷) × 100 queries × 1643 columns.
   **Optimization:** storing the direction-selected node input in witness columns (a degree-2
   *selection* constraint feeding a degree-1 Var into the S-box) drops the membership AIR to degree 7
   → `log_blowup = 3` (blowup 8) → roughly **halves** the proof. Apply to BOTH arms for an
   apples-to-apples comparison, or report the un-optimized degree (done here) honestly.
4. **Single-threaded.** Enabling the `parallel` feature (rayon, 24 threads here) would cut prove
   wall-clock substantially; the numbers above are a single-thread floor.
