# Arm B membership-STARK soundness parameters — computed bits

**Status:** computed (reproducible: `python lib-q-zkp/tools/fri_soundness.py`). Tier RED — this is a
*parameter characterization* of the proof system, not a soundness proof of the AIR. It quantifies the
bits delivered by the FRI/PCS layer + commitment hashes; it does **not** discharge the cryptographer
obligations (AIR completeness, Poseidon2 algebraic security).

> **Headline (honest, paper-critical):** the **default Arm B config** delivers **≈116-bit conjectured**
> security and **≈99-bit fully-provable** security — **NOT a clean 128-bit.** A paper must state ~116-bit
> (conjectured), not 128. The 128-bit figure that appears elsewhere in the Arm B docs is the **Poseidon2
> permutation** target (round-count obligation), a *primitive* property; it does not lift the *proof
> system's* soundness, which is capped below it by the 124-bit challenge field and the FRI query phase.

## The config (mirror of `stark_baby_bear.rs`)

`default_config_bb` / `default_zk_config_bb`: `log_blowup = 3` (rate ρ = 1/8), `num_queries = 100`,
`proof_of_work_bits = 16`, challenge field `BinomialExtensionField⟨BabyBear, 4⟩ = F_{p⁴}`, max AIR
constraint degree 7, max measured trace height 32 rows, Poseidon2 sponge capacity/digest = 9 cells,
Merkle MMCS commitment = Shake256.

## Computed terms

| # | Soundness term | bits | note |
|---|----------------|-----:|------|
| 1 | Challenge field \|F_{p⁴}\| | **123.6** | hard cap on Fiat-Shamir / DEEP sampling (`p⁴`, p=2 013 265 921) |
| 2 | Constraint/DEEP Schwartz–Zippel | **115.8** | \|F\| ÷ (deg 7 × 32 rows); the OOD/ALI soundness term |
| 3a | FRI query + 16b PoW — unique-decoding (provable) | **99.0** | per-query evasion (1+ρ)/2; the conservative provable bound |
| 3b | FRI query + 16b PoW — Johnson (provable) | 166.0 | per-query evasion √ρ (list-decoding, BCIKS20) |
| 3c | FRI query + 16b PoW — capacity (conjectured) | 316.0 | per-query evasion ρ; the ethSTARK/Plonky3 deployment assumption |
| 4 | Merkle MMCS (Shake256) collision | 128.0 | 256/2 |
| 5 | Sponge capacity (9 cells) collision | 139.1 | 9·31/2 |
| 6 | Digest (9 cells) preimage | 278.2 | ≥256 ✓ |

## Overall = min over all terms

| FRI regime | overall bits | binding term |
|------------|-------------:|--------------|
| provable (unique-decoding) | **99.0** | FRI query phase (3a) |
| provable (Johnson) | **115.8** | challenge field / DEEP (2) |
| conjectured (capacity) | **115.8** | challenge field / DEEP (2) |

So: under the **standard conjectured** regime that BabyBear STARKs (SP1/Plonky3) actually deploy,
overall soundness is **≈116 bits**, bounded by the **124-bit challenge field** (minus the degree×rows
DEEP term). Under the **most conservative provable** (unique-decoding) FRI bound it is **≈99 bits**,
bounded by the **FRI query phase** (ρ = 1/8 with only 100 queries + 16-bit grinding).

This is **consistent with the BabyBear ecosystem** — SP1/Plonky3 inner FRI layers target ~100-bit
conjectured and wrap for the final layer; they do **not** claim 128-bit at the BabyBear layer. The only
embarrassment would be *claiming* 128-bit for the Arm B proof. The Poseidon2 hash being 128-bit-strong
does not change this — the proof soundness is gated by the field + FRI params, not the hash.

## To reach a clean 128-bit (if the paper needs it)

Both binders must be lifted (raising one alone is capped by the other):

1. **Challenge field (binds the conjectured ~116):** F_{p⁴} ≈ 124 bits is a hard ceiling. Move to a
   **quintic** challenge extension `F_{p⁵} ≈ 155 bits` (or a 128-bit-capable extension). This is a
   *design change* (new `BinomialExtensionField⟨BabyBear, 5⟩`, new irreducible + DFT data) — not just a
   config knob. ⇒ term 1 → ~155, term 2 → ~147.
2. **FRI query phase (binds the provable ~99):** raise `num_queries`. For provable unique-decoding,
   128-bit needs `(128 − 16)/0.830 ≈ 135` queries (vs 100) at ρ = 1/8; or drop the rate to ρ = 1/16
   (`log_blowup = 4`) and keep ~100 queries. Either grows proof size (queries are the dominant cost).

Recommended honest framing for the ePrint paper: **report ≈116-bit conjectured / ≈99-bit provable for
the default config**, cite the regime explicitly, and — if 128-bit is a hard requirement — adopt the
quintic challenge field + `num_queries ≥ 135` (or `log_blowup 4`) and recompute (the script takes these
as parameters).

## Caveats

- Term 2 (DEEP Schwartz–Zippel) is an *approximation* of the combined ALI/DEEP-OOD soundness; the exact
  constant depends on the precise quotient/DEEP formulation in `lib-q-stark-fri`. It is within ~1 bit of
  the |F|/(deg·domain) variant (using LDE domain 8·32 = 256 gives ~112.8). Either way the field is the
  binder near ~113–116.
- These are **PCS-layer** bits. They assume the AIR is sound and complete (the cryptographer obligation)
  and that Poseidon2's algebraic security holds at its round counts (the other obligation). Both are
  still **RED**.
