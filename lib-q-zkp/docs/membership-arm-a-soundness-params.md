# Arm A membership-STARK soundness parameters — 128-bit post-quantum

**Status:** computed + reproducible (`python lib-q-zkp/tools/fri_soundness.py`, which now reports BOTH
arms). Tier RED — a *parameter characterization* of the PCS/commitment layer, NOT a soundness proof of
the AIR, and NOT a discharge of Arm A's Poseidon-over-GF(p²) obligation (O1). See caveats.

> **Headline:** the Arm A membership config (`stark::membership_config` / `membership_zk_config_*`)
> delivers **≈128-bit post-quantum** soundness (and ≈128-bit classical, conjectured AND
> provable-Johnson), binding on the SHAKE256 Merkle commitment (256-bit → 128-bit collision, NIST
> Category 2). Every other term sits at or above 128.

## History (why the params changed)

Arm A originally used its **value field** `Complex<Mersenne31>` = `GF(p²)` (p = 2³¹−1, ≈62 bits) as
the FRI challenge field, with `log_blowup 2 / q 100 / PoW 16`. A ≈62-bit challenge field is a HARD
ceiling on Fiat–Shamir / DEEP soundness (no query count can lift it), so the proof system was only
≈54–62-bit sound — far below 128, and a stale test (`security_parameter_tests.rs`) falsely certified
it at ≥200/≥100 via a query-only formula that omitted the field term. Fixed by enlarging the
**membership** challenge field and retuning FRI.

## The 128-bit-PQ membership config (mirror of `stark.rs`)

| param | value | was |
|-------|-------|-----|
| value field | `Complex<Mersenne31>` = `GF(p²)` (≈62 b) | unchanged |
| **challenge field** | **degree-3 over `Complex<Mersenne31>` = `GF(p⁶)`** (≈186 b) | `Complex<Mersenne31>` (≈62 b) |
| `log_blowup` | **3** (FRI rate ρ = 1/8) | 2 |
| `num_queries` | **96** | 100 |
| `proof_of_work_bits` | **20** | 16 |
| Merkle commitment | SHAKE256 (256-bit) | unchanged |
| membership AIR degree | 5 (Poseidon256 x⁵ S-box) | unchanged |

The degree-3 challenge extension `GF(p⁶) = F_p[x]/(x²+1)[y]/(y³−5i)` is built in
`lib-q-stark-mersenne31` (`HasComplexBinomialExtension<3>`, `y³ − 5i`, Sage-verified, tested). Only
the **membership** config uses it (`MembershipConfig` / `MembershipZkConfig`); the shared
`default_config` (used by recursion / auth / credential) keeps the ≈62-bit value-field challenge,
because the in-circuit recursive-aggregation verifier (`air/recursive_types.rs`) hardcodes that
width. **The other Arm A proof types are therefore NOT 128-bit and are out of scope for this paper.**

## Computed bits (`tools/fri_soundness.py`)

| term | classical | post-quantum |
|------|----------:|-------------:|
| challenge field `GF(p⁶)` | 186.0 | — |
| constraint/DEEP Schwartz–Zippel | 175.7 | 175.7 |
| FRI query+PoW — unique-decoding (provable) | 100 | — |
| FRI query+PoW — Johnson (provable) | 164 | — |
| FRI query+PoW — capacity (conjectured) | 308 | 298 (grinding Grover-halved) |
| SHAKE256 Merkle collision | 128 | 128 (NIST Cat-2) |
| **OVERALL** | **128 (conj & Johnson)** | **128 (binding: SHAKE256)** |

## Arm A vs Arm B (both 128-bit PQ, hash-bound)

| | Arm A | Arm B |
|--|------|------|
| value field | `Complex<Mersenne31>` (~62 b) | BabyBear (~31 b) |
| challenge field | `GF(p⁶)` deg-3 over complex (~186 b) | `GF(q⁵)` deg-5 (~155 b) |
| FRI | log_blowup 3 / q 96 / PoW 20 | log_blowup 4 / q 96 / PoW 20 |
| AIR degree (S-box) | 5 (x⁵) | 7 (x⁷) |
| OVERALL PQ | **128** (hash-bound) | **128** (hash-bound) |

Both reach the same 128-bit hash floor under the same model, so the paper's headline comparison
(Arm B proofs ~order-of-magnitude smaller) is **at equal security**.

## Caveats

- This is the **PCS/commitment-layer** bit-count. It assumes the AIR is sound + complete (RED) and
  the hash's algebraic security holds. **Arm A additionally carries obligation O1**: Poseidon256 runs
  its STATE over `GF(p²)`, which is OFF the standard prime-field Poseidon security envelope
  (`lib-q-poseidon/src/lib.rs`: "Do NOT rely on a specific bit-security level … for GF(p²)"). That is
  an independent, unresolved reason Arm A's *hash* security is not established — orthogonal to this
  FRI/field characterization. Arm B has no such off-envelope hazard.
- The DEEP term is an approximation (within ~1 bit of |F|/(deg·domain)); the field is well above the
  128 binder regardless.
- PQ model = mainstream/deployed (FS preserves RBR-sound IOP in QROM; SHAKE256/256 = Cat-2). A
  maximally-conservative model (Grover-halve IOP soundness, BHT hash collisions) would need a larger
  field + 384-bit digests for both arms; that is documented as rejected over-conservatism in the Arm B
  soundness doc.
