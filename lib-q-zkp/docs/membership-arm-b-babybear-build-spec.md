# Membership AIR — Arm B Build Spec (BabyBear base-field, Poseidon2)

**Crate:** `lib-q-zkp` · **Status: BUILD SPEC (grounded in current crate structure)** · **Tier: will be RED on its own obligations**

> Supersedes the *field-agnostic* framing of `membership-m31-profiling-scope.md` for the **actually
> buildable** Arm B. That scope doc assumed base-field **M31**; M31 base-field has 2-adicity 1 (no
> radix-2 FFT domain) so it needs the **circle-STARK `CirclePcs`, which lib-Q removed/left incomplete**
> (`lib-q-stark-fri` config: "CirclePcs does not yet honor … verify path"; flagged non-NIST hash).
> The buildable base-field arm is therefore **BabyBear** (2-adicity 27 → the existing `TwoAdicFriPcs`
> works natively, exactly as Arm A uses it over `GF(p²)`). It is a distinct wire variant of the
> frozen `libq.zkfri.membership.v0` statement, selected by a 1-byte instantiation tag (Arm A = `0x01`,
> this BabyBear arm = `0x02`); its public-statement byte widths are fixed only when this build freezes.

---

## 1. Why this is a build, not a port

Arm A's in-circuit hash is `lib_q_poseidon::Poseidon256` over `PoseidonField = Complex<Mersenne31>`
(Poseidon-**1** / HADES: width 7, `R_F=8` full + `R_P=60` partial, S-box **x⁵**). BabyBear cannot
reuse it:

- **S-box.** BabyBear `p − 1 = 2²⁷·3·5`, so `5 | p−1` → `x⁵` is **not** a permutation. BabyBear's
  S-box is **x⁷** (`gcd(7, p−1)=1`). Constraint degree rises 5 → 7 (raises FRI `log_blowup`; report).
- **Permutation.** BabyBear's standard, deployed hash is **Poseidon2** (external/internal round split,
  optimized internal-diagonal matrix), a *different construction* from `Poseidon256`.
- **Field.** No BabyBear in lib-Q's fork (`lib-q-stark-mersenne31` exists; no `lib-q-stark-baby-bear`).

So Arm B needs **new foundational crypto** below the AIR, not a `Mersenne31 → BabyBear` type swap.

## 2. Decided instance (reuse deployed params — the "easier sign-off" story)

Use the **canonical, deployed BabyBear Poseidon2** (the instance SP1 / Plonky3 ship), so Arm B's
round-count obligation is a textbook prime-field citation, not a fresh derivation:

| Parameter | Value | Source / note |
|-----------|-------|---------------|
| Field | BabyBear `p = 2³¹ − 2²⁷ + 1` (`log₂ p ≈ 30.9`) | `p3-baby-bear` (vendored), build a `lib-q-stark-baby-bear` over `lib-q-stark-monty31` |
| Permutation | Poseidon2, **width t = 16** | Plonky3 reference BabyBear Poseidon2 |
| S-box | **x⁷** (α = 7) | BabyBear permutation exponent |
| Rounds | `R_F = 8` external (4+4) · `R_P = 13` internal | Plonky3 deployed BabyBear Poseidon2 |
| Round constants / matrices | **port `p3-baby-bear`'s canonical constants verbatim** | KAT-validate the value-level permutation vs `p3-poseidon2` before any AIR work |

**Sponge geometry (recovers the §9 digest budget over ~31-bit cells):** rate **r = 7**, capacity
**c = 9**, squeeze **w_out = 9** cells.

- Capacity collision: `c·log₂p / 2 = 9·30.9/2 ≈ 139 bits ≥ 128` ✓ (this is the §2 "77.5-bit problem"
  resolved — capacity-5 over base field gives only ~77.5; capacity-9 clears it).
- Digest: `w_out·log₂p = 9·30.9 ≈ 278 bits ≥ 256` ✓; output collision `≈ 139 ≥ 128` ✓.

## 3. Public-statement byte widths (recommended; freeze when the build lands)

Each BabyBear cell serializes canonical LE `u32` = 4 B. Mirrors the frozen Arm A statement shape
(`root‖ctx‖N`), with base-field cells:

| Statement field | Arm A (`0x01`) | This arm (`0x02`, recommended) |
|-----------------|----------------|---------------------------------|
| `root` / `nullifier` (wide digest) | 5 × `GF(p²)` = **40 B** | **9 × BabyBear = 36 B** |
| `ctx` (circuit context) | 2 × `GF(p²)` = **16 B** | **4 × BabyBear = 16 B** (~124-bit linkage parity) |
| envelope `digest_width` header byte | 5 | **9** |

These bytes are **recommended, not frozen** — pin them in the wire-freeze doc only when the
construction lands. Domain separator unchanged: `libq.zkfri.membership.v0`. (The 1-byte
instantiation tag `0x01`/`0x02` lives in the consuming envelope; this crate exposes the statement
bytes + the FFI verify entry point.)

## 4. Build order (each step compiles + tests before the next)

1. **`lib-q-stark-baby-bear`** — BabyBear field over `lib-q-stark-monty31` (mirror
   `lib-q-stark-mersenne31`: modulus, Montgomery params, two-adic generator at 2-adicity 27, the
   extension for FRI challenges). KAT field ops vs `p3-baby-bear`.
2. **BabyBear Poseidon2 in `lib-q-poseidon`** — new `Poseidon2BabyBear16` (constants/params/value-level
   permutation). **KAT vs `p3-poseidon2` BabyBear test vectors** — gate before proceeding.
3. **Poseidon2 in-circuit gadget** — AIR constraints for the Poseidon2 round function (external full +
   internal partial; internal-diagonal MDS), analogue of `poseidon_gadget.rs` but Poseidon2 structure.
   Property test: in-circuit output == value-level permutation for random inputs.
4. **Wide sponge / hash / merkle over BabyBear** — analogues of `air/{wide_sponge,wide_hash,
   wide_merkle,wide_merkle_path}.rs` at `t=16, r=7, c=9, w_out=9`. Reuse Arm A's test pattern
   (value-cells-match-reference, fixture round-trip, corrupted-digest/intermediate/preimage rejection).
5. **`unlinkable_membership` AIR (BabyBear)** — port `air/unlinkable_membership.rs` (~633 lines):
   leaf `L=H(t)`, Merkle path to `R_zk`, nullifier `N=H(domain‖t‖ctx)`, public statement
   `root(36)‖ctx(16)‖N(36)`. `domain` = first cells of `K12("libq.zkfri.membership.v0")` (unchanged).
6. **Prover/verifier** — BabyBear `TwoAdicFriPcs` config (analogue of `stark.rs` `ConfigVal=Complex<
   Mersenne31>` → BabyBear base + its extension for challenges); `prove/verify_unlinkable_membership[_zk]`.
7. **Test suite to parity** — transparent + ZK/hiding prove→verify roundtrips, negatives, at depths
   `[4,8,16,32]`; the §4 measurement table (trace geometry / prove time / proof size / verify time)
   **side-by-side with Arm A** — the comparison the paper's two-arm section wants.

## 5. Security obligations (Arm B's own — do NOT inherit Arm A's)

Per `membership-m31-profiling-scope.md` §5: Arm B needs its **own** sign-off; Arm A's O1–O4 do not
carry. The upside is each item is *textbook prime-field*:

- **(i) Round counts.** `n = log₂ p = 30.9` direct into the standard POSEIDON/POSEIDON2 formulas at
  `α=7, t=16` — **no GF(p²) tower / subfield-invariance / off-envelope-state caveat** (the principal
  O1 hazard simply does not arise). Reusing Plonky3's deployed `R_F=8/R_P=13` makes this a citation.
- **(ii) MDS / internal-diagonal** security over BabyBear at width 16 — inherited from the deployed
  Poseidon2 instance (cite, don't re-derive).
- **(iii) capacity-9 collision ≥128** and **(iv) 9-cell output ≥256** — the §2 derivation above.
- **(v) domain separation** unchanged (frozen `libq.zkfri.membership.v0`, `domain‖t‖ctx` ordering).
- **ZK simulator** — property of the hiding PCS + AIR composition; re-confirm at build, not field choice.

**Even fully built + green, Arm B is tier RED** until a human cryptographer signs (i)–(iv) — same gate
as Arm A, but an *easier* one. Functional tests (roundtrip/ZK/negatives) prove correctness of the
construction, **not** soundness of the parameters.

## 6. Honest scope

This is a multi-day expert STARK build: 3 new foundational pieces (field, Poseidon2, gadget) + ~5,200
lines of AIR to re-derive + prover/verifier + the measurement harness. The crypto-correctness stakes
(Poseidon2 gadget completeness, AIR soundness) make it a **lib-Q-lane** task best done where the
canonical `p3-poseidon2`/`p3-baby-bear` constants are reused and KAT-validated at every layer — not
hand-rolled. The reward is real: a working base-field arm + the A-vs-B measurement table backing the
paper's §5/§6, and a **second, easier-to-sign** soundness path if Arm A's GF(p²) O1 review goes badly.
