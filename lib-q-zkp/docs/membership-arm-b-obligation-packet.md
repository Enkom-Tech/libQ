# Arm B Obligation Packet — BabyBear / Poseidon2 Unlinkable-Membership STARK

**Crate:** `lib-q-zkp` · **Tier status: RED** (no human cryptographer sign-off) · **Build status:
fully built, functionally tested, and measured (see `membership-arm-b-build-status.md`,
`membership-arm-b-measurement.md`).**

> This packet enumerates the cryptographic obligations that gate a GREEN tier for **Arm B** — the
> BabyBear/Poseidon2 instantiation (wire tag `0x02`) of the frozen `libq.zkfri.membership.v0`
> statement. It is the input to a human cryptographer's review; it is **not** sign-off. Each item is
> marked GREEN (arithmetic/structure settled at this level) or RED (needs human/cryptographer
> discharge). **Functional green tests prove the construction RUNS correctly; they do NOT prove
> soundness.** Arm B's obligations do **not** inherit Arm A's O1–O4; each is stated for independent
> assessment per item below. (Where an item notes prior precedent — e.g. a standard prime-field
> Poseidon2 parameter set — that is context for the reviewer, not a claim that sign-off is assured.)

---

## 1. Scope & statement

```text
∃ (secret t, path):
    MerkleVerify(root, L = H(t), path) = true
  ∧ N = H(domain ‖ t ‖ ctx)
reveal only (root, ctx, N);  L and t stay private.
```

- `H` = truncated-output **Poseidon2** wide sponge over **BabyBear** `p = 2³¹−2²⁷+1` (`n = log₂p ≈
  30.9`): permutation width `t = 16`, S-box `x⁷` (`α = 7`), `R_F = 8` (4 initial + 4 terminal),
  `R_P = 13`; sponge **rate r = 7, capacity c = 9, digest w_out = 9 cells**.
- `domain` is a baked circuit constant (first 2 cells of the arm's wide hash of
  `MEMBERSHIP_DOMAIN_STR = "libq.zkfri.membership.v0"`), not a witness/public input — see **(v)** and
  Finding **F8**.
- Public values `[ root(9) ‖ ctx(4) ‖ N(9) ]` (22 cells = 88 B). Trace = one row / Merkle level; row 0
  carries the leaf + nullifier sponge blocks. Challenge field = `BinomialExtensionField⟨BabyBear,5⟩`
  = `GF(q⁵)` (≈ 155 bits).
- **PCS-layer security level (computed — `membership-arm-b-soundness-params.md`):** the config
  (degree-**5** challenge field `F_{p^5}`≈155b, `log_blowup 4`, `num_queries 96`, PoW 20) delivers
  **≈128-bit post-quantum** proof soundness (≈128 classical conjectured & provable-Johnson), binding on
  the SHAKE256 Merkle commitment (NIST Cat-2); field/DEEP ~147 and query 212–404 sit above it. This was
  upgraded from the original deg-4 config (≈116-bit conjectured / ≈99-bit provable). Reproduce with
  `tools/fri_soundness.py`. (Independent of the Poseidon2 round-count obligation below, which concerns
  the *primitive*.)
- Files: `air/{poseidon2_gadget, wide_sponge_baby_bear, wide_merkle_path_baby_bear,
  unlinkable_membership_baby_bear}.rs`, `stark_baby_bear.rs`; `lib-q-poseidon/src/poseidon2_baby_bear.rs`;
  `lib-q-stark-baby-bear/src/baby_bear.rs`.

---

## 2. The defining advantage over Arm A

Arm A's principal blocking obligation (**O1**) is that its in-circuit hash is **Poseidon-1 over
`Complex⟨Mersenne31⟩` = GF(p²)** — an *extension-field state*, off the envelope of the standard
Poseidon security analysis (which is stated over a **prime** field). `lib-q-poseidon/src/lib.rs:18–23`
says so in its own words: *"the round counts and sponge parameters … have NOT been independently
verified for the `Complex<Mersenne31>` extension field GF(p²) … Do NOT rely on a specific bit-security
level."* **Arm B eliminates this hazard by construction**: BabyBear is a textbook prime field and
Poseidon2 width-16 is a *deployed, published* instance. Every obligation below is therefore a
**citation of an analyzed, shipped construction**, not a fresh or off-envelope derivation.

---

## 3. Obligations

### (i) Round counts `R_F = 8`, `R_P = 13` at `α = 7`, `t = 16`, `n ≈ 30.9` — **RED (citation-grade)**
The round counts must resist statistical (differential/linear) and algebraic (interpolation,
Gröbner-basis/FreeLunch, higher-order differential) attacks at the target security level. For
Poseidon2 the count is fixed by the formulas in the Poseidon2 paper (Grassi, Khovratovich, Roy,
Schofnegger, *Poseidon2*, ePrint **2023/323**) as a function of `(p, α, t, security)`. The values
`R_F = 8, R_P = 13` for `(BabyBear, α=7, t=16)` are **exactly the deployed Plonky3 / SP1 instance**
(Grain-LFSR generated, `field_type=1, alpha=7, n=31, t=16`; transcribed verbatim, and the
permutation is now anchored to Plonky3's published production-constant KAT — F6 RESOLVED). The
algebraic degree after `R_F + R_P` rounds is `α^(R_F+R_P) = 7^21`, far exceeding the
interpolation/Gröbner bound at 128 bits.
- **Why GREEN-leaning:** this is a *textbook prime-field* parameter set with **no GF(p²)
  tower / subfield-invariance / off-envelope-state caveat** — the Arm-A O1 hazard simply does not
  arise. `n = 30.9` plugs directly into the published formula.
- **Why still RED:** lib-Q has not independently re-run the round-count script for these exact
  parameters, and "matches a deployed instance" is a strong heuristic but not a proof. A cryptographer
  must confirm the count against the paper/reference for the **128-bit** target and the `α=7` choice
  (forced because `5 ∣ p−1`, so `x⁵` is not a permutation). **Open:** confirm whether the deployed
  count targets 128 or 100 bits, and that `x⁷` (not the alternate `x^{-1}` or higher α) is the intended
  S-box.

### (ii) MDS / internal-diagonal over width 16 — **RED (inherited from deployed instance)**
External layer: the block-circulant `M_E` from `M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`.
Internal layer: `1 + diag(V)`, `V = [-2,1,2,½,3,4,-½,-3,-4,1/2⁸,¼,⅛,1/2²⁷,-1/2⁸,-1/16,-1/2²⁷]`. The
Poseidon2 paper requires the internal matrix and its powers up to `2t` to have maximal, irreducible
minimal polynomials (no subspace trails); this is verifiable by the Sage snippet in the upstream
`poseidon2/src/internal.rs` comment. These matrices are the **canonical deployed BabyBear width-16
values** (transcribed verbatim; our `gen_poseidon2_ref.py` cross-checks the external layer against its
matrix form and the internal layer against `(J + diag(V))`).
- **Why still RED:** lib-Q has not re-run the irreducibility check for width 16; a cryptographer should
  confirm (or cite the upstream verification). Again **no off-envelope concern** — it's the shipped
  instance.

### (iii) Capacity-9 collision resistance ≥ 128 — **GREEN (arithmetic), conditional on (i)/(ii)**
Sponge collision resistance is bounded by the capacity: `c · log₂p / 2 = 9 · 30.9 / 2 ≈ **139 bits** ≥
128`. (A base-field capacity of 5 would give only `5·30.9/2 ≈ 77.5` — *insufficient* — which is exactly
why this arm widens to capacity 9; see build-spec §2.) Independently recomputed.
- **Caveat:** "GREEN" is the *reduction* (capacity ⇒ collision bound); it is **conditional on the
  permutation being indistinguishable from a random permutation**, i.e. on (i)/(ii). It is not an
  unconditional claim.

### (iv) 9-cell output, digest ≥ 256 — **GREEN (arithmetic), one structural note**
Digest entropy: `w_out · log₂p = 9 · 30.9 ≈ **278 bits** ≥ 256`; output-collision `≈ 139 ≥ 128`. The
digest is `state[..9]` of the final permutation output.
- **Structural note (recompute):** with rate 7 and digest 9, the digest reads the 7 rate cells **plus 2
  cells of the capacity region**. This does **not** weaken the capacity-9 collision bound: during
  absorption the attacker controls only the rate (7 cells); the 9-cell capacity that feeds each
  permutation is never directly set, so the `c=9` collision bound stands. (Arm A does the same — digest
  5 of state 7, rate 2.) A cryptographer should confirm this wide-squeeze read is acceptable for the
  intended indifferentiability claim.

### (v) Domain separation carryover — **GREEN (structure) / RED (F8 derivation choice)**
The separator string `libq.zkfri.membership.v0` is **unchanged** from the frozen v0. The nullifier
preimage ordering is `domain ‖ t ‖ ctx` (constant ‖ secret ‖ public), injected as constant expressions
(no committed domain column). Sponge padding is `10*1` with capacity, so there is **no length-extension**
(the capacity is never revealed/absorbed-into by the attacker). The wire variant is disjoint from Arm A
(tag `0x01` vs `0x02`; different field, different digest width).
- **RED item — F8:** the build spec said `domain = first cells of K12(separator)`; Arm B instead bakes
  `domain = first cells of the arm's OWN wide hash of the separator` (mirroring Arm A's method, no K12
  dependency). This is a *purely off-circuit constant derivation* and does not affect soundness, but a
  cryptographer should choose: keep the in-family Poseidon2 derivation (parallel to Arm A) **or** switch
  both arms to a K12-derived constant for cross-family domain separation. The string is frozen either way.

### (vi) Zero-knowledge simulator — **RED (no formal simulator; mechanism in place)**
ZK is provided by the hiding PCS: `HidingFriPcs` + `MerkleTreeHidingMmcs` (per-leaf `Kt128Rng` salts) +
FRI blinding (independent `Kt128Rng` seed), with the trace padded to `MIN_ZK_DEPTH = 8`. The ZK
prove→verify roundtrip **works** (`stark_baby_bear::tests::membership_zk_prove_verify_roundtrip`). The ZK
property is a property of the hiding-PCS + AIR composition (standard in the Plonky3/ethSTARK lineage).
- **Why RED:** a *formal* simulator argument (that the proof transcript is simulatable without the
  witness, including the AIR's row-0/ungated-row structure) has **not** been written for this AIR. The
  honest-but-curious leakage of the leaf/nullifier ungated rows (rows 1.. hash a zero preimage) should be
  confirmed to not leak `t`/`ctx`. A cryptographer must discharge this.

---

## 4. Tier verdict

**RED.** Items (iii) and (iv) are GREEN at the arithmetic/structure level but are *conditional* on
(i)/(ii); items (i), (ii), (v-F8), (vi) require human/cryptographer discharge. **No item is blocked by
an off-envelope or non-standard-field hazard** — a structural difference from Arm A, whose O1
(Poseidon STATE over GF(p²)) is such a hazard. In short: **Arm B's sign-off is the same gate as Arm
A's; the items differ because Arm B operates over a standard prime field.** Whether each item actually
discharges is the reviewer's determination, not asserted here.

Functional evidence on file (NOT soundness): value-level Poseidon2 KAT (3 vectors, one byte-identical
to Plonky3's published production-constant vector — third-party anchor, F6 resolved); in-circuit
gadget == value-level (32 inputs) + 5 corruption rejections; wide-sponge digest == reference (all
lengths) + 3 corruption rejections; Merkle path roundtrip (depths 1–8) + 4 corruption rejections;
membership unlinkability-across-ctx / linkability-within-ctx + 5 corruption rejections; transparent +
ZK prove→verify roundtrips.
