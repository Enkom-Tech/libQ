# Cryptographer sign-off register (repo-wide RED items)

> **RED — every entry below awaits human cryptographer sign-off.** No item here carries a "secure"
> claim. Constructions are built and self-reviewed (estimators run, adversarial self-review, KATs) but
> **none is proven or signed.** This register is the single index of what a two-human cryptographic
> review must discharge before any of these can be called secure, wire-frozen, or wired downstream.
> Self-review has repeatedly caught real defects in these constructions; that does not substitute for
> sign-off.

**Five** independent sign-off gates are open. Each has its own detail docs; this file states the
**blocking claim**, the **status**, and the **concrete open item** per gate, with load-bearing numbers.

| # | Gate | Crate(s) | Detail docs | State |
|---|------|----------|-------------|-------|
| A | Anon-cred one-out-of-many membership | `lib-q-lattice-zkp` | `lib-q-lattice-zkp/docs/anon-cred-oom-signoff-brief.md` (+ 7 companions) | design + test-only oracles |
| B | Membership AIR soundness/ZK (Arm A + Arm B) | `lib-q-zkp` | `lib-q-zkp/docs/membership-adr113-freeze-gate-review.md`, `…-arm-b-obligation-packet.md`, `…-arm-{a,b}-soundness-params.md` | built + wire-frozen v0 |
| C | Threshold-KEM CCA closure + its ZK encryption proof | `lib-q-threshold-kem-lattice`, `lib-q-zk-encryption-proof` | `lib-q-threshold-kem-lattice/SECURITY-STATUS.md` (shipped summary), those crates' `README.md` / `src/lib.rs`, `dev/conformance/…` design docs | KEM shipped (KAT v1); proof partial |
| D | Saturnin CTX committing transform (H-1, S-2, Q-1, L-1, RK-1) | `lib-q-saturnin` | `lib-q-saturnin/src/commit.rs`, `src/aead_ctx.rs`, `src/qcb.rs`, `SECURITY.md` | **shipped and reachable** — opt-in `SaturninAeadCtx` / `SaturninQcb` |
| E | CTR-Cascade's own IND-qCCA claim (Q-2) | `lib-q-saturnin` | `lib-q-saturnin/src/aead.rs` §"Open obligation Q-2", `README.md`; card `t_1af26ff2` | **shipped, frozen wire, reached by every product** |

> **Gate E was promoted out of a footnote on 2026-08-11, and the promotion is the point.** Q-2 was
> recorded only as one clause inside Gate D's S-2 bullet ("A third, **Q-2**, lands on the base
> CTR-Cascade mode…"), while this table described Gate D as "the only gate on a default-feature code
> path". Both were wrong in the same direction: Q-2 lands on **`SaturninAead`**, whose wire is frozen
> and which *every* product decrypts through (GIP, uGrid, My-Grid, Bitlink), whereas Gate D's own
> subjects — `SaturninAeadCtx` and `SaturninQcb` — are opt-in types (and `qcb` was removed from
> default features in `c1d27a6`). A reviewer triaging by this table would have ranked the most
> broadly-reachable open item as an aside. Q-2 is also **not** part of Gate D: Gate D is about a
> transform we added, Q-2 is about the mode as its designers published it.

---

## Gate A — Anon-cred one-out-of-many membership (`lib-q-lattice-zkp`)

**Blocking claim.** A log-size lattice one-out-of-many membership proof (Groth–Kohlweiss selector fold
over `R_q = Z_q[X]/(X²⁵⁶+1)`, `q = 8380417`, on the shipped ABDLOP substrate) is knowledge-sound,
binding, and HVZK-unlinkable at parameters fitting a 160 KiB presentation budget.

**Status.** Full protocol equations + extractor + simulator drafted; six of seven residuals
**argued-conditional**, each with ≥1 real defect found and fixed during self-review. Artifacts are
**test-only oracles + design docs**, consumer-agnostic, held on the never-merged branch
`spike/anon-cred-oom-red` (never on `main` — see "What signed off requires" below).

**The single reviewable packet:** `anon-cred-oom-signoff-brief.md` — it gathers the six results and
their open lists. Do not review the sub-docs cold; start there. The load-bearing open items it
consolidates:
- **Three distinct estimator runs owed (do not merge).** They must stay separate; do not collapse
  them into one sweep.
  - (1) binding M-SIS at the *final* `β_SIS` (set by the mandatory `Π_norm` + the RO-drawn
    `‖c̄‖_op` p99.99≈34 tail, NOT the honest `≈3.5e5`). **RUN, PASSES.** Every finite cell clears
    128-bit under every model; lowest ADPS16 = 136.9 bits at `κ_c=4, w_c=14`. That is a ~9-bit
    margin, thin enough that a later parameter change must re-run this rather than assume it. Two
    cells at `‖c̄‖₁ = 78` are reported BROKEN rather than infinite, which is correct: a bound
    `≥ (q−1)/2` is trivially satisfiable, i.e. no security, not unbounded security.
  - (2) small-secret **decision-LWR** for the nullifier at sample ceiling `κ_nf·N·#realms`.
    **RUN, FAILS AT THE CANDIDATE PARAMETERS, fix identified and estimator-verified.** See card
    `t_c972f73f`. At `κ_nf·d_κ = 1` (secret dimension `n = 256`) security collapses once more than
    one realm exists: ADPS16 82.3 bits at `α=4096` and 95.5 at `α=8192`, against 278–539 bits at
    `#realms = 1`. The sample count saturates by `#realms ≈ 4`, so the plateau is the operative
    number and adding realms past that costs the attacker nothing further. Since the nullifier
    exists to give per-realm unlinkability, single-realm is not a real configuration and the
    failing rows are the operative ones.
    Raising the rounding step alone does NOT fix it: `α=24576` still gives only 122.9 bits.
    Doubling the nullifier secret dimension does, with room to spare: `κ_nf·d_κ = 2` (`n = 512`)
    gives ADPS16 **221.0** / MATZOV 238.2 at the existing `α=8192`, and 275.6 / 289.5 at
    `α=24576`, unchanged from `#realms = 4` to `#realms = 100`.
    **This is a proposal, not an applied change** — the construction lives on the never-merged
    branch, so nothing has been edited into it. Gate A must not be signed until the design fixes
    `κ_nf`, `d_κ` and `α` explicitly; all three are currently UNDETERMINED in the source docs,
    which is why the run had to sweep candidates at all.
    Known gap in that run: an estimator-version crash silently drops the `dual` sub-attack from
    the `Kyber` cost-model column only. MATZOV and ADPS16, the columns the verdict rests on, are
    unaffected.
  - (3) **M-LWE on the credential matrix `A_c`** hiding the fold objects (distinct from the
    326-bit proof-system Ext-M-LWE). **STILL OWED.**
- **Assumption I1** (issuance yields exact short openings) — load-bearing for single-difference binding.
- **Proofs:** §6 one-first-order-layer completeness; the `(k+1)`-Vandermonde binding + forking
  accounting; `Δ_reject` as a *proven* Rényi/statistical bound; LNP22 `Πquad/Πlin/Πsim` composition.
- **Protocol additions to confirm (already edited in):** `Π_norm` on `(r_ℓ,m_ℓ,a_j)`; `(V-link) +W_γ`;
  `z_γ` uniform-mask; `Ĉ` round-1 + `(V-tie)`; `nf := HighBits` via `Decompose` with `α|(q−1)`.
- **Phrasing:** per-realm privacy (unlinkability across realms / among distinct creds in a realm).

---

## Gate B — Membership AIR soundness + ZK (`lib-q-zkp`, Arms A & B)

**Blocking claim.** Two STARK/FRI membership proofs for the frozen statement
`libq.zkfri.membership.v0` (`MerkleVerify(root,L=H(t),path) ∧ N=H(domain‖t‖ctx)`, revealing only
`(root, ctx, N)`) are 128-bit sound and zero-knowledge. Both arms are RED; Arm B does **not** inherit
Arm A's obligations.

**Status.** Circuits built, wire v0 frozen; commitment-layer bit-counts computed; hash algebraic-
security and the ZK simulators are **argued or implemented-but-unwritten**, not proven.

**Soundness parameters to cite (PCS/commitment-layer only — assume AIR sound+complete, which is RED):**
- **Shared binding term:** SHAKE256 Merkle commitment → 128-bit collision (Cat-2); `num_queries=96`,
  `PoW=20`. Reproduce via `lib-q-zkp/tools/fri_soundness.py`.
- **Arm A:** value field `Complex<Mersenne31>` = GF(p²), p=2³¹−1; challenge field GF(p⁶) (≈186 b);
  `log_blowup=3`; AIR degree 5 (`x⁵`). Overall **128** (Johnson provable 164 / capacity-conj
  308c·298pq / SHAKE 128).
- **Arm B:** BabyBear p=2³¹−2²⁷+1; challenge field `F_{p⁵}` (≈155 b); `log_blowup=4`; AIR degree 7
  (`x⁷`); Poseidon2 t=16, R_F=8, R_P=13, sponge rate 7 / capacity 9 / digest 9. Overall **128**
  (Johnson provable 212 / capacity-conj 404c·394pq / sponge-collision 139 / SHAKE 128).
- PQ model = mainstream QROM (FS preserves RBR soundness; Grover halves only the PoW grinding 20→10;
  SHAKE256 Cat-2, BHT collisions not counted). Max-conservative model rejected (documented).

**Open items the human owes:**

*Arm A (obligations O1–O4):*
- **O1 [blocking] — Poseidon-256 round security over GF(p²):** prove 8 full + 60 partial, `x⁵`,
  width 7 resist Gröbner/interpolation/higher-order-diff at ≥128 bits **over the extension field**
  (off the standard prime-field envelope). *Argued* (§7 derivation; subfield-invariance closed via
  generic nonzero-imaginary round constants). Owes: confirm the constant-genericity subfield defense +
  its base-field-only Cauchy-MDS dependency; accept residual re future cryptanalysis.
- **O2 — capacity-5 truncated-sponge collision/2nd-preimage ≥128:** *argued* (155-bit), conditional on
  O1 (sponge-indifferentiability premise = O1's PRP).
- **O3 — domain-separation adequacy** (baked 2-cell domain, `domain‖t‖ctx` ordering, no leaf↔nullifier
  cross-collision): *argued*, conditional on O1/O2. Owes: confirm global domain-string uniqueness.
- **O4 [blocking residual] — formal ZK simulator:** PPT simulator from `(root,ctx,N)` for the AIR +
  HidingFriPcs/salted-MMCS/Kt128Rng over GF(p²). Mechanism *implemented* (L1 weak-RNG + L2 guessable-
  seed leaks fixed in code); **no formal write-up**. Owes: write the simulator; close the masking-
  degree ≥ `#queries(100)+#OOD+1` vs opening-count budget at `log_blowup≥3`; re-confirm 5-of-7
  truncated openings leak nothing.
- (O5 depth-confusion guard, O6 canonical byte-decode: closed in code, confirm cross-check.)

*Arm B (obligations (i)–(vi)):*
- **(i) [RED] round counts R_F=8, R_P=13 at α=7, t=16 resist attacks at 128:** *argued* (matches
  deployed Plonky3/SP1 verbatim, constant-KAT anchored); count script **not** independently re-run.
  Owes: confirm against ePrint 2023/323 for the 128-bit target; confirm 128-vs-100 intent; `x⁷` forced.
- **(ii) [RED] MDS / internal diagonal over width 16 (no subspace trails):** *argued* (canonical
  values, cross-checked); irreducibility check **not** re-run for width 16. Owes: re-run or cite upstream.
- **(v) domain-separation constant derivation (F8):** off-circuit choice, soundness-neutral,
  **untouched**. Owes: decide in-family Poseidon2 vs K12-derived (string frozen either way).
- **(vi) [RED] ZK simulator** for this AIR (incl. row-0/ungated rows) under Hiding PCS/MMCS/Kt128Rng:
  mechanism *implemented + roundtrip-tested*, **no formal simulator**. Owes: write it; confirm ungated
  leaf/nullifier rows (hashing a zero preimage) leak neither `t` nor `ctx`.
- ((iii) capacity-9 collision ≈139, (iv) 9-cell digest ≈278: GREEN arithmetic, conditional on (i)/(ii);
  confirm (iv)'s wide-squeeze read is indifferentiability-acceptable.)

---

## Gate C — Threshold-KEM CCA closure + ZK encryption proof

Two crates, one gate: the KEM's remaining CCA boundary and the proof that would close it
assumption-free.

### C1 — `lib-q-threshold-kem-lattice`

**Blocking claim.** No formal threshold IND-CCA theorem: an inside coalition probing with **malformed**
ciphertexts can defeat per-partial flooding by amplification (~63 queries), because the FO⊥
re-encryption check fires only at `combine`. Security is conditional on a chosen-ciphertext **closure**
being in force.

**Status.** PROVISIONAL / unsigned. Core KEM built + hardened (branchless codec, structural guards,
zeroization, NTT accumulation, KAT-frozen v1 wire; adversarially self-reviewed 2026-07-10). Estimator-
gated, no human sign-off, no CCA theorem.

**Load-bearing numbers.** Ring `R_q=Z_q[X]/(X¹⁰²⁴+1)`, `q≈2⁴⁸`, MU=6, KAPPA=9. Dec-key hiding
(recover `r` from `t0=B0·r`): **M-LWE 169-bit quantum core-SVP, β=636**. Ciphertext hiding: distinct
M-LWE, n=6144, uniform error, easiest swept point **≈2⁹⁷¹ rop**. Noise worst-case `≈2⁴⁴` vs `q/4≈2⁴⁶`
⇒ FO decryption-failure **δ=0**. Flooding `2⁴⁰` per partial; enc-error bound `2²⁰`.

**Open item.** Sign off on the closure. Two offered: (i) *deployable* — authenticated encapsulator +
enforceable `DecapBudget` (`untrusted()` capped below the ~63-query probe; `authenticated()` = 2²⁰
budget) + DKG key rotation; (ii) *assumption-free* — the ZK proof in C2. Sign-off must confirm a
norm-only well-formedness proof is genuinely insufficient (the `f=δ·unit_k`, `‖f‖=1`
direction-not-magnitude argument) and that the deployed closure is sound.

**Two 2026-08-11 changes a reviewer should know about, neither of which discharges anything.**

1. `lib-q-threshold-kem-lattice/SECURITY-STATUS.md` (`44925ed`) is a **shipped** one-page summary —
   it is inside the published crate, verified via `cargo package --list`, unlike the
   `dev/conformance/…` treatment, which crates.io and docs.rs never see. Start there. It states the
   position (provisional, missing result named), answers the "does a masked partial leak the share"
   question in full (no under honest ciphertexts, **yes** after ≈63 malformed ones), and gives the
   migration deltas off the withdrawn `lib-q-threshold-kem`. **Caveat on the honest-ciphertext half:
   its LWE argument is heuristic-by-domination — no dedicated estimator run exists for the
   dimension-9216 instance.** That is a gap a reviewer may want closed.
2. `0575c11` publishes the BDLOP coefficient commitments (`KeygenSharesOutput::
   coefficient_commitments`) and carries the DKG's per-party verification keys across the crate
   boundary (`share_verifiers_from_dkg`). Before it, both were discarded, which meant *verifiable*
   partial decapsulation was impossible for a non-cryptographic reason: a verifier had no public
   value binding a `PartialDecap` to a party's share, so the statement a proof would prove had no
   public input. The crate still verifies nothing; this only makes the statement expressible. The
   v1 wire (`ThresholdKemLatticePublicKey`) is unchanged, with a test asserting so.

### C2 — `lib-q-zk-encryption-proof`

**Blocking claim.** A ZK-STARK PoK-of-`µ` for `R_enc` (knowledge of `µ` with
`(e,f,g)=Expand(SHAKE256(seed‖pk_digest‖µ))`, `p=B0ᵀe+f`, `v=⟨t0,e⟩+g+encode(µ)`) is sound **and**
zero-knowledge — forcing the ciphertext noise pseudorandom so the C1 probe cannot be aimed. Explicitly
**RED/unsigned, not production-ready.**

**Status — 2026-08-08, card `t_a73aaed2`: the R3 relation this gate reviewed was VACUOUS, and has
been replaced.** Everything the previous version of this entry said about fold soundness (the
Schwartz–Zippel `(2N−2)/q ≈ 2⁻³⁷` per point, `m=4 ⇒ ≤2⁻¹⁴⁸`, the shared FS `ζ`, the `µ↔sponge
transitive binding`) described a construction that proved nothing. It is retained below only as the
record of what was refuted.

**What was wrong.** Each R3 relation lifted the ring identity to `Z_q[X]` as `D(X)=H(X)·(X^N+1)` and
checked it at `ζ = SHAKE(pk_digest‖ct)`. `H` was a FREE prover-chosen coefficient column committed
*after* `ζ` was fixed by the statement, entering with the nonzero public coefficient `−(ζ^N+1)`, so
`H(ζ) := D(ζ)/(ζ^N+1)` satisfied the relation for ANY ciphertext. Not grindable — **vacuous**.
Schwartz–Zippel never applied: it needs the polynomial fixed BEFORE the point is drawn. Confirmed by
exploit at every tier including the "complete closure" tier at production FRI parameters, at `m=1`
AND `m=3` (each challenge carried its own free fold, so `m` bought nothing). Two further operands of
the same class were also free and are also closed: tier 1's `g` fold, and `EncodeMuFoldAir`'s 256
µ-bits — the latter allowed an **arbitrary malformed `v`** via a subset-sum, since
`⟨encode(µ),κ⟩ = ⌊q/2⌋·Σᵢ µᵢκᵢ` is linear with public coefficients and `κ` is known before `µ` is
chosen. "Boolean-constrained" is not "bound".

**What replaced it (main @ `d023856`).** The quotient is deleted. The already-reduced residual is
tested with a public random linear functional `⟨D, κ⟩ = 0`, `κ` drawn from the statement; the
negacyclic identity `⟨u ⊛ w, κ⟩ = Σ_b w_b·ψ_b` makes the public `t0`/`B0` side collapse into
per-coefficient public multipliers `ψ`, so the relation is a linear form over coefficient columns the
byte-provenance COEFF buses already pin. `HornerFoldAir → DotFoldAir` (`acc + w·ψ`, `ψ` in a
**verifier-rebuilt preprocessed** column). New `mu_bits` limb→bit bridge + `MU_LIMB_BUS`/`MU_BIT_BUS`
binds the encode fold's µ to the sponge preimage. `derive_zetas`, both `*_quotient_poly`, both
`*_public_coeffs`, `horner_public_values`, and the whole `prove` module are DELETED, not deprecated.
103 tests green (98 fast + 5 heavy at production FRI params, incl. the full tier at `m=3` and the
hiding-FRI path); clippy/no_std/fmt clean. **Still RED — no cryptographer has reviewed any of it.**

**Load-bearing numbers (revised).** Per-challenge soundness of the new relation is claimed at
`≤ 2/q ≈ 2⁻⁴⁷` over `(κ, ρ)` — 1/q that the ρ-combination cancels a nonzero `⟨D_j,κ⟩`, plus 1/q that
every `⟨D_j,κ⟩` vanished — so forging costs `≈ (q/2)^m`, `m=3 ⇒ ≈2¹⁴¹`. **This bound is unreviewed
and is open item (1) below.** Unchanged: `R_enc` sufficiency (grinding `µ` to steer `f` infeasible at
≈2⁻¹¹⁰⁰⁰/draw); the STARK config (Mersenne31, GF(p²) value field, GF(p⁶) challenge field,
`log_blowup=2`, `num_queries=64`, `pow=16` ⇒ ≈128 *conjectured*); ring `q=2⁴⁸−2¹⁴+1`, `N=1024`,
`MU=6`, `KAPPA=9`; `κ`/`ρ` rejection-sampled (bare mod-q biases ≈2⁻³⁴).

**Open items for a reviewer.**
1. The Fiat–Shamir / grinding bound in the (Q)ROM: is the `2/q` per-challenge union bound the right
   shape, and is it tight? Does `(q/2)^m` correctly capture a prover who grinds `ct`?
2. `κ ⊥ ρ` independence. Both are rejection-sampled from the same statement `(pk_digest ‖ ct)` under
   separated domain tags (`DOM_KAPPA`, `DOM_RHO`). The bound treats them as independent draws.
3. **The verifier-rebuilt-preprocessed obligation, now load-bearing for soundness rather than only
   for the sponge round constants.** Every fold's public multiplier `ψ` lives in a preprocessed
   trace; if a verifier reuses the prover's preprocessed `CommonData` the prover chooses the linear
   functional and every relation is vacuous again. `ψ` is public so non-hiding leaks nothing, but the
   ZK path currently reproduces the hiding commitment by restarting the MMCS RNG at a fixed seed — a
   deployment wanting genuinely random witness blinding needs preprocessed under a separate
   non-hiding sub-commitment. `build_preprocessed` is a TEST helper, so this is a caller obligation.
4. That the negacyclic sign table in `corr_negacyclic` equals the KEM's own ring multiplication.
   Cross-checked in-tree at `N=1024` against a real ciphertext, but by the same author as the code.
5. Confirm randomized-trace + hiding-PCS actually hide `µ` and all `(e,f,g)` (sponge first-block
   bytes 70..102 = `µ` must be blinded) — carried over unchanged from the previous review list.
6. State the *provable* STARK bound in any claim, not the conjectured 128 — carried over unchanged.

**Refuted, retained as the record of what this gate used to say:** fold (Schwartz–Zippel) soundness
`≤ (2N−2)/q ≈ 2⁻³⁷` per point with `m=4 ⇒ ≤2⁻¹⁴⁸`; "`µ↔sponge` transitive binding"; and the claim
that the `Z_q` toolkit was "self-reviewed-sound + fuzzed, zero survivors". The fuzzing was real and
found no *implementation* bugs; the defect was in the protocol the AIRs correctly implemented, which
is precisely the class fuzzing cannot reach.

---

## Gate D — Saturnin CTX committing transform (`lib-q-saturnin`)

**Read this one and Gate E first if you have limited reviewer time.** Gates A–C guard constructions
that are either branch-only, wire-frozen-but-unwired, or partial. Gates D and E guard code that
**ships and is used by real products** (GIP, uGrid, My-Grid and Bitlink all reach Saturnin through
`SaturninAead`) — the two gates where an unsound assumption is already in someone's hands.

Between them, **Gate E is the more reachable**: its subject is `SaturninAead` itself, which every
one of those products decrypts through. Gate D's subjects, `SaturninAeadCtx` and `SaturninQcb`, are
opt-in types, and `qcb` is no longer a default feature (`c1d27a6`). This paragraph previously called
Gate D "the only gate on a default-feature code path", which under-ranked Gate E.

**Blocking claim.** `T' = SaturninHash(label ‖ K ‖ N ‖ T ‖ A)` — the CTX transform (Chan and
Rogaway, *On Committing Authenticated-Encryption*, ESORICS 2022 / ePrint 2022/1260, Fig. 2 / Thm 2) —
gives CMT-4 committing security to `SaturninQcb` and to `SaturninAeadCtx` (CTR-Cascade), bounded by
Saturnin-Hash's collision resistance.

**Status.** Both instantiations are **built, tested and shipped**. `SaturninQcb` closes a
*demonstrated* CMT-1 break (a ~2⁸ padding search plus a closed-form associated-data solve costing 6
block calls; the attack is retained verbatim in `tests/key_commitment.rs` and now asserts failure).
`SaturninAeadCtx` (commit `f7ce5e2`) is a separate opt-in type, because `SaturninAead` already
encrypts stored data in shipped products and changing its tag would render those blobs
undecryptable; `tests/aead_kat_pin.rs` freezes its wire format. **Nothing here is proven.**

**The three obligations.**

- **H-1 — is the published bound the right one?** The transform inherits Saturnin-Hash's collision
  resistance, and the designers *claim* rather than prove `2^112` classical / `~2^75` quantum. The
  quotes are verified current: the hash claim box is byte-identical across spec v1, spec v1.1 and the
  ToSC published version, and the `~2^75` is the designers' own derivation (ToSC line 756: "we
  necessarily have `Mq < T`", so `T⁵·Mq < 2^448` becomes `T⁶ < 2^448`). Best published cryptanalysis
  leaves wide margin: classical hash collision 6 of 32 rounds at `2^112`, quantum 7 of 32 at
  `2^113.5`, free-start 8 of 32. **A cryptographer must still accept the designers' claim as a bound
  to publish.** Not closable by citation.
- **S-2 — does CTX's Theorem 2 apply to our base schemes?** Thm 2 assumes the base scheme's core `C`
  has the same length as `M`. **Does not apply to `SaturninAeadCtx`**: CTR-Cascade XORs a keystream,
  so `|C| = |M|` natively and the hypothesis holds. **Still open for `SaturninQcb`**, whose `10*`
  padding makes `|C| ≠ |M|`; the argument that injectivity suffices has not been reviewed.
  **CORRECTION 2026-08-07 (the papers were obtained and read): S-2 is NARROWED, and it is NOT
  closable by citation.** The old line here — "Likely closable by citation to Bellare–Hoang
  (ePrint 2022/268 …; 2024/875 …), whose tag-based definition carries no length relation" — is
  false as to **2022/268**, which contains zero occurrences of "CTX", zero of "tag-based", and
  does not cite Chan–Rogaway at all. And **2024/875's Theorem 3.3 is about CTY, not CTX** — the
  authors explicitly "omit a statement and proof about the security of our general form of CTX
  because we are going to improve it to CTY" (p.12). What actually narrows S-2 is proof
  inspection of Chan–Rogaway themselves: `|C| = |M|` appears only as the premise of an inference
  *to* bijectivity, and Theorem 2's proof consumes only injectivity ("there exists only one `M`
  such that `E1(Ki, N, A, M) = C`", p.10; restated by the authors at p.2–3 and p.4). That is an
  argument a cryptographer must confirm, not a citation. Full write-up, plus a *second* violated
  Chan–Rogaway requirement (constant expansion `τ`, immaterial to Theorem 2 but **not** to
  Theorem 3): `lib-q-saturnin/src/commit.rs`. Two further obligations opened the same day:
  **L-1** (Theorem 3 is single-user and single-verification-query — 2024/875 p.12; both
  instantiations) and **RK-1** (`SaturninQcb` only). A third, **Q-2**, is **not part of this gate**
  — it is about the base CTR-Cascade mode as its designers published it, lands on the frozen
  `SaturninAead`, and is now **Gate E** below.
- **Q-1 — does CTX preserve Q2 security?** CTX's nAE-preservation proof (Thm 3) is in the *classical*
  random-oracle model, and `SaturninQcb` exists specifically for superposition-query security.
  **Expect this to get worse, not better:** ePrint 2025/387 shows Q2 security is not automatically
  preserved under composition, and the hypothesis its counterexample breaks (plus-one unforgeability)
  is what QCB's own integrity proof delivers. ePrint 2023/1653 proves QCB blindly unforgeable, which
  may or may not rescue the composition.

**Three things a reviewer must not miss.**

1. **Any QCB security sentence we publish is an ideal-cipher claim.** QCB's TBC is tweak-rekeyable,
   `E(K ⊕ T, x)`, and Mennink (ePrint 2017/474, CRYPTO 2017) *proves* the impossibility of a
   standard-model optimal-security proof for that class.
2. **QCB's usage exceeds the qualifier on the claim it relies on.** The Saturnin spec says Saturnin16
   resists related-key attacks "involving **a small number of keys**"; QCB uses up to `2^95` tweaks,
   each a distinct related key. The spec separately states Saturnin "**does not provide security
   against related-key superposition attacks**" — while QCB is a related-key construction built for
   superposition security. Both qualifiers survive verbatim into the peer-reviewed ToSC version.
3. **The related-key margin is thinner than the hash margin.** The designers' own Note-RK-1 gives a
   10-of-16-super-round related-key attack at `2^236`. The published trail cannot be mounted through
   QCB's tweak interface (our tweak forces one nibble slot of every key word to zero, and every
   nibble of the trail's four active values is nonzero), but **≥65,025 admissible alternative tuples
   are reachable**, and a constrained optimum only 6.7 bits worse than the published one would still
   work. That computation has not been done. See card `t_5d1460b7`.

**Mitigations already taken, so a reviewer knows the blast radius.** `qcb` was removed from the
crate's default features (`c1d27a6`) — it is nonce-catastrophic and has zero consumers. The tweak's
byte 16 was corrected to the `10*` pad bit (`c43689d`) while the hardware was still at trace design.

---

## Gate E — CTR-Cascade's own IND-qCCA claim (`lib-q-saturnin`, obligation Q-2)

**Read this one alongside Gate D, and note which is more reachable.** Gate D guards a transform
*we* added, on opt-in types. Gate E is about `SaturninAead` — the base CTR-Cascade mode, as its
designers published it — whose wire format is **frozen** and which every product decrypts through
(GIP `bitlink-wrapkey-argon2id-v1`, My-Grid vault, My-Grid recovery, uGrid). `SaturninAeadCtx`
inherits it, since CTX wraps this mode rather than replacing it.

**Nothing here says the mode is broken.** It says the published *argument* for one of its advertised
properties has a hole, and that the repair is available but unratified.

**Blocking claim.** The Saturnin submission claims IND-qCCA security for Saturnin-CTR-Cascade
(§2.2 / §4.3) and argues it at §4.3.1 via a result of Soukharev–Jao–Seshadri \[SJS16\]: that an
IND-qCPA-secure scheme composed with a quantum-secure MAC yields IND-qCCA. **IACR ePrint 2025/387
(Lang, Leuther, Lucks) disproves exactly that implication** — it exhibits an IND-qCPA scheme and a
plus-one unforgeable MAC whose encrypt-then-MAC composition is IND-qCCA\[LoR\] *insecure*.

**Status.** Open, unratified, shipped. No code change is available or appropriate: the wire is frozen
and the mode is not known to be broken.

**The repair, and why it is not self-evident.** 2025/387's own **Theorem 3** gives IND-qCCA for the
EatM composition when the encryption is IND-qCPA\[LoR\] and the MAC is a **qPRF** — strictly stronger
than the hypothesis shown insufficient — carried to EtM by its **Theorem 4** and **Corollary 1**. The
Saturnin spec does argue the qPRF property separately (§4.3.3, citing Song–Yun Thm 5.1). So the
conclusion looks recoverable by a citation swap. **Whether Saturnin's §4.3.3 argument actually
discharges 2025/387's hypothesis is the open question, and nobody has ratified it.** The spec's own
hedging on tightness ("seems not tight") is part of what a reviewer must weigh.

**Open item.** Ratify or refute the citation swap. If it goes through, the claim stands on a
different footing and the docs should say so. If it does not, the honest statement is that
CTR-Cascade's IND-qCCA claim is **unproven**, and every restatement of it in this repo must be
corrected. Classical AE security is unaffected either way.

**What is already enforced while this is open.** `scripts/ci-guard-standards-claims.sh` fails CI if
`IND-qCCA` appears anywhere outside `lib-q-saturnin/`, so the claim cannot leak — into a crate
description, an npm blurb, or another crate's README — separated from the caveat that accompanies it
there. That guard was observed failing against a deliberate fixture before being trusted. It is a
containment control, **not** a resolution.

---

## What "signed off" requires (all gates)

For each gate, two independent human cryptographers must: accept the stated assumptions, confirm the
estimator instances at the **deployed** parameters (not the draft numbers), and check the soundness/ZK
proofs actually exist and compose. Until then every gate stays RED — test-only where noted, wire-frozen
but unsigned where noted, and **not** to be advertised as secure. Gate A additionally must not be
**merged to `main`** or wired downstream until signed.

This previously read "must not be committed". That was reworded, not relaxed: leaving ~3,800 lines
of drafted protocol on a single machine's working tree is itself a risk (unbacked, and it blocks
clean gating in `lib-q-lattice-zkp`), and it is not what protects `main` from unsigned crypto —
*not merging* is. The work is therefore preserved on the never-merged branch
`spike/anon-cred-oom-red`. The no-reachability property is structural, not a promise: every Gate A
module carries an inner `#![cfg(test)]` **and** is declared `#[cfg(test)] mod` (private, not `pub`)
in `sigma/mod.rs`, so no shipped build and no downstream crate can name them. Merging that branch,
or making any of those modules `pub`, is the thing the gate forbids.

---

## CORRECTION (appended 2026-08-04, release/0.0.10 @ 2f0d43c, by post-hoc triage of `spike/anon-cred-oom-red`)

This file was recovered verbatim (byte-for-byte, `git show spike/anon-cred-oom-red:docs/crypto-signoff-register.md`)
from the never-merged spike branch, where it was the only copy in the repo (absent from `main`,
`release/0.0.10`, and `wip/pvtn-v1-construction7` before this recovery). The body above is
unedited. This note records what was checked for staleness against `release/0.0.10` and what a
reader should know before following its links from *this* tree.

**Gate A doc/module paths do not resolve in this tree — by design, not by rot.** The register's
Gate A row and detail-packet reference (`lib-q-lattice-zkp/docs/anon-cred-oom-signoff-brief.md`
+ companions) are branch-relative to `spike/anon-cred-oom-red`. OBSERVED:
`git ls-tree release/0.0.10 -- lib-q-lattice-zkp/docs/` returns exactly one file,
`pvtn-v2-unlinkable-membership.md` — none of the nine `anon-cred-oom-*.md` docs (`-binding`,
`-bounding`, `-hvzk`, `-invariant`, `-nullifier`, `-obligations`, `-protocol`, `-signoff-brief`,
`-spike`) are present. Correspondingly `git show release/0.0.10:lib-q-lattice-zkp/src/sigma/mod.rs`
has no `binary_range`, `nullifier_consistency`, or `one_out_of_many` module declarations — those
three source files simply don't exist on `release/0.0.10` (`git ls-tree spike/anon-cred-oom-red --
lib-q-lattice-zkp/src/sigma/` has 12 files where `release/0.0.10` has 9). This is the intended
state per the closing section above ("preserved on the never-merged branch") and per this
release's triage of the same branch (see the commit-by-commit classification: only `facfc87`, the
spike commit itself, was withheld — everything recoverable from the other nine commits already
landed by other routes). It is flagged here only so a reader on `release/0.0.10` who clicks these
links knows to look on `spike/anon-cred-oom-red`, not to conclude the docs were lost.

**Minor: Gate C2's "README.md / src/lib.rs" reference.** `lib-q-zk-encryption-proof/README.md`
does not exist on `release/0.0.10` (`git cat-file -e` fails: "does not exist in
'release/0.0.10'") — OBSERVED it also does not exist on `spike/anon-cred-oom-red` at the commit
this file was read from, so this is not new rot, just a standing overstatement in the original
text; `src/lib.rs` (which does exist on both) carries the design docs for that crate.

**Checked and found NOT stale (no correction needed):**
- All three other crates the register names — `lib-q-lattice-zkp`, `lib-q-zkp`,
  `lib-q-threshold-kem-lattice`, `lib-q-zk-encryption-proof` — exist on `release/0.0.10`
  (`git ls-tree -d release/0.0.10 -- <crate>` non-empty for each).
- All nine Gate B detail docs (`membership-adr113-freeze-gate-review.md`,
  `membership-arm-a-soundness-params.md`, `membership-arm-b-babybear-build-spec.md`,
  `membership-arm-b-build-status.md`, `membership-arm-b-measurement.md`,
  `membership-arm-b-obligation-packet.md`, `membership-arm-b-poseidon2-gadget-design.md`,
  `membership-arm-b-redteam.md`, `membership-arm-b-soundness-params.md`,
  `membership-wire-v0-FROZEN.md`) and `lib-q-zkp/tools/fri_soundness.py` resolve on
  `release/0.0.10`.
- Gate C's `dev/conformance/integration/lib-q-threshold-kem-lattice/*` design docs resolve
  identically on both `release/0.0.10` and `spike/anon-cred-oom-red`.
- The register does **not** name any of the four crates deleted this release cycle
  (`lib-q-threshold-sig`, `lib-q-double-kem`, `lib-q-threshold-kem` [distinct from
  `lib-q-threshold-kem-lattice`, which it does name and which is still present], `lib-q-fhe`) —
  `git ls-tree -d release/0.0.10 -- <name>` is empty for all four, and none of the four strings
  appear in the register body above. No dangling reference to a deleted crate exists in this file.

**Not checked in this pass (SUSPECTED-accurate, not verified):** the numeric claims themselves
(β_SIS, the M-LWE/M-LWR bit estimates, MU/KAPPA/ring parameters, the STARK soundness bit-counts) —
this correction only re-verified that named files, crates, and modules still exist and resolve to
the described structure, not that the underlying security-parameter arithmetic is still current.
Re-running the cited estimator scripts / `fri_soundness.py` against `release/0.0.10`'s actual
constants was out of scope for this recovery pass.
