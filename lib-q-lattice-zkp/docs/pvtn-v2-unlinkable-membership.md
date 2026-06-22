# PVTN V2 — cross-presentation-unlinkable membership (design)

> **Status: DRAFT — RED / research-grade. NO CODE MERGES from this design without a written,
> cryptographer-reviewed soundness/ZK argument and a RED sign-off recorded in the PR.** This document
> is the design-first deliverable that ADR 095 (pvtn-unlinkable-presentation)
> and HANDOFF-65 (pvtn-unlinkable-membership) call for
> *before* implementation. It is authored as a starting draft for the `lib-q-lattice-zkp` cryptographer
> to review, correct, and complete — not as a finished, self-attested construction. Audit 2026-06-17
> finding **#65**. Until landed and reviewed, #65 stays **descoped (trusted-realm-only)**.
>
> Authored against the crate at commit `9ed65ed` (worktree `feat/pvtn-v2-unlinkable`). Every
> file:line and API reference below was read from source, not assumed.

## 0. Reading order

1. §1 — the confirmed leak (what V2 must hide).
2. §2 — goal + threat model.
3. §3 — the existing building blocks we reuse (real API).
4. §4–§9 — the V2 construction.
5. §10 — wire + Fiat–Shamir transcript.
6. §11 — security-argument skeleton (the review gate).
7. §12 — answers to the four ADR-095 open questions.
8. §13 — parameters/performance; §14 — what is drafted vs review-gated; §15 — acceptance criteria.

---

## 1. The leak (confirmed against source)

`PrivateMembershipProof` ([`sigma/hierarchical.rs:359`](../src/sigma/hierarchical.rs)) and its verifier
`verify_private_membership` ([`hierarchical.rs:506`](../src/sigma/hierarchical.rs)) put the following
**stable-per-credential** values on the wire, all in cleartext:

| Field | Type | Leak |
|-------|------|------|
| `merkle_path.path_index` | `u32` | **leaf position**, in clear |
| `merkle_path.siblings` | `Vec<[u8;32]>` | sibling digests ⇒ co-locates credential in tree |
| `leaf_digest` | `[u8;32]` | identical across presentations ⇒ **linkable** |
| `clearance_level` | `u32` | exact level revealed (not just `≥ min`) |
| `role_tag` | `[u8;16]` | stable attribute, in clear |
| `parent_digest` | `[u8;32]` | stable attribute, in clear |
| `credential_com` | `AjtaiCommitment` | stable commitment (unless re-randomized) |
| `clearance_margin_witness_polys` | `Vec<Poly>` | coeff[0] = `clearance_level − min_clearance` in clear |

Two presentations of one credential therefore share `leaf_digest`, `role_tag`, `parent_digest`,
`path_index`, siblings, and (absent re-randomization) `credential_com` — trivially linkable, with leaf
position exposed.

**Key correction to the "just re-randomize" instinct (and to one ADR phrasing):** `CrtPackedNormProof`
is **not** zero-knowledge. [`norm.rs:9`](../src/sigma/norm.rs) defines it as
`{ slot_bounds: Vec<i32>, beta, max_norm }` where `slot_bounds[i] = ‖slot_i‖_∞` is the **exact** norm,
and `verify_clearance_margin_public` ([`hierarchical.rs:392`](../src/sigma/hierarchical.rs)) reads the
witness polynomial's `coeffs[0]` directly. So the current "margin proof" *reveals* `delta` exactly. The
V2 clearance proof **cannot reuse `CrtPackedNormProof`** — it needs a genuine ZK range argument (§7).
This settles ADR-095 open-question Q2: the answer is "no, it must be re-built for the hidden-attribute
setting."

---

## 2. Goal and threat model

**Goal.** A presentation reveals to the verifier *only*: "some credential whose leaf is in the tree
with public root `tree_root` has `clearance_level ≥ min_clearance`," plus whatever the application
explicitly discloses (e.g. a fresh per-session pseudonym/nullifier). It must hide: leaf identity, leaf
position, `role_tag`, `parent_digest`, the exact `clearance_level`, and any cross-presentation linkage.

**Preserve all v1 soundness:** membership in the public-root tree; `clearance ≥ min`; binding of the
credential opening; and (new, explicit) that `role_tag`/`parent_digest`/`clearance` all belong to the
*same* committed leaf (no mix-and-match across credentials).

**Adversary.** Malicious verifier (tries to link/deanonymize — defended by ZK/unlinkability); malicious
prover (tries to prove membership for a non-member or under-clearance credential, or to splice
attributes — defended by soundness/extractability). Network adversary sees only the wire. PQ adversary:
all hardness rests on Module-SIS over `R_q = Z_q[X]/(X^256+1)`, `q = 8 380 417` — **no classical
assumptions** (project hard floor).

---

## 3. Building blocks in `lib-q-lattice-zkp` (reused, real API)

| Primitive | Location | Role in V2 |
|-----------|----------|-----------|
| `AjtaiCommitment`/`AjtaiOpening`/`commit` | [`commitment.rs:19–59`](../src/commitment.rs) | credential commitment; node values are SIS images |
| Additive homomorphism `aggregate_opening`, `blinded_commitment` | [`blind.rs:604–625`](../src/blind.rs) | per-presentation re-randomization (§8) |
| `ModuleMatrix::expand_from_seed`, `mul_vec` | `lib-q-ring` `module.rs` | the SIS hash `A·x mod q` (§5) |
| `Poly` (256-coeff, `add_assign`/`scalar_mul`/`infinity_norm`) | `lib-q-ring` `poly.rs` | ring arithmetic; bit-vectors as low-norm polys |
| `prove_opening`/`verify_opening` (Schnorr+rejection, QROM-FS) | [`opening.rs:221,337`](../src/sigma/opening.rs) | credential opening leg; FS pattern to mirror |
| `prove_linear`/`verify_linear` (`L·wit ≡ t`, public `t`) | [`linear.rs:78,227`](../src/sigma/linear.rs) | building block, but see caveat below |
| `fs_w_digest`, `sample_in_ball`, statement-ctx binding | [`opening.rs:87–139`](../src/sigma/opening.rs) | V2 transcript (§10) |
| `SecretPolyVec`, `MaskedWitness` (hardened) | [`secrets.rs`](../src/sigma/secrets.rs) | Zeroize + first-order masking of witnesses |
| `CrtPackedNormProof` | [`norm.rs`](../src/sigma/norm.rs) | **NOT reused** — see §1/§7 |
| profiles (`pvtn_membership_v0`, ids) | [`profile.rs`](../src/profile.rs) | add `pvtn_membership_v2` |

**Caveat that forces a new protocol.** `prove_linear` proves `L·wit ≡ t (mod q)` for a witness behind a
*single* commitment with **public** `L` and `t`. Merkle membership with hidden intermediate nodes is a
*chain* of relations whose intermediate `t` (each interior node) is itself secret, and which selects
left/right by a secret bit. Neither hidden-`t` nor the branch selection is expressible as one
public-output linear relation. So the membership argument (§6) is a **new sigma protocol**, not a
reuse of `prove_linear`. (`prove_linear` is still reused inside the range proof's linear sum, §7,
where the output *is* public.)

---

## 4. Construction overview

Replace the SHAKE-Merkle tree (`node_hash = SHAKE256(0x01‖L‖R)`, [`hierarchical.rs:63`](../src/sigma/hierarchical.rs))
with an **algebraic SIS-Merkle accumulator** (§5) whose node compression is a linear-over-{0,1}
relation, so a sigma protocol can prove a path in zero knowledge. `PrivateMembershipProofV2` is then a
single combined argument over one witness:

```
witness  W = ( leaf attribute bits  x_attr   = bin(clearance ‖ role_tag ‖ parent_digest),
               leaf node value       u_leaf,
               sibling nodes          {s_i}_{i<d},  direction bits {b_i}_{i<d},
               interior nodes         {u_i}_{i≤d}  (u_0 = u_leaf, u_d = root),
               clearance margin bits  {δ_j}_{j<B},
               credential opening      (m, r) + per-presentation blind r' )
public   X = ( tree_root, min_clearance, opening_base_ctx, params/profile_id,
               re-randomized credential_com' )

statement(W;X):   (a) u_leaf = AccLeaf(x_attr)                              -- leaf commit
                  (b) ∀i<d:  u_{i+1} = AccNode(select(u_i, s_i; b_i))       -- path to root
                  (c) u_d = tree_root                                        -- ends at public root
                  (d) clearance(x_attr) − min_clearance = Σ_j δ_j 2^j, δ_j∈{0,1}, ≥ 0   -- range
                  (e) credential_com' = commit(m + 0; r + r'); (m) consistent with x_attr -- binding
```

No `leaf_digest`, no `merkle_path`, no cleartext attribute is on the wire; the verifier learns only
`X`. The four ADR sub-arguments map to: (a)+(b)+(c) = §6 membership; (d) = §7 range; (e) = §8 re-rand +
§9 attribute binding.

---

## 5. The algebraic accumulator (SIS-Merkle, Libert–Ling–Nguyen–Wang style)

**Nodes are binary vectors.** Following LLNW (EUROCRYPT 2016), keep every node a *bit-vector* so all
relations are linear over `{0,1}` and a Stern-type argument applies. Concretely, in this crate's ring
setting:

- A node is `u ∈ {0,1}^{m}` realised as a `ModuleVec` of `nk_acc` ring elements whose coefficients are
  all in `{0,1}` (low-norm). `m = 256 · nk_acc` bits.
- Public matrices `A0, A1 = ModuleMatrix::expand_from_seed(seed0|seed1, k_acc, nk_acc)` — derived from
  two domain-separated seeds pinned in the profile (reusing `ExpandA`, the same rejection sampler as
  `commit`).
- **Node compression** `AccNode(left, right)` for bit-vectors `left,right ∈ {0,1}^m`:
  ```
  v        = A0·left + A1·right                 (mod q)      -- v ∈ R_q^{k_acc}
  parent   = G⁻¹(v)  ∈ {0,1}^m                              -- gadget bit-decomposition of v
  ```
  where `G⁻¹` is the standard base-2 gadget decomposition (`m = k_acc·256·⌈log₂ q⌉`,
  `⌈log₂ q⌉ = 23` per `profile.rs::RQ_COEFF_PACK_BITS`) and the gadget matrix `G` satisfies
  `G·G⁻¹(v) = v`. The relation "`parent = G⁻¹(v)`" is captured by the **linear** equation
  `G·parent = A0·left + A1·right (mod q)` **plus** `parent ∈ {0,1}^m`.
- **Leaf compression** `AccLeaf(x_attr)`: encode the attribute bits `x_attr = bin(clearance(32) ‖
  role_tag(128) ‖ parent_digest(256))` (a fixed-width bit-vector) and set
  `u_leaf = G⁻¹(A_leaf · x_attr mod q)`, `A_leaf = expand_from_seed(seed_leaf, …)`. Same linear+binary
  shape.
- **Tree root** is the public bit-vector `u_root = u_d`.

**Why this shape:** every parent/leaf relation is now `G·u_out = A·(inputs) (mod q)` with all of
`u_out`, `inputs` binary. The *only* nonlinearity (left/right selection by `b_i`) is handled by the
Stern witness-extension trick (§6). The accumulator is **collision-resistant under Module-SIS**: a
collision yields two distinct short preimages of the same `v`, i.e. a short nonzero kernel vector of
`[A0 | A1 | −G]`, an SIS solution. (Argument detailed in §11.)

**Public, non-ZK part (fully implementable + testable now):** the accumulator hash, the gadget
`G`/`G⁻¹`, tree construction, and a *cleartext* membership check (the analogue of `verify_merkle_path`).
This is sound, deterministic, and KAT-pinnable independently of the ZK layer — it is implemented in
the companion `accumulator.rs` scaffold (§14).

---

## 6. ZK membership argument (Stern-type) — the NEW core

**This is the load-bearing novel protocol and the principal review target. It is specified here and
scaffolded in code, but its sound implementation is explicitly review-gated — do not treat the scaffold
as validated.**

**Statement (public):** `A0, A1, A_leaf, G, tree_root`, depth `d`.
**Witness (secret):** `x_attr`, `{u_i}_{i≤d}` (with `u_0=u_leaf`, `u_d=tree_root`), `{s_i}`, `{b_i}`.
**Relation:** `u_0 = G⁻¹(A_leaf·x_attr)` and for each `i<d`,
`G·u_{i+1} = A0·L_i + A1·R_i (mod q)` where `(L_i,R_i) = (u_i,s_i)` if `b_i=0` else `(s_i,u_i)`, and all
`x_attr, u_i, s_i ∈ {0,1}^*`, `b_i ∈ {0,1}`.

**Protocol = abstract Stern (3-move, 3-special-sound):**
- The branch selection `(L_i,R_i)=select(u_i,s_i;b_i)` is linearised with the standard LLNW extension:
  introduce `ũ_i = (b_i·u_i, (1−b_i)·u_i)` etc., so each level becomes a *fixed* linear relation
  `M_i · ext_witness_i = 0 (mod q)` over an extended binary witness, with the witness constrained to a
  public set `VALID` (bit-vectors of prescribed Hamming structure encoding "binary" and "exactly one
  branch chosen").
- **Commit:** prover samples a random permutation `π` over coordinate blocks and masking vector `ρ`;
  sends three SHAKE256 commitments `c1,c2,c3` to `(π, A·ρ)`, `(π(witness+ρ))`, `(π(ρ))` shapes (exact
  LLNW commitment triples).
- **Challenge:** `ch ∈ {1,2,3}` via Fiat–Shamir over the §10 transcript.
- **Response:** open two of the three commitments per `ch`; verifier checks the opened relation and that
  the revealed permuted vector lies in `VALID`.
- **Soundness error 2/3 per round** ⇒ run `t = ⌈λ / log₂(3/2)⌉ ≈ 171` parallel rounds (Fiat–Shamir) for
  `λ = 128`. This dominates proof size/time (§13). 3-special-soundness gives a knowledge extractor
  (§11). HVZK via the permutation+mask simulator (§11).

**Position hiding** is automatic: `b_i` and `s_i` are inside the witness, never revealed; the verifier
only ever sees permuted, masked openings.

**Alternative for a v2.1 (flagged, not for first landing):** a Lyubashevsky/Schnorr-with-rejection
"commit-and-prove" over Ajtai-committed intermediate nodes (relate two *committed* witnesses per level)
would shrink proofs from ~171 rounds to a constant-round rejection-sampled argument, à la later LLNW /
Yang-et-al. work — but it requires extending this crate's linear protocol from "public `t`" to
"committed-to-committed" relations and re-deriving soundness/abort bounds. **Recommend Stern first**
(well-understood, 3-special-sound, reuses only SHAKE + ring ops), optimise later. This is ADR-095
open-question Q1's answer: *SIS-Merkle with a ZK Stern path for the first sound version; a direct
shorter-witness accumulator is the optimisation track.*

---

## 7. ZK clearance range proof (replaces `CrtPackedNormProof`)

Prove `clearance − min_clearance = δ ∈ [0, 2^B − 1]` **without revealing `δ`** (`B = 20` to match the
current `PVTN_CLEARANCE_MARGIN_NORM_BETA ≈ 2^20`, [`hierarchical.rs:49`](../src/sigma/hierarchical.rs)):

1. The bits `{δ_j}_{j<B}` are part of `x_attr` (the clearance field of the leaf preimage), so the same
   binary constraint Stern already enforces in §6 covers `δ_j ∈ {0,1}`.
2. The **linear sum** `Σ_j δ_j 2^j = clearance(x_attr) − min_clearance` has a *public* right-hand side
   structure once `min_clearance` is public, so it is provable with the existing **`prove_linear`**
   (`L·wit ≡ t`, public `L=[2^0,…,2^{B−1}]`, `t` derived from the committed clearance bits and public
   `min_clearance`) — folded into the same combined witness/transcript.
3. Non-negativity is immediate from the bit representation (`δ ≥ 0` because it is a sum of `2^j·{0,1}`).

This is genuine ZK (no norm/value on the wire), unlike v1. It reuses `prove_linear` precisely because
the sum's output is public, while the *membership* output (interior nodes) is not — which is exactly
why §6 cannot.

---

## 8. Re-randomized credential commitment

Per presentation, sample a fresh blind opening `blind = (message 0, randomness r')` and publish
`credential_com' = blinded_commitment(key, user_opening, blind)` =
`commit(m + 0; r + r')` ([`blind.rs:618`](../src/blind.rs)). The §6/§9 argument proves knowledge of the
*combined* opening of `credential_com'`. Because every other field is now hidden, `credential_com'` is
the only credential-derived value on the wire and it is freshly randomised each time ⇒ unlinkable.
(Per the ADR: re-randomisation is *necessary but not sufficient* — it does nothing until §1's cleartext
fields are removed, which §6/§7 do.)

---

## 9. Attribute binding (`role_tag`/`parent_digest`/clearance) in ZK

All three attributes are the **leaf preimage** `x_attr`. The single combined witness `W` (§4) is used
by §6 (membership of `u_leaf = AccLeaf(x_attr)`), §7 (range over the clearance sub-bits of `x_attr`),
and §8/§9 (the credential opening `m` is constrained equal to / derived from `x_attr` via a linear
relation). Because one extractor (§11) pulls a *single* consistent `W`, the attributes cannot be
mix-and-matched across credentials: the leaf proven in-tree, the clearance proven in-range, and the
opened commitment all reference the same `x_attr`. This is ADR-095 open-question Q4's resolution: bind
by **shared witness in one argument**, not by separate proofs glued post-hoc.

---

## 10. Fiat–Shamir transcript and wire format (V2)

**Transcript** (mirrors `opening_statement_ctx`, [`opening.rs:110`](../src/sigma/opening.rs)). Absorb,
before any challenge:
```
DOMAIN = "lattice-zkp/pvtn-membership/v2"
  ‖ profile_id (u8)              ‖ seed0 ‖ seed1 ‖ seed_leaf ‖ gadget params
  ‖ tree_root                    ‖ min_clearance (u32 LE)
  ‖ opening_base_ctx             ‖ wire(credential_com')
  ‖ all Stern round commitments  ‖ range-proof first message u
```
Challenges (`ch_i ∈ {1,2,3}` for Stern rounds; `c` for the linear leg) derive via
`SHAKE256(transcript)` exactly as `fs_sparse_challenge`. **Binding `tree_root`, `min_clearance`,
`opening_base_ctx` is mandatory** to stop cross-context replay (ADR §Consequences).

**Wire `PrivateMembershipProofV2`** (new `ProofKindV2` / `profile_id = PROFILE_ID_PVTN_MEMBERSHIP_V2`):
```
struct PrivateMembershipProofV2 {
    credential_com:    AjtaiCommitment,           // re-randomised (§8)
    membership:        SternMembershipProof,      // §6: t rounds of (c1,c2,c3,opened views)
    clearance_range:   LinearRelationProof,       // §7 (reuses linear.rs)
    // NO leaf_digest, NO merkle_path, NO clearance_level, NO role_tag/parent_digest, NO margin polys
}
```
A new `wire/v2.rs` section encodes it; `max_wire_bytes` in the profile must rise from v0's 4 096 to
accommodate ~171 Stern rounds (§13). Fresh KATs replace `pvtn-membership-v0.json`.

---

## 11. Security-argument skeleton (the review gate — must be completed & reviewed before merge)

**Completeness.** Honest `W` satisfies (a)–(e); each Stern round and the linear leg accept by
construction; rejection-sampling abort probability bounded as in `prove_opening`. *To finish: exact
abort bound for the combined witness norms.*

**Soundness / knowledge-extraction.** From 3 accepting Stern transcripts with distinct `ch∈{1,2,3}` on
the same commitments (3-special-soundness), extract `W'` satisfying the linearised relations and the
`VALID` membership ⇒ either (i) a genuine path `u_0→…→u_d=root` with in-range clearance and a consistent
opening of `credential_com'`, or (ii) a **Module-SIS collision** in the accumulator (two short preimages
of one node) — reduce to M-SIS hardness over `R_q`. The linear leg's soundness is inherited from
`verify_linear`. *To finish (cryptographer):* (1) the explicit `VALID` set + extension matrices `M_i`
and proof they encode exactly (a)–(c); (2) the M-SIS parameters (root Hamming weight, `q`, `m`, `β`)
giving ≥128-bit hardness; (3) attribute-binding non-malleability (no splicing) as a corollary of the
single extracted `W'`.

**Zero-knowledge / unlinkability.** HVZK simulator: for each Stern round, sample `ch` first, then
produce commitments/openings from the permutation+mask distribution without `W` (standard Stern
simulator); the linear leg is simulated as in `prove_linear`'s HVZK. The simulated proof is independent
of the credential ⇒ **(unlinkability)** two presentations of one credential are simulatable from the
same public `X`, hence computationally indistinguishable and share no credential-derived wire field
except the freshly-randomised `credential_com'` (§8), which is itself distributed independently of the
credential. *To finish:* the simulator's indistinguishability advance bounded by the commitment's
hiding (SHAKE256 as a programmable RO) and the M-LWE/uniformity of `credential_com'` re-randomisation.

**Transcript replay.** FS binding of `tree_root`/`min_clearance`/`opening_base_ctx` (§10) prevents
lifting a proof to another root/threshold/context.

---

## 12. Answers to ADR-095 open questions

- **Q1 (accumulator choice).** SIS-Merkle with a ZK Stern path (LLNW) for the first sound version; it
  fits the existing `ExpandA`/`ModuleMatrix`/`Poly` machinery and Module-SIS parameters with only a new
  gadget `G`. A direct shorter-witness lattice accumulator (constant-round Schnorr/rejection variant)
  is the **optimisation track** (v2.1, §6), deferred because it needs new committed-to-committed linear
  soundness.
- **Q2 (range proof).** The `clearance_margin` `CrtPackedNormProof` does **not** compose — it reveals
  the value (§1). V2 uses a bit-decomposition range proof (§7) reusing `prove_linear` for the public
  sum and Stern's binariness for the bits.
- **Q3 (revocation/rotation).** Root update on add/remove changes `tree_root`; presentations pin a
  **root epoch** by binding `tree_root` in the FS transcript (§10). Removing a credential re-roots
  without linking the departing holder *provided* the root is published per-epoch and verifiers accept a
  sliding window of recent roots; an accumulator-with-deletion (e.g. dynamic LLNW) is the richer option
  — **flagged for the cryptographer**, as deletion soundness/unlinkability interact.
- **Q4 (attribute binding).** Single shared witness in one combined argument (§9); the extractor pulls
  one consistent `W'`, so no mix-and-match.

---

## 13. Parameters and performance

- Ring/SIS: `R_q`, `q=8 380 417`, `n=256` (unchanged). Accumulator `k_acc`, gadget width
  `⌈log₂ q⌉=23`, node bit-length `m = 256·k_acc·23` — **to be pinned by the cryptographer** for ≥128-bit
  M-SIS collision resistance at tree depth `d ≤ 16` (`merkle_depth_cap`).
- Stern rounds `t ≈ 171` for `λ=128` (soundness error `(2/3)^t`). Proof size ≈ `t ×` (per-round
  commitments + one opened permuted witness of length `O(d·m)`), i.e. **kilobytes→tens of KB** — far
  larger than v0's 4 KB cap. Raise `max_wire_bytes`; **bench before pinning** (handoff acceptance item).
- Verify is `O(t·d·m)` ring/SHAKE ops — slower than v0's cleartext path, acceptable at credential-
  presentation cadence.

---

## 14. Implementation status (drafted vs review-gated)

Companion scaffold on this branch (`feat/pvtn-v2-unlinkable`):

- ✅ **`accumulator.rs`** — SIS hash node/leaf compression, gadget `G`/`G⁻¹`, tree build, and a
  *cleartext* membership check, with unit tests/KATs. **Sound and testable now** (it is the public
  relation, not the ZK layer).
- 🟡 **`PrivateMembershipProofV2` types + profile id + wire stub** — type-level scaffold; no false
  "it verifies" claim.
- 🔴 **`SternMembershipProof` prove/verify (§6)** — specified here; **NOT implemented as validated**.
  This is the cryptographer's core task and must not land until §11 is completed and reviewed.
- 🟡 **range leg (§7)** — reuses `prove_linear`; wired only after §6's witness layout is fixed.

Sequencing follows HANDOFF-65 §9 (pvtn-unlinkable-membership):
finish §11 argument → review gate → implement §6 → wire+KATs → swap SDK consumers
(the consumer crates' PVTN and interop-test call sites) → flip #65.

## 15. Acceptance criteria (from the handoff)

- [ ] §11 completeness+soundness+ZK/unlinkability argument written and **cryptographer-reviewed** (RED).
- [ ] `prove/verify_private_membership_v2` + `PrivateMembershipProofV2`; SHAKE-Merkle retired from the
      private path (may remain for non-private `HierarchicalAuthProof`).
- [ ] new `lattice-zkp-wire-v…` section + `wire/v2.rs`.
- [ ] KATs: round-trip; **unlinkability** (two presentations share no wire field but `credential_com'`,
      itself fresh); **soundness** (non-member / under-clearance / spliced-attribute rejected).
- [ ] bench Stern rounds over a `d`-deep tree before pinning params.
- [ ] consumers swapped + `sdk/vectors/security/` regenerated; RED sign-off recorded.

---

*Guardrails (unchanged): PQ-only (Module-SIS/Ajtai + SHAKE; no RSA/ECDSA/Ed25519/X25519); `Zeroize` on
secret witnesses (`SecretPolyVec`/`MaskedWitness`); constant-time where secrets compare; `Debug` never
prints secret bytes; no `unwrap`/`expect` in library paths. RED zone — sole-maintainer review of
record, ideally a second `lib-q-lattice-zkp` author for the Stern core.*
