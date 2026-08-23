# ENK-52 — verification record for the three RED boundaries

Independent re-run of the current tree, not carried from a commit message. Recorded because the
board channel was unavailable this run (see final note). This file is a **verification log**, not a
closure: it states which boundaries are closed *in code*, which remain RED, and — for each RED — who
owns the residual. It authors no cryptographic reduction and asserts no sign-off.

- Tree: `HEAD = 8788981` (tkem/zk-enc-proof tip `3bb92b5` + release commits `1253646`,`8788981`).
- Toolchain: repo-pinned via `agent-toolchain --export .`; `cargo test ... --release`.
- Date: 2026-08-23.

## Boundary (1) — malformed-ciphertext insider probe

**Closed in code; RED label is a human sign-off, not an agent decision.**

The card's stated criterion (prove `p = B0ᵀe + f` with *bounded* `(e,f)`) is the superseded,
*insufficient* one — the `δ·unit_k` spike has `‖f‖∞ = 1`, inside any norm ball
(`THRESHOLD_SECURITY.md` §4.2). The sufficient statement (§4.3) is PoK of `μ` with
`(e,f,g)=XOF(pk‖μ)` **and** `p=B0ᵀe+f`; it is built in `lib-q-zk-encryption-proof`
(`encryption_proof::assemble_full_provenance_{prover,verifier}`) and enforced by
`gate::gated_partial_decap_masked*` *before* a share is read. Comment 29's confirmed soundness
break (the free evaluation-at-`ζ` quotient fold) was removed and replaced by the `⟨D,κ⟩` additive
functional (`relation_assembly.rs`); the first-pass regression (free `EncodeMuFold` bits) was also
closed and pinned.

VERIFIED — `cargo test -p lib-q-zk-encryption-proof --release --lib`, run one test per process,
`--test-threads=1` (the batch run SIGKILLs on peak RAM; serial is clean):

    compose::tests::compose_byte_provenance_wrong_sponge_rejected ......... ok   (1.65s)
    encryption_proof::tests::spike_tampered_e_witness_rejected ............ ok  (172.22s)
    encryption_proof::tests::spike_tampered_f_witness_rejected ............ ok   (90.66s)
    encryption_proof::tests::forged_relation_term_..._is_rejected ......... ok   (44.53s)
    encryption_proof::tests::no_fold_instance_is_left_unbound ............. ok    (2.67s)
    gate::tests (7 tests) ................................................. ok    (0.06s)

`gate::tests` includes `gate_refuses_unverified_ciphertext`,
`budgeted_gate_exhausted_budget_short_circuits_before_verifier_runs`,
`budgeted_gate_rejected_proof_does_not_charge_budget`, and
`authenticated_gate_bad_tag_is_rejected_before_budget_or_proof` — i.e. the malformed probe is
refused structurally before the share, a rejected probe cannot burn an honest party's budget, and
the authenticator is checked ahead of both. Each `--exact` run reports `113 filtered out`, i.e. 114
unit tests in the lib target, corroborating the 114/109-passed/5-ignored figure of comment 37.

RESIDUAL (RED, human cryptographer — unchanged): the Fiat–Shamir/grinding bound in the (Q)ROM, the
`κ ⊥ ρ` independence under a shared statement hash, and the preprocessed-commitment obligation.
These are not agent-closable and no code change makes them so.

## Boundary (2) — verifiable partial decapsulation (cheater ID)

**Public-input prerequisite closed (`0575c11`); the proof itself is NOT built. Still RED.**

Comment 31's blocker was not a proof obligation: the crate discarded the values a verifier checks
against. `0575c11` fixes exactly that — `keygen_shares` now publishes all `t` BDLOP coefficient
commitments (`KeygenSharesOutput::coefficient_commitments`), and `share_verifiers_from_dkg` carries
`lib_q_dkg::VerificationKeySet::share_verifiers` across the crate boundary (previously dropped).

VERIFIED — `cargo test -p lib-q-threshold-kem-lattice --release` (`tests/share_commitments.rs`):

    published_coefficient_commitments_open_every_share ................... ok
    a_foreign_share_does_not_open_against_the_published_commitments ...... ok
    public_key_is_still_the_t0_half_of_the_constant_term_commitment ...... ok
    dkg_share_verifiers_survive_the_crate_boundary ...................... ok
    (full crate: 20 passed / 0 failed / 1 ignored across all test binaries)

`public_key_is_still_the_t0_half_...` confirms the publish is additive — the v1 encapsulation wire
is byte-unchanged. The Feldman relation each cheater-ID verifier would run
(`commit(share_i.value; share_i.rand) == Σ_j C_j · i^j`) is now checkable because the `C_j` are
published; a foreign share is rejected, so the check is not vacuous.

RESIDUAL (RED — genuinely open, research-grade, deliberately NOT attempted here): the crate still
does not verify a partial. A sound cheater-ID proof must show `value_i` opens correctly against the
published commitments; the masked path's `value_i = λ_i·⟨rand(i),p⟩ + m_i + flood_i` carries the
pairwise zero-share `m_i`, which is exactly what a naive Feldman opening cannot see. Building that ZK
argument (candidate machinery: lib-q-dkg BDLOP FS proofs, lib-q-lattice-zkp) is the remaining work;
a speculative implementation would be worse than none (card rule 9) and is not landed.

## Boundary (3) — formal threshold IND-CCA reduction

**Stays RED by the card's own statement — human cryptographer sign-off.**

`THRESHOLD_SECURITY.md` §7 states the conditional claim (threshold IND-CCA in the ROM at §2/§3
hardness, *conditional on closure A, or B+C*) and marks the bare-model theorem "not claimed". The
sign-off — confirming or refuting that conditional statement — is item 4 of §8's reviewer list and
is not agent-closable. No code artifact changes this.

## Net

The implementable/verifiable work across all three boundaries has already landed (commits
`21f9cab`→`3bb92b5` for (1)/closures, `9786780` for closure B, `0575c11` for (2)'s public inputs);
this run independently re-ran the load-bearing positive and negative tests and they pass at `HEAD`.
The three residual RED labels are human-cryptographer sign-off items, not defects and not code gaps,
so no additional sound code change was warranted this run. The card is NOT closable by an agent:
each remaining boundary asserts something a human must still check.
