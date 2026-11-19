# Reverse-firewall re-randomisation for custodian share generation

Status: research note, RED zone. No code changed. The question
examined here is whether verifiable secret sharing (VSS) alone rules out a subliminal channel
in which of the valid share values a dealer chose; it does not.

Legend: **[V]** verified here by reading source or running a command; **[I]** inferred /
from the literature, not checked here.

## 1. Answer

**Not as a mandatory step inside the libQ crates; yes as a deployment-level control for
specific, named threat models. Nothing in the current code makes it cheap to claim a
firewall exists.** Detail:

1. The question's premise is partly wrong for `lib-q-dkg`. [V] Once a dealer has published its
   BDLOP round-1 commitments (`dkg_round1_commit`, `dkg.rs`), every share `f(j)` is
   *determined* by the committed polynomial, and `dkg_verify_share` checks both the
   homomorphic opening and the FS proof (`dkg.rs`, `dkg_verify_share`). There is no
   freedom in "which valid share" after commitment. The subliminal freedom is *earlier*:
   in the dealer's choice of polynomial `(a_i, rho_i)` and in the proof's masking
   randomness (`prove_share`), i.e. in the RNG the dealer draws from.
2. `lib-q-sss` has no VSS at all. [V] `split` (`lib-q-sss/src/lib.rs:200-232`) takes the
   `k-1` random coefficient rows (32 bytes each) straight from the caller's RNG; the
   output shares are not checkable against anything. Every byte of those coefficients is a
   free subliminal channel for a dealer with a subverted RNG.
3. `lib-q-threshold-raccoon::keygen_shares` is a trusted-dealer reference [V]
   (`lib.rs:147-`): the dealer sees the whole key, so a dealer-side firewall adds nothing
   there; the threat model is the same as for any trusted dealer.

## 2. Which channels exist, and what a firewall would have to cover

| # | Channel | Who can exploit it | Covered by a zero-sharing re-randomisation? |
|---|---|---|---|
| A | Higher-degree coefficients / commitment randomness in a dealer's polynomial (SSS `split`; DKG `a_i, rho_i`, i>=1) | Colluder who sees shares or public commitments | Yes, if the mask is drawn from an *independent, honest* source [I]. |
| B | Dealer's constant term (its secret contribution; group key `T` is the sum) | Anyone who learns `T` (public) | **No** — the zero-sharing pins the constant term by design (`dkg_round1_commit_refresh`). Needs commit-then-reveal on round 1 so a rushing dealer cannot grind its contribution against the others'. [V] The code has no such ordering (grep for rushing/grind/commit-then-reveal in `lib-q-dkg` returned nothing). Grinding yields roughly log2(trials) leaked bits per run [I]. |
| C | FS-proof masking randomness / abort pattern in `prove_share` | Recipient (proofs are not retained) | Not needed if proofs are discarded after verification [I]; abort-count channel is small. |
| D | Threshold signing nonces (`threshold.rs` `sign_round1`: `y_s`, `y_r`) | Anyone collecting signatures | Out of scope of share generation; this is the BPR signing channel. |

## 3. Why the existing refresh is not a firewall [V]/[I]

`dkg_round1_commit_refresh` + `dkg_check_zero_dealer` + `dkg_apply_refresh` re-randomise
shares while preserving the group secret and `t0 = B0*r` [V] (tests
`refresh_preserves_group_key_and_rekeys_shares`, `refresh_rejects_a_non_zero_dealer`
pass: `cargo test -p lib-q-dkg --release --lib refresh` -> 2 passed). But the refresh
dealers are the *same parties running the same RNG*. A subverted RNG simply subverts the
refresh too, and channel A has already been published in the first-round commitments, so
refresh cannot retroactively scrub them. A reverse firewall is only as good as the
independence of the firewall's own randomness [I, Mironov-Stephens-Davidowitz]. Refresh
is a good *building block* but, unchanged, it is not the control.

## 4. Threat-model gating: when it matters

- A single subverted custodian is already one of the `t-1` corruptions the threshold
  tolerates [I]; the firewall buys nothing against it for secrecy of the group key.
- It matters when the *same* subversion is common to several or all custodians: one
  vendor TEE/HSM RNG, one firmware, one build pipeline (the StrongBox case raised in the question) [I].
  Then "independent honest randomness" must come from a different trust domain.
- For `lib-q-sss` with a single dealer, the dealer already knows the secret, so the real
  risk is leakage *to an outside observer* of the shares; a firewall run by a party that
  never sees the secret is feasible: it deals a fresh zero-polynomial (constant term 0)
  and each holder adds it to their share [I]. The shares stay valid and the coefficients
  become uniform if the mask is honest.

## 5. Candidate designs and cost

Measured on this VM, release build, 3-of-5 (n=5, t=3), single-threaded [V]
(an uncommitted local measurement with a throwaway timing test that is not part of this
change, so the figures are not reproducible from this repository): `dkg_round1_commit`
11.4 ms; `dkg_eval_share` incl. FS proof 163.8 ms; `dkg_verify_share` 9.4 ms; full
`dkg_run_honest` 4.72 s.

| Design | What it closes | Cost |
|---|---|---|
| D1. Mix independent entropy into every RNG that feeds share generation (e.g. `H(os_rng || device_rng || counter)`) | A, C, D when the streams are independent and the subverted one cannot see the other | ~0 ms. A one-wrapper change [I]. Weakest guarantee: no *verifiable* property. |
| D2. SSS zero-polynomial mask by a second, non-secret-holding party | A for `lib-q-sss` | One extra `split`-like pass with constant term 0 plus `n` XORs-in-GF(256) additions; microseconds [I]. Needs a new API and a second party. |
| D3. DKG dealer-side firewall: external party supplies `(a'_i, rho'_i)` for i>=1 that are added to the dealer polynomial and its commitments (BDLOP is additive-homomorphic), then the dealer proves the share | A | Roughly doubles round-1 (about +11 ms) but forces re-proving each share (~164 ms per recipient, dominant) [I from the measurements above]. Needs a firewall-to-dealer protocol and a new proof statement. This is new work; no off-the-shelf PQ lattice construction was checked here. |
| D4. Commit-then-reveal on round 1 (hash-commit the BDLOP commitments, reveal after all are in) | B (rushing / grinding of the group key) | One extra broadcast round; negligible compute [I]. Does not hide A. |
| D5. Reproducible builds + cross-implementation KATs | Build-level SETUP delivery | Medium, as the question suggests. |

## 6. Recommendation

1. Do **not** add a mandatory firewall step to `lib-q-dkg` / `lib-q-sss` now: no
   deployment today has an independent honest randomness source to run it from, and D3
   is unreviewed new cryptography (needs a design record and cryptographer review).
2. Cheap, worth a follow-up: **D4** (closes channel B, which the question did not
   identify and which refresh cannot fix) and **D1** (document and, where possible, enforce
   an RNG-mixing wrapper for share generation).
3. Document in `lib-q-sss/README.md` that `split` is not verifiable and that the RNG is
   a trusted input.
4. Revisit D2/D3 only if a threat model with a common-mode subverted custodian RNG is
   adopted for the deployment.

## 7. Not checked

- Did not read the Mironov-Stephens-Davidowitz or PQ reverse-firewall papers; the
  literature statements are from the question and memory [I].
- No attack was implemented; the bit-rate of channels A and B is not measured.
- Did not examine `lib-q-threshold-kem-lattice` share generation.
- Cost figures are one run on one VM (3-of-5), not a benchmark.
