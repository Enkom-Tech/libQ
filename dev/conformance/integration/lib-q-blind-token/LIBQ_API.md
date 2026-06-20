# lib-q-blind-token — LIBQ_API contract (v1, PROVISIONAL)

GIP-agnostic contract for the post-quantum unlinkable blind-token crate. This document is the
normative description of what the crate guarantees; it carries no consumer-protocol references.

## 1. Scheme choice (for RED-zone review)

- **Primitive:** an **unlinkable lattice blind token** in the keyed-verification anonymous-credential
  style of Agrawal–Kirshanova–Stehlé–Yadav (CCS 2022, "Practical, Round-Optimal Lattice-Based Blind
  Signatures") over a **self-contained** ring \(R_q = \mathbb{Z}_q[X]/(X^{1024}+1)\),
  `q = 281 474 976 694 273` (prime, `q ≡ 1 (mod 2N)`, `q < 2^48`). The ring (NTT, sampler,
  `sample_in_ball`) is implemented in-crate so the modulus/dimension are sized for *concrete
  security* rather than borrowed from an ML-DSA ring. Two layers:
  1. **GPV signature with a Micciancio–Peikert gadget trapdoor.** The issuer key is a matrix `A`
     (row of `PREIMAGE_LEN = 66` ring elements) with an MP trapdoor `A = [Ā | G − Ā·R]`,
     `Ā = [1, a_1, …, a_{m̄-1}]` (`m̄ = 18`), `R ∈ R_q^{m̄×k}` short Gaussian, `G = (1,2,…,2^{k-1})`
     (`k = 48`). A credential on a *hidden* attribute `a_tok` is a short preimage `x` with
     `A·x = d·a_tok + d0` (`d, d0` public), produced by GPV preimage sampling (Peikert convolution
     perturbation + gadget sampling), so `x` is a spherical discrete Gaussian independent of `R`.
  2. **Re-randomizable ZK proof of possession at redemption.** The redeemable token is a fresh
     Fiat–Shamir-with-aborts (Lyubashevsky) proof of knowledge of short `(x, a_tok)` with
     `[A | −d]·(x ‖ a_tok) = d0`. The binding `A·x = d·a_tok + d0` is a public **linear** map (no
     hash), so possession is provable with a lattice sigma-protocol.
- **Forbidden alternatives avoided:** this is **not** the classical 2HashDH VOPRF and **not** an RSA
  blind signature. Unlinkability is algebraic (ZK), not a wrapper over a linkable attestation.
- **References:** Agrawal et al. CCS'22 (one-more-ISIS blind signatures); Micciancio–Peikert 2012
  (gadget trapdoors / `SampleD`); Gentry–Peikert–Vaikuntanathan 2008 (preimage sampling);
  Lyubashevsky 2012 (FS-with-aborts / rejection sampling); Privacy Pass / RFC 9497 (API slot).

## 2. Why this gives unlinkability (the property the tier exists for)

The issuer sees the credential `(a_tok, x)` at **issuance** (issuance is in the clear — there is no
blind-issuance step to subvert). Redemption is an HVZK proof that reveals **nothing** about
`(a_tok, x)`, and is freshly randomized each time. Therefore an issuer that records every issued
`(a_tok_i, x_i)` and colludes with the verifier cannot link a redemption to its issuance better than
guessing within the `(issuer_key_id, epoch)` anonymity set — and repeated redemptions of one
credential are mutually unlinkable. This is validated empirically by the `unlinkability_experiment`
test: a best-effort residual-attack adversary (`argmin_i ‖z − c·w_i‖`) links at ≈ chance, not ≈ 1.

This is the genuine improvement over the previous gadget wrapper, whose redeemed token disclosed the
issuer-signed commitment and was therefore linkable.

## 3. Hardness assumptions and concrete security

Parameters were **selected against a BKZ core-SVP cost model** (root-Hermite-factor estimate;
classical sieving `0.292·b`, quantum `0.265·b`), not borrowed. The set:

| quantity | value |
|----------|-------|
| ring | `N = 1024`, `q ≈ 2^48` (prime, `q ≡ 1 mod 2N`) |
| trapdoor | `m̄ = 18`, `k = 48`, `PREIMAGE_LEN = 66`, `s_r = 4`, `s = S_SIGN = 5248` |
| proof | `WITNESS_LEN = 67`, `τ = 16`, `S_Y ≈ 2.4·10^7`, `BETA_Z = 1.21·10^8` |

- **One-more unforgeability ⇐ Module-SIS.** Forging a fresh accepting proof yields (by the
  knowledge extractor of the Σ-protocol) a short `(x̄, ā)` with `A·x̄ = d·ā` of `ℓ₂`-norm
  `β ≈ 2·‖z‖₂ ≈ 5.0·10^9`; finding one without the trapdoor is **Module-SIS** on `A`. At
  `n·N = 1024` rows and modulus `q`, the cost model gives **≈131-bit classical** (BKZ-450),
  **≈119-bit quantum** core-SVP. (Core-SVP is conservative — it charges one SVP call and ignores
  the large per-call sieve overhead — so the realistic quantum margin is higher.)
- **Trapdoor hiding is statistical, *not* Module-LWE.** `m̄ = 18` is chosen so `[Ā | Ā·R]` is within
  `2^{-128}` statistical distance of uniform (ring leftover-hash), so `A` is indistinguishable from a
  uniform matrix unconditionally — the issuer's `R` does not leak from the public key. (A small
  trapdoor width with a `2^48` modulus would have made a Module-LWE-based hiding argument *easy* to
  break; statistical hiding sidesteps this, at the cost of a larger `m̄`.) The trapdoor also does not
  leak through issued credentials, because GPV preimages are spherical Gaussians independent of `R`
  (validated empirically: `preimage_covariance_is_spherical`).
- **Knowledge soundness of redemption.** The sparse challenge space has
  `|C| = 2^τ·\binom{N}{τ} ≈ 2^{131.6}`, so a cheating prover's knowledge error is ≈2^-128 per
  invocation. The masked response stays below `q/2` (no wraparound), so verification of shortness is
  meaningful.
- **Blindness / unlinkability:** statistical HVZK of the redemption proof (Lyubashevsky rejection
  sampling makes the accepted response `z ~ D_{S_Y}` independent of the witness).
- **Post-quantum:** Module-SIS only; no classical (DL / RSA / pairing) assumptions, and no
  Module-LWE assumption (hiding is statistical).

## 4. Public interface (contract op → function)

| contract op | function | role |
|-------------|----------|------|
| key setup | `keygen_issuer(rng, issuer_key_id, epoch) -> (IssuerPublic, IssuerSecret)` | MP trapdoor key + public `(A, d, d0)` |
| Blind | `blind(rng, issuer_pub) -> (IssueRequest, IssueState)` | sample a hidden credential attribute |
| Evaluate / BlindSign | `blind_sign(rng, issuer_priv, req) -> IssueResponse` | issuer GPV-signs `d·a_tok + d0` |
| Unblind | `unblind(issuer_pub, state, resp) -> Option<Credential>` | check the signature, store credential |
| Redeem | `redeem(rng, issuer_pub, credential, nonce) -> Vec<u8>` | fresh ZK proof of possession (token bytes) |
| Verify | `verify(issuer_pub, nonce, token_value) -> bool` | verify the ZK proof |

The whole API is **std-gated** (the Gaussian samplers need `f64`). `(issuer_key_id, epoch)` is the
anonymity-set label; the nonce is bound into the redemption proof's Fiat–Shamir challenge (context
separation / replay binding).

## 5. Security properties (claimed / argued)

- **Unlinkability:** §2 (`unlinkability_experiment`, `repeated_redemptions_are_fresh_and_both_verify`).
- **One-more unforgeability:** §3; a random/forged proof is rejected (`forged_proof_without_credential_fails`),
  as are tampered tokens (`tampered_token_fails`) and tokens under a different issuer (`wrong_issuer_fails`).
- **Context binding:** a token only verifies against the nonce it was redeemed for (`wrong_nonce_fails`).

## 6. Wire (v1, provisional)

`encode_token_value` / `decode_token_value`. Header `[ver=1][profile=1]`, then length-prefixed
`w_commit` (1 ring element) and `z` (`WITNESS_LEN = 67` ring elements). Each ring element is `N = 1024`
coefficients encoded as **6 little-endian bytes** each (canonical residue in `[0, q)`, validated on
decode), i.e. `6144` bytes/element, so a token is `≈ 408 KB`. Budget-gated by
`WIRE_BUDGET_BLIND_TOKEN_BYTES = 524 288`. The token is a re-randomized proof, so its bytes vary per
redemption (this is intended — it is what makes redemptions unlinkable). Layouts are provisional
until the interoperable wire freeze.

## 7. Assumptions / caveats surfaced for RED-zone review

1. **Concrete security is a BKZ-cost-model estimate, not a proof.** The set targets ≈131-bit
   classical / ≈119-bit quantum **core-SVP** (§3). Core-SVP is the standard conservative model used
   by NIST PQC submissions, but it is a heuristic: the true cost depends on the lattice estimator
   version, sieve/enumeration crossover, and memory model. The estimate should be re-run with an
   up-to-date lattice estimator before this instance is treated as load-bearing. The classical
   margin clears 128-bit; the quantum core-SVP margin (119-bit) is just under a 128-bit *quantum*
   target — closing it fully needs a larger `q` (and larger keys), a documented trade-off.
2. **Large keys / proofs.** Public key `≈ 396 KB` (`A` is 66 ring elements at 6 KB each), token
   `≈ 408 KB`. This is inherent to a statistically-hidden gadget trapdoor at this modulus; a smaller
   instance would need a Module-LWE hiding argument (see §3) or a different construction.
3. **Samplers are not constant-time.** The discrete Gaussian / gadget / perturbation samplers are
   research-grade (data-dependent branches, `f64`); a production build needs constant-time base
   samplers (CDT / Karney) and a hardened FFT-domain perturbation sampler. The perturbation FFT uses
   `f64` canonical embedding; its numerical error budget vs. the smoothing parameter is not formally
   bounded in-repo.
4. **Soundness/ZK conventions vs. the literature.** The Lyubashevsky rejection uses a `κ = 12`-σ tail
   factor with a clamp on the rare overflow; the resulting statistical distance must be re-derived
   for a target bound. The perturbation sampler's covariance scaling is validated empirically
   (`preimage_covariance_is_spherical`) rather than by a formal proof in-repo.
5. **Issuance is in the clear (KVAC model).** The issuer learns the credential at issuance;
   unlinkability is between issuance and the anonymous redemption, not blindness of the issuance
   message itself. This matches the anonymity goal (issuer ↮ redemption) but differs from a
   blind-issuance Privacy-Pass flow.
6. **Double-spend / replay** is out of scope (a redemption ledger / nullifier is the consumer's
   concern); this crate only attests possession of a valid credential for a `(issuer_key_id, epoch,
   nonce)`. An unlinkable nullifier would need a PRF-in-ZK layer (follow-up).
7. **No lattice signer interop yet.** As with `lib-q-dkg`, there is no in-repo lattice signer to
   exercise end-to-end; the contract is validated by the crate's own tests.
