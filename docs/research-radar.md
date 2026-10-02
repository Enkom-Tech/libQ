# Research radar triage log

Durable conclusions for cryptography papers routed to libQ from the IACR eprint
radar (`iacr-radar`). One entry per triaged paper. The triage records that a
paper was assessed and by whom; **this file is the durable record of the verdict**,
per the repo convention of keeping the durable conclusion in the tree, not only
on the tracking issue.

Fetched PDFs live under the git-ignored `/reference` tree and are not committed.
Every quoted/attributed claim below was verified against the source PDF at the
cited location before being written in.

---

## k-Anonymous Group Signatures (eprint 2025/2007)

- **Paper:** Shalini Banerjee, Andrey Bozhko, Andy Rupp, *"k-Anonymous Group Signatures"*, IACR eprint 2025/2007
  (<https://eprint.iacr.org/2025/2007>).
- **Radar rationale (as imported):** *"medium (conf 0.85) — anonymous credentials.
  Offers post-quantum anonymous group signatures with selective disclosure
  potential."*
- **Verdict:** **Tracked, not actionable.** The radar rationale is inaccurate on
  two counts (see below). Of research interest to Phase 7 only as a *framework* to
  be re-instantiated post-quantumly; the paper itself ships nothing usable here.

### What the paper actually is (VERIFIED against the PDF)

A definitional + generic-construction + proof-of-concept paper. No implementation,
no concrete parameters, no benchmarks. Three primitives:

| Primitive | Property | Tracing cost | Assumptions |
|-----------|----------|--------------|-------------|
| **k-AGS** | stateless signing, **linkable** to the group manager | `O(n+k)` | generic: polynomial commitment + blind signature + hash-to-field + subversion-resistant NIZK (Sec 3.2) |
| **k-UGS** | stateless, **unlinkable** to the group manager | `O(n^2 k)` | M-FASS of [BGI+25] as a black box → compute-and-compare **obfuscation** + injective PRGs (Sec 4) |
| **k-ASPCGS** | k-AGS + Set-Pre-Constrained tracing (threshold variant of SPCGS [BGJP22]) | inherits base | adds subversion-resistant NIZK + set-pre-constrained encryption (Sec 5) |

Core idea of k-AGS (Sec 1.2, p.6-7): a user blindly obtains a pseudo-identity
`pid = ((com, pk_Sig), σ_BS)` where `com` commits to a degree-`k` polynomial `f`
with `f(0) = id`. Each signature carries a conventional signature `σ_Sig` on the
message, a ciphertext encrypting the Shamir share `f(x)` (with
`x = M2F(σ_Sig)`) together with `pid`, and a NIZK that the ciphertext is
well-formed. The group manager links by `pid` and, once `k+1` distinct shares of
one signer are reported, interpolates `f(0) = id` — hence `O(n+k)` tracing.
Application motivation is **threshold traceability for content moderation in E2EE
messaging**, not attribute credentials (abstract; Sec 1).

### Why the radar rationale is wrong (VERIFIED)

1. **NOT post-quantum.** The only concrete "efficient instantiation" (Sec 1.1
   Constructions, p.5; realised in Sec 3.3) is:
   *KZG polynomial commitments [KZG10], a PKE with lifted ElGamal, Schnorr
   signatures, a two-round blind signature = the round-optimal FHS scheme
   [FHS15], and two subversion-resistant Groth–Sahai NIZKs [GS08, ALSZ21].*
   Every one of these is a classical discrete-log / bilinear-pairing primitive,
   broken by Shor. This **violates libQ's stated success metric** ("No classical
   cryptographic primitives in the project's stated PQC / SHA-3 / Saturnin threat
   model", ROADMAP "Success metrics → Security").
   The authors themselves list a post-quantum (lattice) instantiation of the
   *unlinkable* variant as an **open problem** ("Avenues for Further Research",
   p.10: *"whether unlinkability can be achieved from simpler assumptions, such as
   pairings, lattices, or standard public-key primitives"*).

2. **No selective disclosure.** The mechanism is threshold *traceability*
   (k-anonymity) plus optional set-pre-constrained tracing. There is no selective
   disclosure of attributes anywhere in the paper.

### Relevance to libQ Phase 7 (INFERRED — assessment, not from the PDF)

The k-AGS *generic* construction is defined over building blocks libQ already has
pilot post-quantum analogues of, so a PQ re-instantiation is a plausible future
research spike rather than a copy-in:

| k-AGS generic slot | Classical choice in the paper | Nearest libQ PQ building block |
|--------------------|-------------------------------|--------------------------------|
| conventional signature `Sig` | Schnorr | `lib-q-ml-dsa`, `lib-q-fn-dsa` |
| polynomial commitment | KZG | `lib-q-blind-pcs`, `lib-q-plonky` (hash/lattice PCS) |
| round-optimal blind signature | FHS | `lib-q-lattice-zkp` `BlindIssuance`, `lib-q-blind-token` |
| NIZK (subversion-resistant) | Groth–Sahai | `lib-q-zkp`, `lib-q-lattice-zkp`, `lib-q-stark` |
| PKE for the encrypted share | lifted ElGamal | `lib-q-ml-kem` (KEM/DEM); IND-CPA suffices — tracing decrypts then interpolates in the clear, no homomorphism needed |

The gating pieces for a PQ k-AGS are therefore **(a)** a NIZK that a ciphertext
encrypts a correct opening of a PQ polynomial commitment (verifiable encryption of
an opening), and **(b)** a PQ round-optimal blind signature on the committed
`(com, pk)`. libQ has pilot-grade versions of both directions (opening proofs and
`BlindIssuance` in `lib-q-lattice-zkp`), but wiring them into a k-AGS is
substantial new protocol work, not covered by this paper.

### Recommendation

- Correct the triage tags: drop "post-quantum" and "selective disclosure".
- Keep at **medium/low**; no code action now.
- If a stateless, linear-tracing, k-anonymous group signature is ever wanted for a
  moderation/reputation use case, open a Phase 7 research spike to PQ-instantiate
  the k-AGS *framework* from the crates above — do **not** port the paper's
  pairing-based instantiation.

---

## PANCAKE: A SNARK with Plonkish Constraints, Almost-Free Additions, No Permutation Check, and a Linear-Time Prover (eprint 2026/212)

- **Paper:** Yuxi Xue, Peimin Gao, Xingye Lu, Man Ho Au, *"Pancake: A SNARK with
  Plonkish Constraints, Almost-Free Additions, No Permutation Check, and a
  Linear-Time Prover"*, IACR eprint 2026/212 (<https://eprint.iacr.org/2026/212>).
- **Radar rationale (as imported):** *"high (conf 0.95) — post-quantum
  zero-knowledge credentials. PANCAKE enables efficient, scalable ZK proofs with
  minimal overhead for credential systems."*
- **Verdict:** **Not applicable — no code action.** The radar rationale's
  "post-quantum" tag is wrong (see below); this is the same misclassification
  pattern already recorded in an earlier radar entry. No crate, module, or line in libQ is
  affected.

### What the paper actually is (VERIFIED against the PDF)

An asymptotic/constant-factor optimization of HyperPlonk's arithmetization, not a
new proof system family. Pancake removes HyperPlonk's permutation-check argument
for wiring by folding wiring constraints and addition-gate constraints into one
family of batched linear constraints checked by a single sumcheck (Sec. 1,
"Technique overview"; Eq. 1-3). This shrinks the witness domain from all gates to
only non-addition (multiplication/custom) gates and yields the claimed 1.67x
(1 thread) / 2.43x (32 threads) prover speedup over HyperPlonk at circuit size
2^24, half of which are addition gates (Sec. 1, Fig. 1). Setup is
circuit-specific (not universal); the paper states this as an explicit
limitation, justified for long-lived circuits (zkRollups, L2s, VMs) where prover
cost dominates (p.3).

### Why the radar rationale is wrong (VERIFIED)

**NOT post-quantum.** Section 1.2 states the construction "leverages the
multilinear KZG polynomial commitment scheme [36] (see Section 3.5), which is
additively homomorphic" and the online-verification step is checked "using the
pairing-based relation involving commitments to `Q`, `W`, and `W_r`" (p.10,
"Challenge: Costly online computation of Q"). Multilinear KZG is a bilinear-pairing
/ discrete-log-hardness commitment scheme, broken by Shor's algorithm — the exact
assumption class libQ's own architecture doc excludes: "Classical ZKP systems
that rely on elliptic-curve pairings or discrete-logarithm hardness (e.g.
zk-SNARKs, Bulletproofs, Plonk, Halo2) are not in scope for this library — they
depend on classical asymmetric assumptions and are broken by quantum adversaries"
(`docs/zkp-implementation.md`, "Future Enhancements → Advanced ZKP Types"). This
also **violates libQ's stated success metric** ("No classical cryptographic
primitives in the project's stated PQC / SHA-3 / Saturnin threat model", ROADMAP
"Success metrics → Security"). Nothing in the paper suggests a hash-based /
FRI-style PCS swap-in: the linear-check technique (Sec. 1.2, "Challenge: Efficient
evaluation of `W_r`") depends on KZG's additive homomorphism and pairing checks
for the offline-precomputed basis-polynomial commitments `C_i`, so it is not a
drop-in for libQ's STARK/FRI pipeline (`lib-q-stark`, `lib-q-zkp`,
`lib-q-plonky`) without new protocol work the paper does not provide.

**"Credentials" claim is the radar classifier's addition, not the paper's.**
Pancake's abstract and introduction describe a general-purpose Plonkish SNARK
benchmarked against HyperPlonk on synthetic vanilla-Plonk / Jellyfish
Turbo-Plonk circuits; there is no mention of credentials, identity, or
attribute-disclosure anywhere in the paper (checked full text, Sections 1-2 and
headings through the appendices).

### Relevance to libQ (VERIFIED — no applicable crate)

libQ's ZKP stack is zk-STARK / FRI based by explicit design choice
(`docs/zkp-implementation.md` §"Library layout", §"Future Enhancements"); pairing-
based Plonkish SNARKs (HyperPlonk and, by the same token, Pancake) are the
category the doc names as out of scope. `lib-q-plonky` is a Plonky3-derived
**STARK** ecosystem (FRI-based, no pairings) and is unrelated to Plonk/PLONK-family
pairing-based SNARKs despite the name overlap — confirmed by reading
`docs/zkp-implementation.md` line 15 ("Full Plonky3-derived STARK ecosystem").
Pancake's optimization (batched linear-constraint sumcheck replacing a
permutation check) is specific to Plonkish wiring/permutation arguments, which
libQ's STARK/AIR pipeline does not use. No crate, module, or line in libQ
references HyperPlonk, a permutation argument, or a KZG-style PCS as production
code.

### Recommendation

- Correct the card's tag: drop "post-quantum"; this is a classical
  (discrete-log/pairing) construction.
- No code action. No libQ crate is affected.
- If a future Plonkish-with-linear-time-prover primitive is ever wanted over a
  hash-based/FRI PCS instead of KZG, Pancake's linear-constraint idea (fold
  wiring + addition into one batched sumcheck) is the citable technique — but
  that would be new protocol work re-deriving the linear-check argument over a
  FRI-compatible commitment, not a port of this paper.
