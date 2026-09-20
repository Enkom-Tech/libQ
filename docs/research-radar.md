# Research radar triage log

Durable conclusions for cryptography papers routed to libQ from the IACR eprint
radar (Hive `iacr-radar` board). One entry per card. The card records that a
paper was assessed and by whom; **this file is the durable record of the verdict**,
per the repo convention of keeping the durable conclusion in the tree, not only
on the tracking issue.

Fetched PDFs live under the git-ignored `/reference` tree and are not committed.
Every quoted/attributed claim below was verified against the source PDF at the
cited location before being written in.

---

## ENK-469 — k-Anonymous Group Signatures (eprint 2025/2007)

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

- Correct the card's tags: drop "post-quantum" and "selective disclosure".
- Keep at **medium/low**; no code action now.
- If a stateless, linear-tracing, k-anonymous group signature is ever wanted for a
  moderation/reputation use case, open a Phase 7 research spike to PQ-instantiate
  the k-AGS *framework* from the crates above — do **not** port the paper's
  pairing-based instantiation.
