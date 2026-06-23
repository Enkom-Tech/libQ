# FAEST / VOLE-in-the-Head — Reserved Diversity Signature Evaluation

## 1. Status & scope

FAEST is evaluated here as a **reserved diversity signature** for lib-Q: a registered
algorithm identifier that is **disabled by default** (`enabled = false`) and carries **no
implementation**. It exists to hedge a single-point-of-failure risk in the primary signature,
not to be selected in normal operation.

- **State:** identifier-only. No signing or verification code is present in lib-Q.
- **Role:** break-glass reserve, never a default. ML-DSA (Dilithium) remains the default and
  primary signature.
- **Activation:** a deliberate, audited operational decision (see §5), not an automatic or
  negotiable fallback.

This document plus the reserved `Algorithm::FaestReserved` identifier are the **entire
deliverable** of the evaluation card. Nothing in lib-Q's signing path is affected.

## 2. Assumption basis

FAEST is built on **VOLE-in-the-Head (VOLEitH)** with a Fiat-Shamir transform, instantiated
over **AES** (FAEST) or an Even-Mansour-style construction (FAEST-EM). Its security reduces to
**symmetric-primitive assumptions only** — essentially the one-wayness / pseudorandomness of a
block cipher and the random-oracle model for Fiat-Shamir. There is **no structured-lattice,
code-based, or number-theoretic hardness assumption**.

By contrast, lib-Q's default ML-DSA-65 rests on **Module-LWE / Module-SIS** over structured
(cyclotomic) lattices. ML-KEM (the default KEM) shares this Module-LWE family.

**Why this matters.** If the structured-lattice assumption underpinning ML-DSA were broken or
materially weakened, every Module-LWE/Module-SIS signature would fall together — a correlated,
single-point-of-failure event. FAEST's security lives in an **orthogonal assumption class**
(symmetric cryptanalysis of AES), so it is extremely unlikely to fall to the same advance. That
orthogonality is the **entire value proposition** of the reserve: assumption diversity, not
performance.

## 3. Why FAEST over Picnic

The earlier diversity candidate in this niche was **Picnic** (MPC-in-the-Head + ZKB++/KKW over
LowMC/SHA-3). FAEST supersedes it:

- **Newer paradigm:** VOLEitH replaces the MPC-in-the-Head transcript with VOLE correlations,
  yielding **smaller signatures** and **better signing/verification performance** at comparable
  security.
- **Cleaner primitive:** FAEST targets standard **AES** rather than LowMC, removing reliance on
  a less-studied cipher.
- **Active track:** FAEST is a **NIST additional-signatures (on-ramp) candidate** under ongoing
  analysis; **Picnic is deprecated** and was not advanced.

**Picnic must not be used** in lib-Q. FAEST is its modern replacement for the symmetric-only
diversity role.

## 4. Size & speed vs ML-DSA-65

All figures below are **approximate**, drawn from round-3-era FAEST specifications, and depend
on the chosen parameter set (`128s` "small" vs `128f` "fast") and on FAEST vs FAEST-EM. Treat
them as order-of-magnitude, not exact.

| Metric                 | FAEST-128s (approx.) | FAEST-128f (approx.) | ML-DSA-65 (ref.) |
|------------------------|----------------------|----------------------|------------------|
| Signature size         | ~4–5 KB              | ~5–6 KB              | ~3.3 KB          |
| Public key size        | ~32 B                | ~32 B                | ~1.95 KB         |
| Secret key size        | ~32 B                | ~32 B                | ~4.0 KB          |
| Keygen cost            | very low             | very low             | low              |
| Sign cost              | **markedly slower**  | slower (less so)     | fast             |
| Verify cost            | slower               | slower               | fast             |

Reading the table:

- **Public/secret keys are tiny** (~32 B) — FAEST keys are essentially a block-cipher
  key/plaintext pair, far smaller than ML-DSA's ~2 KB public key.
- **Signatures are larger** than ML-DSA-65, and the `s`/`f` knob trades signature size against
  signing time (smaller signatures cost more time, and vice versa).
- **Signing is the headline cost:** FAEST signing is **markedly slower** than ML-DSA signing
  (orders of magnitude in software), and verification is also slower.

**Net:** FAEST trades **much slower signing and larger signatures** for a **tiny key** and,
decisively, a **fundamentally different (symmetric) security assumption**. That trade is
unacceptable as a default and is exactly why FAEST is held in reserve rather than enabled.

## 5. Activation policy

The reserved `FaestReserved` sig_id stays **disabled** until an explicit decision flips it:

- **Trigger:** a **structured-lattice cryptanalysis event** — a break or serious weakening of
  Module-LWE / Module-SIS (and hence ML-DSA / ML-KEM) credible enough to warrant migrating off
  the lattice assumption family.
- **Not automatic:** activation is a **deliberate, audited operational decision**. The library
  does not silently downgrade or negotiate into FAEST.
- **Scope of activation:** flipping the reserve requires landing an actual FAEST implementation,
  test vectors, and a registry change setting `enabled = true` — none of which exist today.

Until that trigger fires, FAEST contributes **only assumption diversity on paper**: a registered
identifier and this evaluation, ready to be promoted if the lattice floor ever gives way.

## 6. Implementation status in lib-Q

Only the **reserved identifier and a disabled registry row** exist:

- **Enum variant:** `Algorithm::FaestReserved` in `lib-q-types/src/lib.rs` (the `Algorithm`
  enum), `category = Signature`, `security_level = 3` (≈ ML-DSA-65 class), `Display` string
  **`"FAEST-Reserved"`**.
- **Registry row:** registered in `lib-q-core/src/algorithm_registry.rs` via
  `AlgorithmRegistry::register_all` as an `AlgorithmMetadata` with **`enabled: false`**,
  `category: AlgorithmCategory::Signature`, `security_level: 3`.
- **No signing/verification:** there is **no FAEST signing or verification implementation**
  anywhere in lib-Q (notably none in `lib-q-sig`). The reserved id is inert.

This document and the reserved id together constitute the **complete deliverable** for the
evaluation card. No default behavior, signing path, or wire format changes.

## 7. References

- **FAEST** — signature scheme website and specification: <https://faest.info>. NIST Additional
  (on-ramp) Digital Signature Schemes call, "Round" submissions for additional PQC signatures.
- **VOLE-in-the-Head** — C. Baum, L. Braun, C. Delpech de Saint Guilhem, M. Klooß, E. Orsini,
  L. Roy, P. Scholl, *"Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from
  VOLE-in-the-Head,"* CRYPTO 2023.
- **Picnic** — *superseded*; the MPC-in-the-Head predecessor (ZKB++/KKW over LowMC),
  **deprecated** and **not to be used** in lib-Q. Retained here only for historical contrast.

---

*Reserved diversity signature evaluation. Status: disabled (`enabled = false`), identifier-only.
Neutral assessment for the lib-Q signature registry; no endorsement of FAEST as a default.*
