# Security — lib-q-cb-kem (Classic McEliece–family CB-KEM)

## Standardization status

Classic McEliece was a **NIST round-4 submission** that NIST evaluated and **did not select**
for standardization (NIST selected HQC as the code-based KEM). There is **no NIST/FIPS encoding**
for this algorithm. This crate implements the round-4 submission's own wire format and parameter

It is, however, standardized elsewhere and deployed: ePrint 2026/1630 records that Classic
McEliece **was incorporated into ISO/IEC 18033-2 in 2026**, and names Mullvad and Rosenpass
as deployments. "No NIST/FIPS encoding" is not the same as "unstandardized", and reading it
that way would understate who is affected by anything in this file.
sets; the five sets (348864, 460896, 6688128, 6960119, 8192128, each with an `f` "fast keygen"
variant) are **frozen to that submission** and are not something this repository may re-parametrize
unilaterally — doing so would break the KATs and interoperability.

## Structural cryptanalysis: public-key distinguishers

This section tracks published *structural* cryptanalysis against Goppa–McEliece — attacks that
try to recognize the hidden algebraic code, as opposed to generic decoding (ISD). It is the
anchor for the crate; the crate `README.md` and `src/lib.rs` point here.

### 2026: provable quasipolynomial distinguisher (ePrint 2026/1630)

**Paper.** Ghoshal, Ishai, Jain, Sun, *"Quasipolynomial Cryptanalysis of the McEliece
Cryptosystem (or: PIR Meets McEliece)"*, IACR ePrint **2026/1630**, dated August 7, 2026.
Every claim below was read against the ePrint PDF and is cited to its section/table.

**What it is.** A **classical, provable, quasipolynomial-time distinguisher** that tells a
Goppa–McEliece public key apart from a uniformly random matrix over `F_2^{k×n}`. In the
asymptotic "Classic McEliece" regime (`n ≤ 2^m`, `m = Θ(log n)`, `t = Θ(n/log n)`,
`k = Θ(n)`) it runs in time `n^{O(log n)}` with advantage `1 − o(1)` (Theorem 1.1).
Mechanically it is a *hold-out test*: hold out one column `y_τ`, compute the space of
multilinear homogeneous degree-`d` polynomials over `F_2` whose order-`<s` Hasse jets vanish
on all other columns (`s, d = Θ(log n)`, `d = s+1`), and accept "Goppa" iff a nonzero such
polynomial also vanishes at `y_τ`. Structured keys always vanish (Hermite interpolation);
random matrices vanish only with small probability (binary Reed–Muller minimum distance).

**Why it is new.** Prior structural distinguishers in this regime were either heuristic or
subexponential: Randriambololona's syzygy distinguisher [Ran25] `2^{O(n (loglog n)^3/(log n)^2)}`
(under a heuristic), and Hemmert–Wiemers [HW25] / Hemmert [Hem26] higher-order-vanishing
(better concrete cost, extended to conjectural key recovery). 2026/1630's distinguishing
analysis is **unconditional** (no heuristic) and is the first to reach **quasipolynomial** time
asymptotically. It arose from a failed attempt to build doubly-efficient PIR from algebraic
locally decodable codes; the "multiplicity code" viewpoint is what crosses the Schur-product
rate-1/2 barrier that stopped earlier square-code distinguishers on subcodes.

**Concrete estimates (this is the part that matters for deployed sets).** The asymptotic attack
is made concrete with shortening + systematic-form optimizations (§5.1–5.2) and a small-field
Block Lanczos solver [Ebe10]. Verbatim from the abstract and §1: it "applies to **all** Classic
McEliece parameter sets considered in the NIST process and yields improved (though not yet
practical) concrete attack estimates," ranging "**from 2^114 to 2^124 binary operations and
from 2^66 to 2^72 bits of storage**." Table 1 / Table 2 (VERIFIED against the PDF; `log₂` values):

| parameter set   | log₂ T_new (this attack) | log₂ storage | log₂ T_ISD (generic decoding, ref.) | log₂ T_HW (prev. best structural [HW25/Hem26]) |
|-----------------|--------------------------|--------------|-------------------------------------|-----------------------------------------------|
| mceliece348864/f  | 114.16 | 66.45 | 151 | 298 |
| mceliece460896/f  | 120.29 | 69.54 | 191 | 595 |
| mceliece6688128/f | 123.95 | 71.37 | 257 | 691 |
| mceliece6960119/f | 123.02 | 70.91 | 257 | 565 |
| mceliece8192128/f | 123.95 | 71.37 | 287 | 551 |

The distinguisher's cost (`2^114`–`2^124`) is **below** the paper's generic-decoding reference
(`T_ISD`, `2^151`–`2^287`) and far below the previous best structural distinguisher
(`T_HW`, `≥ 2^298`).

### What this does and does NOT mean for this crate

- **It is a distinguisher of the *public key*, not a message- or key-recovery attack.** It
  breaks the *conservative* "public key is pseudorandom" assumption (ePrint 2026/1630
  Definition 2.4), **not** OW-CPA (Definition 2.6), on which the KEM's IND-CCA security is built
  on which confidentiality of an encapsulation rests. The authors state plainly that
  "distinguishing does not by itself compromise security" but "reveals non-random algebraic
  structure and is therefore considered a serious warning sign" (§1).

- **No practical break of any deployed set.** `2^114`–`2^124` binary operations with
  `2^66`–`2^72` bits of storage is not runnable; the authors describe the estimates as
  "not yet practical." **NOT VERIFIED by us** by execution — we did not (and cannot) run the
  attack; these are the paper's own cost-model estimates, reproduced, not independently
  reproduced.

- **The public-key-pseudorandomness margin is nonetheless eroded below the nominal level for
  the smallest set.** For `mceliece348864` (the submission's Category-1 set, ~2^128 classical
  target) `T_new ≈ 2^114.16 < 2^128`. So the *conservative indistinguishability* design
  assumption no longer holds up to the claimed level for that set, even though message/key
  secrecy is not shown broken. (The Category↔set mapping here is the submission's own target,
  not re-derived in this file.)

- **The decryption (message-recovery) extension is heuristic and impractical.** §1.1.2/§6 give
  a heuristic `n^{O(log n)}`-time algorithm to recover `u` from `c = uY + e`; the authors call
  its concrete cost "currently far beyond practical reach" and "an asymptotic proof of concept,"
  and could not even run it on a binary square-free Goppa instance (the smallest compatible one
  needs a linear system of dimension ≈`2^27`, §"End-to-End … Tests"). **No key-recovery** attack
  is claimed; extending to key recovery is left as open (§1.2).

- **Scope caveats worth reading before over-reacting.** The distinguisher is unconditional; the
  decryption attack is heuristic (open to proof or refutation, §1.2). The asymptotic exponent
  scales with the extension degree `m` when `mt = Θ(n)` (§1.2 "dependence on the extension
  degree"). The result is framed as bringing Goppa–McEliece under the same qualitative
  quadratic ciphertext/security tradeoff as Alekhnovich's LPN scheme (§1.2), i.e. an
  *asymptotic* re-appraisal of McEliece's advantage, not a today-exploitable flaw.

### Obligation / status

- **CM-1 (tracking, open).** Structural public-key distinguisher on all Classic McEliece
  parameter sets is now **provable and quasipolynomial**, with concrete distinguisher costs
  (`2^114`–`2^124`) below generic decoding — and, for `mceliece348864`, below the set's nominal
  ~2^128 target. **Action taken:** documentation only. **No code, wire-format, KAT, or parameter
  change is warranted or possible** here: the sets are frozen to the round-4 submission, and no
  practical message/key recovery exists. Re-open for a code/parameter decision **only** if a
  future result turns this into a practical distinguisher, a message-recovery attack within the
  nominal level, or a key-recovery attack. A human cryptographer should decide whether
  `mceliece348864` in particular should be de-emphasized in favor of the larger sets given that
  its public-key-pseudorandomness margin is the first to fall below target.

- Consumers who selected CB-KEM specifically for its *conservative code-based* assumption (rather
  than for KEM confidentiality alone) should note that the conservative assumption is the one this
  line of work erodes; for those users, diversity against ML-KEM (lattice) via HQC (also
  code-based, but a different assumption) or a hybrid is the relevant hedge.

## Verified vs inferred

- **VERIFIED (read against ePrint 2026/1630 PDF):** the attack type (distinguisher, not
  recovery); the asymptotic regime and `n^{O(log n)}` time; the `2^114`–`2^124` / `2^66`–`2^72`
  concrete ranges; the per-set Table 1/Table 2 numbers reproduced above; the "not yet practical"
  and "far beyond practical reach" characterizations; the heuristic status of the decryption
  attack and the absence of a key-recovery attack; the Definition 2.4 vs 2.6 distinction.
- **REPRODUCED, NOT INDEPENDENTLY VERIFIED:** all cost figures are the paper's own cost-model
  estimates. We did not execute the attack; the `2^114 < 2^128` observation for `mceliece348864`
  combines the paper's `T_new` with the submission's Category-1 target.
- **INFERRED (our engineering reading, not the authors' claim):** that no code/wire/parameter
  change is warranted for this crate today, and the CM-1 re-open triggers above.
