# Security analysis — lib-q-dkg + lib-q-threshold-raccoon (PROVISIONAL)

RED-zone analysis for the dealerless binding DKG and the distributed t-of-n lattice threshold
signature, at the **reparameterized** instance (≥128-bit *quantum* core-SVP). Covers (1) the
binding/hiding hardness, (2) the per-key flooding budget, (3) the unforgeability reduction
(single-signer EUF-CMA + a paper-grade threshold TS-UF-1 reduction), and (4) the constant-time
posture of the implementation. **The hiding hardness is now gated on the canonical
[lattice-estimator](https://github.com/malb/lattice-estimator) — the numbers in §2/§5 are the
estimator's, not a hand cross-check** (§6 gives the exact invocation and the result). The earlier
hand core-SVP estimate was **over-optimistic** and is retained only as a cautionary note in §2.
Hiding figures reproduce via [`sweep_qs_preserving.py`](sweep_qs_preserving.py); binding/flooding via
[`security_estimate.py`](security_estimate.py) (run under SageMath:
`PYTHONPATH=lattice-estimator sage-python <file>.py`).

## 0. Parameters (reparameterized 2026-06; KAPPA 8→9 after the estimator run)

| symbol | value | meaning |
|--------|-------|---------|
| `N` | 1024 | ring degree, `R_q = Z_q[X]/(X^N+1)` |
| `q` | 281 474 976 694 273 (≈2⁴⁸) | modulus (prime, `q ≡ 1 mod 2N`) |
| `MU` | **6** | BDLOP binding rows (`B0 ∈ R_q^{MU×KAPPA}`) |
| `KAPPA` | **9** | BDLOP randomness width (raised 8→9 to reach ≥128-bit quantum hiding) |
| `TAU` | 22 | sparse FS challenge weight |
| `SECRET_KEY_WIDTH` | 8.0 | Gaussian width of the secret `s` (sampled constant-time, §8) |
| `S_SIGN` | **290 000** | distributed mask width (param `s`; `σ = s/√(2π)`); raised 268 000→290 000 with `KAPPA` (see below) |
| `BETA_R` | **4 060 000** | verifier ℓ∞ bound on `z_r` (= 14·`S_SIGN`) |
| `MAX_SIGNATURES_PER_KEY` | **2²⁰** | certified per-key flooding budget (enforced caller-side, §4) |

**Why these values (the estimator was the gate).** Three constraints had to hold *simultaneously* at
one parameter set: (C1) hiding ≥128-bit **quantum** core-SVP, (C2) serialized signature ≤
`WIRE_BUDGET_SIGNATURE_BYTES` = 128 KiB, (C3) per-key signature budget `Q_s` ≥ 2¹⁶ (target 2²⁰). The
history:

- `MU=4, KAPPA=6, S_SIGN=28 000` — met C2/C3, hand-estimated 118-bit quantum hiding.
- `MU=6, KAPPA=8` — a hand core-SVP cross-check claimed 150-bit quantum, but **the lattice-estimator
  (§6) returned only 98-bit quantum** (β=368): the hand model used full-kernel uSVP geometry and did
  not optimize over the sublattice dimension (the estimator's optimal attack uses d≈3900, not the full
  9216). C1 **failed**. This is exactly the discrepancy the RED-zone review anticipated.
- **`MU=6, KAPPA=9` (current)** — the estimator gives β=636 ⇒ **169-bit quantum** / 186-bit classical
  hiding. The extra bits are bought with **module rank** (one extra `R_q` element of hiding redundancy,
  `κ−μ` = 2→3). Because the group randomness `r_grp ∈ R_q^KAPPA` grows with `KAPPA`, `‖c·r_grp‖` rose
  and the worst-case flooding budget would have slipped to `2¹⁹·⁸`; `S_SIGN` was therefore raised
  268 000→290 000 (`Q_s ∝ S_SIGN²`) to **restore** the certified worst case to `2²⁰·¹ ≥ 2²⁰` — so
  `Q_s` is **not** traded down to pay for hiding bits (the review's explicit constraint). Signature =
  **66.0 KiB** (< 128 KiB); the `S_SIGN`/`BETA_R` increase does not change the signature byte size
  (`BETA_R ≪ q/2`, still 6 B/coeff).

All three constraints clear at this one set, so **there is no Pareto conflict to escalate**. The
Q_s-preserving sweep ([`sweep_qs_preserving.py`](sweep_qs_preserving.py)) shows `KAPPA=8` is the
largest module rank that *fails* (98q) and `KAPPA=9` the smallest that *clears* 128q (169q) at this
ring; the lattice granularity (one `R_q` element = `N` = 1024 secret coordinates) is coarse, so 169q
is the minimum achievable headroom without a ring-constant change. A lower-`q` ring retune (e.g.
`q≈2⁴¹`) could land nearer ~130q at 60 KiB but requires recomputing the NTT constants and lands with
a thinner binding margin; that trade is left open for the reviewer (see §6).

**Serialized sizes.** Signature `(c, z_s, z_r[KAPPA])` = `2 + 9 = 11` ring elements × 6144 B + 2 B
header = **67 586 B (66.0 KiB)**. DKG round-1 broadcast is `t·(MU+1)` ring elements — **independent
of `KAPPA`** (it carries commitments `C=(t0[MU], t1)`, not responses) — so ≈ 672 KB at `t = 16`
(< 768 KB budget), unchanged from the `KAPPA=8` instance; the KAT vector at the test threshold is
129 030 B. The share proof / complaint carries `t·KAPPA` response elements and grows ≈ 9/8 vs the
`KAPPA=8` instance, remaining within the 1 MB complaint budget (enforced by the `budget_gates` test).

## 1. Binding (statistical — no computational assumption)

The kernel lattice `Λ^⊥(B0) = {x : B0·x ≡ 0}` has dimension `κN = 9216`, determinant `q^{μN}`, so its
shortest vector (Gaussian heuristic) is `λ₁ ≈ q^{μ/κ}·√(κN/2πe) = 2³⁶·⁵`. A Fiat–Shamir extractor
(§7) produces a *relaxed* opening whose difference, times the challenge difference `(c−c′)`, is a
kernel vector; its ℓ₂ norm is bounded by `√(κN)·(2·BETA_R + 2·TAU) ≈ 2²⁹·⁵` (the `2·TAU` term is the
sparse challenge-difference contribution — this is what makes the bound cover *relaxed* openings, not
just exact ones). A second opening would be a kernel vector of that norm; the GH count of such
vectors scales as `(2^-7.0)^{9216} ≈ 2^{-64500}`, so **none exists** — binding holds unconditionally
and independently of `t`. The 7.0-bit "margin" is a ratio over dimension 9216, not a `2^-7.0` risk.
Raising `KAPPA` 8→9 lowered this margin from 11.1 to 7.0 bits (more hiding redundancy ⇒ a
larger-dimension kernel ⇒ a shorter GH vector; the `S_SIGN`→290 000 bump adds a further ~0.1 bit to
the gap); 7.0 bits over dimension 9216 is still an astronomical `2^{-64500}` collision probability.
The SIS estimate confirms no lattice attack reaches the `2²⁹·⁵` target (§6).

## 2. Hiding (computational — Module-LWE) — estimator-gated

Hiding of `s` reduces to recovering the unique ternary `ρ` from `t0 = B0·ρ` (then `s = t1 − ⟨b1,ρ⟩`).
In BDLOP Hermite-normal form `B0 = [I | B0′]`, this is a **Module-LWE** instance with secret `ρ_bottom`
of dimension `(κ−μ)N = 3072`, ternary error `ρ_top` of dimension `μN = 6144`, `m = μN = 6144` samples,
modulus `q`. The malb lattice-estimator (§6), minimizing over usvp/bdd/dual/dual_hybrid/
bdd_mitm_hybrid, returns:

> best attack `dual_hybrid` at `2^212.3` ROP, **BKZ blocksize β = 636** ⇒ **186-bit classical /
> 169-bit quantum** core-SVP (classical 0.292·β, quantum 0.265·β).

This clears the 128-bit **quantum** bar with **41 bits of headroom**.

> **Cautionary note (do not repeat the §0 mistake).** At `KAPPA=8` a hand "2016 estimate" gave
> blocksize 566 ⇒ 150-bit quantum, but the estimator gave β=368 ⇒ 98-bit quantum — the hand model was
> over-optimistic by ~50 bits of blocksize because it assumed full-kernel uSVP geometry instead of the
> estimator's sublattice optimization. **The estimator, not the hand model, is the gate.** The 41-bit
> headroom at `KAPPA=9` is partly insurance against exactly this class of model error.

## 3. Knowledge soundness (Fiat–Shamir)

`|C| = 2^τ·C(N,τ) = 2^{171.7}` ⇒ ≫128-bit knowledge soundness. The challenge set is sparse ternary;
the soundness uses a rewinding/forking extractor in the **classical** ROM (QROM caveat in §7.2).

## 4. Flooding / Rényi — the distributed per-key signature budget

The distributed protocol is **rejection-free**: `z_r = Y_r + c·r_grp`, with `Y_r` the sum of `t` party
masks (aggregate width `s' = S_SIGN·√t`) and the secret-dependent shift `Δ = c·r_grp`. Zero-knowledge
holds only up to the Rényi divergence `D_α(D_{s',Δ}‖D_{s',0}) = exp(α·π·‖Δ‖²/s'²)`. Over `Q_s`
signatures the ZK advantage is preserved up to a factor `exp(Q_s·α·π·‖Δ‖²/s'²)`; requiring this to
cost < 1 bit at 128-bit security gives the **per-key signature budget** (`security_estimate.py`):

| `t` | `n` | aggregate width `s'` | `‖c·r_grp‖₂` | flood ratio | budget `Q_s` @128-bit |
|----:|----:|---------------------:|-------------:|------------:|----------------------:|
| 2 | 16 | 410 122 | 1471 | 279 | **2²⁰·¹** (worst case) |
| 3 | 16 | 502 295 | 1471 | 342 | 2²⁰·⁷ |
| 16 | 16 | 1 160 000 | 1471 | 789 | 2²³·¹ |
| 2 | 5 | 410 122 | 822 | 499 | 2²¹·⁷ |

The worst case (smallest threshold `t = 2`, largest committee `n = 16`) gives `Q_s = 2²⁰·¹`. The
enforced constant [`signer::MAX_SIGNATURES_PER_KEY`] = 2²⁰ therefore sits at-or-below the certified
worst case — above the 2¹⁶ floor and at the 2²⁰ target. (`‖c·r_grp‖` rose from 1387 to 1471 with
`KAPPA` 8→9 because `r_grp ∈ R_q^KAPPA`; `S_SIGN` was raised 268 000→290 000 to restore the
worst-case budget to ≥ 2²⁰.) Because the budget is a Rényi/flooding parameter (not a convenience
number), a deployment
**MUST** enforce it as a per-key counter; the constant is exposed so callers can. The counter is
stateful and therefore lives in the caller, not in these stateless protocol functions. The
single-signer `sign` path is rejection-sampled and is **not** subject to this budget. To extend the
budget, raise `S_SIGN` (roughly `∝ √Q_s`, at a `z_r`/signature-size and `BETA_R` cost — note `BETA_R`
feeds the §1 binding gap, so re-check the binding margin if `S_SIGN` is raised).

## 5. Summary

| property | basis | level |
|----------|-------|-------|
| Commitment binding | statistical (GH, dim 9216) | unconditional (~2⁻⁶⁴⁵⁰⁰ failure) |
| Hiding of `s` | Module-LWE (estimator-gated) | **186-bit classical / 169-bit quantum** (β=636) |
| Knowledge soundness | combinatorial (FS/ROM) | ≈172-bit |
| Distributed ZK | Rényi flooding | per-key budget `Q_s = 2²⁰·¹` (worst case), enforced 2²⁰ |
| Signature size | — | 66.0 KiB (< 128 KiB) |

## 6. Canonical estimator invocation (the gate — status: RUN, 2026-06)

The §2 hiding figure **is** the lattice-estimator's number. Run under SageMath (the
`miniforge3` `sage` env with `PYTHONPATH=lattice-estimator`). Hiding uses the BDLOP HNF Module-LWE
framing (ternary secret **and** error — *not* `n=KAPPA·N` with tiny error, which is degenerate and
returns a spurious `2^∞`):

```python
from estimator import *
N, q, MU, KAPPA = 1024, 281474976694273, 6, 9
# HIDING: B0=[I|B0'] (HNF) => M-LWE, secret rho_bottom dim (KAPPA-MU)*N, ternary error dim MU*N.
LWE.estimate(LWE.Parameters(
    n  = (KAPPA-MU)*N,            # 3072 secret coordinates
    q  = q,
    Xs = ND.Uniform(-1, 1),      # ternary secret
    Xe = ND.Uniform(-1, 1),      # ternary error (the rho_top half)
    m  = MU*N,                   # 6144 samples (B0 rows)
), deny_list=("arora-gb", "bkw"))   # both are never optimal here and are the slow attacks
# BINDING sanity: SIS on B0 with bound = worst-case relaxed-extractor gap (expect infeasible).
SIS.estimate(SIS.Parameters(n=MU*N, q=q, length_bound=2**29.5, m=KAPPA*N))
```

**Result (2026-06).** Hiding: best attack `dual_hybrid`, `2^212.3` ROP, **β = 636 ⇒ 186 cls / 169
qnt** core-SVP — clears ≥128-quantum. Binding: SIS returns infeasible (target `2²⁹·⁵` is below the
GH kernel vector `2³⁶·⁵`), consistent with the §1 statistical argument. The **raw estimator output
(full per-attack table) is archived at [`estimator_run_kappa9.txt`](estimator_run_kappa9.txt)** —
regenerate it with [`archive_estimator_run.py`](archive_estimator_run.py) under SageMath, so the 169q
figure is reproducible-from-artifact rather than a transcribed constant. The full
Q_s-preserving Pareto sweep (six candidates) is in
[`sweep_qs_preserving.py`](sweep_qs_preserving.py); the operative rows:

| candidate | `κ−μ` | sig | `Q_s` | binding margin | β | quantum core-SVP | verdict |
|-----------|------:|----:|------:|---------------:|--:|-----------------:|:-------:|
| `q48 MU6 K8` (prev) | 2 | 60 KiB | 2²⁰ | 11.1 bit | 368 | 98 | ✗ FAIL |
| **`q48 MU6 K9`** (current) | 3 | 66 KiB | 2²⁰·¹ | 7.0 bit | 636 | **169** | ✓ |
| `q48 MU6 K10` | 4 | 72 KiB | 2²⁰ | 3.9 bit | 921 | 244 | ✓ (overkill) |
| `q40 MU6 K8` (low-q) | 2 | 60 KiB | 2²⁰ | 5.1 bit | 468 | 124 | ✗ (just misses) |

(Binding-margin column is the sweep's hand GH check at the pre-bump `BETA_R`; the current row shows
the final `7.0` at `BETA_R = 4 060 000`. Hiding β/core-SVP are `BETA_R`-independent.)

The `q40` low-q row shows the alternative lever (smaller `q`, signature stays 60 KiB) lands just under
128q at `KAPPA=8`; a slightly larger `q≈2⁴¹–2⁴²` would likely clear it at 60 KiB but needs a ring
retune and lands with thinner margin. Whatever `Q_s` the §4 Rényi analysis certifies at the chosen
params is the enforced counter value; at these params it is 2²⁰.

## 7. Unforgeability

### 7.1 Base (single-signer) EUF-CMA — full reduction (ROM)

A signature is a Fiat–Shamir proof of knowledge of a short-`r` opening `(s, r)` of `T = commit(s; r)`
bound to the message: `c = H(T, msg, W)`, `(z_s, z_r) = (y_s + c·s, y_r + c·r)`, accept iff
`commit(z_s; z_r) − c·T = W` and `‖z_r‖∞ ≤ BETA_R`.

**Theorem 1.** For any EUF-CMA adversary `A` making `Q_s` sign queries and `Q_H` RO queries,
```
Adv^{euf-cma}(A) ≤ √(Q_H · Adv^{mlwe}(B_LWE))  +  Q_H · Adv^{bind}  +  Q_s · ε_zk  +  Q_H²/|C|·negl
```
with `Adv^{bind} ≤ 2^{-64500}` (§1) and `ε_zk` the per-signature simulation distance (§7.1.2).

*Proof (game hops).*
1. **G0** real game.
2. **G1 (simulate signing).** Replace `sign` by the HVZK simulator: sample `c ←$ C`, `z_s ←$ R_q`,
   `z_r ← D_{S_SIGN}`, set `W := commit(z_s;z_r) − c·T`, program `H(T,msg,W) := c` (abort on
   collision, prob ≤ `Q_s(Q_s+Q_H)/|C|`). `z_s` is exactly uniform (perfect), and `z_r` is
   within statistical distance `ε_zk` of the rejection output (`ε_zk ≤ 2^{-128}` from the
   single-signer rejection-sampling design). `|G1−G0| ≤ Q_s·ε_zk + coll`.
3. **G2 (extract).** Run `A` in G1; on a forgery `(msg*, σ*=(c*,z*))` whose RO query
   `H(T,msg*,W*)` is the forking point, apply the forking lemma to obtain a second accepting transcript
   `(c′, z′)` with the same `W*`, `c′ ≠ c*`, with prob ≥ `Adv_{G1}·(Adv_{G1}/Q_H − 1/|C|)`.
4. **Special soundness → opening.** From the two transcripts:
   `commit(z_s*−z_s′; z_r*−z_r′) = (c*−c′)·T`, with `z_r*−z_r′` short. Set `(ŝ, r̂) := (z_s*−z_s′,
   z_r*−z_r′)`; this is a **relaxed** opening of `T` w.r.t. factor `(c*−c′)` (cf. §1: the relaxed
   factor is already inside the binding gap).
5. **Dichotomy.** By statistical binding (§1), the *only* short-`r` relaxed opening of `T` is the
   committed `(s, r)` (up to the `(c*−c′)` factor), except with prob `Adv^{bind}`. So the extractor
   recovers `s` (equivalently a short `r` for `T`). The reduction `B_LWE` embeds its Module-LWE
   challenge as `T` (it can simulate all of G1 without the witness, step 2), and outputs the extracted
   `s` — breaking Module-LWE (§2). The `√(Q_H·…)` comes from the forking-lemma rewinding factor. ∎

The two ways a forger can win — recovering the key (→ Module-LWE) or forging a *second* opening (→
binding) — are exactly the two assumptions of §1/§2.

### 7.2 Threshold (t-of-n) TS-UF-1 — paper-grade reduction

The distributed signer is the Threshold-Raccoon (del Pino–Katsumata–Reichle–Takemure, **CRYPTO
2024**) 3-round template (commit → reveal → respond) over a Shamir-shared BDLOP opening, with additive
zero-sharing of the response masks. We prove TS-UF-1 (unforgeability under up to `t−1` static
corruptions) by reduction to the **same** assumptions as the base scheme, plus a PRF assumption for
the zero-share and the §4 flooding budget.

**Setup / notation.** `H = [n]\C` honest, `|C| ≤ t−1`. A qualified signing set `S` has `|S| ≥ t`, so
`|S ∩ H| ≥ 1`. Group key `T = commit(s; r_grp)`. Party `i` holds `(value_i, rand_i) =
(f(i), f_ρ(i))` for the degree-`(t−1)` sharings `f, f_ρ` of `s, r_grp`; reconstruction is
`Σ_{i∈S} λ_i·value_i = s`, `Σ_{i∈S} λ_i·rand_i = r_grp`.

**Theorem 2.** For any TS-UF-1 adversary `A` statically corrupting `≤ t−1` parties, making `Q_h ≤ Q_s`
honest signing queries and `Q_H` RO queries,
```
Adv^{ts-uf-1}(A) ≤ √(Q_H · Adv^{mlwe}(B_LWE)) + Q_H·Adv^{bind} + Adv^{prf}(B_PRF)
                   + Q_h·ε_flood + Q_H²/|C|·negl,
```
where `Q_h·ε_flood ≤ 2^{-128}` by the per-key budget (§4, `Q_h ≤ MAX_SIGNATURES_PER_KEY`) and
`Adv^{bind} ≤ 2^{-64500}` (§1).

*Proof (game hops).*

1. **G0** real TS-UF-1 game: `B` runs honest parties with their true shares.

2. **G1 (idealize the zero-share PRF).** Replace `PRF(seed_{jk}, ·)` for **honest–honest** seed pairs
   `j,k ∈ H` by truly random functions. A corrupt party holds every seed it shares with an honest
   party, so only honest–honest seeds are unknown to `A`. `|G1−G0| ≤ Adv^{prf}(B_PRF)`. After this
   hop, the honest parties' masks `{m_j}_{j∈H∩S}` are, conditioned on `A`'s view, uniform subject to
   `Σ_{j∈H∩S} m_j = −Σ_{i∈C∩S} m_i` (the corrupt total, which `A` can compute).

3. **G2 (simulate honest partials).** `B` produces the honest broadcast without honest shares:
   - **Round 1/2:** sample honest `w_j` as a fresh commitment to simulated `(y_s,j, y_r,j)`, commit
     `H(w_j)`, reveal `w_j` (the protocol's hiding-commit then open). `W = Σ_{i∈S} w_i`.
   - **Round 3:** `B` first determines the *aggregate* target. Let `c = H(T, msg, W)`. `B` samples the
     final aggregate `(z_s, z_r)` from the simulator distribution of §7.1.2 (`z_s ←$ R_q`, `z_r ←
     D_{s'}` with `s' = S_SIGN·√{|S|}`), consistent with `W = commit(z_s;z_r) − c·T`. It then splits
     into per-party broadcasts: corrupt partials are whatever `A` sends; honest partials are chosen
     uniformly subject to (a) summing (with the now-uniform honest masks) to `z` minus the corrupt
     contributions, and (b) each honest `z_s,j` uniform. This split is *perfectly* simulatable when
     `|S ∩ H| ≥ 2` (the honest masks supply the freedom); when `|S ∩ H| = 1` the single honest
     partial is exposed and its hiding rests on the flooding of `y_r,j` — bounded by the **Rényi**
     term: `|G2−G1| ≤ Q_h·ε_flood` via the probability-preservation lemma (Bai et al.; del Pino et
     al. Lemma "flooding"), and `Q_h·ε_flood ≤ 2^{-128}` by the §4 budget.
   - Anti-rushing: the round-1 `H(w_i)` commitment forces `A` to fix its `w_i` before seeing honest
     `w_j`, so it cannot bias `W` (hence `c`) adaptively — standard commit-then-open argument, no
     additional loss beyond RO collision.

   Crucially, **`B` now needs no honest shares.** The `≤ t−1` corrupt shares are independent of `s`
   (Shamir privacy), so `B` samples them uniformly at setup; the public coefficient commitments
   `C_1..C_{t−1}` are then fixed by the `t−1` Vandermonde constraints `Σ_k i^k C_k = commit(value_i;
   rand_i)` (`i ∈ C`) together with `C_0 = T`, solved in the **homomorphic commitment domain** (no
   message knowledge needed). For the *dealerless* DKG, `B` absorbs the Module-LWE challenge into one
   honest dealer's constant-term commitment so that `Σ_dealer C_{dealer,0} = T`; `|S∩H| ≥ 1` makes
   this possible.

4. **G3 (extract & reduce).** `B` runs `A` in G2 (which uses no secret), embeds the Module-LWE
   challenge as `T`, and on a forgery applies forking + special soundness exactly as Theorem 1
   steps 3–5 to recover the short opening of `T`, breaking Module-LWE — or, with prob `Adv^{bind}`, a
   second opening breaking binding. ∎

**What is rigorous vs. what is flagged (the honest accounting the review asked for):**

- *Rigorous given standard lemmas:* the PRF hop, the Shamir-privacy share simulation, the homomorphic
  commitment reconstruction, the forking/special-soundness extraction, and the dichotomy to
  MLWE/binding. The zero-sharing composes because **both the verification map and the secret-sharing
  are linear**, the only structural property the TRaccoon simulation uses.
- *The flooding term `Q_h·ε_flood`* is rigorous **only up to the per-key budget**: it is `≤ 2^{-128}`
  iff `Q_h ≤ 2²⁰`. This is why the counter is load-bearing, not advisory.
- **Heuristic step #1 (cost: the relaxed-opening gap).** Special soundness in a **fully-splitting**
  ring (`q ≡ 1 mod 2N`) extracts an opening scaled by `(c*−c′)`, which need not be invertible — so the
  guarantee is a *relaxed* opening, not an exact one. Cost: the extracted second opening is inflated
  by the challenge difference, which is exactly the `2·TAU·√(κN)` term already added to the §1 binding
  gap; binding therefore still holds (7.0-bit margin) **for relaxed openings**. The residual
  assumption is the standard "module-SIS relaxed binding" — sound here because the relaxed norm stays
  ≪ GH kernel vector, but it is an assumption about the relaxation, not a bare reduction.
- **Heuristic step #2 (cost: QROM).** The forking lemma is **classical-ROM**. A quantum adversary
  needs the measure-and-reprogram / online-extractability machinery; we do not carry that out, so the
  quantum unforgeability claim is heuristic (the *hardness assumptions* §2 are already costed in the
  quantum core-SVP model, but the *reduction* is classical). This is the one genuinely open theory
  step for a machine-checkable proof.
- *Not claimed:* a machine-checked proof. This is a paper-grade pen-and-paper reduction with the two
  heuristic steps above named and costed.

### 7.3 Net

Single-signer EUF-CMA reduces to Module-LWE + statistical binding (Theorem 1, ROM). Threshold TS-UF-1
reduces to the same plus a PRF assumption and the flooding budget (Theorem 2, ROM), with the
relaxed-opening and QROM caveats explicit.

## 8. Constant-time / side-channel analysis (implementation status)

The CT-relevant code was implemented in this pass (not merely specified). Status per component:

| component | secret-dependent? | status |
|-----------|-------------------|--------|
| Ring reduction `mont_reduce`/`modadd`/`modsub` | runs on secret·challenge products | **CT-implemented + tested + measured** — branchless masked conditional subtract (`csub_q_u64`), no data-dependent branch; `branchless_reduction_matches_reference` checks 10⁵ random equivalences; **dudect (freq-locked, core-pinned): max \|t\| ≈ 3.4, stable, fixed-vs-random secret via `ring_mul`** — no leakage (\|t\| ≪ 10) |
| Secret base sampler (width 8, the key `a₀`) | **yes** — samples the secret | **CT-implemented + tested + measured** — fixed-width CDT with a branchless `u64` table scan (`sample_secret_coeff_ct`), fixed iteration count `CDT_ZMAX`, no `exp`/branch; `ct_lt_matches_naive` + moment test; **dudect (freq-locked, core-pinned): max \|t\| ≈ 2.2 over ~1.8M samples, fixed-vs-random seed** — no leakage. Table precision `f64` (≈53-bit) ⇒ statistical distance `≲ 2⁻⁴³`/poly (research-grade; widen to 128-bit fixed point for production) |
| Distributed response (`threshold`) | **rejection-free** | **CT-by-design** — no secret-dependent abort (the Raccoon motivation); this is the path for secret keys under a timing adversary |
| Single-signer `sign` rejection | **yes** | **partially hardened, NOT fully CT** — accept/abort is now isochronous *per iteration* (no `&&` short-circuit; both predicates always evaluated). Residual channels: the *iteration count* and the float `exp` are inherently data-dependent in Lyubashevsky rejection. **Must not be used for secret keys vs. a timing adversary — use the distributed path.** |
| Mask samplers `y_s` (uniform), `y_r` (Box–Muller) | inputs secret-independent | CT-by-construction-but-untested — fresh secret-independent randomness; float `ln/cos` are not CT but leak nothing about the key |
| Lagrange / `scalar_mul` / NTT loops | data-independent index patterns | CT-shaped (untested for timing) |

**Net.** The two exposures the review named — branchless ring reduction and a constant-time base
sampler — are **implemented, unit-tested, and now timing-measured**. A `dudect` harness
([`lib-q-dkg/benches/ct_dudect.rs`](../../../../lib-q-dkg/benches/ct_dudect.rs), `dudect-bencher`
0.7) drives each secret-dependent component with a fixed-vs-random class design; both keep the Welch
t-statistic well below the `|t| < 10` leakage threshold and **non-divergent as sample count grows**
(the constant-time signature): `sample_secret_coeff_ct` max |t| ≈ 2.2 over ~1.8 M samples,
`ring_mul`-driven reduction max |t| ≈ 3.4. Reproduce with
`taskset -c <core> cargo bench -p lib-q-dkg --bench ct_dudect -- --continuous <bench>`, or for the
gold-standard pass run the ready harness [`lib-q-dkg/benches/run_dudect.sh`](../../../../lib-q-dkg/benches/run_dudect.sh)
`<core> <seconds>` on an `isolcpus`-reserved core (it locks the governor, pins, and time-boxes both benches).

*Measurement caveat:* this campaign ran on the dev host (Windows) hardened as far as the OS allows —
**CPU frequency locked (High-Performance power plan, no turbo/SpeedStep jitter), single-core
processor-affinity, High priority**. True bare metal was not used: the box runs Windows, and WSL2 is a
Hyper-V VM (a *worse* timing environment, not better), so the residual gap vs. the gold standard is
specifically **kernel-level core isolation** (`isolcpus`/`nohz_full`) on a quiet Linux host — not
frequency or affinity, which are already controlled here. The verdict (no leakage signal, t bounded as
n grows) is robust; a production sign-off should still re-run under `isolcpus` on bare-metal Linux. The
single-signer
`sign` rejection loop's accept/abort is isochronous, but its **iteration count remains a channel
(inherent to rejection) and is explicitly out-of-scope for secret keys — use the rejection-free
distributed path for those**. None of this changes the wire format or protocol. Remaining CT work for
a production build: a 128-bit fixed-point CDT, a constant-time large-σ mask sampler, and the
bare-metal re-run of this campaign (plus optional `ctgrind`/valgrind instrumentation).

## 9. ADR-109 amendment — DONE GIP-side

The ADR-109 amendment naming `lib-q-threshold-raccoon` as the PQ production signer (and demoting the
GF(256) `lib-q-threshold-sig` to a classical placeholder off the PQ root/recovery path) has been
**applied GIP-side** (spec `gip-dealerless-dkg-v0.md` §1/§9, spec-main `8a8c414`) and is not repeated
here. Load-bearing use remains gated on: the external lattice-estimator sign-off (§6, **done —
169-bit quantum at `KAPPA=9`**), the per-key signature counter enforced for the flooding path (§4),
the production CT items (§8), and promotion of the §7.2 reduction past its two flagged heuristic steps.
