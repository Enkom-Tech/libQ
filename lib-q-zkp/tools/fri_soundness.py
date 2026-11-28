#!/usr/bin/env python3
"""Membership-STARK soundness calculator — BOTH arms, transparent AND hiding, classical AND post-quantum.

Computes the bits of security delivered by each arm's membership config across every soundness term
and the overall (min). Run: `python fri_soundness.py`. Mirrors `tests/soundness_gate/mod.rs`, which
is the gate CI enforces.

This is HASH + Reed-Solomon soundness arithmetic, not lattice estimation — Sage / lattice-estimator
(M-SIS/M-LWE) is NOT applicable to FRI.

FRI query regimes (BCIKS20 "Proximity Gaps for Reed-Solomon Codes" + the ethSTARK conjecture):
  unique-decoding (provable) · Johnson bound (provable) · capacity (conjectured, deployed).

PROVEN bound, every term a cited theorem, ONE m = 3 throughout:
  eps_FRI = eps_MCA + eps_C + (sqrt(rho) (1 + 1/(2m)))^s
  - eps_MCA: the PCS folds the l opened (column, point) quotients into ONE word with powers of one
    alpha, the univariate powers generator (1, x, ..., x^d), d = l - 1. Bordage, Chiesa, Guan,
    Manzur, "All Polynomial Generators Preserve Distance with Mutual Correlated Agreement" (ePrint
    2025/2051, version of May 19, 2026), Lemma 9.3 / Def 9.1, MCA for RS codes up to
    1 - (1 + 1/2m) sqrt(rho):  (m+1/2)^7 d n^2 / (3 rho^(3/2) |F|).
  - eps_C and the query term: BCIKS20 (ePrint 2020/654, version of July 3, 2021) Thm 8.3 /
    Lemma 8.2 eq (8.5), applied to that one word:
      (m+1/2)^7 n^2 / (2 rho^(3/2) |F|) + (2m+1)(n+1) sum_i l^(i) / (sqrt(rho) |F|),  l^(i) = 2.
  All priced at the LARGEST LDE domain n = |D^(0)| the verifier accepts. l, the domain rule and the
  single LDE height (no beta^2 roll-in) are measured from real proofs in
  `tests/soundness_gate_shape_tests.rs`.
  Not used: Manzur, ePrint 2026/2617 (powers generator, any linear code): its radius
  J_{d+2} = 1 - rho^(1/(d+2)) is ~1e-3 at d ~ 3400, so s = 96 queries give ~0.1 bit there
  (printed below as a check).

Post-quantum model (the deployed / "mainstream" one — Plonky3, ethSTARK, SP1, Risc0):
  the Fiat–Shamir compilation of a round-by-round-sound IOP preserves its soundness in the QROM up to
  small factors (no Grover square-root loss on the IOP terms); Grover halves only the grinding PoW;
  SHAKE256/256 = NIST Category-2 (~128-bit PQ collision; BHT not counted).
"""
import math

log2 = math.log2

# Field cell sizes.
M31 = 2 ** 31 - 1            # Mersenne31 (Arm A base; value field = Complex<M31> = GF(p^2))
BABYBEAR = 2_013_265_921     # BabyBear (Arm B base)
M = 3                        # BCIKS20 m (Thm 5.1 / 6.2 / 7.2 / Lemma 8.2 need m >= 3)


def fri_proven(field, log_blowup, num_queries, pow_bits, lde_log2, batched):
    """Returns (eps_MCA bits, eps_C bits, query bits, eps_FRI bits)."""
    rho = 2.0 ** (-log_blowup)
    n = 2.0 ** lde_log2
    d = batched - 1                                                    # powers generator degree
    mca = (M + 0.5) ** 7 * d * n * n / (3 * rho ** 1.5)               # BCGM Def 9.1
    rounds = lde_log2 - log_blowup                                    # binary folds, final poly 1
    lemma = (M + 0.5) ** 7 * n * n / (2 * rho ** 1.5) \
        + (2 * M + 1) * (n + 1) * (2 * rounds) / math.sqrt(rho)       # BCIKS20 Lemma 8.2 (8.5)
    mca_bits = field - log2(mca) if d > 0 else math.inf
    commit = field - log2(lemma)
    query = -num_queries * log2(math.sqrt(rho) * (1 + 1 / (2 * M))) + pow_bits
    fri = -log2(2.0 ** -mca_bits + 2.0 ** -commit + 2.0 ** -query)
    return mca_bits, commit, query, fri


def manzur_powers_radius(log_blowup, num_queries, pow_bits, batched):
    """Manzur 2026/2617 radius J_{d+2}(1 - rho) and the query+PoW bits it would allow."""
    rho = 2.0 ** (-log_blowup)
    j = 1 - rho ** (1 / (batched - 1 + 2))
    return j, -num_queries * log2(1 - j) + pow_bits


def report(label, cell_bits, challenge_ext_deg, log_blowup, num_queries, pow_bits,
           max_deg, lde_log2, batched, hash_bits=256):
    rho = 2.0 ** (-log_blowup)
    field = challenge_ext_deg * cell_bits
    deep = field - log2(max_deg * 2 ** lde_log2)                    # DEEP/ALI Schwartz-Zippel term
    def q(one_minus_delta):
        return -num_queries * log2(one_minus_delta) + pow_bits
    ud, john_limit, conj = q((1 + rho) / 2), q(math.sqrt(rho)), q(rho)
    hash_coll = hash_bits / 2
    pq_grind_conj = conj - pow_bits + pow_bits / 2                 # quantum: grinding Grover-halved
    mca, commit, query, fri = fri_proven(field, log_blowup, num_queries, pow_bits, lde_log2, batched)
    _, _, _, fri_pq = fri_proven(field, log_blowup, num_queries, pow_bits / 2, lde_log2, batched)
    manzur_j, manzur_bits = manzur_powers_radius(log_blowup, num_queries, pow_bits, batched)
    classical = min(deep, conj, hash_coll)
    classical_prov = min(deep, fri, hash_coll)
    pq = min(deep, pq_grind_conj, hash_coll)                      # IOP preserved; hash = Cat-2
    pq_prov = min(deep, fri_pq, hash_coll)                        # PROVEN (BCIKS20 Thm 8.3)
    print(f"=== {label} ===")
    print(f"  challenge field {challenge_ext_deg}x{cell_bits:.1f}b   : {field:6.1f} bits")
    print(f"  LDE domain priced (verifier max) : 2^{lde_log2}, batched openings l = {batched}")
    print(f"  constraint/DEEP (deg{max_deg})       : {deep:6.1f} bits")
    print(f"  BCGM Lemma 9.3 eps_MCA (d=l-1): {mca:6.1f} bits")
    print(f"  BCIKS Lemma 8.2 eps_C         : {commit:6.1f} bits")
    print(f"  BCIKS Thm 8.3 query (m=3)     : {query:6.1f} bits")
    print(f"  eps_FRI (MCA + eps_C + query) : {fri:6.1f} bits   ({fri:.4f})")
    print(f"  [not used] Manzur J_(d+2) = {manzur_j:.1e}: query+PoW {manzur_bits:5.1f} bits")
    print(f"  FRI query+PoW ud/john(m->inf)/conj : {ud:5.0f} / {john_limit:5.0f} / {conj:5.0f} bits")
    print(f"  SHAKE256 collision            : {hash_coll:6.1f} bits")
    print(f"  OVERALL classical conj/proven : {classical:6.1f} / {classical_prov:6.1f} bits")
    print(f"  OVERALL POST-QUANTUM (conj)   : {pq:6.1f} bits   {'>= 128 OK' if pq >= 128 else '< 128'}")
    print(f"  OVERALL POST-QUANTUM (PROVEN) : {pq_prov:6.1f} bits   {'>= 128 OK' if pq_prov >= 128 else '< 128'}")
    print()
    return min(pq, pq_prov)


if __name__ == "__main__":
    # Arm A (`membership_config` / hiding `prove_unlinkable_membership_zk`): challenge field =
    # degree-3 over Complex<Mersenne31> = GF(p^6); FRI log_blowup 3 / q 96 / PoW 20; AIR degree 5.
    # Both verifiers pin the trace height to the padded depth <= MAX_DEPTH = 64 rows (doubled under
    # the hiding PCS), so n <= 2^(6 + zk + 3).
    a = report("ARM A  (Complex<M31> value, Poseidon256, challenge GF(p^6))",
               log2(M31), 6, 3, 96, 20, max_deg=5, lde_log2=6 + 3, batched=34_316)
    az = report("ARM A zk (hiding PCS)",
                log2(M31), 6, 3, 96, 20, max_deg=5, lde_log2=6 + 1 + 3, batched=34_431)
    # Arm B (`default_config_bb` / `default_zk_config_bb`): challenge field = degree-8 over BabyBear
    # = GF(q^8); FRI log_blowup 4 / q 96 / PoW 20; AIR degree 7. `verify_membership_bb` does not bind
    # the trace height to a depth, so only BabyBear's two-adicity (27) bounds n.
    b = report("ARM B  (BabyBear value, Poseidon2, challenge GF(q^8))",
               log2(BABYBEAR), 8, 4, 96, 20, max_deg=7, lde_log2=27, batched=3_386)
    bz = report("ARM B zk (hiding PCS)",
                log2(BABYBEAR), 8, 4, 96, 20, max_deg=7, lde_log2=27, batched=3_534)
    report("superseded ARM B GF(q^5) (positive control: must be < 128)",
           log2(BABYBEAR), 5, 4, 96, 20, max_deg=7, lde_log2=27, batched=3_386)
    ok = min(a, az, b, bz) >= 128
    print(f"All membership configs >= 128-bit PQ: {ok}  (binding term: SHAKE256 hash, 128)")
