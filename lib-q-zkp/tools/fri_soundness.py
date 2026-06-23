#!/usr/bin/env python3
"""Membership-STARK soundness calculator — BOTH arms, classical AND post-quantum.

Computes the bits of security delivered by each arm's membership config across every soundness term
and the overall (min). Run: `python fri_soundness.py`.

This is HASH + Reed-Solomon soundness arithmetic, not lattice estimation — Sage / lattice-estimator
(M-SIS/M-LWE) is NOT applicable to FRI.

FRI query regimes (BCIKS20 "Proximity Gaps for Reed-Solomon Codes" + the ethSTARK conjecture):
  unique-decoding (provable) · Johnson bound (provable) · capacity (conjectured, deployed).

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

def report(label, cell_bits, challenge_ext_deg, log_blowup, num_queries, pow_bits,
           max_deg, max_rows, hash_bits=256):
    rho = 2.0 ** (-log_blowup)
    field = challenge_ext_deg * cell_bits
    deep = field - log2(max_deg * (2 ** log_blowup) * max_rows)   # DEEP/ALI Schwartz-Zippel term
    def q(one_minus_delta):
        return -num_queries * log2(one_minus_delta) + pow_bits
    ud, john, conj = q((1 + rho) / 2), q(math.sqrt(rho)), q(rho)
    hash_coll = hash_bits / 2
    pq_grind_conj = conj - pow_bits + pow_bits / 2                 # quantum: grinding Grover-halved
    classical = min(deep, conj, hash_coll)
    classical_prov = min(deep, john, hash_coll)
    pq = min(deep, pq_grind_conj, hash_coll)                      # IOP preserved; hash = Cat-2
    print(f"=== {label} ===")
    print(f"  challenge field {challenge_ext_deg}x{cell_bits:.1f}b   : {field:6.1f} bits")
    print(f"  constraint/DEEP (deg{max_deg})       : {deep:6.1f} bits")
    print(f"  FRI query+PoW ud/john/conj    : {ud:5.0f} / {john:5.0f} / {conj:5.0f} bits")
    print(f"  SHAKE256 collision            : {hash_coll:6.1f} bits")
    print(f"  OVERALL classical conj/john   : {classical:6.1f} / {classical_prov:6.1f} bits")
    print(f"  OVERALL POST-QUANTUM          : {pq:6.1f} bits   {'>= 128 OK' if pq >= 128 else '< 128'}")
    print()
    return pq

if __name__ == "__main__":
    # Arm A membership (membership_config): challenge field = degree-3 over Complex<Mersenne31>
    # = GF(p^6), p = 2^31-1; FRI log_blowup 3 / q 96 / PoW 20; membership AIR degree 5.
    a = report("ARM A  (Complex<M31> value, Poseidon256, challenge GF(p^6))",
               log2(M31), 6, 3, 96, 20, max_deg=5, max_rows=32)
    # Arm B membership (default_config_bb): challenge field = degree-5 over BabyBear = GF(q^5);
    # FRI log_blowup 4 / q 96 / PoW 20; membership AIR degree 7.
    b = report("ARM B  (BabyBear value, Poseidon2, challenge GF(q^5))",
               log2(BABYBEAR), 5, 4, 96, 20, max_deg=7, max_rows=32)
    print(f"Both arms >= 128-bit PQ: {a >= 128 and b >= 128}  (binding term: SHAKE256 hash, 128)")
