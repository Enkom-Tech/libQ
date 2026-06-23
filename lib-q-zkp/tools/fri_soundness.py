#!/usr/bin/env python3
"""Arm B (BabyBear / Poseidon2) membership-STARK soundness calculator — classical AND post-quantum.

Computes the bits of security delivered by the Arm B config (`default_config_bb` /
`default_zk_config_bb` in `lib-q-zkp/src/stark_baby_bear.rs`) across every soundness term, and the
overall (min) under each FRI regime, classically and post-quantum. Run: `python fri_soundness.py`.

This is HASH + Reed-Solomon soundness arithmetic, not lattice estimation — Sage / lattice-estimator
(M-SIS/M-LWE) is NOT applicable to FRI.

FRI query regimes (BCIKS20 "Proximity Gaps for Reed-Solomon Codes" + the ethSTARK conjecture):
  unique-decoding (provable) · Johnson bound (provable) · capacity (conjectured, deployed).

Post-quantum model (the deployed / "mainstream" one — Plonky3, ethSTARK, SP1, Risc0):
  - The Fiat-Shamir compilation of a round-by-round-sound IOP preserves its soundness in the QROM
    up to small factors, so the IOP terms (challenge field / DEEP / query) keep ~their classical
    bits (NOT a Grover square-root loss on soundness).
  - Grover gives a quadratic speedup on the GRINDING proof-of-work only (c-bit -> c/2).
  - The Merkle (SHAKE256) commitment binding rests on collision resistance: 256-bit output ->
    128-bit classical; NIST rates SHAKE256/256 as Category 2 (~128-bit PQ collision; the BHT
    quantum-collision speedup needs exponential QRAM and is not counted here).
"""
import math

log2 = math.log2

# ---- Arm B 128-bit-PQ config (mirror of stark_baby_bear.rs) ----------------
p           = 2_013_265_921   # BabyBear modulus 2^31 - 2^27 + 1
ext_deg     = 5               # challenge field F_{p^5}  (was 4 -> ~124b, now ~155b)
log_blowup  = 4               # FRI rate rho = 2^-4 = 1/16  (was 3)
num_queries = 96              # (was 100)
pow_bits    = 20              # FRI grinding (was 16)
max_deg     = 7               # max AIR constraint degree (degree-7 optimized)
max_rows    = 32              # largest measured trace height (depth 32)
capacity    = 9               # Poseidon2 sponge capacity cells
hash_bits   = 256             # Merkle MMCS commitment hash = SHAKE256

cell_bits = log2(p)           # ~30.91 bits per BabyBear element
rho       = 2.0 ** (-log_blowup)

def query_classical(one_minus_delta_per_query):
    return -num_queries * log2(one_minus_delta_per_query) + pow_bits

field_bits = ext_deg * cell_bits
sz_bits    = field_bits - log2(max_deg * max_rows)          # DEEP/ALI Schwartz-Zippel term
ud, john, conj = (query_classical((1 + rho) / 2),
                  query_classical(math.sqrt(rho)),
                  query_classical(rho))
merkle_bits = hash_bits / 2
sponge_bits = capacity * cell_bits / 2

# Post-quantum (mainstream model): IOP terms preserved; grinding Grover-halved; hash = NIST Cat-2.
pq_grind   = pow_bits / 2
pq_query_conj = conj - pow_bits + pq_grind                 # conjectured query, quantum grinding
pq_field   = sz_bits                                       # FS/DEEP preserved in QROM
pq_hash    = hash_bits / 2                                 # SHAKE256/256 collision, Cat-2 PQ

if __name__ == "__main__":
    print(f"=== Arm B soundness (deg={ext_deg}, log_blowup={log_blowup}, rho=1/{2**log_blowup}, "
          f"q={num_queries}, PoW={pow_bits}) ===\n")
    print("CLASSICAL")
    print(f"  [1] challenge field |F_p^{ext_deg}|     : {field_bits:6.1f} bits")
    print(f"  [2] constraint/DEEP Schwartz-Zippel : {sz_bits:6.1f} bits")
    print(f"  [3] FRI query+PoW  ud / john / conj : {ud:5.0f} / {john:5.0f} / {conj:5.0f} bits")
    print(f"  [4] SHAKE256 Merkle collision       : {merkle_bits:6.1f} bits")
    print(f"  [5] sponge capacity ({capacity}) collision   : {sponge_bits:6.1f} bits")
    print(f"  OVERALL classical (conjectured)     : {min(field_bits, sz_bits, conj, merkle_bits, sponge_bits):6.1f} bits")
    print(f"  OVERALL classical (provable-Johnson): {min(field_bits, sz_bits, john, merkle_bits, sponge_bits):6.1f} bits")
    print("\nPOST-QUANTUM (mainstream / deployed model)")
    print(f"  field/DEEP (FS preserved)           : {pq_field:6.1f} bits")
    print(f"  FRI query (conj, quantum grinding)  : {pq_query_conj:6.1f} bits")
    print(f"  SHAKE256 collision (NIST Cat-2)     : {pq_hash:6.1f} bits")
    pq_overall = min(pq_field, pq_query_conj, pq_hash, sponge_bits)
    print(f"  OVERALL POST-QUANTUM                : {pq_overall:6.1f} bits   "
          f"{'>= 128 OK' if pq_overall >= 128 else '< 128 FAIL'}  (binding: SHAKE256 hash)")
