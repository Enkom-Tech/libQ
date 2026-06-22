#!/usr/bin/env python3
"""Arm B (BabyBear / Poseidon2) membership-STARK soundness-parameter calculator.

Computes the bits of security delivered by the *default* Arm B config
(`default_config_bb` / `default_zk_config_bb` in `lib-q-zkp/src/stark_baby_bear.rs`)
across every soundness term, and reports the overall (min) under each FRI regime.

This is HASH + Reed-Solomon soundness arithmetic, not lattice estimation — Sage /
lattice-estimator (M-SIS/M-LWE) is NOT applicable to FRI. Run: `python fri_soundness.py`.

Regimes for the FRI query phase (per BCIKS20 "Proximity Gaps for Reed-Solomon Codes"
and the ethSTARK soundness conjecture):
  - unique-decoding  : fully provable, per-query evasion (1+rho)/2
  - Johnson bound    : provable (list-decoding), per-query evasion sqrt(rho)
  - capacity         : conjectured (what Plonky3 / ethSTARK deploy), per-query evasion rho
"""
import math

log2 = math.log2

# ---- Arm B default config (mirror of stark_baby_bear.rs) --------------------
p           = 2_013_265_921   # BabyBear modulus 2^31 - 2^27 + 1
ext_deg     = 4               # challenge field F_{p^4}  (BbChallenge)
log_blowup  = 3               # FRI rate rho = 2^-3 = 1/8
num_queries = 100
pow_bits    = 16              # FRI grinding (proof_of_work_bits)
max_deg     = 7               # max AIR constraint degree (degree-7 optimized)
max_rows    = 32              # largest measured trace height (depth 32)
capacity    = 9               # Poseidon2 sponge capacity cells
digest      = 9               # output digest cells
hash_bits   = 256             # Merkle MMCS commitment hash = Shake256

cell_bits = log2(p)           # ~30.91 bits per BabyBear element
rho       = 2.0 ** (-log_blowup)

def query_bits(one_minus_delta_per_query):
    return -num_queries * log2(one_minus_delta_per_query) + pow_bits

field_bits = ext_deg * cell_bits
sz_bits    = field_bits - log2(max_deg * max_rows)         # DEEP/ALI Schwartz-Zippel term
ud, john, conj = (query_bits((1 + rho) / 2),
                  query_bits(math.sqrt(rho)),
                  query_bits(rho))
merkle_bits  = hash_bits / 2
sponge_bits  = capacity * cell_bits / 2

if __name__ == "__main__":
    print(f"=== Arm B FRI soundness (log_blowup={log_blowup}, rho=1/{2**log_blowup}, "
          f"q={num_queries}, PoW={pow_bits}) ===\n")
    print(f"[1] Challenge field |F_p^4|         : {field_bits:6.1f} bits")
    print(f"[2] Constraint/DEEP Schwartz-Zippel : {sz_bits:6.1f} bits   (|F| / (deg{max_deg} * rows{max_rows}))")
    print(f"[3] FRI query phase + {pow_bits}b PoW:")
    print(f"      unique-decoding (provable)    : {ud:6.1f} bits")
    print(f"      Johnson bound   (provable)    : {john:6.1f} bits")
    print(f"      capacity        (conjectured) : {conj:6.1f} bits")
    print(f"[4] Merkle MMCS (Shake256) collision: {merkle_bits:6.1f} bits")
    print(f"    Sponge capacity ({capacity} cells) coll. : {sponge_bits:6.1f} bits")
    print(f"\n=== OVERALL (min of all terms) ===")
    for label, q in [("provable (unique-decoding)", ud),
                     ("provable (Johnson)", john),
                     ("conjectured (capacity)", conj)]:
        overall = min(field_bits, sz_bits, q, merkle_bits, sponge_bits)
        print(f"  {label:30s}: {overall:6.1f} bits")
