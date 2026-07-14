#!/usr/bin/env python3
"""Decapsulation-KEY-side Module-LWE estimate for lib-q-threshold-kem-lattice.

This is the **load-bearing** hardness gate for the KEM (SECURITY_ANALYSIS.md §1):
the ciphertext instance (`ciphertext_estimate.py`) is ~800 bits above the bar, so the
key-hiding instance below is the actual security bottleneck.

Recovering the decapsulation key `r` from the public key

    t0 = B0 * r        (B0 in HNF [I | B0'] over R_q^{MU x KAPPA}, r ternary in R_q^KAPPA)

is **exactly** the BDLOP-randomness Module-LWE instance the DKG / lib-q-threshold-raccoon
stack is estimator-gated on (`t0` is the raccoon DKG public key; nothing in this crate
changes that instance). In Hermite-normal form the decision problem is

    secret dimension  n = (KAPPA - MU) * N = 3072    (ternary)
    samples           m = MU * N          = 6144
    modulus           q = 281474976694273 (~2^48)
    secret dist       Xs = U(-1, 1)       (ternary)
    error dist        Xe = U(-1, 1)       (ternary)

This file exists to make that number **reproducible-from-config in THIS crate** (closing
review finding H3) rather than transcribed from the sibling repo. It is byte-for-byte the
same instance as ../lib-q-threshold-raccoon/archive_estimator_run.py's HIDING block; the
archived output is vendored alongside as `key_estimate.log` (provenance in its header).

Run under the SageMath conda env with the malb/lattice-estimator on PYTHONPATH:

    export PYTHONPATH=/home/unix/lattice-estimator
    /home/unix/miniforge3/envs/sage/bin/python -u key_estimate.py > key_estimate.log 2>&1

GOTCHA: always deny bkw / arora-gb (pathologically slow at these dimensions, never the
minimum). Emit the full per-attack table (not just the best line) so the load-bearing
figure is reproducible-from-artifact, not a transcribed constant; report the cost-model
spread on the best attack (single-model claims are not robust).
"""

import math
import time

from estimator import LWE, ND
from estimator.reduction import RC

N = 1024
MU = 6
KAPPA = 9
Q = 281474976694273

# HNF hiding instance: (KAPPA - MU)*N ternary secret, MU*N ternary error / samples.
SECRET_DIM = (KAPPA - MU) * N   # 3072
SAMPLES = MU * N               # 6144

DENY = ("bkw", "arora-gb")

# core-SVP exponents (per BKZ blocksize beta): classical 0.292, quantum 0.265.
CLASSICAL = 0.292
QUANTUM = 0.265


def params() -> "LWE.Parameters":
    return LWE.Parameters(
        n=SECRET_DIM,
        q=Q,
        Xs=ND.Uniform(-1, 1),
        Xe=ND.Uniform(-1, 1),
        m=SAMPLES,
        tag="tkem-key-hiding",
    )


def main() -> None:
    print(f"# decap-key hiding MLWE (HNF): n={SECRET_DIM} m={SAMPLES} "
          f"q={Q} Xs=Xe=U(-1,1)")
    print("# deny_list=('bkw','arora-gb')  [never optimal here; the slow attacks]")

    print("\n--- full attack table (deny bkw/arora-gb), default cost model ---")
    t0 = time.time()
    res = LWE.estimate(params(), deny_list=DENY)
    for name, cost in res.items():
        print(f"    {name}: rop=2^{math.log2(float(cost['rop'])):.1f} "
              f"beta={int(cost.get('beta', 0))}")
    best = min(res.values(), key=lambda v: float(v["rop"]))
    b = int(best["beta"])
    print(f"\n>>> BEST attack: rop=2^{math.log2(float(best['rop'])):.1f} beta={b} "
          f"=> core-SVP {CLASSICAL * b:.0f}-bit classical / {QUANTUM * b:.0f}-bit quantum "
          f"({time.time() - t0:.0f}s)", flush=True)
    print(f">>> Gate: {'PASS' if QUANTUM * b >= 128 else 'FAIL'} "
          f"(>=128 quantum core-SVP)")

    print("\n--- cost-model spread at the best point ---")
    for model_name in ("ADPS16", "MATZOV", "CheNgu12"):
        model = getattr(RC, model_name)
        t0 = time.time()
        r = LWE.estimate(params(), red_cost_model=model, deny_list=DENY)
        bb = int(min(r.values(), key=lambda v: float(v["rop"]))["beta"])
        print(f"model={model_name}: beta={bb} => {QUANTUM * bb:.0f}-bit quantum "
              f"({time.time() - t0:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
