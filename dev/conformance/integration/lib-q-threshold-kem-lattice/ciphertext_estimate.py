#!/usr/bin/env python3
"""Ciphertext-side Module-LWE estimate for lib-q-threshold-kem-lattice.

The dual-Regev ciphertext is

    p = B0^T e + f   (KAPPA ring elements)
    v = <t0, e> + g  (1 ring element)

with e uniform ternary in R_q^MU and f, g uniform in [-B, B] per coefficient.
IND-CPA of the ciphertext is decision Module-LWE with

    secret dimension  n = MU * N          = 6144
    samples           m = (KAPPA+1) * N   = 10240
    modulus           q = 281474976694273 (~2^48)
    secret dist       Xs = U(-1, 1)       (ternary)
    error dist        Xe = U(-B, B)       (uniform, integer-only for the FO check)

This is a DISTINCT instance from the decapsulation-key instance (t0 = B0 r,
secret r ternary in R_q^KAPPA), which is the same MLWE the DKG/raccoon archive
run gated at 186-bit classical / 169-bit quantum core-SVP (beta = 636); see
../lib-q-threshold-raccoon/archive_estimator_run.py.

Run under the SageMath conda env with the malb/lattice-estimator on PYTHONPATH:

    export PYTHONPATH=/home/unix/lattice-estimator
    /home/unix/miniforge3/envs/sage/bin/python ciphertext_estimate.py

GOTCHA: always deny bkw / arora-gb (pathologically slow at these dimensions,
never the minimum). rough() first to locate the threshold, full estimate to
confirm the chosen point, and report the cost-model spread on the load-bearing
number (single-model claims are not robust; see the repo estimator notes).
"""

import math
import time

from estimator import LWE, ND
from estimator.reduction import RC

N = 1024
MU = 6
KAPPA = 9
Q = 281474976694273

SECRET_DIM = MU * N
SAMPLES = (KAPPA + 1) * N

DENY = ("bkw", "arora-gb")

# Uniform error bounds to sweep (the width knob ENC_ERROR_BOUND in kem.rs).
BOUNDS = [2**18, 2**20, 2**22, 2**24]


def bits(result) -> float:
    return min(math.log2(float(cost["rop"])) for cost in result.values())


def params(bound: int) -> "LWE.Parameters":
    return LWE.Parameters(
        n=SECRET_DIM,
        q=Q,
        Xs=ND.Uniform(-1, 1),
        Xe=ND.Uniform(-bound, bound),
        m=SAMPLES,
        tag=f"tkem-ct-B={bound}",
    )


def main() -> None:
    print(f"# ciphertext MLWE: n={SECRET_DIM} m={SAMPLES} q={Q} Xs=U(-1,1)")
    print("## rough sweep (conservative ~half-bits; threshold location only)")
    for bound in BOUNDS:
        t0 = time.time()
        res = LWE.estimate.rough(params(bound))
        print(f"B=2^{int(math.log2(bound))}: rough={bits(res):.1f} bits "
              f"({time.time() - t0:.0f}s)", flush=True)

    print("## full estimate (deny bkw/arora-gb), default cost model")
    for bound in BOUNDS:
        t0 = time.time()
        res = LWE.estimate(params(bound), deny_list=DENY)
        print(f"B=2^{int(math.log2(bound))}: full={bits(res):.1f} bits "
              f"({time.time() - t0:.0f}s)", flush=True)
        for name, cost in res.items():
            print(f"    {name}: rop=2^{math.log2(float(cost['rop'])):.1f}")

    print("## cost-model spread at B=2^20 (load-bearing point)")
    for model_name in ("ADPS16", "MATZOV", "CheNgu12"):
        model = getattr(RC, model_name)
        t0 = time.time()
        res = LWE.estimate(params(2**20), red_cost_model=model, deny_list=DENY)
        print(f"model={model_name}: {bits(res):.1f} bits "
              f"({time.time() - t0:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
