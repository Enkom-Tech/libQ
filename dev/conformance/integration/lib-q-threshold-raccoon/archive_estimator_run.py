"""Archival lattice-estimator run for the FINAL Threshold-Raccoon / lib-q-dkg params.

Emits the full per-attack table (not just the best line) so the 169-bit-quantum hiding
figure in SECURITY_ANALYSIS.md §6 is reproducible-from-artifact, not a transcribed constant.

Run under SageMath with malb's lattice-estimator:
  PYTHONPATH=~/lattice-estimator python -u archive_estimator_run.py > estimator_run_kappa9.txt 2>&1
"""
import sys
from sage.all import RR, log
from estimator import *

N, q, MU, KAPPA = 1024, 281474976694273, 6, 9
n_lwe, m = (KAPPA - MU) * N, MU * N

print("==================================================================")
print(" lib-q-dkg / lib-q-threshold-raccoon - ARCHIVED estimator run")
print(" FINAL params: N=%d  q=%d (~2^48)  MU=%d  KAPPA=%d" % (N, q, MU, KAPPA))
print(" HIDING M-LWE (BDLOP HNF): n=(KAPPA-MU)*N=%d secret + MU*N=%d ternary error, m=%d" % (n_lwe, m, m))
print(" deny_list=('arora-gb','bkw')  [never optimal here; the slow attacks]")
print("==================================================================")
sys.stdout.flush()

print("\n--- HIDING: LWE.estimate full attack table ---")
sys.stdout.flush()
r = LWE.estimate(
    LWE.Parameters(n=n_lwe, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1), m=m),
    deny_list=("arora-gb", "bkw"))
best = min(r.values(), key=lambda v: v["rop"])
b = best["beta"]
print("\n>>> BEST attack: rop=2^%.1f  beta=%d  =>  core-SVP %.0f-bit classical / %.0f-bit quantum"
      % (RR(log(best["rop"], 2)), b, 0.292 * b, 0.265 * b))
print(">>> Gate: %s (>=128 quantum core-SVP)" % ("PASS" if 0.265 * b >= 128 else "FAIL"))
sys.stdout.flush()

print("\n--- BINDING: SIS.estimate on B0 (l2 target = relaxed-extractor gap 2^29.5; expect infeasible) ---")
sys.stdout.flush()
try:
    s = SIS.estimate(SIS.Parameters(n=MU * N, q=q, length_bound=2 ** 29.5, m=KAPPA * N))
    bs = min(s.values(), key=lambda v: v["rop"])
    print(">>> BEST SIS: rop=2^%.1f  (infeasible <=> target below GH kernel vector 2^36.5)"
          % RR(log(bs["rop"], 2)))
except Exception as ex:
    print(">>> SIS:", repr(ex))
sys.stdout.flush()
