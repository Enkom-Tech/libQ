# L1: both-sided lattice-estimator check of LaZer anon_cred parameters (+ controls).
import os
import sys
import time
# Path to a lattice-estimator checkout, from $LATTICE_ESTIMATOR.
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", "lattice-estimator"))
from estimator import *
from sage.all import oo, log, RR
d, q = 64, 2199023255717
which = sys.argv[1]

def mlwe(k, m, tag):
    # module rank k, m ring samples, ternary secret and error, flattened to LWE over Z_q
    return LWE.Parameters(n=k*d, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1), m=m*d, tag=tag)

def sis(k, m, bound, tag):
    return SIS.Parameters(n=k*d, q=q, length_bound=bound, m=m*d, norm=2, tag=tag)

t = time.time()
if which == "mlwe_ctrl":
    r = LWE.estimate(mlwe(2, 3, "ctrl"), deny_list=("bkw", "arora-gb"))
elif which == "mlwe_real":
    r = LWE.estimate(mlwe(26, 29, "lazer"), deny_list=("bkw", "arora-gb"))
elif which == "sis_ctrl":      # same q,d,bound, tiny rank: must be easy
    r = SIS.estimate(sis(2, 5, 2**33.599457, "ctrl"))
elif which == "sis_real":
    r = SIS.estimate(sis(17, 79, 2**33.599457, "lazer"))
for k, v in r.items():
    print(which, k, v)
print(which, "min log2 rop =", min(float(log(v["rop"], 2)) for v in r.values()), "secs", round(time.time()-t))
