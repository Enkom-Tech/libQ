import math
import os
import sys

# The shim sits next to this file. The lattice-estimator checkout is found through
# LATTICE_ESTIMATOR (a directory containing the `estimator` package).
sys.path[:0] = [os.path.dirname(os.path.abspath(__file__)), os.environ.get("LATTICE_ESTIMATOR", "lattice-estimator")]
import sage_all_shim  # noqa: F401
from estimator import LWE, SIS
from estimator import nd as ND

# Approximation used for every number in blns-138bit-parameter-set.md: 2**41 = 2199023255552, versus
# LaZer's q = 2199023255717 (they differ by 165). Override with the environment variable Q to re-run
# with the exact modulus; the committed numbers were NOT produced with it.
q = int(os.environ.get("Q", 2**41))
B = 2**33.599457
d = 64


def lg(x):
    return round(math.log2(x), 1)


which = sys.argv[1]
ranks = [int(x) for x in sys.argv[2:]]
for k in ranks:
    if which == "lwe":
        # keep the declared MLWE(26,29): n = 64*k secret rank, m = 64*(k+3) samples
        p = LWE.Parameters(n=d*k, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1), m=d*(k+3))
        r = LWE.estimate(p, deny_list=("arora-gb", "bkw"), jobs=1, quiet=True)
    else:
        # keep the declared MSIS(17,79): m = 64*(k+62)
        p = SIS.Parameters(n=d*k, q=q, length_bound=B, m=d*(k+62), norm=2)
        r = SIS.estimate(p, quiet=True)
    print(which, k, min(lg(v["rop"]) for v in r.values()), flush=True)
