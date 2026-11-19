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
which = sys.argv[1]


def lg(x):
    return round(math.log2(x), 1)


if which == "lwe":
    # CONTROL first, then REAL; full estimate, default cost model, bkw/arora-gb denied (as in the research note)
    for name, (n, m) in {"CONTROL": (256, 300), "REAL": (1664, 1856)}.items():
        p = LWE.Parameters(n=n, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1), m=m)
        r = LWE.estimate(p, deny_list=("arora-gb", "bkw"), jobs=1, quiet=True)
        print(name, {k: lg(v["rop"]) for k, v in r.items()}, "MIN", min(lg(v["rop"]) for v in r.values()), flush=True)
else:
    # MSIS(17,79,B=2^33.599457) at d=64: SIS n=17*64, m=79*64, l2 bound B. CONTROL: tiny rank.
    for name, (n, m, B) in {"CONTROL": (64, 300, 2**20.0), "REAL": (17*64, 79*64, 2**33.599457)}.items():
        p = SIS.Parameters(n=n, q=q, length_bound=B, m=m, norm=2)
        r = SIS.estimate(p, quiet=True)
        print(name, {k: lg(v["rop"]) for k, v in r.items()}, "MIN", min(lg(v["rop"]) for v in r.values()), flush=True)
