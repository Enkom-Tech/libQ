import os
import sys
# Path to a lattice-estimator checkout, from $LATTICE_ESTIMATOR.
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", "lattice-estimator"))
from estimator import *
from sage.all import log

d, q = 64, 2199023255717
B = 2**33.599457
lw = LWE.Parameters(n=26*d, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1), m=29*d, tag="lazer")
sp = SIS.Parameters(n=17*d, q=q, length_bound=B, m=79*d, norm=2, tag="lazer")
for name in ("ADPS16", "MATZOV", "GJ21", "BDGL16", "LaaMosPol14", "ChaLoy21", "Kyber"):
    rc = getattr(RC, name, None)
    if rc is None:
        print(name, "not in this estimator")
        continue
    try:
        s = SIS.lattice(sp, red_cost_model=rc)
        print("SIS ", name, "%.1f" % float(log(s["rop"], 2)), "beta", s["beta"], flush=True)
    except Exception as ex:
        print("SIS ", name, "ERR", repr(ex)[:100])
    try:
        ks = {"usvp": LWE.primal_usvp, "bdd": LWE.primal_bdd, "dual_hybrid": LWE.dual_hybrid}
        res = {k: float(log(f(lw, red_cost_model=rc)["rop"], 2)) for k, f in ks.items()}
        print("LWE ", name, {k: round(v, 1) for k, v in res.items()}, "min %.1f" % min(res.values()), flush=True)
    except Exception as ex:
        print("LWE ", name, "ERR", repr(ex)[:100])
