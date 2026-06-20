import sys
from sage.all import RR, log, sqrt, pi, e
from estimator import *

# Estimator-driven Pareto sweep for lib-q hiding (Module-LWE).
# INVARIANT: BETA_R is held FIXED (at the final 4_060_000) so S_SIGN and therefore the
# per-key budget Q_s = 2^20 are PRESERVED on every row. We only move levers that
# do NOT touch Q_s: the ring modulus q and the module shape (MU, KAPPA).
# Goal: quantum core-SVP >= 128  <=>  BKZ blocksize beta >= 483.

N = 1024
# BETA_R is the FINAL value (= 14*S_SIGN, S_SIGN=290_000) at the chosen KAPPA=9, which restores the
# worst-case Q_s to >= 2^20 after the KAPPA bump grew ||c*r_grp||. Hiding (LWE.estimate) is
# BETA_R-independent, so the per-candidate beta/core-SVP are unchanged; only the binding-margin
# column reflects this value. Q_s is held at >= 2^20 on every row (not traded down for hiding bits).
BETA_R = 4_060_000
TAU = 22

def coreq(b): return 0.265 * b
def corec(b): return 0.292 * b

def bind_margin(q, MU, KAPPA):
    d = KAPPA * N
    gh = min(RR(log(q, 2)), RR(log(q, 2)) * MU / KAPPA + 0.5 * RR(log(d / (2 * pi * e), 2)))
    gap = RR(log(sqrt(d) * 2 * BETA_R + sqrt(d) * 2 * TAU, 2))
    return float(gh - gap), float(gh), float(gap)

def sig_kib(KAPPA): return ((2 + KAPPA) * N * 6 + 2) / 1024.0

# (label, q, MU, KAPPA) -- BETA_R fixed above (Q_s = 2^20 everywhere)
cands = [
    ("q48 mu6 k8  (current)", 281474976694273, 6,  8),
    ("q48 mu6 k9",            281474976694273, 6,  9),
    ("q48 mu6 k10",           281474976694273, 6, 10),
    ("q48 mu6 k11",           281474976694273, 6, 11),
    ("q48 mu8 k12",           281474976694273, 8, 12),
    ("q40 mu6 k8  (low-q)",   1099511627689,   6,  8),
]

for label, q, MU, KAPPA in cands:
    n_lwe = (KAPPA - MU) * N
    m = MU * N
    bm, gh, gap = bind_margin(q, MU, KAPPA)
    print("==== %s : n_lwe=%d m=%d sig=%.1fKiB Qs=2^20 bind_margin=%.1f (GH2^%.1f gap2^%.1f) ====" %
          (label, n_lwe, m, sig_kib(KAPPA), bm, gh, gap))
    sys.stdout.flush()
    try:
        r = LWE.estimate(
            LWE.Parameters(n=n_lwe, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1), m=m),
            deny_list=("arora-gb", "bkw"))
        best = min(r.values(), key=lambda v: v["rop"])
        b = best.get("beta", 0)
        print("   >>> best 2^%.1f rop beta=%d  coreSVP %.0f cls / %.0f qnt  %s  bind=%s" %
              (RR(log(best["rop"], 2)), b, corec(b), coreq(b),
               "OK>=128q" if coreq(b) >= 128 else "FAIL<128q",
               "OK" if bm > 0 else "BROKEN"))
        sys.stdout.flush()
    except Exception as ex:
        print("   estimate error:", repr(ex))
        sys.stdout.flush()
