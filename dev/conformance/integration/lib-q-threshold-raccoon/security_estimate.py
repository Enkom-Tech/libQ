#!/usr/bin/env python3
"""Reproducible binding / soundness / flooding cross-check for lib-q-dkg + lib-q-threshold-raccoon.

HIDING is NOT cross-checked here by hand any more: the hand primal-uSVP model was found to be
~50 bits-of-blocksize OVER-OPTIMISTIC vs malb's lattice-estimator (it assumed full-kernel uSVP
geometry instead of the estimator's sublattice optimization). The estimator IS the gate — see
SECURITY_ANALYSIS.md §6 and sweep_qs_preserving.py. This script reports the estimator's
authoritative hiding number as a constant and keeps the statistical/combinatorial checks (binding,
soundness, flooding) that do not depend on the lattice cost model.

Cost model (binding GH only): core-SVP, classical 0.292*b, quantum 0.265*b (b = BKZ blocksize).
"""
import math

# ---- shared ring / scheme parameters ----
N      = 1024
Q      = 281_474_976_694_273          # ~2^48
LOG2Q  = math.log2(Q)
KAPPA  = 9                            # BDLOP randomness width (raised 8->9 to clear 128-bit quantum)
MU     = 6                            # BDLOP binding rows
# Authoritative hiding numbers from malb's lattice-estimator (the gate), q48 MU=6 KAPPA=9:
EST_BETA, EST_CLS, EST_QNT = 636, 186, 169   # best attack dual_hybrid, 2^212.3 ROP
TAU    = 22                           # sparse challenge weight
S_SIGN = 290_000.0                    # distributed mask width (param s; sigma = s/sqrt(2pi))
BETA_R = 4_060_000                    # verifier inf-norm bound on z_r (= 14*S_SIGN)

def delta(b):
    return ((b/(2*math.pi*math.e))*(math.pi*b)**(1.0/b))**(1.0/(2*(b-1)))

def core_svp_bits(b):
    return 0.292*b, 0.265*b

# ---- 1. BINDING (statistical): GH shortest kernel vector vs worst-case extractor gap ----
def gh_lambda1(mu, kappa):
    d = kappa*N
    return min(Q, (Q**(mu/kappa))*math.sqrt(d/(2*math.pi*math.e)))

def extractor_gap_l2(t_threshold):
    # worst case: ||z-z'||_inf <= 2*BETA_R over kappa*N dims (l-infinity-enforced response bound)
    return math.sqrt(KAPPA*N)*2*BETA_R + math.sqrt(KAPPA*N)*2*TAU

# ---- 2. HIDING: reported from the lattice-estimator (the gate), NOT a hand model ----
# The BDLOP-HNF Module-LWE instance is n=(KAPPA-MU)*N secret + MU*N ternary error, m=MU*N samples.
# Reproduce with sweep_qs_preserving.py under SageMath. Constants pinned above (EST_*).

# ---- 3. KNOWLEDGE SOUNDNESS: |C| = 2^tau * C(N, tau) ----
def soundness_bits():
    lb = (math.lgamma(N+1)-math.lgamma(TAU+1)-math.lgamma(N-TAU+1))/math.log(2)
    return TAU + lb

# ---- 4. FLOODING / RENYI for the distributed (rejection-free) protocol ----
def flooding(t_threshold, n_dealers, alpha=2.0, target_bits=128):
    """z_r = Y_r + c*r_grp ; Y_r = sum of t party masks (param S_SIGN each) => width s' = S_SIGN*sqrt(t).
       shift Delta = c*r_grp. Renyi D_alpha(shifted||centered) <= exp(alpha*pi*||Delta||^2 / s'^2).
       Bits lost over Q_s queries ~ Q_s * alpha*pi*||Delta||^2/s'^2 / ln2.
       Returns the per-key signature budget Q_s keeping the loss <= target_bits."""
    s_prime = S_SIGN*math.sqrt(t_threshold)
    # ||r_grp||_2: each of kappa*N coeffs ~ sum of n ternary, var n*(2/3)
    rgrp_l2 = math.sqrt(KAPPA*N*n_dealers*(2.0/3.0))
    delta_l2 = math.sqrt(TAU)*rgrp_l2                       # ||c*r_grp||_2 <= sqrt(tau)*||r_grp||
    per_query = alpha*math.pi*(delta_l2**2)/(s_prime**2)
    q_s = (target_bits*math.log(2))/per_query
    ratio = s_prime/delta_l2
    return s_prime, delta_l2, ratio, per_query, q_s

print("="*72)
print("lib-q-dkg / lib-q-threshold-raccoon - core-SVP & flooding cross-check")
print(f"N={N} q~2^{LOG2Q:.1f} MU={MU} KAPPA={KAPPA} TAU={TAU}")
print("="*72)

print("\n[1] BINDING (statistical, no assumption):")
gh = gh_lambda1(MU, KAPPA)
for t in (3, 16):
    gap = extractor_gap_l2(t)
    margin = math.log2(gh) - math.log2(gap)
    print(f"   t={t:2d}: GH lambda1=2^{math.log2(gh):.1f}  gap=2^{math.log2(gap):.1f}  "
          f"margin={margin:.1f} bits  (failure prob ~ 2^-{margin*KAPPA*N:.0f})")

print("\n[2] HIDING (Module-LWE) - from the lattice-estimator (the GATE, not a hand model):")
print(f"   beta={EST_BETA} (best attack dual_hybrid) -> {EST_CLS}-bit classical, {EST_QNT}-bit quantum core-SVP")
print("   (reproduce: sweep_qs_preserving.py under SageMath; hand uSVP model was ~50b over-optimistic)")

print("\n[3] KNOWLEDGE SOUNDNESS (Fiat-Shamir):")
print(f"   |C| = 2^tau * C(N,tau) = 2^{soundness_bits():.1f}")

print("\n[4] FLOODING / RENYI (distributed rejection-free signing, per-key signature budget):")
for t in (2, 3, 16):
    for n in (5, 16):
        s_prime, delta_l2, ratio, per_q, q_s = flooding(t, n)
        print(f"   t={t:2d} n={n:2d}: s'={s_prime:.0f} ||c*r_grp||={delta_l2:.0f} "
              f"flood-ratio={ratio:.0f}  budget Q_s ~ 2^{math.log2(q_s):.1f} sigs (128-bit)")
print("   (root/recovery keys sign rarely; raise S_SIGN to extend the budget, at z_r/sig-size cost)")
