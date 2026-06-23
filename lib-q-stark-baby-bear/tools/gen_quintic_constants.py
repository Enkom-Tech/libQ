#!/usr/bin/env python3
"""Derive + validate the BabyBear DEGREE-5 binomial extension constants F_{p^5}=F_p[x]/(x^5-W),
the FRI challenge field for the 128-bit-PQ Arm B config (5*log2 p ~= 155 bits).

Run under SageMath (needs sage.all):
  /home/unix/miniforge3/envs/sage/bin/python gen_quintic_constants.py

Emits: W, DTH_ROOT = W^((p-1)/5), EXT_GENERATOR (a VERIFIED multiplicative generator of F_{p^5}^*
expressed in the basis {1,a,a^2,a^3,a^4}), EXT_TWO_ADICITY = v_2(p^5-1). For odd degree 5,
v_2(p^5-1) = v_2(p-1) = 27 (= the base two-adicity), so there are NO extension-only 2-adic
generators (TWO_ADIC_EXTENSION_GENERATORS is empty).
"""
from sage.all import GF, PolynomialRing, valuation, factor

p = 2_013_265_921  # BabyBear 2^31 - 2^27 + 1
Fp = GF(p)
R = PolynomialRing(Fp, 'x')
x = R.gen()

# Smallest positive W such that x^5 - W is irreducible over F_p (<=> W is a non-5th-power; 5 | p-1).
W = next(w for w in range(2, 500) if (x**5 - Fp(w)).is_irreducible())
print(f"W = {W}")
assert (x**5 - Fp(W)).is_irreducible()

dth = Fp(W) ** ((p - 1) // 5)
print(f"DTH_ROOT = {dth}")
assert dth != 1 and dth**5 == 1, "DTH_ROOT must be a primitive 5th root of unity"

ta_base = valuation(p - 1, 2)
ta_ext = valuation(p**5 - 1, 2)
print(f"TWO_ADICITY(base)      = {ta_base}")
print(f"EXT_TWO_ADICITY(p^5-1) = {ta_ext}")
assert ta_ext == ta_base == 27, "odd-degree extension must not add 2-adic structure"

# VERIFY the DEPLOYED EXT_GENERATOR has full multiplicative order p^5 - 1. We check the exact literal
# shipped in baby_bear.rs (g = 8 + a, i.e. [8,1,0,0,0] in basis {1,a,a^2,a^3,a^4}) rather than emitting
# Sage's own multiplicative_generator() — that picker is non-canonical (its choice can vary by Sage
# version), so a third party re-running this script must reproduce the EXACT deployed literal, not a
# different valid generator. (Sage's multiplicative_generator() does return 8+a here, which is how the
# deployed value was originally chosen; we now pin it deterministically.)
K = GF(p**5, name='a', modulus=x**5 - Fp(W))
a = K.gen()
coeffs = [8, 1, 0, 0, 0]  # deployed EXT_GENERATOR (baby_bear.rs): g = 8 + a
g = sum(K(c) * a**i for i, c in enumerate(coeffs))
assert g.multiplicative_order() == p**5 - 1, "deployed EXT_GENERATOR [8,1,0,0,0] must generate F_{p^5}^*"
print(f"EXT_GENERATOR = {coeffs}  (deployed literal; verified order == p^5-1)")
print(f"(p^5-1 = {p**5-1})")
print(f"p^5-1 factorization 2-part: {factor(p**5-1)[0]}")

print("\n--- Rust (impl BinomialExtensionData<5> for BabyBearParameters) ---")
print(f"const W: MontyField31<Self> = MontyField31::new({W});")
print(f"const DTH_ROOT: MontyField31<Self> = MontyField31::new({dth});")
g0, g1, g2, g3, g4 = coeffs
print("const EXT_GENERATOR: [MontyField31<Self>; 5] = [")
for c in coeffs:
    print(f"    MontyField31::new({c}),")
print("];")
print(f"const EXT_TWO_ADICITY: usize = {ta_ext};")
print("type ArrayLike = [[MontyField31<Self>; 5]; 0];")
print("const TWO_ADIC_EXTENSION_GENERATORS: Self::ArrayLike = [];")
