#!/usr/bin/env python3
"""Reproducible derivation + validation of the canonical BabyBear field constants.

BabyBear is the unique 31-bit prime p = 2^31 - 2^27 + 1 with maximal 2-adicity (27).
This script DERIVES every constant the `lib-q-stark-monty31` instance needs (Montgomery
mu, the 28-entry two-adic generator table, ROOTS_8/16 and their inverses) from first
principles and cross-checks them against the canonical Plonky3 reference values that are
quotable in the paper. Output is Rust `MontyField31::new(..)` literals in CANONICAL
(non-Montgomery) form -- `new()` performs the Montgomery conversion at const-eval time.

Run:  python tools/gen_constants.py
"""

P = 2**31 - 2**27 + 1
assert P == 0x78000001 == 2013265921, "modulus"
R = 2**32  # MONTY_BITS = 32

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def inv(a, m):
    g, x, _ = egcd(a % m, m)
    assert g == 1
    return x % m

# ---- Montgomery mu: MONTY_MU = P^{-1} mod 2^32 (non-negated convention, per data_traits.rs) ----
monty_mu = inv(P, R)
print(f"P            = {P}  (0x{P:08x})")
print(f"MONTY_MU     = 0x{monty_mu:08x}   (expect 0x88000001)")
assert monty_mu == 0x88000001, "MONTY_MU mismatch vs canonical Plonky3 BabyBear"

# ---- multiplicative generator ----
order = P - 1                      # = 2^27 * 3 * 5
# factor p-1
def factor(n):
    f = {}
    d = 2
    while d * d <= n:
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1
    if n > 1:
        f[n] = f.get(n, 0) + 1
    return f
fac = factor(order)
print(f"p-1 factors  = {fac}   (expect 2^27 * 3 * 5)")
assert fac == {2: 27, 3: 1, 5: 1}

def is_gen(a):
    return all(pow(a, order // q, P) != 1 for q in fac)
GEN = 31
assert is_gen(GEN), "31 is not a multiplicative generator"
print(f"MONTY_GEN    = {GEN}  (multiplicative generator, given to new() in canonical form)")

# ---- two-adicity ----
ta = 0
o = order
while o % 2 == 0:
    o //= 2
    ta += 1
assert ta == 27 and o == 15, (ta, o)
ODD = order >> ta
print(f"TWO_ADICITY  = {ta}   ODD_FACTOR = {ODD}")

# ---- two-adic generator of order 2^27 and the whole table ----
# w27 = GEN^((p-1)/2^27) = 31^15 ; table[i] = w27^(2^(27-i)) so table[i]^2 = table[i-1], table[27]=w27
w27 = pow(GEN, order // (2**ta), P)
print(f"2^27 root    = 0x{w27:08x}   (expect 0x1a427a41)")
assert w27 == 0x1a427a41, "2^27 generator mismatch vs canonical Plonky3"
assert pow(w27, 2**27, P) == 1 and pow(w27, 2**26, P) != 1, "not a primitive 2^27 root"

TWO_ADIC = [pow(w27, 2**(ta - i), P) for i in range(ta + 1)]   # indices 0..27, length 28
assert TWO_ADIC[0] == 1 and TWO_ADIC[27] == w27
for i in range(1, ta + 1):
    assert pow(TWO_ADIC[i], 2, P) == TWO_ADIC[i - 1], f"chain break at {i}"

# ---- ROOTS_8: the radix-2 DFT's `forward_pass` asserts roots.len() == input.len()/2, so a
# size-8 block needs HALF_N = 4 roots: [w8^0, w8^1, w8^2, w8^3]. ROOTS_8[1] == TWO_ADIC[3]. ----
w8 = TWO_ADIC[3]
ROOTS_8 = [pow(w8, k, P) for k in range(4)]
INV_ROOTS_8 = [inv(x, P) for x in ROOTS_8]
assert ROOTS_8[1] == TWO_ADIC[3]

# ---- ROOTS_16: size-16 block needs HALF_N = 8 roots: [w16^0, ..., w16^7]. ROOTS_16[1]==TWO_ADIC[4]. ----
w16 = TWO_ADIC[4]
ROOTS_16 = [pow(w16, k, P) for k in range(8)]
INV_ROOTS_16 = [inv(x, P) for x in ROOTS_16]
assert ROOTS_16[1] == TWO_ADIC[4]
# Cross-check against canonical Plonky3 BabyBear values.
assert ROOTS_8 == [0x1, 0x5ee99486, 0x67055c21, 0xc9ea3ba], ROOTS_8
assert ROOTS_16 == [0x1, 0xbb4c4e4, 0x5ee99486, 0x4b49e08, 0x67055c21, 0x5376917a, 0xc9ea3ba, 0x563112a7], ROOTS_16
assert INV_ROOTS_8 == [0x1, 0x6b615c47, 0x10faa3e0, 0x19166b7b], INV_ROOTS_8
assert INV_ROOTS_16 == [0x1, 0x21ceed5a, 0x6b615c47, 0x24896e87, 0x10faa3e0, 0x734b61f9, 0x19166b7b, 0x6c4b3b1d], INV_ROOTS_16

def rust_arr(vals):
    body = ",\n    ".join(f"MontyField31::new({v})" for v in vals)
    return "[\n    " + body + ",\n]"

print("\n==== Rust literals (canonical form; new() -> Montgomery) ====\n")
print(f"// TWO_ADIC_GENERATORS: &[MontyField31<BabyBearParameters>; 28]")
print("const TWO_ADIC_GENERATORS: &[MontyField31<BabyBearParameters>; 28] = &" + rust_arr(TWO_ADIC) + ";\n")
print("const ROOTS_8:      &[MontyField31<BabyBearParameters>; 3] = &" + rust_arr(ROOTS_8) + ";")
print("const INV_ROOTS_8:  &[MontyField31<BabyBearParameters>; 3] = &" + rust_arr(INV_ROOTS_8) + ";")
print("const ROOTS_16:     &[MontyField31<BabyBearParameters>; 7] = &" + rust_arr(ROOTS_16) + ";")
print("const INV_ROOTS_16: &[MontyField31<BabyBearParameters>; 7] = &" + rust_arr(INV_ROOTS_16) + ";")

# ===== Degree-4 binomial extension F_{p^4} = F_p[x]/(x^4 - W4), W4 = 11 (FRI challenge field) =====
W4 = 11
def e_mul(a, b):
    r = [0] * 7
    for i in range(4):
        for j in range(4):
            r[i + j] = (r[i + j] + a[i] * b[j]) % P
    for k in range(6, 3, -1):  # x^4=W4, x^5=W4*x, x^6=W4*x^2
        r[k - 4] = (r[k - 4] + W4 * r[k]) % P
        r[k] = 0
    return r[:4]
def e_pow(a, n):
    res, base = [1, 0, 0, 0], a[:]
    while n > 0:
        if n & 1:
            res = e_mul(res, base)
        base = e_mul(base, base)
        n >>= 1
    return res
ONE_E = [1, 0, 0, 0]
X = [0, 1, 0, 0]
# x^4 - 11 irreducible iff x has degree 4 over F_p:
assert e_pow(X, P) != X and e_pow(X, P * P) != X and e_pow(X, P**4) == X, "x^4-11 not irreducible"
dth4 = pow(W4, (P - 1) // 4, P)
print(f"\ndeg4 W=11  DTH_ROOT = {dth4}  (expect 1728404513)")
assert dth4 == 1728404513
o = P**4 - 1
ta4 = 0
while o % 2 == 0:
    o //= 2; ta4 += 1
print(f"deg4 EXT_TWO_ADICITY = {ta4}  (expect 29)")
assert ta4 == 29
g28 = [0, 0, 1996171314, 0]
g29 = [0, 0, 0, 124907976]
assert e_pow(g28, 2**28) == ONE_E and e_pow(g28, 2**27) != ONE_E, "TWO_ADIC_EXT_GEN[0] not order 2^28"
assert e_pow(g29, 2**29) == ONE_E and e_pow(g29, 2**28) != ONE_E, "TWO_ADIC_EXT_GEN[1] not order 2^29"
EG = [8, 1, 0, 0]  # EXT_GENERATOR = 8 + x
assert e_pow(EG, P) != EG and e_pow(EG, P * P) != EG, "EXT_GENERATOR not a degree-4 (primitive-field) element"
print("DEG-4 EXTENSION CHECKS PASSED: irreducible x^4-11, DTH_ROOT, two-adicity 29, ext 2-adic gens (orders 2^28/2^29), EXT_GENERATOR degree 4")
print("(EXT_GENERATOR full multiplicative-generator order requires factoring p^4-1; value transcribed verbatim from canonical Plonky3.)")

print("\nALL CHECKS PASSED")
