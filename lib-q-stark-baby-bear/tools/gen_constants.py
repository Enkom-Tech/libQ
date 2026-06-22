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

# ---- ROOTS_8 (first 3 8th-roots: [1, w8, w8^2]) ; ROOTS_8[1] == TWO_ADIC[3] ----
w8 = TWO_ADIC[3]
ROOTS_8 = [pow(w8, k, P) for k in range(3)]
INV_ROOTS_8 = [inv(x, P) for x in ROOTS_8]
assert ROOTS_8[1] == TWO_ADIC[3]

# ---- ROOTS_16 (first 7 16th-roots: [1, w16, ..., w16^6]) ; ROOTS_16[1] == TWO_ADIC[4] ----
w16 = TWO_ADIC[4]
ROOTS_16 = [pow(w16, k, P) for k in range(7)]
INV_ROOTS_16 = [inv(x, P) for x in ROOTS_16]
assert ROOTS_16[1] == TWO_ADIC[4]

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

print("\nALL CHECKS PASSED")
