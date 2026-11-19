#!/usr/bin/env python3
"""Derive + self-certify the BabyBear DEGREE-8 binomial extension constants F_{p^8}=F_p[x]/(x^8-W),
the FRI challenge field for Arm B (8*log2 p ~= 248 bits), so the Fiat-Shamir/DEEP/BCIKS field term
clears 128 bits on the PROVEN (Johnson) bound as well as the conjectured one.

Pure Python 3 (no Sage). Self-certifying: an element of multiplicative order p^8-1 inside the ring
F_p[x]/(x^8-W) proves the ring is a field AND that the element generates its unit group. The prime
factorisation of p^8-1 = (p-1)(p+1)(p^2+1)(p^4+1) below was produced with coreutils `factor`, and it
is re-checked here (all prime factors divided out leaves 1).

Run:  python3 gen_octic_constants.py
"""
P = 2_013_265_921            # 2^31 - 2^27 + 1
D = 8
W = 11                       # same non-residue as the deployed degree-4 field (x^4-11)

FACTORS = {  # prime factors of the cyclotomic pieces of p^8 - 1, via coreutils `factor`
    "p-1":   [2, 3, 5],
    "p+1":   [2, 31, 32472031],
    "p^2+1": [2, 97, 12241, 1706804017873],
    "p^4+1": [2, 17, 1666201, 74565857, 3889181823063218424889],
}
PRIMES = sorted({q for v in FACTORS.values() for q in v})
N = P**8 - 1


def mult(n, q):
    k = 0
    while n % q == 0:
        n //= q
        k += 1
    return k, n


rest = N
for q in PRIMES:
    _, rest = mult(rest, q)
assert rest == 1, "factorisation of p^8-1 incomplete"
V2 = mult(N, 2)[0]
print(f"v_2(p^8-1) = {V2}")


def mul(a, b):
    r = [0] * (2 * D - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i + j] += ai * bj
    out = r[:D]
    for k in range(D, 2 * D - 1):
        out[k - D] += W * r[k]
    return [c % P for c in out]


ONE = [1] + [0] * (D - 1)


def pw(a, e):
    r = ONE
    while e:
        if e & 1:
            r = mul(r, a)
        a = mul(a, a)
        e >>= 1
    return r


def is_generator(g):
    if pw(g, N) != ONE:
        return False
    return all(pw(g, N // q) != ONE for q in PRIMES)


a = next(a for a in range(1, 1000) if is_generator([a, 1] + [0] * (D - 2)))
GEN = [a, 1] + [0] * (D - 2)
print(f"EXT_GENERATOR = {GEN}  (order == p^8-1  =>  x^8-{W} is a field and g generates F_p8*)")

dth = pow(W, (P - 1) // D, P)
assert pow(dth, D, P) == 1 and pow(dth, D // 2, P) != 1
print(f"DTH_ROOT = {dth}")

# Base-field two-adic generator of order exactly 2^27 (BabyBear TWO_ADIC_GENERATORS[27]).
G27 = 440564289
assert pow(G27, 2**26, P) == P - 1, "G27 must have order exactly 2^27"
h = pw(GEN, N >> V2)                       # order exactly 2^V2
assert pw(h, 2 ** (V2 - 1)) != ONE
h27 = pw(h, 2 ** (V2 - 27))                # order 2^27, necessarily inside the base field
assert all(c == 0 for c in h27[1:])
target = h27[0]
# Pohlig-Hellman in the 2-group: find log with G27^log == target.
log = 0
for i in range(27):
    cur = target * pow(pow(G27, log, P), P - 2, P) % P
    if pow(cur, 2 ** (26 - i), P) != 1:
        log |= 1 << i
assert pow(G27, log, P) == target and log % 2 == 1
m = pow(log, -1, 2**27)
hh = pw(h, m)                              # now hh^(2^(V2-27)) == G27 exactly
top = pw(hh, 2 ** (V2 - 27))
assert top[0] == G27 and top[1:] == [0] * (D - 1)
gens = []
for bits in range(28, V2 + 1):             # TWO_ADIC_EXTENSION_GENERATORS[bits-28]
    g = pw(hh, 2 ** (V2 - bits))
    gens.append(g)
    assert pw(g, 2 ** (bits - 1)) != ONE and pw(g, 2**bits) == ONE
# consistency: each generator squares to the previous level
prev = [G27] + [0] * (D - 1)
for g in gens:
    assert mul(g, g) == prev
    prev = g
print(f"EXT_TWO_ADICITY = {V2}")
for bits, g in zip(range(28, V2 + 1), gens):
    print(f"two-adic generator 2^{bits}: {g}")

print("\n--- Rust (impl BinomialExtensionData<8> for BabyBearParameters) ---")
print(f"const W: MontyField31<Self> = MontyField31::new({W});")
print(f"const DTH_ROOT: MontyField31<Self> = MontyField31::new({dth});")
print(f"const EXT_GENERATOR: [MontyField31<Self>; 8] = {GEN};")
print(f"const EXT_TWO_ADICITY: usize = {V2};")
