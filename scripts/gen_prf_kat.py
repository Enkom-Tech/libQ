#!/usr/bin/env python3
"""Generate KAT lines for lib-q-prf (Legendre + Gold PRF) using SymPy.

Requires: pip install sympy

Output: prints lines suitable for appending to lib-q-prf/tests/reference_vectors.txt
"""

from __future__ import annotations

import hashlib
import sys

try:
    from sympy import isprime
except ImportError as e:  # pragma: no cover
    print("Install sympy: pip install sympy", file=sys.stderr)
    raise e


P256_HEX = (
    "6f7cfe74b8a1892ed54ec11ae8141a65dad3440973464111361ce7de4a5c5cfb"
)
P512_HEX = (
    "6fa0e975b4660858abfccfb1a2f3b5f8cda4239a89afa1840e62d758ae53a940"
    "59ab27f1f7833146306bf0d1c2647d9ca136b85e4c24dbdf0a4c8ef916f0094f"
)


def legendre_symbol(a: int, p: int) -> int:
    """Jacobi/Legendre for odd prime p."""
    if a % p == 0:
        return 0
    return pow(a, (p - 1) // 2, p) if pow(a, (p - 1) // 2, p) == 1 else -1


def gold_prf(k: int, x: int, g: int, p: int) -> int:
    return pow((k + x) % p, g, p)


def sha256_le_uint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def emit_set(name: str, p: int) -> None:
    assert isprime(p)
    q = (p - 1) // 2
    assert isprime(q)
    p_le = p.to_bytes((p.bit_length() + 7) // 8, "little")
    # left-pad to 32 or 64 bytes for U256/U512 wire
    if name == "256":
        assert p.bit_length() <= 256
        p_le_padded = p_le.ljust(32, b"\x00")
    else:
        assert p.bit_length() <= 512
        p_le_padded = p_le.ljust(64, b"\x00")
    label = "SHA256_P256_LE" if name == "256" else "SHA256_P512_LE"
    print(f"{label}={sha256_le_uint(p_le_padded)}")
    k = 0x123456789ABCDEF % p
    if k == 0:
        k = 1
    x = 0xFEDCBA9876543210 % p
    if (x + k) % p == 0:
        x = (x + 1) % p
    leg = legendre_symbol((x + k) % p, p)
    g_exp = q
    gout = gold_prf(k, x, g_exp, p)
    print(f"KAT_{name}_K_LE={k.to_bytes(32 if name=='256' else 64, 'little').hex()}")
    print(f"KAT_{name}_X_LE={x.to_bytes(32 if name=='256' else 64, 'little').hex()}")
    print(f"KAT_{name}_LEGENDRE={leg}")
    print(
        f"KAT_{name}_GOLD_LE="
        f"{gout.to_bytes(32 if name=='256' else 64, 'little').hex()}"
    )


def main() -> None:
    p256 = int(P256_HEX, 16)
    p512 = int(P512_HEX, 16)
    emit_set("256", p256)
    emit_set("512", p512)


if __name__ == "__main__":
    main()
