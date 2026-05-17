"""One-off: strip hax from portable NTT sources (run from lib-q-ring/)."""
from __future__ import annotations

import pathlib
import re


def strip_hax(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("#[cfg(hax)]"):
            i += 1
            continue
        if "hax_lib::" in line and line.strip().startswith("#["):
            depth = line.count("(") - line.count(")")
            i += 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count("(") - lines[i].count(")")
                i += 1
            continue
        if "hax_lib::loop_invariant" in line or "hax_lib::fstar!" in line:
            depth = line.count("(") - line.count(")")
            i += 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count("(") - lines[i].count(")")
                i += 1
            continue
        if stripped.startswith("hax_lib!"):
            depth = line.count("(") - line.count(")")
            i += 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count("(") - lines[i].count(")")
                i += 1
            continue
        if "#[cfg_attr(tarpaulin" in line:
            out.append("#[inline(always)]\n")
            i += 1
            continue
        out.append(line)
        i += 1
    return "".join(out)


def main() -> None:
    here = pathlib.Path(__file__).resolve().parent
    root = here.parent / "lib-q-ml-dsa" / "src" / "simd" / "portable"
    for name in ["ntt.rs", "invntt.rs"]:
        src = (root / name).read_text(encoding="utf-8")
        s = strip_hax(src)
        s = re.sub(
            r"use super::arithmetic::\{[^}]+\};\n",
            "use crate::field::{\n    add_coeffs,\n    montgomery_multiply_by_constant,\n    montgomery_multiply_fe_by_fer,\n    subtract_coeffs,\n};\n",
            s,
            count=1,
        )
        s = s.replace("arithmetic::add", "add_coeffs")
        s = s.replace("arithmetic::subtract", "subtract_coeffs")
        s = s.replace(
            "arithmetic::montgomery_multiply_by_constant",
            "montgomery_multiply_by_constant",
        )
        s = s.replace("use super::vector_type::Coefficients;", "use crate::coeff::Coefficients;")
        s = re.sub(r"use crate::simd::traits::specs::\*;\n", "", s)
        s = s.replace(
            "use crate::simd::traits::{\n    COEFFICIENTS_IN_SIMD_UNIT,\n    SIMD_UNITS_IN_RING_ELEMENT,\n};",
            "use crate::coeff::{COEFFICIENTS_IN_SIMD_UNIT, SIMD_UNITS_IN_RING_ELEMENT};",
        )
        s = s.replace("pub(crate) fn ntt(", "pub(crate) fn ntt_forward(")
        s = s.replace(
            "pub(crate) fn invert_ntt_montgomery(",
            "pub(crate) fn invert_ntt_montgomery_inner(",
        )
        (here / "src" / f"generated_{name}").write_text(s, encoding="utf-8")
        print("wrote", name)


if __name__ == "__main__":
    main()
