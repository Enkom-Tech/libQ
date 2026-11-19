#!/usr/bin/env python3
"""Independent recomputation of lib-q-hpke's RFC 9180 Section 4/5.1 key-schedule
stage outputs (freeze independent HPKE KATs).

This script is a SEPARATE implementation from lib-q-hpke's Rust code: it uses
CPython's `hashlib` (SHA3-256/512 backed by the interpreter's built-in Keccak
code, distinct from libQ's own `lib-q-sha3`/`lib-q-keccak` crates) to
independently compute LabeledExtract, LabeledExpand, and KeySchedule for a
fixed set of inputs. The frozen JSON output (vectors.json) is checked into the
repo and loaded by ../../independent_key_schedule_kat_tests.rs, which asserts
lib_q_hpke::hpke_core's own key_schedule()/labeled_extract()/labeled_expand()
byte-for-byte reproduce these independently-computed values.

IMPORTANT — this is NOT a re-implementation of RFC 5869 HKDF (HMAC-based
extract/expand). lib-q-hpke's HkdfSha3_256/HkdfSha3_512 KDFs are a
non-standard, hash-only construction (see lib-q-hpke/src/kdf/hkdf.rs
`HkdfImpl::extract`/`expand`): Extract(salt, ikm) = Hash(salt || ikm), and
Expand(prk, info, L) = Hash(prk || info || L_as_8_byte_LE) with additional
Hash(prev || round_as_4_byte_LE) rounds if L exceeds one hash output. RFC
9180's own Appendix A test vectors are for HMAC-based HKDF-SHA256/384/512
paired with classical (X25519/P-256/P-521) DHKEM, which lib-q-hpke does not
implement at all (PQ-only KEMs) -- so those vectors cannot apply here, and
mirroring RFC 5869 HKDF here would independently verify the WRONG construction.
Instead, this script independently reimplements lib-q-hpke's actual
(non-standard) Extract/Expand construction using an independent SHA3/SHAKE
library, so it catches:
  - a changed LabeledExtract/LabeledExpand label string or concat order,
  - a changed key_schedule_context layout (mode || psk_id_hash || info_hash),
  - a changed suite_id layout,
  - a changed/broken SHA3-256/512 or SHAKE128/256 computation,
  - a changed length-prefix (the 8-byte-LE `output_len` used inside Expand,
    which is itself a NON-PORTABLE encoding: it is `usize::to_le_bytes()` in
    Rust, i.e. 8 bytes on the 64-bit hosts these vectors were generated on,
    but 4 bytes on any 32-bit target such as wasm32. See the write-up in the
    PR description for why this is flagged as a separate, wire-relevant gap
    and is NOT fixed here.)
without being a mechanical restatement of the Rust source it is checking.

Regenerate with: python3 generate_vectors.py > vectors.json
"""
import hashlib
import json


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def shake128(data: bytes, length: int) -> bytes:
    return hashlib.shake_128(data).digest(length)


def shake256(data: bytes, length: int) -> bytes:
    return hashlib.shake_256(data).digest(length)


# KDF table: name -> (algorithm_id, extract_len / Nh, extract_fn, expand-hash-fn-or-None, xof-fn-or-None)
KDFS = {
    "HkdfShake128": dict(alg_id=0x0004, nh=16, xof=shake128),
    "HkdfShake256": dict(alg_id=0x0005, nh=32, xof=shake256),
    "HkdfSha3_256": dict(alg_id=0x0006, nh=32, hashfn=sha3_256),
    "HkdfSha3_512": dict(alg_id=0x0007, nh=64, hashfn=sha3_512),
}

AEADS = {
    "Saturnin256": dict(alg_id=0x0004, key_len=32, nonce_len=16),
    "Shake256": dict(alg_id=0x0005, key_len=32, nonce_len=16),
    "DuplexSpongeAead": dict(alg_id=0x0006, key_len=32, nonce_len=16),
}

KEMS = {
    "MlKem512": 0x0022,
    "MlKem768": 0x0023,
    "MlKem1024": 0x0024,
}

MODES = {"Base": 0x00, "Psk": 0x01}


def extract(kdf_name: str, salt: bytes, ikm: bytes) -> bytes:
    kdf = KDFS[kdf_name]
    if "xof" in kdf:
        return kdf["xof"](salt + ikm, kdf["nh"])
    h = kdf["hashfn"](salt + ikm)
    return h[: kdf["nh"]]


def expand(kdf_name: str, prk: bytes, info: bytes, length: int) -> bytes:
    kdf = KDFS[kdf_name]
    length_le = length.to_bytes(8, "little")
    if "xof" in kdf:
        return kdf["xof"](prk + info + length_le, length)

    hashfn = kdf["hashfn"]
    h = hashfn(prk + info + length_le)
    out = h[: min(length, len(h))]
    if length > len(h):
        round_no = 1
        offset = len(h)
        while offset < length:
            rh = hashfn(h + round_no.to_bytes(4, "little"))
            chunk = rh[: min(length - offset, len(rh))]
            out += chunk
            offset += len(chunk)
            round_no += 1
    return out[:length]


def suite_id(kem_name: str, kdf_name: str, aead_name: str) -> bytes:
    return (
        b"HPKE"
        + KEMS[kem_name].to_bytes(2, "big")
        + KDFS[kdf_name]["alg_id"].to_bytes(2, "big")
        + AEADS[aead_name]["alg_id"].to_bytes(2, "big")
    )


def labeled_extract(kdf_name: str, salt: bytes, sid: bytes, label: str, ikm: bytes) -> bytes:
    labeled_ikm = b"HPKE-v1" + sid + label.encode("ascii") + ikm
    return extract(kdf_name, salt, labeled_ikm)


def labeled_expand(kdf_name: str, prk: bytes, sid: bytes, label: str, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + sid + label.encode("ascii") + info
    return expand(kdf_name, prk, labeled_info, length)


def key_schedule(mode_name: str, kem_name: str, kdf_name: str, aead_name: str,
                  shared_secret: bytes, info: bytes, psk: bytes, psk_id: bytes) -> dict:
    sid = suite_id(kem_name, kdf_name, aead_name)
    mode = MODES[mode_name]
    nh = KDFS[kdf_name]["nh"]

    psk_id_hash = labeled_extract(kdf_name, b"", sid, "psk_id_hash", psk_id)
    info_hash = labeled_extract(kdf_name, b"", sid, "info_hash", info)
    assert len(psk_id_hash) == nh
    assert len(info_hash) == nh

    context = bytes([mode]) + psk_id_hash + info_hash

    secret = labeled_extract(kdf_name, shared_secret, sid, "secret", psk)

    aead = AEADS[aead_name]
    key = labeled_expand(kdf_name, secret, sid, "key", context, aead["key_len"])
    nonce = labeled_expand(kdf_name, secret, sid, "base_nonce", context, aead["nonce_len"])
    exp = labeled_expand(kdf_name, secret, sid, "exp", context, nh)

    return {
        "suite_id": sid.hex(),
        "psk_id_hash": psk_id_hash.hex(),
        "info_hash": info_hash.hex(),
        "key_schedule_context": context.hex(),
        "secret": secret.hex(),
        "key": key.hex(),
        "base_nonce": nonce.hex(),
        "exporter_secret": exp.hex(),
    }


def main():
    cases = []

    # Base mode, one case per KDF variant, fixed KEM/AEAD so only the KDF differs.
    shared_secret = bytes(range(32))  # 0x00 0x01 .. 0x1f -- deterministic, independent of any RNG
    info = b"independent HPKE key-schedule KAT fixture / base mode / info"
    for kdf_name in ("HkdfShake128", "HkdfShake256", "HkdfSha3_256", "HkdfSha3_512"):
        case = dict(
            name=f"base_mlkem512_{kdf_name.lower()}_saturnin256",
            mode="Base",
            kem="MlKem512",
            kdf=kdf_name,
            aead="Saturnin256",
            shared_secret=shared_secret.hex(),
            info=info.hex(),
            psk="",
            psk_id="",
        )
        case["expected"] = key_schedule("Base", "MlKem512", kdf_name, "Saturnin256",
                                         shared_secret, info, b"", b"")
        cases.append(case)

    # PSK mode: non-empty psk/psk_id exercise the branches the Base-mode cases above leave at
    # their b"" defaults, on a different KEM/AEAD pairing so this is not just a mode-flag toggle.
    psk = b"hpke-kat-psk-material-0123456789"
    psk_id = b"hpke-kat-psk-id"
    shared_secret_2 = bytes(range(200, 232))
    info_2 = b"independent HPKE key-schedule KAT fixture / psk mode / info"
    for kdf_name in ("HkdfSha3_256", "HkdfShake256"):
        case = dict(
            name=f"psk_mlkem768_{kdf_name.lower()}_shake256aead",
            mode="Psk",
            kem="MlKem768",
            kdf=kdf_name,
            aead="Shake256",
            shared_secret=shared_secret_2.hex(),
            info=info_2.hex(),
            psk=psk.hex(),
            psk_id=psk_id.hex(),
        )
        case["expected"] = key_schedule("Psk", "MlKem768", kdf_name, "Shake256",
                                         shared_secret_2, info_2, psk, psk_id)
        cases.append(case)

    # Largest KEM (MlKem1024) x largest KDF (HkdfSha3_512, Nh=64 forces the Expand round-chaining
    # loop for base_nonce/exp since 64 > one SHA3-512 block only if key_len/nonce_len/nh exceed 64;
    # here nh=64 exactly equals one hash output, so this also pins the exact-boundary (no extra
    # round) case) x DuplexSpongeAead.
    shared_secret_3 = bytes(range(50, 82))
    info_3 = b""  # empty info is legal and exercises LabeledExtract/Expand with a zero-length field
    case = dict(
        name="base_mlkem1024_hkdfsha3_512_duplexspongeaead_empty_info",
        mode="Base",
        kem="MlKem1024",
        kdf="HkdfSha3_512",
        aead="DuplexSpongeAead",
        shared_secret=shared_secret_3.hex(),
        info=info_3.hex(),
        psk="",
        psk_id="",
    )
    case["expected"] = key_schedule("Base", "MlKem1024", "HkdfSha3_512", "DuplexSpongeAead",
                                     shared_secret_3, info_3, b"", b"")
    cases.append(case)

    print(json.dumps({
        "provenance": (
            "Independently computed by generate_vectors.py (CPython hashlib SHA3-256/512 and "
            "SHAKE128/256), NOT derived from or checked against lib-q-hpke's own output at "
            "generation time. See PROVENANCE.md."
        ),
        "cases": cases,
    }, indent=2))


if __name__ == "__main__":
    main()
