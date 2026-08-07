#! /usr/bin/env python3

from dilithium import Dilithium2, Dilithium3, Dilithium5
from aes256_ctr_drbg import AES256_CTR_DRBG

import json
import hashlib


# NAMING (changed 2026-08-07, card t_71d4f79a). These files used to be written as
# `nistkats-<k><l>.json` / `nistkats_pre_hashed-<k><l>.json`. They are NOT NIST vectors and never
# were: every value is produced by `dilithium.py` in this directory. A filename asserting otherwise
# is the exact "the name claims conformance the file does not have" pattern that card is about, so
# they are now named for what actually generates them.
#
# NOTE FOR ANYONE RE-RUNNING THIS. The committed vectors did not come from a run of this script.
# They are byte-for-byte identical to github.com/cryspen/libcrux @ 5c3fc214 under
# libcrux-ml-dsa/tests/kats/, and so is dilithium.py -- verified by live download 2026-08-07. This
# script reproduces them; it did not originate them. Re-running it and committing the result would
# turn an upstream-verifiable file into a locally-regenerated one, so update PROVENANCE.md and
# kats-manifest.toml in the same review if you ever do. Both record the caveats on how independent
# these vectors actually are, which is less than the crate README used to imply.
def generate_dilithium_py_kats(algorithm):
    kats_formatted = []
    pre_hashed_kats_formatted = []

    entropy_input = bytes([i for i in range(48)])
    rng = AES256_CTR_DRBG(entropy_input)

    print("Generating dilithium-py KATs for ML-DSA-{}{}.".format(algorithm.k, algorithm.l))

    for i in range(100):
        seed = rng.random_bytes(48)

        algorithm.set_drbg_seed(seed)

        vk, sk = algorithm.keygen()

        msg_len = 33 * (i + 1)
        msg = rng.random_bytes(msg_len)
        sig = algorithm.sign(sk, msg)

        kats_formatted.append(
            {
                "key_generation_seed": bytes(algorithm.keygen_seed).hex(),
                "sha3_256_hash_of_verification_key": bytes(
                    hashlib.sha3_256(vk).digest()
                ).hex(),
                "sha3_256_hash_of_signing_key": bytes(
                    hashlib.sha3_256(sk).digest()
                ).hex(),
                "message": bytes(msg).hex(),
                "signing_randomness": bytes(algorithm.signing_randomness).hex(),
                "sha3_256_hash_of_signature": bytes(
                    hashlib.sha3_256(sig).digest()
                ).hex(),
            }
        )
        with open("dilithium-py-kats-{}{}.json".format(algorithm.k, algorithm.l), "w") as f:
            json.dump(kats_formatted, f, ensure_ascii=False, indent=4)


    for i in range(100):
        seed = rng.random_bytes(48)

        algorithm.set_drbg_seed(seed)

        vk, sk = algorithm.keygen()

        msg_len = 33 * (i + 1)
        msg = rng.random_bytes(msg_len)
        sig_pre_hashed = algorithm.sign_pre_hashed_shake128(sk, msg)

        pre_hashed_kats_formatted.append(
            {
                "key_generation_seed": bytes(algorithm.keygen_seed).hex(),
                "sha3_256_hash_of_verification_key": bytes(
                    hashlib.sha3_256(vk).digest()
                ).hex(),
                "sha3_256_hash_of_signing_key": bytes(
                    hashlib.sha3_256(sk).digest()
                ).hex(),
                "message": bytes(msg).hex(),
                "signing_randomness": bytes(algorithm.signing_randomness).hex(),
                "sha3_256_hash_of_signature": bytes(
                    hashlib.sha3_256(sig_pre_hashed).digest()
                ).hex(),
            }
        )
            
        with open(
            "dilithium-py-kats-pre-hashed-{}{}.json".format(algorithm.k, algorithm.l), "w"
        ) as f:
            json.dump(pre_hashed_kats_formatted, f, ensure_ascii=False, indent=4)

generate_dilithium_py_kats(Dilithium2)
generate_dilithium_py_kats(Dilithium3)
generate_dilithium_py_kats(Dilithium5)
