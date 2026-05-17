# Constrained-device signature suite (FN-DSA vs ML-DSA)

Integrators choosing a **bandwidth-constrained** post-quantum signature for transport or firmware updates can prefer **FN-DSA** over **ML-DSA-65** when signature byte cost dominates latency or flash budget.

## Wire sizes (typical)

| Algorithm        | Approx. signature size (bytes) | Notes                                      |
|-----------------|----------------------------------|--------------------------------------------|
| FN-DSA-512      | 666                              | Level 1 (128-bit classical target)         |
| FN-DSA-1024     | 1280                             | Level 5 (256-bit classical target)         |
| ML-DSA-65       | 3293                             | Level 3 (192-bit classical target)         |

Sizes follow [`lib-q-core`](../lib-q-core/src/security/constants.rs) `get_expected_signature_size` for the registered `Algorithm` variants.

## Suite negotiation guidance

- **Constrained uplink / IoT**: Offer **FN-DSA-512** alongside ML-DSA where policy allows Level-1-equivalent signatures; reduces airtime versus ML-DSA-65 by roughly **5×** on the signature alone.
- **High assurance**: Retain **ML-DSA-65** or **FN-DSA-1024** where Level 3/5 targets are required.
- **Interoperability**: Handshake or credential policies (outside this crate) should list acceptable `Algorithm` identifiers and enforce mutual support before committing to FN-DSA-only paths.

## Standards references

- FN-DSA: NIST FIPS 206.
- ML-DSA: NIST FIPS 204.

This document describes **library-level sizing and selection guidance** only. Product-specific `HandshakeSuitePolicy` or ACVP `sigid` metadata live in consuming systems and validation tooling.
