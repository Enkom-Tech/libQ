# Lattice blind issuance (design)

This document specifies the **cryptographic intent** for BLNS-style blind issuance on top of the Ajtai commitment and Fiat–Shamir opening proofs in this crate.

## Security goals

- **Blindness**: The issuer learns no function of the user’s token descriptor beyond what is implied by a single public commitment.
- **One-more unforgeability**: Without an additional issuer secret key (outside the CRS model used here), users cannot mint arbitrary valid openings at will.

## CRS model

The current `AjtaiCommitmentKey` is **common random string** style: nobody holds a trapdoor for `A`. Classical Chaum blind RSA therefore does not map directly. Production blind issuance under Module-SIS requires a **two-party** or **issuer-keyed** variant from the literature (e.g. Lyubashevsky-style blind signatures, or hash-and-sign on a trapdoor Ajtai family).

## Implemented helpers (`src/blind.rs`)

- **Homomorphic combination** of openings: `com(o₁)+com(o₂)=com(o₁+o₂)` in the coefficient domain.
- **Blinded commitment** construction used to randomise the user’s commitment before an issuer-side operation.
- **Fiat–Shamir context binding** for transcripts that include a user-chosen domain separator and optional public metadata (epoch, realm id).

`BlindIssuerKeypair`, `BlindIssuance::issuer_sign_message`, `finalize_message`, and the
[`BlindSignature`](src/blind.rs) trait on [`UnblindedBlindSignature`](src/blind.rs) form a
**pilot blind-signature-shaped** API: the issuer attestation still reduces to an Ajtai
opening proof under the shared CRS (issuer “secret” is a sampled opening, not a
trapdoor), but the Fiat–Shamir transcript now binds the issuer public image and an
application [`blind_message_digest`](src/blind.rs).

Integrators MUST still treat parameter choices and soundness margins as **research-grade**
until a trapdoor- or issuer-keyed Module-SIS family is frozen for production.
