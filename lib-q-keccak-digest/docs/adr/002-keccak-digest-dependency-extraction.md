# ADR 002: Slimmer `lib-q-keccak-digest` dependency graph (follow-up)

## Status

**Proposed** — not required for the initial [Option B split](https://github.com/Enkom-Tech/libQ/blob/main/lib-q-sha3/docs/adr/001-keccak-nonfips-surface.md). Revisit when a semver-major or workspace maintenance window allows shared-core extraction.

## Context

`lib-q-keccak-digest` v1 depends on `lib-q-sha3` to reuse `block_api::SpongeHasherCore` and `KECCAK_DIGEST_PAD` without duplicating the sponge implementation. Some deployments want **only** pre-FIPS Keccak digests and a **minimal** `cargo tree` (no full FIPS façade crate).

## Options

1. **Status quo** — Keep v1 dependency; document tradeoff in README (current).
2. **Extract** `SpongeHasherCore` / `SpongeReaderCore` and related `block_api` into a new workspace crate (e.g. `lib-q-sponge-core` or `lib-q-keccak-sponge`) depended on by both `lib-q-sha3` and `lib-q-keccak-digest`.
3. **Move** the entire `block_api` module to a lower-level crate; `lib-q-sha3` becomes a thin façade (largest API churn).

## Decision

None — record options for future work. **No** commitment until dependency graphs and release/version policy are agreed.

## Consequences (if 2 or 3 is chosen later)

- `lib-q-sha3` and `lib-q-keccak-digest` `Cargo.toml` / public paths may change; publish a migration guide and semver bump.

## References

- [ADR 001: Keccak / FIPS-202 surface](../../../lib-q-sha3/docs/adr/001-keccak-nonfips-surface.md)
