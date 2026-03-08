# Resolving Workspace Example Naming Collision

## Problem

`cargo test --workspace` fails with **LNK1104** (cannot open file) because two packages produce binaries with the same names:

- **Root package `lib-q`**: package root is the repo root, so Cargo auto-discovers examples from `./examples/*.rs` and builds e.g. `keccak_no_std_test`, `cb_kem_example`, etc.
- **Package `lib-q-examples`**: has `path = "examples"` and explicitly declares the same `[[example]]` names for the same files.

Both write to `target/debug/examples/<name>.exe`. On Windows, the second write fails (file in use or path collision).

## Root cause

The same `examples/` directory is effectively owned by two packages: the root package (by Cargo’s discovery rules) and the `lib-q-examples` member. Example names are not namespaced per-package; only the binary name is used for the output path.

---

## Option A: Virtual manifest (recommended, one-time refactor)

**Idea:** The workspace root has no package. Only member crates (each with its own directory) have packages. Then no package has the repo root as its root, so no package auto-discovers `./examples/`; only `lib-q-examples` (with `path = "examples"`) builds the examples.

**Steps:**

1. **Create a crate for the umbrella library**  
   e.g. `crates/lib-q/` (or `package/lib-q/`).

2. **Move root package content into that crate:**
   - Move root `Cargo.toml`’s `[package]`, `[lib]`, `[dependencies]`, `[features]`, `[profile.*]`, and any package-specific config into `crates/lib-q/Cargo.toml`.
   - Move root `lib.rs`, `build.rs`, and any root-only source into `crates/lib-q/`.
   - Keep path dependencies as relative to the **workspace root** (e.g. `lib-q-core = { path = "../lib-q-core" }` from `crates/lib-q/`).

3. **Turn the root into a virtual manifest**  
   Root `Cargo.toml` should contain only:
   - `[workspace]` with `members = [..., "crates/lib-q", "examples", ...]` (and no `"."`).
   - `[workspace.package]` and `[workspace.dependencies]` as now.
   - Shared `[profile.*]` if you want them at the root (optional; can stay in `crates/lib-q`).
   - No `[package]`, no `[lib]`, no `[dependencies]`.

4. **Adjust workspace members**  
   Replace `"."` with `"crates/lib-q"` (or whatever path you chose).

5. **Update CI and docs**  
   Any script that builds or tests the “root” package should use `-p lib-q` (or the new package name) from the repo root.

**Result:**  
- Only `lib-q-examples` builds the examples in `examples/`.  
- No more double-built examples and no more LNK1104 from name clashes.  
- `cargo test --workspace` and `cargo build --workspace` work without collision.

This is the usual “senior” layout: workspace root = virtual manifest; all real packages live under subdirectories.

---

## Option B: Single package owns examples (minimal change)

**Idea:** Only one package should declare/build the examples. So either the root package builds them, or `lib-q-examples` does—not both.

**Variant B1 – Only root builds examples (drop `lib-q-examples` as a package):**

- Remove `examples` from `[workspace]` members (or delete `examples/Cargo.toml` and treat `examples/` as a plain directory).
- Root package keeps auto-discovering `./examples/*.rs`.
- Downside: the dedicated “examples” crate and its dependency set go away; examples are just the root package’s examples.

**Variant B2 – Only `lib-q-examples` builds examples (stop root from seeing `examples/`):**

- Make the root a virtual manifest and move the current root package into a subdirectory (same as Option A).  
- So B2 is effectively the same as Option A.

So if you want “only one owner” and no big refactor, you can do B1. If you want to keep a dedicated examples package and fix the collision properly, Option A (or B2) is the way.

---

## Option C: Namespace example names (workaround, no structural change)

**Idea:** Change example **names** in one of the two packages so that the produced binary names differ. Then both packages can keep building, but artifacts no longer collide.

**Steps:**

1. In `examples/Cargo.toml` (lib-q-examples), rename each `[[example]]` so the binary name is unique, e.g.:
   - `hash_example` → `libq_hash_example`
   - `keccak_no_std_test` → `libq_keccak_no_std_test`
   - `cb_kem_example` → `libq_cb_kem_example`
   - (and similarly for the other cb_kem_* examples).

2. Keep the same `path = "..."` and same `.rs` filenames; only the `name = "..."` (and thus the output binary name) changes.

**Result:**  
- Root package still builds `hash_example`, `keccak_no_std_test`, etc.  
- lib-q-examples builds `libq_hash_example`, `libq_keccak_no_std_test`, etc.  
- No path collision; `cargo test --workspace` can succeed.

**Downside:**  
- The same example sources are still built twice (once by root, once by lib-q-examples).  
- You have two sets of binaries for the same examples.  
- Slightly more confusing for contributors (“which one do I run?”).

Use this when you want a quick fix without moving the root package or changing the workspace layout.

---

## Recommendation

- **Long term / “senior” layout:** Use **Option A** (virtual manifest + umbrella crate in e.g. `crates/lib-q`). One place owns examples, no duplicate builds, and the layout matches common Rust workspace practice.
- **Short term / minimal change:** Use **Option C** (rename in `examples/Cargo.toml`) to unblock `cargo test --workspace` and CI; plan Option A when you’re ready to refactor.

Option B1 is only if you explicitly want to drop the separate examples package and keep everything in the root package.
