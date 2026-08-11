#!/usr/bin/env bash
# Guard: no tracked file may assert a standardization status ("NIST-approved", "FIPS
# 206-compliant", etc.) that the algorithm it describes does not actually have.
#
# GROUND TRUTH (NIST CSRC, checked 2026-08):
#   * ML-KEM  -- FIPS 203, finalized/published 2024-08-14.
#   * ML-DSA  -- FIPS 204, finalized/published 2024-08-14.
#   * SLH-DSA -- FIPS 205, finalized/published 2024-08-14.
#   * FN-DSA (Falcon) -- selected by NIST, but FIPS 206 has NOT been published: not as a final
#     standard and not even as an initial public draft. https://csrc.nist.gov/pubs/fips/206/ipd
#     returned HTTP 404 when this was checked (2026-08); NIST's own FIPS 206 status update
#     (csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon) describes the IPD as written and
#     awaiting approval, i.e. still forthcoming. There is no published text -- draft or final --
#     to be "approved" or "compliant" against.
#   * HQC -- selected for standardization 2025-03-11 (NIST IR 8545); no FIPS draft has been
#     published yet. Selected, not approved.
#   * Classic McEliece -- a round-4 submission NIST evaluated and did NOT select for
#     standardization. There is no NIST/FIPS encoding for it at all.
#   * Saturnin, Rocca-S, Romulus -- none of these AEADs is a NIST algorithm. Saturnin was a NIST
#     Lightweight Cryptography round-2 candidate that did not advance to the finals; Romulus DID
#     reach the ten LWC finalists (csrc.nist.gov/projects/lightweight-cryptography/finalists) but
#     was not selected -- Ascon won that competition (SP 800-232). Rocca-S is an IETF draft
#     (draft-nakano-rocca-s), never a NIST candidate.
#
# WHY THIS EXISTS
# ---------------
# Several crate READMEs were corrected to state their true standardization status honestly:
#
#   * lib-q-fn-dsa/README.md: "FIPS 206 is not yet published. There is no finalized standard --
#     and no public draft -- to be 'compliant' with."
#   * lib-q-cb-kem/README.md: Classic McEliece is described against "NIST round 4" -- it was a
#     round-4 submission, never selected for standardization, and there is no NIST/FIPS encoding
#     for it.
#   * lib-q-hqc/README.md: HQC lists "full NIST KEM KAT conformance" as a remaining blocker, i.e.
#     not yet conformant.
#   * lib-q-aead/README.md: "None of these AEAD modes is NIST-approved."
#
# Those caveats were landed at the crate-README level, but the identical overclaim kept living
# one level up -- in workspace-wide docs (README.md, CONTRIBUTING.md, DEVELOPMENT.md,
# docs/security.md, PR/CD templates), in crate *source* doc-comments (lib-q-fn-dsa/src/lib.rs,
# lib-q-cb-kem/src/lib.rs, lib-q-hqc/src/lib.rs, lib-q/src/lib.rs), and in CI workflow YAML
# (security.yml, cd.yml, the test-fn-dsa action) -- files a reader (or a release changelog) is
# just as likely to land on. A caveat that lives in only one of several contradicting files is
# not a fix, it is a new inconsistency. An earlier version of this guard only grepped `*.md`,
# which is exactly why the `.rs` and `.yml` copies of the overclaim survived a "the docs are
# fixed" review undetected.
#
# This guard fails on any phrase/pattern from that overclaim class appearing in ANY tracked
# file (not just Markdown) in the repository. It is deliberately a denylist of phrases and
# short word-proximity patterns, not a semantic checker: it will not catch every conceivable
# rewording of the same overclaim. Extend PATTERN below if a new one shows up.
#
# Usage: bash scripts/ci-guard-standards-claims.sh [REPO_ROOT]

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

# `grep -P` (PCRE, needed for the lazy `{0,60}?` proximity match below) refuses to run under a
# non-UTF-8 "C" locale ("grep: -P supports only unibyte and UTF-8 locales"). Force a UTF-8
# locale so this guard behaves the same on a from-scratch CI runner as it does interactively.
export LC_ALL=C.UTF-8

# Each alternative is its own overclaim shape found (or plausible near-miss of one found) in
# this repo's history:
#   - the specific phrases from the original incident (kept verbatim, both spellings of
#     "standardi[sz]ed");
#   - `NIST-approved` (or `NIST-Approved`) followed within ~60 chars, on the same line, by
#     "algorithm(s)/KEM(s)/signature(s)/scheme/variant(s)" -- e.g. "NIST-approved post-quantum
#     algorithms", "NIST-approved HQC algorithms", "a NIST-approved ... signature scheme",
#     "NIST-approved variants". The trailing noun list is what keeps this off the many lines
#     elsewhere in the workspace that call SHAKE256/SHA3-256/Keccak "NIST-approved" -- those say
#     "hash function" / "primitives" / "proof systems" / "challenger". For SHAKE/SHA-3 that is a
#     true statement (FIPS 202 is finalized); this pattern makes no claim either way about the
#     other nouns (e.g. "NIST-approved post-quantum proof systems" in lib-q-zkp is itself an
#     overclaim -- no proof system is NIST-approved -- it is simply out of this pattern's reach).
#     KNOWN FALSE NEGATIVE, accepted deliberately: the proximity match is line-scoped, so a
#     doc-comment that wraps between "NIST-approved" and its noun slips through. lib-q/src/lib.rs
#     used to read "...built exclusively with NIST-approved" / "post-quantum algorithms." across
#     two lines and this pattern did not flag it. A bare `NIST-[Aa]pproved\s*$` alternative was
#     tried and reverted: it fires on lib-q-poseidon/src/constants.rs:12 ("SHAKE256 is
#     NIST-approved") and lib-q-stark-challenger/src/lib.rs:53, which are TRUE claims that wrap.
#     Flagging true statements would pressure authors to delete accurate text, which is worse
#     than the miss. Closing this properly needs a multi-line matcher, not another alternative.
#   - "NIST-Approved: Implements ..." (the fn-dsa doc-comment shape);
#   - "NIST-approved Classic(al) McEliece" / "NIST-approved code-based McEliece" (McEliece was
#     never NIST-approved -- it wasn't even selected);
#   - "follows the FIPS <nnn> standard" / "FIPS <nnn>-compliant" / "FIPS <nnn> compliant" for a
#     standard that is not yet published (guards FN-DSA/FIPS 206 specifically, but is written
#     generically so it also catches a future HQC "FIPS 207-compliant" claim before that FIPS
#     exists).
PATTERN='(NIST PQC Standard \(FIPS 206\)|NIST-standardi[sz]ed post-quantum|NIST-standardi[sz]ed modules|NIST-standardi[sz]ed code-based KEM|five NIST parameter sets|NIST-track / standardized PQC|NIST FIPS 206|NIST-[Aa]pproved[^.\n]{0,60}?\b(algorithms?|KEMs?|signatures?|scheme|variants?)\b|NIST-[Aa]pproved:?\s*Implements|NIST-approved (Classic(al)?|code-based) ?McEliece|follows the FIPS [0-9]+ standard|FIPS [0-9]+[- ]compliant)'

# No file-extension filter: this must cover Markdown, Rust doc-comments, and workflow YAML alike
# (see "WHY THIS EXISTS" above) -- the exact three file classes an earlier, `*.md`-only version of
# this guard missed. `git grep` already skips anything Git considers binary.
#
# The ONE exclusion is this script itself. Its comments necessarily quote the banned phrases
# verbatim in order to document them, and `PATTERN` above literally contains `NIST FIPS 206` as an
# alternative -- so the moment this file is tracked, an unfiltered `git grep` matches six of its
# own lines and the guard fails forever on its own source, no matter how the prose is reworded.
# Verified: `git grep -InP --untracked "$PATTERN" -- scripts/` reports those six self-hits.
HITS="$(git grep -InP "$PATTERN" -- ':(exclude)scripts/ci-guard-standards-claims.sh' || true)"

if [[ -n "$HITS" ]]; then
  echo "ci-guard-standards-claims: found overclaim phrases that contradict the actual NIST PQC standardization status:" >&2
  echo "$HITS" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Second check: BARE FIPS 206 ATTRIBUTION.
#
# The phrase list above enumerates known bad shapes, so it only catches wordings someone already
# thought of. That is the wrong shape of defence for FIPS 206 specifically, which is by far this
# repo's most-repeated false claim and appears in registry metadata that ships to users.
#
# The invariant is simpler than any phrase list: FIPS 206 does not exist as a published document,
# so no line may attribute anything to it WITHOUT saying so. Rather than enumerate every bad
# phrasing, flag every mention that lacks a qualifier. New prose has to opt in to the caveat.
#
# This is what caught `scripts/publish-npm-ordered.sh` still carrying
# "FN-DSA (FIPS 206) post-quantum digital signatures for Node.js" after the same string had already
# been fixed in `.github/workflows/cd.yml` and `npm-publish-only.yml` -- three copies of one npm
# description, of which a phrase-list guard flagged none, because "(FIPS 206)" was not on the list.
#
# Two files are excluded, both because they establish the caveat once at the top and then use
# "FIPS 206" as shorthand throughout, which is legitimate and would otherwise need the disclaimer
# repeated on ~15 lines:
#   - lib-q-fn-dsa/README.md      -- states the convention explicitly at lines 5-10.
#   - docs/fn-dsa-nist-gate.md    -- its opening paragraph is the caveat.
FIPS206_QUALIFIED='not yet published|not been published|no public draft|no finalized standard|NIST-selected|NIST selected|selected for|intends to publish|will become|if and when|unpublished|pre-standard|not yet|future FIPS 206|published FIPS 206 text|once NIST publishes'
FIPS206_HITS="$(
  git grep -InP 'FIPS[- ]206' -- \
    ':(exclude)scripts/ci-guard-standards-claims.sh' \
    ':(exclude)lib-q-fn-dsa/README.md' \
    ':(exclude)docs/fn-dsa-nist-gate.md' \
  | grep -vP "$FIPS206_QUALIFIED" || true
)"

if [[ -n "$FIPS206_HITS" ]]; then
  echo "ci-guard-standards-claims: FIPS 206 attributed without a qualifier." >&2
  echo "FIPS 206 has not been published -- not as a final standard and not as a public draft." >&2
  echo "Say so on the line, e.g. 'FN-DSA (NIST-selected; FIPS 206 not yet published)':" >&2
  echo "$FIPS206_HITS" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Third check: IND-qCCA CONTAINMENT (board card `t_1af26ff2`, obligation Q-2).
#
# The Saturnin submission claims IND-qCCA for CTR-Cascade and argues it (spec §4.3.1) via the
# Soukharev-Jao-Seshadri composition theorem, which IACR ePrint 2025/387 DISPROVES. The repair
# looks real -- 2025/387's own Theorem 3 needs the MAC to be a qPRF, which the spec does argue
# separately -- but nobody has ratified that citation swap. So today the honest statement is that
# CTR-Cascade's IND-qCCA claim is UNPROVEN, and it lands on `SaturninAead`, whose wire is frozen
# and which every product reaches.
#
# `lib-q-saturnin`'s own docs already say all of this at length, and they end with an instruction:
# "Do not restate the spec's IND-qCCA claim for CTR-Cascade without this footnote"
# (README.md, and again in src/aead.rs / src/aead_ctx.rs). That instruction is prose, and prose
# does not fail CI.
#
# This makes it enforceable, and deliberately NOT as a per-line qualifier check. Several of the
# existing lines are direct QUOTATIONS of the spec's own wording ("...offers IND-qCCA security,
# assuming..."), which read correctly inside the surrounding caveat and would have to be mangled
# to satisfy a line-scoped rule. Flagging true, in-context text pressures authors to delete
# accurate prose -- the same trap already documented for the bare `NIST-approved` alternative
# above.
#
# The containment rule instead: the qCCA discussion lives in `lib-q-saturnin`'s own documentation,
# where the caveat is established. A mention ANYWHERE ELSE in the repo is, by construction, a
# restatement separated from its footnote. That is exactly the failure mode the FIPS 206 check was
# written for after one npm description was copied into three files.
#
# It is also not satisfiable by wordsmithing: adding the term to a new file is a deliberate act,
# and the fix is either to keep it in lib-q-saturnin or to extend this allow-list on purpose.
# The allow-list. `lib-q-saturnin/` is where the caveat is established.
#
# `docs/crypto-signoff-register.md` was added deliberately, and the way it got added is the
# evidence that this check does what it claims: the register is the repo-wide index a cryptographer
# triages from, Q-2 is Gate E in it, and when that gate was written this guard failed the commit and
# named the file. It forced an explicit decision instead of letting the term spread quietly — which
# is the whole design. The register carries the full caveat (blocking claim, the 2025/387 disproof,
# the unratified repair), so it qualifies on the same grounds lib-q-saturnin does.
#
# Add to this list only for a file that likewise states the caveat in full. "It mentions it in
# passing" is the case this guard exists to reject.
QCCA_ALLOWED_PREFIX='(lib-q-saturnin/|docs/crypto-signoff-register\.md)'
QCCA_HITS="$(
  git grep -InP 'IND-qCCA' -- \
    ':(exclude)scripts/ci-guard-standards-claims.sh' \
  | grep -vP "^${QCCA_ALLOWED_PREFIX}" || true
)"

if [[ -n "$QCCA_HITS" ]]; then
  echo "ci-guard-standards-claims: IND-qCCA mentioned outside lib-q-saturnin/." >&2
  echo "CTR-Cascade's IND-qCCA claim is UNPROVEN: the Saturnin spec argues it via the" >&2
  echo "Soukharev-Jao-Seshadri composition theorem, which IACR ePrint 2025/387 disproves. The" >&2
  echo "repair (2025/387 Thm 3 + Thm 4 + Cor 1, needing the MAC to be a qPRF) is unratified --" >&2
  echo "open obligation Q-2, board card t_1af26ff2." >&2
  echo "The full caveat lives in lib-q-saturnin/README.md and src/aead.rs; a mention outside that" >&2
  echo "crate is a restatement separated from its footnote. Keep it there, or extend the" >&2
  echo "allow-list in this script deliberately:" >&2
  echo "$QCCA_HITS" >&2
  exit 1
fi

echo "ci-guard-standards-claims: OK (no overclaim phrases found)"
