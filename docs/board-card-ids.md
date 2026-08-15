# Board card ids: `t_`-prefixed ids are legacy and most of them are dead

Written 2026-08-15. Read this before chasing a `t_xxxxxxxx` reference out of a doc or a source
comment and concluding the tooling is broken.

## The short version

Issue tracking moved from the Akira Hermes kanban to a shared **Hive** board. Cards are now
identified as **`ENK-<n>`** (e.g. `ENK-216`), not `t_<8 hex>`. The two are unrelated id spaces.

`hive-board show t_7123c738` does **not** return "not found" — it returns **HTTP 500**. That failure
looks like an outage and is not one. Use the `ENK-` id.

## Why most of them cannot be fixed

The migration imported **open work only**. OBSERVED 2026-08-15:

```
hive-board list -Json          -> 564 cards: 384 todo, 130 blocked, 44 backlog, 6 cancelled
hive-board list -Status done   -> "No issues."
```

There are no completed cards on the Hive board at all. Anything that was `done` on the old board
was not carried over, and its content is not retrievable through `hive-board`. The old
`kanban.db` is not in this repo either.

This repo cites **64 distinct legacy ids across 345 references in 158 files**. Six resolve. The
other **58 refer to cards that no longer exist anywhere reachable** — they are almost all work that
had already been completed when the migration ran, which is exactly why they were being cited in
the past tense.

**Treat an unresolvable `t_` id as a provenance marker, not a link.** It records that a decision was
tracked and by whom, at a point in time. The surrounding prose is the durable record; that was
always the repo's convention ("keep the durable conclusion on the issue *and* in the tree"), and it
is why losing the cards costs less than it might.

## The six that do resolve

Mapped by the `Akira-Id:` trailer that the import script wrote into each migrated card's
description; 536 of the 564 cards carry one, and that trailer is the only surviving link between
the two id spaces.

| legacy | Hive | status (2026-08-15) | subject |
|---|---|---|---|
| `t_05e76e6c` | **ENK-266** | todo | anon-cred wire through LNP22/ABDLOP |
| `t_12eb0701` | **ENK-255** | blocked | gip-crypto RED: HQC-192/256 secret keys cannot round-trip |
| `t_1af26ff2` | **ENK-223** | blocked | libq Q-2: CTR-Cascade's quantum-CCA argument (statement and caveat: `lib-q-saturnin/SECURITY.md`) |
| `t_7123c738` | **ENK-216** | blocked | contact the Saturnin/QCB designers before silicon |
| `t_79295151` | **ENK-52** | todo | tkem-lattice: close RED boundaries |
| `t_a8f6abd8` | **ENK-244** | todo | blind-pcs unversioned commitment wire break |

These six have been rewritten to their `ENK-` ids in live docs and source comments. They were
**not** rewritten inside `CHANGELOG.md` files: changelog entries are append-only records of what was
written at the time, and retro-editing them would be the same mistake the board's own
correction rule forbids.

## To reverse-map an id yourself

There is no lookup command. The trailer is in the card body, so search bodies:

```powershell
hive-board list -Json | ConvertFrom-Json |
  Where-Object { $_.description -match 'Akira-Id:\s*t_1234abcd' } |
  Select-Object identifier, title, status
```

If that returns nothing, the card was not migrated and there is nothing to find.

## The 58 known-dead ids

Listed so nobody spends time confirming it twice. Every one of these appears somewhere in the tree
and none resolves:

```
t_00ab900a t_02643c8d t_043571b4 t_09d6f186 t_0aa1a2c8 t_103554a6
t_121ec837 t_1531578e t_1558e72f t_1594295d t_16ddf21c t_1d516263
t_26d3b638 t_2a1456b0 t_2a349708 t_2d79cd69 t_3986efb2 t_3cf78cba
t_3d6e8d50 t_42086971 t_4333e4ea t_437f3820 t_4d0a0662 t_4d2dc427
t_51797de7 t_580dc5fd t_59609fc3 t_5bc0f630 t_5d1460b7 t_62273504
t_6ea7cb21 t_71d4f79a t_7f110663 t_883438eb t_8ca3fd06 t_8f408920
t_93dc6b27 t_9ad8ef08 t_9cd430c2 t_9d1766f3 t_9f13e8e5 t_a73aaed2
t_ae63f1ec t_b0acaea1 t_bab219ba t_c6851177 t_c801e460 t_c972f73f
t_d2ee7042 t_d707d46b t_e3457ac8 t_e3ac1c87 t_eacf23b1 t_f0d676d1
t_f3ea6b2a t_f88bc433 t_faa048e0 t_fe2722bf
```

Two worth knowing by name, because they are cited as live obligations rather than as history:
`t_5d1460b7` (the QCB related-key constrained-optimum computation, cited from
`docs/crypto-signoff-register.md` and `lib-q-saturnin/SECURITY.md`) and `t_a73aaed2` (the vacuous-R3
refutation behind Gate C2). Both cards are gone; both are described in full in the prose that cites
them, and `t_5d1460b7` is additionally quoted inside the body of **ENK-218**.

## Going forward

Cite cards as `ENK-<n>`. Do not invent a `t_` id.
