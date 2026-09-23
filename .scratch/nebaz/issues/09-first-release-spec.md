# 09 — First-release spec

Type: grilling
Status: open
Blocked by: 04, 05, 06, 07
Map: ../map.md

## Question

Assemble the destination artifact: the first-release spec for nebaz, written
into the new repo as `docs/SPEC-v0.1.md`, plus the seed `CLAUDE.md` /
`CONTEXT.md` (conventions carried from neboto, the "ported from neboto"
table from ticket 02, the ADR from ticket 04).

The spec covers: scoping model + auth (tickets 04, 05), the six services'
catalog (06), the read-only mechanism (07), the Tier 1 feature list, and an
ordered build plan sized in agent sessions. Resolving this ticket ends the
map — everything after it is building.

## Comments

**2026-09-23 — input from ticket 07.** The read-only guarantee is three
layers (GET-only constructor + `ReadOnlyPolicy`, `tests/readonly_guard.rs`,
`PERMISSIONS.md` with `Reader` at subscription scope). The spec's
permissions section can point at `PERMISSIONS.md` rather than restate it;
the one user-facing line is "assign Reader, nothing else, no vault access
policy".

**2026-09-23 — input from ticket 08.** The release pipeline is live and
dry-run verified; cutting `v0.1.0` is `cargo set-version 0.1.0`, commit,
tag, push. The spec should say what the first tag contains and whether the
repo hardening checklist in `docs/RELEASING.md` (branch ruleset → PR flow)
is applied before or after it.

