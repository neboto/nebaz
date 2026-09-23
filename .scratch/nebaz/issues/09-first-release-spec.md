# 09 — First-release spec

Type: grilling
Status: resolved
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


## Answer

**Resolved 2026-09-24 (grilled, one round, all recommendations accepted).
This ticket ends the map.**

The destination artifact is `docs/SPEC-v0.1.md` in the repo: what
`v0.1.0` is (six services, CLI auth, prebuilt binaries, the three-layer
read-only guarantee), a table of where each decision lives (ADRs 0001–0003,
`CONTEXT.md`, `SERVICES.md`, `PERMISSIONS.md`, `RELEASING.md`), the Tier 1
feature list as shipped, what is not in it (`docs/BACKLOG.md`), the
acceptance checklist for the tag, and the remaining plan: two sessions
(the live tour on the Azure machine; hardening + tag + crates.io).

Decisions:
1. **Spec shape**: short, pointing, not restating. The catalog (ticket
   06) is promoted into `docs/SERVICES.md` (neboto's name), with the
   cross-cutting rules, the catalog table, the call table and the
   verified-live list; the map's copy is now history.
2. **Tier 1 scope**: exactly what is wired. `@all` and list visual
   selection are dropped from `v0.1.0`; the four dead symbols
   (`parse_all_query`, `DetailSections`, `export_detail_multi`,
   `multi_detail_csv`) and their tests are deleted, the build is
   warning-free and clippy is clean (four style lints in copied files
   fixed or allowed). Watch mode ships as is: one watched Storage view is
   60 list calls per 5 min at the 5 s preset against 100 allowed; no
   floor.
3. **Fog closed**: every remaining fog item is product scope, not
   first-release scope, and moved to `docs/BACKLOG.md` with what is known
   (including two facts found while writing it: NSG effective access is a
   `POST` action in ARM, so it conflicts with the guarantee; blob and Log
   Analytics views need data-plane hosts the guard forbids today). The
   map's "Not yet specified" section is empty.
4. **Bar for the tag**: the live tour (checklist in the spec, incl. the
   catalog's rule-8 check), dead code gone, the docs in. The smoke
   harness was committed (`scripts/smoke.sh`, fake `az`, pty runner,
   three scenarios, passing) but does not gate. Demo GIF after the tag.
5. **Hardening**: seven of the nine checklist items before the tag, the
   branch ruleset after. **Not applied**: the agent session's API calls
   were denied by its permission policy; the commands are in
   `docs/RELEASING.md` and the spec's step 2, for the operator to run.
6. **crates.io**: publish `nebaz` when `v0.1.0` is cut (manual
   `cargo publish`), recorded in the spec and runbook.

Also written: `CLAUDE.md` (neboto's lean shape: where to look, commands,
architecture in a page, adding a service, conventions, key files,
testing). README points at the promoted docs.

Built off-map in the same session (commit "First-release spec…"): the
dead-code removal, the clippy fixes, `scripts/smoke.sh`.
