# Map: nebaz — the Azure sibling of neboto

Label: wayfinder:map
Tracker: local markdown (`~/work/nebaz/.scratch/nebaz/`, see plugin doc `issue-tracker-local.md`)
Home: https://github.com/neboto/nebaz (local clone `~/work/nebaz`). Run wayfinder sessions from the clone, not from neboto-tui. The map is committed, so **pull before a session and push after it** — two machines edit this tracker.
Charted: 2026-09-23

## Destination

A locked architecture decision on how nebaz is built from neboto (recorded as
an ADR) plus a written first-release spec — services, scoping model, auth,
read-only guarantee — ready to hand to build sessions in the new `neboto/nebaz`
repo. No nebaz code is written on this map beyond the sizing prototype, which builds in place in this directory and becomes the initial commit.

## Notes

Domain: a read-only Azure resource browser TUI (ratatui + tokio), a sibling
product to neboto (`neboto/neboto-tui`, the AWS one). Skills every session
should consult: `grilling` + `domain-modeling` for decision tickets;
`prototype` for the sizing ticket; `research` for SDK facts. neboto's own
CLAUDE.md and CONTEXT.md are the convention reference — nebaz inherits the
vocabulary (Lazy, LazyStore, epoch, section descriptor, step, checkpoint…)
unless a ticket says otherwise.

Standing preferences: **neboto is stable and must not be touched** — no shared
crate, no workspace, no refactor of the AWS app to serve nebaz. Reuse is by
copying files, never by depending on them.

Off-map build (2026-09-23): the Destination's "no code beyond the prototype"
was relaxed by the operator's call once tickets 04 and 05 resolved — the
skeleton deltas both tickets listed and the Subscriptions service (the
subscription list from `az account list`, resource groups from ARM, streamed
per page) were built and committed as ordinary feature work (commits
`20a83d1`, `3dbf9ba`, `94dcde7`), so the catalog ticket grills
against an app showing real rows rather than the stub. Once the catalog
resolved, the five remaining services were built to it the same way
(commit `d2e02f4`, all six services real, stub gone). Nothing else is
built on this map; the live-tenant checks the catalog lists happen on the
Azure machine before ticket 09. Ticket 07's mechanism (policy, guard test,
`PERMISSIONS.md`, `ci.yml`, PR template) and ticket 08's pipeline were
built the same way; ticket 09 removed the dead code and committed the
smoke harness. **The map is complete** (2026-09-24): no open tickets; the
remaining work (live tour, hardening, tag, crates.io) is in
`docs/SPEC-v0.1.md`, not here.

### Settled at charting (decisions made in the charting grill, no ticket)

- **Name**: binary + crate `nebaz`, repo `neboto/nebaz`, docs later at
  neboto.dev/azure. "neboto" is the family name. (crates.io + GitHub org
  checked free 2026-09-23.)
- **Fork shape**: fresh repo; copy neboto's provider-neutral modules verbatim
  (event loop, lazy store, section descriptors, search, macros, bookmarks,
  export, theme, layout, resource list, sub-tab bar, editor, tui, config,
  cli); write a new small `App` + `details_pane` following the same
  conventions. Not clone-and-strip. No git history carried; copied files get
  a one-line origin header.
- **Sync policy**: no expectation of sync between the apps. nebaz's CLAUDE.md
  carries a "ported from neboto" table so a fix can be ported deliberately.
- **First-release services** (in order): Subscriptions + Resource Groups,
  Virtual Machines (+ disks, NICs), Storage Accounts (+ containers), Virtual
  Networks (+ subnets, NSGs), Key Vault (metadata only, never values), AKS.
- **Scoping model**: subscription takes the profile slot (`P`), location takes
  the region slot (`R`) as a client-side filter (Azure list APIs are
  subscription-wide), resource group is a filter chip on every list. Glossary
  keeps "subscription" and "resource group" verbatim — never "profile".
- **Auth day one**: Azure CLI credential (`az login`) only, structured so
  service-principal env vars / managed identity are a config addition later.
- **Feature tier for the first release**: Tier 1 only — split detail pane with
  lazy sections, `@service` search, sub-tabs, bookmarks, jump list, export,
  themes, macros, `$EDITOR`, CLI command copy.
- **Read-only guarantee** carries over (CI check + RBAC permissions doc).
- **Release/install** copies neboto's workflow, install.sh and binstall table.

## Decisions so far

<!-- one line per resolved ticket: gist + link -->

- [Azure Rust SDK landscape](issues/01-azure-rust-sdk-landscape.md): use
  `azure_core` 1.x + `azure_identity` 1.x (own `AzureCliCredential`, keep the
  pipeline for token caching) and call ARM REST directly — no maintained
  management crate exists; every list is subscription-wide with no
  server-side location filter; containers/subnets/agent pools come via ARM.
- [Skeleton sizing prototype](issues/02-skeleton-sizing-prototype.md): built
  in place and committed as the initial commit — 7.2K copied lines (from
  9.8K) vs 2.9K new; six files copied untouched, thirteen needed structural
  cuts (`event`, `lazy`, `service`, `resource`, `cache`, `config`, `macros`,
  `resource_list`… — the "neutral" list was neutral at the module level,
  not the file level); cache re-keyed by subscription; `Resource` trait
  proposal (`portal_url` from the ARM id, `location`, `resource_group`;
  trail/security-group hooks dropped) for ticket 04; per-file table in the
  repo's `docs/PORTED-FROM-NEBOTO.md`.
- [Create the neboto/nebaz repo](issues/03-create-nebaz-repo.md): live at
  https://github.com/neboto/nebaz — public, MIT, squash-only merges,
  `.scratch/` (this map) committed so every machine shares the tracker.
- [Provider traits and scoping model](issues/04-provider-traits-and-scoping-model.md):
  locked as ADR 0002 (+ ADR 0001 for the copy-not-depend fork) and a new
  `CONTEXT.md` — `Location` is a string fed from the locations endpoint,
  resource group is an `rg:` query token, list cache keyed
  `(service, subscription, sub-tab)` survives a subscription switch while
  the LazyStore (keyed by ARM id) is replaced; sub-tabs only for
  subscription-wide or embedded lists (containers and secret names are lazy
  sections); routing prefixes `@rg @disk @nic @subnet @nsg @pool`;
  `--ids` commands, tenant-qualified portal links.

- [Auth and the credential chain](issues/05-auth-and-credential-chain.md):
  ADR 0003 — `AzureCliCredential` + bearer policy, **one pipeline per
  tenant** built on demand; the `P` picker reads `az account list` (all
  tenants, no tenant picker); explicit `auth = "cli"` config key, no
  auto-detection; one app-wide auth error line instead of per-service
  errors; `endpoint_url` is the live ARM base URL and the scope derives
  from it; flags stay `-s -r -p`; the double-slash ARM scope is verified.
- [Service catalog for the first six services](issues/06-service-catalog-first-six.md):
  one state ladder (transitional or failed `provisioningState` > runtime
  state > stateless, native word as label); VM power state on the row via
  a second `statusOnly=true` list; jumps are ARM id → `NavLocation` from a
  **Related** section on every type; Key Vault secret/key *names* via ARM;
  noise = non-enabled subscriptions only; embedded children named
  `parent/child` and inheriting the parent's location; AKS node pools need
  no lazy call; per-type section, state, `az` and API-call tables — 11 list
  calls for a full tour, only Storage's throttled.

- [Read-only guarantee mechanism](issues/07-read-only-guarantee-mechanism.md):
  three layers — the single `GET` constructor plus a `ReadOnlyPolicy` on the
  pipeline that refuses any other method at runtime; a Rust guard test
  (`tests/readonly_guard.rs`) under `cargo test` checking verbs, data-plane
  hosts, `az` command verbs and `PERMISSIONS.md` actions; `PERMISSIONS.md`
  says `Reader` at subscription scope covers everything, Key Vault names
  included, no data-plane role. Built off-map with `ci.yml` and the PR
  template.

- [Release and install pipeline](issues/08-release-and-install-pipeline.md):
  `release.yml` (draft → 4 targets → attestation → publish), `install.sh`,
  binstall table, `docs/RELEASING.md`, Dependabot, rulesets (not applied)
  and a shipped `config.example.toml` — ported from neboto without the
  private-repo knobs; dry run green on all four targets in 4 minutes,
  provenance verified. No tag cut yet.

- [First-release spec](issues/09-first-release-spec.md): **the map's
  destination, reached 2026-09-24** — `docs/SPEC-v0.1.md` (short, pointing
  at the ADRs, `SERVICES.md`, `PERMISSIONS.md`, `RELEASING.md`), the
  catalog promoted to `docs/SERVICES.md`, the fog closed into
  `docs/BACKLOG.md`, `CLAUDE.md` seeded; `v0.1.0` = what is wired (`@all`
  and visual selection dropped, dead code deleted, clippy clean); bar for
  the tag = the live tour + docs; seven hardening items before the tag
  (not yet applied), branch ruleset after; crates.io publish at the tag.
  Two sessions remain, both in the spec.

## Not yet specified

Empty: the destination is reached. Every item that was here (Key Vault
surface, AKS beyond the cluster, Azure analogs of neboto behaviours,
watch mode vs. throttling, emulator and sovereign clouds, `@all` and
visual selection, Tier 2 and 3) was either decided by tickets 06–09 or
moved to the repo's `docs/BACKLOG.md` with what is known. The next effort
starts from the backlog, with a fresh map if it needs one.

## Out of scope

- The neboto.dev website section for nebaz — separate effort once a release
  exists.
- Any Azure write action — the product is read-only.
- A shared crate / Cargo workspace / upstream sync with neboto — ruled out
  because neboto is stable and must not be rebuilt to serve nebaz.
