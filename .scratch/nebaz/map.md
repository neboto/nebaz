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

## Not yet specified

- **Key Vault surface**: which metadata to show (secret names/versions, keys,
  certificates, access model RBAC vs. access policies) and where the
  "never a value" line sits when a list call itself returns attributes.
- **AKS beyond the cluster row**: node pools yes; whether the Kubernetes API
  (data plane, separate auth) is ever touched — probably not, but the
  neboto EKS pane precedent needs checking against what ARM alone offers.
- **Which neboto behaviours have an Azure analog**: ownership ribbon (tags are
  tags; CloudFormation → ARM deployments / Bicep), watch mode, `is_noise`
  (portal deep links are settled: ticket 04).
- **Watch mode vs. ARM throttling**: the Storage RP allows 100 list calls
  per 5 min per subscription/region; whether watch mode ships in the first
  release, and with what floor interval, needs a decision once the catalog
  (ticket 06) shows how many list calls one view costs.
- **Emulator and sovereign clouds**: `endpoint_url` is now the live ARM base
  URL (ticket 05), so a sovereign cloud works by hand; whether to auto-detect
  it from `az cloud show`, and whether Azurite (storage only) is worth an
  emulator mode at all, is open.
- **Two copied neboto behaviours with no Tier-1 entry**: `@all`
  cross-service cached search and list visual selection (`V` / `Ctrl-A`
  multi-row copy/export). The skeleton carries hooks for both; whether
  either is in the first release is ticket 09's call.
- **Tier 2 rich views** (Azure Monitor metrics, Log Analytics tail, blob
  browser) and **Tier 3 lenses** (Activity Log timeline, referenced-by, NSG
  access) — deliberately fog for the first release; each needs its own
  data-plane research before it can be ticketed. In scope for the product,
  not for the first release.

## Out of scope

- The neboto.dev website section for nebaz — separate effort once a release
  exists.
- Any Azure write action — the product is read-only.
- A shared crate / Cargo workspace / upstream sync with neboto — ruled out
  because neboto is stable and must not be rebuilt to serve nebaz.
