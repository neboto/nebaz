# Backlog

What is deliberately not in `v0.1.0`, with what is already known about
each item. This list closed the wayfinder map's fog on 2026-09-24 (ticket
09): every item is product scope, none is first-release scope. The next
effort starts here, not from the map. Release mechanics still to do
(Homebrew tap, crates.io, macOS signing, musl, CHANGELOG) live at the end
of [`RELEASING.md`](RELEASING.md).

## Copied from neboto, not wired

- **`@all` cross-service search** — fuzzy-match every service with a warm
  cache entry instead of switching to one. neboto has it; the parser
  half (`parse_all_query`) was removed from nebaz in the `v0.1.0` cleanup
  and is in git history (commit "First-release spec"), the app half was
  never ported.
- **List visual selection** (`V` / `Ctrl-A`, multi-row copy and deep
  export) — `App` still says "no row is ever in one"; the multi-resource
  deep export (`export_detail_multi`, long-format CSV) was removed in the
  same cleanup and is in git history.

## Azure analogs of neboto behaviours

- **Ownership ribbon** — neboto shows CloudFormation ownership; the Azure
  analog is ARM deployments / Bicep (`Microsoft.Resources/deployments` per
  resource group, correlation by resource id). Needs its own design.
- **Watch-mode floor for Storage** — one watched Accounts view fits the
  Storage RP's 100 list calls / 5 min at the 5 s preset (60 calls); two
  watched Storage views in one subscription would not. A per-service floor
  (Storage: 10 s) is the fix if anyone hits it.
- **Cross-fill embedded sub-tabs from one call** — VNets/Subnets and
  Clusters/Node pools are two cache entries from the same list and refetch
  on sub-tab switch (`SERVICES.md` rule 7).
- **One-call VM list** — check whether `statusOnly=true` also returns the
  full VM model; if so the two-call form collapses to one.

## Environment

- **Sovereign-cloud auto-detect** — `endpoint_url` works by hand for Azure
  Government / China (the token scope derives from it, ADR 0003). Reading
  `az cloud show` to set it automatically is a small addition once
  someone needs it.
- **Azurite emulator mode** — storage only, data-plane only, so it offers
  nothing to a control-plane browser; probably never.
- **Windows** — the CLI credential already runs `az.cmd` through `cmd /C`
  and crossterm supports it; `$EDITOR` and the browser opener are
  Unix-shaped; not in the release matrix; untested.

## Tier 2 rich views (each needs data-plane research before a ticket)

- Azure Monitor metrics (`Microsoft.Insights/metrics`, control-plane, so
  `Reader` covers it — the cheapest of the three).
- Log Analytics tail (data plane `api.loganalytics.io`, separate scope and
  role: a new endpoint the read-only guard must learn about first).
- Blob browser (data plane `blob.core.windows.net`, a host the guard
  currently forbids by name; listing blobs needs `Storage Blob Data
  Reader`, a data-plane role `PERMISSIONS.md` says is not needed today).

## Tier 3 lenses

- Activity Log timeline (`Microsoft.Insights/eventtypes/management/values`,
  control plane).
- Referenced-by (the reverse of the Related section).
- NSG effective access (effective security rules are a `POST` action in
  ARM — `…/effectiveNetworkSecurityGroups` — so this one conflicts with the
  read-only guarantee as built and may never ship).

## Catalog leftovers

- Key Vault certificates — no ARM list exists; data plane only.
- The `agentPoolProfiles` live check (`SERVICES.md` rule 8).
- An offline wiring harness like neboto's `src/harness_tests/` (build the
  app with a dead endpoint, inject mock rows, smash the keymap against a
  `TestBackend`). Today: unit tests, the read-only guard, and the pty
  smoke run in `scripts/smoke.sh`.
