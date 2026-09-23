# nebaz

A fast, keyboard-driven, **read-only** terminal UI for browsing Azure — the
Azure sibling of [neboto](https://github.com/neboto/neboto-tui) (the AWS one).

Built in Rust with [Ratatui](https://ratatui.rs/). Website and guide will live
at **[neboto.dev/azure](https://neboto.dev/azure)** once there is a release.

## Status

Pre-release. The provider-neutral core (event loop, lazy sections, section
descriptors, search, macros, bookmarks, export, themes, `$EDITOR`) is ported
from neboto — see [`docs/PORTED-FROM-NEBOTO.md`](docs/PORTED-FROM-NEBOTO.md)
for what came from where and what was changed. The foundation is in: the
scoping model ([ADR 0002](docs/adr/0002-subscription-scoped-lists-location-as-filter.md)),
auth through the Azure CLI ([ADR 0003](docs/adr/0003-azure-cli-credential-per-tenant.md))
and the six first-release services are real, per the catalog in
`.scratch/nebaz/issues/06-service-catalog-first-six.md`: Subscriptions +
Resource Groups, Virtual Machines (+ disks, NICs; power state on the row),
Storage Accounts (+ blob containers, lazy), Virtual Networks (+ subnets,
NSGs), Key Vault (metadata plus secret and key *names*, never values), AKS
(+ node pools). Every row has a **Related** section listing the ARM ids it
points at; Enter on one jumps there. Unverified against a live tenant
until the Azure machine runs it: the `statusOnly=true` VM list shape, and
`--ids` on `az keyvault show` / `az aks show` / `az aks nodepool show`.

## Build

```bash
cargo build            # debug   (cargo build --release for release)
cargo run -- -s sub    # subscriptions + resource groups (needs `az login`)
cargo run -- -s rg     # straight to the Resource Groups sub-tab
cargo run -- -s vm     # virtual machines (Tab / 2 / 3 for Disks, NICs)
cargo run -- -s kv     # key vaults; 4 / 5 on a row list secret and key names
cargo test             # all tests
cargo clippy           # lint
```

## Scoping model

- `P` — **subscription** (the profile slot in neboto); `-p` takes an id or
  a display name
- `R` — **location**, a client-side filter over subscription-wide lists
  (Azure list APIs have no server-side location filter); `All locations`
  is the default; the picker is fed from the subscription's locations list
- resource group — the `rg:<name>` search token on every list
- sub-tabs — digits / Tab, or a routing prefix (`@rg`, `@disk`, `@nsg`, …)

## Auth

The first release authenticates through the **Azure CLI** (≥ 2.54):
`az login`, then run nebaz. The `P` picker lists every subscription the CLI
knows across tenants; switching subscription switches tenant implicitly.
`auth = "cli"` in config (env `NEBAZ_AUTH`) is the only source for now;
`endpoint_url` sets the ARM base URL for a sovereign cloud. A missing `az`
exits with the install link; not being logged in opens the TUI with one
status line and `R` retries.
