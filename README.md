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
and the first service, **Subscriptions** (the subscription list from
`az account list`, resource groups from ARM). The other five services are
stubs until their catalog lands.

Planned first release: Subscriptions + Resource Groups, Virtual Machines
(+ disks, NICs), Storage Accounts (+ containers), Virtual Networks (+ subnets,
NSGs), Key Vault (metadata only, never values), AKS.

## Build

```bash
cargo build            # debug   (cargo build --release for release)
cargo run -- -s sub    # subscriptions + resource groups (needs `az login`)
cargo run -- -s rg     # straight to the Resource Groups sub-tab
cargo run -- -s vm     # a stub service
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
