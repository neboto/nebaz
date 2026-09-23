# nebaz

A fast, keyboard-driven, **read-only** terminal UI for browsing Azure — the
Azure sibling of [neboto](https://github.com/neboto/neboto-tui) (the AWS one).

Built in Rust with [Ratatui](https://ratatui.rs/). Website and guide will live
at **[neboto.dev/azure](https://neboto.dev/azure)** once there is a release.

## Status

Pre-release skeleton. The provider-neutral core (event loop, lazy sections,
section descriptors, search, macros, bookmarks, export, themes, `$EDITOR`) is
ported from neboto; every service is a stub until its catalog lands. See
[`docs/PORTED-FROM-NEBOTO.md`](docs/PORTED-FROM-NEBOTO.md) for what came from
where and what was changed.

Planned first release: Subscriptions + Resource Groups, Virtual Machines
(+ disks, NICs), Storage Accounts (+ containers), Virtual Networks (+ subnets,
NSGs), Key Vault (metadata only, never values), AKS.

## Build

```bash
cargo build            # debug   (cargo build --release for release)
cargo run -- -s vm     # run against the stub provider
cargo test             # all tests
cargo clippy           # lint
```

## Scoping model

- `P` — **subscription** (the profile slot in neboto)
- `R` — **location**, a client-side filter over subscription-wide lists
  (Azure list APIs have no server-side location filter); `All locations`
  is the default
- resource group — a filter chip on every list

Auth on day one is the Azure CLI credential (`az login`).
