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
[`docs/SERVICES.md`](docs/SERVICES.md): Subscriptions +
Resource Groups, Virtual Machines (+ disks, NICs; power state on the row),
Storage Accounts (+ blob containers, lazy), Virtual Networks (+ subnets,
NSGs), Key Vault (metadata plus secret and key *names*, never values), AKS
(+ node pools). Since `v0.1.0`: Foundry (every Cognitive Services
account, Azure OpenAI included; model deployments and projects lazy, never
keys). Every row has a **Related** section listing the ARM ids it
points at; Enter on one jumps there. The detail pane has a line cursor,
vim-style visual selection (`V`, `J`/`K`, `Ctrl-A`, then `y`) and a flat
view (`\`) that puts every section in one scroll. Verified against a live tenant:
VM power state on the row, and the copied `az` commands (Key Vault and
AKS use the name form, since those `show` commands take no `--ids`).
What `v0.1.0` is, and what must be true before it is tagged, is in
[`docs/SPEC-v0.1.md`](docs/SPEC-v0.1.md); what is deliberately not in it
is in [`docs/BACKLOG.md`](docs/BACKLOG.md).

## Install

Prebuilt binaries for Linux (x86_64, aarch64) and macOS (Intel, Apple
Silicon) are attached to every [GitHub release](https://github.com/neboto/nebaz/releases)
(none cut yet; the pipeline is in place, see [`docs/RELEASING.md`](docs/RELEASING.md)).
nebaz needs the **Azure CLI** (≥ 2.54.0), logged in with `az login`; the
installer does not install it.

**Installer** — picks the right binary, verifies its SHA-256 and, when the
GitHub CLI is installed, its signed build provenance, and puts it in
`~/.local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/neboto/nebaz/main/install.sh | sh
```

Prefer to read a script before running it? Download it first:

```bash
curl -fsSLO https://raw.githubusercontent.com/neboto/nebaz/main/install.sh && less install.sh && sh install.sh
```

**Or with [cargo-binstall](https://github.com/cargo-bins/cargo-binstall)**:

```bash
cargo binstall --git https://github.com/neboto/nebaz nebaz
```

`NEBAZ_VERSION=v0.1.0` pins a version and `NEBAZ_INSTALL_DIR` changes the
destination. Or grab the tarball for your platform from the releases page and
put `nebaz` anywhere on your `PATH`.

**Verify a download.** Every release archive carries a signed [build
provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
naming the commit and workflow that built it. With the GitHub CLI:

```bash
gh attestation verify nebaz-aarch64-apple-darwin.tar.gz --repo neboto/nebaz
```

**From source** — needs a recent stable Rust toolchain:

```bash
cargo install --git https://github.com/neboto/nebaz
```

Configuration lives in `~/.config/nebaz/config.toml`; every key is
documented in [`config.example.toml`](config.example.toml).

## Build

```bash
cargo build            # debug   (cargo build --release for release)
cargo run -- -s sub    # subscriptions + resource groups (needs `az login`)
cargo run -- -s rg     # straight to the Resource Groups sub-tab
cargo run -- -s vm     # virtual machines (Tab / 2 / 3 for Disks, NICs)
cargo run -- -s kv     # key vaults; 4 / 5 on a row list secret and key names
cargo run -- -s foundry  # Foundry / AI Services / OpenAI; 2 on a row lists deployments
cargo test             # all tests, including the read-only guard
cargo test --test readonly_guard   # just the guard (see "Why read-only")
cargo clippy           # lint
scripts/smoke.sh       # offline pty run with a fake az (needs python3)
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

## Why read-only

This is a design constraint, not a missing feature. A `PERMISSIONS.md`
that documents a pure `*/read` footprint is a trust asset: a security team
can approve nebaz precisely *because* it cannot change anything, and the
built-in `Reader` role at subscription scope is the whole requirement. One
gated write action would change that conversation permanently.

The promise is held at three layers, not by convention
([`PERMISSIONS.md`](PERMISSIONS.md)):

1. the single request constructor only builds `GET`s, and a pipeline policy
   refuses any other method at runtime;
2. `tests/readonly_guard.rs` fails `cargo test` if the source gains another
   request builder, an HTTP client crate, a data-plane host (vault, blob, AI model endpoints),
   a mutating `az` command, or a non-read action in `PERMISSIONS.md`;
3. `Reader` grants nothing a write could use.

Key Vault is the case people ask about: nebaz lists secret and key
**names** through ARM's control-plane actions, which never return a value,
and no vault data-plane call exists in the codebase (the guard checks).

Where a change is what you want, **`C`** copies the `az … show` command for
the selected resource; edit the verb and run it yourself.
