# nebaz

A fast, keyboard-driven, **read-only** terminal UI for browsing Azure — the
Azure sibling of [neboto](https://github.com/neboto/neboto-tui) (the AWS one).

Built in Rust with [Ratatui](https://ratatui.rs/). Website and guide will live
at **[neboto.dev/azure](https://neboto.dev/azure)** once there is a release.

> [!WARNING]
> **nebaz is experimental.** Most services were built against Azure's API
> specs and tested offline (unit tests, a fake `az`, a dead endpoint), and
> have **not** had in-depth real-world testing against live subscriptions.
> Expect missing fields, wrong labels and rough edges, especially in the
> services added since `v0.1.0`. The read-only guarantee does not depend on
> any of that: every layer that keeps nebaz from changing anything is
> enforced and tested (see [Why read-only](#why-read-only)). Issues and
> reports from real tenants are very welcome.

## Status

Experimental. What has been checked live is listed under "Verified live" in
[`docs/SERVICES.md`](docs/SERVICES.md); everything else is untested against a
real subscription. The provider-neutral core (event loop, lazy sections, section
descriptors, search, macros, bookmarks, export, themes, `$EDITOR`) is ported
from neboto — see [`docs/PORTED-FROM-NEBOTO.md`](docs/PORTED-FROM-NEBOTO.md)
for what came from where and what was changed. The foundation is in: the
scoping model ([ADR 0002](docs/adr/0002-subscription-scoped-lists-location-as-filter.md)),
auth through the Azure CLI ([ADR 0003](docs/adr/0003-azure-cli-credential-per-tenant.md))
and the first-release services are real, per the catalog in
[`docs/SERVICES.md`](docs/SERVICES.md): Subscriptions +
Resource Groups, Virtual Machines (+ disks, NICs; power state on the row),
Storage Accounts (+ blob containers, lazy), Virtual Networks (+ subnets,
NSGs; since `v0.1.0` public IPs, load balancers, route tables, NAT
gateways, private endpoints and private DNS zones), Key Vault (metadata plus secret and key *names*, never values),
Managed Identity (since `v0.1.0`; federated credentials lazy, and VMs and
AKS link to the identities they use; service principals and app
registrations from Microsoft Graph, with credential expiry), App Service (since `v0.1.0`; apps,
function apps and plans, never app settings), SQL (since `v0.1.0`;
servers, with databases and firewall rules lazy), AKS
(+ node pools). Since `v0.1.0`: Container Registry (registry metadata;
replications and webhooks lazy, never repositories, tags or credentials),
Cosmos DB (accounts, with databases lazy on whichever API the account
uses; never keys or connection strings), Foundry (every Cognitive Services
account, Azure OpenAI included; model deployments and projects lazy, never
keys), Monitor (Log Analytics workspaces and App Insights components,
metadata only; AKS links to its workspace), and Container Apps
(apps, environments and jobs; revisions and auth settings lazy, secret and
env var names only, never values). Every row has an **Access**
section (the role assignments that apply to it, principals named through
Microsoft Graph, inherited ones jumping to where they were made; an
identity also shows what it can do), an
**Activity** section (the last week of operations on it: who, what, when,
whether it worked) and a
**Related** section listing the ARM ids it points at; Enter on one jumps
there; a link to a type nebaz does not browse yet lands in **All
resources**, which lists every resource in the subscription. The detail pane has a line cursor,
vim-style visual selection (`V`, `J`/`K`, `Ctrl-A`, then `y`), a flat
view (`\`) that puts every section in one scroll, a body filter (`/`,
`n`/`N` while it is on), group jumps (`[[`/`]]`) and `Ctrl-W` to wrap long
values such as ARM ids; `H`/`L` step sub-tabs from either pane. `X` exports the
selected resource (every section, after waiting for the lazy ones to load;
`Esc` cancels) and `Ctrl-X` the list, as JSON, CSV and Markdown carrying
the same data (`export_formats` / `export_dir` in the config). The list
pane has its own visual selection (`V`, `J`/`K`, `Ctrl-A`, or a mouse
drag): `y` copies the rows as a Markdown table, `Ctrl-X` exports just
those rows and `X` deep-exports them (every section of up to 50 rows, in
one file per format). The mouse does what the keys do: a click selects a
row or a detail line (under wrap and the filter too) or presses the chip,
marker, badge or hint under it, a double-click is `⏎`, a right-click is
`⌫` (back), a drag selects, the wheel scrolls the pane under it, and the
pickers and popups take clicks without letting them through. `N` on a VM, NIC,
subnet or NSG opens the **network access lens**: the NSG rules that apply,
subnet then NIC, in priority order, defaults included, shadowed rules and
rules the other layer blocks marked (computed from the rules with GETs
only, not Azure's effective view). `m` opens **Azure Monitor metrics**
in the detail pane: a curated set per type (VM, AKS, Container Apps, App
Service, SQL database, storage, Key Vault, Cosmos, load balancer, public
IP, …) with sparklines and last / min / max / avg, a chart of the
selected one, 1h / 6h / 24h / 7d windows (`[`/`]`), and `a` for every
metric the resource publishes. `W` opens the **change timeline**: the
Activity Log's changes, Resource Health transitions, fired alerts and
the deployments that touched the row, merged newest first over 7d / 30d
/ 90d (`[`/`]`), `f` for one source. Verified against a live tenant:
VM power state on the row, and the copied `az` commands (Key Vault and
AKS use the name form, since those `show` commands take no `--ids`).
What `v0.1.0` is, and what must be true before it is tagged, is in
[`docs/SPEC-v0.1.md`](docs/SPEC-v0.1.md); what is not built yet is tracked in
[GitHub issues](https://github.com/neboto/nebaz/issues).

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
cargo run -- -s all    # every resource in the subscription; Enter on a → row opens its typed tab
cargo run -- -s vm     # virtual machines (Tab / 2 / 3 for Disks, NICs)
cargo run -- -s kv     # key vaults; 4 / 5 on a row list secret and key names
cargo run -- -s id     # managed identities; search by client or principal id
cargo run -- -s app    # App Service apps (2 Functions, 3 Plans); 2 on a row loads Configuration
cargo run -- -s sql    # SQL servers; 3 / 4 on a row list databases and firewall rules
cargo run -- -s acr    # container registries; 3 / 4 on a row list replications and webhooks
cargo run -- -s cosmos # Cosmos DB accounts; 5 on a row lists databases
cargo run -- -s subnet # subnets; N on one shows the NSG rules for anything placed in it
cargo run -- -s pip    # public IPs, attached / unattached on the row (also -s lb / rt / nat / pe)
cargo run -- -s dns    # DNS: Private DNS, zones, Private Resolver (3), rulesets (4), DNS policies (5); -s dnsr for resolvers
cargo run -- -s foundry  # Foundry / AI Services / OpenAI; 2 on a row lists deployments
cargo run -- -s law    # Log Analytics workspaces (-s appi for App Insights)
cargo run -- -s pp     # Power Platform enterprise policies; a delegated subnet's Related links back
cargo run -- -s aca    # container apps (2 Ingress); -s acaenv for environments (2 Network), -s acajob for jobs
cargo test             # all tests, including the read-only guard
cargo test --test readonly_guard   # just the guard (see "Why read-only")
cargo clippy --all-targets -- -D warnings   # lint; CI fails on any warning
scripts/smoke.sh       # offline pty run with a fake az (needs python3)
```

## Headless: `services`, `ls`, `get`

With a subcommand nebaz runs once and prints instead of opening the TUI:
the same read-only calls, for scripts and agents. Output is JSON (the
default, carrying `"schema": "nebaz/v1"`) or Markdown (`-o md`); stdout
carries only the result, warnings go to stderr.

```bash
nebaz services                              # every service, its sub-tabs and their prefixes
nebaz ls vm                                 # one subscription-wide list
nebaz ls vnet/subnets -r westeurope -f 'rg:prod tag:env=prod' --limit 20
nebaz ls nsg -p "Prod" -o md                # another subscription, as a Markdown table
nebaz get /subscriptions/…/virtualMachines/vm-1          # every section, lazy ones fetched
nebaz get vm-1 --in vm --section access --section related
nebaz get graph:/servicePrincipals/<object id>
```

`get` shows what the detail pane shows: it drives the same `App` without a
terminal, selects the row the way a jump does and enters every section
(`--section` limits both the output and the calls; `--wait SECS`, default
60, bounds the lazy fetches, and a section still loading prints as
`null`). Exit codes: `0` ok (an empty list included), `1` an Azure error,
`2` a wrong request (unknown prefix, section, subscription or location, a
resource that isn't there or is ambiguous), `4` not signed in (`az
login`); `3` is reserved for `audit`. A wrong `-p` or `-r` fails rather
than falling back. The stable keys, flags and exit codes are pinned in
[`src/headless/contract.json`](src/headless/contract.json); an agent skill
describing all of it is in [`skills/nebaz/SKILL.md`](skills/nebaz/SKILL.md).

## Scoping model

- `P` — **subscription** (the profile slot in neboto); `-p` takes an id or
  a display name
- `R` — **location**, a client-side filter over subscription-wide lists
  (Azure list APIs have no server-side location filter); `All locations`
  is the default; the picker is fed from the subscription's locations list
- resource group — the `rg:<name>` search token on every list
- sub-tabs — digits / Tab, or a routing prefix (`@rg`, `@disk`, `@nsg`, …)
- `@* <text>` — one search over every list already loaded this session
  (warm caches only, never a fetch); `⏎` opens a row in its tab

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
   request builder, an HTTP client crate, a data-plane host (vault, blob, AI model endpoints, App Service sites, SQL servers, container registries, Cosmos DB, container apps, log queries),
   a mutating `az` command, or a non-read action in `PERMISSIONS.md`;
3. `Reader` grants nothing a write could use.

Key Vault is the case people ask about: nebaz lists secret and key
**names** through ARM's control-plane actions, which never return a value,
and no vault data-plane call exists in the codebase (the guard checks).

**Check it yourself.** Every request nebaz makes, to ARM and to Microsoft
Graph, carries `nebaz azsdk-rust-nebaz/<version>` at the front of its
`User-Agent`. With Microsoft Graph activity logs sent to a Log Analytics
workspace, `MicrosoftGraphActivityLogs | where UserAgent startswith "nebaz "`
lists its directory reads, every one a `GET`. ARM's Activity Log records
writes only, so nebaz should never appear in it at all.

Where a change is what you want, **`C`** opens a picker of `az` commands
for the selected resource — Inspect (reads), Connect (`ssh vm`,
`aks get-credentials`, `containerapp exec`) and Change (start / stop /
restart / scale, flagged ⚠) — and copies the one you pick for you to run
yourself. nebaz never runs them (ADR 0005).
