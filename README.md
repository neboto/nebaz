# nebaz

A fast, keyboard-driven, **read-only** terminal UI for browsing Azure: 20
services, console-style detail panes, follow-the-links navigation across
subscriptions, a network access lens, metrics, a change timeline and a
security audit, all without leaving the terminal. The Azure sibling of
[neboto](https://github.com/neboto/neboto-tui) (the AWS one).

Built in Rust with [Ratatui](https://ratatui.rs/).

<p align="center">
  <img src="demo/nebaz.gif" width="100%"
       alt="nebaz demo: a container app's failed revision, then @changes finds a new NSG deny rule, the change timeline puts it next to the alert, the network access lens shows it blocking the Power Platform subnet, and @audit lists the findings">
</p>

<p align="center"><em>Recorded with <code>nebaz --demo</code>. Nothing on screen is a real tenant.</em></p>

**Try it without an Azure account:** `nebaz --demo` opens a made-up tenant
with an outage to track down and misconfigurations planted for the audit to
find. It needs no `az`, no login, and makes no network calls.

**nebaz is read-only.** It issues only `GET`s, the built-in `Reader` role is
all it needs, and a test fails the build if that ever changes. See
[Why read-only](#why-read-only).

> [!WARNING]
> **nebaz is experimental.** Most services were built against Azure's API
> specs and tested offline, and have **not** had in-depth testing against
> live subscriptions. Expect missing fields, wrong labels and rough edges.
> The read-only guarantee does not depend on any of that: every layer that
> keeps nebaz from changing anything is enforced and tested. Reports from
> real tenants are very welcome.

---

## Highlights

- **20 Azure services** behind an `@prefix` fuzzy search (`@vm web`,
  `@nsg`, `@aca`), with numbered sub-tabs: about 50 lists, every one
  subscription-wide.
- **Console-style split detail panes**: overview, the type's own sections
  (loaded lazily on first view), **Access** (the role assignments that apply,
  principals named through Microsoft Graph), **Activity** (the last week of
  operations: who, what, when) and **Related**.
- **Follow the links**: `Enter` on any ARM id jumps to that resource, across
  services, resource groups and subscriptions. `⌫` comes back.
- **Network access lens** (`N`) on a VM, NIC, subnet or NSG: the NSG rules
  that apply, in priority order with defaults, shadowed rules marked.
- **Metrics** (`m`): Azure Monitor charts in the pane, a curated set per type.
  On an Application Gateway with WAF, a Front Door profile or a WAF policy it
  is the WAF view: requests by action, the block rate and per-rule tables
  (`Tab` between them, `⏎` charts a rule, `d` back, `w` toggles with the
  default set).
- **Change timeline** (`W`) on any resource: the Activity Log, Resource Health
  and fired alerts, merged. **`@changes`** does it subscription-wide.
- **`@audit`**: over 60 checks (world-open NSG rules, subnets without an NSG,
  public storage and vaults, open SQL firewalls, expiring app credentials,
  privileged guests and service principals, VPN and ExpressRoute links down,
  firewalls with threat intelligence off, …) computed from what is already
  loaded.
- **Directory**: service principals and app registrations from Microsoft
  Graph, with credential expiry.
- **Referenced by** (`U`) and an **ownership ribbon**: what points at this
  resource, and who manages it.
- **Copy, never run**: `y` copies the id, `C` picks an `az` command to copy
  (read, connect or change); nebaz runs none of them.
- **Export** (`X` / `Ctrl-X`) to JSON, CSV and Markdown, **headless
  subcommands** for scripts and agents, **macros**, **bookmarks**, **10
  themes**, **mouse** support.

---

## See it in action

Each clip is one workflow against `nebaz --demo`. Click for full size.

<table>
  <tr>
    <td width="50%"><a href="demo/scenes/power-platform-outage.gif"><img src="demo/scenes/power-platform-outage.gif" alt="Tracking down a Power Platform outage: @changes, the change timeline, then the network access lens"></a><br><b>Why can't Power Platform reach the API?</b> <code>@changes</code> shows a new NSG rule, <kbd>W</kbd> puts it next to the alert, and <kbd>N</kbd> shows it shadowing the default allow for the injected subnet.</td>
    <td width="50%"><a href="demo/scenes/audit.gif"><img src="demo/scenes/audit.gif" alt="The @audit findings, then opening the open SSH rule and its change timeline"></a><br><b>Audit.</b> <code>@audit</code> lists what is wrong, worst first; <kbd>Enter</kbd> opens the NSG with SSH open to the internet and <kbd>W</kbd> shows the vendor's guest account added it.</td>
  </tr>
  <tr>
    <td width="50%"><a href="demo/scenes/identities.gif"><img src="demo/scenes/identities.gif" alt="An app registration with expired and expiring secrets, a service principal's roles, and the subscription's Access section"></a><br><b>Who can do what.</b> An app registration with one secret expired and one expiring in six days, and a deploy service principal holding User Access Administrator on the subscription.</td>
    <td width="50%"><a href="demo/scenes/dns.gif"><img src="demo/scenes/dns.gif" alt="Private DNS zones, their records and VNet links"></a><br><b>Private DNS.</b> A private-link zone with records but no VNet link, so nothing resolves it, and which networks each zone is linked to.</td>
  </tr>
  <tr>
    <td width="50%"><a href="demo/scenes/follow-links.gif"><img src="demo/scenes/follow-links.gif" alt="From an application gateway backend to the container app, its environment and subnet, then the network access lens"></a><br><b>Follow the links.</b> <kbd>Enter</kbd> from an application gateway's backend to the container app, its environment and its subnet, then <kbd>N</kbd> for what may reach it.</td>
    <td width="50%"></td>
  </tr>
</table>

---

## Install

nebaz needs the **Azure CLI** (≥ 2.54.0), logged in with `az login`. The
installer does not install it.

**Installer:** picks the right binary for Linux (x86_64, aarch64) or macOS
(Intel, Apple Silicon), verifies its SHA-256 and, when the GitHub CLI is
installed, its signed build provenance, and puts it in `~/.local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/neboto/nebaz/main/install.sh | sh
```

Prefer to read a script before running it?

```bash
curl -fsSLO https://raw.githubusercontent.com/neboto/nebaz/main/install.sh && less install.sh && sh install.sh
```

`NEBAZ_VERSION=v0.3.0` pins a version and `NEBAZ_INSTALL_DIR` changes the
destination.

**Windows (PowerShell):** installs `nebaz.exe` to
`%LOCALAPPDATA%\Programs\nebaz`, verifies the SHA-256 (and the provenance
when `gh` is installed and logged in), and adds the folder to your user PATH:

```powershell
irm https://raw.githubusercontent.com/neboto/nebaz/main/install.ps1 | iex
```

`NEBAZ_VERSION`, `NEBAZ_INSTALL_DIR` and `NEBAZ_NO_ATTEST` work as above. On
Windows on ARM it takes the native build when the release has one, else the
x64 build (emulated). scoop and winget packages: not yet.

**Other ways:**

```bash
cargo binstall --git https://github.com/neboto/nebaz nebaz   # cargo-binstall
cargo install --git https://github.com/neboto/nebaz          # from source, recent stable Rust
```

or download the archive for your platform from the
[releases page](https://github.com/neboto/nebaz/releases). Every archive
carries a signed build provenance attestation:

```bash
gh attestation verify nebaz-aarch64-apple-darwin.tar.gz --repo neboto/nebaz
```

### Windows

nebaz builds and is tested on Windows (CI runs the suite on `windows-latest`;
install with the PowerShell line under [Install](#install)). Use Windows Terminal; the
Azure CLI (`az`) must be installed and logged in. Files live under
`%APPDATA%\nebaz` (config, bookmarks, macros) and `%LOCALAPPDATA%\nebaz`
(cache). The system proxy is not read: set `HTTPS_PROXY` if you need one
(`nebaz doctor` shows what it sees). `$EDITOR` may be quoted, for example
`"C:\Program Files\Microsoft VS Code\bin\code.cmd" --wait`; the default is
`notepad`. The Linux build also runs under WSL.

---

## Quick start

```bash
az login
nebaz                 # the welcome screen; S picks a service
nebaz -s vm           # straight to virtual machines
nebaz -s nsg -r westeurope -p "Prod"   # a sub-tab, a location filter, a subscription
nebaz --demo          # the made-up tenant, no Azure needed
nebaz open /subscriptions/…/virtualMachines/vm-1 --charts 7d   # straight to one resource's charts
nebaz --bookmark web  # a saved bookmark, by part of its name
```

Then: `j`/`k` to move, `⏎` to open the detail pane, `1`–`9` for its
sections, `⏎` on an ARM id to jump, `⌫` to come back, `/` to search,
`@` to switch service, `?` for every key.

---

## Services

`-s <prefix>` on the command line, or `@<prefix>` in the search box. Each
service's sub-tabs have prefixes of their own (`nebaz services` lists them
all).

| Prefix | Service | Sub-tabs |
|---|---|---|
| `sub` | Subscriptions | Subscriptions, Resource groups (`rg`), All resources (`all`) |
| `vm` | Virtual Machines | VMs, Disks (`disk`), NICs (`nic`), Scale sets (`vmss`, instances lazy; a Flexible set's VMs are in VMs), ASGs (`asg`: member NICs, the NSG rules that name them), Galleries (`gallery`: image definitions and versions) |
| `arc` | Azure Arc | Servers (status, Expired after 45 days disconnected, OS, agent, extensions, ESU licence and patch settings), Kubernetes (`arck8s`: connectivity, distribution, agent and its errors), Private link scopes (`arcpls`); never an extension's settings, a run command or a cluster credential |
| `avd` | Virtual Desktop | Host pools (session hosts: status, sessions, heartbeat, agent, failed health checks; configuration, agent update windows), App groups (`avdag`), Workspaces (`avdws`), Scaling plans (`avdsp`: schedules); never a registration token or a user session |
| `storage` | Storage | Accounts (blob containers lazy) |
| `gov` | Governance | Policy assignments (management groups' included), exemptions (`exempt`), custom definitions and initiatives (`pdef`), resource locks (`lock`), the management groups you can read (`mg`), budgets (`budget`: spend, forecast and thresholds); never compliance or cost queries (POSTs) |
| `defender` | Defender | Defender for Cloud recommendations with their severity, alerts (`secalert`, never a command line), the secure score and its controls (`score`), which plans are on (`pricing`); beside `@audit`, never in it |
| `advisor` | Advisor | Advisor recommendations by impact and category with their savings and age (Security ones are Defender's, hidden until `a`), the Advisor score and its history (`advscore`), what was snoozed or dismissed (`snooze`) |
| `backup` | Backup | Recovery Services vaults (protected items, policies, failed jobs), Backup vaults (`bvault`: backup instances, policies, jobs) |
| `vnet` | Virtual Network | VNets, Subnets (`subnet`), NSGs (`nsg`), Public IPs (`pip`), Load balancers (`lb`), Route tables (`rt`, appliance next hops matched to their NIC / VM or load balancer), NAT gateways (`nat`), Private endpoints (`pe`), Bastion hosts (`bastion`), DDoS protection plans (`ddos`); VNets and NSGs show their Network Watcher flow logs |
| `dns` | DNS | Private DNS zones, DNS zones (`dnsz`), Private resolvers (`dnsr`), Forwarding rulesets (`dnsfr`), DNS security policies (`dnsp`), Traffic Manager profiles (`tm`, endpoints) |
| `agw` | Edge | Application gateways, Front Door (`afd`), WAF policies (`waf`), Private Link services (`pls`, consumer connections) |
| `er` | Hybrid | ExpressRoute circuits, VNet gateways (`vgw`), Connections (`cn`), Local network gateways (`lgw`) |
| `vwan` | Virtual WAN | Virtual WANs, Hubs (`hub`: VNet connections, route tables and routing intent), hub VPN gateways (`hubvpn`), ExpressRoute gateways (`huber`), point-to-site gateways (`p2s`), VPN sites (`vpnsite`) |
| `fw` | Firewall | Azure Firewalls, Firewall policies (`fwp`, rule collection groups), IP groups (`ipg`), Palo Alto Cloud NGFW (`ngfw`), Local rulestacks (`rulestack`, rules) |
| `kv` | Key Vault | Vaults (secret and key *names*, never values) |
| `id` | Identity | Managed identities, Service principals (`sp`), App registrations (`appreg`) |
| `aks` | AKS | Clusters, Node pools (`pool`) |
| `acr` | Container Registry | Registries (replications, webhooks) |
| `app` | App Service | Apps, Function apps (`func`), Plans (`plan`), Static sites (`swa`: Static Web Apps, environments, custom domains, linked backends) |
| `sql` | SQL | Servers (databases, firewall rules), Managed instances (`sqlmi`: databases, failover group), Instance pools (`sqlpool`) |
| `cosmos` | Cosmos DB | Accounts (databases on whichever API) |
| `pg` | PostgreSQL & MySQL | PostgreSQL flexible servers, MySQL (`mysql`) |
| `foundry` | Foundry | AI Services and Azure OpenAI accounts (deployments, projects), Search services (`search`: shared private links) |
| `monitor` | Monitor | Log Analytics workspaces, App Insights (`appi`), Metric alerts (`malert`), Log search alerts (`logalert`), Activity log alerts (`activityalert`), Action groups (`ag`), Alert processing rules (`apr`), Fired alerts (`alert`, the last 30 days); every row's Related names the alert rules watching it |
| `pp` | Power Platform | Enterprise policies (VNet injection, encryption) |
| `automation` | Automation | Accounts (`aa`): runbooks with their schedules and last job, schedules, the last 7 days of jobs, hybrid worker groups and their machines; never variables, credentials, runbook content or job output |
| `aca` | Container Apps | Apps (revisions), Environments (`acaenv`), Jobs (`acajob`, executions), Container groups (`aci`: Container Instances, each container's state and restarts) |
| `redis` | Redis | Azure Cache for Redis, Managed Redis (`amr`) |
| `sb` | Messaging | Service Bus namespaces, Event Hubs (`eh`) |
| `changes` | Changes | Everything that changed recently: activity, deployments, health |
| `audit` | Audit | Security findings over what is loaded |

What each service shows, its state rule and the calls behind it:
[`docs/SERVICES.md`](docs/SERVICES.md). Keys, credentials, connection
strings, app settings and secret values are never fetched.

---

## Keys

`?` shows them all in the app.

**Anywhere**

| Key | |
|---|---|
| `S` · `R` · `P` | service · location · subscription pickers |
| `/` · `@svc text` | fuzzy search · switch service and search |
| `↑`/`↓` in the bar · `←` `→` `Home` `End` | earlier searches (this session); move through the query, so `/` `↑` `←←←` fixes a typo in the last one (`^A` `^E` `Alt-←` `^W` `^U` `^K` `Del` work too) |
| `⌫` / `Ctrl-O` · `Ctrl-F` · `` ` `` | history back · forward · jump list (the `←` `→` left of the service tabs click the same) |
| `B` · `'` | bookmark · bookmarks |
| `,` | macros (record, replay; `--macro NAME` on startup) |
| `:` | command picker: run any key by name (`:m` metrics; the keys that work on the selection lead; `⏎` presses the key) |
| `\|` | split out: this place (row, section, subscription; the charts at their window) in a second nebaz beside this one: a new pane in tmux, zellij, WezTerm, kitty, iTerm or Ghostty (macOS); a window or tab in Alacritty, Terminal, GNOME Terminal, Konsole or foot; config `split_command` for anything else. With no terminal to split, the command is copied |
| `M` · `b` · `?` · `q` | messages · banner · help (type to filter it: `log`, `copy`, `mouse`; leads with **Here**, the keys that work on the selection) · quit |

**List pane**

| Key | |
|---|---|
| `j`/`k` · `gg`/`G` · `^d`/`^u` | move · top/bottom · half page |
| `⏎` / `l` | open the detail pane |
| `Tab` · `1`–`9` · `H`/`L` | sub-tabs |
| `z` · `F` · `a` | sort · state filter · hide noisy rows |
| `V` · `J`/`K` · `^A` | select rows; then `y` copies a Markdown table, `X` deep-exports |
| `r` / `F5` · `w` | refresh · watch mode |

**Detail pane**

| Key | |
|---|---|
| `Tab` · `1`–`9` | sections |
| `⏎` | jump to the ARM id on the line |
| `\` · `Z` · `^W` | every section in one scroll · full width · wrap long values |
| `/` · `n`/`N` | filter the lines (edited like the search bar; `^W` deletes a word there) · step matches |
| `[[` / `]]` | previous / next group |
| `V` · `y` | select lines · copy line or selection |

**On a resource**

| Key | |
|---|---|
| `N` | network access lens (VM, NIC, subnet, NSG) |
| `m` | metrics (WAF view on a gateway, Front Door profile or WAF policy: `Tab` `⏎` `d` `w` `n`) |
| `W` | change timeline (`f` one source, `[`/`]` window) |
| `U` | referenced by |
| `i` | about this service: what it is, what nebaz shows of it, Microsoft Learn links (`o` opens the one under the cursor, `1`–`9` copy one; `j`/`k`, `V`, `^A` and `y` copy text as in the detail pane); VNets, Arc servers and Automation so far |
| `C` | copy an `az` command (inspect, connect, change; never run) |
| `y` · `O` · `e` | copy the id · open in the portal (over SSH, or with no browser, the link is copied) · open the JSON in `$EDITOR` |
| `X` / `^X` | export the resource / the list |

**Search tokens:** `rg:name` (resource group), `tag:key=value`, and
`@* text` to search every list already loaded this session. **Mouse:**
click, double-click (`⏎`), right-click (`⌫`), drag to select, wheel to
scroll.

On a service with sub-tabs, `/` counts its matches in every tab already
loaded this session (it never fetches): the tabs it found nothing on are
dimmed, and while you type, a tab with no matches gives way to the first
loaded tab that has some. It returns to the tab you started on once that
tab matches again, or on `Esc`; `⏎` keeps the tab it found; an `F` state
filter holds the tab still. A tab not loaded yet is neither followed nor
dimmed.

---

## Subscriptions and locations

- Every list is **subscription-wide**. `P` (or `-p`, by id or name) switches
  subscription, and with it tenant; the picker lists every subscription the
  Azure CLI knows. With `subscriptions = [...]` in the config, `P` also
  shows each one's row count for the current sub-tab.
- **Location** (`R`, `-r`) is a filter over rows already fetched, never a
  call scope; `global` resources pass every filter.
- **Resource group** is the `rg:<name>` search token.

---

## Scripts and agents

With a subcommand nebaz runs once and prints instead of opening the TUI:
the same read-only calls. Output is JSON (`"schema": "nebaz/v1"`) or
Markdown (`-o md`); stdout carries only the result, warnings go to stderr.

```bash
nebaz services                              # every service, its sub-tabs and their prefixes
nebaz ls vm                                 # one subscription-wide list
nebaz ls vnet/subnets -r westeurope -f 'rg:prod tag:env=prod' --limit 20
nebaz ls vm --subscriptions Prod,Dev        # several subscriptions, each row tagged
nebaz get /subscriptions/…/virtualMachines/vm-1          # every section, lazy ones fetched
nebaz get vm-1 --in vm --section access --section related
nebaz changes --since 6h                    # what changed, subscription-wide
nebaz audit --fail-on high                  # exit 3 on a finding at or above high
nebaz doctor -o md                          # proxy, certificates, az login, ARM, Graph, GitHub: each failure in full
```

`get` shows what the detail pane shows, driving the same app without a
terminal. Exit codes: `0` ok, `1` an Azure error, `2` a wrong request, `3`
an audit finding at or above `--fail-on`, `4` not signed in. The stable
keys, flags and exit codes are pinned in
[`src/headless/contract.json`](src/headless/contract.json); an agent skill
describing all of it is in [`skills/nebaz/SKILL.md`](skills/nebaz/SKILL.md).
Every subcommand takes `--demo` too.

`open` is the one subcommand that starts the TUI: at a resource's detail
pane, a section of it, or its charts. Its flags are pinned in the same
contract, so a script or a tmux layout can rely on them.

```bash
nebaz open /subscriptions/…/virtualMachines/vm-1            # the detail pane
nebaz open vm-1 --in vm --section networking --full         # by name, one section, full width
nebaz open /subscriptions/…/virtualMachines/vm-1 --charts 24h --metric cpu
nebaz --bookmark "prod gateway"                             # a bookmark saved with B
```

A wrong id, service or window exits `2` before the TUI starts; a resource,
section or metric that isn't there says so in the status bar.

---

## Configuration

`~/.config/nebaz/config.toml` (`%APPDATA%\nebaz\config.toml` on Windows;
bookmarks and macros live beside it, the update-check state under
`%LOCALAPPDATA%\nebaz`); every key is documented in
[`config.example.toml`](config.example.toml). Command-line flags override it
for one run.

- **Auth** is the Azure CLI: `az login`, then run nebaz (`auth = "cli"`, env
  `NEBAZ_AUTH`). A missing `az` exits with the install link; not being
  logged in opens the TUI with one status line, and `R` retries.
- **Sovereign clouds:** `endpoint_url` (`--endpoint-url`) sets the ARM base
  URL.
- **Themes:** `theme = "gruvbox-dark"` (`--theme`): dark, light,
  solarized, gruvbox, dracula, nord and catppuccin presets.
- **Syntax colours:** JSON, YAML and shell blocks in the detail pane (a
  policy definition's rule, say) are coloured from the theme.
  `syntax_highlight = false` turns it off. Display only: copy, export and
  `nebaz get` stay plain text.
- **Recordings:** `--show-keys` names each key in a corner box as it's
  pressed, with what it did.
- **Update check:** once a day nebaz asks GitHub for its latest release and
  shows a dim `↑ vX.Y.Z` when it is newer. `update_check = false`,
  `--no-update-check` or `NEBAZ_NO_UPDATE_CHECK=1` turn it off.
- **Behind a proxy:** nebaz reads `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`,
  not the macOS or Windows system proxy settings or a PAC file, and trusts
  the OS certificate store (so a TLS-inspecting proxy's root CA that IT
  installed is trusted; on Linux and WSL, the system CA bundle or
  `SSL_CERT_FILE`). `nebaz doctor -o md` shows what fails and why.

---

## Why read-only

This is a design constraint, not a missing feature. A
[`PERMISSIONS.md`](PERMISSIONS.md) that documents a pure `*/read` footprint
is a trust asset: a security team can approve nebaz precisely *because* it
cannot change anything, and the built-in **Reader** role at subscription
scope is the whole requirement.

The promise is held at three layers, not by convention:

1. the single request constructor only builds `GET`s, and a pipeline policy
   refuses any other method at runtime;
2. [`tests/readonly_guard.rs`](tests/readonly_guard.rs) fails `cargo test`
   if the source gains another request builder, an HTTP client crate, a
   data-plane host (Key Vault, blob, SQL, Cosmos, model endpoints, …), a
   mutating `az` command, or a non-read action in `PERMISSIONS.md`;
3. `Reader` grants nothing a write could use.

**Key Vault** is the case people ask about: nebaz lists secret and key
**names** through ARM's control-plane actions, which never return a value,
and no vault data-plane call exists in the codebase.

**Microsoft Graph** is read the same way: `GET`s of directory objects, never
a secret ([ADR 0004](docs/adr/0004-read-only-microsoft-graph.md)).

**The one non-Azure request** is the daily update check: an anonymous `GET`
of `api.github.com/repos/neboto/nebaz/releases/latest`, no token, through
the same GET-only pipeline, allowed from one file
([ADR 0008](docs/adr/0008-update-check-is-the-one-non-azure-request.md)).

**Check it yourself.** Every request carries `nebaz azsdk-rust-nebaz/<version>`
at the front of its `User-Agent`. With Microsoft Graph activity logs in a
Log Analytics workspace, `MicrosoftGraphActivityLogs | where UserAgent
startswith "nebaz "` lists its directory reads, every one a `GET`. ARM's
Activity Log records writes only, so nebaz never appears in it.

Where a change is what you want, `C` copies the `az` command (`vm start`,
`aks get-credentials`, `containerapp exec`, …) for you to run yourself
([ADR 0005](docs/adr/0005-copied-commands-may-change-azure.md)).

---

## Development

```bash
cargo build
cargo run -- --demo                          # the offline tenant (docs/DEMO.md)
cargo test                                   # every test, the read-only guard included
cargo clippy --all-targets -- -D warnings    # CI fails on any warning
scripts/smoke.sh                             # offline pty run with a fake az (needs python3; Unix only)
```

- [`CONTRIBUTING.md`](CONTRIBUTING.md): how to send a change.
- [`CLAUDE.md`](CLAUDE.md): the architecture and the conventions.
- [`docs/SERVICES.md`](docs/SERVICES.md): what each service shows and why.
- [`docs/DEMO.md`](docs/DEMO.md): the demo tenant, and how to add to it.
- [`docs/adr/`](docs/adr): the design decisions.
- [`docs/RELEASING.md`](docs/RELEASING.md): how a release is cut.
- [`docs/PORTED-FROM-NEBOTO.md`](docs/PORTED-FROM-NEBOTO.md): the core
  (event loop, lazy sections, search, macros, bookmarks, export, themes) is
  copied from neboto, and this is what came from where.
- What is not built yet: [GitHub issues](https://github.com/neboto/nebaz/issues).

Security issues: see [`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)
