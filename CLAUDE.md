# CLAUDE.md

Guidance for Claude Code working in this repository. This file is the **lean
architecture + conventions** reference: how the app is put together and the
rules that apply everywhere. It is loaded into every session, so keep it
that way; per-service prose goes in `docs/SERVICES.md`.

The app ("nebaz") is a read-only Azure resource browser TUI (ratatui +
tokio + `azure_core`/`azure_identity`, calling ARM REST directly). It is the
Azure sibling of neboto (`neboto/neboto-tui`, the AWS one) and was built by
**copying** neboto's provider-neutral modules, never depending on them
(ADR 0001). neboto is stable and is not touched to serve nebaz.

**Where else to look:**

| For | Read |
|---|---|
| What each service shows, its state rule, its links, its ARM call | [`docs/SERVICES.md`](docs/SERVICES.md) — **before editing `src/azure/services/<svc>.rs`** |
| What a service actually renders today | the service file itself; it is the reference |
| The ARM actions per service, the one role to assign | [`PERMISSIONS.md`](PERMISSIONS.md) |
| The project's own vocabulary (subscription, location, ARM id, Lazy, LazyStore, epoch, state ladder, Related section, guard…) | [`CONTEXT.md`](CONTEXT.md) |
| Why a design is the way it is | [`docs/adr/`](docs/adr) — 0001 copy-not-depend, 0002 scoping, 0003 auth |
| What `v0.1.0` is and is not | [`docs/SPEC-v0.1.md`](docs/SPEC-v0.1.md) |
| What is deliberately unbuilt | [`docs/BACKLOG.md`](docs/BACKLOG.md) |
| What came from neboto and what changed | [`docs/PORTED-FROM-NEBOTO.md`](docs/PORTED-FROM-NEBOTO.md) |
| How a release is cut, how users install | [`docs/RELEASING.md`](docs/RELEASING.md) |

Prefer a grep the reader can run over a count they have to trust.

## Commands

```bash
cargo build                         # debug
cargo run -- -s vm                  # needs `az login`; -s sub / rg / storage / vnet / kv / id / aks / acr / app / sql / foundry
cargo test                          # unit tests + the read-only guard (tests/readonly_guard.rs)
cargo test --test readonly_guard    # just the guard
cargo clippy --all-targets          # CI runs this; keep it clean
scripts/smoke.sh                    # offline pty run with a fake az (manual, not a CI gate)
```

## Architecture

**Event-driven async core** (`src/main.rs`, `src/event.rs`, `src/app.rs`):
one `App` owns all state; a tokio task per load sends `Event`s over a
channel (`ResourcesPartiallyLoaded` per page, `ResourcesLoaded` /
`FullyLoaded`, `ResourceLoadWarning`, `ResourceLoadError`, plus the one
**apply-closure event** every lazy fetch returns through). The draw loop
never blocks; `Ctrl-L` clears and repaints.

**Scoping** (ADR 0002): `subscription` is the `P` slot, the one thing the
app is pointed at; every list is subscription-wide. `location` is a
client-side `R` filter over rows already fetched, never a call scope;
`global` rows pass every filter (`Location::admits`).
Resource group is the `rg:` search token. The **ARM id** is the universal
key: row identity, portal link, cache and lazy key, the copied command's
argument.

**Auth** (ADR 0003, `src/azure/auth.rs`, `src/azure/arm.rs`):
`AzureCliCredential` (az CLI login) behind a `BearerTokenAuthorizationPolicy`,
**one pipeline per tenant** built on demand by `AzureClients`
(`src/azure/client.rs`). The `P` picker reads `az account list` across
tenants; choosing a subscription chooses its tenant. Not being logged in is
one app-wide status line (`AuthError`), never per-service errors.

**The ARM client** (`src/azure/arm.rs`): the single request constructor
(`get_request`, `Method::Get` only), `nextLink` paging (`list_pages`), and
`ReadOnlyPolicy`, which refuses any non-GET at runtime. Connection failures
name the host and the root cause.

**Service / Resource traits** (`src/azure/service.rs`, `src/azure/resource.rs`):
`ServiceType` is the tab strip and the routing prefixes; `JumpView` is the
sub-tab and `JumpView::for_arm_id` routes an ARM id to a view. `Resource`
is the row: `id`, `name`, `location`, `tags`, `state()` through the **state
ladder** (`state_ladder`, `provisioning_rung`), `related()` (the Related
section), `cli_command()`, `portal_url()`. `src/azure/services/mod.rs`
holds what every provider shares: `ArmBase` (the ARM envelope), the
`arm_row!` boilerplate, `Scope` (pipeline + current subscription, page
streaming, `finish_stream`), `overview_rows` / `related_rows` /
`lazy_list_rows`, and the `json` pointer readers.

**Sub-tabs** (`src/ui/widgets/subtab_bar.rs`): every sub-tab is one
subscription-wide list or flattened from one (embedded children). Lazy
children (containers, secret and key names) are sections on the parent,
never sub-tabs.

**Split detail pane** (`src/sections.rs`, `src/ui/widgets/details_pane.rs`):
each type declares a **section descriptor** (`*_SECTIONS` in its service
file: label + optional on-enter hook); digit keys, `Tab`, reset, snapshot
and flat view all derive from it. `App::section_lines_for` dispatches by
downcast to the type's `*_section_lines`. Every type has Overview first,
**Related** second to last, Tags last. `details_scroll` is the body's
line cursor (the pane scrolls to keep it visible); `detail_visual_anchor`
is the vim-style linewise selection (`V`, `J`/`K`, `Ctrl-A`; `y` copies
the range); `detail_flat_mode` (`\`, config `detail_flat`) renders every
section in one scroll with `━━ Name ━━` headers, digits and Tab jumping
between headers, and `App::flat_tick` firing every lazy section once per
focused resource.

**Lazy loading** (`src/lazy.rs`): `LazyStore` owns every `LazyMap`
(instance views, containers, vault secrets, vault keys) keyed by ARM id,
stamped with an **epoch**, and is replaced wholesale on subscription
switch. Triggering a present key is a no-op, so on-enter hooks may fire
repeatedly. `App::trigger_selected` is the one way to start a fetch.

**List cache** (`src/azure/cache.rs`): keyed `(service, subscription,
sub-tab)`, survives a subscription switch (switching back is instant),
untouched by a location change.

**Jumps**: the Related section is the only jump mechanism. `Enter` on an
ARM-id line → `jump_to_arm_id` → `NavLocation` (service, view,
subscription, selected id) → `restore_nav_location`, with `pending_jump`
resolving once the target list loads (lifting the location filter, with
a toast). Unbrowsed types copy the id instead.

**Copy** (`src/clipboard.rs`): OSC 52 to the terminal (tmux passthrough)
plus one long-lived arboard handle; `y` copies the id, `C` the `az`
command. Search (`src/search/`), macros (`src/macros.rs`), bookmarks,
export (`src/export.rs`), themes and `$EDITOR` are neboto's, ported
verbatim where the concept is unchanged.

## Adding a service or sub-tab

1. Decide with `docs/SERVICES.md` open: is the new type a subscription-wide
   list (sub-tab), an embedded child (sub-tab flattened from the parent's
   list, named `parent/child`, inheriting the parent's location) or a lazy
   child (a section on the parent, one call per parent)?
2. `ServiceType` / `JumpView` in `src/azure/service.rs`: the tab, the
   sub-tab, the routing prefix, the `for_arm_id` arm.
3. `src/azure/services/<svc>.rs`: the row struct via `ArmBase` +
   `arm_row!`, `from_json`, the state through `state_ladder`, `related()`,
   `cli_command()` (`show --ids` unless the command takes none), the
   `*_SECTIONS` descriptor, `*_section_lines`, and the `Service` impl using
   `Scope::stream` / `finish_stream`. Unit-test the row parse and the
   section labels.
4. `src/azure/client.rs`: register in `service(ServiceType)`.
5. `src/app.rs`: the `section_lines_for` downcast arm; a lazy section also
   needs a `LazyMap` in `src/lazy.rs`, a `trigger_*` fn and the on-enter
   hook.
6. Docs: the row in `docs/SERVICES.md` (catalog **and** call table), the
   action in `PERMISSIONS.md`, the build line in `README.md`. The
   read-only guard will tell you if the `az` verb or the path is wrong.

## Conventions & gotchas

- **Read-only, three layers** (`PERMISSIONS.md`): only `arm.rs` builds
  requests and only GETs; `tests/readonly_guard.rs` fails the build on a
  `Method::` elsewhere, an HTTP client crate, a data-plane host
  (`vault.azure.net`, `blob.core.windows.net`, …) in non-test code, an
  `az` literal without a read verb, or a non-`/read` action in
  `PERMISSIONS.md`; `Reader` at subscription scope is the whole RBAC
  requirement. Test fixtures may carry a `vaultUri`; live code may not.
- **State**: never a per-type state table. `state_ladder(provisioning,
  runtime)` and the native word lowercased as the label
  (`native_state_label`).
- **Partial failures**: a second-phase or lazy failure sends
  `ResourceLoadWarning` and keeps streaming; `ResourceLoadError` (fatal)
  only when nothing can stream. Sending the error mid-stream clears
  `loading` and drops every later page.
- **Errors** (`src/error.rs`): `From<azure_core::Error>` keeps the whole
  cause chain (`cause_chain`, `root_cause`); `AuthError::classify` only
  calls something an auth condition when the text says so (a transport
  "retry policy expired" is not a token expiry).
- **Colors** (`src/ui/theme.rs`): the palette is runtime-selected and
  read through accessors (`theme::accent()`, …). Never hardcode
  `Color::White` and friends for UI text; that is what breaks the light
  preset.
- **`is_noise()`** is a session-wide toggle (`a`); only mark a category
  noise when the non-noise subset is normally non-empty (today: only
  non-Enabled subscriptions).
- **Embedded children** (`SubnetRow`, `NodePoolRow`) expose the
  `parent/child` display name from `name()` (`#[allow(clippy::misnamed_getters)]`
  on purpose) and carry the parent's location.
- **`az` commands** are the name form for the `show` commands that take
  no `--ids` (`SERVICES.md` rule 9 lists them); every other row is
  `show --ids`. Check the CLI's parameter table (`id_part`) before
  assuming either.
  The app never runs a copied command; it runs `az account list` and, via
  azure_identity, `az account get-access-token`, nothing else.
- **Clipboard**: no `eprintln!` anywhere in the TUI path; arboard's
  dropped-handle warning over the raw terminal was a real rendering bug.
- **Copied files carry a one-line origin header**; the per-file table in
  `docs/PORTED-FROM-NEBOTO.md` is how a neboto fix gets ported deliberately.
  There is no sync.
- **Counts rot**: say "the list in `ServiceType`", not "twelve sub-tabs".

## Key files

| File | What |
|---|---|
| `src/app.rs` | all state, key handling, jumps, lazy triggers, `section_lines_for` |
| `src/main.rs` | terminal setup, draw loop, event dispatch |
| `src/azure/arm.rs` | the ARM client: the one GET constructor, paging, `ReadOnlyPolicy` |
| `src/azure/auth.rs` | CLI credential, `az account list`, `AuthError` |
| `src/azure/client.rs` | per-tenant pipelines, `service(ServiceType)`, lazy fetch builders |
| `src/azure/service.rs` | `ServiceType`, `JumpView`, routing prefixes, `for_arm_id` |
| `src/azure/resource.rs` | `Resource` trait, state ladder, ARM-id helpers, `scope_related` |
| `src/azure/services/mod.rs` | `ArmBase`, `arm_row!`, `Scope`, shared section builders, `json` |
| `src/azure/services/{subscriptions,compute,storage,network,network_edge,network_private,keyvault,identity,aks,container_registry,app_service,sql,foundry}.rs` | one file per service |
| `src/lazy.rs` | `Lazy`, `LazyMap`, `LazyStore`, epoch |
| `src/azure/cache.rs` | the list cache |
| `src/sections.rs` | section descriptors and the section index |
| `src/clipboard.rs` | OSC 52 + arboard |
| `tests/readonly_guard.rs` | the guard |
| `scripts/smoke.sh`, `scripts/smoke/` | the offline pty run and its fake `az` |

## Testing

Unit tests live next to the code (row parsing, section labels, the state
ladder, `for_arm_id`, the config example, auth classification, the
clipboard encoding). The read-only guard is an integration test under
`cargo test`. `scripts/smoke.sh` drives the binary in a pty with a fake
`az` and a dead endpoint and greps the screen (manual; needs python3).
There is no offline wiring harness yet (backlog). Live behaviour is
checked by hand on a machine with `az` (this dev machine has none):
`docs/SPEC-v0.1.md` carries the tour checklist.

## Permissions

nebaz is read-only. `PERMISSIONS.md` names the one role and the ARM action
per service; the guard keeps it honest.
