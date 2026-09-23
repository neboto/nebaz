# nebaz v0.1.0 — first-release spec

The destination artifact of the wayfinder map that planned nebaz
(`.scratch/nebaz/map.md`, charted and worked 2026-09-23 to 2026-09-24).
It says what `v0.1.0` **is**, what it deliberately **is not**, what must be
true before the tag is cut, and the work left in between. It points at the
documents that hold each decision instead of restating them; those move,
this page does not.

## What v0.1.0 is

A read-only Azure resource browser TUI for six services, authenticated
through the Azure CLI, installable as a prebuilt binary on Linux and macOS,
with a mechanically enforced read-only guarantee. It is the Azure sibling
of neboto, built by copying neboto's provider-neutral core (ADR 0001) and
inheriting its vocabulary, keys and conventions wherever the concept is
unchanged.

| Decision | Where it lives |
|---|---|
| Fork shape: copy, never depend; no sync with neboto | [ADR 0001](adr/0001-copy-not-depend-on-neboto.md), [`PORTED-FROM-NEBOTO.md`](PORTED-FROM-NEBOTO.md) |
| Scoping: subscription is the `P` slot, location a client-side `R` filter, `rg:` a query token, ARM id the universal key | [ADR 0002](adr/0002-subscription-scoped-lists-location-as-filter.md), [`CONTEXT.md`](../CONTEXT.md) |
| Auth: `az login` only, one pipeline per tenant, one app-wide auth line, `endpoint_url` for sovereign clouds | [ADR 0003](adr/0003-azure-cli-credential-per-tenant.md) |
| The six services: sub-tabs, sections, state ladder, Related links, `az` commands, ARM calls | [`SERVICES.md`](SERVICES.md) |
| Read-only: GET-only constructor + runtime policy, the guard test, `Reader` at subscription scope | [`PERMISSIONS.md`](../PERMISSIONS.md), `tests/readonly_guard.rs` |
| Release: four targets, attested archives, installer, binstall, runbook | [`RELEASING.md`](RELEASING.md) |
| Vocabulary | [`CONTEXT.md`](../CONTEXT.md) |
| Architecture and conventions for agent sessions | [`CLAUDE.md`](../CLAUDE.md) |

### Services

Subscriptions + Resource Groups · Virtual Machines (+ Disks, NICs; power
state on the row) · Storage Accounts (+ blob containers, lazy) · Virtual
Networks (+ Subnets, NSGs) · Key Vault (metadata plus secret and key
*names*, never values) · AKS (+ Node pools). Every row has a Related
section; Enter on an ARM id jumps to it across services, subscriptions
and tenants.

### Features (Tier 1, as shipped)

Split detail pane with lazy sections (`Tab`, digits) · `@service` and
sub-tab routing prefixes (`@vm`, `@disk`, `@nsg`, …) · fuzzy search with
`rg:` and `tag:` filters · pickers `S` / `R` / `P` · sort, state filter
(`F`), noise toggle (`a`) · bookmarks, jump list, history · export
(`X` / `^X`) · themes and `[theme_colors]` · macros · `$EDITOR` · copy id
(`y`) and `az` command (`C`) via OSC 52 and the system clipboard · open
in portal (`O`) · watch mode (`w`) · message history (`M`) · `Ctrl-L`
repaint. The help overlay (`?`) is the reference for keys.

### Runtime requirement, one line for users

Azure CLI ≥ 2.54.0, logged in. Assign the built-in **`Reader`** role at
subscription scope; nothing else, no vault access policy.

## What v0.1.0 is not

Everything in [`BACKLOG.md`](BACKLOG.md): `@all` cross-service search and
list visual selection (copied from neboto, not wired, code removed), the
ownership ribbon analog, a Storage watch floor, sovereign-cloud
auto-detect, an emulator mode, Windows, every Tier 2 rich view and Tier 3
lens, Key Vault certificates, an offline wiring harness. Any Azure write
action is out of scope for the product, not just the release.

## Acceptance: what must be true before the tag

Done (2026-09-24, on `main`):

- [x] all six services real; the stub is gone
- [x] the read-only guard passes and CI runs it (`cargo test --locked`)
- [x] the build is warning-free; dead code from unwired neboto features
      removed
- [x] `PERMISSIONS.md`, `SERVICES.md`, `BACKLOG.md`, `CLAUDE.md`,
      `CONTEXT.md`, this spec
- [x] release workflow dry run green on all four targets; archive layout,
      checksum and provenance verified
- [x] `scripts/smoke.sh` passes offline (fake `az`, dead endpoint)

Still to do, in order:

1. **Live tour on the Azure machine** (the only machine with `az`), one
   session. Walk every sub-tab and every lazy section in one subscription,
   then:
   - [ ] VM: power state on rows; Instance view; Networking and Storage
         sections; Enter on a NIC line jumps to NICs
   - [ ] Disks, NICs: attachment states read as `attached` /
         `unattached`
   - [ ] Storage: Security section; Containers lazy section lists names
   - [ ] VNets: embedded subnets on both the section and the Subnets
         sub-tab, named `vnet/subnet`, filtered by the parent's location
   - [ ] NSGs: custom rules before default rules; Used by
   - [ ] Key Vault: Access, Network; Secrets and Keys list names only;
         `C` copies the name-form command
   - [ ] AKS: cluster Network / Access / Add-ons; Node pools sub-tab;
         **rule 8**: embedded profiles carry autoscale and power (else
         add the lazy Detail section)
   - [ ] jump from a Related line into another subscription in another
         tenant; the toast, the location filter lift
   - [ ] `P` switch and back is instant (cache), lazy data is gone
         (LazyStore replaced)
   - [ ] `O` opens the tenant-qualified portal link; `C` on every type
         runs unmodified in a shell
   - [ ] watch mode on Accounts for five minutes at the 5 s preset:
         no 429
   - [ ] not logged in (`az logout`): the one status line, `R` retries
         after `az login`
   Fix what the tour finds, on `main`, as ordinary commits.
2. **Repo hardening**, seven API calls from the checklist in
   `RELEASING.md` (everything except the branch ruleset): private
   vulnerability reporting, secret scanning and push protection, fork-PR
   approval, immutable releases, tag protection, Dependabot security
   fixes, SHA-pinned actions. They were prepared on 2026-09-24 but not
   applied (the agent session lacked permission); run them by hand.
3. **Cut `v0.1.0`**: `cargo set-version 0.1.0`, commit "Release v0.1.0",
   tag, push; watch the workflow; `gh release view v0.1.0`; run
   `install.sh` on the Azure machine and start the installed binary.
4. **Publish to crates.io** the same day (`cargo publish`, manual, needs
   a crates.io token) so `cargo install nebaz` and plain
   `cargo binstall nebaz` work; then update the install table in
   `RELEASING.md` and `README.md`.

After the tag: apply the branch ruleset and move to branch → PR → CI →
squash merge; record a demo GIF against a real subscription with nothing
sensitive on screen; open the backlog as a new effort.

## Build plan, sized in agent sessions

| Session | Work | Machine |
|---|---|---|
| 1 | the live tour above, fixing as it goes; record results in `SERVICES.md` "Verified live" | the Azure machine |
| 2 (short) | hardening calls, version bump, tag, watch the release, install check, `cargo publish` | any, with `gh` and a crates.io token |

Everything else the map's tickets listed as "build sessions" was built
off-map while the map was worked: the skeleton and Subscriptions service
(after tickets 04 and 05), the five remaining services (after 06), the
guard, policy and CI (after 07), the release pipeline (after 08). The map
ends with this spec.
