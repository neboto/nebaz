# 02 — Skeleton sizing prototype

Type: prototype
Status: resolved
Blocked by: —
Map: ../map.md

## Question

How big is neboto's provider-neutral skeleton, and which "neutral" modules
turn out to have hidden AWS coupling?

Build the crate **in place** at `~/work/nebaz` (this directory — already
`git init`ed, it is the future repo): `cargo init --name nebaz`, copy the modules the charting grill listed as neutral (event loop /
`event.rs`, `lazy.rs`, `sections.rs`, `search/`, `macros.rs`, `bookmarks.rs`,
`export.rs`, `ui/theme.rs`, `ui/layout.rs`, `ui/widgets/resource_list.rs`,
`ui/widgets/subtab_bar.rs`, `editor.rs`, `tui.rs`, `config.rs`, `cli.rs`, plus
the generic pickers / help / message log / splash / jump list / macro picker
widgets), a `Resource` + `Service` trait pair with the AWS-specific methods
stripped, a stub provider that lists one hard-coded resource type, and a
minimal `App` + `details_pane` with one `sections!` pane. Get `cargo build`
green.

Report back:
- line count of the copied skeleton vs. the new `App` / `details_pane`;
- every copied file that needed an edit, and why (that is the hidden coupling
  list — it feeds the "ported from neboto" table);
- which `Resource` trait methods are AWS-shaped (`security_group_ids`,
  `trail_lookup_keys`, `cli_command`, `console_url(region)`) and what the
  Azure-neutral form should be.

The prototype is *not* thrown away: once `cargo build` is green and the
report is written, it is committed as the initial commit (each copied file
headed `// ported from neboto-tui <path> @ <commit>`). Its findings seed
ticket 04; ticket 03 pushes the commit to the org.

## Answer

Resolved 2026-09-23. The skeleton is built in place, `cargo build` is green,
66 unit tests pass, and a pseudo-terminal run confirms the stub rows render,
the lazy Details section fires through `Event::Lazy` and lands, `@kv`
switches service, and the pickers/help open. Committed as the initial
commit of `~/work/nebaz` (the crate only; `.scratch/` stays untracked for
ticket 03 to decide). The full per-file table lives in the repo at
[`docs/PORTED-FROM-NEBOTO.md`](../../../docs/PORTED-FROM-NEBOTO.md) — that
file *is* the "ported from neboto" table ticket 09 folds into CLAUDE.md.

### Sizes

| | files | lines |
|---|---|---|
| Copied skeleton, as copied from neboto @ d483900 | 34 | 9 790 |
| Copied skeleton after the cuts | 34 | 7 232 |
| New: `App` (`src/app.rs`) | 1 | ~1 950 |
| New: `details_pane.rs` | 1 | 263 |
| New: `main.rs` (run loop + status bar hand-ported), client stub, stub provider, mod files | 6 | ~690 |
| **New total** | 8 | **~2 900** |

Copied-to-new ratio is roughly 2.5:1. Six copied files needed zero edits
(`editor`, `sections`, `tui`, `ui/layout`, two `mod.rs`); the rest split
into mechanical renames and structural cuts, below.

### Hidden coupling: every copied file that needed an edit, and why

**Structural (the charting list called these "neutral"; they are not at the
file level):**

- `event.rs` 750→185: ~90 per-service `*Loaded` variants predating the
  apply-closure design, plus region/profile/org-role events. Kept 16.
- `lazy.rs` 823→166: `LazyStore` is 231 AWS-typed map fields; the mechanism
  is 160 lines.
- `aws/service.rs` 734→200: 74-variant `ServiceType` with five string
  tables; `execute_action` (unused write hook) dropped.
- `aws/resource.rs` 278→243: see the trait analysis below.
- `aws/cache.rs`: key `(service, region, variant)` → `(service, subscription,
  variant)` — location is a client-side filter so a location switch must
  not refetch (this is also what protects the Storage RP's 100-list-calls
  per 5 min budget). `is_global()` → `is_tenant_scoped()`.
- `aws/region.rs` → `azure/location.rs`: SDK conversions dropped; `All`
  became a first-class default; `admits()` encodes ticket 01's rule (rows
  with no location of their own are never filtered).
- `error.rs` 87→45: `SdkError` message extraction and `From<SdkError>` are
  SDK-typed.
- `config.rs` 284→206: region/profile fields; six AWS-only keys (org roles,
  Control Tower audit account, log wrap, ownership tags).
- `macros.rs` 429→380: `S3Object` / `AssumeRole` / `ExitRole` steps and
  their state-diff checkpoints.
- `resource_list.rs` 829→492: downcasts to four AWS types, 14
  service-specific empty-state arms, S3 out-of-region dimming, Cost wide
  exclusion. Gained one generic arm for "everything filtered out by
  location".
- `service_tabs.rs`: badges read the AWS client's assumed role / profile
  and the account id/alias → one subscription badge.
- `profile_selector.rs` → `subscription_selector.rs`: `list_profiles()`
  from the AWS client; assume-role synthetic entries.
- `help_overlay.rs`: the key table itself lists AWS-only actions.

**Mechanical (sed-able; safe to re-port by copy + rename):** `cli.rs`,
`export.rs` (only branding: `neboto-` file prefix, `NEBOTO_EXPORT_DIR`),
`search/fuzzy.rs`, `search/query_parser.rs` (tests), `bookmarks.rs`
(tests + env var), `theme.rs` (palette slot `aws_orange` → `brand`, used by
nine widgets), `region_selector.rs` (type rename), `banner.rs` / `splash.rs`
(art, wording), `service_selector.rs` (tests), and the one-line
`theme::brand()` edits in `jump_list`, `macro_picker`, `message_log`,
`subtab_bar`, `search_bar`.

**Not on the charting list but required:** `error.rs`, `aws/resource.rs`,
`aws/service.rs`, `aws/cache.rs`, `aws/region.rs`, `banner.rs`,
`search_bar.rs`, `service_tabs.rs`, `service_selector.rs`. **Not ported at
all:** `aws/client.rs` (957 lines, entirely SDK/STS/profile parsing),
`aws/pagination.rs`, `aws/document.rs`, `ownership.rs`, `references.rs`,
`timeline.rs`, `terraform.rs`, `html.rs`, `harness_tests/`.

### `Resource` trait: which methods are AWS-shaped, and the Azure-neutral form

Implemented in the skeleton as a proposal; **ticket 04 decides**.

- `console_url(&self, region)` → `portal_url(&self)`. A portal deep link is
  a pure function of the ARM id (`https://portal.azure.com/#@/resource{id}`),
  so it needs no region argument and gets a default from `id()`; override
  only for rows without an ARM id. Tenant-qualified form
  (`#@{tenant}/resource{id}`) is possible once the tenant is known.
- `cli_command()` → kept, `az … --ids {id}` form; the app appends
  `--subscription`. Same read-only rule (Key Vault maps to `secret list`,
  never `secret show`).
- `trail_lookup_keys()` → dropped. The Activity Log analog filters by
  `resourceId eq '{id}'`, so the ARM id is the only key and no per-type
  override exists; a Tier-3 lens takes `id()` directly.
- `security_group_ids()` and `references()` (whose default was
  `sg_refs(...)`) → dropped. NSG associations hang off subnets and NICs, not
  off "any resource with a security_groups field"; a Tier-3 access lens
  derives them from the network module's own model, and reference labels
  are derivable from an ARM id's provider/type segments.
- Added `location() -> Option<&str>`: what the `R` filter keys on; `None`
  for subscription/RG rows and child resources (subnets, containers, node
  pools), which are never filtered out.
- Added `resource_group() -> Option<&str>`: default parses the id
  (case-insensitive); drives the RG filter chip.
- Dropped as unused even in neboto: `estimated_monthly_cost`, `cost_trend`,
  `available_actions` + `ResourceAction` / `ActionResult`, and
  `AwsService::execute_action`.
- `id()` is the full ARM id everywhere it exists — the universal jump key,
  portal source and cache/lazy key.

### Other things the build surfaced (inputs to later tickets)

- `Location` is a static enum like neboto's `Region` (24 entries + `All`).
  The real list is per-subscription (`GET /subscriptions/{id}/locations`);
  whether the picker is fed from the API is ticket 04's call. The macro
  shape survives either way.
- `AzureClients::list_subscriptions()` is empty: `az account list` vs the
  ARM subscriptions endpoint is ticket 05's call; the `P` picker shows an
  empty-state hint until then.
- Watch-mode presets were shifted to `15/30/60/120/300s` (neboto: 5–300s)
  as a placeholder for the throttling decision in the fog.
- The copied `JumpView` collapsed to a single `None` variant: every
  per-service view enum is catalog work (ticket 06), and the sub-tab bar
  is copied but unused until one exists.
- 15 dead-code warnings remain on purpose: they are the copied Tier-1
  hooks not yet wired (sub-tab bar, `@all` search, deep multi-export,
  `shell_quote`, `native_state_label`) — listed at the end of
  `docs/PORTED-FROM-NEBOTO.md`.
