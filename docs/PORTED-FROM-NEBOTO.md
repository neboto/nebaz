# Ported from neboto

nebaz is a fresh repo that **copies** neboto's provider-neutral modules
(never depends on them — neboto is stable and is not rebuilt to serve
nebaz). There is no expectation of sync; when a fix in neboto matters here,
port it deliberately using this table. Every copied file starts with
`// ported from neboto-tui <path> @ <commit>`.

Source: `neboto/neboto-tui` @ `d483900` (v0.1.4), ported 2026-09-23.

## Copied verbatim (zero diff beyond the origin header)

| nebaz file | neboto file |
|---|---|
| `src/editor.rs` | `src/editor.rs` |
| `src/sections.rs` | `src/sections.rs` |
| `src/tui.rs` | `src/tui.rs` |
| `src/ui/layout.rs` | `src/ui/layout.rs` |
| `src/ui/mod.rs`, `src/search/mod.rs` | same |

## Copied with mechanical edits only (paths, `aws_orange` → `brand`, names, tests)

Safe to re-port by copying and re-applying the same renames.

| nebaz file | neboto file | edit |
|---|---|---|
| `src/cli.rs` | `src/cli.rs` | `--region/--profile` → `--location/--subscription` |
| `src/export.rs` | `src/export.rs` | `crate::aws` → `crate::azure`; `neboto-` file prefix and `NEBOTO_EXPORT_DIR` → `nebaz-` / `NEBAZ_EXPORT_DIR` |
| `src/search/fuzzy.rs` | `src/search/fuzzy.rs` | path |
| `src/search/query_parser.rs` | `src/search/query_parser.rs` | path; tests rewritten for the Azure prefixes |
| `src/bookmarks.rs` | `src/bookmarks.rs` | env var / path; tests rewritten (`NavLocation` no longer carries `EcsView` / S3 paths) |
| `src/ui/theme.rs` | `src/ui/theme.rs` | palette slot `aws_orange` → `brand` (Azure blue per preset); `"aws_orange"` still accepted as an override key |
| `src/ui/widgets/jump_list.rs`, `macro_picker.rs`, `message_log.rs`, `subtab_bar.rs`, `search_bar.rs` | same | `theme::aws_orange()` → `theme::brand()`; one hint string |
| `src/ui/widgets/service_selector.rs` | same | path; tests reference `Aks` / `KeyVault` |
| `src/ui/widgets/location_selector.rs` | `src/ui/widgets/region_selector.rs` | `Region` → `Location` throughout |
| `src/ui/widgets/banner.rs`, `splash.rs` | same | logo art, tagline, menu text |

## Copied with structural edits (the hidden AWS coupling)

Re-porting these means re-doing the cut; diff against the origin commit.

| nebaz file | neboto file | what was AWS-shaped |
|---|---|---|
| `src/event.rs` (185 lines, was 750) | `src/event.rs` | ~90 per-service `*Loaded` variants (metrics overlays, log tails, lenses, object/item browsers) that predate the apply-closure design; `RegionSwitchRequested` / `ProfileSwitchRequested` / org-role events → `LocationSwitchRequested` / `SubscriptionSwitchRequested`; `AccountInfoLoaded` → `SubscriptionInfoLoaded` |
| `src/lazy.rs` (166, was 823) | `src/lazy.rs` | `LazyStore` is 231 AWS-typed `LazyMap` fields (657 lines); the machinery (`Lazy`, `LazyMap`, epoch, `LazyApply`) is 160 lines and is what was kept |
| `src/azure/service.rs` (200, was 734) | `src/aws/service.rs` | 74-variant `ServiceType` with five string tables → 6 variants; `is_global()` → `is_tenant_scoped()`; `AwsService::execute_action` (unused write hook) dropped |
| `src/azure/resource.rs` (243, was 278) | `src/aws/resource.rs` | dropped `console_url(region)`, `trail_lookup_keys`, `security_group_ids`, `references`/`sg_refs`, `estimated_monthly_cost`, `cost_trend`, `available_actions` + `ResourceAction`/`ActionResult`; added `location()`, `resource_group()`, `portal_url()` (from the ARM id, no region arg) |
| `src/azure/cache.rs` (137, was 154) | `src/aws/cache.rs` | key `(service, region, variant)` → `(service, subscription, variant)`: location is a client-side filter, so a location switch never touches the cache; Cost 6h TTL special case dropped |
| `src/azure/location.rs` (137, was 124) | `src/aws/region.rs` | SDK `Region` conversions dropped; `All` is a first-class default; `admits()` implements the filter rule (rows without a location are never filtered) |
| `src/error.rs` (45, was 87) | `src/error.rs` | `sdk_error_message` + `From<SdkError>` are AWS-SDK-typed; `Error::AwsSdk` → `Error::Azure` (the `azure_core::Error` conversion arrives with auth) |
| `src/config.rs` (206, was 284) | `src/config.rs` | `default_region/profile` → `default_location/subscription`; AWS-only keys removed: `org_access_role(s)`, `controltower_audit_*`, `log_wrap`, `owner_tags`, `managed_by_tags`, `ownership_ribbon` |
| `src/macros.rs` (380, was 429) | `src/macros.rs` | steps `S3Object`, `AssumeRole`, `ExitRole` and their recorder checkpoints dropped; `SwitchRegion/Profile` → `SwitchLocation/Subscription` |
| `src/ui/widgets/resource_list.rs` (492, was 829) | same | downcasts to `R53Record` / `OrgScp` / `S3Bucket` / `InspResourceGroup`; 14 service-specific empty-state arms; S3 out-of-region dimming; Cost wide-column exclusion. Added one generic empty state: "No resources in <location> · N in other locations" |
| `src/ui/widgets/service_tabs.rs` (250, was 277) | same | badges read `aws_clients.current_assumed_role()` / `current_profile()` and `account_id/alias` → one subscription badge (`⦿ name (id)` degrading to `⦿ id`) |
| `src/ui/widgets/subscription_selector.rs` (242, was 267) | `src/ui/widgets/profile_selector.rs` | `list_profiles()` from the AWS client → `azure::client::list_subscriptions()`; the assume-role synthetic entries dropped |
| `src/ui/widgets/help_overlay.rs` (251, was 278) | same | key table listed AWS-only actions (console, CloudTrail lens, SSM session, S3 objects, secret reveal); now the Tier-1 set |

## Written fresh for nebaz (nothing copied)

| nebaz file | lines | neboto analog |
|---|---|---|
| `src/app.rs` | ~1950 | `src/app.rs` (30 233 lines, per-service) — same conventions: state only here, mutated only in `handle_event`/`handle_key`, widgets read `&App` |
| `src/main.rs` | 420 | `src/main.rs` (839) — run loop, `$EDITOR` teardown and status bar ported by hand; the 50-arm sub-tab router and lens overlays are not |
| `src/ui/widgets/details_pane.rs` | 263 | `src/ui/widgets/details_pane.rs` (42 408) — the `header | rule | tabs | rule | body` skeleton, `descriptor_tabs`, `style_detail_row` conventions, `spin_loading_row` |
| `src/azure/client.rs` | ~330 | `src/aws/client.rs` (957, entirely AWS SDK / STS / profile-file code) — `az account list` subscription table, one `ArmClient` per tenant built on demand, startup subscription resolution (ADR 0003) |
| `src/azure/auth.rs` | ~360 | `src/aws/client.rs` (credential half) — `CredentialSource`, the classifying/timeout `TokenCredential` wrapper, `AuthError`, `az account list` parsing |
| `src/azure/arm.rs` | ~230 | `src/aws/pagination.rs` (in spirit) — the one `GET` constructor, `nextLink` paging, the `{endpoint}//.default` scope |
| `src/azure/services/mod.rs` | ~420 | `src/aws/services/mod.rs` — plus what every Azure provider shares: `ArmBase` (the ARM envelope), the `arm_row!` boilerplate, `Scope` (pipeline + subscription, page streaming), `json` pointer readers |
| `src/azure/services/subscriptions.rs` | ~620 | `src/aws/services/organizations.rs` (in spirit) — subscription rows from the CLI list, resource groups from ARM, streamed per page |
| `src/azure/services/compute.rs` | ~990 | `src/aws/services/ec2.rs` (instances, volumes, ENIs) — VMs with the `statusOnly=true` power-state pass, disks, NICs |
| `src/azure/services/storage.rs` | ~380 | `src/aws/services/s3.rs` (buckets) — storage accounts, lazy containers |
| `src/azure/services/network.rs` | ~790 | `src/aws/services/vpc.rs` + the EC2 security-group rows — VNets, embedded subnets, NSGs with rule tables |
| `src/azure/services/keyvault.rs` | ~450 | `src/aws/services/kms.rs` (in spirit) — vault metadata, lazy secret/key names through ARM |
| `tests/readonly_guard.rs` | ~230 | `scripts/check-readonly.py` — a Rust integration test instead of Python: GET-only constructor, no data-plane host, `az` verbs, `PERMISSIONS.md` actions |
| `PERMISSIONS.md` | — | `PERMISSIONS.md` — one built-in role (`Reader`) instead of an IAM action list per service; actions listed for a custom role |
| `.github/workflows/ci.yml`, `.github/PULL_REQUEST_TEMPLATE.md` | — | copied; the guard step is gone because the guard runs inside `cargo test` |
| `.github/workflows/release.yml`, `install.sh`, `docs/RELEASING.md`, `.github/dependabot.yml`, `.github/rulesets/*.json`, `config.example.toml` | — | copied and renamed (ticket 08); the private-repo knobs (`RELEASE_ON_CI`, `BUILD_MACOS`, `scripts/release-local.sh`) are dropped because nebaz is public; the example config carries the Azure keys (`auth`, `endpoint_url`, `default_subscription`, `default_location`) |
| `src/azure/services/aks.rs` | ~680 | `src/aws/services/eks.rs` — clusters, embedded node pools |

## Not ported (deliberately)

- `src/aws/pagination.rs` — AWS `next_token` stop rules; ARM paging is `nextLink` through `azure_core::http::Pager`.
- `src/aws/document.rs` — `aws_smithy_types::Document` conversion.
- `src/ownership.rs`, `src/references.rs`, `src/timeline.rs`, `src/terraform.rs`, `src/html.rs` — ownership ribbon, refs lens, change timeline, Terraform state, HTML export: each needs its own Azure design (see the map's fog).
- `src/harness_tests/` — layer-2 harness; nebaz gets its own once a real service exists.
- Every `src/aws/services/*.rs` and `src/ui/widgets/*_tabs.rs`, `metrics_overlay.rs`, `log_tail.rs`, `*_lens.rs`, `*_browser.rs`, `*_modal.rs`.

## Copied but not yet wired (dead-code warnings at build)

`parse_all_query` (`@all` cross-service search), `export_detail_multi` /
`multi_detail_csv` (deep export over a list selection). Each is a Tier-1
or fog feature ticket 09 decides on; the warnings are the to-do list.
`subtab_bar`, `AppLayout::sub_tabs_area` and `shell_quote` lit up with the
sub-tab model and the Subscriptions service; `native_state_label` with the
catalog's state ladder.
