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
| `src/ui/widgets/network_lens.rs` | `src/ui/widgets/access_lens.rs` @ `456eb70` | the merged security-group table + subnet NACLs became NSG layers (subnet then NIC) in Azure's priority order; the evaluation moved to `src/azure/nsg_eval.rs` (fresh); the state, the `t` direction cycle, the header / body / footer layout and the keys are neboto's |
| `src/ui/widgets/help_overlay.rs` (251, was 278) | same | key table listed AWS-only actions (console, CloudTrail lens, SSM session, S3 objects, secret reveal); now the Tier-1 set |
| `src/harness_tests/mod.rs` (#46, from neboto `ae78599`) | `src/harness_tests/mod.rs` | `AwsClients::new_for_test` + `build_services` → `AzureClients::new_for_test` (fixture subscriptions, an offline credential that never yields a token); neboto's free functions (`select_mock`, `check_section_invariants`) → a `Harness` driver that runs `main`'s loop pass and lands rows as load-stream events; the 166-mock `mocks_*` batches → one `mocks.rs` built through `from_json` |
| `src/harness_tests/load_stream_test.rs` (#46, from `ae78599`) | same | profile/region switch → subscription switch and sub-tab switch; the load-task abort case is not ported (nebaz does not track the task yet) |

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
| `CLAUDE.md`, `docs/SERVICES.md` | — | same names and shape as neboto's; written fresh for nebaz (ticket 09), the catalog promoted from the map |
| `scripts/smoke.sh`, `scripts/smoke/` | — | no neboto equivalent (neboto has an in-crate harness and an emulator); a pty run with a fake `az` |
| `src/azure/services/aks.rs` | ~680 | `src/aws/services/eks.rs` — clusters, embedded node pools |

## neboto fixes ported later

| nebaz change | neboto commits | what |
|---|---|---|
| `src/search/fuzzy.rs`; `subscription_selector.rs`, `service_selector.rs`, `location_selector.rs` (#59) | `df76264`, `fd548fe` | `filter_fields` (best field scores, an exact any-case match on any field floats), the threshold counts characters, the query is trimmed; the `P`, `S` and `R` pickers fuzzy-filter through it, `P` and `R` cache `filtered()` per query. Not taken: `filter_strings`, since no nebaz picker filters a single field (its tests call `filter_fields` with one), and `filter_resources`' exact id/name float (`dde77e1`, an `@audit` change) |
| `Resource::list_summary` (`src/azure/resource.rs`, the service rows); `/` search history, the `⌫ back to …` footer hint, the history fixes (`src/app.rs`, `details_pane.rs`); `pinned_services` (`src/config.rs`); `src/harness_tests/list_ux_test.rs` (#58) | `3183ba1` | `list_summary` fills the list's dim second column from fields the row already carries; nebaz's existing `list_cell` stays the column's one renderer and now reads it (All resources' type moves onto it). ↑/↓ walk this session's submitted queries (de-duplicated, capped at 50, the draft restored). The detail footer names where `⌫` goes and says `h list`; `⌫` walks history from the list and, when there is history, the detail pane. A parked history entry is replaced by the place being left, and a `@service` query records as no filter. nebaz also gains a guard neboto already had: a restore's own switches record nothing (they bounced Ctrl-O). Not taken: Ctrl-F forward, `park_here`, and the clickable hints (nebaz has no `click_regions` on the detail footer yet) |

## Not ported (deliberately)

- `src/aws/pagination.rs` — AWS `next_token` stop rules; ARM paging is `nextLink` through `azure_core::http::Pager`.
- `src/aws/document.rs` — `aws_smithy_types::Document` conversion.
- `src/ownership.rs`, `src/references.rs`, `src/timeline.rs`, `src/terraform.rs`, `src/html.rs` — ownership ribbon, refs lens, change timeline, Terraform state, HTML export: each needs its own Azure design (see the map's fog).
- `src/harness_tests/` per-service tests (`*_test.rs` beyond `load_stream_test.rs`) — AWS panes; nebaz's `wiring_test.rs` and `navigation_test.rs` are written fresh against the ported driver.
- Every `src/aws/services/*.rs` and `src/ui/widgets/*_tabs.rs`, `metrics_overlay.rs`, `log_tail.rs`, `*_lens.rs`, `*_browser.rs`, `*_modal.rs`.

## Copied but not wired, then removed

`parse_all_query` (`@all` cross-service search) and `export_detail_multi`
/ `multi_detail_csv` (deep export over a list selection) were copied, never
wired, and removed for `v0.1.0` (ticket 09) so the build is warning-free;
they are in git history and tracked as #38 and #39. `subtab_bar`,
`AppLayout::sub_tabs_area` and `shell_quote` lit up with the sub-tab model
and the Subscriptions service; `native_state_label` with the catalog's
state ladder.
