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
| `src/export.rs` | `src/export.rs` | `crate::aws` → `crate::azure`; `neboto-` file prefix and `NEBOTO_EXPORT_DIR` → `nebaz-` / `NEBAZ_EXPORT_DIR`; re-ported at `03760c0` without `detail_text` and the `--regions` variants (headless `neboto get` / `ls`), see below |
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
| `src/ui/widgets/metrics_overlay.rs` (#51) | `src/ui/widgets/metrics_overlay.rs` @ `03760c0` | ~40 per-kind CloudWatch renderers and their `*MetricsState`s → one renderer over `azure::metrics::MetricSeries` (a line per metric with a sparkline and last / min / max / avg, the selected one charted); kept: the range chrome and `[`/`]`, `spark_line`, the braille value chart, `MetricsTimeRange` (→ `MetricWindow`, grains per Azure), `Z` full width. The change markers, dashboards and alarm thresholds are not ported |
| `src/azure/cli_actions.rs` (#47) | `src/aws/cli_actions.rs` @ `343ef65` | AWS catalogues on each `Resource::cli_actions()` → one Azure catalogue file dispatched by downcast (the guard's one Connect / Change exception, ADR 0005); `--region/--profile/--endpoint-url` suffix dropped (`--ids` carries the subscription, the name form `--subscription`); org-role gate and visual-selection batching dropped; tiers, ordering and the catalogue rules are neboto's |
| `src/ui/widgets/command_picker.rs`, `src/app/command_picker.rs` (#47) | `src/ui/widgets/cli_picker.rs`, `src/app.rs` (`copy_cli_command`, `handle_cli_picker_key`) @ `343ef65` | picker state moved into the widget; a `/` fuzzy filter (`filter_fields`); previews cut by character; the mouse through #42's modal path (`Modal::Commands`, rows recorded by wrapped height as neboto's `record_hits` did; a click outside or a right-click closes outright, past a filter); the disabled-row gate dropped |
| `src/harness_tests/command_picker_test.rs` (#47) | `src/harness_tests/cli_picker_test.rs` @ `343ef65` | Azure rows; filter, digit and Esc cases; no batch or role cases |
| `src/azure/timeline.rs`, `src/ui/widgets/timeline_lens.rs`, `src/app/timeline.rs` (#52) | `src/timeline.rs`, `src/ui/widgets/trail_lens.rs`, `src/app.rs` (`seed_trail_lens`, the lens keys) @ `ee8eb89` | Six AWS sources (CloudTrail, alarms, CloudFormation, ECS, Auto Scaling, RDS) → four Azure ones (the Activity Log, Resource Health, fired alerts, ARM deployments), each one task through the apply-closure event under a generation instead of `TrailLensLoaded` / `TrailLensAux`; `[`/`]` step 7d / 30d / 90d; `a` is "every operation" (the Activity Log has no reads to add); rows keep named fields for `$EDITOR` (no raw JSON). Kept: the row model (`TimelineRow`, badge, `failed`), the per-source lists merged newest first, the primary source's error slot vs dim notes, `f`, the header / counts / body / footer layout. Not taken: the ownership line (nebaz has no ownership resolver yet) |
| `src/azure/services/changes.rs`, `src/app/changes.rs`, `src/harness_tests/changes_test.rs`, `docs/adr/0006-changes-is-a-fetching-service.md`, `nebaz changes` in `src/headless.rs` / `src/cli.rs` (#61) | `src/aws/services/changes.rs`, `src/harness_tests/changes_test.rs`, `docs/adr/0007-changes-is-a-fetching-service.md` @ `08fcd0c`; `changes --since` from neboto-tui#256 | Six AWS sources → three Azure ones (the subscription's Activity Log, the deployments of the groups it names, Resource Health), streamed per source, failures as warnings, the Activity Log capped at 10 pages with the "back to …" warning; `ChangesWindow` kept (15m … 7d, `[`/`]`), its cache variant now the list's whole identity because nebaz sub-tabs are `JumpView`s (the sub-tabs filter one list in `update_search`, neboto's `ChangesView`); noise is the caller's kind from Microsoft Graph instead of `invokedBy` / session churn; rows are `TimelineRow`s (shared with `W`), Overview + Related. Not taken: Config, CloudFormation, CodePipeline / CodeBuild, Auto Scaling, RDS, the us-east-1 IAM lookups, demo data |
| `src/ui/widgets/help_overlay.rs` (251, was 278) | same | key table listed AWS-only actions (console, CloudTrail lens, SSM session, S3 objects, secret reveal); now the Tier-1 set |
| `src/harness_tests/mod.rs` (#46, from neboto `ae78599`) | `src/harness_tests/mod.rs` | `AwsClients::new_for_test` + `build_services` → `AzureClients::new_for_test` (fixture subscriptions, an offline credential that never yields a token); neboto's free functions (`select_mock`, `check_section_invariants`) → a `Harness` driver that runs `main`'s loop pass and lands rows as load-stream events; the 166-mock `mocks_*` batches → one `mocks.rs` built through `from_json` |
| `src/headless.rs`, `src/headless/tests.rs`, `src/headless/contract_tests.rs`, `src/headless/contract.json` (#44, from `08fcd0c`) | same | `services` / `ls` / `get` kept, with neboto's `Failure`, `pump`, `--section` / `--wait` and the contract test; `get` routes ARM and `graph:/` ids with `JumpView::landing_for_arm_id` (no service argument; names need `--in`) and selects by id; `ls` drives the headless `App` too, so its filters are the TUI's `update_search` (`-f` with `rg:` / `tag:`, `-r` location); table and CSV output, `--regions`, `--type` and `audit` dropped; auth is its own exit code (4); demo data → the harness mocks |
| `src/app/headless.rs` (#44, from `08fcd0c`) | `src/app.rs` (the `headless (neboto get)` block) | `new_headless` / `headless_find` / `headless_select` / `headless_section_labels` / `headless_capture` moved into a submodule; selection by sub-tab + id instead of `align_view_to_resource_type`; capture also fires the principal-name follow-ups, which nebaz starts from the selection; `headless_rows` added for `ls` |
| `src/cli.rs` subcommands, `skills/nebaz/SKILL.md` (#44, from `08fcd0c`) | `src/cli.rs`, `skills/neboto/SKILL.md` | `Command` / `LsArgs` / `GetArgs` / `OutputFormat` (json, md); `-p` / `-r` / `--endpoint-url` global; the skill rewritten for ARM ids, prefixes and the exit codes, its examples parse-checked |
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
| `src/export.rs`, `src/app/export.rs`, `src/harness_tests/export_test.rs`, `src/config.rs` (#40) | `bcfb8d1`, `feb0ebe`, `6b03ab1` (neboto-tui#192, #191, #38) | `X` arms a wait instead of refusing: every section's on-enter hook fires, the files are written once nothing reads `Loading…` (a single `Loading…` row, or Access's "principal names are loading" footer, counts), 2-minute limit, `Esc` cancels; nebaz also cancels on a subscription or service switch. JSON / CSV / Markdown of one resource all come from the captured sections (`detail_json`, long `ID,Section,Key,Value` CSV, which writes `(not loaded)` where neboto skipped the section); the list Markdown shares `list_columns` with the CSV. Stable section JSON keys (arrays for repeats, counts dropped from group names, indented rows nested), key hints stripped. `export_formats` / `export_dir` config. Not taken: `detail_text` and the region columns (headless CLI) |
| `src/app/list_visual.rs`, `src/app/export.rs`, `src/export.rs`, `src/harness_tests/list_visual_test.rs` (#39) | the list visual selection and deep export @ `03760c0` (`bcfb8d1`, neboto-tui#192) | List-pane `V` / `J` `K` / Shift-↓↑ / `Ctrl-A` / left-drag, positional over `filtered_resources` and cleared by `update_search` and a drill-in; `y`/`c` copy `list_markdown`, `Ctrl-X` shallow-exports the rows, `X` arms the export wait over every selected row (by id, capped at 50) and writes `export_detail_multi`'s combined `-deep-` trio. The walk fires nebaz's section descriptors per row rather than neboto's reset+cycle sweep. Watch mode is not wired in nebaz, so nothing to hold off. Not taken: neboto's `list_selection_side_effects` (nebaz has no list-nav triggers) |
| `src/search/fuzzy.rs`; `subscription_selector.rs`, `service_selector.rs`, `location_selector.rs` (#59) | `df76264`, `fd548fe` | `filter_fields` (best field scores, an exact any-case match on any field floats), the threshold counts characters, the query is trimmed; the `P`, `S` and `R` pickers fuzzy-filter through it, `P` and `R` cache `filtered()` per query. Not taken: `filter_strings`, since no nebaz picker filters a single field (its tests call `filter_fields` with one), and `filter_resources`' exact id/name float (`dde77e1`, an `@audit` change) |
| `Resource::list_summary` (`src/azure/resource.rs`, the service rows); `/` search history, the `⌫ back to …` footer hint, the history fixes (`src/app.rs`, `details_pane.rs`); `pinned_services` (`src/config.rs`); `src/harness_tests/list_ux_test.rs` (#58) | `3183ba1` | `list_summary` fills the list's dim second column from fields the row already carries; nebaz's existing `list_cell` stays the column's one renderer and now reads it (All resources' type moves onto it). ↑/↓ walk this session's submitted queries (de-duplicated, capped at 50, the draft restored). The detail footer names where `⌫` goes and says `h list`; `⌫` walks history from the list and, when there is history, the detail pane. A parked history entry is replaced by the place being left, and a `@service` query records as no filter. nebaz also gains a guard neboto already had: a restore's own switches record nothing (they bounced Ctrl-O). Not taken: Ctrl-F forward, `park_here`, and the clickable hints (they came with #42) |
| `src/app.rs` (`filter_detail_rows`, `detail_body`, `detail_group_jump`, `step_sub_tab`), `src/ui/widgets/details_pane.rs` (`layout_body`, `wrap_styled_line`, `first_visible_row`) (#41) | `c814b26`, `9cbaa41`, `40b402f`; `filter_detail_rows` and the bracket jumps as of `7330ba4` | the `/` body filter (group-aware, a flat match keeps its `━━` header), `[[`/`]]` group-header jumps, `Ctrl-W` wrap (config `detail_wrap`), `H`/`L` sub-tab steps from either pane. Changed: the filter applies through one `detail_body` every key reads instead of a separate filtered accessor; typing puts the cursor on the first match and `n`/`N` (new in nebaz) step matches; matches are reverse-video in place; flat digits find a header by name under a filter; `H`/`L` from the pane wait for an unloaded tab's first row (`pending_detail_focus`) instead of replaying keys. Not taken: the mouse screen-row map (it came with #42), the keycast labels. `h` never popped history in nebaz, so that half of `40b402f` has nothing to port |
| `src/search/query_parser.rs` (`parse_all_query`), `src/app/all_search.rs`, `resource_list.rs` badge and empty state (#38) | #68, #78, #79, `df95f85` (neboto-tui @ `03760c0`) | `@all` cross-service search over warm caches, never fetching (neboto ADR 0004): flattened rows with a parallel source list, ⏎ jumps into the owning tab, `l` peeks, Ctrl-O returns to the results, a load can't land on or be cached from the foreign rows. Changed: the prefix is `@*` (`@all` is nebaz's All resources routing prefix, #23); sources are sub-tabs, not services (the cache key is per sub-tab); entering the mode supersedes the current load instead of guarding each stream handler; All resources rows only fill in ids no typed list has. Not taken: the service-strip `@all` chip with per-service match counts and chip narrowing (`Tab`/`H`/`L`), the `service` sort, `@audit` |
| `src/app/mouse.rs`, the widgets' hit recording (`details_pane.rs` `layout_body`'s row map, `subtab_bar.rs`, `service_tabs.rs`, `search_bar.rs`, the pickers, `jump_list.rs`, `message_log.rs`, `macro_picker.rs`, `help_overlay.rs`, `network_lens.rs`, `metrics_overlay.rs`, `main.rs`'s status bar), `src/harness_tests/mouse_test.rs` (#42) | neboto-tui#131, #136, #139, #140, #141 @ `03760c0` (`handle_mouse`, `apply_click_action`, `note_left_click`, `PopupHits`, `handle_modal_mouse`, `select_modal_row`, `handle_pane_view_mouse`, `click_select_detail_row`, `hint_click_key`, `record_hint_regions`, `record_nav_hint_regions`) | Double-click (same cell, 400 ms) is `⏎` on a list row, a detail line and an in-pane view row; a right-click is `⌫` (history back, else to the list; neboto-tui#148's context menu is not taken), `Esc` on a popup or in-pane view; a body click goes through the renderer's screen-row → `detail_body()` row map (wrap, filter); a left-drag selects lines (the list's drag from #39 stays); the wheel scrolls the pane under the pointer (three lines in the body); every centered modal owns the mouse (a click outside or a right-click closes it, a click on the highlighted row or a double-click confirms; the macro name prompt ignores it); status-bar, detail-footer, lens and metrics hints, the subscription badge (`P`), the strip hint (`S`), the location chip (`R`), the `‹`/`›` markers, the search bar (`/`), the detail title bar (`Z`) and the metrics window chips are click targets. Changed: the click actions are `List` / `Detail` / `Press` by which pane the key goes to (neboto's `Key` / `DetailSection` / `Press`); the mouse state is one `MouseState` field; the body's scroll keeps last frame's top while the cursor is on screen (nebaz's pane had none, so a click scrolled the line clicked); outside an in-pane view a click closes it and goes on, as before. Not taken: the update chip, the Cost period chips, `@all` strip chips, the forward hint (nebaz has no Ctrl-F), the dashboard grid |

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
they are in git history and tracked as #38 and #39 (`parse_all_query` came back with #38, above). `multi_detail_csv` came
back with #40 as the single export's CSV, `export_detail_multi` with #39. `subtab_bar`,
`AppLayout::sub_tabs_area` and `shell_quote` lit up with the sub-tab model
and the Subscriptions service; `native_state_label` with the catalog's
state ladder.
