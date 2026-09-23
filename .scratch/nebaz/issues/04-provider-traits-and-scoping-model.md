# 04 — Provider traits and scoping model

Type: grilling
Status: resolved
Blocked by: 01, 02
Map: ../map.md

## Question

What do `AwsService` / `ServiceType` / `Region` / `AwsClients` / `CacheKey`
become in nebaz, given the settled scoping model (subscription on `P`,
location on `R` as a client-side filter, resource group as a filter chip)?

Decide and record as an ADR + CONTEXT.md glossary entries:
- The `Service` and `Resource` trait shapes (from ticket 02's coupling list):
  what replaces `security_group_ids` / `trail_lookup_keys` / `console_url`
  / `cli_command` (an `az` read command) and how the ARM resource id serves as
  the universal jump key.
- Cache keying: `(subscription, ServiceType, variant)` with location filtered
  client-side — confirm against the SDK research (are any of the six
  services' list calls location-scoped rather than subscription-scoped?).
- The client factory: one credential, per-service clients built per
  subscription; what a subscription switch replaces (LazyStore epoch bump as
  in neboto).
- The search prefixes for the six services (`@sub`, `@rg`, `@vm`, `@storage`,
  `@vnet`, `@kv`, `@aks`) and their sub-tab layout.
- Whether "location" is a picker at all in the first release or just a chip.

## Inputs from ticket 01

Confirmed: no server-side location filter on any list; `id` is the full ARM
resource id; children carry no `location`. Client shape: one
`azure_core` pipeline with `BearerTokenAuthorizationPolicy` + hand-written
GET request constructors per endpoint, paged with `Pager`/`ItemIterator`
(`PagerContinuation::Link`). Endpoint table in
`../research/azure-rust-sdk.md`.

## Comments

**2026-09-23 — input from ticket 02.** The skeleton now carries a concrete
proposal for every question above; grill against it rather than from
scratch. See the "`Resource` trait" and "Other things the build surfaced"
sections of the [ticket 02 answer](02-skeleton-sizing-prototype.md) and the
code: `src/azure/resource.rs` (trait), `src/azure/service.rs`
(`ServiceType` + `AzureService`, `is_tenant_scoped`), `src/azure/cache.rs`
(key `(service, subscription, variant)`), `src/azure/location.rs` (static
`Location` with `All` + `admits()`; the static-vs-API question is open),
`src/azure/client.rs` (`AzureClients` shape). Open here specifically:
whether `Location` stays a compiled table or is fed from
`GET /subscriptions/{id}/locations`, and whether `resource_group()` should
be a first-class filter slot rather than a chip.

## Answer

**Resolved 2026-09-23** in a grill against the skeleton's proposal; every
recommendation was accepted. Recorded as
[ADR 0002](../../../docs/adr/0002-subscription-scoped-lists-location-as-filter.md)
(the scoping model and the two stores), [ADR 0001](../../../docs/adr/0001-copy-not-depend-on-neboto.md)
(the charting-time fork decision, now written down) and the new
[`CONTEXT.md`](../../../CONTEXT.md) glossary (neboto's vocabulary ported, plus a
Scoping and a Resources section). The skeleton code is **not** changed on
this map; the build session for each item applies the deltas below.

### Decisions

1. **Location is a string, not an enum.** `Location` becomes a string-backed
   value with an `All` sentinel; `define_locations!` and the 24-entry table go.
   The `R` picker is fed from `GET /subscriptions/{id}/locations` (fetched once
   per subscription, held as a lazy value that resets with the LazyStore)
   merged with the distinct `location()` values of the current list and their
   row counts, so a location with zero rows in this service is still pickable.
   `admits()` keeps its rule: rows with no location are never filtered.
   `-r`/`default_location` accept any string; an unknown value simply filters
   to the "N in other locations" empty state.
2. **Resource group is a query token**, `rg:<name>`, split out like `tag:`:
   case-insensitive exact match on `resource_group()`; several `rg:` tokens
   OR together (a row has exactly one group); a bare `rg:` stays literal
   text. No slot, no app field, no picker in the first release (a picker that
   inserts the token is a later nicety).
3. **Two stores.** List cache keyed `(service, subscription, variant)` where
   `variant` is the sub-tab; tenant-scoped lists under `<tenant>`. LazyStore
   keyed by ARM id for every per-resource fetch. Ticket 01's table confirms
   none of the six services' list calls is location-scoped.
4. **Subscription switch**: keep the client (subscription is a value, not a
   client — tenant change is ticket 05's), keep the list cache, replace the
   LazyStore (epoch bump), bump the load generation. `NavLocation` gains a
   `subscription` field; a jump or bookmark into another subscription
   switches it first (status message), or fails with a message if that
   subscription is not in the picker's list.
5. **Sub-tab layout** (rule: a sub-tab is fed by one subscription-wide list
   or flattened from one; per-parent calls are lazy sections):

   | Service | Sub-tabs | Lazy children (sections on the parent) |
   |---|---|---|
   | Subscriptions | Subscriptions · Resource Groups | — |
   | Virtual Machines | VMs · Disks · NICs | instance view (power state, agent, disks) |
   | Storage | Accounts | blob containers |
   | Network | VNets · Subnets (embedded) · NSGs | — |
   | Key Vault | Vaults | secret names, key names |
   | AKS | Clusters · Node pools (embedded) | node-pool detail (autoscale, power) |

   Embedded children appear in both places: their own sub-tab *and* a section
   on the parent. `JumpView` becomes one flat enum with a variant per sub-tab;
   its string form is the cache `variant`. A single-sub-tab service hides the
   bar, as in neboto.
6. **Routing prefixes**: `@rg`, `@disk`, `@nic`, `@subnet`, `@nsg`, `@pool`
   select service *and* sub-tab; `@sub @vm @storage @vnet @kv @aks` land on
   the first sub-tab. `from_prefix` therefore returns `(ServiceType,
   Option<JumpView>)` rather than a bare service.
7. **Jump keys**: `portal_url()` uses `#@{tenant}/resource{id}` when the
   tenant is known, else `#@/resource{id}`. `cli_command()` uses `--ids {id}`
   wherever `az` supports it and the app does **not** append
   `--subscription`; commands without `--ids` (`az account show`,
   `az group show -n`) carry it themselves. The skeleton's doc comment on
   `cli_command` is wrong on this point.
8. **`Resource` trait** as the skeleton proposes: `id()` = ARM id;
   `location()`, `resource_group()` (default parsed from the id),
   `portal_url()` (default from the id), `cli_command()`; `console_url`,
   `trail_lookup_keys`, `security_group_ids`, `references`, cost and action
   hooks dropped. `AzureService` as the skeleton has it (no `execute_action`).
   `AzureClients::service(ServiceType)` builds a provider holding a shared
   ARM client (pipeline + endpoint + credential) plus the subscription id.
9. **Vocabulary**: location (never region), subscription (never
   profile/account), service vs resource provider, tenant scope, embedded
   child vs lazy child, node pool (never agent pool), routing prefix, ARM id.
   See `CONTEXT.md`.

### Skeleton deltas for the build session

- `src/azure/location.rs`: string-backed `Location`; drop the macro.
- `src/app.rs`: `locations` lazy value; `rg:` in `update_search`;
  `NavLocation.subscription`; `switch_subscription` no longer rebuilds
  `AzureClients`.
- `src/search/query_parser.rs`: `split_rg_filters` beside `split_tag_filters`.
- `src/azure/service.rs`: `from_prefix` → `(ServiceType, Option<JumpView>)`;
  routing aliases.
- `src/azure/resource.rs`: fix the `cli_command` doc comment.

### Deferred, by design

- Per-type `ResourceState` / `state_label` mapping (`provisioningState`,
  `powerState`) → **Service catalog: the first six**.
- Tenant switching, subscription discovery, credential per tenant → **Auth
  and the credential chain**.
- The read-only rule for every `cli_command` → **Read-only guarantee
  mechanism**.
