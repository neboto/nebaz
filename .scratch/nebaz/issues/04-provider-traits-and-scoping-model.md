# 04 — Provider traits and scoping model

Type: grilling
Status: open
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
