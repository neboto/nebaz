# 01 — Azure Rust SDK landscape

Type: research
Status: resolved
Blocked by: —
Map: ../map.md

## Question

Which Rust crates are current (as of 2026-09) for (a) Azure authentication
via the Azure CLI credential, and (b) management-plane list/get calls for
Subscriptions, Resource Groups, Virtual Machines (+ disks, NICs), Storage
Accounts (+ containers via ARM), Virtual Networks (+ subnets, NSGs), Key Vault
(vault metadata; secret/key/cert *names* if a management-plane list exists),
and AKS (clusters + node pools)?

Specifically:
- Status of the official `Azure/azure-sdk-for-rust` (azure_core, azure_identity):
  release state, how `AzureCliCredential` / the default chain is built, token
  refresh behaviour, tenant/subscription selection.
- Status of the `azure_mgmt_*` autorest-generated crates vs. any newer
  TypeSpec-generated management crates: are they maintained, which versions,
  do they cover the six services, what does pagination look like (a
  `next_link` loop? a stream?).
- Whether calling ARM REST directly (reqwest + a bearer token) is the more
  stable path, and if so what the six services' list endpoints and API
  versions are.
- How resource ids (ARM resource id strings) and locations come back, since
  the scoping model keys on subscription + client-side location filter.
- Any read-only guarantee angle: how to tell a GET/list op from a mutation at
  the crate level (a naming convention? HTTP verb visible?).

## Findings location

`.scratch/nebaz/research/azure-rust-sdk.md` (working tree, no branch — neboto
is not to be disturbed).

## Answer

Resolved 2026-09-23 by a research subagent. Full findings with sources:
[`research/azure-rust-sdk.md`](../research/azure-rust-sdk.md).

- **Use `azure_core` 1.x + `azure_identity` 1.x for auth and HTTP plumbing;
  call ARM REST directly for every list/get.** No maintained Rust
  management-plane crate exists: `azure_mgmt_*` is frozen at 0.21 (2024-10,
  `legacy` branch, "no plans to update"); the AKS crate stopped in 2023; the
  TypeSpec-era `azure_resourcemanager_*` names are 0.0.1 placeholders.
- **Auth**: `DefaultAzureCredential` is gone. `DeveloperToolsCredential` has
  no tenant/subscription option, so nebaz builds `AzureCliCredential`
  itself (options `subscription`, `tenant_id`, `executor`; `tokio` feature).
  It shells out to `az account get-access-token` on every `get_token` and
  does not cache; caching lives in `azure_core`'s
  `BearerTokenAuthorizationPolicy` (refresh 5 min before expiry, https
  only). Needs Azure CLI ≥ 2.54.0. Bypassing the `azure_core` pipeline with
  bare reqwest means re-implementing that cache — so use the pipeline.
- **Paging**: `azure_core::http::Pager` / `ItemIterator` with
  `PagerContinuation::Link` for ARM `nextLink`; implements `futures::Stream`,
  `.into_pages()` for per-page streaming (maps onto neboto's
  `list_resources_streaming`).
- **Scoping**: every list is subscription-wide (subscriptions themselves are
  tenant-scoped); no server-side location filter exists anywhere, so
  subscription + client-side location filter is the only model — confirms
  the charting decision. `id` is the full `/subscriptions/…/providers/…`
  string; `location` is the short name (`eastus`); child resources (subnets,
  containers, agent pools) carry no location; a resource group's location can
  differ from its resources'.
- **Endpoints**: 10 subscription-wide GETs + per-parent child lists, with
  api-versions, tabled in the findings. VNet list embeds subnets; AKS list
  embeds agentPoolProfiles; VM list omits power state unless
  `statusOnly=true`. Blob containers are listable via ARM
  (`blobServices/default/containers`) — no data-plane auth needed.
- **Read-only**: with direct REST the verb guard is a grep for `Method::Get`
  in one request constructor; RBAC `Reader` (`*/read`) is the server-side
  backstop. ARM exposes Key Vault `Secrets_List` / `Keys_List` (names only,
  values never returned) but no certificates list.
- **Gotchas**: Storage RP allows only 100 list calls per 5 min per
  subscription/region (watch mode on storage accounts would exhaust it);
  ARM scope may need `https://management.azure.com//.default` (double
  slash) — open; blob-container paging is ambiguous; `statusOnly=true` cost.
