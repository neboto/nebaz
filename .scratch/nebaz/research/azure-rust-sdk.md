# Azure Rust SDK landscape (for `nebaz`)

Research for ticket `../issues/01-azure-rust-sdk-landscape.md`. Verified against
live sources on 2026-09-23. Every claim carries the URL it came from; where the
claim is about code, the source file on the SDK's `main` branch is cited rather
than a rendered doc page.

## TL;DR recommendation

**Use the official `azure_core` 1.x + `azure_identity` 1.x for auth and HTTP
plumbing, and call ARM REST directly for every list/get.** Do not depend on any
management-plane crate.

Why:

1. **There is no maintained Rust management-plane crate today.**
   - The autorest-generated `azure_mgmt_*` family last shipped **0.21.0 on
     2024-10-16**, pins `azure_core = "^0.21"` (2024-10-15, MSRV 1.74), and lives
     on the `legacy` branch, whose README says "This project is no longer under
     active development" and "Microsoft is developing the official Azure SDK for
     Rust crates and has no plans to update these unofficial crates."
     ([crates.io](https://crates.io/api/v1/crates/azure_mgmt_compute),
     [legacy README](https://github.com/Azure/azure-sdk-for-rust/blob/legacy/README.md),
     [legacy compute Cargo.toml](https://github.com/Azure/azure-sdk-for-rust/blob/legacy/services/mgmt/compute/Cargo.toml)).
   - The AKS crate is worse: `azure_mgmt_containerservice` stopped at **0.10.0
     on 2023-02-15** and its directory is absent from `services/mgmt` on
     `legacy` ([crates.io versions](https://crates.io/api/v1/crates/azure_mgmt_containerservice/versions),
     [legacy services/mgmt listing via GitHub API](https://api.github.com/repos/Azure/azure-sdk-for-rust/contents/services/mgmt?ref=legacy)).
   - The TypeSpec-era names `azure_resourcemanager_{compute,network,storage,keyvault,containerservice,resources}`
     exist on crates.io only as **0.0.1 placeholders published 2025-03-07/08**;
     docs.rs states "azure_resourcemanager_compute-0.0.1 is not a library" and the
     README reads "Coming soon." Nothing has been published since, and the
     official release inventory lists **no management libraries** at all
     ([crates.io](https://crates.io/api/v1/crates/azure_resourcemanager_compute),
     [docs.rs](https://docs.rs/crate/azure_resourcemanager_compute/latest),
     [azure.github.io release table](https://azure.github.io/azure-sdk/releases/latest/rust.html)).
2. **The official core is GA and moving.** `azure_core` 1.0.0 shipped
   2026-05-12, 1.1.0 on 2026-07-10, 1.2.0-beta.1 on 2026-09-05 (MSRV 1.88);
   `azure_identity` 1.0.0 on 2026-05-12, 1.1.0-beta.1 on 2026-09-05
   ([crates.io azure_core](https://crates.io/api/v1/crates/azure_core),
   [crates.io azure_identity](https://crates.io/api/v1/crates/azure_identity)).
   It ships exactly the three pieces a hand-rolled ARM client needs: a
   `TokenCredential` (`AzureCliCredential`), a `BearerTokenAuthorizationPolicy`
   that caches and refreshes tokens, and a `Pager`/`ItemIterator` built for
   `nextLink` paging (sources cited in sections 2 and 4).
3. **Mixing generations is not an option.** `azure_mgmt_*` needs `azure_core
   0.21` and therefore `azure_identity 0.21`; the 1.x identity crate cannot be
   plugged into them. Choosing the legacy crates means freezing on a 2024
   core with no security fixes and pre-1.0 auth.
4. **The six services' ARM surface is small and stable**: seven subscription-
   scoped `GET …?api-version=…` collections plus four child collections, all
   returning `{ value: [...], nextLink?: string }` (table in section 7). A
   thin typed client over `serde_json` is less code than adapting a generated
   crate per API version, and the read-only guarantee becomes a grep for one
   `Method::Get` constructor (section 6).

Fallback if the official management crates ship mid-project: they will be
built on the same `azure_core` 1.x `Pipeline`/`Pager` types, so a hand-rolled
client using those types is the cheapest thing to migrate later.

## 1. Status of `Azure/azure-sdk-for-rust` (`azure_core`, `azure_identity`)

| Fact | Value | Source |
|---|---|---|
| `azure_core` stable | 1.1.0 (2026-07-10); 1.0.0 GA 2026-05-12 | [crates.io](https://crates.io/api/v1/crates/azure_core) |
| `azure_core` latest | 1.2.0-beta.1 (2026-09-05) | same |
| `azure_core` MSRV | 1.88 (all 1.x versions) | [crates.io versions](https://crates.io/api/v1/crates/azure_core/versions) |
| `azure_identity` stable | 1.0.0 (2026-05-12) | [crates.io](https://crates.io/api/v1/crates/azure_identity) |
| `azure_identity` latest | 1.1.0-beta.1 (2026-09-05) | same |
| Default HTTP transport | reqwest + rustls (aws-lc-rs); `reqwest_native_tls` feature was replaced by `reqwest_rustls` in 0.35.0 (2026-04-22), with a 20s connect / 60s read timeout | [azure_core CHANGELOG](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/core/azure_core/CHANGELOG.md) |
| 1.0.0 breaking changes | `#[non_exhaustive]` on many types; "TLS requirement for bearer token authorization" (the bearer policy rejects non-`https` URLs) | CHANGELOG above; [bearer_token_policy.rs](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/core/azure_core/src/http/policies/auth/bearer_token_policy.rs) line ~70 |
| wasm32 | removed in 0.33.0 | [azure_identity CHANGELOG](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/identity/azure_identity/CHANGELOG.md) |
| Repo `sdk/` on `main` | `canary core cosmos eventhubs identity keyvault servicebus storage` — **no resourcemanager directory** | [GitHub contents API](https://api.github.com/repos/Azure/azure-sdk-for-rust/contents/sdk) |
| Official inventory | data-plane only: core, identity, cosmos, eventhubs, keyvault {secrets,keys,certificates} 1.0.1, storage_blob 1.1.0, storage_queue 1.1.0, servicebus … — "No management plane crates" | [azure.github.io/azure-sdk/releases/latest/rust.html](https://azure.github.io/azure-sdk/releases/latest/rust.html) |
| Management plane in flight | The only ARM-related work on `main` is an ARM long-running-operation poller helper (`azure_core::http::poller::resource_manager`, issue #4508, open, 2026-06-01) — plumbing for future generated clients, not a client | [issue 4508](https://github.com/Azure/azure-sdk-for-rust/issues/4508) |

The `main` README does not mention `azure_mgmt_*`, TypeSpec generation or an
MSRV; it only says the crates are "the successor to the `azure_sdk*` crates
from MindFlavor/AzureSDKForRust" ([README](https://github.com/Azure/azure-sdk-for-rust)).

## 2. `AzureCliCredential`, the default chain, refresh, tenant/subscription

**Credential types in `azure_identity` 1.0.0**: `AzureCliCredential`,
`AzureDeveloperCliCredential`, `DeveloperToolsCredential`,
`ManagedIdentityCredential`, `WorkloadIdentityCredential`,
`AzurePipelinesCredential`, `ClientAssertionCredential`,
`ClientCertificateCredential`, `ClientSecretCredential`
([docs.rs](https://docs.rs/azure_identity/latest/azure_identity/)).

**There is no `DefaultAzureCredential`.** 0.28.0 (2025-09-16) "Replaced
`DefaultAzureCredential` with `DeveloperToolsCredential`"
([CHANGELOG](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/identity/azure_identity/CHANGELOG.md)).

**How `AzureCliCredential` gets a token** (all from
[azure_cli_credential.rs](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/identity/azure_identity/src/azure_cli_credential.rs)):

- Constructor: `AzureCliCredential::new(options: Option<AzureCliCredentialOptions>) -> Result<Arc<Self>>`.
- Options ([docs.rs](https://docs.rs/azure_identity/latest/azure_identity/struct.AzureCliCredentialOptions.html)):
  - `subscription: Option<String>` — "The name or ID of a subscription. Set this to acquire tokens for an account other than the Azure CLI's current account."
  - `tenant_id: Option<String>` — "Identifies the tenant the credential should authenticate in. Defaults to the CLI's default tenant, which is typically the home tenant of the logged in user."
  - `executor: Option<Arc<dyn Executor>>` — process runner; default `new_executor()` uses `tokio::process::Command` with the `tokio` feature, else `std::process::Command` on a `std::thread::spawn` ([process/mod.rs](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/identity/azure_identity/src/process/mod.rs)).
  - There is **no** `process_timeout` or `additionally_allowed_tenants` field in 1.x.
- `get_token(scopes, _)` requires **exactly one scope** ("exactly one scope required"), validates it against `[A-Za-z0-9.\-_:/]`, then shells out to
  `az account get-access-token -o json --scope <scope> [--tenant <id>] [--subscription "<sub>"]`.
- The response is parsed from the CLI's `expires_on` (POSIX seconds); missing it fails with "expires_on field not found. Please use Azure CLI 2.54.0 or newer."
- Doc comment on the impl: **"This credential doesn't cache tokens, so every call invokes the CLI."**

**So who caches?** The HTTP layer. `BearerTokenAuthorizationPolicy::new(credential: Arc<dyn TokenCredential>, scopes)` holds one cached `AccessToken`, calls `get_token` on first use, and refreshes when `expires_on <= now + 5 min` (`should_refresh`); a concurrent refresh failure is ignored while the cached token is still valid. It also invalidates its cache on a 401 challenge ([bearer_token_policy.rs](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/core/azure_core/src/http/policies/auth/bearer_token_policy.rs); exported as `azure_core::http::policies::auth::BearerTokenAuthorizationPolicy` per [auth/mod.rs](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/core/azure_core/src/http/policies/auth/mod.rs)). If nebaz bypasses the pipeline and uses `reqwest` directly, it must reproduce this cache itself, or every ARM call spawns `az`.

**CLI token lifetime**: "The token will be valid for at least 5 minutes with the maximum at 60 minutes. If the subscription argument isn't specified, the current account is used." `--scope` is "Space-separated scopes in Microsoft Entra v2.0. Default to Azure Resource Manager." `--tenant` is "Only available for user and service principal account, not for managed identity or Cloud Shell account." ([az account get-access-token](https://learn.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest#az-account-get-access-token)).

**Which scope string for ARM**: v2 scopes are `{resource-identifier}/.default`; the Entra docs specifically warn that ARM's identifier carries a trailing slash, so "you must request `https://management.azure.com//.default` (notice the double slash!)" ([scopes-oidc](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc#trailing-slash-and-default)). The CLI's own default (`--scope` omitted) targets ARM. Open question 1 covers which spelling to use.

**Default chain**: `DeveloperToolsCredential::new(None)` "tries the following credential types, in this order, stopping when one provides a token: `AzureCliCredential`, `AzureDeveloperCliCredential`" and "uses the first credential that provides a token for all subsequent token requests. It never tries the others again." Its options struct exposes only `executor` — **no tenant/subscription passthrough**, so a TUI that lets the user pick a subscription must construct `AzureCliCredential` itself ([developer_tools_credential.rs](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/identity/azure_identity/src/developer_tools_credential.rs)).

**Per-request tenant override**: `azure_core::credentials::TokenRequestOptions` has a single field, `method_options: ClientMethodOptions` — no tenant/claims knob ([docs.rs](https://docs.rs/azure_core/latest/azure_core/credentials/struct.TokenRequestOptions.html)). Tenant selection is therefore a construction-time choice: one `AzureCliCredential` per tenant.

**Subscription discovery for the picker**: `GET https://management.azure.com/subscriptions?api-version=2022-12-01` is tenant-scoped and returns `subscriptionId`, `displayName`, `state` (Enabled/Warned/PastDue/Disabled/Deleted), `tenantId`, `managedByTenants[]`, `tags` ([Subscriptions - List](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list)). This is the same list `az account list --refresh` fetches; nebaz can call it directly rather than parsing `az account list`.

**Feature flags to set**: `azure_identity` default features are `["azure_core/default", "reqwest_rustls"]`; `tokio = ["dep:tokio", "azure_core/tokio", "tokio/process"]` is opt-in ([Cargo.toml](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/identity/azure_identity/Cargo.toml)). nebaz is tokio-based, so enable `tokio` to avoid the std-thread executor.

## 3. `azure_mgmt_*` (autorest) vs `azure_resourcemanager_*` (TypeSpec)

### The autorest generation (`legacy` branch)

| Crate | Last version | Date | Notes |
|---|---|---|---|
| `azure_mgmt_subscription` | 0.21.0 | 2024-10-16 | tags `package_2019_10_preview … package_2024_08_preview` |
| `azure_mgmt_resources` | 0.21.0 | 2024-10-16 | resource groups |
| `azure_mgmt_compute` | 0.21.0 | 2024-10-16 | default tag `package-2024-07-01`; VMs + disks |
| `azure_mgmt_network` | 0.21.0 | 2024-10-16 | VNets, subnets, NSGs, NICs |
| `azure_mgmt_storage` | 0.21.0 | 2024-10-16 | accounts + blob containers |
| `azure_mgmt_keyvault` | 0.21.0 | 2024-10-16 | vaults + ARM secrets/keys |
| `azure_mgmt_containerservice` | **0.10.0** | **2023-02-15** | **dropped**; not in `services/mgmt` on `legacy` |

Sources: [crates.io search sorted by recent updates](https://crates.io/api/v1/crates?q=azure_mgmt&per_page=50&sort=recent-updates) (newest `azure_mgmt_*` update anywhere is 2024-10-16), per-crate pages linked in the TL;DR, [legacy services README](https://github.com/Azure/azure-sdk-for-rust/blob/legacy/services/README.md) ("202 control plane crates … generated by AutoRust"), [legacy branch commits](https://api.github.com/repos/Azure/azure-sdk-for-rust/commits?sha=legacy&per_page=3) (last commit 2025-01-10, storage data-plane).

- Every crate README says "This is an unofficial, unsupported generated Azure SDK for Rust crate from the Azure REST API specifications" ([docs.rs azure_mgmt_compute](https://docs.rs/crate/azure_mgmt_compute/latest)).
- Dependency pin: `azure_core = { version = "0.21" }`, default features `["default_tag", "enable_reqwest"]`, API version selected by a `package-YYYY-MM-DD` cargo feature ([legacy compute Cargo.toml](https://github.com/Azure/azure-sdk-for-rust/blob/legacy/services/mgmt/compute/Cargo.toml)).
- **Pagination shape**: a builder per operation; `RequestBuilder::into_stream(self) -> azure_core::Pageable<VirtualMachineListResult, Error>`, where `Pageable<T, E>` "implements `futures::Stream`" with `Item = Result<T, E>`, yielding one *page* per item and following the continuation automatically ([docs.rs list_all RequestBuilder](https://docs.rs/azure_mgmt_compute/latest/azure_mgmt_compute/package_2024_07_01/virtual_machines/list_all/struct.RequestBuilder.html), [docs.rs Pageable 0.21](https://docs.rs/azure_core/0.21.0/azure_core/struct.Pageable.html)). So: a stream of pages, not a stream of items, and not a hand `next_link` loop.
- The VM `list_all` builder exposes `status_only()` ("statusOnly=true enables fetching run time status of all Virtual Machines in the subscription"), `filter()`, `expand()` (docs.rs page above) — mirroring the REST query parameters in section 7.

### The TypeSpec generation (`main` branch)

- crates.io holds ~30 `azure_resourcemanager_*` names at **0.0.1**, all created 2025-03-07/08, description "Microsoft Azure management client SDK for Azure resource provider Microsoft.X"; the six we need all exist as placeholders ([crates.io search](https://crates.io/api/v1/crates?q=azure_resourcemanager&per_page=30); [per-crate API checks](https://crates.io/api/v1/crates/azure_resourcemanager_keyvault)).
- docs.rs for each: "not a library", README "Coming soon.", no dependencies ([azure_resourcemanager](https://docs.rs/crate/azure_resourcemanager/latest), [azure_resourcemanager_compute](https://docs.rs/crate/azure_resourcemanager_compute/latest)).
- No `sdk/resourcemanager` on `main`; no open issue/PR titled as a management-plane roadmap (GitHub issue search over the repo for "resource manager"/"management-plane"/"control plane" in title returns only the poller helper #4508, a Cosmos control-plane feature gate, and a 2026-03 question about contributing PIM endpoints) ([search](https://api.github.com/search/issues?q=repo:Azure/azure-sdk-for-rust+%22resource+manager%22+in:title)).
- Issue #3411 "Add documentation for Resource Manager generation" was closed 2025-12-11, so a generator path exists internally, but 18 months after the placeholders nothing has been published.

**Verdict**: neither generation is usable. Legacy = frozen on `azure_core 0.21`, AKS missing. TypeSpec = names reserved, no code.

## 4. Calling ARM REST directly

Yes, this is the stable path, and `azure_core` 1.x is built to make it a small amount of code:

- **Request/response types**: `azure_core::http::{Request, Method, Url, RawResponse, Response, Pipeline, ClientOptions, …}` — `Method` has variants `Get, Head, Post, Put, Patch, Delete, Follow` ([docs.rs http module](https://docs.rs/azure_core/latest/azure_core/http/index.html), [Method](https://docs.rs/azure_core/latest/azure_core/http/enum.Method.html)).
- **Pipeline**: `Pipeline::new(crate_name, crate_version, ClientOptions, per_call_policies, per_try_policies, Option<PipelineOptions>)`, then `pipeline.send(&ctx, &mut request, None).await -> Result<RawResponse>`; retry and transport policies are built in ([docs.rs Pipeline](https://docs.rs/azure_core/latest/azure_core/http/struct.Pipeline.html)). Add `BearerTokenAuthorizationPolicy::new(cred, ["<arm scope>"])` as a per-call policy and every request is authorized + token-cached (section 2).
- **Paging**: `pub type Pager<P, F = JsonFormat> = ItemIterator<Response<P, F>>`. `ItemIterator::new(|state: PagerState, opts: PagerOptions<'static>| -> PagerResultFuture<P>)`: the closure receives `PagerState::Initial` or `PagerState::More(PagerContinuation)`, does the GET, and returns `PagerResult::More { response, continuation: PagerContinuation::Link(url) }` or `PagerResult::Done { response }`. The iterator implements `futures::Stream`; `.into_pages()` gives a `PageIterator` for page-at-a-time streaming (exactly the `ResourcesPartiallyLoaded` shape neboto uses). `PagerContinuation` distinguishes `Link(Url)` (ARM's `nextLink`) from `Token(String)` (header-based continuation) ([pager.rs](https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/core/azure_core/src/http/pager.rs), including a doc example that follows a JSON `next_link`).
- **ARM paging contract**: "Some list operations return a property called `nextLink` in the response body … Typically, the response includes the nextLink property when the list operation returns more than 1,000 items. When nextLink isn't present in the results, the returned results are complete … Continue sending requests to the nextLink URL until it no longer contains a URL." Format `{ "value": [...], "nextLink": "https://management.azure.com/{operation}?api-version={version}&%24skiptoken={token}" }`. Every ARM request needs `api-version`; auth is `Authorization: Bearer <token>`; host `management.azure.com` (sovereign clouds differ) ([Azure REST reference](https://learn.microsoft.com/en-us/rest/api/azure/), [control plane and data plane](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/control-plane-and-data-plane)).
- **Throttling** (matters for a TUI that fans out): ARM uses a per-region token bucket — subscription **reads: bucket 250, refill 25/s**; 429 with `Retry-After`; remaining budget in `x-ms-ratelimit-remaining-subscription-reads`. Resource-provider limits sit on top: **Storage "management operations (list): 100 per 5 minutes"** and reads 800 per 5 min; **Network reads 10,000 per 5 minutes**; Compute has its own page ([request-limits-and-throttling](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling)). The Storage list quota is the one to design around: cache storage-account lists aggressively and never re-list on every keystroke.
- **Alternative for cross-subscription search**: Azure Resource Graph, `POST https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01` with a KQL `query`, `subscriptions[]`, `options.$top` ≤ 1000 and `$skipToken` paging; response `data[]`, `totalRecords`, `resultTruncated`. ARM's throttling page points at it for high-volume reads ([Resource Graph Resources](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources)). It is a candidate for an `@all`-style search later, not for the first six services.

Plain `reqwest` + a bearer header also works (and ARM is just JSON over HTTPS), but you then own token caching, retry on 429/`Retry-After`, and the `nextLink` loop. `azure_core` gives all three for one dependency you need anyway for `azure_identity`.

## 5. Resource ids and locations

- **Id format**: every ARM resource carries `id` = "Fully qualified resource ID for the resource. E.g. `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}`" (typed `string (arm-id)` in the newer specs) ([Disks - List definitions](https://learn.microsoft.com/en-us/rest/api/compute/disks/list), [Storage Accounts - List](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list)). Child resources nest under the parent: `…/virtualNetworks/{vnet}/subnets/{subnet}`, `…/storageAccounts/{acct}/blobServices/default/containers/{name}`, `…/managedClusters/{c}/agentPools/{p}` (sample responses on the pages in section 7). Subscriptions: `/subscriptions/{guid}`; resource groups: `/subscriptions/{guid}/resourceGroups/{name}`. Ids are case-insensitive in practice (resource group names are documented "case insensitive" on the container list page), so compare case-insensitively.
- **Provider namespaces** for the six: `Microsoft.Resources` (groups), `Microsoft.Compute` (VMs, disks), `Microsoft.Network` (VNets, subnets, NSGs, NICs), `Microsoft.Storage`, `Microsoft.KeyVault`, `Microsoft.ContainerService` ([resource providers by service](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-services-resource-providers)).
- **Location values**: top-level resources have `location` = "The geo-location where the resource lives", in the **normalized short form** (`eastus`, `westus`) — every sample response uses that form. `GET /subscriptions/{id}/locations?api-version=2022-12-01` returns the mapping `name: "eastus"`, `displayName: "East US"`, `regionalDisplayName: "(US) East US"`, plus `metadata.regionType` (Physical/Logical), `regionCategory` (Recommended/Extended/Other), `pairedRegion[]`, and `type: Region|EdgeZone` ([Subscriptions - List Locations](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list-locations)). That endpoint is the source for a region picker; `az account list-locations` wraps it.
- **Resource groups have their own `location`** ("It cannot be changed after the resource group has been created") and "The resources in a resource group can be located in different regions than the resource group" ([Resource Groups - List](https://learn.microsoft.com/en-us/rest/api/resources/resource-groups/list), [ARM overview](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview)). So a location filter must key on the resource's own `location`, never the group's.
- **Child resources carry no `location`**: the `Subnet` definition has `id, name, type, etag, properties.*` only; `ListContainerItem` and `AgentPool` likewise. Their location is the parent's ([Subnets - List](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/subnets/list), [Blob Containers - List](https://learn.microsoft.com/en-us/rest/api/storagerp/blob-containers/list), [Agent Pools - List](https://learn.microsoft.com/en-us/rest/api/aks/agent-pools/list)). Subscriptions have no location at all.
- **Consequence for the scoping model**: all list endpoints in section 7 are subscription-wide (or parent-scoped); ARM has no server-side location filter on them. "Subscription + client-side location filter" is therefore the only model available, and it needs one exception: subscription- and group-level rows (and children inheriting a parent's location) are not filtered by location.

## 6. Read-only guarantee at the crate level

- **REST**: the verb is the guarantee. ARM control-plane APIs "support GET, HEAD, PUT, POST, and PATCH" ([Azure REST reference](https://learn.microsoft.com/en-us/rest/api/azure/)); every list/get in section 7 is `GET`. With a hand-rolled client the check is mechanical: one place constructs requests, and a script (the `scripts/check-readonly.py` shape) can assert that every `Request::new(_, Method::…)` in `src/azure/` uses `Method::Get` (plus `Method::Post` for the Resource Graph query, which is a read despite the verb — flag it explicitly if adopted).
- **Legacy `azure_mgmt_*`**: the verb *is* visible in the generated source — each builder's `send` does `azure_core::Request::new(url, azure_core::Method::Get)` (e.g. 23 `Method::` uses in `azure_mgmt_subscription`'s `package_2021_10/mod.rs`) — and the method names follow `list`/`list_all`/`get` vs `create_or_update`/`delete`/`update` ([docs.rs source](https://docs.rs/crate/azure_mgmt_subscription/0.21.0/source/src/package_2021_10/mod.rs)). But the verb lives inside the dependency, so a guard would have to allow-list operation names rather than grep verbs. Moot given section 3.
- **Server-side backstop**: Azure RBAC's built-in **Reader** role is `Actions: ["*/read"]`, no DataActions, id `acdd72a7-3385-48ef-bd42-f606fba81ae7` — "View all resources, but does not allow you to make any changes." Running nebaz under a Reader-only assignment makes any accidental mutation fail at ARM ([built-in roles: General](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general#reader)). Note this covers the control plane only; the ARM Key Vault secrets endpoints below are control-plane too, but never return values.
- **Key Vault specifics**: the ARM `Secrets_List` and `Keys_List` operations are `GET`s and the spec says of `SecretProperties.value`: "'value' will never be returned from the service" — so listing *names* via ARM is read-only and cannot leak a secret. The same spec warns "This API is intended for internal use in ARM deployments. Users should use the data-plane REST service for interaction with vault secrets." There is **no ARM certificates list** (no `/certificates` path in the spec) ([openapi.json 2026-05-15](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/keyvault/resource-manager/Microsoft.KeyVault/KeyVault/stable/2026-05-15/openapi.json)). Certificate names would need the data-plane `azure_security_keyvault_certificates` 1.0.1 crate against `vault.azure.net` — a second token scope and a second RBAC model (`enableRbacAuthorization` vs access policies, exposed on the vault). Recommend: vault metadata + ARM secret/key names in v1; certificates later.

## 7. List endpoints for the six services

All endpoints are `GET https://management.azure.com` + path; all responses are `{ "value": [...], "nextLink": "<uri>" }` unless noted. api-version is the current one on the Learn page on 2026-09-23 (the ticket's fixed-in-code version; older versions remain valid — the legacy crates target 2024-era versions and still work).

| Service | Resource | Path | api-version | Scope of the call | Notes |
|---|---|---|---|---|---|
| Subscriptions | Subscription | `/subscriptions` | `2022-12-01` | **Tenant** (no subscription in path) | `subscriptionId`, `displayName`, `state`, `tenantId`, `managedByTenants[]`, `tags`. No `location`. [src](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list) |
| Subscriptions | Location | `/subscriptions/{sub}/locations` | `2022-12-01` | Subscription | `name`/`displayName`/`regionalDisplayName`/`metadata`; `includeExtendedLocations` opt-in. [src](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list-locations) |
| Resource Groups | ResourceGroup | `/subscriptions/{sub}/resourcegroups` | `2021-04-01` | Subscription | `location` (the group's own), `tags`, `managedBy`, `properties.provisioningState`; `$filter` supports `tagName eq 'x' and tagValue eq 'y'`; `$top`. [src](https://learn.microsoft.com/en-us/rest/api/resources/resource-groups/list) |
| Compute | VirtualMachine | `/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines` | `2026-04-01` | Subscription; `location` per row | `properties.instanceView` (power state) is **not** included by default; `statusOnly=true` fetches runtime status for all VMs in the subscription; `$expand=instanceView` only works with a `$filter` on `virtualMachineScaleSet/id`. `zones[]`, `hardwareProfile.vmSize`, `provisioningState`. [src](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/list-all) |
| Compute | VM instance view (per VM) | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView` | `2026-04-01` | Resource | `statuses[]` with `code: "PowerState/running"`, `displayStatus: "VM running"`; `computerName`, `osName`, `osVersion`, `vmAgent`, `disks[]`. Lazy-section material. [src](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/instance-view) |
| Compute | Disk | `/subscriptions/{sub}/providers/Microsoft.Compute/disks` | `2026-03-02` | Subscription; `location` per row | `managedBy` (attached VM id), `sku.name`, `properties.diskSizeGB`, `diskState`, `osType`, `timeCreated`, `zones[]`. [src](https://learn.microsoft.com/en-us/rest/api/compute/disks/list) |
| Network | NetworkInterface | `/subscriptions/{sub}/providers/Microsoft.Network/networkInterfaces` | `2025-09-01` | Subscription; `location` per row | `properties.virtualMachine.id`, `macAddress`, `networkSecurityGroup.id`, `ipConfigurations[].properties.{privateIPAddress, subnet.id, publicIPAddress.id}`. [src](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-interfaces/list-all) |
| Storage | StorageAccount | `/subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts` | `2026-06-01` | Subscription; `location` per row | "storage keys are not returned"; `kind`, `sku`, `properties.{provisioningState, primaryEndpoints, accessTier, allowBlobPublicAccess, minimumTlsVersion, publicNetworkAccess, supportsHttpsTrafficOnly, creationTime, statusOfPrimary}`. RP limit: **100 list calls / 5 min**. [src](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list) |
| Storage | BlobContainer (ARM) | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{acct}/blobServices/default/containers` | `2026-06-01` | Resource (per account); no `location` | `$maxpagesize`, `$filter` (name prefix), `$include=deleted`. `properties.{publicAccess, leaseState, leaseStatus, lastModifiedTime, hasImmutabilityPolicy, hasLegalHold, deleted}`. Page description says "SRP today does not return continuation token" yet the schema and sample carry `nextLink` with `$skipToken` — handle both. [src](https://learn.microsoft.com/en-us/rest/api/storagerp/blob-containers/list) |
| Network | VirtualNetwork | `/subscriptions/{sub}/providers/Microsoft.Network/virtualNetworks` | `2025-09-01` | Subscription; `location` per row | `properties.addressSpace.addressPrefixes[]`; **`properties.subnets[]` is embedded** (full `Subnet` objects with `addressPrefix`, `networkSecurityGroup.id`, `routeTable.id`, `natGateway.id`, `delegations[]`), so one call fills VNets + subnets. [src](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/virtual-networks/list-all) |
| Network | Subnet (standalone) | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets` | `2025-09-01` | Resource (per VNet); no `location` | Only needed for a per-VNet refresh; otherwise redundant with the embedded list. [src](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/subnets/list) |
| Network | NetworkSecurityGroup | `/subscriptions/{sub}/providers/Microsoft.Network/networkSecurityGroups` | `2025-09-01` | Subscription; `location` per row | `properties.securityRules[]` and `defaultSecurityRules[]` (`priority`, `direction`, `access`, `protocol`, `sourceAddressPrefix`, `destinationPortRange`), `networkInterfaces[].id`, `subnets[].id` — the raw material for an `N`-style access lens. [src](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list-all) |
| Key Vault | Vault | `/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults` | `2024-11-01` (spec has `2026-05-15` stable) | Subscription; `location` per row | `properties.{vaultUri, tenantId, sku, enableRbacAuthorization, enableSoftDelete, enablePurgeProtection, softDeleteRetentionInDays, publicNetworkAccess, networkAcls, accessPolicies[], privateEndpointConnections[]}`; `$top`. The `nextLink` sample points at the generic `/resources?$skiptoken=` endpoint — treat it as opaque. [src](https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription) |
| Key Vault | Secret names (ARM) | `…/Microsoft.KeyVault/vaults/{vault}/secrets` (`Secrets_List`) | `2026-05-15` | Resource (per vault) | `properties.{contentType, attributes, secretUri, secretUriWithVersion}`; `value` never returned; "intended for internal use in ARM deployments"; `$top`; paged. [spec](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/keyvault/resource-manager/Microsoft.KeyVault/KeyVault/stable/2026-05-15/openapi.json) |
| Key Vault | Key names (ARM) | `…/Microsoft.KeyVault/vaults/{vault}/keys` (`Keys_List`) | `2026-05-15` | Resource (per vault) | `properties.{kty, keyOps, keySize, curveName, keyUri, attributes, rotationPolicy}`; paged. No ARM certificate list. same spec |
| AKS | ManagedCluster | `/subscriptions/{sub}/providers/Microsoft.ContainerService/managedClusters` | `2026-06-01` | Subscription; `location` per row | `sku`, `properties.{provisioningState, powerState.code, kubernetesVersion, currentKubernetesVersion, fqdn, nodeResourceGroup, networkProfile}`; **`properties.agentPoolProfiles[]` is embedded** (name, count, vmSize, mode, osType, orchestratorVersion, provisioningState). [src](https://learn.microsoft.com/en-us/rest/api/aks/managed-clusters/list) |
| AKS | AgentPool | `…/Microsoft.ContainerService/managedClusters/{cluster}/agentPools` | `2026-06-01` | Resource (per cluster); no `location` | Adds `powerState`, `enableAutoScaling`, `minCount`/`maxCount`, `nodeImageVersion`, `currentOrchestratorVersion` beyond the embedded profile. [src](https://learn.microsoft.com/en-us/rest/api/aks/agent-pools/list) |

Reading the "scope" column: seven collections are one subscription-wide GET each (subscriptions/tenant, groups, VMs, disks, NICs, storage accounts, VNets, NSGs, vaults, AKS clusters); the rest are per-parent and belong in lazy detail sections. Nothing is location-scoped on the server.

## 8. Open questions

1. **ARM scope spelling.** Entra docs say `https://management.azure.com//.default` (double slash); the Go/Python SDKs and the CLI default work in practice with one slash, and `AzureCliCredential::validate_scope` accepts either. Needs a one-line live test against a real tenant; pick whichever `az account get-access-token --scope` returns a usable token for.
2. **VM power state at list time.** `statusOnly=true` on the subscription-wide VM list is documented to return runtime status; the Learn page's schema is ambiguous about how much of `instanceView` it populates and whether it costs a Compute RP throttling bucket per VM. Verify on a real subscription before making it the default; the per-VM `instanceView` GET is the safe lazy fallback.
3. **Blob container paging.** The container list page contradicts itself ("SRP today does not return continuation token" vs a `nextLink` in the sample). Test against an account with >5000 containers or treat `nextLink` as optional and never rely on `$maxpagesize`.
4. **Subscriptions-list vs `az account list`.** ARM's `/subscriptions` returns every subscription the token can see across the CLI's tenant; the CLI's cached list may include other tenants. Decide whether nebaz's picker is tenant-scoped (one `AzureCliCredential` per tenant, section 2) or reads `az account list` once for the tenant set.
5. **Storage RP list quota (100 / 5 min)** vs neboto-style watch mode: with a 10 s watch interval, 30 refreshes burn the whole quota. Storage accounts need a longer minimum TTL or watch mode must exclude them.
6. **Emulator story.** neboto's floci/LocalStack workflow has no Azure equivalent for ARM (Azurite is data-plane only). The offline harness (`App::new_for_test` + mocks) will carry all of the test load.
7. **When `azure_resourcemanager_*` ships.** Its pager/pipeline will be `azure_core` 1.x's; if nebaz's client wraps `Pipeline` + `ItemIterator` from the start, migration is a type swap. Worth re-checking crates.io quarterly; the placeholders have been silent since 2025-03.
