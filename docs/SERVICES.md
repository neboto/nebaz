# Services

What each first-release service shows, how its rows get a state, what a row
links to, and which ARM call feeds it. This is the service catalog decided
on the wayfinder map (ticket 06, 2026-09-23) promoted into the repo; the
service file itself (`src/azure/services/<svc>.rs`) is the reference for
what renders today and moves faster than this page. Read this **before
editing a service file**; the cross-cutting rules are the ones that bit.

Vocabulary (state ladder, Related section, embedded vs. lazy child, sub-tab)
is in [`CONTEXT.md`](../CONTEXT.md). Permissions per service are in
[`PERMISSIONS.md`](../PERMISSIONS.md).

## Cross-cutting rules

1. **State ladder**, applied top down on every type
   (`resource::state_ladder`):
   1. a `provisioningState` in transition (`Creating`, `Updating`,
      `Deleting`, `Upgrading`, `Scaling`, `Accepted`, `ResolvingDNS`, …) or
      `Failed`/`Canceled` wins → Creating / Deleting / Pending /
      Unavailable, label the native word;
   2. else the runtime state when the type has one: VM power state
      (`running` → Running, `deallocated`/`stopped` → Stopped,
      `starting`/`stopping`/`deallocating` → Pending), disk `diskState`
      (`Attached` → Running, `Unattached` → Available, `Reserved`,
      `ActiveSAS`, uploads → Pending), NIC attachment derived from
      `virtualMachine.id` (`attached` → Running, `unattached` →
      Available), public IP attachment derived from `ipConfiguration.id`
      or `natGateway.id` (same words, same buckets: an unattached public
      IP still bills), AKS `powerState.code` (`Running`/`Stopped`), storage
      `statusOfPrimary` (`available`/`unavailable`), subscription `state`
      (`Enabled` → Available, `Disabled` → Unavailable, `Warned`/`PastDue`
      → Pending, `Deleted` → Terminated);
   3. else stateless (dim `○`, blank label): resource groups, VNets,
      subnets, NSGs, load balancers, route tables, NAT gateways, vaults,
      managed identities (no `provisioningState` at all).
   The label is always the native word lowercased (`native_state_label`),
   so the `F` chips read `deallocated`, `unattached`, `upgrading`. Never
   add a per-type state table that disagrees on what `Succeeded` means.
2. **VM power state is on the row.** The VM list is two subscription-wide
   calls: the model pages stream in with a blank state, then the same list
   with `statusOnly=true` fills the power state, merged by id, delivered
   as one replacement (`ResourcesLoaded`). If the second call fails the
   rows stay, with a load warning. The Instance view section stays lazy
   for the rest. Verified live 2026-09-23.
3. **Jumps** are one function, ARM id → `NavLocation`, routing on the id's
   `providers/{namespace}/{type}` segment (`JumpView::for_arm_id`); a
   resource-group id lands on Resource Groups, a bare subscription id on
   Subscriptions. The user presses it in a **Related** section every type
   carries (non-lazy, derived from the list body): Subscription and
   Resource group first, then the type's own targets; Enter on a line
   jumps, switching subscription (and tenant) and lifting the location
   filter if needed, with a toast. An id whose type nebaz does not browse
   (public IP prefix, firewall) still lists; Enter copies it with a toast.
   Enter on any other ARM-id valued line in the pane does the same, so the
   Networking and Storage sections of a VM jump too.
4. **Key Vault names come from ARM** (`Secrets_List`, `Keys_List`): the
   control-plane token, `Reader` suffices, values never returned by
   construction. Both section bodies open with "names and attributes from
   ARM; values are never fetched". No certificates (no ARM list). The
   read-only guard (`tests/readonly_guard.rs`) fails the build on any
   vault data-plane host or `az keyvault secret show`.
5. **Noise** (`a` hides it): only subscriptions whose state is not
   `Enabled`. Every other type is false in the first release. Mark a
   category noise only when the non-noise subset is normally non-empty,
   because `a` is a session-wide toggle.
6. **Embedded children** (subnets, node pools) are named `parent/child`
   on their own sub-tab (`vnet-prod/default`, `aks-prod/system`), bare
   inside the parent's section; `search_text` carries both. They
   **inherit the parent's location** for the `R` filter (ADR 0002). Lazy
   children (containers, secret and key names) are section lines, never
   rows, so they carry no `cli_command`; the section footer names the
   read command.
7. **One call, two sub-tabs**: VNets/Subnets and Clusters/Node pools are
   two cache entries from the same list; switching sub-tab refetches
   (Network reads allow 10,000 per 5 min; AKS is a handful of rows).
   Cross-filling both from one call is a backlog nicety.
8. **AKS node pools need no lazy call**: the list's `agentPoolProfiles`
   is the full agent-pool property set (autoscale bounds, power state,
   node image version, current version). Still to confirm on a
   subscription with a cluster; if the live JSON lacks those fields, add
   a lazy Detail section per cluster rather than a per-pool call.
9. **`az` commands** are `show --ids {id}` for every ARM row except those
   whose `show` takes no `--ids` (`az account show`, `az group show`,
   `az keyvault show`, `az aks show`, `az aks nodepool show`,
   `az cognitiveservices account show`, `az functionapp show`,
   `az logicapp show`), which use the name form with `--subscription`.
   `functionapp show` re-declares its name argument without an `id_part`,
   so its `--ids` support is not certain from the source; the name form
   works either way. Verified live 2026-09-23; the Cognitive Services one
   from the CLI's parameter table (no `id_part` on the account name,
   2026-09-24), not yet live. The
   guard requires a read verb on every `az` literal in `src/`.
10. **Partial failures**: a phase failure (the power-state pass, a lazy
    section) sends `ResourceLoadWarning` and keeps going; `ResourceLoadError`
    is for a first-phase failure where nothing can stream. Connection
    failures name the host and the root cause ("cannot reach
    management.azure.com: Connection refused (gave up after retries)").

## The catalog

Every type: Overview first, Related second to last, Tags last; ⧗ marks a
lazy section; every `az` command is `show --ids {id}` unless stated.

| Service · sub-tab | Sections between Overview and Related | State | Related (after Subscription, Resource group) | `az` |
|---|---|---|---|---|
| Subscriptions · Subscriptions | Details ⧗ · Locations ⧗ · Tags (from Details) | subscription state; noise unless `Enabled` | — (root) | `az account show --subscription {id}` |
| Subscriptions · Resource Groups | — | stateless when `Succeeded` | `managedBy` id when set | `az group show -n {name} --subscription {sub}` |
| Virtual Machines · VMs | Instance view ⧗ (agent, OS, boot diagnostics, disk statuses) · Networking (NICs, primary) · Storage (OS disk, data disks with LUN, size) | power state | each NIC, OS and data disks, availability set, user-assigned identities | `az vm show` |
| Virtual Machines · Disks | — | `diskState` | `managedBy` VM | `az disk show` |
| Virtual Machines · NICs | IP configurations (name, private IP, allocation, primary, public IP) | attached / unattached | VM, NSG, each IP config's subnet and public IP | `az network nic show` |
| Storage · Accounts | Endpoints · Security (public blob access, shared key, min TLS, HTTPS only, public network access, network default action, encryption key source, HNS) · Containers ⧗ | `statusOfPrimary` | — | `az storage account show` |
| Network · VNets | Subnets (embedded) · Peerings | stateless | each subnet, each peered VNet | `az network vnet show` |
| Network · Subnets | — (Overview: prefix, NSG, route table, NAT gateway, delegations, service endpoints, IP configuration count) | stateless | VNet, NSG, route table, NAT gateway | `az network vnet subnet show` |
| Network · NSGs | Inbound · Outbound (custom rules by priority, then default rules dimmed) · Used by (NICs, subnets) | stateless | each associated subnet and NIC | `az network nsg show` |
| Network · Public IPs | — (Overview: address, allocation, version, SKU · tier, attached to, DNS label, FQDN, idle timeout, zones, DDoS) | attached / unattached | the owner of its IP configuration (NIC, load balancer, gateway, firewall, bastion), NAT gateway, prefix | `az network public-ip show` |
| Network · LBs | Frontends (public IP, or private IP + subnet) · Backend pools (NICs, deduplicated from IP configurations; or addresses) · Rules (LB rules, health probes, inbound NAT, outbound) | stateless | frontend public IPs and subnets, backend NICs | `az network lb show` |
| Network · Routes | Routes (prefix → next hop type and IP) | stateless | each associated subnet | `az network route-table show` |
| Network · NAT | — (Overview: SKU, idle timeout, zones, counts) | stateless | public IPs (v4 and v6), prefixes, each subnet | `az network nat gateway show` |
| Network · PEs | Connection (target, sub-resource, status, description, automatic or manual approval) · DNS (custom DNS configs: FQDN → IPs) | ladder, then connection status (`Approved` → Available, `Pending` → Pending, `Rejected` / `Disconnected` → Unavailable) | **target** (`privateLinkServiceId`: jumps to the vault, account, storage account… it fronts), subnet, NICs | `az network private-endpoint show` |
| Network · Private DNS | Records ⧗ (name, type, TTL, values; auto-registered flagged) · VNet links ⧗ (each linked VNet jumps; auto-registration, state) | stateless; `location` is `global`, which passes every `R` filter | — (linked VNets are in VNet links) | `az network private-dns zone show` |
| Key Vault · Vaults | Access (policies, or "Azure RBAC") · Network (default action, bypass, IP and VNet rules, private endpoints) · Secrets ⧗ · Keys ⧗ | stateless | each network-rule subnet | `az keyvault show -n {name} -g {rg} --subscription {sub}` |
| Identity · Identities | Federated credentials ⧗ (issuer, subject, audiences) · (Overview: client id, principal id, tenant, isolation scope; both ids searchable) | stateless | — (users list the identity in their own Related) | `az identity show` |
| AKS · Clusters | Network · Access · Node pools (embedded) · Add-ons | ladder, then `powerState` | node resource group, user-assigned identities, kubelet identity | `az aks show -n {name} -g {rg} --subscription {sub}` |
| AKS · Node pools | — (Overview: mode, count, size, OS, versions, node image, autoscale, max pods, zones, priority, power, taints, labels) | ladder on the pool's fields | Cluster | `az aks nodepool show --cluster-name {cluster} -g {rg} -n {pool} --subscription {sub}` |
| App Service · Apps | Configuration ⧗ (`config/web`: runtime, always on, TLS, FTPS, HTTP/2, health check, VNet routing, access restrictions; never app settings or connection strings) · Hostnames (TLS state, SCM flagged) · Networking (public access, VNet integration subnet, outbound IPs) | ladder, then `state` (`Running` / `Stopped`) | plan, VNet integration subnet, Container Apps environment, user-assigned identities, Key Vault reference identity | web apps `az webapp show --ids`; function and logic apps `az functionapp` / `az logicapp show -n {name} -g {rg} --subscription {sub}` |
| App Service · Functions | the same rows as Apps, filtered to `kind` containing `functionapp` (Logic Apps Standard included) | as Apps | as Apps | as Apps |
| App Service · Plans | — (Overview: SKU · tier, OS, workers of max, apps, zone redundancy, per-app and elastic scaling) | ladder, then `status` (`Ready` → Available) | — (apps list their plan) | `az appservice plan show` |
| Foundry · Resources | Deployments ⧗ (model, version, format, SKU and capacity, PTUs for provisioned SKUs, rate limits, state, upgrade option, RAI policy) · Projects ⧗ (only when `allowProjectManagement`; no call otherwise) · Network (public access, ACLs, restrict outbound + FQDNs, agent subnets, private endpoints) · Security (key auth, identity, CMK) | ladder only | network-rule and agent subnets, private endpoints, user-assigned identities, user-owned storage | `az cognitiveservices account show -n {name} -g {rg} --subscription {sub}` |

Routing prefixes: `@sub @rg @vm @disk @nic @storage @vnet @subnet @nsg @pip
@lb @rt @nat @pe @pdns @kv @id @aks @pool @app @func @plan @foundry` (the list in `ServiceType`, `src/azure/service.rs`, is the
reference).

## API calls per view

All `GET`, all under `/subscriptions/{sub}`; paged with `nextLink`. Every
path is built by the one constructor in `src/azure/arm.rs`; the ARM action
each one needs is in `PERMISSIONS.md`. **A new call goes in both tables.**

| View or section | Calls | Path · api-version |
|---|---|---|
| Subscriptions | 0 ARM (`az account list`) | — |
| Subscription Details / Locations | 1 each, per row, on demand | `/subscriptions/{id}` · `/subscriptions/{id}/locations` · `2022-12-01` |
| Resource Groups | 1 | `/resourcegroups` · `2021-04-01` |
| VMs | 2 | `/providers/Microsoft.Compute/virtualMachines` (+ `statusOnly=true`) · `2026-04-01` |
| VM Instance view | 1 per VM, on demand | `{vm}/instanceView` · `2026-04-01` |
| Disks | 1 | `/providers/Microsoft.Compute/disks` · `2026-03-02` |
| NICs | 1 | `/providers/Microsoft.Network/networkInterfaces` · `2025-09-01` |
| Accounts | 1 (Storage RP: 100 list calls / 5 min) | `/providers/Microsoft.Storage/storageAccounts` · `2026-06-01` |
| Containers | 1 per account, on demand (same budget) | `{account}/blobServices/default/containers` · `2026-06-01` |
| VNets, Subnets | 1 each (same list) | `/providers/Microsoft.Network/virtualNetworks` · `2025-09-01` |
| NSGs | 1 | `/providers/Microsoft.Network/networkSecurityGroups` · `2025-09-01` |
| Public IPs | 1 | `/providers/Microsoft.Network/publicIPAddresses` · `2025-09-01` |
| LBs | 1 (frontends, pools, rules, probes embedded) | `/providers/Microsoft.Network/loadBalancers` · `2025-09-01` |
| Routes | 1 (routes embedded) | `/providers/Microsoft.Network/routeTables` · `2025-09-01` |
| NAT | 1 | `/providers/Microsoft.Network/natGateways` · `2025-09-01` |
| PEs | 1 | `/providers/Microsoft.Network/privateEndpoints` · `2025-09-01` |
| Private DNS | 1 | `/providers/Microsoft.Network/privateDnsZones` · `2024-06-01` (its own spec) |
| Records, VNet links | 1 each per zone, on demand | `{zone}/ALL` · `{zone}/virtualNetworkLinks` · `2024-06-01` |
| Vaults | 1 | `/providers/Microsoft.KeyVault/vaults` · `2024-11-01` |
| Identities | 1 | `/providers/Microsoft.ManagedIdentity/userAssignedIdentities` · `2024-11-30` |
| Federated credentials | 1 per identity, on demand | `{identity}/federatedIdentityCredentials` · `2024-11-30` |
| Secrets, Keys | 1 each per vault, on demand | `{vault}/secrets` · `{vault}/keys` · `2026-05-15` |
| Clusters, Node pools | 1 each (same list) | `/providers/Microsoft.ContainerService/managedClusters` · `2026-06-01` |
| Apps, Functions | 1 each (the same sites list; Apps is every site because a site id does not say its kind) | `/providers/Microsoft.Web/sites` · `2026-03-15` |
| Plans | 1 | `/providers/Microsoft.Web/serverfarms` · `2026-03-15` |
| App Configuration | 1 per app, on demand | `{site}/config/web` · `2026-03-15` |
| Foundry resources | 1 (every Cognitive Services kind; `kind` on the row) | `/providers/Microsoft.CognitiveServices/accounts` · `2026-07-01` |
| Deployments, Projects | 1 each per account, on demand | `{account}/deployments` · `{account}/projects` · `2026-07-01` |

A full tour of every sub-tab in one subscription is one list call per
sub-tab. Only
the Accounts view and its Containers sections touch the throttled Storage
budget. **Watch mode** (`w`, presets 5–300 s) needs no floor for one
watched view: the 5 s preset is 60 list calls per 5 minutes against the
100 allowed. Two watched Storage views in one subscription would exceed
it; that floor is on the backlog.

## Verified live (2026-09-23, the Azure machine)

- VM power state on the row through the `statusOnly=true` pass. Whether
  that pass also carries the full model (one call instead of two) is
  unchecked; the two-call form stays.
- `az keyvault show`, `az aks show`, `az aks nodepool show` take no
  `--ids` (name form above).
- The api-versions above were accepted.
- Still to check: embedded `agentPoolProfiles` carry autoscale and power
  (rule 8), on a subscription with an AKS cluster.
