# 06 — Service catalog for the first six services

Type: grilling
Status: resolved
Blocked by: 04
Map: ../map.md

## Question

For each of the six first-release services, what exactly does nebaz list and
show?

Per service (Subscriptions + Resource Groups, Virtual Machines, Storage
Accounts, Virtual Networks, Key Vault, AKS):
- resource types per sub-tab (e.g. VMs: Instances / Disks / NICs; VNets:
  Networks / Subnets / NSGs);
- the split-pane sections and which are lazy (`sections!` tables);
- row id, name, state vocabulary (`state_label`), `is_noise` candidates;
- jump targets between them (VM → its NIC → its subnet → its VNet, VM → its
  resource group, everything → its subscription) via ARM resource ids;
- the `az` read command per type;
- the API calls each needs (feeds ticket 07's allowlist and RBAC doc).

Output is the service section of the first-release spec (ticket 09).

## Inputs from ticket 01

Blob containers list via ARM (`blobServices/default/containers`, no data-plane
auth); VNet list embeds subnets; AKS list embeds agentPoolProfiles; VM list
omits power state unless `statusOnly=true` (decide whether the row's state
is worth that call); Key Vault has ARM `Secrets_List` / `Keys_List` (names
only) but no certificates list. Storage RP list throttle: 100 calls / 5 min
per subscription/region.

## Comments

**2026-09-23 — input from ticket 04.** The sub-tab layout is decided (see
the table in [ticket 04's answer](04-provider-traits-and-scoping-model.md)):
which types are sub-tabs, which are embedded children (subnets, node pools)
and which are lazy children (containers, secret/key names, instance view).
Left to this ticket per type: the `ResourceState` bucket + `state_label`
mapping from `provisioningState` / `powerState`, the section descriptor,
the `is_noise` rule, and the read-only `az … --ids` command. Vocabulary in
`CONTEXT.md`: "node pool", never "agent pool".

**2026-09-23 — input from the off-map foundation build.** The skeleton
deltas of tickets 04 and 05 are in the repo, and the first service is real:
`src/azure/services/subscriptions.rs` lists subscriptions (from
`az account list`, all tenants, no ARM call) and resource groups
(`GET /subscriptions/{sub}/resourcegroups`, one `ResourcesPartiallyLoaded`
per page) with `sections!` tables, `*_section_lines` bodies and two lazy
sections on a subscription row (the ARM subscription object; the
locations list, which also feeds the `R` picker). Grill this ticket
against that file, not from scratch: it made three calls this ticket
owns — (1) a resource group's `Succeeded` provisioning state renders as
`ResourceState::stateless()` (dim `○`, blank label) and only `Deleting` /
`Failed` / `Creating` get a colour and an `F` chip; (2) subscription rows
map `Enabled → Available`, `Disabled → Unavailable`, `Warned | PastDue →
Pending`, `Deleted → Terminated`, label = the native word lowercased;
(3) `is_noise` is untouched (a disabled subscription is a candidate). The
five other services still run on `services/stub.rs`, which shows the
shape (`error_rows` / `tag_rows` now live in `services/mod.rs`). The ARM
client (`src/azure/arm.rs`) has `get`, `list` and page-streaming
`list_pages`; api-versions live as constants next to each service.

## Answer

**Resolved 2026-09-23** in a two-round grill against the Subscriptions
service as built; every recommendation accepted. This section is the
service catalog of the first-release spec (ticket 09). One consequence line
was added to [ADR 0002](../../../docs/adr/0002-subscription-scoped-lists-location-as-filter.md)
(embedded children inherit the parent's location) and two glossary entries
to [`CONTEXT.md`](../../../CONTEXT.md) (state ladder, Related section). No
new ADR: nothing here is hard to reverse.

### Cross-cutting rules

1. **State ladder**, applied top down on every type:
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
      Available), AKS `powerState.code` (`Running`/`Stopped`), storage
      `statusOfPrimary` (`available`/`unavailable`), subscription `state`
      (as built: `Enabled` → Available, `Disabled` → Unavailable,
      `Warned`/`PastDue` → Pending, `Deleted` → Terminated);
   3. else stateless (dim `○`, blank label): resource groups, VNets,
      subnets, NSGs, vaults.
   The label is always the native word lowercased (`native_state_label`),
   so the `F` chips read `deallocated`, `unattached`, `upgrading`.
2. **VM power state is on the row.** The VM list is two subscription-wide
   calls: the model pages stream in with a blank state, then the same list
   with `statusOnly=true` fills the power state, merged by id, delivered
   as one replacement. If the second call fails the rows stay, with a
   load warning. The Instance view section stays lazy for the rest.
3. **Jumps** are one function, ARM id → `NavLocation`, routing on the id's
   `providers/{namespace}/{type}` segment (`JumpView::for_arm_id`); a
   resource-group id lands on Resource Groups, a bare subscription id on
   Subscriptions. The user presses it in a **Related** section every type
   carries (non-lazy, derived from the list body): Subscription and
   Resource group first, then the type's own targets; Enter on a line
   jumps. An id whose type nebaz does not browse (public IP, route table)
   still lists; Enter copies it with a toast. Enter on any other ARM-id
   valued line in the pane does the same, so the Networking and Storage
   sections of a VM jump too.
4. **Key Vault names come from ARM** (`Secrets_List`, `Keys_List`): the
   control-plane token, Reader suffices, values never returned by
   construction. Both section bodies open with "names and attributes from
   ARM; values are never fetched". No certificates (no ARM list).
5. **Noise**: only subscriptions whose state is not `Enabled`. Every other
   type is false in the first release.
6. **Embedded children** (subnets, node pools) are named `parent/child`
   on their own sub-tab (`vnet-prod/default`, `aks-prod/system`), bare
   inside the parent's section; `search_text` carries both. They
   **inherit the parent's location** for the `R` filter (the ADR's
   "rows with no location are never filtered" still holds; embedded rows
   simply get one). Lazy children (containers, secret and key names) are
   section lines, never rows, so they carry no `cli_command`; the section
   footer names the read command.
7. **One call, two sub-tabs**: VNets/Subnets and Clusters/Node pools are
   two cache entries from the same list; switching sub-tab refetches
   (Network reads allow 10,000 per 5 min; AKS is a handful of rows).
   Cross-filling both variants from one call is a later nicety.
8. **AKS node pools need no lazy call**: the list's `agentPoolProfiles`
   is the full agent-pool property set (autoscale bounds, power state,
   node image version, current version). Ticket 04's "node-pool detail"
   lazy child is dropped; if the Azure machine's raw JSON lacks those
   fields it comes back as a lazy Detail section per cluster.

### The catalog

Every type: Overview first, Related second to last, Tags last; ⧗ marks a
lazy section; every `az` command is `show --ids {id}` unless stated.

| Service · sub-tab | Sections between Overview and Related | State | Related (after Subscription, Resource group) | `az` |
|---|---|---|---|---|
| Subscriptions · Subscriptions | Details ⧗ · Locations ⧗ · Tags (from Details) | subscription state; noise unless `Enabled` | — (root) | `az account show --subscription {id}` |
| Subscriptions · Resource Groups | — | stateless when `Succeeded` | `managedBy` id when set | `az group show -n {name} --subscription {sub}` |
| Virtual Machines · VMs | Instance view ⧗ (agent, OS, boot diagnostics, disk statuses) · Networking (NICs, primary) · Storage (OS disk, data disks with LUN, size) | power state | each NIC, OS and data disks, availability set | `az vm show` |
| Virtual Machines · Disks | — | `diskState` | `managedBy` VM | `az disk show` |
| Virtual Machines · NICs | IP configurations (name, private IP, allocation, primary, public IP) | attached / unattached | VM, NSG, each IP config's subnet and public IP | `az network nic show` |
| Storage · Accounts | Endpoints · Security (public blob access, shared key, min TLS, HTTPS only, public network access, network default action, encryption key source, HNS) · Containers ⧗ | `statusOfPrimary` | — | `az storage account show` |
| Network · VNets | Subnets (embedded) · Peerings | stateless | each subnet, each peered VNet | `az network vnet show` |
| Network · Subnets | — (Overview: prefix, NSG, route table, NAT gateway, delegations, service endpoints, IP configuration count) | stateless | VNet, NSG, route table, NAT gateway | `az network vnet subnet show` |
| Network · NSGs | Inbound · Outbound (custom rules by priority, then default rules dimmed) · Used by (NICs, subnets) | stateless | each associated subnet and NIC | `az network nsg show` |
| Key Vault · Vaults | Access (policies, or "Azure RBAC") · Network (default action, bypass, IP and VNet rules, private endpoints) · Secrets ⧗ · Keys ⧗ | stateless | each network-rule subnet | `az keyvault show -n {name} -g {rg} --subscription {sub}` (no `--ids`) |
| AKS · Clusters | Network · Access · Node pools (embedded) · Add-ons | ladder, then `powerState` | node resource group | `az aks show -n {name} -g {rg} --subscription {sub}` (no `--ids`) |
| AKS · Node pools | — (Overview: mode, count, size, OS, versions, node image, autoscale, max pods, zones, priority, power, taints, labels) | ladder on the pool's fields | Cluster | `az aks nodepool show --cluster-name {cluster} -g {rg} -n {pool} --subscription {sub}` (no `--ids`) |

### API calls per view (input to ticket 07's allowlist and the watch-mode decision)

All `GET`, all under `/subscriptions/{sub}`; paged with `nextLink`.

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
| Vaults | 1 | `/providers/Microsoft.KeyVault/vaults` · `2024-11-01` |
| Secrets, Keys | 1 each per vault, on demand | `{vault}/secrets` · `{vault}/keys` · `2026-05-15` |
| Clusters, Node pools | 1 each (same list) | `/providers/Microsoft.ContainerService/managedClusters` · `2026-06-01` |

A full tour of every sub-tab in one subscription is 11 list calls; only
the Accounts view and its Containers sections touch the throttled Storage
budget, so a watch mode needs a floor only there.

### Verified on the Azure machine (2026-09-23)

- VM rows show their power state: the `statusOnly=true` pass works as
  documented. Whether it also carries the full model (one call instead of
  two) is still unchecked; the two-call form stays.
- `az keyvault show`, `az aks show` and `az aks nodepool show` do **not**
  take `--ids`; the copied commands use the name form with
  `--subscription` (the table above is corrected).
- The api-versions were accepted (rows rendered for the services tried).

Still to check: the embedded `agentPoolProfiles` carry autoscale and
power fields (rule 8), on a subscription with an AKS cluster.

### Inputs to later tickets

- **Read-only guarantee mechanism**: the call table above is the
  allowlist; every path is a `GET` through `ArmClient::get_request`.
- **First-release spec**: this answer is the service section verbatim.
