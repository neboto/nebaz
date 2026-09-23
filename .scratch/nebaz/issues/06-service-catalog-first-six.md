# 06 — Service catalog for the first six services

Type: grilling
Status: open
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
