# Azure permissions

nebaz is **read-only**: every request it sends is an HTTP `GET` to Azure
Resource Manager (ARM), nothing else. Three layers hold that promise:

1. **Runtime** — the one request constructor in `src/azure/arm.rs` only
   builds `GET`s, and the pipeline's `ReadOnlyPolicy` refuses any other
   method before it leaves the process.
2. **Guard test** — `tests/readonly_guard.rs` fails `cargo test` (and so
   CI) if the source gains another request builder, an HTTP client crate,
   a data-plane host, a mutating `az` command, or a non-read action in this
   file.
3. **RBAC** — the role below is a pure `*/read` footprint, so the
   subscription itself cannot be changed through nebaz even if the first
   two layers failed.

## The role

Assign the built-in **`Reader`** role at **subscription** scope to the
identity `az login` signed in as, for every subscription you want to
browse. That is the whole requirement: `Reader` grants every action listed
below and nothing more. No Key Vault data-plane role (`Key Vault Reader`,
`Key Vault Secrets User`) and no vault access policy is needed, because
nebaz lists secret and key **names** through ARM's control-plane actions,
which never return a value.

Subscriptions the identity cannot read still appear in the `P` picker (the
list comes from `az account list`); their lists fail with an authorisation
error and nothing else.

To build a narrower custom role, grant exactly the actions below.

## Per-service actions

Every action is an ARM control-plane `…/read`. The path and api-version
each one backs are in the catalog table
(`.scratch/nebaz/issues/06-service-catalog-first-six.md`).

- **Subscriptions + Resource Groups**: the subscription list itself comes
  from `az account list` (local, no ARM call). Details and Locations:
  `Microsoft.Resources/subscriptions/read`,
  `Microsoft.Resources/subscriptions/locations/read`. Resource groups:
  `Microsoft.Resources/subscriptions/resourceGroups/read`.
- **Virtual Machines**: `Microsoft.Compute/virtualMachines/read` (the list,
  and the `statusOnly=true` pass that puts the power state on the row),
  `Microsoft.Compute/virtualMachines/instanceView/read` (Instance view
  section); Disks: `Microsoft.Compute/disks/read`; NICs:
  `Microsoft.Network/networkInterfaces/read`.
- **Storage**: `Microsoft.Storage/storageAccounts/read`; the lazy
  Containers section: `Microsoft.Storage/storageAccounts/blobServices/containers/read`
  (container metadata through ARM, never a blob).
- **Virtual Networks**: `Microsoft.Network/virtualNetworks/read` (subnets
  and peerings arrive embedded in the same list; the Subnets sub-tab needs
  nothing more); NSGs: `Microsoft.Network/networkSecurityGroups/read`;
  public IPs: `Microsoft.Network/publicIPAddresses/read`; load balancers:
  `Microsoft.Network/loadBalancers/read` (frontends, pools, rules and
  probes arrive embedded); route tables: `Microsoft.Network/routeTables/read`;
  NAT gateways: `Microsoft.Network/natGateways/read`; private endpoints:
  `Microsoft.Network/privateEndpoints/read`; private DNS zones:
  `Microsoft.Network/privateDnsZones/read`, and the lazy Records and VNet
  links sections: `Microsoft.Network/privateDnsZones/ALL/read`,
  `Microsoft.Network/privateDnsZones/virtualNetworkLinks/read`.
- **Key Vault**: `Microsoft.KeyVault/vaults/read`; the lazy Secrets and Keys
  sections: `Microsoft.KeyVault/vaults/secrets/read`,
  `Microsoft.KeyVault/vaults/keys/read`. These are control-plane actions:
  they return names and attributes only. Certificates are not listed.
- **Managed Identity**: `Microsoft.ManagedIdentity/userAssignedIdentities/read`;
  the lazy Federated credentials section:
  `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read`.
  Role assignments (what an identity can do) are not read.
- **AKS**: `Microsoft.ContainerService/managedClusters/read` (node pools
  arrive embedded as `agentPoolProfiles` in the same list).
- **App Service**: `Microsoft.Web/sites/read` (web, function and logic
  apps), `Microsoft.Web/serverfarms/read` (plans); the lazy Configuration
  section: `Microsoft.Web/sites/config/read` (`config/web` only). App
  settings, connection strings, publishing credentials and function keys
  are all `POST` actions nebaz never sends; the guard names the `az`
  commands that would print them.
- **SQL**: `Microsoft.Sql/servers/read`; the lazy Databases and
  Firewall sections: `Microsoft.Sql/servers/databases/read`,
  `Microsoft.Sql/servers/firewallRules/read`. Metadata only: nebaz never
  connects to a database (the server endpoints are on the guard's list).
- **Foundry** (every Cognitive Services account, Azure OpenAI included):
  `Microsoft.CognitiveServices/accounts/read`; the lazy Deployments and
  Projects sections: `Microsoft.CognitiveServices/accounts/deployments/read`,
  `Microsoft.CognitiveServices/accounts/projects/read`. Keys (`listKeys`)
  are a `POST` nebaz never sends, and no model is ever called: the AI
  data-plane hosts are on the guard's list, and
  `az cognitiveservices account keys` is named forbidden.

## Local commands

nebaz runs two `az` commands itself, both reads of the CLI's own state:

- `az account list` — the subscription picker (all tenants the CLI is
  logged in to);
- `az account get-access-token --scope … --tenant …` — run by
  `azure_identity` to mint the ARM token for the current tenant.

`C` copies an `az … show` / `az … list` command to the clipboard for you to
run; nebaz never executes it. `az keyvault secret show` and `key show` are
never generated (the guard names them forbidden); the vault sections name
`az keyvault secret list` / `key list`, which return names only.
