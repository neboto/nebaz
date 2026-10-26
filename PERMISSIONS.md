# Azure permissions

nebaz is **read-only**: every request it sends is an HTTP `GET` to Azure
Resource Manager (ARM), or to Microsoft Graph for directory objects
(ADR 0004), nothing else; the one exception is not to Azure at all, the
daily update check (see [Update check](#update-check)). Three layers hold
that promise:

1. **Runtime** — the one request constructor in `src/azure/arm.rs` only
   builds `GET`s, and the pipeline's `ReadOnlyPolicy` refuses any other
   method before it leaves the process.
2. **Guard test** — `tests/readonly_guard.rs` fails `cargo test` (and so
   CI) if the source gains another request builder, an HTTP client crate,
   a data-plane host, a Graph host outside `src/azure/graph.rs`, Graph's
   `getByIds` (a `POST`) or a Graph `$select`, a non-Azure host or a
   tokenless GET outside the update check, a mutating `az`
   command outside the `C` catalogue (ADR 0005: copied, never run), a
   destructive or secret-revealing `az` command anywhere, or a non-read
   action in this file.
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

## Directory read (Microsoft Graph)

Principal names in Access (and, with issue #78, service principals and app
registrations) come from Microsoft Graph `GET`s made as the same `az login`
identity. They need **directory read** in the subscription's tenant, which
every member user has by default; no Graph permission is granted to
anything and no admin consent is involved (the Azure CLI's own token is
used). Guests, and tenants that restrict members' directory access, get a
`403`: the section says "directory read not allowed for this account" and
shows object ids, and nothing else is affected.

The Graph calls (all `GET`, all under `/v1.0`):

- `directoryObjects/{id}`: one per principal id in an Access section,
  cached for the session, at most 50 per section (and the APIs a service
  principal's grants point at);
- `servicePrincipals?$filter=servicePrincipalType eq 'ManagedIdentity'`
  and `servicePrincipals?$filter=appOwnerOrganizationId eq {tenant}`
  (an advanced query: `$count=true`, `ConsistencyLevel: eventual`): the
  Service principals sub-tab;
- `applications`: the App registrations sub-tab;
- `{applications|servicePrincipals}/{id}/owners`,
  `applications/{id}/federatedIdentityCredentials`,
  `servicePrincipals/{id}/appRoleAssignments`,
  `servicePrincipals/{id}/oauth2PermissionGrants`: lazy sections;
- `servicePrincipals(appId='{appId}')`: an app registration's APIs, named,
  and (with `directoryObjects/{id}`) an `@changes` caller's kind: at most
  50 per load.

A credential's value is never shown: Graph returns no `secretText` to a
`GET`, nebaz never `$select`s (so a certificate's `key` stays null), and
the `hint` is not displayed.

Never sent: `directoryObjects/getByIds` (a `POST`), `addPassword` /
`addKey` (the only calls that return a secret value), and any `$select`
(selecting `keyCredentials` would return the certificate's key).

## Per-service actions

Every action is an ARM control-plane `…/read`. The path and api-version
each one backs are in the catalog table
(`.scratch/nebaz/issues/06-service-catalog-first-six.md`).

- **Subscriptions + Resource Groups**: the subscription list itself comes
  from `az account list` (local, no ARM call). Details and Locations:
  `Microsoft.Resources/subscriptions/read`,
  `Microsoft.Resources/subscriptions/locations/read`. Resource groups:
  `Microsoft.Resources/subscriptions/resourceGroups/read`. All resources:
  `Microsoft.Resources/subscriptions/resources/read` (the generic list:
  ids, types, SKUs and tags, never a resource's properties).
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
  `Microsoft.Network/privateEndpoints/read`; Bastion hosts:
  `Microsoft.Network/bastionHosts/read`; DDoS protection plans:
  `Microsoft.Network/ddosProtectionPlans/read`. Appliance next hops are
  matched in lists already read: no action of their own.
- **DNS**: private DNS zones:
  `Microsoft.Network/privateDnsZones/read`, and the lazy Records and VNet
  links sections: `Microsoft.Network/privateDnsZones/ALL/read`,
  `Microsoft.Network/privateDnsZones/virtualNetworkLinks/read`. Public DNS
  zones: `Microsoft.Network/dnszones/read`, and the lazy Records section:
  `Microsoft.Network/dnszones/all/read`. DNS Private Resolver:
  `Microsoft.Network/dnsResolvers/read`,
  `Microsoft.Network/dnsResolvers/inboundEndpoints/read`,
  `Microsoft.Network/dnsResolvers/outboundEndpoints/read`; forwarding
  rulesets: `Microsoft.Network/dnsForwardingRulesets/read`,
  `Microsoft.Network/dnsForwardingRulesets/forwardingRules/read`,
  `Microsoft.Network/dnsForwardingRulesets/virtualNetworkLinks/read`; DNS
  security policies: `Microsoft.Network/dnsResolverPolicies/read`,
  `Microsoft.Network/dnsResolverPolicies/dnsSecurityRules/read`,
  `Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks/read`. The
  VNet ⇄ resolver lookups the resolver API offers
  (`virtualNetworks/listDnsResolvers`, `listDnsForwardingRulesets`) are
  `POST`s and are never sent; the links are gathered from the `GET`s above.
  The network access lens (`N`) needs nothing more: it reads NICs, VNets
  and NSGs with the actions above and computes the rules itself, because a
  NIC's effective rules and routes are POST actions nebaz never calls.
- **Edge** (application gateways, Front Door, WAF policies):
  `Microsoft.Network/applicationGateways/read` (frontends, listeners,
  rules, pools, settings and probes arrive embedded),
  `Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read`,
  `Microsoft.Network/frontDoorWebApplicationFirewallPolicies/read`,
  `Microsoft.Cdn/profiles/read`; a Front Door profile's lazy topology:
  `Microsoft.Cdn/profiles/afdendpoints/read`,
  `Microsoft.Cdn/profiles/afdendpoints/routes/read`,
  `Microsoft.Cdn/profiles/origingroups/read`,
  `Microsoft.Cdn/profiles/origingroups/origins/read`,
  `Microsoft.Cdn/profiles/customdomains/read`,
  `Microsoft.Cdn/profiles/securitypolicies/read`. A gateway's backend
  health is a `POST` (`…/backendhealth`), outside `Reader`, that nebaz never
  sends (the guard refuses the literal; `C` copies the CLI command for you
  to run). A gateway certificate's `data` and `password`, the certificate
  blobs beside them and a custom domain's validation token are stripped
  before the row keeps the JSON; Front Door `secrets` are never listed, and
  `az network application-gateway ssl-cert`, `root-cert` and `az afd secret`
  are named forbidden. The Front Door endpoints' own hosts are on the
  guard's list.
- **Key Vault**: `Microsoft.KeyVault/vaults/read`; the lazy Secrets and Keys
  sections: `Microsoft.KeyVault/vaults/secrets/read`,
  `Microsoft.KeyVault/vaults/keys/read`. These are control-plane actions:
  they return names and attributes only. Certificates are not listed.
- **Referenced by** (`U`): no action of its own. It reads the list caches
  already loaded; its `L` key runs the ordinary list loads of the lists it
  names, with those lists' actions above.
- **Ownership ribbon** (every type): `Microsoft.Resources/deployments/read`,
  `Microsoft.Resources/deployments/operations/read` (the resource group's
  deployments and, for the newest unfinished ones, their operations).
  Without them the ribbon says `⚠ deployments: …` and keeps the rest.
- **Access** (every type, and an identity's Can do):
  `Microsoft.Authorization/roleAssignments/read`,
  `Microsoft.Authorization/roleDefinitions/read`. Principal names come
  from Microsoft Graph (directory read, above); without it a principal is
  its type and object id.
- **Activity** (every type): `Microsoft.Insights/eventtypes/values/read`.
  Only named fields are selected; the caller's token claims and request
  bodies are never fetched.
- **Metrics** (`m`, any ARM resource): `Microsoft.Insights/metrics/read`
  and, for the all-metrics picker, `Microsoft.Insights/metricDefinitions/read`.
  Both are control-plane `GET`s on the resource's own id (platform
  metrics only; no log query); a 403 is a line in the view, never fatal.
- **Change timeline** (`W`, any ARM row): the Activity log action
  above, `Microsoft.AlertsManagement/alerts/read` (fired alerts),
  `Microsoft.ResourceHealth/availabilityStatuses/read` (the health
  history) and `Microsoft.Resources/deployments/read` (the group's
  deployments: their state, what they deployed and their error; nebaz
  never shows a deployment's parameters or outputs). Each source that
  is denied is a note in the view.
- **Changes** (`@changes`, subscription-wide): the Activity log action
  above, `Microsoft.ResourceHealth/availabilityStatuses/read` and
  `Microsoft.Resources/deployments/read` at subscription scope. Callers
  are classified through Graph (`directoryObjects/{id}`, then
  `servicePrincipals(appId='{id}')`), with directory read as above;
  without it, callers stay unclassified. Resource Graph's
  `resourcechanges` is a `POST` and is never sent.
- **Power Platform**: `Microsoft.PowerPlatform/enterprisePolicies/read`.
  Environments and their policy links are in the Power Platform admin
  API, not ARM: nebaz never calls it, and its hosts are on the guard's
  list.
- **Managed Identity**: `Microsoft.ManagedIdentity/userAssignedIdentities/read`;
  the lazy Federated credentials section:
  `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read`.
  The Can do section reads role assignments (below).
- **AKS**: `Microsoft.ContainerService/managedClusters/read` (node pools
  arrive embedded as `agentPoolProfiles` in the same list).
- **Container Registry**: `Microsoft.ContainerRegistry/registries/read`;
  the lazy Replications and Webhooks sections:
  `Microsoft.ContainerRegistry/registries/replications/read`,
  `Microsoft.ContainerRegistry/registries/webhooks/read`. Repositories and
  tags are data plane (the registry's login server is on the guard's
  list); admin credentials (`listCredentials`) and a webhook's service URI
  (`getCallbackConfig`) are `POST` actions nebaz never sends.
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
- **Redis**: `Microsoft.Cache/redis/read` (Azure Cache for Redis),
  `Microsoft.Cache/redisEnterprise/read` (Managed Redis); the lazy
  sections: `Microsoft.Cache/redis/firewallRules/read`,
  `Microsoft.Cache/redis/linkedServers/read`,
  `Microsoft.Cache/redisEnterprise/databases/read`. Access keys are the
  `listKeys` `POST` on both types, never sent (`az redis list-keys` and
  `az redisenterprise database list-keys` are named forbidden); the
  caches' own hosts are on the guard's list.
- **PostgreSQL & MySQL** (flexible servers):
  `Microsoft.DBforPostgreSQL/flexibleServers/read` and
  `Microsoft.DBforMySQL/flexibleServers/read`; the lazy Databases,
  Firewall, Security (Entra admins) and Parameters sections:
  `Microsoft.DBforPostgreSQL/flexibleServers/databases/read`,
  `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/read`,
  `Microsoft.DBforPostgreSQL/flexibleServers/administrators/read`,
  `Microsoft.DBforPostgreSQL/flexibleServers/configurations/read`,
  `Microsoft.DBforMySQL/flexibleServers/databases/read`,
  `Microsoft.DBforMySQL/flexibleServers/firewallRules/read`,
  `Microsoft.DBforMySQL/flexibleServers/administrators/read`,
  `Microsoft.DBforMySQL/flexibleServers/configurations/read`. The admin
  password is write-only and MySQL's import SAS token create-only; both
  are stripped from the body before the row keeps it. nebaz never
  connects to a server (the server endpoints are on the guard's list).
- **Cosmos DB**: `Microsoft.DocumentDB/databaseAccounts/read`; the lazy
  Databases section, one of (the account's API picks):
  `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/read`,
  `Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/read`,
  `Microsoft.DocumentDB/databaseAccounts/cassandraKeyspaces/read`,
  `Microsoft.DocumentDB/databaseAccounts/gremlinDatabases/read`,
  `Microsoft.DocumentDB/databaseAccounts/tables/read`. Keys, read-only keys
  and connection strings are `POST` actions nebaz never sends; the
  document endpoints are on the guard's list, and `az cosmosdb keys` is
  named forbidden.
- **Monitor**: `Microsoft.OperationalInsights/workspaces/read`,
  `Microsoft.Insights/components/read`. Metadata only: no log query is
  ever run (the query hosts are on the guard's list), a workspace's shared
  keys are a `POST` nebaz never sends, and a component's instrumentation
  key and connection string, which its `GET` does return, are stripped
  before the row keeps the JSON.
- **Container Apps**: `Microsoft.App/containerApps/read`,
  `Microsoft.App/managedEnvironments/read`, `Microsoft.App/jobs/read`; the
  lazy Revisions and Auth sections:
  `Microsoft.App/containerApps/revisions/read`,
  `Microsoft.App/containerApps/authConfigs/read`; a job's Executions:
  `Microsoft.App/jobs/executions/read`. Secret values
  (`listSecrets`) are a `POST` nebaz never sends; secret and env var values
  a `GET` body does carry, and an environment's shared keys and connection
  strings, are stripped before the row keeps the JSON. The apps' own
  hosts are on the guard's list, and `az containerapp secret` is named
  forbidden.
- **Messaging** (Service Bus, Event Hubs):
  `Microsoft.ServiceBus/namespaces/read`,
  `Microsoft.EventHub/namespaces/read`; the lazy sections:
  `Microsoft.ServiceBus/namespaces/networkrulesets/read`,
  `Microsoft.ServiceBus/namespaces/authorizationRules/read`,
  `Microsoft.ServiceBus/namespaces/queues/read`,
  `Microsoft.ServiceBus/namespaces/topics/read`,
  `Microsoft.EventHub/namespaces/networkrulesets/read`,
  `Microsoft.EventHub/namespaces/authorizationRules/read`,
  `Microsoft.EventHub/namespaces/eventhubs/read`. Access policies show
  names and rights only: their keys and connection strings come only from
  `listKeys`, a `POST` nebaz never sends (the guard also refuses the
  literal), and any key-shaped field a `GET` body might carry is stripped
  before the row keeps the JSON. The namespaces' own hosts (both
  providers share one suffix) are on the guard's list, and every
  `az servicebus … authorization-rule keys` and
  `az eventhubs … authorization-rule keys` chain is named forbidden.
- **Foundry** (every Cognitive Services account, Azure OpenAI included):
  `Microsoft.CognitiveServices/accounts/read`; the lazy Deployments and
  Projects sections: `Microsoft.CognitiveServices/accounts/deployments/read`,
  `Microsoft.CognitiveServices/accounts/projects/read`. Keys (`listKeys`)
  are a `POST` nebaz never sends, and no model is ever called: the AI
  data-plane hosts are on the guard's list, and
  `az cognitiveservices account keys` is named forbidden.
- **`@audit`**: no action of its own. Its checks read lists and sections
  already loaded (ADR 0007); `r` there runs the same list loads and lazy
  reads listed above for Network, Storage, Key Vault, SQL (servers and
  firewall rules), Cosmos DB, AKS, Container Registry, App Service (sites
  and `config/web`), Container Apps, Redis (caches, Managed Redis and cache
  firewall rules), PostgreSQL and MySQL (servers, and each one's firewall
  rules, parameters and Entra admins), Service Bus and Event Hubs (namespaces and their
  network rule sets), Power Platform, the subscription's
  Access list, and the Graph directory reads (app registrations, service
  principals, principal names). A denied one leaves its checks "not
  checked". `nebaz audit` makes the same calls.

## Update check

The only request nebaz makes that isn't to Azure (ADR 0008): once a day,
an anonymous `GET https://api.github.com/repos/neboto/nebaz/releases/latest`
to show a dim `↑ vX.Y.Z` chip when a newer release is out. It goes through
the same `azure_core` pipeline and `ReadOnlyPolicy` as every ARM call, with
**no** token (the pipeline has no bearer policy), a 3 s timeout and no
retries; a failure is silent. The answer is cached in
`~/.cache/nebaz/update-check.json`. It needs no Azure permission. Turn it
off with `update_check = false` in the config, `--no-update-check`, or
`NEBAZ_NO_UPDATE_CHECK=1`; it never runs with `CI` set or for the headless
subcommands.

## Local commands

nebaz runs two `az` commands itself, both reads of the CLI's own state:

- `az account list` — the subscription picker (all tenants the CLI is
  logged in to);
- `az account get-access-token --scope … --tenant …` — run by
  `azure_identity` to mint the ARM token (and, for directory reads, the
  Graph token) for the current tenant.

`C` copies an `az` command to the clipboard for you to run; nebaz never
executes it. The picker (#47, ADR 0005) offers **Inspect** commands
(reads), **Connect** commands (`ssh vm`, `aks get-credentials`,
`containerapp exec`, `acr login`) and **Change** commands (start, stop,
restart, deallocate, scale), the last under a `⚠ changes Azure` heading.
A pasted command runs under **your** `az login` with **your** roles, not
under the `Reader` role above: Connect and Change commands need more
(a VM login role, a VM's start action, …),
and nebaz grants none of it. Nothing destructive (delete, purge, remove,
reset, regenerate, run-command, update, …) and nothing that prints a
credential (`--admin`, `--expose-token`, account keys, connection
strings, `acr credential`) is ever offered; the guard refuses them even
in the catalogue. `az keyvault secret show` and `key show` are
never generated (the guard names them forbidden); the vault sections name
`az keyvault secret list` / `key list`, which return names only.
