# Demo mode

`nebaz --demo` browses a made-up, offline Azure tenant: no `az`, no login,
no network. It is for trying nebaz without an Azure account, for the
README's recordings (`demo/`), and as an offline end-to-end check of every
screen (`src/headless/demo_tests.rs`).

```bash
nebaz --demo                 # the TUI, on contoso-prod
nebaz --demo -s aca          # straight to Container Apps
nebaz --demo ls nsg          # headless works too
nebaz --demo audit
NEBAZ_DEMO_TRACE=/tmp/t nebaz --demo get <ARM id>   # what each request was answered with
```

## How it works

Demo mode is a credential source (`auth = "demo"`; `--demo` sets it).
`ArmClient::build` gives a demo pipeline a fixed token and
`src/demo`'s transport in place of the network, under the same
`ReadOnlyPolicy`. Nothing above the pipeline knows, so a screen gets demo
coverage by adding a **fixture**, never code. The guard's rule 6 keeps the
transport canned.

- **Fixtures** are real ARM / Graph response bodies under
  `src/demo/fixtures/<area>/`, registered in `src/demo/fixtures/<area>.rs`
  with `fx!("<area>", "<path pattern>", "<file>.json")`. The pattern is the
  request path, `*` matching one segment, case-insensitive; `when [..]`
  narrows by substrings of the decoded query (a `$filter`), `status 404`
  answers an error body. First match wins, so narrow before broad.
- **Placeholders** in bodies and patterns: `{{prod}}`, `{{dev}}`,
  `{{tenant}}` (the ids below), `{{iso:now-15m}}` / `{{iso:now+6d}}` (units
  `s m h d`) so the story never ages.
- **Computed** responses (`src/demo/generate.rs`): metric series and the
  All resources lists, which are derived from every other fixture so they
  can never disagree with them.
- **No fixture**: a collection answers `{"value": []}`, a single resource
  `404 ResourceNotFound` (what Azure says for "none"); the list pane says
  "Not in the demo dataset yet".
- **Finding what a screen asks for**: run it with `NEBAZ_DEMO_TRACE=<file>`;
  every `EMPTY` / `404` line is a request no fixture answered.
- **Tests**: `src/demo/tests.rs` (every fixture is JSON, every file is
  registered); `src/headless/demo_tests.rs` (every sub-tab lists rows and
  every row opens without a `⚠`, with two lists that only shrink).

## The story

**Contoso** runs an orders platform on **Azure Container Apps** in
`contoso-prod`. A vendor, **Fabrikam**, connects **Power Platform** to it
through VNet injection: Power Platform's enterprise policy injects into a
delegated subnet of the hub VNet and calls the orders API on the Container
Apps environment's internal ingress. It worked until two hours ago.

The incident the demo is built around (`@changes`, then `W`, then `N`):

1. **2h10m ago** `alex.kim@contoso.com` added `DenyAllOutbound` (priority
   4000, "lockdown per security review") to `nsg-pp-injection`, the NSG
   on Power Platform's delegated subnet. It sits ahead of the default
   `AllowVnetOutBound` (65000), so the injected connector can no longer
   reach `cae-orders-prod` (10.10.0.62:443).
2. **1h50m ago** the alert `orders-api-requests-dropped` fired: requests to
   `ca-orders-api` fell to almost nothing (its `Requests` metric shows the
   cliff). The app itself is healthy.
3. **25m ago** the `github-actions-deploy` service principal rolled out
   `ca-orders-worker` revision `ca-orders-worker--v119` with image
   `orders-worker:1.19.0`, a tag that was never pushed to `acrcontosoprod`:
   the revision failed and Resource Health says Degraded. Unrelated, but it
   is what everyone looks at first.

`N` from `snet-pp-injection` to `cae-orders-prod` shows the deny;
`@changes` shows who and when; `W` on `nsg-pp-injection` shows the rule
change next to the alert.

Planted findings, one per thing a screen or `@audit` shows off:

| What | Where it shows |
|---|---|
| `nsg-jump-prod` allows SSH from the Internet ("temp vendor access", added 3 days ago by the Fabrikam guest `j.ortiz_fabrikam.com#EXT#`) | `@audit`, `N`, `W` |
| `vm-jump-01` has a public IP | `@audit`, Related |
| `disk-legacy-data-01`: 1 TiB Premium SSD, unattached | Disks state, `@audit` |
| `vm-legacy-app-01` deallocated for 40 days | VMs state |
| `stcontosoordersprod` allows blob public access, minimum TLS 1.0 | `@audit` |
| `privatelink.blob.core.windows.net` has the PE's A record but no link to `vnet-hub-prod`: the blob PE resolves publicly | DNS topology |
| The Container Apps environment's private zone is linked to `vnet-hub-prod` but not to Power Platform's failover VNet `vnet-pp-dr` | DNS topology |
| `kv-legacy-prod`: public network on, purge protection off, access policies (not RBAC) — `kv-orders-prod` is the good contrast | `@audit` |
| `sql-orders-prod` firewall rule `AllowAll-temp` 0.0.0.0–255.255.255.255 | `@audit` |
| `acrcontosoprod` admin user enabled | `@audit` |
| `aks-platform-prod` runs Kubernetes 1.28 (out of support), local accounts on, public API server with no authorized ranges; node pool `batch` failed to scale | AKS, `@audit` |
| `app-legacy-portal`: HTTPS-only off, TLS 1.0, FTP allowed | `@audit` |
| `cosmos-legacy`: public network, key auth on | `@audit` |
| `redis-orders-cache`: non-TLS port 6379 enabled | `@audit` |
| `agw-contoso-prod`'s WAF policy is in Detection mode | Edge, `@audit` |
| `mysql-reporting-legacy`: public access, `require_secure_transport` OFF | `@audit` |
| `sb-orders-prod` queue `orders` has 1,284 dead-lettered messages; local auth on | Messaging |
| `ai-contoso-prod` (Foundry): public network and key auth on | `@audit` |
| `github-actions-deploy` has Contributor on the **subscription** (granted yesterday by alex) | Access, `@changes` |
| App registration `orders-api-client`: one client secret expires in 6 days, one expired last month, no owners | `@appreg` |
| The Fabrikam guest has Contributor on `rg-orders-prod` | Access |
| `caj-nightly-export`'s last execution failed | Jobs |
| `vnet-hub-prod` peers with `vnet-dev` in **contoso-dev** (a cross-subscription jump) | Related |
| `snet-pp-injection-dr`, Power Platform's failover subnet in `vnet-pp-dr`, has no NSG | `@audit` |

## Ids

| | |
|---|---|
| Tenant | `{{tenant}}` = `a1c3e5f7-2b4d-4f6a-8c0e-1d3f5a7b9c2e`, `contoso.onmicrosoft.com` |
| contoso-prod | `{{prod}}` = `8f4c2a1e-6b3d-4e7a-9c15-2d8e0f6a7b31` (default) |
| contoso-dev | `{{dev}}` = `3b9e7d52-1a4f-4c8b-b2e6-7f0a9d1c5e48` |
| Fabrikam tenant (the vendor's) | `5b888731-5714-47aa-9f0a-d158b563fcb6` |

Locations: `westeurope` (primary), `northeurope` (Power Platform's paired
failover; Power Platform's `europe` geography wants both), `global`
(DNS zones, Front Door).

Directory objects (Graph object ids; `appId` where it has one):

| Object | Object id | appId |
|---|---|---|
| user `alex.kim@contoso.com` (Owner on the subscription) | `8851538f-3984-4858-a0fd-773a4f49a810` | |
| guest `j.ortiz_fabrikam.com#EXT#@contoso.onmicrosoft.com` | `e37ad877-49b0-4f5a-b333-31c5f278f12f` | |
| app registration `github-actions-deploy` | `4087b8f1-0c36-436a-a23c-1868b3c7fb86` | `edc89266-a363-4046-9c6e-e0629dfedbad` |
| its service principal | `f5233913-f487-4d23-b621-98c7511347d1` | `edc89266-a363-4046-9c6e-e0629dfedbad` |
| app registration `orders-api-client` | `65269b0d-f929-40b3-a28d-a281b6b6503b` | `7b985643-85cc-4880-8e95-9dac694b9dfc` |
| its service principal | `47302d33-ba06-4194-bc89-bec920f2a564` | `7b985643-85cc-4880-8e95-9dac694b9dfc` |
| service principal `Fabrikam Orders Connector` (multi-tenant, owned by the Fabrikam tenant) | `80303294-4904-46c2-87a0-d8cb283aa2a9` | `600d5263-b150-479c-ab05-60929b2edcbd` |
| user-assigned identity `id-orders-api` (principal) | `535edf48-335f-4761-b6ed-e0613ed690b3` | client id `a486b752-7257-42ba-bc16-23a4e0381f56` |
| `ca-orders-worker`'s system-assigned identity | `51b687b3-bdb3-4408-b436-500e659cc8cb` | |
| `aks-platform-prod`'s kubelet identity `aks-platform-prod-agentpool` | `37ec34fc-62c5-4180-a17f-0cccd5ed2e95` | |
| group `Contoso Platform Admins` | `e1a8fb8b-9024-4a39-abf4-cc2a5c73b98d` | |

A new object id: any fresh `uuid4`, added to this table.

## Resources

ARM ids are `/subscriptions/{{prod}}/resourceGroups/<rg>/providers/<type>/<name>`.
Everything is in `westeurope` unless it says otherwise. Tags on most
things: `env` (`prod`/`dev`), `team` (`orders`, `platform`, `data`,
`legacy`), `owner`; `costCenter` on some.

### contoso-prod

**`rg-network-prod`** (team platform)
- `vnet-hub-prod` 10.10.0.0/16, peered with `vnet-dev` (contoso-dev) and with `vnet-pp-dr`. Subnets:
  - `snet-aca` 10.10.0.0/23, delegated `Microsoft.App/environments`, NSG `nsg-aca`, route table `rt-spoke-egress`, NAT gateway `ng-prod`
  - `snet-pp-injection` 10.10.4.0/24, delegated `Microsoft.PowerPlatform/enterprisePolicies`, NSG `nsg-pp-injection`
  - `snet-pe` 10.10.5.0/24, private endpoints
  - `snet-appgw` 10.10.6.0/24, `agw-contoso-prod`, NSG `nsg-appgw-prod`
  - `snet-data` 10.10.7.0/24, delegated `Microsoft.DBforPostgreSQL/flexibleServers`
  - `snet-jump` 10.10.8.0/27, NSG `nsg-jump-prod`: `nic-vm-jump-01` 10.10.8.4, `nic-vm-legacy-app-01` 10.10.8.5, `lb-legacy-internal`'s frontend `fe-legacy-app` 10.10.8.10
  - `AzureFirewallSubnet` 10.10.9.0/26 (the firewall itself is not in the demo; `rt-spoke-egress` sends 0.0.0.0/0 to 10.10.9.4)
  - `snet-dns-outbound` 10.10.10.0/28, delegated `Microsoft.Network/dnsResolvers` (the resolver's outbound endpoint)
- `vnet-pp-dr` (northeurope) 10.20.0.0/16, peered with `vnet-hub-prod`, subnet `snet-pp-injection-dr` 10.20.4.0/24 delegated `Microsoft.PowerPlatform/enterprisePolicies`, **no NSG**
- NSGs: `nsg-aca` (inbound 443 from 10.10.4.0/24, 10.20.4.0/24 and 10.10.6.0/24), `nsg-pp-injection` (outbound `DenyAllOutbound` 4000, added 2h10m ago), `nsg-jump-prod` (inbound `AllowSSHInbound` 100 from `*`, "temp vendor access"; `AllowRdpFromOnPrem` 110 from 192.168.0.0/16), `nsg-appgw-prod` (GatewayManager 65200–65535, 443 from `AzureFrontDoor.Backend`)
- Public IPs: `pip-agw-prod` (20.103.45.10, DNS label `agw-contoso-prod` → `agw-contoso-prod.westeurope.cloudapp.azure.com`), `pip-ng-prod` (20.103.45.11), `pip-vm-jump-01` (20.103.45.12)
- `ng-prod` (NAT gateway), `rt-spoke-egress`, `lb-legacy-internal` (internal LB in front of `vm-legacy-app-01`: pool `be-legacy-app`, rule `lbr-https` 443)
- Private endpoints (in `snet-pe`): `pe-kv-orders` (vault, 10.10.5.4), `pe-sql-orders` (sqlServer, 10.10.5.5), `pe-st-orders-blob` (blob, 10.10.5.6), `pe-acr-prod` (registry, 10.10.5.7 data endpoint + 10.10.5.8); their NICs `<pe>.nic.<guid>` in this group too
- Private DNS zones (global): `privatelink.vaultcore.azure.net`, `privatelink.database.windows.net`, `privatelink.azurecr.io` (each linked to `vnet-hub-prod` by `link-vnet-hub-prod`), `privatelink.blob.core.windows.net` (**not linked**), `psql-orders-prod.private.postgres.database.azure.com` (`psql-orders-prod`'s VNet-integration zone: A `7f3a9c2e1b4d` → 10.10.7.4 in `snet-data`; linked to `vnet-hub-prod`), and the environment's zone `wonderfulsea-7c1e2a9b.westeurope.azurecontainerapps.io` (`*` and `@` → 10.10.0.62; linked to `vnet-hub-prod`, **not** to `vnet-pp-dr`)
- Public DNS zone `contoso-demo.com` (global): `api` A alias → `pip-agw-prod`, `www` CNAME → the Front Door endpoint (`_dnsauth.www` TXT validates it), MX and SPF
- A DNS private resolver `dnspr-hub-prod` with an outbound endpoint `outbound-onprem` (in `snet-dns-outbound`, no inbound endpoint) and a forwarding ruleset `dnsfrs-onprem` (rule `corp-contoso-com`: `corp.contoso.com.` → 192.168.10.4; linked to `vnet-hub-prod`)
- A DNS security policy `dnssp-hub-prod` (rule `block-malicious-domains` 100 blocks the domain list `dnsdl-malicious-domains`; linked to `vnet-hub-prod`)

**`rg-orders-prod`** (team orders)
- Container Apps environment `cae-orders-prod`: internal, workload profiles (`Consumption`, `D4`), in `snet-aca`, static IP 10.10.0.62, default domain `wonderfulsea-7c1e2a9b.westeurope.azurecontainerapps.io`, logs to `law-contoso-prod`
- `ca-orders-api`: internal ingress 443 → 8080, image `acrcontosoprod.azurecr.io/orders-api:2.31.0`, revision `ca-orders-api--v231` (100%, healthy, 3 replicas), identity `id-orders-api`, secret refs to `kv-orders-prod`
- `ca-orders-worker`: no ingress, system-assigned identity, latest revision `ca-orders-worker--v119` failed (image `orders-worker:1.19.0` not found), previous `ca-orders-worker--v118` still running
- Job `caj-nightly-export`: scheduled `0 2 * * *`, last execution failed
- `id-orders-api` (user-assigned): AcrPull on `acrcontosoprod`, Key Vault Secrets User on `kv-orders-prod`
- `kv-orders-prod`: RBAC, public network disabled, purge protection on, behind `pe-kv-orders`
- `stcontosoordersprod`: StorageV2, behind `pe-st-orders-blob` but public network still enabled, blob public access allowed, TLS 1.0
- `sql-orders-prod` (SQL server) with database `sqldb-orders` (GP_S_Gen5_2), firewall `AllowAll-temp`, behind `pe-sql-orders`
- `psql-orders-prod` (PostgreSQL flexible, 16, VNet-integrated in `snet-data`) — the good one
- `redis-orders-cache` (Standard C1, non-TLS port on)
- `sb-orders-prod` (Service Bus Standard): queue `orders` (1,284 dead-lettered), topic `order-events` with subscription `billing`
- `evh-orders-prod` (Event Hubs namespace): hub `order-telemetry`
- `appi-orders` (App Insights, workspace-based on `law-contoso-prod`), the alert `orders-api-requests-dropped`

**`rg-platform-prod`** (team platform)
- `acrcontosoprod` (Premium, admin user on, behind `pe-acr-prod`)
- `aks-platform-prod`: 1.28.9, node pools `system` (3 × Standard_D4s_v5, Succeeded) and `batch` (0 → 4 × Standard_D8s_v5, Failed)
- `agw-contoso-prod` (WAF_v2, in `snet-appgw`, `pip-agw-prod`): listener `api.contoso-demo.com` → backend pool `orders-api` → `ca-orders-api`'s FQDN `ca-orders-api.wonderfulsea-7c1e2a9b.westeurope.azurecontainerapps.io` (the app's `ingress.fqdn` must be exactly this for the backend to match); WAF policy `wafp-agw-prod` in **Detection**
- Front Door `afd-contoso` (Premium, global): endpoint `contoso-web` (host `contoso-web-c7d9e2f4a1b3.z01.azurefd.net`) with route `route-web` for the custom domain `www.contoso-demo.com`, origin group `og-agw-prod` → origin `origin-agw-prod` at `pip-agw-prod`'s FQDN, WAF policy `wafpafdcontoso` in Prevention (through security policy `sp-wafpafdcontoso`)
- `law-contoso-prod` (Log Analytics, 30 days)
- Power Platform enterprise policy `ep-pp-network-injection` (kind `NetworkInjection`, location `europe`): `snet-pp-injection` in `vnet-hub-prod` and `snet-pp-injection-dr` in `vnet-pp-dr`

**`rg-legacy-prod`** (team legacy)
- `vm-jump-01` (Standard_B2s, Ubuntu 22.04, running, NIC `nic-vm-jump-01` in `snet-jump` with `pip-vm-jump-01`)
- `vm-legacy-app-01` (Standard_D4s_v3, Windows Server 2019, deallocated 40 days, NIC `nic-vm-legacy-app-01` in `snet-jump` behind `lb-legacy-internal`)
- `disk-legacy-data-01` (1024 GiB Premium_LRS, Unattached)
- `kv-legacy-prod` (access policies, public network on, purge protection off)
- App Service plan `asp-legacy` (S1, Windows) with `app-legacy-portal` and Function app `func-legacy-reports`
- `cosmos-legacy` (SQL API, public, key auth on)
- `mysql-reporting-legacy` (MySQL flexible 8.0, public access, `require_secure_transport` OFF)

**`rg-ai-prod`** (team data)
- `ai-contoso-prod` (Foundry / `AIServices`, public network on, key auth on) with project `orders-assistant` and deployment `gpt-4o`

### contoso-dev

**`rg-dev`** (westeurope, team platform): `vnet-dev` 10.30.0.0/16 (peered with
`vnet-hub-prod`), `cae-orders-dev` (external ingress) with `ca-orders-api-dev`,
`kv-orders-dev`, `stcontosoordersdev`.

## Who owns what

One fixture module per area; each owns its services' paths. The
cross-cutting sections every resource carries (Access, Activity, `W`,
`m`) are `core`'s, except that **resolving a principal's name** through
Graph (`directoryObjects`) is `identity`'s.

| Area | Services |
|---|---|
| `core` | Subscriptions (subscription details, locations, resource groups, All resources), the Activity Log, deployments, Resource Health, alerts, role assignments and definitions, `@changes`, `W`, metrics (`generate.rs`) |
| `network` | Virtual Network (VNets, subnets, NSGs, public IPs, LBs, route tables, NAT, PEs), NICs, DNS, Edge |
| `compute` | VMs, disks, AKS, Container Registry, App Service, Container Apps |
| `data` | Storage, Key Vault, SQL, Cosmos DB, PostgreSQL & MySQL, Redis, Messaging |
| `identity` | Managed identities, service principals, app registrations, directory objects, Power Platform, Monitor (workspaces, App Insights), Foundry |
