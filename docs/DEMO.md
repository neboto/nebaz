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
| `vm-jump-01` has a public IP | Related, `@pip` (no audit check: the lists `@audit` reads carry no NIC's public IP) |
| `disk-legacy-data-01`: 1 TiB Premium SSD, unattached | Disks state, `@audit` (info) |
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
| `github-actions-deploy` has Contributor and User Access Administrator on the **subscription** (both granted yesterday by alex; UAA so its Bicep can assign AcrPull) | Access, `@changes`, `@audit` |
| App registration `orders-api-client`: one client secret expires in 6 days, one expired last month, no owners | `@appreg` |
| The Fabrikam guest has Contributor on `rg-orders-prod` and Network Contributor on `nsg-jump-prod` (granted 3 days ago, just before the SSH rule) | Access |
| `caj-nightly-export`'s last execution failed | Jobs (Executions) |
| `vnet-hub-prod` peers with `vnet-dev` in **contoso-dev** (a cross-subscription jump) | Related |
| `snet-pp-injection-dr`, Power Platform's failover subnet in `vnet-pp-dr`, has no NSG | `@audit` |
| `ca-orders-api-dev` (contoso-dev): external ingress on a public environment, no IP restrictions | `@audit` on contoso-dev |

## Recordings

The README's GIFs are VHS tapes over `--demo`: `demo/nebaz.tape` (the
hero: this outage, then `@audit`) and one tape per story in
`demo/scenes/` (the outage, `@audit`, identities, private DNS, following
links). Each tape's header counts the rows its keys rely on, so a fixture
change that adds or reorders rows on those screens means re-checking that
tape; `demo/scenes/README.md` says how to re-record.

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
| `ca-orders-worker`'s system-assigned identity | `51b687b3-bdb3-4408-b436-500e659cc8cb` | `8587b0bc-6107-463b-a8d3-278472a07067` |
| `aks-platform-prod`'s kubelet identity `aks-platform-prod-agentpool` (user-assigned, in `MC_rg-platform-prod_aks-platform-prod_westeurope`) | `37ec34fc-62c5-4180-a17f-0cccd5ed2e95` | client id `e12c192b-685e-4570-b8f9-758cef84d4d0` |
| `ai-contoso-prod`'s system-assigned identity | `1f342012-a634-4ddc-8970-f178395ab2e5` | `f7e9cf30-122a-4b27-a009-e51ffcb17c73` |
| Foundry project `orders-assistant`'s system-assigned identity | `2163cbd0-48ad-4c52-bb85-c34c6c4809cf` | `05bac95b-e64c-4bd3-af4c-4b3baf097c09` |
| service principal `Microsoft Graph` (first-party, in the Contoso tenant) | `0fa66fc7-cbb8-497a-84a2-8c6dc97ef59a` | `00000003-0000-0000-c000-000000000000` |
| group `Contoso Platform Admins` | `e1a8fb8b-9024-4a39-abf4-cc2a5c73b98d` | |
| `aks-platform-prod`'s kubelet identity, client id | | client id `abcad6b0-6864-4d49-9bd6-061456b54bed` |
| `aks-platform-prod`'s system-assigned (control plane) identity | `9d2b4f6e-8a1c-4e3d-b5f7-0c2e4a6b8d91` | |
| `vm-jump-01`'s system-assigned identity | `6a0f3e1c-9b52-4d7e-8c34-1f2e5d6a7b80` | |
| `ca-orders-api-dev`'s system-assigned identity | `0b4e2c9a-7d3f-4a1e-b6c8-2f5d9e1a3c74` | |

A new object id: any fresh `uuid4`, added to this table.

In the directory: `github-actions-deploy` has two GitHub Actions federated
credentials (`repo:contoso/orders-platform:environment:production` and
`…:pull_request`) and owner alex; `orders-api-client` requests delegated
Microsoft Graph scopes, which its service principal holds by admin consent.
`id-orders-api` federates `system:serviceaccount:orders:orders-migrations`
from `aks-platform-prod`'s OIDC issuer. The Fabrikam connector is not owned
by Contoso, so the `sp` list (managed identities + this tenant's apps) does
not show it; it resolves by object id and app id.

## Resources

ARM ids are `/subscriptions/{{prod}}/resourceGroups/<rg>/providers/<type>/<name>`.
Everything is in `westeurope` unless it says otherwise. Tags on most
things: `env` (`prod`/`dev`), `team` (`orders`, `platform`, `data`,
`legacy`), `owner`; `costCenter` on some. The office's public address
is `203.0.113.24`: the one allowed IP the firewalls name (SQL, MySQL,
Redis, `stcontosoordersdev`, `kv-orders-dev`).

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
- Container Apps environment `cae-orders-prod`: internal, workload profiles (`Consumption`, `D4` 1–3 nodes), zone redundant, in `snet-aca`, static IP 10.10.0.62, default domain `wonderfulsea-7c1e2a9b.westeurope.azurecontainerapps.io`, logs to `law-contoso-prod`
- `ca-orders-api` (profile `D4`): ingress 443 → 8080, `external: true` on the internal environment (so: reachable from the VNet, never the internet; with `external: false` neither Power Platform nor the app gateway could call it), IP restrictions allowing only 10.10.4.0/24, 10.20.4.0/24 and 10.10.6.0/24 (the same sources as `nsg-aca`), FQDN `ca-orders-api.wonderfulsea-7c1e2a9b.westeurope.azurecontainerapps.io`, image `acrcontosoprod.azurecr.io/orders-api:2.31.0`, revision `ca-orders-api--v231` (100%, healthy, 3 replicas; `--v230`, `--v229` inactive), identity `id-orders-api` (also its ACR pull identity), three secrets, all Key Vault references to `kv-orders-prod`
- `ca-orders-worker`: no ingress, system-assigned identity (pulls from ACR with it), KEDA `azure-servicebus` scale rule on `sb-orders-prod`/`orders`; app provisioning state Failed, latest revision `ca-orders-worker--v119` failed (image `orders-worker:1.19.0` not found, the revision's `provisioningError`), previous `ca-orders-worker--v118` (`orders-worker:1.18.2`, 2 replicas) still running
- Job `caj-nightly-export`: scheduled `0 2 * * *`, identity `id-orders-api`, image `orders-export:1.4.2`; last execution (`caj-nightly-export-q7k2m9x`, 6h ago) Failed, the three before Succeeded (the `executions` fixture, read by the job's Executions section)
- `id-orders-api` (user-assigned): AcrPull on `acrcontosoprod`, Key Vault Secrets User on `kv-orders-prod`
- `kv-orders-prod`: RBAC, public network disabled, purge protection on, behind `pe-kv-orders`
- `stcontosoordersprod`: StorageV2, behind `pe-st-orders-blob` but public network still enabled, blob public access allowed, TLS 1.0
- `sql-orders-prod` (SQL server) with database `sqldb-orders` (GP_S_Gen5_2), firewall `AllowAll-temp`, behind `pe-sql-orders`
- `psql-orders-prod` (PostgreSQL flexible, 16, VNet-integrated in `snet-data`) — the good one: Entra-only auth (admins `Contoso Platform Admins` and `id-orders-api`), zone-redundant HA, database `orders`; its private DNS zone is `psql-orders-prod.private.postgres.database.azure.com` in `rg-network-prod` (referenced by id; network may add the zone)
- `redis-orders-cache` (Standard C1, non-TLS port on), firewall rules for `pip-ng-prod` (20.103.45.11) and the office (203.0.113.24)
- `amr-orders-sessions` (Azure Managed Redis, Balanced_B5, zone-redundant, identity `id-orders-api`): database `default`, TLS only, access keys off — the `amr` row, nothing planted
- `sb-orders-prod` (Service Bus Standard): queue `orders` (1,284 dead-lettered), `orders-retry` (forwards to `orders`), topic `order-events` with subscription `billing`; network rule set default action Allow
- `evh-orders-prod` (Event Hubs namespace, Standard, local auth off): hub `order-telemetry` (8 partitions, 3 days); network rule set Deny with a VNet rule for `snet-aca`, trusted services on
- `appi-orders` (App Insights, workspace-based on `law-contoso-prod`), the alert `orders-api-requests-dropped`

**`rg-platform-prod`** (team platform)
- `acrcontosoprod` (Premium, admin user on, public network disabled, behind `pe-acr-prod`; replicated to `northeurope`; webhook `ordersapipush` on `orders-api:*` pushes)
- `aks-platform-prod`: 1.28.9, Free tier, Azure CNI overlay (managed VNet, no subnet of ours), Entra integration with `Contoso Platform Admins` as admins, monitoring to `law-contoso-prod`, node resource group `MC_rg-platform-prod_aks-platform-prod_westeurope`; node pools `system` (3 × Standard_D4s_v5, Succeeded) and `batch` (autoscale 0 → 4 × Standard_D8s_v5, Failed)
- `agw-contoso-prod` (WAF_v2, in `snet-appgw`, `pip-agw-prod`): listener `api.contoso-demo.com` → backend pool `orders-api` → `ca-orders-api`'s FQDN `ca-orders-api.wonderfulsea-7c1e2a9b.westeurope.azurecontainerapps.io` (the app's `ingress.fqdn` must be exactly this for the backend to match); WAF policy `wafp-agw-prod` in **Detection**
- Front Door `afd-contoso` (Premium, global): endpoint `contoso-web` (host `contoso-web-c7d9e2f4a1b3.z01.azurefd.net`) with route `route-web` for the custom domain `www.contoso-demo.com`, origin group `og-agw-prod` → origin `origin-agw-prod` at `pip-agw-prod`'s FQDN, WAF policy `wafpafdcontoso` in Prevention (through security policy `sp-wafpafdcontoso`)
- `law-contoso-prod` (Log Analytics, 30 days; workspace (customer) id `a5584474-4031-4fdf-9df6-93254d6c4c43`, which `cae-orders-prod`'s logs config names)
- Power Platform enterprise policy `ep-pp-network-injection` (kind `NetworkInjection`, location `europe`): `snet-pp-injection` in `vnet-hub-prod` and `snet-pp-injection-dr` in `vnet-pp-dr`

**`rg-legacy-prod`** (team legacy)
- `vm-jump-01` (Standard_B2s, Ubuntu 22.04, running, zone 1, NIC `nic-vm-jump-01` (in `rg-legacy-prod`) in `snet-jump` with `pip-vm-jump-01`; OS disk `vm-jump-01_OsDisk_1_3f9a2c7e8b1d4e6fa0c5b7d9e2f41a68`)
- `vm-legacy-app-01` (Standard_D4s_v3, Windows Server 2019, deallocated 40 days, NIC `nic-vm-legacy-app-01` (in `rg-legacy-prod`) in `snet-jump` behind `lb-legacy-internal`; OS disk `vm-legacy-app-01_OsDisk_1_8d2e4f6a1b3c4d5e9f7a0b2c4d6e8f13`, Reserved)
- `disk-legacy-data-01` (1024 GiB Premium_LRS P30, Unattached; last owner change 40 days ago)
- `kv-legacy-prod` (access policies, public network on, purge protection off)
- App Service plan `asp-legacy` (S1, Windows) with `app-legacy-portal` (.NET Framework 4, `config/web`: TLS 1.0, FTP `AllAllowed`) and Function app `func-legacy-reports` (HTTPS only, TLS 1.2, FTPS only)
- `cosmos-legacy` (SQL API, public, key auth on)
- `mysql-reporting-legacy` (MySQL flexible 8.0, public access, `require_secure_transport` OFF)

**`rg-ai-prod`** (team data)
- `ai-contoso-prod` (Foundry / `AIServices`, public network on, key auth on) with project `orders-assistant` and deployment `gpt-4o`

**Core's own** (no service browses these; All resources lists them)
- Groups `MC_rg-platform-prod_aks-platform-prod_westeurope` (managed by the cluster) and `NetworkWatcherRG` (`NetworkWatcher_westeurope`, `NetworkWatcher_northeurope`; dev has its own)
- Alert rules: metric alerts `orders-api-requests-dropped` and `caj-nightly-export-failed` (rg-orders-prod), `aks-node-cpu-high` (rg-platform-prod); activity log alert `nsg-change-rg-network-prod` (rg-network-prod, fires on any security-rule write); action groups `ag-orders-oncall`, `ag-platform-oncall`
- Deployments: rg-orders-prod `orders-worker-v119` (failed, 25m ago), `orders-api-v231`, `orders-worker-v118`, `orders-jobs-20261001`, `orders-platform-20260912` (from template spec `ts-orders-platform` 1.4.0); rg-network-prod `hub-network-20260801`; rg-platform-prod `aks-batch-nodepool-scale` (failed, QuotaExceeded, 6 days ago), `platform-core-20260715`; rg-ai-prod `ai-foundry-20260905`; the subscription's `sub-baseline-20260610`; rg-dev `dev-env-20261020`

### contoso-dev

**`rg-dev`** (westeurope, team platform): `vnet-dev` 10.30.0.0/16 (peered with
`vnet-hub-prod`), `cae-orders-dev` (no VNet, public static IP 51.105.164.93,
default domain `happyhill-4f2d8c1a.westeurope.azurecontainerapps.io`) with
`ca-orders-api-dev` (external ingress, `orders-api:2.32.0-rc.1`, scaled to zero),
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
