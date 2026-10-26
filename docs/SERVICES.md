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
   Cross-filling both from one call is #64.
8. **AKS node pools need no lazy call**: the list's `agentPoolProfiles`
   is the full agent-pool property set (autoscale bounds, power state,
   node image version, current version). Still to confirm on a
   subscription with a cluster; if the live JSON lacks those fields, add
   a lazy Detail section per cluster rather than a per-pool call (#66).
9. **`az` commands** are `show --ids {id}` for every ARM row except those
   whose `show` takes no `--ids` (`az account show`, `az group show`,
   `az keyvault show`, `az aks show`, `az aks nodepool show`,
   `az cognitiveservices account show`, `az acr show`,
   `az functionapp show`, `az logicapp show`), which use the name form with `--subscription`.
   `functionapp show` re-declares its name argument without an `id_part`,
   so its `--ids` support is not certain from the source; the name form
   works either way. Verified live 2026-09-23; the Cognitive Services one
   and ACR ones from the CLI's parameter table (no `id_part` on the
   account or registry name, 2026-09-24), not yet live. The
   guard requires a read verb on every `az` literal in `src/`.
10. **Partial failures**: a phase failure (the power-state pass, a lazy
    section) sends `ResourceLoadWarning` and keeps going; `ResourceLoadError`
    is for a first-phase failure where nothing can stream. Connection
    failures name the host and the root cause ("cannot reach
    management.azure.com: Connection refused (gave up after retries)").
11. **Access** (RBAC) is a section on every type, just before Related,
    rendered once by `App::section_lines_for` (matched on the label) and
    never by a type's own renderer: `GET {id}/…/roleAssignments?$filter=atScope()`
    lists what applies at the row, made there or inherited (Enter on an
    inherited line jumps to the resource group or subscription it came
    from). Role names come from the subscription's `roleDefinitions`, one
    list per subscription per session; GUIDs show until it lands.
    Principals resolve to names through Microsoft Graph (ADR 0004): one
    `GET directoryObjects/{id}` per principal once the list lands, the
    first 50 per section, cached by object id; a 403 (guests, restricted
    tenants) is a footer warning and the line stays type and object id.
    Identity rows add
    **Can do**, the identity principal's own assignments across its
    subscription (direct only; group memberships are not followed). A
    new type gets Access by adding the one descriptor line
    (`Access "Access" => crate::app::App::trigger_access`) and the
    `rendered_by_app()` arm.
12. **Activity** is a section on every type, after Access, rendered the
    same way (`src/azure/services/activity.rs`): the subscription's
    activity log filtered to the row (`resourceUri eq` for a resource,
    `resourceGroupName eq` for a group, time alone for a subscription),
    the last 7 days, capped at 500 events (`list_pages_while` stops
    paging). Events collapse to one entry per operation (correlation id +
    operation name, the newest status wins), newest first; failures are
    flagged. At a group or subscription each entry names its target, which
    Enter jumps to. `$select` names the fields read, so the caller's token
    `claims`, `httpRequest` and `properties` (request bodies) are never
    fetched. A new type gets it with the descriptor line
    (`Activity "Activity" => crate::app::App::trigger_activity`) and the
    `rendered_by_app()` arm.
13. **Directory rows** (Identity · Service principals, App registrations)
    come from Microsoft Graph (ADR 0004), not ARM. They key on a
    synthetic id, `graph:/servicePrincipals/{objectId}` or
    `graph:/applications/{objectId}`, and also match the app-id alias
    `graph:/{collection}(appId='{appId}')` (`Resource::matches_id`), so a
    link that only knows an app id can jump. They have no location (`R`
    never hides them), no resource group, and no Access or Activity (those
    are ARM scopes). Their portal link is the Entra blade, and their `az`
    command is `az ad sp show --id {appId}` / `az ad app show --id {appId}`.
    The list cache keys them per subscription like every other list,
    because its tenant pseudo-key is shared by all tenants. A 403 (no
    directory read) is the list's error, or a section's warning. The
    state is the worst credential's expiry through the ladder:
    `expired`, `expiring` (within 30 days), `ok`, or stateless with no
    credentials.
14. **Network access lens** (`N`, `src/azure/nsg_eval.rs`, drawn by
    `src/ui/widgets/network_lens.rs`): the NSG rules that apply to the
    selected row, in the order Azure evaluates them, owning the detail
    pane until `Esc`. It starts from an NSG (its own rules, and the
    subnets and NICs it guards), a NIC, a subnet (what applies to anything
    placed in it, plus the NICs in it that carry their own NSG, from the
    warm lists), or any row whose Related lists NICs (a VM, a private
    endpoint) or else subnets (a Container Apps environment's infrastructure subnet, a node pool, an app's VNet integration, a
    Power Platform policy). Inbound runs the subnet's NSG, then the
    NIC's; outbound the reverse; both must allow, and a layer with no NSG
    allows everything. Within an NSG: priority order, first match wins,
    the six default rules included (added when a body has none) and
    labelled. A rule an earlier one fully covers is marked **shadowed**;
    each live allow rule is run through the other layer's NSG and marked
    allowed, blocked, or "depends on the flow" when the first rule there
    only partly overlaps it. CIDRs compare numerically; service tags and
    ASGs by name only, never expanded, so a claim about them errs to
    "depends". It is **computed, not Azure's effective view** (the
    effective-rules and effective-routes calls are POSTs; the guard
    refuses their names) and says so on screen: Azure Firewall, UDRs and
    AVNM admin rules are ignored, and a route table or delegation on the
    path is a note line. Rows come from the warm NICs, VNets, Subnets and
    NSGs lists, else one GET each, in one task delivered through the
    apply-closure event (off the `LazyStore`; `r` refetches without the
    caches). Anything unread is a warning line, never an error. `t`
    cycles inbound + outbound / inbound / outbound; `⏎` jumps to the
    line's NSG (or subnet, NIC); `y` copies a line; `e` opens it all.

15. **DNS is its own tab** although every DNS type is Microsoft.Network:
    Network with Private DNS, public zones, resolvers, rulesets and DNS
    policies was thirteen sub-tabs, past the ten digit keys, and DNS is
    debugged as one workflow (which zone answers, which resolver forwards,
    which ruleset rule, which VNet is linked) that VNets and subnets only
    touch through their Related lines. Private DNS moved with it; its
    prefix (`@pdns`), view and cache key are unchanged.
16. **DNS topology** (`network_dns.rs`): what ties resolvers, endpoints,
    subnets, rulesets, policies, private zones and VNets together lives in
    child lists no list body carries, and the API's reverse lookups
    (`virtualNetworks/listDnsResolvers`, `listDnsForwardingRulesets`) are
    `POST`s. So one lazy fetch per subscription (`App::trigger_dns_topology`,
    keyed `/subscriptions/{sub}`) lists the resolvers with their endpoints
    and the rulesets, DNS security policies and private DNS zones with their
    VNet links; a child list that fails is a warning line, only the resolver
    list failing fails the whole. The resolver's Endpoints and Rulesets,
    every VNet links section of a ruleset or policy, and the extra lines of
    a resolver's, ruleset's, policy's, VNet's and subnet's **Related** read
    it (those Related sections carry the trigger as their on-enter hook).
    It is read once per session: `r` on a row does not refresh it, a
    subscription switch does.
17. **The list's second column** is `Resource::list_summary` when the
    type has one, else the ARM id (`list_cell` draws either). A summary
    is one fact the row already carries, never a new call: VM size; AKS
    `k8s {version}`; node pool `{size} × {count}`; plan SKU · tier; web
    app `kind` (`Function app · Linux`; the runtime is in `config/web`,
    not the list body); storage kind · SKU; Cosmos API (+ `serverless`);
    Key Vault and registry SKU; public IP address (or `{allocation} ·
    unassigned`); NSG custom rule count; VNet address space; subnet
    prefix; Container App `{min}–{max} replicas`; environment
    `internal` / `external`; job trigger type; DNS zone record-set
    count (+ `private` for a legacy private zone); private DNS zone
    record sets · VNet links; DNS resolver `vnet {name}`; Redis cache SKU
    (`Premium P1`) + shards + `VNet` when injected; Managed Redis SKU (+
    `no HA`); Service Bus `{tier}` (+ `· {n} MU` on Premium) and Event
    Hubs `{tier} · {n} TU` (PU, CU), both `· private` when public access
    is off; flexible server
    `{version} · {sku} · {VNet|public|PE|public + PE|no access}`; application gateway `{tier} · {n} instances` or
    `autoscale {min}–{max}`; Front Door `Front Door {tier}`; WAF policy
    `{App Gateway | Front Door tier} · {mode}` (+ `· {n} custom`, `· not
    attached`); All resources `→`/`·` and
    the ARM type. Everything else shows the id.
18. **Cross-cache search** (`@* <text>`, #38, `src/app/all_search.rs`):
    one fuzzy search over every list of the current subscription that has
    a warm cache entry (tenant-scoped Graph lists included; never `@changes`, whose rows are events), with the
    same `rg:` / `tag:` tokens, location filter and noise toggle as any
    list. It **never fetches**: a list not loaded this session (or past
    its TTL) is not searched, the title counts the warm lists and the
    status line names the services not checked. All resources rows only
    add ids no typed list has. Each row carries its `Service/Sub-tab`
    badge; `⏎` opens it in that tab through the jump path (an All
    resources row of a browsed type in its typed tab), `l` peeks in
    place, `Ctrl-O` returns to the results. Not `@all`: that is the All
    resources routing prefix (#23), which lists the subscription from ARM.
19. **Metrics** (`m`, #51, `src/azure/metrics.rs`, drawn by
    `src/ui/widgets/metrics_overlay.rs`): Azure Monitor platform metrics
    for the selected row, owning the detail pane until `Esc` (`Z` full
    width). The default set is curated by **ARM type**, not row struct,
    so an All resources row (a SQL database) gets it too: VM, AKS,
    Container App, web app (and slot), App Service plan, SQL database,
    storage account, Key Vault, Cosmos account, load balancer, public IP,
    NAT gateway, container registry, Application Insights, Foundry /
    Cognitive Services account, Redis cache (the `all…` names, every
    shard), Managed Redis, Service Bus and Event Hubs namespace,
    PostgreSQL and MySQL flexible server, application gateway (healthy and unhealthy host counts: what backend
    health would say, without its POST), Front Door profile, ExpressRoute
    circuit (BGP and ARP availability, bits in / out), virtual network
    gateway (ExpressRoute and VPN names in one set), gateway connection
    (`curated_metrics` is the list). Any other
    ARM resource opens on the `a` picker (its metric definitions);
    `supports_metrics` drives the status-bar hint, so the hint and the
    default set cannot drift. One call per aggregation (2–3 per open, no
    `$filter`, so dimensions are aggregated away); a failed call of
    several names is retried name by name (a vCore database has no DTU
    metric, which fails the whole call), and whatever still fails is a
    warning on its line. Windows 1h / 6h / 24h / 7d (`[` / `]`, `1`–`4`)
    at `PT1M` / `PT5M` / `PT15M` / `PT1H` with `AutoAdjustTimegrain`;
    every open, window change and `r` refetches (off the `LazyStore`, one
    task, a generation drops a superseded answer). Opening from the list
    fires the default section's on-enter hook first, so closing never
    leaves a section waiting.
20. **`C` command picker** (#47, ADR 0005, `src/azure/cli_actions.rs`):
    the row's read command first (rule 9; `⏎` on it is the old `C`),
    then the type's commands in three tiers, then two reads every ARM
    row shares (`role assignment list --scope {id} --include-inherited`;
    for a resource, `monitor activity-log list --resource-id {id}
    --offset 7d`). Copied, never run. `--ids` or the name form per
    command from the CLI's `id_part`, checked 2026-10-23 against
    azure-cli `dev` and azure-cli-extensions (`ssh`, `serial-console`):
    `vm`, `webapp`, `containerapp` (not `exec` / `logs show` / `replica` /
    `revision list`), `containerapp job` (not `execution`), `network nic`,
    `nsg` / `route-table` / `vnet subnet show` take `--ids`; `aks`,
    `functionapp`, `logicapp`, `ssh vm`, `serial-console`, `acr`,
    `keyvault … list`, `storage account network-rule`, `sql … list` use
    names. Per type: **VM** get-instance-view, boot log · ssh vm, Bastion
    ssh (rdp on Windows; the Bastion host is a placeholder), serial
    console · start, restart, stop, deallocate. **NIC** effective NSG and
    routes (Azure `POST`s; not under `Reader`). **AKS** get-upgrades,
    nodepool list · get-credentials (never `--admin`) · start, stop;
    **node pool** get-upgrades · scale `--node-count <current>` (a no-op
    as pasted; noted when the autoscaler owns it), start, stop.
    **Container App** revision / replica list, last 50 log lines · exec,
    log stream · restart the latest revision; **environment** its apps,
    certificates · system log stream; **job** executions · start one.
    **Web app** config, instances · ssh, log tail · restart, stop, start;
    **function / logic app** restart, stop, start (function list).
    **Key Vault** secret and key names, network rules (never a value).
    **ACR** repositories, replications · `acr login` (never
    `--expose-token`). **Storage** network rules, containers with
    `--auth-mode login` (never the account key). **SQL server**
    databases, firewall rules, Entra admin. **PostgreSQL / MySQL flexible
    server** databases, firewall rules, Entra admins, `require_secure_transport`
    (PostgreSQL: private endpoint connections) · `connect --interactive`
    (the rdbms-connect extension; prompts for the password, never carries
    one) · start when stopped, restart and stop when ready (`show`,
    `start`, `stop`, `restart` take `--ids`; the child lists and
    `connect` use names). **NSG** rules with defaults.
    **Subnet** its NSG, its route table. **Service principal / app
    registration** credential metadata, owners, federated credentials
    (never `credential reset`). **Power Platform policy** each injected
    subnet. **Redis cache** firewall rules, server links, patch schedule,
    Entra access-policy assignments (name form; never `list-keys`);
    **Managed Redis** databases (`redisenterprise` extension).
    **Service Bus / Event Hubs namespace** queues and topics, or
    event hubs; network rule set, private endpoint connections, access
    policies (names and rights; `authorization-rule keys` is forbidden by
    the guard), all in the name form (`--namespace-name` has no
    `id_part` on `list`). **Application gateway**
    `show-backend-health` (`--ids`; a POST outside `Reader`, copied, never
    sent), listeners, rules, pools, settings, probes (`--gateway-name`, no
    `id_part`) · stop, start; never `ssl-cert` or `root-cert` (guard).
    **ExpressRoute circuit** peering list (name form), `get-stats`
    (`--ids`), route table summary and ARP table of the first peering
    (name form: the peering is in the id; POSTs outside `Reader`); never
    `express-route auth` (it lists the keys). **VNet gateway** BGP peer
    status, learned routes (`--ids`; POSTs). **IPsec connection** its
    IPsec policies (`--connection-name`, no `id_part`); never
    `vpn-connection shared-key` or `show-device-config-script` (guard).
    **WAF policy** custom rules (`--policy-name`; Front Door's from the
    `front-door` extension). **Front Door profile** endpoints, origin
    groups, custom domains, security policies (`--profile-name`, the `cdn`
    extension); never `afd secret` or a purge. A list visual selection (#39) merged into one `--ids a b c` command
    (neboto's batch mode) is not built yet: `C` acts on the cursor row.
21. **Referenced by** (`U`, #49, `src/azure/references.rs`, keys and the
    cache walk in `src/app/refs_lens.rs`, drawn by
    `src/ui/widgets/refs_lens.rs`): the reverse of Related. A reverse
    index over every warm list of the current subscription (the `@*`
    walk: typed lists first, All resources last for ids no typed list
    has; the on-screen list stands in for a lapsed entry) maps each id a
    row's `related()` points at, and each ARM id in a tag key or value
    (`hidden-link:/subscriptions/…`), to the row. Ids match
    case-insensitively; a link to a child (`…/subnets/s`) also counts
    for its parent (`via Subnet s (in it)`); Graph `graph:/` ids match
    through the target's own `matches_id` (a service principal's
    `(appId='…')` alias). Not references: the subscription and resource
    group links every row has, a row's own id, and containment either
    way (a VNet listing its subnets). **Zero calls**: the index is kept
    and reused while the cache's write generation, the subscription and
    the warm-list count hold. The coverage line counts the lists searched
    and names the cold ones likely to point at this type
    (`likely_referrers`, a hand-kept table) as `not checked — load …`;
    `L` loads those through their ordinary list load in the background
    (into the cache, never onto the screen; a failure is a `⚠` line) and
    the lens rescans as each lands. `f` narrows to one service, `⏎`
    jumps through the jump path, `y` copies the id, `e` opens the list
    in `$EDITOR`, `r` rescans.
22. **Ownership ribbon** (#48, `src/azure/ownership.rs`, `src/app/ownership.rs`,
    drawn right-aligned on the detail pane's top border by
    `details_pane.rs`): one dim line on every type, e.g. `⛓ managed by
    aks-1 · terraform · owner alice · deployed by main 2026-10-20 14:03`,
    cut to the border. In order: ARM's `managedBy` (read from the row's
    raw ARM body; the Related section carries it as a `Managed by` line
    for every type, so `⏎` jumps there); IaC hints (a `managed-by` /
    `provisioner` / `iac` / `deployed-by` tag's value as written, and
    `terraform` / `bicep` / `pulumi` / `azd` when a tag key or value names
    one); the configured `ownership_tags` (default `owner`, `team`,
    `CreatedBy`, `cost-center`, `azd-env-name`, `hidden-link:`; tried in
    order, case-insensitively, a trailing `:` a key prefix, so App
    Insights' `hidden-link:/subscriptions/…` reads `linked to app-1`); then
    the **deployment that last touched it**. That last part is the one call:
    with the pane focused on a row inside a group, the group's deployments
    (one page of up to 100, newest first) are read once per group per
    subscription visit and matched by `outputResources` and `dependencies`
    id; for the newest three that did not succeed (no `outputResources`),
    their operations are read too and matched by `targetResource.id`. An
    inline template (Bicep, `-f`) names only the deployment; a template
    spec or linked template is named. `⧗` while loading; a failure is
    `⚠ deployments: …` on the ribbon in the warning colour, never an
    error. `ownership_ribbon = false` hides it and skips the call.

23. **Change timeline** (`W`, #52, `src/azure/timeline.rs`, drawn by
    `src/ui/widgets/timeline_lens.rs`): "what changed around this row?",
    owning the detail pane until `Esc` (`Z` full width). Four sources,
    each one task under one generation (a reopen, `[` / `]` or `r`
    supersedes them; off the `LazyStore`, every open refetches), merged
    newest first with a badge: **ACT**, the Activity Log through rule
    12's query over the window, collapsed to operations and kept to the
    changes (a `/write`, `/delete` or `/action` that ended `Succeeded` or
    `Failed`; `a` shows every operation), at most 1,000 events;
    **HLTH**, the resource's Resource Health history (resources only; a
    group or subscription says so); **ALRT**, alerts fired on the row (its
    resource, or its group), a row when one fired and one when it
    resolved; **DEP**, the deployments in the row's group that deployed
    it (`outputResources`; a group's timeline takes all of them),
    at most 200 items each. The Activity Log failing is the header's
    error; any other source failing is a dim note, never an error. Windows
    7d / 30d / 90d (`[` / `]`; 90 days is the log's retention, and alerts
    keep 30, which the 90d window notes). Rows keep named fields only:
    `⏎` / `v` open the row's in `$EDITOR`, `e` the whole timeline, `y`
    copies the row, `l` goes to what the row is about, `f` cycles one
    source; the counts row carries the ownership ribbon (rule 22). Never a deployment's parameters or outputs, an event's
    `properties` or the caller's claims. Any ARM row has one (a directory
    row does not), and an `@changes` row opens on what it happened to.

24. **`@changes`** (#61, ADR 0006, `src/azure/services/changes.rs`):
    what changed recently, subscription-wide, newest first, over a `[` /
    `]` window (15m, 1h, 6h, 24h, 7d; the chips on the sub-tab row). A
    service that fetches, not a view over caches: one list **per window**
    (the cache variant is `changes-{window}`), and the sub-tabs All /
    Activity / Deployments / Health filter it without a call. Sources,
    concurrent, each streamed when done: the subscription's **Activity
    Log** (rule 12's query, no scope term) kept to the changes (rule 23),
    at most 10 pages, past which a warning says how far back it got; the
    **deployments** of the groups the log saw a
    `Microsoft.Resources/deployments` operation in (at most 20 groups, 200
    deployments each; there is no subscription-wide deployment list);
    **Resource Health**, every resource's current status whose transition
    is in the window (at most 20 pages). A failing source is a warning;
    only the Activity Log and health both failing is the list's error.
    **Noise** (`a`): an Activity row whose caller is not a person: a
    service name or none, or an id Microsoft Graph says is a managed
    identity or an app a Microsoft tenant owns (object id, then app id; at
    most 50 lookups; without directory read, ids stay unclassified and a
    warning says so). The tenant's own apps are not noise. A row is an
    event (`change:…` id): Overview (named fields) and Related (what it
    happened to); its `az` command lists the operation's events
    (`--correlation-id`) or shows the deployment. Headless: `nebaz changes
    --since 6h [--source activity|deployments|health]`. Never Resource
    Graph `resourcechanges` (a POST).

25. **`@audit`** (#60, ADR 0007; `src/audit.rs`, `src/audit/checks.rs`,
    `src/app/audit.rs`) is a virtual tab: its own entry in the service
    strip and picker (Security), not a sub-tab of Subscriptions like All
    resources, because its rows are no ARM list (`is_virtual()`: never
    cached, never streamed) and span every service. One sub-tab,
    *Findings*. Rows are findings computed by pure checks over the current
    subscription's **warm** lists (any sub-tab cached under the
    subscription) and lazy store; opening it makes no call. Severity is the
    state through the ladder (critical → Unavailable, high → Stopped,
    medium → Pending, low → Creating, info stateless; the word is the
    label), so `F` filters and `z` sorts critical first. A check whose list
    is not cached is a dim "not checked — load @x" row; a check whose lazy
    data is missing for some resources says how many, never passes them.
    `Enter` on a finding jumps to its resource (`jump_to_arm_id`; a
    directory row's `graph:/…` id included); `l` reads it: evidence, why it
    matters, remediation as **text** (no command is run or offered). `r`
    loads every uncached source list in the background with the tab's own
    streaming load, cached under the tab's key, then fetches the lazy reads
    the checks use through the sections' own maps (the subscription's role
    assignments, its Owner / User Access Administrator / Contributor
    users' directory objects, each SQL server's and Redis cache's firewall rules, each
    PostgreSQL and MySQL server's firewall rules, parameters and Entra
    admins, each
    messaging namespace's network rule set, each site's `config/web`; at most 50 each), re-auditing as each lands; a
    failed source is one status error. A subscription switch drops what is
    in flight (the lazy epoch). A finding row is a list row like any
    other: a click selects it, a double-click is Enter. Headless: `nebaz
    audit [--fail-on SEVERITY]` is `@audit` with `r` pressed, printed once
    everything has landed; exit 3 on a finding at or above `--fail-on`
    (default `low`), `not_checked` for what couldn't run. The checks are
    listed below the catalog.

26. **Edge is its own tab** (#31, `src/azure/services/edge.rs`): App
    gateways (`@agw`), Front Door (`@afd`) and WAF policies (`@waf`).
    Network already had eight sub-tabs; two more reach the ten digit keys
    and Front Door (`Microsoft.Cdn`) would be an eleventh, the DNS problem
    of rule 15 again. The WAF policies serve both front ends (one list of
    both kinds, the kind in the summary), and debugging ingress is one
    workflow: listener → rule → pool → the app behind it. A gateway's own
    subnet, NSG and public IP stay in Network and jump from its Related;
    `N` on a gateway runs its gateway subnet's NSG (v2 needs GatewayManager
    on 65200–65535). **Backends are matched, never resolved**: a pool
    address or origin host is compared with the warm Container Apps
    (FQDN, custom domains), environments (default domain suffix, static
    IP), App Service sites (default and custom host names), private
    endpoints (their DNS records) and public IPs lists; a match jumps, a
    miss says which of those lists is cold. No DNS lookup, no call. The
    same matches feed `U` (a gateway or Front Door fronting a Container
    App, once its list and the gateway's are warm or the profile's
    topology has loaded). A Front Door profile's endpoints, routes,
    origin groups, origins, custom domains and security policies are one
    lazy read per profile (`fetch_afd_topology`, the first 50 endpoints and
    origin groups followed), shared by its four lazy sections and Related.
    **Never**: a gateway certificate's `data` / `password` (stripped, also
    from the gateways a WAF policy body embeds), a custom domain's
    validation token (stripped), Front Door `secrets` (not listed), backend
    health (a POST; the guard refuses the `backendhealth` literal). Classic
    Front Door and classic CDN profiles are out (filtered from the
    `Microsoft.Cdn/profiles` list; their ids land in All resources or are
    not found).
27. **Hybrid is its own tab** (#135, `src/azure/services/hybrid.rs`):
    ExpressRoute circuits (`@er`), virtual network gateways (`@vgw`,
    ExpressRoute and VPN in one list), connections (`@cn`) and local
    network gateways (`@lgw`). Four more Network sub-tabs would pass the
    ten digit keys (rule 15 again), and a CAF landing zone keeps the whole
    estate in its connectivity subscription, debugged as one path: circuit
    → connection → gateway → GatewaySubnet. **Listed by group**: ARM has
    a subscription-wide list for circuits only; gateways, connections and
    local gateways are read by asking the generic list which groups hold
    the type (`$filter=resourceType eq '…'`) and listing each group, every
    page streamed; a group that fails beside others is a warning. A
    circuit's, gateway's or local gateway's Connections section and Related
    lines are matched in the warm Connections list (never a call; a
    circuit in another subscription is just the connection's jumpable id).
    State: a circuit is the ladder, then disabled (`circuitProvisioningState`)
    → stopped, then `serviceProviderProvisioningState` (`Provisioned` →
    available, `Deprovisioning` → deleting, `DeProvisioned` → stopped, the
    rest pending: a `NotProvisioned` circuit bills already); a connection
    `connectionStatus` (`Connected` → available, `NotConnected` →
    unavailable, `Connecting` / `Unknown` → pending); a gateway the ladder,
    then an `adminState` of `Disabled` → stopped; a local gateway the
    ladder only. **Never**: an authorization's or a Global Reach
    connection's `authorizationKey`, a connection's `sharedKey` and
    redeemed `authorizationKey`, a peering's MD5 `sharedKey`, RADIUS
    secrets, the circuit `activationKey` and P2S root certificate data
    (all stripped before the row keeps the JSON), the circuit `serviceKey`
    (masked to its last four characters), the `{connection}/sharedkey`
    read (a `GET` `Reader` may call; the guard refuses the path). ARP and
    route tables, BGP peer status, learned and advertised routes and VPN
    diagnostics are `POST`s, and circuit stats are left out: `C` copies
    those commands, nebaz never sends them.

## The catalog

Every type: Overview first, then Access ⧗ (rule 11), Activity ⧗
(rule 12), Related, and Tags last, so Access and Activity are not
repeated in the rows below; ⧗ marks a
lazy section; every `az` command is `show --ids {id}` unless stated.

| Service · sub-tab | Sections between Overview and Related | State | Related (after Subscription, Resource group) | `az` |
|---|---|---|---|---|
| Subscriptions · Subscriptions | Details ⧗ · Locations ⧗ · Tags (from Details) | subscription state; noise unless `Enabled` | — (root) | `az account show --subscription {id}` |
| Changes · All / Activity / Deployments / Health (rule 24) | — (an event: Overview is its named fields, then Related; no Access, Activity or Tags) | `failed` on a failed operation or deployment, an unavailable or degraded transition; else none; noise per rule 22 | what it happened to; a deployment's group and what it deployed; an alert's rule | `az monitor activity-log list --correlation-id {c} --subscription {sub}` · `az deployment group show -g {rg} -n {name} --subscription {sub}` · none for health |
| Subscriptions · All resources | — (Overview: type, kind, SKU, identity, managed by, created, changed, and whether nebaz browses the type) | ladder on the expanded `provisioningState` | `Open in {Service › Sub-tab}` when browsed (Enter on the list row does the same), `managedBy` | `az resource show --ids` |
| Subscriptions · Resource Groups | — | stateless when `Succeeded` | `managedBy` id when set | `az group show -n {name} --subscription {sub}` |
| Virtual Machines · VMs | Instance view ⧗ (agent, OS, boot diagnostics, disk statuses) · Networking (NICs, primary) · Storage (OS disk, data disks with LUN, size) | power state | each NIC, OS and data disks, availability set, user-assigned identities | `az vm show` |
| Virtual Machines · Disks | — | `diskState` | `managedBy` VM | `az disk show` |
| Virtual Machines · NICs | IP configurations (name, private IP, allocation, primary, public IP) | attached / unattached | VM, NSG, each IP config's subnet and public IP | `az network nic show` |
| Storage · Accounts | Endpoints · Security (public blob access, shared key, min TLS, HTTPS only, public network access, network default action, encryption key source, HNS) · Containers ⧗ | `statusOfPrimary` | — | `az storage account show` |
| Network · VNets | Subnets (embedded) · Peerings | stateless | each subnet, each peered VNet; ⧗ (rule 16) the DNS resolvers in it and the rulesets, DNS security policies and private DNS zones linked to it | `az network vnet show` |
| Network · Subnets | — (Overview: prefix, NSG, route table, NAT gateway, delegations, service endpoints, IP configuration count) | stateless | VNet, NSG, route table, NAT gateway, the Power Platform policy whose network injection names it (matched in the warm policies list, no call; else "delegated to Power Platform" when the delegation says so); ⧗ (rule 16) the DNS resolver endpoints in it | `az network vnet subnet show` |
| Network · NSGs | Inbound · Outbound (custom rules by priority, then default rules dimmed) · Used by (NICs, subnets) | stateless | each associated subnet and NIC | `az network nsg show` |
| Network · Public IPs | — (Overview: address, allocation, version, SKU · tier, attached to, DNS label, FQDN, idle timeout, zones, DDoS) | attached / unattached | the owner of its IP configuration (NIC, load balancer, gateway, firewall, bastion), NAT gateway, prefix | `az network public-ip show` |
| Network · LBs | Frontends (public IP, or private IP + subnet) · Backend pools (NICs, deduplicated from IP configurations; or addresses) · Rules (LB rules, health probes, inbound NAT, outbound) | stateless | frontend public IPs and subnets, backend NICs | `az network lb show` |
| Network · Routes | Routes (prefix → next hop type and IP) | stateless | each associated subnet | `az network route-table show` |
| Network · NAT | — (Overview: SKU, idle timeout, zones, counts) | stateless | public IPs (v4 and v6), prefixes, each subnet | `az network nat gateway show` |
| Network · PEs | Connection (target, sub-resource, status, description, automatic or manual approval) · DNS (custom DNS configs: FQDN → IPs) | ladder, then connection status (`Approved` → Available, `Pending` → Pending, `Rejected` / `Disconnected` → Unavailable) | **target** (`privateLinkServiceId`: jumps to the vault, account, storage account… it fronts), subnet, NICs | `az network private-endpoint show` |
| DNS · Private DNS | Records ⧗ (name, type, TTL, values; auto-registered flagged) · VNet links ⧗ (each linked VNet jumps; auto-registration, state) | stateless; `location` is `global`, which passes every `R` filter | — (linked VNets are in VNet links) | `az network private-dns zone show` |
| DNS · DNS zones | Records ⧗ (name, type, TTL, values, TXT cut at 60 characters; an alias record set's target is its own line and jumps; the first 1,000 record sets) · Delegation (the name servers, as text; never resolved) · (Overview: zone type, record sets of max, records per set) | stateless; `location` is `global` | alias targets (once Records has loaded: public IPs, Traffic Manager and Front Door land in All resources, record sets copy), a legacy private zone's VNets | `az network dns zone show` |
| DNS · Resolvers | Endpoints ⧗ (inbound: private IP, subnet, allocation; outbound: subnet) · Rulesets ⧗ (those forwarding through its outbound endpoints) | ladder, then `dnsResolverState` (`Connected` → Available, `Disconnected` → Unavailable) | VNet; then ⧗ each endpoint's subnet, each ruleset | `az dns-resolver show` (the `dns-resolver` CLI extension) |
| DNS · Rulesets | Rules ⧗ (domain → target servers and ports, enabled) · VNet links ⧗ (each linked VNet jumps; metadata) | ladder only | each outbound endpoint's resolver; then ⧗ the endpoints' subnets, the resolver's VNet, each linked VNet | `az dns-resolver forwarding-ruleset show` (extension) |
| DNS · DNS policies | Rules ⧗ (security rules by priority: action, state, each domain list, which lands in All resources) · VNet links ⧗ | ladder only | ⧗ each linked VNet | `az dns-resolver policy show` (extension) |
| Edge · App gateways (rule 26) | Frontends (public IP jumpable with its address from the warm list, or private IP + subnet; each frontend's listeners; the gateway subnet and its NSG requirement; private link configurations and endpoints) · Listeners (TLS policy; protocol, port, frontend, host names; certificate **name** and Key Vault secret id or "uploaded"; SNI; per-listener WAF policy; the rules using it, ⚠ when none) · Rules (by priority, the chain a request follows: listener → pool via settings, or path map → each path rule's pool, default, redirects; matched targets jumpable; ⚠ a Container App / App Service pool behind settings that keep the client's host) · Backends (pools with every address matched to a warm target or "not matched", backend NICs, empty pools flagged, which rules use each; HTTP and L4 settings: host name handling, path, affinity, probe, trusted roots, draining; probes; backend health is a POST, never sent) · WAF (gateway, listener and path-rule policies with mode and rule sets from the warm WAF list; classic WAF config; a policy on a non-WAF tier flagged) · (Overview: SKU, capacity or autoscale bounds, zones, HTTP/2, FIPS, counts) | ladder, then `operationalState` (`Running`, `Stopped`, else Pending) | gateway and frontend subnets, frontend public IPs, every WAF policy, backend NICs, private endpoints, user-assigned identities; then each matched backend | `az network application-gateway show` |
| Edge · Front Door | Endpoints ⧗ (host name as text, enabled, deployment; each route: patterns, protocols → origin group, domains, forwarding protocol and HTTPS redirect, origin path, caching, rule sets, the group's origin hosts) · Origins ⧗ (per group: probe, load balancing, session affinity, origin auth identity, the routes using it; per origin by priority: host, priority, weight, ports, host header, certificate name check, the Azure resource (`azureOrigin`) or the warm-list match, host header warnings for Container Apps / App Service, Private Link target jumpable with status, ⚠ until approved) · Domains ⧗ (host name, validation state, ⚠ until approved, certificate type and secret **name**, min TLS, Azure DNS zone jumpable, routes and WAF using it; the DCV token is never shown) · Security ⧗ (each security policy's WAF policy jumpable, its mode from the warm WAF list, the domains and patterns it covers; ⚠ when none) · (Overview: SKU, resource state, Front Door id for `X-Azure-FDID`, origin response timeout, identity) | ladder, then `resourceState` (`Active` → available, `Disabled` → stopped); `location` is `global` | user-assigned identities; ⧗ WAF policies, Azure origins, Private Link targets, origin hosts matched in the warm lists, DNS zones, origin auth identities | `az afd profile show` (the `cdn` CLI extension) |
| Edge · WAF policies | Settings (state, mode explained, request body inspection and limits, file upload limit, block response, log scrubbing) · Managed rules (each set and version, rule-group overrides with rule ids and state, exclusions) · Custom rules (by priority: action, type, rate limit, each condition with variable, selector, operator, negation, values, transforms) · Associations (gateways, listeners and path rules, Front Door security policies, classic endpoints; each jumps to its top resource) · (Overview: kind, resource state, mode, rule sets, counts) | ladder, then `resourceState` (`Enabled` → available, `Disabled` → stopped), else the policy's enabled state | each associated gateway or Front Door profile (classic Front Door lands in All resources) | `az network application-gateway waf-policy show`; Front Door: `az network front-door waf-policy show` (the `front-door` CLI extension) |
| Hybrid · ER circuits (rule 27) | Provider (provider, peering location, bandwidth or the Direct port, SKU tier · family, circuit and provider state explained, service key masked, notes, Global Reach, classic operations) · Peerings (each: type and state, VLAN, peer and Azure ASN, primary / secondary prefixes, Azure ports, route filter jumpable; Microsoft peering: advertised prefixes, ⚠ while `ValidationNeeded`, customer ASN, routing registry, communities; IPv6) · Global Reach (each peer circuit jumpable, the peering it rides, address prefix, status) · Authorizations (name and use status only) · Connections (from the warm Connections list: each jumpable, type, status, the gateway, FastPath) · (Overview: states, provider, location, bandwidth, SKU, peerings, authorizations) | ladder, then disabled → stopped, then the provider state (rule 27) | ExpressRoute port, route filters, Global Reach peer circuits; then each connection in the warm list | `az network express-route show` |
| Hybrid · VNet gateways | Configuration (gateway type, SKU and tier, zone redundancy from an `…AZ` SKU, active-active; VPN: VPN type, generation, private IP; ExpressRoute: FastPath is per connection, remote VNet and Virtual WAN traffic; BGP, admin state, custom routes) · IP configurations (allocation, private IP, subnet and public IP jumpable; ⚠ a subnet not named GatewaySubnet) · BGP (ASN, peer weight, peering addresses; per IP configuration the default, APIPA and tunnel addresses) · Point-to-site (address pool, tunnel types, auth types, Entra tenant / audience / issuer, RADIUS server addresses, root certificate **names**, revoked count, custom IPsec policies) · Connections (warm list) · (Overview: type, SKU, zone redundancy, active-active, BGP, ASN, VNet, public IPs) | ladder, then `adminState` `Disabled` → stopped | VNet, GatewaySubnet, public IPs; then each connection in the warm list | `az network vnet-gateway show` |
| Hybrid · Connections | Configuration (type, status, ⚠ when `NotConnected`, routing weight, ingress / egress bytes; ExpressRoute: FastPath, Private Link FastPath; IPsec / VNet-to-VNet: protocol, BGP, policy-based selectors, DPD timeout, mode, authentication (the key is never read); each tunnel's status, bytes and last connect) · IPsec (custom policies: IKE and IPsec proposals, SA lifetime; or Azure's defaults; traffic selectors) · (Overview: type, status, gateway, other side, routing weight) | ladder, then `connectionStatus` (rule 27) | the gateway, the circuit (any subscription), the local gateway, the VNet-to-VNet peer gateway | `az network vpn-connection show` |
| Hybrid · Local gateways | On-premises (gateway IP, FQDN, address space, BGP ASN, peer address, weight) · Connections (warm list) · (Overview: endpoint, address space, BGP ASN) | ladder only | each connection in the warm list | `az network local-gateway show` |
| Key Vault · Vaults | Access model (policies, or "Azure RBAC") · Network (default action, bypass, IP and VNet rules, private endpoints) · Secrets ⧗ · Keys ⧗ | stateless | each network-rule subnet | `az keyvault show -n {name} -g {rg} --subscription {sub}` |
| Identity · Service principals (Graph, rule 13) | Credentials (secrets and certificates: name, key id, start, end, expiry; never a value or hint) · App role assignments ⧗ (each API and role, the role named from the API's service principal) · OAuth2 grants ⧗ (API, consent all-users or one user, scopes) · Owners ⧗ · Azure roles ⧗ (rule 11's Can do over the current subscription) · Tags (Graph's string list); no Access or Activity | worst credential expiry | the managed identity it belongs to (`alternativeNames`), this tenant's app registration (by app id) | `az ad sp show --id {appId}` |
| Identity · App registrations (Graph, rule 13) | Credentials · Federated credentials ⧗ (issuer, subject, audiences) · API permissions (`requiredResourceAccess`, each API's service principal fetched by app id to name it and its permissions) · Redirect URIs (web, SPA, public client) · Owners ⧗ · Exposed API (identifier URIs, scopes, app roles) · Tags; no Access or Activity | worst credential expiry | its service principal (by app id) | `az ad app show --id {appId}` |
| Identity · Identities | Federated credentials ⧗ (issuer, subject, audiences) · Can do ⧗ (rule 11: each role the identity holds, its scope a jumpable id) · (Overview: client id, principal id, tenant, isolation scope; both ids searchable) | stateless | its service principal (Graph); users list the identity in their own Related | `az identity show` |
| AKS · Clusters | Network · API access · Node pools (embedded) · Add-ons (the monitoring add-on's workspace under `omsagent`) | ladder, then `powerState` | node resource group, user-assigned identities, kubelet identity, Log Analytics workspace | `az aks show -n {name} -g {rg} --subscription {sub}` |
| AKS · Node pools | — (Overview: mode, count, size, OS, versions, node image, autoscale, max pods, zones, priority, power, taints, labels) | ladder on the pool's fields | Cluster | `az aks nodepool show --cluster-name {cluster} -g {rg} -n {pool} --subscription {sub}` |
| Container Registry · Registries | Security (admin user and anonymous pull flagged, public access, network default action, trusted-services bypass, IP rules, encryption service- or customer-managed, zone redundancy, identity, private endpoints) · Replications ⧗ (Premium only, no call otherwise: location with the home region marked, status, zone redundancy, regional endpoint) · Webhooks ⧗ (status, actions, scope; never the service URI) · (Overview: SKU, login server, created, retention, data endpoint, role assignment mode) | ladder only | private endpoints, user-assigned identities (the CMK key is a URL, shown in Security) | `az acr show -n {name} -g {rg} --subscription {sub}` |
| App Service · Apps | Configuration ⧗ (`config/web`: runtime, always on, TLS, FTPS, HTTP/2, health check, VNet routing, access restrictions; never app settings or connection strings) · Hostnames (TLS state, SCM flagged) · Networking (public access, VNet integration subnet, outbound IPs) | ladder, then `state` (`Running` / `Stopped`) | plan, VNet integration subnet, Container Apps environment, user-assigned identities, Key Vault reference identity | web apps `az webapp show --ids`; function and logic apps `az functionapp` / `az logicapp show -n {name} -g {rg} --subscription {sub}` |
| App Service · Functions | the same rows as Apps, filtered to `kind` containing `functionapp` (Logic Apps Standard included) | as Apps | as Apps | as Apps |
| App Service · Plans | — (Overview: SKU · tier, OS, workers of max, apps, zone redundancy, per-app and elastic scaling) | ladder, then `status` (`Ready` → Available) | — (apps list their plan) | `az appservice plan show` |
| SQL · Servers | Security (Entra admin, Entra-only auth, SQL admin login, min TLS, TDE key service- or customer-managed, identity) · Databases ⧗ (user databases: SKU, status, max size, zone redundancy, backup redundancy, serverless auto-pause, elastic pool; system databases as a note) · Firewall ⧗ (IP rules; `AllowAllWindowsAzureIps` flagged) · Networking (public access, outbound restriction, IPv6, private endpoints) | `state` (`Ready` → Available; no `provisioningState` on servers) | private endpoints, user-assigned and primary identities | `az sql server show` |
| Cosmos DB · Accounts | Replication (consistency, bounded-staleness limits, multi-region writes, automatic failover, write regions, every region by failover priority with zone redundancy) · Security (public access, network access all / selected / private only, IP and VNet rules, ACL bypass, key auth, metadata writes by key, min TLS, encryption service- or customer-managed, identity, private endpoints) · Backup (periodic interval, retention, redundancy; or the continuous tier; a mode migration in progress) · Databases ⧗ (on the path the API picks; names only, containers not listed) · (Overview: API from `kind` + `capabilities`, endpoint as text, capacity mode, free tier, analytical storage) | ladder only; `location` is a display name (`West US`), stored as `westus` so `R` matches | VNet rule subnets, private endpoints, user-assigned identities (the CMK key is a URL, shown in Security) | `az cosmosdb show` |
| PostgreSQL & MySQL · PostgreSQL, MySQL (flexible servers; Single Server is retired and stays out) | Networking (how it is reached: VNet integration, public, private endpoints or none; public access; FQDN as text; delegated subnet and its VNet; private DNS zone, flagged when its name does not end in the FQDN's domain; private endpoints with approval status, flagged unless Approved; what a caller in another VNet needs) · Firewall ⧗ (IP rules; 0.0.0.0 "allow Azure services", the whole internet and ranges of 65,536+ addresses flagged; says when the rules do not apply: VNet-integrated, or public access off) · Security (auth: password / Entra / both on PostgreSQL; admin login, never the password; Entra admins ⧗, a service principal jumping to its Graph row, MySQL's Graph lookup identity; encryption service- or customer-managed with key, status and identity; managed identity) · Parameters ⧗ (`configurations`, one call; only `require_secure_transport` (off flagged), the TLS minimum / maximum, `password_encryption`, `pgbouncer.enabled`, `aad_auth_only`, `max_connections`, each with its default) · HA & backup (HA mode, state, standby zone; retention, interval, geo-redundant backup, earliest restore; replication role, replica capacity, source server; maintenance window) · Databases ⧗ (charset, collation; system databases as a note) · (Overview: version, SKU, storage size, tier and autogrow, IOPS, zone, FQDN, connectivity, admin login, created) | ladder, then `state` (`Ready` → Available, `Stopped` → Stopped, `Disabled` / `Inaccessible` → Unavailable, the rest Pending) | delegated subnet, its VNet, private DNS zone (DNS tab), private endpoints, source server, user-assigned and key identities, the system identity's service principal (Graph) | `az postgres flexible-server show` · `az mysql flexible-server show` |
| Monitor · Workspaces | — (Overview: customer id, SKU and commitment tier, retention, daily cap and reset time, ingestion status, public ingestion and query, local auth, access mode, created) | ladder only | dedicated cluster (AKS clusters and App Insights components link here from their own Related) | `az monitor log-analytics workspace show` |
| Monitor · App Insights | — (Overview: application type, kind, app id, ingestion mode, workspace, retention, sampling, public ingestion and query, local auth, IP masking, created; the instrumentation key, connection string and HockeyApp token are stripped from the JSON before the row keeps it) | ladder only | workspace (`WorkspaceResourceId`; none for a classic component). App Service apps cannot link here: the link is an app setting | `az monitor app-insights component show` (the `application-insights` CLI extension) |
| Container Apps · Apps | Ingress (external / internal, FQDN as text, transport, ports, insecure HTTP flagged, client certificate mode, sticky sessions, IP restrictions as an allow- or deny-list, CORS, traffic split by revision and label, custom domains with their certificates) · Scale (min / max replicas, rules by kind with metadata and auth as trigger parameter → secret **name**) · Containers (init first; image, CPU / memory, probes, env var **names** with secret refs named, volume mounts) · Revisions ⧗ (active first: active, traffic, replicas, health, running state, created, last active, provisioning error) · Auth ⧗ (`authConfigs`: on / off, unauthenticated action, excluded paths, per provider the client id; Entra ID issuer, client secret setting **name**, audiences, allowed client apps and identities) · Identity (system principal; each user-assigned identity with client and principal id; lifecycle; registry pull identities) · Secrets (names, Key Vault references and the identity reading them; registries) · (Overview: environment, workload profile, running status, ingress, FQDN, revisions mode, latest and latest-ready revision, Dapr, outbound IPs). Secret and env var `value`s are stripped from the JSON before the row keeps it | ladder, then `runningStatus` (`Running`, `Ready` → Available, `Stopped` / `Suspended` → Stopped, `Progressing` → Pending); `location` is a display name, stored as `eastus` | environment, user-assigned identities, registry pull identities, Express outbound subnet | `az containerapp show` |
| Container Apps · Environments | Network (public access, internal only, static IP, default domain, infrastructure subnet, Docker bridge and platform reserved ranges, reserved DNS IP, the private DNS a VNet caller needs when internal, custom DNS suffix with its certificate subject / thumbprint / expiry / Key Vault source, peer mTLS, peer traffic encryption, the ingress tier, private endpoints) · Workload profiles (name, type, node bounds) · (Overview: mode, default domain, static IP, zone redundancy, logs destination and workspace customer id, Dapr / KEDA versions, deployment errors). The Log Analytics shared key, Dapr App Insights key and connection string, App Insights connection string and certificate blob and password are stripped | ladder only | infrastructure subnet, infrastructure resource group, private endpoints, user-assigned identities. The workspace is a customer id, not an ARM id: no link (search `@law` for it) | `az containerapp env show` |
| Container Apps · Jobs | Trigger (manual, schedule with cron, or event with KEDA rules; parallelism, completions, replica timeout, retry limit) · Executions ⧗ (newest first: status, a failed one `⚠`, start and end) · Containers · Identity · Secrets (as Apps) · (Overview: environment, workload profile, running state, trigger, outbound IPs) | ladder only | environment, user-assigned identities, registry pull identities | `az containerapp job show` |
| Redis · Caches | Security (non-SSL port flagged, min TLS (1.0 / 1.1 flagged), Entra auth, access-key auth, `authnotrequired` flagged, public access, identity) · Network ⧗ (public access, VNet injection subnet with static IP (classic Premium), ports, host name as text, private endpoints with their connection status (not Approved flagged), VNet injection together with private endpoints flagged; then the firewall rules ⧗, an empty list flagged when public access is on and nothing else fences it) · Geo-replication ⧗ (linked servers: each linked cache, role, location, state; no call when the list body names none) · (Overview: SKU and family/capacity, shards, replicas per primary, Redis version, zones, host name and ports as text, update channel, max memory policy, persistence) | ladder only (caches report no runtime state); a `Disabled` provisioning state is Unavailable | subnet, private endpoints, user-assigned identities; ⧗ (Related fires Geo-replication's fetch) the linked caches | `az redis show` |
| Redis · Managed Redis | Security (min TLS, encryption service- or customer-managed with the key identity, public access, identity) · Network (public access, host name as text, private endpoints with status; no firewall or VNet injection exists) · Databases ⧗ (port, client protocol (`Plaintext` flagged), access-key auth, clustering and eviction policy, persistence, modules, Redis version, state, geo-replication group with each linked cluster jumpable) · (Overview: kind, SKU, capacity, high availability, redundancy, zones, Redis version, resource state, host name) | ladder, then `resourceState` (`Running` → Available, `Disabled` / `…Failed` → Unavailable, else Pending) | private endpoints, user-assigned identities, the CMK identity | `az redisenterprise show` (the `redisenterprise` CLI extension) |
| Messaging · Service Bus | Network ⧗ (effective access in one line; public network access; from the rule set: default action, trusted services, IP rules, VNet rules with each subnet jumpable and whether the service endpoint is required; private endpoints jumpable with connection state; the endpoint host as text, the `privatelink.` zone a private caller must resolve through; IP address type, min TLS, local auth; the tier's limits: VNet rules and private endpoints are Premium only. Deny with no IP or VNet rule is flagged: the service does not enforce it) · Security (local auth, min TLS, Microsoft- or customer-managed keys with the reading identity, infrastructure encryption, identity system / user-assigned) · Queues ⧗ (active, dead-lettered, scheduled and transfer counts from `countDetails`, size, lock duration, max deliveries, sessions, duplicate detection, TTL, partitioning, forwarding) · Topics ⧗ (subscription count, size, TTL, ordering, partitioning) · Access policies ⧗ (names and rights; never keys) · (Overview: status, SKU and messaging units, partitions, zone redundancy, endpoint, geo-replication) | ladder, then `status` (`Active` → available, `Disabled` → stopped) | private endpoints, user-assigned identities, a CMK identity, VNet rule subnets (once the rule set loads) | `az servicebus namespace show` |
| Messaging · Event Hubs | Network ⧗ · Security · Access policies ⧗ (as Service Bus; Basic has no firewall, VNet rules or private endpoints) · Event hubs ⧗ (partitions, retention and cleanup policy, status, capture on / off with format, window, destination storage account jumpable or Data Lake, container, identity) · (Overview: SKU, throughput / processing / capacity units, auto-inflate maximum, Kafka, dedicated cluster, zone redundancy) | ladder, then `status` | as Service Bus, plus the dedicated cluster and each capture storage account (once Event hubs loads) | `az eventhubs namespace show` |
| Power Platform · Enterprise policies | Network injection (each VNet and its delegated subnet, in the order the policy lists them: the environment's region pair) · Encryption (key vault, key name and version, state) · Identity (type, principal id, tenant) · (Overview: kind, `systemId` as text, health, lockbox state) | ladder, then `healthStatus` (`Healthy` → Available, `Warning` → Pending, `Unhealthy` → Unavailable, `Undetermined` stateless); `location` is a Power Platform geography, so the row passes every `R` filter like `global` | each VNet and subnet, the key vault when named by ARM id. Linked environments are in the Power Platform admin API, not ARM: never called, and the guard forbids its hosts | `az resource show --ids` (no `az powerplatform` group in core) |
| Foundry · Resources | Deployments ⧗ (model, version, format, SKU and capacity, PTUs for provisioned SKUs, rate limits, state, upgrade option, RAI policy) · Projects ⧗ (only when `allowProjectManagement`; no call otherwise) · Network (public access, ACLs, restrict outbound + FQDNs, agent subnets, private endpoints) · Security (key auth, identity, CMK) | ladder only | network-rule and agent subnets, private endpoints, user-assigned identities, user-owned storage | `az cognitiveservices account show -n {name} -g {rg} --subscription {sub}` |

Routing prefixes: `@sub @rg @vm @disk @nic @storage @vnet @subnet @nsg @pip
@lb @rt @nat @pe @dns @pdns @dnsz @dnsr @dnsfr @dnsp @agw @afd @waf @er @vgw @cn @lgw @kv @id @sp @appreg @aks @pool @acr @app @func @plan @sql @cosmos @pg @mysql @foundry @monitor @law @appi @pp @aca @acaenv @acajob @redis @amr @sb @eh @changes @activity @deploys @health @audit` (no `@ai`: it could mean Foundry or App Insights) (the list in `ServiceType`, `src/azure/service.rs`, is the
reference).

## The audit checks

Rule 25. Each reads the lists named (all of them must be cached) and, for
⧗, warm lazy data; `src/audit/checks.rs` is the reference and every check
has a fixture test there.

| Check id | Reads | Fires on | Severity |
|---|---|---|---|
| `nsg-open-internet` | NSGs | a custom inbound Allow rule from `*` / `Internet` / `0.0.0.0/0` / `::/0` | critical: all ports, 22, 3389 · high: database, cache, SMB and control-plane ports · medium: others · low: 80 or 443 alone, ICMP |
| `subnet-pp-no-nsg` | VNets or Subnets | a subnet delegated to `Microsoft.PowerPlatform/enterprisePolicies` with no NSG | medium |
| `waf-not-blocking` | WAF policies (both kinds) | a policy attached to something (a gateway, listener, path rule, Front Door security policy) in Detection mode or disabled; an unattached policy is skipped | medium |
| `storage-blob-public-access` | Storage | `allowBlobPublicAccess` true | high |
| `storage-shared-key` | Storage | `allowSharedKeyAccess` true or unset | medium |
| `storage-min-tls` | Storage | `minimumTlsVersion` below 1.2 | high |
| `storage-https-only` | Storage | `supportsHttpsTrafficOnly` false | high |
| `storage-public-network` | Storage | public network access enabled, `networkAcls.defaultAction` Allow | medium |
| `kv-purge-protection` | Vaults | purge protection off or unset | medium |
| `kv-soft-delete` | Vaults | `enableSoftDelete` false | high |
| `kv-public-network` | Vaults | public network access enabled, default action Allow | medium |
| `sql-public-network` | SQL servers | public network access not Disabled | medium |
| `sql-firewall-open` | SQL servers + Firewall ⧗ | a rule 0.0.0.0–255.255.255.255 · 0.0.0.0–0.0.0.0 (Allow Azure services) | critical · low |
| `sql-min-tls` | SQL servers | `minimalTlsVersion` below 1.2 or `None` | medium |
| `cosmos-public-network` | Cosmos | public network access enabled: no IP or VNet rules · with rules | medium · low |
| `cosmos-local-auth` | Cosmos | `disableLocalAuth` not true | medium |
| `aks-public-api` | Clusters | not private and no `authorizedIPRanges` | high |
| `aks-local-accounts` | Clusters | `disableLocalAccounts` not true (raw JSON) | medium |
| `aks-rbac-disabled` | Clusters | `enableRBAC` false | high |
| `acr-admin-user` | Registries | `adminUserEnabled` | medium |
| `acr-anonymous-pull` | Registries | `anonymousPullEnabled` | high |
| `app-https-only` | Apps | `httpsOnly` false | high |
| `app-min-tls` | Apps + Configuration ⧗ | `minTlsVersion` below 1.2 | medium |
| `app-ftps` | Apps + Configuration ⧗ | `ftpsState` AllAllowed | medium |
| `aca-ingress-open` | Container apps (+ environments when cached) | external ingress, no `ipSecurityRestrictions` | medium · low when the environment is internal (VNet-wide, not internet) |
| `aca-allow-insecure` | Container apps | ingress `allowInsecure` | medium |
| `aca-env-external-pp-vnet` | ACA environments + Enterprise policies | an environment not internal whose infrastructure subnet is in a VNet a Power Platform policy injects into | info |
| `aca-secrets-not-kv` | Container apps (+ jobs when cached) | a secret with no `keyVaultUrl` | low |
| `redis-non-ssl-port` | Redis caches | `enableNonSslPort` true | high |
| `redis-min-tls` | Redis caches | `minimumTlsVersion` below 1.2 | medium |
| `redis-public-no-firewall` | Redis caches + Network's firewall rules ⧗ | public network access enabled, not VNet-injected, no firewall rules | medium |
| `amr-min-tls` | Managed Redis | `minimumTlsVersion` below 1.2 | medium |
| `pg-public-network` · `mysql-public-network` | PostgreSQL · MySQL servers | public network access enabled and not VNet-integrated (the firewall is then the only network control) | medium |
| `pg-firewall-open` · `mysql-firewall-open` | the same + Firewall ⧗ (public servers only: other servers' rules admit nothing) | a rule 0.0.0.0–255.255.255.255 · 0.0.0.0–0.0.0.0 (Allow Azure services) | critical · low |
| `pg-insecure-transport` · `mysql-insecure-transport` | the same + Parameters ⧗ | `require_secure_transport` off | high |
| `pg-min-tls` · `mysql-min-tls` | the same + Parameters ⧗ | `ssl_min_protocol_version` (PostgreSQL) or any `tls_version` entry (MySQL) below 1.2 | medium |
| `pg-password-no-entra` · `mysql-password-no-entra` | the same + Security's Entra admins ⧗ (PostgreSQL with Entra auth off needs none) | password auth on and no Entra admin | low |
| `sb-local-auth` · `eh-local-auth` | Service Bus · Event Hubs namespaces | `disableLocalAuth` not true (SAS keys work) | medium |
| `sb-min-tls` · `eh-min-tls` | Service Bus · Event Hubs namespaces | `minimumTlsVersion` below 1.2 | medium |
| `sb-public-network` · `eh-public-network` | Service Bus · Event Hubs namespaces + Network's rule set ⧗ | public network access enabled and default action Allow, or Deny with no IP or VNet rule (not enforced) | medium |
| `foundry-public-network` | Foundry | public network access enabled, `networkAcls.defaultAction` not Deny | medium |
| `foundry-local-auth` | Foundry | `disableLocalAuth` not true (API keys work) | medium |
| `disk-unattached` | Disks | `diskState` Unattached (Reserved, a deallocated VM's disk, is not) | info: cost and data-at-rest hygiene, below the default `--fail-on low` |
| `pp-policy-unhealthy` | Enterprise policies | `healthStatus` not Healthy | medium |
| `appreg-credential-expiry` | App registrations | a secret or certificate expired · expiring within 30 days | medium · low |
| `sp-credential-expiry` | Service principals (managed identities skipped) | the same | medium · low |
| `sub-privileged-guest-or-sp` | the subscription's Access ⧗ (+ principals ⧗; a service principal is named from them, else from the cached Service principals list, else by object id) | Owner or User Access Administrator at or above the subscription (assigned on it or a management group, not a resource group) held by a guest user (`userType` Guest or `#EXT#`) · a service principal | critical · high |
| `sub-contributor-guest-or-sp` | the same | Contributor at or above the subscription held by a guest user · a service principal (a separate check: Contributor cannot grant access, so one severity lower) | high · medium |

## API calls per view

All `GET`, all under `/subscriptions/{sub}`; paged with `nextLink`. Every
path is built by the one constructor in `src/azure/arm.rs`; the ARM action
each one needs is in `PERMISSIONS.md`. **A new call goes in both tables.**

| View or section | Calls | Path · api-version |
|---|---|---|
| Subscriptions | 0 ARM (`az account list`) | — |
| Subscription Details / Locations | 1 each, per row, on demand | `/subscriptions/{id}` · `/subscriptions/{id}/locations` · `2022-12-01` |
| Resource Groups | 1 | `/resourcegroups` · `2021-04-01` |
| All resources | 1 (every type; the envelope only, never `properties`); `r` on a row lists its group filtered to its type | `/resources?$expand=createdTime,changedTime,provisioningState` · `2025-04-01` |
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
| DNS zones | 1 | `/providers/Microsoft.Network/dnszones` · `2018-05-01` (its own spec; the newest stable, DNSSEC is preview-only) |
| DNS zone Records (and Related's alias targets) | 1 per zone, on demand, stopping at 1,000 record sets | `{zone}/all` · `2018-05-01` |
| Resolvers, Rulesets, DNS policies | 1 each | `/providers/Microsoft.Network/dnsResolvers` · `dnsForwardingRulesets` · `dnsResolverPolicies` · `2025-05-01` (the resolver spec) |
| Ruleset Rules, policy Rules | 1 per ruleset or policy, on demand | `{ruleset}/forwardingRules` · `{policy}/dnsSecurityRules` · `2025-05-01` |
| DNS topology (resolver Endpoints / Rulesets, ruleset and policy VNet links, the DNS lines of VNet and subnet Related; rule 16) | once per subscription per session, on demand: `4 + 2·resolvers + rulesets + policies + private zones`, each parent list followed for its first 100 | the three resolver lists, then `{resolver}/inboundEndpoints` · `{resolver}/outboundEndpoints` · `{ruleset}/virtualNetworkLinks` · `{policy}/virtualNetworkLinks` (`2025-05-01`); `privateDnsZones`, then `{zone}/virtualNetworkLinks` (`2024-06-01`) |
| Access (every type) | 1 per row, on demand, plus 1 per subscription for role names | `{id}/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()` · `/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions` · `2022-04-01` |
| Access principal names (Graph) | 1 per principal, on demand, at most 50 per section, cached by object id | Graph `/v1.0/directoryObjects/{id}` (never `getByIds`, a `POST`) |
| Activity (every type) | 1 per row, on demand, stopping at 500 events | `/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values?$filter=eventTimestamp ge '{7 days ago}' and resourceUri eq '{id}'` · `2015-04-01` (the only stable version) |
| Metrics (`m`, rule 19) | 1 per aggregation in the default set (2–3), on demand, each open, window change and `r`; a failed multi-name call adds 1 per name. The `a` picker: 1 | `{id}/providers/Microsoft.Insights/metrics?metricnames=…&timespan=…&interval=…&aggregation=…&AutoAdjustTimegrain=true` · `{id}/providers/Microsoft.Insights/metricDefinitions` · `2023-10-01` |
| Change timeline (`W`, rule 23) | 3–4 per open, window change and `r`, on demand: the Activity Log (stopping at 1,000 events), fired alerts, the resource's health history (resources only), the group's deployments (each stopping at 200) | `/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values?$filter=…` · `2015-04-01`; `/subscriptions/{sub}/providers/Microsoft.AlertsManagement/alerts?targetResource={id}&timeRange=7d` · `2019-03-01` (the only stable version); `{id}/providers/Microsoft.ResourceHealth/availabilityStatuses` · `2025-05-01`; `/subscriptions/{sub}/resourcegroups/{rg}/providers/Microsoft.Resources/deployments` · `2025-04-01` |
| `@changes` (rule 24) | per window, on load and `r`: the Activity Log (≤10 pages), Resource Health (≤20 pages), then 1 per group with a deployment in the window (≤20); Graph: ≤50 caller lookups (2 when an id is an app id) | `/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values?$filter=eventTimestamp ge '{window start}'` · `2015-04-01`; `/subscriptions/{sub}/providers/Microsoft.ResourceHealth/availabilityStatuses` · `2025-05-01`; `/subscriptions/{sub}/resourcegroups/{rg}/providers/Microsoft.Resources/deployments` (or `/subscriptions/{sub}/providers/Microsoft.Resources/deployments`) · `2025-04-01`; Graph `/v1.0/directoryObjects/{id}`, `/v1.0/servicePrincipals(appId='{id}')` |
| `@audit` (rule 25) | 0 on open (the warm caches only). `r`: each uncached source list once (the rows above), then at most 50 each of SQL Firewall, Redis firewall rules, Service Bus and Event Hubs network rule sets, App Configuration and Access principal names, plus the subscription's Access list. `nebaz audit` makes the same calls | the paths of the rows above |
| Network access lens (`N`) | 0 when the NICs, VNets and NSGs lists are warm; else 1 per missing NIC, VNet (for its subnet) and NSG, on demand. Never the POST effective-rules call | `{nic}` · `{vnet}` · `{nsg}` · `2025-09-01` |
| Referenced by (`U`, rule 21) | 0. `L`: each likely list not warm, at that list's own cost (below), once | the lists' own calls |
| Ownership ribbon (rule 22) | 0 for tags and `managedBy`; with the pane focused, 1 per resource group per subscription visit, plus 1 per not-succeeded deployment among the newest 3 | `{group}/providers/Microsoft.Resources/deployments?$top=100` · `{group}/providers/Microsoft.Resources/deployments/{name}/operations` · `2025-04-01` |
| Can do (identities) | 1 per identity, on demand | `/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?$filter=principalId eq '{principal}'` · `2022-04-01` |
| App gateways | 1 (frontends, listeners, rules, pools, settings, probes embedded; certificate `data` and `password` stripped before the row keeps it; backend health is a POST, never sent) | `/providers/Microsoft.Network/applicationGateways` · `2025-09-01` |
| WAF policies | 2 (one list; a failure of either beside the other is a warning) | `/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies` · `2025-09-01`; `/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies` · `2026-04-01` (its own spec) |
| Front Door | 1 (classic CDN SKUs filtered out client-side) | `/providers/Microsoft.Cdn/profiles` · `2026-07-01` |
| Front Door Endpoints, Origins, Domains, Security (and Related) | once per profile, on demand: `4 + endpoints + origin groups`, the first 50 of each followed; only the endpoints failing fails it, any other child is a warning line. Never `{profile}/secrets` | `{profile}/afdEndpoints` · `{endpoint}/routes` · `{profile}/originGroups` · `{group}/origins` · `{profile}/customDomains` · `{profile}/securityPolicies` · `2026-07-01` |
| Hybrid ER circuits | 1 (peerings, authorizations and Global Reach connections embedded; authorization and shared keys stripped, the service key masked) | `/providers/Microsoft.Network/expressRouteCircuits` · `2025-09-01` |
| Hybrid VNet gateways, Connections, Local gateways (rule 27) | 1 + 1 per group holding the type (no subscription-wide list exists); a failed group beside others is a warning. Never `{connection}/sharedkey` | `/resources?$filter=resourceType eq 'Microsoft.Network/{virtualNetworkGateways,connections,localNetworkGateways}'` · `2025-04-01`, then `/resourceGroups/{rg}/providers/Microsoft.Network/{type}` · `2025-09-01` |
| Vaults | 1 | `/providers/Microsoft.KeyVault/vaults` · `2024-11-01` |
| Identities | 1 | `/providers/Microsoft.ManagedIdentity/userAssignedIdentities` · `2024-11-30` |
| Federated credentials | 1 per identity, on demand | `{identity}/federatedIdentityCredentials` · `2024-11-30` |
| Service principals | 2 (merged): managed identities by a default filter, then this tenant's apps by an advanced query | Graph `/v1.0/servicePrincipals?$filter=servicePrincipalType eq 'ManagedIdentity'` · `?$filter=appOwnerOrganizationId eq {tenant}&$count=true` with `ConsistencyLevel: eventual`; `$top=999` |
| App registrations | 1 | Graph `/v1.0/applications?$top=999` |
| Owners, Federated credentials (apps), App role assignments, OAuth2 grants | 1 per row, on demand | Graph `/v1.0/{applications|servicePrincipals}/{id}/{owners|federatedIdentityCredentials|appRoleAssignments|oauth2PermissionGrants}` |
| API permission names | 1 per API, on demand, at most 30 | Graph `/v1.0/servicePrincipals(appId='{appId}')` |
| Secrets, Keys | 1 each per vault, on demand | `{vault}/secrets` · `{vault}/keys` · `2026-05-15` |
| Clusters, Node pools | 1 each (same list) | `/providers/Microsoft.ContainerService/managedClusters` · `2026-06-01` |
| Registries | 1 | `/providers/Microsoft.ContainerRegistry/registries` · `2025-11-01` |
| Replications, Webhooks | 1 each per registry, on demand (replications only for Premium) | `{registry}/replications` · `{registry}/webhooks` · `2025-11-01` |
| Apps, Functions | 1 each (the same sites list; Apps is every site because a site id does not say its kind) | `/providers/Microsoft.Web/sites` · `2026-03-15` |
| Plans | 1 | `/providers/Microsoft.Web/serverfarms` · `2026-03-15` |
| App Configuration | 1 per app, on demand | `{site}/config/web` · `2026-03-15` |
| SQL servers | 1 | `/providers/Microsoft.Sql/servers` · `2025-01-01` |
| Databases, Firewall | 1 each per server, on demand (no subscription-wide database list exists) | `{server}/databases` · `{server}/firewallRules` · `2025-01-01` |
| Cosmos DB accounts | 1 | `/providers/Microsoft.DocumentDB/databaseAccounts` · `2026-03-15` |
| Cosmos databases | 1 per account, on demand; the API picks the path (containers would be one call per database, so they are not listed) | `{account}/sqlDatabases` · `mongodbDatabases` · `cassandraKeyspaces` · `gremlinDatabases` · `tables` · `2026-03-15` |
| PostgreSQL / MySQL flexible servers | 1 each | `/providers/Microsoft.DBforPostgreSQL/flexibleServers` · `2025-08-01` (`2026-10-01` is newer but only weeks old) · `/providers/Microsoft.DBforMySQL/flexibleServers` · `2024-12-30` |
| Flexible server Databases, Firewall, Entra admins (Security), Parameters | 1 each per server, on demand | `{server}/databases` · `{server}/firewallRules` · `{server}/administrators` · `{server}/configurations` · the engine's version above |
| Workspaces | 1 | `/providers/Microsoft.OperationalInsights/workspaces` · `2026-03-01` |
| App Insights | 1 | `/providers/Microsoft.Insights/components` · `2020-02-02` (the newest stable that has components) |
| Container apps | 1 | `/providers/Microsoft.App/containerApps` · `2026-07-01` |
| Container Apps environments | 1 | `/providers/Microsoft.App/managedEnvironments` · `2026-07-01` |
| Container Apps jobs | 1 | `/providers/Microsoft.App/jobs` · `2026-07-01` |
| Revisions, Auth | 1 each per app, on demand (`listSecrets` is a POST and never sent) | `{app}/revisions` · `{app}/authConfigs` · `2026-07-01` |
| Job Executions | 1 per job, on demand (newest first; the execution's template, which carries env, is never rendered) | `{job}/executions` · `2026-07-01` |
| Redis caches | 1 (the access keys and the persistence storage connection strings a body can carry are stripped before the row keeps it; `listKeys` is a POST and never sent) | `/providers/Microsoft.Cache/redis` · `2024-11-01` |
| Redis Firewall, Geo-replication | 1 each per cache, on demand (linked servers only when the list body names one) | `{cache}/firewallRules` · `{cache}/linkedServers` · `2024-11-01` |
| Managed Redis | 1 | `/providers/Microsoft.Cache/redisEnterprise` · `2026-09-01` |
| Managed Redis Databases | 1 per cluster, on demand | `{cluster}/databases` · `2026-09-01` |
| Service Bus namespaces | 1 | `/providers/Microsoft.ServiceBus/namespaces` · `2026-01-01` |
| Event Hubs namespaces | 1 | `/providers/Microsoft.EventHub/namespaces` · `2026-01-01` |
| Network (firewall), Access policies | 1 each per namespace, on demand (Related fires the rule set too; a policy's keys are the `listKeys` POST, never sent) | `{ns}/networkRuleSets/default` · `{ns}/authorizationRules` · `2026-01-01` |
| Queues, Topics, Event hubs | 1 each per namespace, on demand (a topic's subscriptions and a hub's consumer groups would be one call per entity, so they are not listed; an Event Hubs Related fires Event hubs for the capture accounts) | `{ns}/queues` · `{ns}/topics` · `{ns}/eventhubs` · `2026-01-01` |
| Foundry resources | 1 (every Cognitive Services kind; `kind` on the row) | `/providers/Microsoft.CognitiveServices/accounts` · `2026-07-01` |
| Enterprise policies | 1 (every kind; `kind` on the row) | `/providers/Microsoft.PowerPlatform/enterprisePolicies` · `2020-10-30-preview` (the only version in the specs; not yet tried live) |
| Deployments, Projects | 1 each per account, on demand | `{account}/deployments` · `{account}/projects` · `2026-07-01` |

A full tour of every sub-tab in one subscription is one list call per
sub-tab. Only
the Accounts view and its Containers sections touch the throttled Storage
budget. **Watch mode** (`w`, presets 5–300 s) needs no floor for one
watched view: the 5 s preset is 60 list calls per 5 minutes against the
100 allowed. Two watched Storage views in one subscription would exceed
it; that floor is #63.

## Verified live (2026-09-23, the Azure machine)

- VM power state on the row through the `statusOnly=true` pass. Whether
  that pass also carries the full model (one call instead of two) is
  unchecked (#65); the two-call form stays.
- `az keyvault show`, `az aks show`, `az aks nodepool show` take no
  `--ids` (name form above).
- The api-versions above were accepted.
- Still to check: embedded `agentPoolProfiles` carry autoscale and power
  (rule 8), on a subscription with an AKS cluster (#66).

## Not yet verified live

- Hybrid (#135), built without an Azure login from azure-rest-api-specs
  (Network `2025-09-01`, the Network service's version; `expressRoute.json`
  and `networkGateway.json`) and the azure-cli sources. To check: the
  per-group lists answer for every group the filtered generic list names
  (and nothing is missed: a gateway in a group the `$filter` misses);
  whether a connection list body carries `connectionStatus` and the byte
  counters (the spec marks them read-only; some ExpressRoute connections
  may report `Unknown`) and never `sharedKey` (stripped regardless);
  whether the ER gateway's metric set answers the VPN names (one ARM type,
  so the definitions should be shared) and the reverse; `az network
  express-route show`, `vnet-gateway show`, `vpn-connection show` and
  `local-gateway show` take `--ids` (each `-n` carries `id_part='name'`);
  the Hybrid tab at 80×24 on a real estate.

- Redis (#29), built from azure-rest-api-specs (`2024-11-01` for
  `Microsoft.Cache/redis`, `2026-09-01` for `redisEnterprise`, the newest
  stable of each on 2026-10-24) without a subscription that has one. To
  check: both api-versions are accepted; the list body's `location` is a
  display name (stored without spaces, as for Container Apps);
  `redisConfiguration.aad-enabled` is a string; `linkedServers` is on the
  list body; `az redis show` and `az redisenterprise show` take `--ids`
  (both names carry `id_part='name'` in azure-cli and the extension).

- Edge (#31), built without an Azure login from azure-rest-api-specs
  (2026-10-24): gateways and their WAF policies on the Network version
  (`2025-09-01`; `2026-03-01` is the newest stable), `Microsoft.Cdn`
  `2026-07-01` (`2026-10-01` landed two days earlier and is not pinned
  yet), Front Door WAF `2026-04-01`. To check: the versions are accepted;
  the subscription-wide Front Door WAF list answers; a gateway list body
  carries no certificate `data` (stripped regardless); the profile list's
  `location` is `Global`; `az network application-gateway show`,
  `waf-policy show`, `az afd profile show` (cdn extension) and `az network
  front-door waf-policy show` (front-door extension) take `--ids` (all
  four name arguments carry `id_part='name'`); the Edge tab at 80×24.
- Messaging (#27), built without an Azure login from the
  `2026-01-01` specs (the newest stable for both providers on
  2026-10-24; `2024-01-01` is the previous). To check: the api-version
  is accepted; the list `location` is a display name (stored without
  spaces); queue `countDetails` arrive on the ARM list body; the
  `networkRuleSets/default` GET answers for a Basic or Standard namespace
  (or errors, which the section shows); `az servicebus namespace show`
  and `az eventhubs namespace show` take `--ids` (`id_part='name'` in the
  CLI's generated commands).

- PostgreSQL & MySQL flexible servers (#28), built from azure-rest-api-specs
  (PostgreSQL `2025-08-01`, MySQL `2024-12-30`) and the azure-cli sources,
  without an Azure login. To check: both api-versions list; the MySQL
  `privateDnsZoneResourceId` and PostgreSQL `privateDnsZoneArmResourceId`
  names; that `configurations` comes back in one or two pages; that
  `az postgres flexible-server firewall-rule list` takes `--server-name`
  and MySQL's takes `--name` on the installed CLI; the metric names.
- Power Platform enterprise policies (#77): built from the documented
  shape (azure-rest-api-specs `2020-10-30-preview`, the ARM template
  reference, Microsoft's `PowerPlatform-EnterprisePolicies` module), with
  no subscription that has one. To check: the preview api-version is
  accepted for the list (the module deploys with an undocumented
  `2020-10-30`); `healthStatus` and `systemId` appear on a list body;
  `encryption.keyVault.id` is an ARM id (the spec says "Uri"; a URL shows
  as text and does not link); policy `location` is a Power Platform
  geography (`unitedstates`, `europe`; the row passes every `R` filter
  for that reason, `filter_location`), and whether any policy carries an
  Azure region instead; how the list answers in a subscription where
  `Microsoft.PowerPlatform` is not registered.
- DNS (#37), built without an Azure login. To check: the DNS
  api-versions (`2018-05-01` public zones, `2025-05-01` resolver, both the
  newest stable in azure-rest-api-specs on 2026-10-23); the record-set
  JSON's casing (`TTL`, `ARecords`, …, as the spec spells it); and that
  `az network dns zone show` and the `dns-resolver` extension's `show`,
  `forwarding-ruleset show` and `policy show` take `--ids` (their CLI
  parameter tables give the name an `id_part`).
