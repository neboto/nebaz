// ported from neboto-tui src/aws/service.rs @ d483900
use crate::azure::resource::Resource;
use crate::error::Result;
use crate::event::Event;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// One variant per first-release service. neboto's enum has 74; the
/// `name` / `short_name` / `description` / `category` / `prefix` /
/// `from_prefix` surface is kept verbatim because the copied widgets
/// (service picker, tab strip, `@prefix` completion, config) key on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ServiceType {
    /// Subscriptions + resource groups — the scoping rows.
    Subscriptions,
    /// Virtual machines, managed disks, NICs, VM scale sets.
    VirtualMachines,
    /// Storage accounts + blob containers (via ARM).
    Storage,
    /// Recovery Services vaults and Backup vaults (`Microsoft.DataProtection`):
    /// what is protected, by which policy, and whether the last backup
    /// worked. Protected items, policies and jobs lazy. Its own tab
    /// (SERVICES.md rule 31).
    Backup,
    /// Virtual networks, subnets, NSGs, public IPs, load balancers, route
    /// tables, NAT gateways, private endpoints, Bastion hosts, DDoS
    /// protection plans.
    Network,
    /// Private and public DNS zones, the DNS Private Resolver, forwarding
    /// rulesets, DNS security policies. Microsoft.Network, but its own tab
    /// (SERVICES.md says why).
    Dns,
    /// The internet-facing entry points: application gateways, Front Door
    /// Standard / Premium profiles and the WAF policies of both. Its own
    /// tab (SERVICES.md rule 26 says why); backend health is never read.
    Edge,
    /// The hybrid estate: ExpressRoute circuits, virtual network gateways,
    /// their connections and local network gateways. Its own tab
    /// (SERVICES.md rule 28); never a shared or authorization key.
    Hybrid,
    /// Virtual WAN (#158): WANs, hubs (connections and route tables lazy),
    /// the hub gateways and VPN sites. Its own tab (SERVICES.md rule 35);
    /// never a pre-shared or authorization key, never effective routes.
    VirtualWan,
    /// The hub's security layer: Azure Firewalls, firewall policies (rule
    /// collection groups lazy), IP groups, and Palo Alto Networks Cloud
    /// NGFW firewalls and local rulestacks (rules lazy). Its own tab
    /// (SERVICES.md rule 29 says why).
    Firewall,
    /// Key vaults — metadata and secret/key *names* only, never values.
    KeyVault,
    /// User-assigned managed identities (ARM); service principals and app
    /// registrations (Microsoft Graph, ADR 0004).
    Identity,
    /// AKS managed clusters + node pools.
    Aks,
    /// Container registries; replications and webhooks lazy. Never
    /// repositories or tags (data plane).
    ContainerRegistry,
    /// Web, function and logic apps (`Microsoft.Web/sites`) and plans.
    AppService,
    /// Azure SQL logical servers; databases and firewall rules lazy.
    Sql,
    /// Cosmos DB accounts; databases lazy, on the account's API path.
    /// Never keys or connection strings.
    Cosmos,
    /// PostgreSQL and MySQL flexible servers; databases, firewall rules,
    /// Entra admins and the TLS parameters lazy. Never a password.
    PostgresMysql,
    /// Foundry / AI Services / Azure OpenAI accounts; deployments and
    /// projects as lazy sections. Metadata only, never keys.
    Foundry,
    /// Log Analytics workspaces and Application Insights components,
    /// metadata only; never a query, a key or a connection string.
    Monitor,
    /// Power Platform enterprise policies (network injection, encryption,
    /// identity). Never the environments: they are not in ARM.
    PowerPlatform,
    /// Azure Automation accounts (#202): runbooks, schedules, jobs and
    /// hybrid workers lazy. Never variables, credentials, certificates,
    /// connections, runbook content or job output.
    Automation,
    /// Azure Arc (#199): Arc-enabled servers (extensions lazy), Arc
    /// Kubernetes clusters and Arc private link scopes. Never an
    /// extension's settings, never a run command or a patch install.
    Arc,
    /// Azure Virtual Desktop (#198): host pools (session hosts lazy),
    /// application groups, workspaces and scaling plans. Never a
    /// registration token, never a user session's message or disconnect.
    VirtualDesktop,
    /// Container apps, their environments and jobs (`Microsoft.App`);
    /// revisions and auth settings lazy. Never a secret or env var value.
    ContainerApps,
    /// Azure Cache for Redis and Azure Managed Redis (`Microsoft.Cache`);
    /// firewall rules, geo-replication links and databases lazy. Never a
    /// key (`listKeys` is a POST).
    Redis,
    /// Service Bus and Event Hubs namespaces; queues, topics, event hubs,
    /// the network rule set and access policy names lazy. Never a key.
    Messaging,
    /// Policy assignments, exemptions, custom definitions and initiatives,
    /// resource locks (#155, ADR 0009): the subscription's view with what it
    /// inherits from the management groups above. Never compliance (POST).
    Governance,
    /// Microsoft Defender for Cloud (#156, ADR 0010): recommendations,
    /// alerts, the secure score and which plans are on. Its own findings,
    /// never `@audit` rows.
    Defender,
    /// Azure Advisor (#157, ADR 0011): recommendations by category and
    /// impact, the Advisor score, the snoozed and dismissed ones. What
    /// Advisor last computed; never `generateRecommendations` (POST).
    Advisor,
    /// What changed recently, subscription-wide (#61, ADR 0006): the
    /// Activity Log's changes, deployments and health transitions over a
    /// `[` / `]` window. A service that fetches, not a view over caches.
    Changes,
    /// Virtual (`@audit`, #60): security findings computed from the other
    /// services' warm caches (`src/audit.rs`, ADR 0007). No ARM list of
    /// its own, never cached (`is_virtual`).
    Audit,
}

/// One sub-tab: the rows of one resource type within a service. A flat
/// enum with a variant per sub-tab (ADR 0002): its string form is the list
/// cache's `variant`, and a routing prefix (`@disk`) names one directly. A
/// sub-tab exists only when its rows come from one subscription-wide list
/// or are embedded in one (or, for a type ARM lists per resource group
/// only, the per-group lists of the groups that hold it: SERVICES.md rule
/// 27); per-parent lists are lazy sections instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum JumpView {
    // Subscriptions
    Subscriptions,
    ResourceGroups,
    /// Every resource in the subscription, any type (the generic list).
    AllResources,
    // Virtual Machines
    VirtualMachines,
    Disks,
    Nics,
    /// `Microsoft.Compute/virtualMachineScaleSets`; Uniform instances are a
    /// lazy section, Flexible ones are VMs.
    ScaleSets,
    /// `Microsoft.Network/applicationSecurityGroups` (#203): beside the
    /// NICs they group, since Network is at the digit-key ceiling.
    ApplicationSecurityGroups,
    /// `Microsoft.Compute/galleries` (#203): image definitions and their
    /// versions are a lazy section.
    Galleries,
    // Storage
    StorageAccounts,
    // Network
    VirtualNetworks,
    /// Embedded in the virtual-network list.
    Subnets,
    NetworkSecurityGroups,
    PublicIps,
    LoadBalancers,
    RouteTables,
    NatGateways,
    PrivateEndpoints,
    /// `Microsoft.Network/bastionHosts`.
    BastionHosts,
    /// `Microsoft.Network/ddosProtectionPlans`.
    DdosPlans,
    // DNS
    PrivateDnsZones,
    /// Public DNS zones (`Microsoft.Network/dnszones`).
    DnsZones,
    DnsResolvers,
    DnsForwardingRulesets,
    /// DNS security policies (`dnsResolverPolicies`).
    DnsResolverPolicies,
    /// `Microsoft.Network/trafficManagerProfiles` (its own spec; global).
    TrafficManagerProfiles,
    // Edge
    /// `Microsoft.Network/applicationGateways`.
    AppGateways,
    /// Front Door Standard / Premium (`Microsoft.Cdn/profiles`, the classic
    /// CDN SKUs filtered out).
    FrontDoorProfiles,
    /// Application Gateway and Front Door WAF policies, one list of both.
    WafPolicies,
    /// `Microsoft.Network/privateLinkServices`.
    PrivateLinkServices,
    // Hybrid
    /// `Microsoft.Network/expressRouteCircuits`.
    ExpressRouteCircuits,
    /// `virtualNetworkGateways` (ExpressRoute and VPN), listed per group.
    VnetGateways,
    /// `Microsoft.Network/connections`, listed per group.
    GatewayConnections,
    /// `localNetworkGateways`, listed per group.
    LocalGateways,
    // Virtual WAN
    /// `Microsoft.Network/virtualWans`.
    VirtualWans,
    /// `Microsoft.Network/virtualHubs`.
    VirtualHubs,
    /// `Microsoft.Network/vpnGateways`: a hub's site-to-site gateway.
    VwanVpnGateways,
    /// `Microsoft.Network/expressRouteGateways`: a hub's ExpressRoute gateway.
    VwanErGateways,
    /// `Microsoft.Network/p2sVpnGateways`: a hub's point-to-site gateway.
    P2sGateways,
    /// `Microsoft.Network/vpnSites`: the branches a hub's VPN gateway reaches.
    VpnSites,
    // Firewall
    /// `Microsoft.Network/azureFirewalls`.
    AzureFirewalls,
    /// `Microsoft.Network/firewallPolicies`.
    FirewallPolicies,
    /// `Microsoft.Network/ipGroups`.
    IpGroups,
    /// Palo Alto Networks Cloud NGFW (`PaloAltoNetworks.Cloudngfw/firewalls`).
    CloudNgfws,
    /// Cloud NGFW local rulestacks (`PaloAltoNetworks.Cloudngfw/localRulestacks`).
    NgfwRulestacks,
    // Backup
    /// `Microsoft.RecoveryServices/vaults`.
    RecoveryVaults,
    /// `Microsoft.DataProtection/backupVaults`.
    BackupVaults,
    // Key Vault
    KeyVaults,
    // Identity
    Identities,
    /// Microsoft Graph: this tenant's own apps' service principals and
    /// every managed identity's. Rows key on `graph:/servicePrincipals/{id}`.
    ServicePrincipals,
    /// Microsoft Graph: the tenant's app registrations
    /// (`graph:/applications/{id}`).
    AppRegistrations,
    // AKS
    Clusters,
    /// Embedded in the cluster list (the API says agent pool).
    NodePools,
    // Container Registry
    Registries,
    // App Service
    /// Every site: web, API, function and logic apps.
    WebApps,
    /// The same sites list, function and logic apps only.
    FunctionApps,
    AppServicePlans,
    /// `Microsoft.Web/staticSites` (#200).
    StaticSites,
    // SQL
    SqlServers,
    /// `Microsoft.Sql/managedInstances` (#195).
    ManagedInstances,
    /// `Microsoft.Sql/instancePools`.
    InstancePools,
    // Cosmos DB
    CosmosAccounts,
    // PostgreSQL & MySQL
    PostgresServers,
    MysqlServers,
    // Foundry
    /// Every `Microsoft.CognitiveServices` account, `kind` on the row.
    AiAccounts,
    /// `Microsoft.Search/searchServices` (#196).
    SearchServices,
    // Monitor
    LogWorkspaces,
    AppInsights,
    /// `Microsoft.Insights/metricAlerts` (#194).
    MetricAlerts,
    /// `Microsoft.Insights/scheduledQueryRules`: log search alerts.
    LogAlerts,
    /// `Microsoft.Insights/activityLogAlerts` (Service Health too).
    ActivityLogAlerts,
    /// `Microsoft.Insights/actionGroups`: who an alert notifies.
    ActionGroups,
    /// `Microsoft.AlertsManagement/actionRules`: alert processing rules.
    AlertProcessingRules,
    /// `Microsoft.AlertsManagement/alerts`: the alerts that fired, the
    /// last 30 days.
    FiredAlerts,
    // Power Platform
    EnterprisePolicies,
    /// `Microsoft.Automation/automationAccounts` (#202).
    AutomationAccounts,
    // Azure Arc (#199)
    ArcMachines,
    ArcClusters,
    ArcPrivateLinkScopes,
    // Azure Virtual Desktop (#198)
    HostPools,
    AvdApplicationGroups,
    AvdWorkspaces,
    ScalingPlans,
    // Container Apps
    ContainerApps,
    ContainerAppEnvironments,
    ContainerAppJobs,
    /// `Microsoft.ContainerInstance/containerGroups` (#197).
    ContainerGroups,
    // Redis
    /// Azure Cache for Redis (`Microsoft.Cache/redis`).
    RedisCaches,
    /// Azure Managed Redis (`Microsoft.Cache/redisEnterprise`).
    ManagedRedis,
    // Messaging
    ServiceBusNamespaces,
    EventHubNamespaces,
    // Governance
    /// Every policy assignment that applies to the subscription or to
    /// anything in it, management groups' included (unfiltered list).
    PolicyAssignments,
    /// Policy exemptions, the same way.
    PolicyExemptions,
    /// Custom policy definitions and initiatives, one list of both.
    PolicyDefinitions,
    /// Every resource lock in the subscription (`Microsoft.Authorization/locks`).
    ResourceLocks,
    /// The management groups the caller can read (`GET
    /// /providers/Microsoft.Management/managementGroups`, ADR 0009
    /// decision 3): above the subscription, cached per subscription.
    ManagementGroups,
    /// `Microsoft.Consumption/budgets` at the subscription (#203).
    Budgets,
    // Defender
    /// Defender's assessments, one row per recommendation and resource;
    /// healthy and not-applicable ones are noise.
    DefenderRecommendations,
    /// Defender's security alerts.
    DefenderAlerts,
    /// The secure score and its controls, one list of both.
    SecureScore,
    /// The Defender plans (`pricings`): which are on.
    DefenderPlans,
    // Advisor
    /// Advisor's recommendations, one row per recommendation and resource;
    /// Security ones (Defender's, relayed) are noise.
    AdvisorRecommendations,
    /// The Advisor score, overall and per category.
    AdvisorScore,
    /// The snoozed and dismissed recommendations.
    AdvisorSuppressions,
    // Changes: one list per window; the sub-tabs filter it by source.
    ChangesAll,
    ChangesActivity,
    ChangesDeployments,
    ChangesHealth,
    // Audit
    /// The `@audit` findings: computed, never fetched or cached.
    Audit,
}

impl JumpView {
    /// The service this sub-tab belongs to.
    pub fn service(&self) -> ServiceType {
        use JumpView::*;
        match self {
            Subscriptions | ResourceGroups | AllResources => ServiceType::Subscriptions,
            VirtualMachines | Disks | Nics | ScaleSets | ApplicationSecurityGroups | Galleries => ServiceType::VirtualMachines,
            StorageAccounts => ServiceType::Storage,
            VirtualNetworks | Subnets | NetworkSecurityGroups | PublicIps | LoadBalancers | RouteTables
            | NatGateways | PrivateEndpoints | BastionHosts | DdosPlans => ServiceType::Network,
            PrivateDnsZones | DnsZones | DnsResolvers | DnsForwardingRulesets | DnsResolverPolicies | TrafficManagerProfiles => {
                ServiceType::Dns
            }
            AppGateways | FrontDoorProfiles | WafPolicies | PrivateLinkServices => ServiceType::Edge,
            ExpressRouteCircuits | VnetGateways | GatewayConnections | LocalGateways => ServiceType::Hybrid,
            VirtualWans | VirtualHubs | VwanVpnGateways | VwanErGateways | P2sGateways | VpnSites => {
                ServiceType::VirtualWan
            }
            AzureFirewalls | FirewallPolicies | IpGroups | CloudNgfws | NgfwRulestacks => ServiceType::Firewall,
            RecoveryVaults | BackupVaults => ServiceType::Backup,
            KeyVaults => ServiceType::KeyVault,
            Identities | ServicePrincipals | AppRegistrations => ServiceType::Identity,
            Clusters | NodePools => ServiceType::Aks,
            Registries => ServiceType::ContainerRegistry,
            WebApps | FunctionApps | AppServicePlans | StaticSites => ServiceType::AppService,
            SqlServers | ManagedInstances | InstancePools => ServiceType::Sql,
            CosmosAccounts => ServiceType::Cosmos,
            PostgresServers | MysqlServers => ServiceType::PostgresMysql,
            AiAccounts | SearchServices => ServiceType::Foundry,
            LogWorkspaces | AppInsights | MetricAlerts | LogAlerts | ActivityLogAlerts | ActionGroups | AlertProcessingRules
            | FiredAlerts => ServiceType::Monitor,
            EnterprisePolicies => ServiceType::PowerPlatform,
            AutomationAccounts => ServiceType::Automation,
            ArcMachines | ArcClusters | ArcPrivateLinkScopes => ServiceType::Arc,
            HostPools | AvdApplicationGroups | AvdWorkspaces | ScalingPlans => ServiceType::VirtualDesktop,
            ContainerApps | ContainerAppEnvironments | ContainerAppJobs | ContainerGroups => ServiceType::ContainerApps,
            RedisCaches | ManagedRedis => ServiceType::Redis,
            ServiceBusNamespaces | EventHubNamespaces => ServiceType::Messaging,
            PolicyAssignments | PolicyExemptions | PolicyDefinitions | ResourceLocks | ManagementGroups | Budgets => ServiceType::Governance,
            DefenderRecommendations | DefenderAlerts | SecureScore | DefenderPlans => ServiceType::Defender,
            AdvisorRecommendations | AdvisorScore | AdvisorSuppressions => ServiceType::Advisor,
            ChangesAll | ChangesActivity | ChangesDeployments | ChangesHealth => ServiceType::Changes,
            Audit => ServiceType::Audit,
        }
    }

    /// The list-cache variant: stable, never shown to the user.
    pub fn as_str(&self) -> &'static str {
        use JumpView::*;
        match self {
            Subscriptions => "subscriptions",
            ResourceGroups => "resource-groups",
            AllResources => "all-resources",
            VirtualMachines => "vms",
            Disks => "disks",
            Nics => "nics",
            ScaleSets => "scale-sets",
            StorageAccounts => "accounts",
            VirtualNetworks => "vnets",
            Subnets => "subnets",
            NetworkSecurityGroups => "nsgs",
            PublicIps => "public-ips",
            LoadBalancers => "load-balancers",
            RouteTables => "route-tables",
            NatGateways => "nat-gateways",
            PrivateEndpoints => "private-endpoints",
            BastionHosts => "bastion-hosts",
            DdosPlans => "ddos-plans",
            ApplicationSecurityGroups => "asgs",
            Galleries => "galleries",
            PrivateDnsZones => "private-dns-zones",
            DnsZones => "dns-zones",
            DnsResolvers => "dns-resolvers",
            DnsForwardingRulesets => "dns-forwarding-rulesets",
            DnsResolverPolicies => "dns-resolver-policies",
            TrafficManagerProfiles => "traffic-manager-profiles",
            AppGateways => "app-gateways",
            FrontDoorProfiles => "front-door-profiles",
            WafPolicies => "waf-policies",
            PrivateLinkServices => "private-link-services",
            ExpressRouteCircuits => "expressroute-circuits",
            VnetGateways => "vnet-gateways",
            GatewayConnections => "gateway-connections",
            LocalGateways => "local-gateways",
            VirtualWans => "virtual-wans",
            VirtualHubs => "virtual-hubs",
            VwanVpnGateways => "vwan-vpn-gateways",
            VwanErGateways => "vwan-er-gateways",
            P2sGateways => "p2s-gateways",
            VpnSites => "vpn-sites",
            AzureFirewalls => "azure-firewalls",
            FirewallPolicies => "firewall-policies",
            IpGroups => "ip-groups",
            CloudNgfws => "cloud-ngfws",
            NgfwRulestacks => "ngfw-rulestacks",
            RecoveryVaults => "recovery-vaults",
            BackupVaults => "backup-vaults",
            KeyVaults => "vaults",
            Identities => "identities",
            ServicePrincipals => "service-principals",
            AppRegistrations => "app-registrations",
            Clusters => "clusters",
            NodePools => "node-pools",
            Registries => "registries",
            WebApps => "apps",
            FunctionApps => "function-apps",
            AppServicePlans => "plans",
            StaticSites => "static-sites",
            SqlServers => "sql-servers",
            ManagedInstances => "managed-instances",
            InstancePools => "instance-pools",
            CosmosAccounts => "cosmos-accounts",
            PostgresServers => "postgres-servers",
            MysqlServers => "mysql-servers",
            AiAccounts => "ai-accounts",
            SearchServices => "search-services",
            LogWorkspaces => "log-workspaces",
            MetricAlerts => "metric-alerts",
            LogAlerts => "log-alerts",
            ActivityLogAlerts => "activity-log-alerts",
            ActionGroups => "action-groups",
            AlertProcessingRules => "alert-processing-rules",
            FiredAlerts => "fired-alerts",
            AppInsights => "app-insights",
            EnterprisePolicies => "enterprise-policies",
            AutomationAccounts => "automation-accounts",
            ArcMachines => "arc-machines",
            ArcClusters => "arc-kubernetes",
            ArcPrivateLinkScopes => "arc-private-link-scopes",
            HostPools => "host-pools",
            AvdApplicationGroups => "avd-application-groups",
            AvdWorkspaces => "avd-workspaces",
            ScalingPlans => "scaling-plans",
            ContainerApps => "container-apps",
            ContainerAppEnvironments => "container-app-environments",
            ContainerAppJobs => "container-app-jobs",
            ContainerGroups => "container-groups",
            RedisCaches => "redis-caches",
            ManagedRedis => "managed-redis",
            ServiceBusNamespaces => "servicebus-namespaces",
            EventHubNamespaces => "eventhub-namespaces",
            PolicyAssignments => "policy-assignments",
            PolicyExemptions => "policy-exemptions",
            PolicyDefinitions => "policy-definitions",
            ResourceLocks => "resource-locks",
            ManagementGroups => "management-groups",
            Budgets => "budgets",
            DefenderRecommendations => "defender-recommendations",
            DefenderAlerts => "defender-alerts",
            SecureScore => "secure-score",
            DefenderPlans => "defender-plans",
            AdvisorRecommendations => "advisor-recommendations",
            AdvisorScore => "advisor-score",
            AdvisorSuppressions => "advisor-suppressions",
            ChangesAll => "changes",
            ChangesActivity => "changes-activity",
            ChangesDeployments => "changes-deployments",
            ChangesHealth => "changes-health",
            Audit => "audit",
        }
    }

    /// Sub-tab chip label.
    pub fn label(&self) -> &'static str {
        use JumpView::*;
        match self {
            Subscriptions => "Subscriptions",
            ResourceGroups => "Resource Groups",
            AllResources => "All resources",
            VirtualMachines => "VMs",
            Disks => "Disks",
            Nics => "NICs",
            ScaleSets => "Scale sets",
            StorageAccounts => "Accounts",
            VirtualNetworks => "VNets",
            Subnets => "Subnets",
            NetworkSecurityGroups => "NSGs",
            PublicIps => "Public IPs",
            LoadBalancers => "LBs",
            RouteTables => "Routes",
            NatGateways => "NAT",
            PrivateEndpoints => "PEs",
            BastionHosts => "Bastion",
            DdosPlans => "DDoS",
            ApplicationSecurityGroups => "ASGs",
            Galleries => "Galleries",
            PrivateDnsZones => "Private DNS",
            DnsZones => "DNS zones",
            DnsResolvers => "Resolvers",
            DnsForwardingRulesets => "Rulesets",
            DnsResolverPolicies => "DNS policies",
            TrafficManagerProfiles => "Traffic Manager",
            AppGateways => "App gateways",
            FrontDoorProfiles => "Front Door",
            WafPolicies => "WAF policies",
            PrivateLinkServices => "Private Link",
            ExpressRouteCircuits => "ER circuits",
            VnetGateways => "VNet gateways",
            GatewayConnections => "Connections",
            LocalGateways => "Local gateways",
            VirtualWans => "WANs",
            VirtualHubs => "Hubs",
            VwanVpnGateways => "VPN gateways",
            VwanErGateways => "ER gateways",
            P2sGateways => "P2S gateways",
            VpnSites => "VPN sites",
            AzureFirewalls => "Firewalls",
            FirewallPolicies => "Policies",
            IpGroups => "IP groups",
            CloudNgfws => "Cloud NGFW",
            NgfwRulestacks => "Rulestacks",
            RecoveryVaults => "Recovery vaults",
            BackupVaults => "Backup vaults",
            KeyVaults => "Vaults",
            Identities => "Identities",
            ServicePrincipals => "Service principals",
            AppRegistrations => "App registrations",
            Clusters => "Clusters",
            NodePools => "Node pools",
            Registries => "Registries",
            WebApps => "Apps",
            FunctionApps => "Functions",
            AppServicePlans => "Plans",
            StaticSites => "Static sites",
            SqlServers => "Servers",
            ManagedInstances => "Managed instances",
            InstancePools => "Instance pools",
            CosmosAccounts => "Accounts",
            PostgresServers => "PostgreSQL",
            MysqlServers => "MySQL",
            AiAccounts => "Resources",
            SearchServices => "Search services",
            LogWorkspaces => "Workspaces",
            MetricAlerts => "Metric alerts",
            LogAlerts => "Log alerts",
            ActivityLogAlerts => "Activity alerts",
            ActionGroups => "Action groups",
            AlertProcessingRules => "Processing rules",
            FiredAlerts => "Fired alerts",
            AppInsights => "App Insights",
            EnterprisePolicies => "Enterprise policies",
            AutomationAccounts => "Accounts",
            ArcMachines => "Servers",
            ArcClusters => "Kubernetes",
            ArcPrivateLinkScopes => "Private link scopes",
            HostPools => "Host pools",
            AvdApplicationGroups => "App groups",
            AvdWorkspaces => "Workspaces",
            ScalingPlans => "Scaling plans",
            ContainerApps => "Apps",
            ContainerAppEnvironments => "Environments",
            ContainerAppJobs => "Jobs",
            ContainerGroups => "Container groups",
            RedisCaches => "Caches",
            ManagedRedis => "Managed Redis",
            ServiceBusNamespaces => "Service Bus",
            EventHubNamespaces => "Event Hubs",
            PolicyAssignments => "Assignments",
            PolicyExemptions => "Exemptions",
            PolicyDefinitions => "Definitions",
            ResourceLocks => "Locks",
            ManagementGroups => "Management groups",
            Budgets => "Budgets",
            DefenderRecommendations => "Recommendations",
            DefenderAlerts => "Alerts",
            SecureScore => "Secure score",
            DefenderPlans => "Plans",
            AdvisorRecommendations => "Recommendations",
            AdvisorScore => "Score",
            AdvisorSuppressions => "Suppressions",
            ChangesAll => "All",
            ChangesActivity => "Activity",
            ChangesDeployments => "Deployments",
            ChangesHealth => "Health",
            Audit => "Findings",
        }
    }

    /// The sub-tab that lists an ARM id's type, from its resource-provider
    /// namespace and type chain — the jump router (ticket 06). `None` for
    /// a type nebaz does not browse (a public IP prefix, a firewall).
    pub fn for_arm_id(id: &str) -> Option<JumpView> {
        use crate::azure::resource::{arm_type_chain, resource_group_of, subscription_of};
        let Some((ns, chain)) = arm_type_chain(id) else {
            return match (subscription_of(id), resource_group_of(id)) {
                (Some(_), Some(_)) => Some(JumpView::ResourceGroups),
                (Some(_), None) => Some(JumpView::Subscriptions),
                _ => None,
            };
        };
        let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
        Some(match (ns.as_str(), chain.as_slice()) {
            ("microsoft.compute", ["virtualmachines"]) => JumpView::VirtualMachines,
            ("microsoft.compute", ["disks"]) => JumpView::Disks,
            ("microsoft.network", ["networkinterfaces"]) => JumpView::Nics,
            ("microsoft.compute", ["virtualmachinescalesets"]) => JumpView::ScaleSets,
            ("microsoft.storage", ["storageaccounts"]) => JumpView::StorageAccounts,
            ("microsoft.network", ["virtualnetworks"]) => JumpView::VirtualNetworks,
            ("microsoft.network", ["virtualnetworks", "subnets"]) => JumpView::Subnets,
            ("microsoft.network", ["networksecuritygroups"]) => JumpView::NetworkSecurityGroups,
            ("microsoft.network", ["publicipaddresses"]) => JumpView::PublicIps,
            ("microsoft.network", ["loadbalancers"]) => JumpView::LoadBalancers,
            ("microsoft.network", ["routetables"]) => JumpView::RouteTables,
            ("microsoft.network", ["natgateways"]) => JumpView::NatGateways,
            ("microsoft.network", ["privateendpoints"]) => JumpView::PrivateEndpoints,
            ("microsoft.network", ["bastionhosts"]) => JumpView::BastionHosts,
            ("microsoft.network", ["ddosprotectionplans"]) => JumpView::DdosPlans,
            ("microsoft.network", ["applicationsecuritygroups"]) => JumpView::ApplicationSecurityGroups,
            ("microsoft.compute", ["galleries"]) => JumpView::Galleries,
            ("microsoft.network", ["privatednszones"]) => JumpView::PrivateDnsZones,
            ("microsoft.network", ["dnszones"]) => JumpView::DnsZones,
            ("microsoft.network", ["dnsresolvers"]) => JumpView::DnsResolvers,
            ("microsoft.network", ["dnsforwardingrulesets"]) => JumpView::DnsForwardingRulesets,
            ("microsoft.network", ["dnsresolverpolicies"]) => JumpView::DnsResolverPolicies,
            ("microsoft.network", ["trafficmanagerprofiles"]) => JumpView::TrafficManagerProfiles,
            ("microsoft.network", ["applicationgateways"]) => JumpView::AppGateways,
            ("microsoft.network", ["applicationgatewaywebapplicationfirewallpolicies"])
            | ("microsoft.network", ["frontdoorwebapplicationfirewallpolicies"]) => JumpView::WafPolicies,
            ("microsoft.network", ["privatelinkservices"]) => JumpView::PrivateLinkServices,
            // Classic CDN profiles share the type; the list keeps Front
            // Door Standard / Premium only, so a classic one is not found.
            ("microsoft.cdn", ["profiles"]) => JumpView::FrontDoorProfiles,
            ("microsoft.network", ["expressroutecircuits"]) => JumpView::ExpressRouteCircuits,
            ("microsoft.network", ["virtualnetworkgateways"]) => JumpView::VnetGateways,
            ("microsoft.network", ["connections"]) => JumpView::GatewayConnections,
            ("microsoft.network", ["localnetworkgateways"]) => JumpView::LocalGateways,
            ("microsoft.network", ["virtualwans"]) => JumpView::VirtualWans,
            ("microsoft.network", ["virtualhubs"]) => JumpView::VirtualHubs,
            ("microsoft.network", ["vpngateways"]) => JumpView::VwanVpnGateways,
            ("microsoft.network", ["expressroutegateways"]) => JumpView::VwanErGateways,
            ("microsoft.network", ["p2svpngateways"]) => JumpView::P2sGateways,
            ("microsoft.network", ["vpnsites"]) => JumpView::VpnSites,
            ("microsoft.network", ["azurefirewalls"]) => JumpView::AzureFirewalls,
            ("microsoft.network", ["firewallpolicies"]) => JumpView::FirewallPolicies,
            ("microsoft.network", ["ipgroups"]) => JumpView::IpGroups,
            ("paloaltonetworks.cloudngfw", ["firewalls"]) => JumpView::CloudNgfws,
            ("paloaltonetworks.cloudngfw", ["localrulestacks"]) => JumpView::NgfwRulestacks,
            ("microsoft.recoveryservices", ["vaults"]) => JumpView::RecoveryVaults,
            ("microsoft.dataprotection", ["backupvaults"]) => JumpView::BackupVaults,
            ("microsoft.keyvault", ["vaults"]) => JumpView::KeyVaults,
            ("microsoft.managedidentity", ["userassignedidentities"]) => JumpView::Identities,
            ("microsoft.containerservice", ["managedclusters"]) => JumpView::Clusters,
            ("microsoft.containerservice", ["managedclusters", "agentpools"]) => JumpView::NodePools,
            ("microsoft.containerregistry", ["registries"]) => JumpView::Registries,
            // A site's id does not say its kind; Apps lists every site.
            ("microsoft.web", ["sites"]) => JumpView::WebApps,
            ("microsoft.web", ["serverfarms"]) => JumpView::AppServicePlans,
            ("microsoft.web", ["staticsites"]) => JumpView::StaticSites,
            ("microsoft.sql", ["servers"]) => JumpView::SqlServers,
            ("microsoft.sql", ["managedinstances"]) => JumpView::ManagedInstances,
            ("microsoft.sql", ["instancepools"]) => JumpView::InstancePools,
            ("microsoft.documentdb", ["databaseaccounts"]) => JumpView::CosmosAccounts,
            ("microsoft.dbforpostgresql", ["flexibleservers"]) => JumpView::PostgresServers,
            ("microsoft.dbformysql", ["flexibleservers"]) => JumpView::MysqlServers,
            ("microsoft.cognitiveservices", ["accounts"]) => JumpView::AiAccounts,
            ("microsoft.search", ["searchservices"]) => JumpView::SearchServices,
            ("microsoft.operationalinsights", ["workspaces"]) => JumpView::LogWorkspaces,
            ("microsoft.insights", ["components"]) => JumpView::AppInsights,
            ("microsoft.insights", ["metricalerts"]) => JumpView::MetricAlerts,
            ("microsoft.insights", ["scheduledqueryrules"]) => JumpView::LogAlerts,
            ("microsoft.insights", ["activitylogalerts"]) => JumpView::ActivityLogAlerts,
            ("microsoft.insights", ["actiongroups"]) => JumpView::ActionGroups,
            ("microsoft.alertsmanagement", ["actionrules"]) => JumpView::AlertProcessingRules,
            ("microsoft.alertsmanagement", ["alerts"]) => JumpView::FiredAlerts,
            ("microsoft.powerplatform", ["enterprisepolicies"]) => JumpView::EnterprisePolicies,
            ("microsoft.automation", ["automationaccounts"]) => JumpView::AutomationAccounts,
            ("microsoft.hybridcompute", ["machines"]) => JumpView::ArcMachines,
            ("microsoft.kubernetes", ["connectedclusters"]) => JumpView::ArcClusters,
            ("microsoft.hybridcompute", ["privatelinkscopes"]) => JumpView::ArcPrivateLinkScopes,
            ("microsoft.desktopvirtualization", ["hostpools"]) => JumpView::HostPools,
            ("microsoft.desktopvirtualization", ["applicationgroups"]) => JumpView::AvdApplicationGroups,
            ("microsoft.desktopvirtualization", ["workspaces"]) => JumpView::AvdWorkspaces,
            ("microsoft.desktopvirtualization", ["scalingplans"]) => JumpView::ScalingPlans,
            ("microsoft.app", ["containerapps"]) => JumpView::ContainerApps,
            ("microsoft.app", ["managedenvironments"]) => JumpView::ContainerAppEnvironments,
            ("microsoft.app", ["jobs"]) => JumpView::ContainerAppJobs,
            ("microsoft.containerinstance", ["containergroups"]) => JumpView::ContainerGroups,
            ("microsoft.cache", ["redis"]) => JumpView::RedisCaches,
            ("microsoft.cache", ["redisenterprise"]) => JumpView::ManagedRedis,
            ("microsoft.servicebus", ["namespaces"]) => JumpView::ServiceBusNamespaces,
            ("microsoft.eventhub", ["namespaces"]) => JumpView::EventHubNamespaces,
            // Governance (ADR 0009): wherever made, management groups
            // included. A built-in definition is in no list (custom only).
            ("microsoft.authorization", ["policyassignments"]) => JumpView::PolicyAssignments,
            ("microsoft.authorization", ["policyexemptions"]) => JumpView::PolicyExemptions,
            ("microsoft.authorization", ["policydefinitions" | "policysetdefinitions"])
                if !crate::azure::services::governance::is_builtin_definition(id) =>
            {
                JumpView::PolicyDefinitions
            }
            ("microsoft.authorization", ["locks"]) => JumpView::ResourceLocks,
            ("microsoft.management", ["managementgroups"]) => JumpView::ManagementGroups,
            ("microsoft.consumption", ["budgets"]) => JumpView::Budgets,
            // Defender (ADR 0010): an assessment is an extension resource
            // on what it assessed.
            ("microsoft.security", ["assessments"]) => JumpView::DefenderRecommendations,
            ("microsoft.security", ["locations", "alerts"]) => JumpView::DefenderAlerts,
            ("microsoft.security", ["securescores"] | ["securescores", "securescorecontrols"]) => JumpView::SecureScore,
            ("microsoft.security", ["pricings"]) => JumpView::DefenderPlans,
            // Advisor (ADR 0011): a recommendation is an extension
            // resource on what it is about, a suppression its child.
            ("microsoft.advisor", ["recommendations"]) => JumpView::AdvisorRecommendations,
            ("microsoft.advisor", ["recommendations", "suppressions"]) => JumpView::AdvisorSuppressions,
            ("microsoft.advisor", ["advisorscore"]) => JumpView::AdvisorScore,
            _ => return None,
        })
    }

    /// The sub-tab a synthetic directory id (`graph:/servicePrincipals/…`,
    /// or its `(appId='…')` alias) is listed in. Directory rows have no
    /// ARM id, so `for_arm_id` never sees them.
    pub fn for_graph_id(id: &str) -> Option<JumpView> {
        use crate::azure::graph::{kind_of_id, DirectoryKind};
        kind_of_id(id).map(|k| match k {
            DirectoryKind::ServicePrincipal => JumpView::ServicePrincipals,
            DirectoryKind::Application => JumpView::AppRegistrations,
        })
    }

    /// Where a jump to an ARM id lands: its typed sub-tab, else All
    /// resources for a top-level resource in a group (the generic list has
    /// every one). A child of an unbrowsed type (a vault's secret) is in
    /// no list: `None`, and the jump copies the id instead. A synthetic
    /// directory id lands on its Graph sub-tab.
    pub fn landing_for_arm_id(id: &str) -> Option<JumpView> {
        use crate::azure::resource::{arm_type_chain, resource_group_of};
        if let Some(view) = JumpView::for_graph_id(id) {
            return Some(view);
        }
        // All resources lists top-level resources only: never an extension
        // resource (a role assignment, a lock on something).
        JumpView::for_arm_id(id).or_else(|| match arm_type_chain(id) {
            Some((ns, chain))
                if chain.len() == 1
                    && resource_group_of(id).is_some()
                    && ns != "microsoft.authorization"
                    && id.to_ascii_lowercase().matches("/providers/").count() == 1 =>
            {
                Some(JumpView::AllResources)
            }
            _ => None,
        })
    }

    /// Whether this sub-tab's list has no subscription in its path. Only
    /// the subscription list itself: its rows belong to the tenant, so a
    /// subscription switch never invalidates them.
    pub fn is_tenant_scoped(&self) -> bool {
        matches!(self, JumpView::Subscriptions)
    }

    /// Whether listing this sub-tab once per subscription means something
    /// (the `P` counts and `ls --subscriptions`, #62). Not for the tenant's
    /// lists (subscriptions, the directory's service principals and app
    /// registrations, the management groups: the same rows from every
    /// subscription of a tenant),
    /// nor `@changes` (one list per time window, its sub-tabs filter it,
    /// and each subscription's Activity Log read is the costliest list),
    /// nor a virtual service's (`@audit`: computed, never listed).
    pub fn fans_out(&self) -> bool {
        use JumpView::*;
        !self.is_tenant_scoped()
            && !self.service().is_virtual()
            && !matches!(
                self,
                ServicePrincipals
                    | AppRegistrations
                    | ManagementGroups
                    | ChangesAll
                    | ChangesActivity
                    | ChangesDeployments
                    | ChangesHealth
            )
    }
}

impl ServiceType {
    pub fn all() -> Vec<ServiceType> {
        vec![
            ServiceType::Subscriptions,
            ServiceType::VirtualMachines,
            ServiceType::Arc,
            ServiceType::VirtualDesktop,
            ServiceType::Storage,
            ServiceType::Backup,
            ServiceType::Network,
            ServiceType::Dns,
            ServiceType::Edge,
            ServiceType::Hybrid,
            ServiceType::VirtualWan,
            ServiceType::Firewall,
            ServiceType::KeyVault,
            ServiceType::Identity,
            ServiceType::Aks,
            ServiceType::ContainerRegistry,
            ServiceType::AppService,
            ServiceType::Sql,
            ServiceType::Cosmos,
            ServiceType::PostgresMysql,
            ServiceType::Foundry,
            ServiceType::Monitor,
            ServiceType::PowerPlatform,
            ServiceType::Automation,
            ServiceType::ContainerApps,
            ServiceType::Redis,
            ServiceType::Messaging,
            ServiceType::Governance,
            ServiceType::Defender,
            ServiceType::Advisor,
            ServiceType::Changes,
            ServiceType::Audit,
        ]
    }

    /// A service with no ARM list of its own: its rows are computed in the
    /// app from other services' caches (`App::load_service_resources`
    /// short-circuits it), so it is never cached and never streamed.
    pub fn is_virtual(&self) -> bool {
        matches!(self, ServiceType::Audit)
    }

    /// Ordered picker categories. Every `category()` value must appear here.
    pub const CATEGORIES: &'static [&'static str] =
        &["Management", "Compute", "Storage", "Networking", "Security", "Containers", "Web", "Databases", "Integration", "AI", "Monitoring"];

    pub fn category(&self) -> &'static str {
        match self {
            ServiceType::Subscriptions => "Management",
            ServiceType::VirtualMachines => "Compute",
            ServiceType::Storage => "Storage",
            ServiceType::Backup => "Storage",
            ServiceType::Network => "Networking",
            ServiceType::Dns => "Networking",
            ServiceType::Edge => "Networking",
            ServiceType::Hybrid => "Networking",
            ServiceType::VirtualWan => "Networking",
            ServiceType::Firewall => "Networking",
            ServiceType::KeyVault => "Security",
            ServiceType::Identity => "Security",
            ServiceType::Aks => "Containers",
            ServiceType::ContainerRegistry => "Containers",
            ServiceType::AppService => "Web",
            ServiceType::Sql => "Databases",
            ServiceType::Cosmos => "Databases",
            ServiceType::PostgresMysql => "Databases",
            ServiceType::Foundry => "AI",
            ServiceType::Monitor => "Monitoring",
            ServiceType::PowerPlatform => "Management",
            ServiceType::Automation => "Management",
            ServiceType::Arc => "Compute",
            ServiceType::VirtualDesktop => "Compute",
            ServiceType::ContainerApps => "Containers",
            ServiceType::Redis => "Databases",
            ServiceType::Messaging => "Integration",
            ServiceType::Governance => "Management",
            ServiceType::Defender => "Security",
            ServiceType::Advisor => "Management",
            ServiceType::Changes => "Monitoring",
            ServiceType::Audit => "Security",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "Subscriptions",
            ServiceType::VirtualMachines => "Virtual Machines",
            ServiceType::Storage => "Storage",
            ServiceType::Backup => "Backup",
            ServiceType::Network => "Virtual Network",
            ServiceType::Dns => "DNS",
            ServiceType::Edge => "Edge",
            ServiceType::Hybrid => "Hybrid",
            ServiceType::VirtualWan => "Virtual WAN",
            ServiceType::Firewall => "Firewall",
            ServiceType::KeyVault => "Key Vault",
            ServiceType::Identity => "Managed Identity",
            ServiceType::Aks => "AKS",
            ServiceType::ContainerRegistry => "Container Registry",
            ServiceType::AppService => "App Service",
            ServiceType::Sql => "SQL",
            ServiceType::Cosmos => "Cosmos DB",
            ServiceType::PostgresMysql => "PostgreSQL & MySQL",
            ServiceType::Foundry => "Foundry",
            ServiceType::Monitor => "Monitor",
            ServiceType::PowerPlatform => "Power Platform",
            ServiceType::Automation => "Automation",
            ServiceType::Arc => "Azure Arc",
            ServiceType::VirtualDesktop => "Virtual Desktop",
            ServiceType::ContainerApps => "Container Apps",
            ServiceType::Redis => "Redis",
            ServiceType::Messaging => "Messaging",
            ServiceType::Governance => "Governance",
            ServiceType::Defender => "Defender",
            ServiceType::Advisor => "Advisor",
            ServiceType::Changes => "Changes",
            ServiceType::Audit => "Audit",
        }
    }

    /// Tab-strip / picker label (≤ 10 chars).
    pub fn short_name(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "Subs",
            ServiceType::VirtualMachines => "VMs",
            ServiceType::Storage => "Storage",
            ServiceType::Backup => "Backup",
            ServiceType::Network => "VNet",
            ServiceType::Dns => "DNS",
            ServiceType::Edge => "Edge",
            ServiceType::Hybrid => "Hybrid",
            ServiceType::VirtualWan => "vWAN",
            ServiceType::Firewall => "Firewall",
            ServiceType::KeyVault => "Key Vault",
            ServiceType::Identity => "Identity",
            ServiceType::Aks => "AKS",
            ServiceType::ContainerRegistry => "ACR",
            ServiceType::AppService => "App Svc",
            ServiceType::Sql => "SQL",
            ServiceType::Cosmos => "Cosmos",
            ServiceType::PostgresMysql => "PG/MySQL",
            ServiceType::Foundry => "Foundry",
            ServiceType::Monitor => "Monitor",
            ServiceType::PowerPlatform => "Power Plat",
            ServiceType::Automation => "Automation",
            ServiceType::Arc => "Arc",
            ServiceType::VirtualDesktop => "AVD",
            ServiceType::ContainerApps => "ACA",
            ServiceType::Redis => "Redis",
            ServiceType::Messaging => "Messaging",
            ServiceType::Governance => "Governance",
            ServiceType::Defender => "Defender",
            ServiceType::Advisor => "Advisor",
            ServiceType::Changes => "Changes",
            ServiceType::Audit => "Audit",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "Subscriptions, groups & all resources",
            ServiceType::VirtualMachines => "VMs, disks, NICs, scale sets, ASGs & galleries",
            ServiceType::Storage => "Storage Accounts & Containers",
            ServiceType::Backup => "Recovery Services & Backup vaults: protected items, policies, jobs",
            ServiceType::Network => "VNets, NSGs, IPs, LBs, NAT, Bastion & DDoS",
            ServiceType::Dns => "DNS zones, resolvers, rulesets & Traffic Manager",
            ServiceType::Edge => "App gateways, Front Door, WAF & Private Link",
            ServiceType::Hybrid => "ExpressRoute, VNet gateways, connections & local gateways",
            ServiceType::VirtualWan => "Virtual WANs, hubs, hub gateways & VPN sites",
            ServiceType::Firewall => "Azure Firewall, policies, IP groups & Cloud NGFW",
            ServiceType::KeyVault => "Key Vaults (metadata only)",
            ServiceType::Identity => "Managed identities, service principals & app registrations",
            ServiceType::Aks => "Kubernetes Clusters & Node Pools",
            ServiceType::ContainerRegistry => "Container registries",
            ServiceType::AppService => "Web & function apps, plans, static web apps",
            ServiceType::Sql => "SQL servers, managed instances & pools",
            ServiceType::Cosmos => "Cosmos DB accounts",
            ServiceType::PostgresMysql => "PostgreSQL & MySQL flexible servers",
            ServiceType::Foundry => "Foundry, OpenAI & AI Search (metadata only)",
            ServiceType::Monitor => "Log Analytics, App Insights & alerts",
            ServiceType::PowerPlatform => "Power Platform enterprise policies",
            ServiceType::Automation => "Runbooks, schedules, jobs & hybrid workers",
            ServiceType::Arc => "Servers, Kubernetes & private link scopes",
            ServiceType::VirtualDesktop => "Host pools, session hosts, app groups, workspaces & scaling plans",
            ServiceType::ContainerApps => "Container apps, environments, jobs & instances",
            ServiceType::Redis => "Azure Cache for Redis & Managed Redis",
            ServiceType::Messaging => "Service Bus & Event Hubs namespaces",
            ServiceType::Governance => "Policy, locks & management groups",
            ServiceType::Defender => "Recommendations, alerts, score & plans",
            ServiceType::Advisor => "Recommendations, score & suppressions",
            ServiceType::Changes => "What changed recently, subscription-wide",
            ServiceType::Audit => "Security findings from what's loaded (no API calls)",
        }
    }

    /// The service's sub-tabs in display order (ticket 04's table). A
    /// single-entry service hides the sub-tab bar.
    pub fn views(&self) -> &'static [JumpView] {
        use JumpView::*;
        match self {
            ServiceType::Subscriptions => &[Subscriptions, ResourceGroups, AllResources],
            ServiceType::VirtualMachines => &[VirtualMachines, Disks, Nics, ScaleSets, ApplicationSecurityGroups, Galleries],
            ServiceType::Storage => &[StorageAccounts],
            ServiceType::Backup => &[RecoveryVaults, BackupVaults],
            ServiceType::Network => &[
                VirtualNetworks,
                Subnets,
                NetworkSecurityGroups,
                PublicIps,
                LoadBalancers,
                RouteTables,
                NatGateways,
                PrivateEndpoints,
                BastionHosts,
                DdosPlans,
            ],
            ServiceType::Dns => &[
                PrivateDnsZones,
                DnsZones,
                DnsResolvers,
                DnsForwardingRulesets,
                DnsResolverPolicies,
                TrafficManagerProfiles,
            ],
            ServiceType::Edge => &[AppGateways, FrontDoorProfiles, WafPolicies, PrivateLinkServices],
            ServiceType::Hybrid => &[ExpressRouteCircuits, VnetGateways, GatewayConnections, LocalGateways],
            ServiceType::VirtualWan => &[VirtualWans, VirtualHubs, VwanVpnGateways, VwanErGateways, P2sGateways, VpnSites],
            ServiceType::Firewall => &[AzureFirewalls, FirewallPolicies, IpGroups, CloudNgfws, NgfwRulestacks],
            ServiceType::KeyVault => &[KeyVaults],
            ServiceType::Identity => &[Identities, ServicePrincipals, AppRegistrations],
            ServiceType::Aks => &[Clusters, NodePools],
            ServiceType::ContainerRegistry => &[Registries],
            ServiceType::AppService => &[WebApps, FunctionApps, AppServicePlans, StaticSites],
            ServiceType::Sql => &[SqlServers, ManagedInstances, InstancePools],
            ServiceType::Cosmos => &[CosmosAccounts],
            ServiceType::PostgresMysql => &[PostgresServers, MysqlServers],
            ServiceType::Foundry => &[AiAccounts, SearchServices],
            ServiceType::Monitor => &[
                LogWorkspaces,
                AppInsights,
                MetricAlerts,
                LogAlerts,
                ActivityLogAlerts,
                ActionGroups,
                AlertProcessingRules,
                FiredAlerts,
            ],
            ServiceType::PowerPlatform => &[EnterprisePolicies],
            ServiceType::Automation => &[AutomationAccounts],
            ServiceType::Arc => &[ArcMachines, ArcClusters, ArcPrivateLinkScopes],
            ServiceType::VirtualDesktop => &[HostPools, AvdApplicationGroups, AvdWorkspaces, ScalingPlans],
            ServiceType::ContainerApps => &[ContainerApps, ContainerAppEnvironments, ContainerAppJobs, ContainerGroups],
            ServiceType::Redis => &[RedisCaches, ManagedRedis],
            ServiceType::Messaging => &[ServiceBusNamespaces, EventHubNamespaces],
            ServiceType::Governance => &[PolicyAssignments, PolicyExemptions, PolicyDefinitions, ResourceLocks, ManagementGroups, Budgets],
            ServiceType::Defender => &[DefenderRecommendations, DefenderAlerts, SecureScore, DefenderPlans],
            ServiceType::Advisor => &[AdvisorRecommendations, AdvisorScore, AdvisorSuppressions],
            ServiceType::Changes => &[ChangesAll, ChangesActivity, ChangesDeployments, ChangesHealth],
            ServiceType::Audit => &[Audit],
        }
    }

    /// The sub-tab a plain service prefix (`@vm`) lands on.
    pub fn default_view(&self) -> JumpView {
        self.views()[0]
    }

    /// Whether a list is tenant-scoped rather than subscription-scoped,
    /// given its cache variant (a `JumpView::as_str()`). The cache keys such
    /// lists under a fixed pseudo-subscription so a subscription switch
    /// doesn't refetch them (the analog of neboto's `is_global()` →
    /// `us-east-1` pinning). A missing variant means the service's default
    /// sub-tab.
    pub fn is_tenant_scoped(&self, variant: Option<&str>) -> bool {
        match variant {
            None => self.default_view().is_tenant_scoped(),
            Some(v) => self
                .views()
                .iter()
                .any(|view| view.as_str() == v && view.is_tenant_scoped()),
        }
    }

    /// Parse a `@prefix` (with or without the `@`) or any accepted alias.
    /// A **routing prefix** (`@rg`, `@disk`, `@nic`, `@subnet`, `@nsg`,
    /// `@pool`) names a sub-tab as well; a plain service prefix returns
    /// `None` for the view, meaning the service's first sub-tab.
    pub fn from_prefix(s: &str) -> Option<(ServiceType, Option<JumpView>)> {
        let s = s.trim().trim_start_matches('@').to_lowercase();
        let (service, view) = match s.as_str() {
            "sub" | "subs" | "subscription" | "subscriptions" => (ServiceType::Subscriptions, None),
            "rg" | "rgs" | "resourcegroup" | "resourcegroups" | "group" | "groups" => {
                (ServiceType::Subscriptions, Some(JumpView::ResourceGroups))
            }
            "all" | "resources" | "allresources" | "everything" => {
                (ServiceType::Subscriptions, Some(JumpView::AllResources))
            }
            "vm" | "vms" | "compute" | "virtualmachines" => (ServiceType::VirtualMachines, None),
            "disk" | "disks" => (ServiceType::VirtualMachines, Some(JumpView::Disks)),
            "nic" | "nics" => (ServiceType::VirtualMachines, Some(JumpView::Nics)),
            "vmss" | "scaleset" | "scalesets" | "virtualmachinescalesets" => {
                (ServiceType::VirtualMachines, Some(JumpView::ScaleSets))
            }
            "st" | "storage" | "blob" | "blobs" | "storageaccounts" => (ServiceType::Storage, None),
            "backup" | "backups" | "rsv" | "recoveryvault" | "recoveryvaults" | "recoveryservices" => (ServiceType::Backup, None),
            "bvault" | "bvaults" | "backupvault" | "backupvaults" | "dataprotection" | "dpp" => {
                (ServiceType::Backup, Some(JumpView::BackupVaults))
            }
            "vnet" | "vnets" | "net" | "network" => (ServiceType::Network, None),
            "subnet" | "subnets" => (ServiceType::Network, Some(JumpView::Subnets)),
            "nsg" | "nsgs" => (ServiceType::Network, Some(JumpView::NetworkSecurityGroups)),
            "pip" | "pips" | "publicip" | "publicips" => (ServiceType::Network, Some(JumpView::PublicIps)),
            "lb" | "lbs" | "loadbalancer" | "loadbalancers" => (ServiceType::Network, Some(JumpView::LoadBalancers)),
            "rt" | "route" | "routes" | "routetable" | "routetables" => {
                (ServiceType::Network, Some(JumpView::RouteTables))
            }
            "nat" | "natgw" | "natgateway" | "natgateways" => (ServiceType::Network, Some(JumpView::NatGateways)),
            "pe" | "pes" | "privateendpoint" | "privateendpoints" => {
                (ServiceType::Network, Some(JumpView::PrivateEndpoints))
            }
            "bastion" | "bastions" | "bas" | "bastionhost" | "bastionhosts" => {
                (ServiceType::Network, Some(JumpView::BastionHosts))
            }
            "ddos" | "ddosplan" | "ddosplans" | "ddosprotection" | "ddosprotectionplans" => {
                (ServiceType::Network, Some(JumpView::DdosPlans))
            }
            "asg" | "asgs" | "applicationsecuritygroup" | "applicationsecuritygroups" => {
                (ServiceType::VirtualMachines, Some(JumpView::ApplicationSecurityGroups))
            }
            "gallery" | "galleries" | "sig" | "acg" | "computegallery" | "imagegallery" => {
                (ServiceType::VirtualMachines, Some(JumpView::Galleries))
            }
            "dns" => (ServiceType::Dns, None),
            "changes" | "change" | "changed" | "recent" => (ServiceType::Changes, None),
            "activity" | "operations" => (ServiceType::Changes, Some(JumpView::ChangesActivity)),
            "deploys" | "deployments" => (ServiceType::Changes, Some(JumpView::ChangesDeployments)),
            "health" | "resourcehealth" => (ServiceType::Changes, Some(JumpView::ChangesHealth)),
            "pdns" | "privatedns" | "privatednszone" | "privatednszones" => {
                (ServiceType::Dns, Some(JumpView::PrivateDnsZones))
            }
            "dnsz" | "dnszone" | "dnszones" | "publicdns" => (ServiceType::Dns, Some(JumpView::DnsZones)),
            "dnsr" | "resolver" | "resolvers" | "dnsresolver" | "dnsresolvers" => {
                (ServiceType::Dns, Some(JumpView::DnsResolvers))
            }
            "dnsfr" | "ruleset" | "rulesets" | "forwardingruleset" | "forwardingrulesets" => {
                (ServiceType::Dns, Some(JumpView::DnsForwardingRulesets))
            }
            "dnsp" | "dnspolicy" | "dnspolicies" | "dnssecuritypolicy" | "dnssecuritypolicies" => {
                (ServiceType::Dns, Some(JumpView::DnsResolverPolicies))
            }
            "agw" | "appgw" | "appgateway" | "appgateways" | "applicationgateway" | "applicationgateways" | "edge" => {
                (ServiceType::Edge, None)
            }
            "afd" | "frontdoor" | "frontdoors" | "fd" => (ServiceType::Edge, Some(JumpView::FrontDoorProfiles)),
            "waf" | "wafs" | "wafpolicy" | "wafpolicies" => (ServiceType::Edge, Some(JumpView::WafPolicies)),
            "pls" | "privatelink" | "privatelinkservice" | "privatelinkservices" => {
                (ServiceType::Edge, Some(JumpView::PrivateLinkServices))
            }
            "tm" | "trafficmanager" | "trafficmanagerprofile" | "trafficmanagerprofiles" | "atm" => {
                (ServiceType::Dns, Some(JumpView::TrafficManagerProfiles))
            }
            "er" | "erc" | "expressroute" | "expressroutecircuit" | "expressroutecircuits" | "circuit" | "circuits" | "hybrid" => {
                (ServiceType::Hybrid, None)
            }
            "vgw" | "vng" | "vnetgateway" | "vnetgateways" | "vpngateway" | "vpngateways" | "ergateway" => {
                (ServiceType::Hybrid, Some(JumpView::VnetGateways))
            }
            "cn" | "conn" | "connection" | "connections" | "vpnconnection" | "vpnconnections" => {
                (ServiceType::Hybrid, Some(JumpView::GatewayConnections))
            }
            "lgw" | "lng" | "localgateway" | "localgateways" | "localnetworkgateway" | "localnetworkgateways" => {
                (ServiceType::Hybrid, Some(JumpView::LocalGateways))
            }
            "vwan" | "vwans" | "wan" | "wans" | "virtualwan" | "virtualwans" => (ServiceType::VirtualWan, None),
            "vhub" | "vhubs" | "hub" | "hubs" | "virtualhub" | "virtualhubs" => {
                (ServiceType::VirtualWan, Some(JumpView::VirtualHubs))
            }
            "hubvpn" | "s2s" | "s2sgateway" | "s2sgateways" | "vwanvpn" => {
                (ServiceType::VirtualWan, Some(JumpView::VwanVpnGateways))
            }
            "huber" | "vwaner" | "expressroutegateway" | "expressroutegateways" => {
                (ServiceType::VirtualWan, Some(JumpView::VwanErGateways))
            }
            "p2s" | "p2sgw" | "p2sgateway" | "p2sgateways" | "p2svpngateway" | "p2svpngateways" => {
                (ServiceType::VirtualWan, Some(JumpView::P2sGateways))
            }
            "vpnsite" | "vpnsites" | "branch" | "branches" => (ServiceType::VirtualWan, Some(JumpView::VpnSites)),
            "fw" | "fws" | "firewall" | "firewalls" | "azfw" | "azurefirewall" | "azurefirewalls" => (ServiceType::Firewall, None),
            "fwp" | "fwpolicy" | "fwpolicies" | "firewallpolicy" | "firewallpolicies" => {
                (ServiceType::Firewall, Some(JumpView::FirewallPolicies))
            }
            "ipg" | "ipgroup" | "ipgroups" => (ServiceType::Firewall, Some(JumpView::IpGroups)),
            "ngfw" | "cloudngfw" | "palo" | "paloalto" | "pan" => (ServiceType::Firewall, Some(JumpView::CloudNgfws)),
            "rulestack" | "rulestacks" | "lrs" | "localrulestack" | "localrulestacks" => {
                (ServiceType::Firewall, Some(JumpView::NgfwRulestacks))
            }
            "kv" | "keyvault" | "keyvaults" | "vault" | "vaults" => (ServiceType::KeyVault, None),
            "id" | "ids" | "identity" | "identities" | "msi" | "uami" | "managedidentity" => (ServiceType::Identity, None),
            // `@app` is App Service's; app registrations are `@appreg`.
            "sp" | "sps" | "serviceprincipal" | "serviceprincipals" | "enterpriseapp" | "enterpriseapps" => {
                (ServiceType::Identity, Some(JumpView::ServicePrincipals))
            }
            "appreg" | "appregs" | "appregistration" | "appregistrations" | "application" | "applications" => {
                (ServiceType::Identity, Some(JumpView::AppRegistrations))
            }
            "aks" | "k8s" | "kubernetes" | "cluster" | "clusters" => (ServiceType::Aks, None),
            "pool" | "pools" | "nodepool" | "nodepools" => (ServiceType::Aks, Some(JumpView::NodePools)),
            "acr" | "acrs" | "cr" | "registry" | "registries" | "containerregistry" | "containerregistries" => {
                (ServiceType::ContainerRegistry, None)
            }
            "app" | "apps" | "web" | "webapp" | "webapps" | "appservice" | "site" | "sites" => (ServiceType::AppService, None),
            "func" | "funcs" | "function" | "functions" | "functionapp" | "functionapps" | "logicapp" | "logicapps" => {
                (ServiceType::AppService, Some(JumpView::FunctionApps))
            }
            "sql" | "sqlserver" | "sqlservers" | "azuresql" | "db" | "dbs" => (ServiceType::Sql, None),
            "sqlmi" | "mi" | "managedinstance" | "managedinstances" => (ServiceType::Sql, Some(JumpView::ManagedInstances)),
            "sqlpool" | "instancepool" | "instancepools" => (ServiceType::Sql, Some(JumpView::InstancePools)),
            "cosmos" | "cosmosdb" | "documentdb" | "docdb" => (ServiceType::Cosmos, None),
            "pg" | "postgres" | "postgresql" | "psql" | "flexibleserver" | "flexibleservers" => {
                (ServiceType::PostgresMysql, None)
            }
            "mysql" | "mysqlserver" | "mysqlservers" => (ServiceType::PostgresMysql, Some(JumpView::MysqlServers)),
            "plan" | "plans" | "asp" | "serverfarm" | "serverfarms" => {
                (ServiceType::AppService, Some(JumpView::AppServicePlans))
            }
            "swa" | "staticwebapp" | "staticwebapps" | "staticsite" | "staticsites" => {
                (ServiceType::AppService, Some(JumpView::StaticSites))
            }
            "foundry" | "aifoundry" | "aiservices" | "openai" | "aoai" | "cognitive" | "cognitiveservices" | "cog" => {
                (ServiceType::Foundry, None)
            }
            "search" | "srch" | "aisearch" | "cognitivesearch" | "searchservice" | "searchservices" => {
                (ServiceType::Foundry, Some(JumpView::SearchServices))
            }
            "monitor" | "monitoring" => (ServiceType::Monitor, None),
            "malert" | "malerts" | "metricalert" | "metricalerts" => (ServiceType::Monitor, Some(JumpView::MetricAlerts)),
            "logalert" | "logalerts" | "sqr" | "scheduledquery" | "scheduledqueryrules" => {
                (ServiceType::Monitor, Some(JumpView::LogAlerts))
            }
            "activityalert" | "activityalerts" | "activitylogalert" | "activitylogalerts" => {
                (ServiceType::Monitor, Some(JumpView::ActivityLogAlerts))
            }
            "ag" | "actiongroup" | "actiongroups" => (ServiceType::Monitor, Some(JumpView::ActionGroups)),
            "apr" | "processingrule" | "processingrules" | "actionrule" | "actionrules" => {
                (ServiceType::Monitor, Some(JumpView::AlertProcessingRules))
            }
            "alert" | "alerts" | "fired" | "firedalerts" => (ServiceType::Monitor, Some(JumpView::FiredAlerts)),
            "law" | "laws" | "loganalytics" | "workspace" | "workspaces" => {
                (ServiceType::Monitor, Some(JumpView::LogWorkspaces))
            }
            "appi" | "insights" | "appinsights" | "applicationinsights" | "component" | "components" => {
                (ServiceType::Monitor, Some(JumpView::AppInsights))
            }
            "pp" | "powerplatform" | "enterprisepolicy" | "enterprisepolicies" => {
                (ServiceType::PowerPlatform, None)
            }
            "automation" | "aa" | "automationaccount" | "automationaccounts" | "runbook" | "runbooks" => {
                (ServiceType::Automation, None)
            }
            "arc" | "azurearc" | "arcserver" | "arcservers" | "arcmachine" | "arcmachines" | "connectedmachine"
            | "connectedmachines" | "hybridcompute" => (ServiceType::Arc, None),
            "arck8s" | "arckubernetes" | "connectedk8s" | "connectedcluster" | "connectedclusters" => {
                (ServiceType::Arc, Some(JumpView::ArcClusters))
            }
            "arcpls" | "arcprivatelinkscope" | "arcprivatelinkscopes" => {
                (ServiceType::Arc, Some(JumpView::ArcPrivateLinkScopes))
            }
            "avd" | "virtualdesktop" | "wvd" | "hostpool" | "hostpools" | "sessionhost" | "sessionhosts" => {
                (ServiceType::VirtualDesktop, None)
            }
            "avdag" | "appgroup" | "appgroups" | "applicationgroup" | "applicationgroups" => {
                (ServiceType::VirtualDesktop, Some(JumpView::AvdApplicationGroups))
            }
            "avdws" | "avdworkspace" | "avdworkspaces" => (ServiceType::VirtualDesktop, Some(JumpView::AvdWorkspaces)),
            "avdsp" | "scalingplan" | "scalingplans" => (ServiceType::VirtualDesktop, Some(JumpView::ScalingPlans)),
            "aca" | "containerapp" | "containerapps" => (ServiceType::ContainerApps, None),
            "acaenv" | "acaenvs" | "cae" | "managedenvironment" | "managedenvironments" => {
                (ServiceType::ContainerApps, Some(JumpView::ContainerAppEnvironments))
            }
            "acajob" | "acajobs" | "containerappjob" | "containerappjobs" => {
                (ServiceType::ContainerApps, Some(JumpView::ContainerAppJobs))
            }
            "aci" | "containerinstance" | "containerinstances" | "containergroup" | "containergroups" | "cg" => {
                (ServiceType::ContainerApps, Some(JumpView::ContainerGroups))
            }
            "redis" | "cache" | "caches" | "rediscache" | "azurecache" => (ServiceType::Redis, None),
            "amr" | "managedredis" | "redisenterprise" => (ServiceType::Redis, Some(JumpView::ManagedRedis)),
            "sb" | "servicebus" | "messaging" | "msg" => (ServiceType::Messaging, None),
            "eh" | "eventhub" | "eventhubs" | "kafka" => (ServiceType::Messaging, Some(JumpView::EventHubNamespaces)),
            "gov" | "governance" | "policy" | "policies" | "pa" | "assignment" | "assignments" => (ServiceType::Governance, None),
            "exempt" | "exemption" | "exemptions" => (ServiceType::Governance, Some(JumpView::PolicyExemptions)),
            "pdef" | "definition" | "definitions" | "initiative" | "initiatives" | "policyset" | "policysets" => {
                (ServiceType::Governance, Some(JumpView::PolicyDefinitions))
            }
            "lock" | "locks" | "resourcelock" | "resourcelocks" => (ServiceType::Governance, Some(JumpView::ResourceLocks)),
            "mg" | "mgs" | "managementgroup" | "managementgroups" => (ServiceType::Governance, Some(JumpView::ManagementGroups)),
            "budget" | "budgets" | "costbudget" | "costbudgets" => (ServiceType::Governance, Some(JumpView::Budgets)),
            "defender" | "mdc" | "asc" | "rec" | "recs" | "recommendation" | "recommendations" => (ServiceType::Defender, None),
            "secalert" | "secalerts" | "defenderalert" | "defenderalerts" => (ServiceType::Defender, Some(JumpView::DefenderAlerts)),
            "score" | "securescore" => (ServiceType::Defender, Some(JumpView::SecureScore)),
            "pricing" | "pricings" | "defenderplan" | "defenderplans" => (ServiceType::Defender, Some(JumpView::DefenderPlans)),
            "advisor" | "adv" => (ServiceType::Advisor, None),
            "advscore" | "advisorscore" => (ServiceType::Advisor, Some(JumpView::AdvisorScore)),
            "snooze" | "snoozed" | "suppression" | "suppressions" => (ServiceType::Advisor, Some(JumpView::AdvisorSuppressions)),
            "audit" | "findings" | "security" => (ServiceType::Audit, None),
            _ => return None,
        };
        Some((service, view))
    }

    /// Parse a prefix to its service only — for config keys and anything
    /// else that has no sub-tab to land on.
    pub fn from_prefix_service(s: &str) -> Option<ServiceType> {
        Self::from_prefix(s).map(|(service, _)| service)
    }

    /// Canonical `@prefix` (the completion dropdown shows these).
    pub fn prefix(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "@sub",
            ServiceType::VirtualMachines => "@vm",
            ServiceType::Storage => "@storage",
            ServiceType::Backup => "@backup",
            ServiceType::Network => "@vnet",
            ServiceType::Dns => "@dns",
            ServiceType::Edge => "@agw",
            ServiceType::Hybrid => "@er",
            ServiceType::VirtualWan => "@vwan",
            ServiceType::Firewall => "@fw",
            ServiceType::KeyVault => "@kv",
            ServiceType::Identity => "@id",
            ServiceType::Aks => "@aks",
            ServiceType::ContainerRegistry => "@acr",
            ServiceType::AppService => "@app",
            ServiceType::Sql => "@sql",
            ServiceType::Cosmos => "@cosmos",
            ServiceType::PostgresMysql => "@pg",
            ServiceType::Foundry => "@foundry",
            ServiceType::Monitor => "@monitor",
            ServiceType::PowerPlatform => "@pp",
            ServiceType::Automation => "@automation",
            ServiceType::Arc => "@arc",
            ServiceType::VirtualDesktop => "@avd",
            ServiceType::ContainerApps => "@aca",
            ServiceType::Redis => "@redis",
            ServiceType::Messaging => "@sb",
            ServiceType::Governance => "@gov",
            ServiceType::Defender => "@defender",
            ServiceType::Advisor => "@advisor",
            ServiceType::Changes => "@changes",
            ServiceType::Audit => "@audit",
        }
    }

    /// The routing prefixes, in service order, for `@` completion: each
    /// selects a service *and* a sub-tab.
    pub const ROUTING_PREFIXES: &'static [&'static str] =
        &["@search", "@sqlmi", "@sqlpool", "@malert", "@logalert", "@activityalert", "@ag", "@apr", "@alert", "@rg", "@all", "@disk", "@nic", "@bvault", "@vmss", "@asg", "@gallery", "@arck8s", "@arcpls", "@avdag", "@avdws", "@avdsp", "@subnet", "@nsg", "@pip", "@lb", "@rt", "@nat", "@pe", "@bastion", "@ddos", "@pdns", "@dnsz", "@dnsr", "@dnsfr", "@dnsp", "@tm", "@afd", "@waf", "@pls", "@vgw", "@cn", "@lgw", "@hub", "@hubvpn", "@huber", "@p2s", "@vpnsite", "@fwp", "@ipg", "@ngfw", "@rulestack", "@sp", "@appreg", "@pool", "@func", "@plan", "@swa", "@mysql", "@law", "@appi", "@acaenv", "@acajob", "@aci", "@amr", "@eh", "@exempt", "@pdef", "@lock", "@mg", "@budget", "@secalert", "@score", "@pricing", "@advscore", "@snooze", "@activity", "@deploys", "@health"];

    /// Every completable prefix: the canonical ones, then the routing
    /// prefixes.
    pub fn completion_prefixes() -> Vec<&'static str> {
        let mut all: Vec<&'static str> = vec!["@sub", "@vm", "@storage", "@backup", "@vnet", "@dns", "@agw", "@er", "@vwan", "@fw", "@kv", "@id", "@aks", "@acr", "@app", "@sql", "@cosmos", "@pg", "@foundry", "@monitor", "@pp", "@automation", "@arc", "@avd", "@aca", "@redis", "@sb", "@gov", "@defender", "@advisor", "@changes", "@audit"];
        all.extend_from_slice(Self::ROUTING_PREFIXES);
        all
    }
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// One provider per `ServiceType`. Identical to neboto's `AwsService`
/// minus `execute_action` (a write hook that a read-only app never
/// implemented — dropped rather than ported). Every list method takes the
/// sub-tab it is listing; a provider holds the ARM client and the
/// subscription it was built for (`AzureClients::service`).
#[async_trait]
pub trait AzureService: Send + Sync {
    /// Service identifier
    #[allow(dead_code)]
    fn service_type(&self) -> ServiceType;

    /// Human-readable name
    #[allow(dead_code)]
    fn name(&self) -> &str;

    /// List every row of one sub-tab.
    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>>;

    /// List resources with incremental updates via events. Default
    /// implementation falls back to `list_resources()`; real providers
    /// override it to stream one ARM page (`nextLink`) per batch.
    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        match self.list_resources(view).await {
            Ok(resources) => {
                let _ = event_tx.send(Event::ResourcesLoaded {
                    service: service_type,
                    resources,
                });
                Ok(())
            }
            Err(e) => {
                let _ = event_tx.send(Event::ResourceLoadError {
                    service: service_type,
                    auth: e.auth_error(),
                    error: e.to_string(),
                });
                Err(e)
            }
        }
    }

    /// Get detailed info for a specific resource (detail-pane `r`).
    #[allow(dead_code)]
    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_prefix_round_trips_to_the_first_sub_tab() {
        for s in ServiceType::all() {
            assert_eq!(ServiceType::from_prefix(s.prefix()), Some((s, None)), "{:?}", s);
        }
    }

    #[test]
    fn routing_prefixes_select_a_sub_tab_of_the_right_service() {
        for p in ServiceType::ROUTING_PREFIXES {
            let (service, view) = ServiceType::from_prefix(p).unwrap_or_else(|| panic!("{p}"));
            let view = view.unwrap_or_else(|| panic!("{p} must route to a sub-tab"));
            assert_eq!(view.service(), service, "{p}");
            assert!(service.views().contains(&view), "{p}");
        }
        assert_eq!(
            ServiceType::from_prefix("@rg"),
            Some((ServiceType::Subscriptions, Some(JumpView::ResourceGroups)))
        );
        assert_eq!(
            ServiceType::from_prefix("DISK"),
            Some((ServiceType::VirtualMachines, Some(JumpView::Disks)))
        );
    }

    #[test]
    fn aliases_resolve_and_junk_does_not() {
        assert_eq!(ServiceType::from_prefix_service("@K8S"), Some(ServiceType::Aks));
        assert_eq!(ServiceType::from_prefix_service("ec2"), None);
        assert_eq!(ServiceType::from_prefix("ec2"), None);
    }

    #[test]
    fn every_view_belongs_to_exactly_one_service_and_has_a_unique_variant() {
        let mut seen = std::collections::HashSet::new();
        for service in ServiceType::all() {
            assert!(!service.views().is_empty());
            for view in service.views() {
                assert_eq!(view.service(), service, "{:?}", view);
                assert!(seen.insert(view.as_str()), "duplicate variant {:?}", view);
            }
        }
    }

    #[test]
    fn only_the_subscription_list_is_tenant_scoped() {
        assert!(ServiceType::Subscriptions.is_tenant_scoped(None));
        assert!(ServiceType::Subscriptions.is_tenant_scoped(Some("subscriptions")));
        assert!(!ServiceType::Subscriptions.is_tenant_scoped(Some("resource-groups")));
        assert!(!ServiceType::VirtualMachines.is_tenant_scoped(None));
    }

    #[test]
    fn audit_never_fans_out_across_subscriptions() {
        assert!(!JumpView::Audit.fans_out(), "@audit is computed, never listed per subscription");
        assert!(JumpView::VirtualMachines.fans_out());
    }

    #[test]
    fn governance_ids_route_wherever_they_were_made() {
        let rg = "/subscriptions/0/resourceGroups/rg";
        let mg = "/providers/Microsoft.Management/managementGroups/corp";
        let auth = |scope: &str, t: &str| format!("{}/providers/Microsoft.Authorization/{}", scope, t);
        assert_eq!(JumpView::for_arm_id(&auth(mg, "policyAssignments/a")), Some(JumpView::PolicyAssignments));
        assert_eq!(JumpView::for_arm_id(&auth(rg, "policyExemptions/e")), Some(JumpView::PolicyExemptions));
        assert_eq!(JumpView::for_arm_id(&auth(mg, "policySetDefinitions/d")), Some(JumpView::PolicyDefinitions));
        assert_eq!(JumpView::for_arm_id(&auth("/subscriptions/0", "policyDefinitions/d")), Some(JumpView::PolicyDefinitions));
        // A built-in is in no list: copied, not jumped to.
        assert_eq!(JumpView::landing_for_arm_id(&auth("", "policyDefinitions/d")), None);
        let vm = format!("{}/providers/Microsoft.Compute/virtualMachines/vm", rg);
        assert_eq!(JumpView::for_arm_id(&auth(&vm, "locks/l")), Some(JumpView::ResourceLocks));
        assert_eq!(JumpView::for_arm_id(&vm), Some(JumpView::VirtualMachines), "one /providers/: unchanged");
        // Other extension resources are in no list, All resources included.
        assert_eq!(JumpView::landing_for_arm_id(&auth(&vm, "roleAssignments/r")), None);
        assert_eq!(JumpView::landing_for_arm_id(&auth(rg, "roleAssignments/r")), None);
        assert_eq!(JumpView::landing_for_arm_id(&format!("{}/providers/Microsoft.Insights/diagnosticSettings/d", vm)), None);
        assert_eq!(ServiceType::from_prefix("@gov"), Some((ServiceType::Governance, None)));
        assert_eq!(ServiceType::from_prefix("@lock"), Some((ServiceType::Governance, Some(JumpView::ResourceLocks))));
        assert_eq!(ServiceType::from_prefix("@mg"), Some((ServiceType::Governance, Some(JumpView::ManagementGroups))));
        assert_eq!(ServiceType::from_prefix("@defender"), Some((ServiceType::Defender, None)));
        assert_eq!(ServiceType::from_prefix("@secalert"), Some((ServiceType::Defender, Some(JumpView::DefenderAlerts))));
        assert_eq!(ServiceType::from_prefix("@score"), Some((ServiceType::Defender, Some(JumpView::SecureScore))));
        assert_eq!(ServiceType::from_prefix("@pricing"), Some((ServiceType::Defender, Some(JumpView::DefenderPlans))));
        assert_eq!(ServiceType::from_prefix("@advisor"), Some((ServiceType::Advisor, None)));
        assert_eq!(ServiceType::from_prefix("@vwan"), Some((ServiceType::VirtualWan, None)));
        assert_eq!(ServiceType::from_prefix("@malert"), Some((ServiceType::Monitor, Some(JumpView::MetricAlerts))));
        assert_eq!(ServiceType::from_prefix("@ag"), Some((ServiceType::Monitor, Some(JumpView::ActionGroups))));
        assert_eq!(ServiceType::from_prefix("@alert"), Some((ServiceType::Monitor, Some(JumpView::FiredAlerts))));
        // Defender's alerts keep their own prefix.
        assert_eq!(ServiceType::from_prefix("@secalert"), Some((ServiceType::Defender, Some(JumpView::DefenderAlerts))));
        assert_eq!(ServiceType::from_prefix("@hub"), Some((ServiceType::VirtualWan, Some(JumpView::VirtualHubs))));
        assert_eq!(ServiceType::from_prefix("@p2s"), Some((ServiceType::VirtualWan, Some(JumpView::P2sGateways))));
        assert_eq!(ServiceType::from_prefix("@vpnsite"), Some((ServiceType::VirtualWan, Some(JumpView::VpnSites))));
        // Hybrid keeps `vpngateway`: the VNet gateway is the older word.
        assert_eq!(ServiceType::from_prefix("@vpngateway"), Some((ServiceType::Hybrid, Some(JumpView::VnetGateways))));
        assert_eq!(ServiceType::from_prefix("@advscore"), Some((ServiceType::Advisor, Some(JumpView::AdvisorScore))));
        assert_eq!(ServiceType::from_prefix("@snooze"), Some((ServiceType::Advisor, Some(JumpView::AdvisorSuppressions))));
        let corp = "/providers/Microsoft.Management/managementGroups/corp";
        assert_eq!(JumpView::landing_for_arm_id(corp), Some(JumpView::ManagementGroups));
        assert_eq!(JumpView::for_arm_id(&format!("{corp}/subscriptions/s")), None, "a membership, not a group");
        assert!(!JumpView::ManagementGroups.fans_out(), "the tenant's groups: the same rows from every subscription");
        assert_eq!(ServiceType::from_prefix("@exempt"), Some((ServiceType::Governance, Some(JumpView::PolicyExemptions))));
        assert_eq!(ServiceType::from_prefix("@pdef"), Some((ServiceType::Governance, Some(JumpView::PolicyDefinitions))));
    }

    #[test]
    fn for_arm_id_routes_on_namespace_and_type_chain() {
        let rg = "/subscriptions/0/resourceGroups/rg";
        assert_eq!(JumpView::for_arm_id("/subscriptions/0"), Some(JumpView::Subscriptions));
        assert_eq!(JumpView::for_arm_id(rg), Some(JumpView::ResourceGroups));
        let p = |t: &str| format!("{}/providers/{}", rg, t);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Compute/virtualMachines/vm")), Some(JumpView::VirtualMachines));
        assert_eq!(JumpView::for_arm_id(&p("microsoft.compute/DISKS/d")), Some(JumpView::Disks));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/networkInterfaces/n")), Some(JumpView::Nics));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Compute/virtualMachineScaleSets/ss")), Some(JumpView::ScaleSets));
        // A Uniform instance is in no list: its id is copied, not jumped to.
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Compute/virtualMachineScaleSets/ss/virtualMachines/0")), None);
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Compute/virtualMachineScaleSets/ss/virtualMachines/0")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Storage/storageAccounts/a")), Some(JumpView::StorageAccounts));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/virtualNetworks/v")), Some(JumpView::VirtualNetworks));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/virtualNetworks/v/subnets/s")), Some(JumpView::Subnets));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/networkSecurityGroups/g")), Some(JumpView::NetworkSecurityGroups));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.KeyVault/vaults/k")), Some(JumpView::KeyVaults));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.ContainerService/managedClusters/c")), Some(JumpView::Clusters));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.ContainerService/managedClusters/c/agentPools/np")), Some(JumpView::NodePools));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.CognitiveServices/accounts/ai")), Some(JumpView::AiAccounts));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Web/sites/shop")), Some(JumpView::WebApps));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Web/serverfarms/plan")), Some(JumpView::AppServicePlans));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Web/sites/shop/slots/staging")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Sql/servers/sql-prod")), Some(JumpView::SqlServers));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Sql/managedInstances/sqlmi-prod")), Some(JumpView::ManagedInstances));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Sql/instancePools/pool-1")), Some(JumpView::InstancePools));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Search/searchServices/srch")), Some(JumpView::SearchServices));
        assert_eq!(ServiceType::from_prefix("@search"), Some((ServiceType::Foundry, Some(JumpView::SearchServices))));
        // An instance database is a child: in no list of its own.
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Sql/managedInstances/sqlmi-prod/databases/orders")), None);
        assert_eq!(ServiceType::from_prefix("@sqlmi"), Some((ServiceType::Sql, Some(JumpView::ManagedInstances))));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Web/staticSites/docs")), Some(JumpView::StaticSites));
        assert_eq!(ServiceType::from_prefix("@swa"), Some((ServiceType::AppService, Some(JumpView::StaticSites))));
        // An environment is a child: in no list of its own.
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Web/staticSites/docs/builds/12")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Automation/automationAccounts/aa")), Some(JumpView::AutomationAccounts));
        assert_eq!(ServiceType::from_prefix("@automation"), Some((ServiceType::Automation, None)));
        assert_eq!(ServiceType::from_prefix("@aa"), Some((ServiceType::Automation, None)));
        // A runbook is a child: in no list of its own.
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Automation/automationAccounts/aa/runbooks/r")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.HybridCompute/machines/srv")), Some(JumpView::ArcMachines));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Kubernetes/connectedClusters/k")), Some(JumpView::ArcClusters));
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.HybridCompute/privateLinkScopes/pls")),
            Some(JumpView::ArcPrivateLinkScopes)
        );
        assert_eq!(ServiceType::from_prefix("@arc"), Some((ServiceType::Arc, None)));
        assert_eq!(ServiceType::from_prefix("@arck8s"), Some((ServiceType::Arc, Some(JumpView::ArcClusters))));
        assert_eq!(ServiceType::from_prefix("@arcpls"), Some((ServiceType::Arc, Some(JumpView::ArcPrivateLinkScopes))));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.DesktopVirtualization/hostPools/hp")), Some(JumpView::HostPools));
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.DesktopVirtualization/applicationGroups/dag")),
            Some(JumpView::AvdApplicationGroups)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.DesktopVirtualization/workspaces/ws")), Some(JumpView::AvdWorkspaces));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.DesktopVirtualization/scalingPlans/sp")), Some(JumpView::ScalingPlans));
        assert_eq!(ServiceType::from_prefix("@avd"), Some((ServiceType::VirtualDesktop, None)));
        assert_eq!(
            ServiceType::from_prefix("@avdag"),
            Some((ServiceType::VirtualDesktop, Some(JumpView::AvdApplicationGroups)))
        );
        assert_eq!(ServiceType::from_prefix("@avdsp"), Some((ServiceType::VirtualDesktop, Some(JumpView::ScalingPlans))));
        // A session host is a child: in no list of its own.
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.DesktopVirtualization/hostPools/hp/sessionHosts/h")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Logic/workflows/la")), None);
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Logic/workflows/la")), Some(JumpView::AllResources));
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Sql/servers/sql-prod")), Some(JumpView::SqlServers));
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.KeyVault/vaults/kv/secrets/db")), None);
        assert_eq!(
            JumpView::for_arm_id(&p("microsoft.operationalinsights/workspaces/law-prod")),
            Some(JumpView::LogWorkspaces)
        );
        assert_eq!(JumpView::for_arm_id(&p("microsoft.insights/components/appi-shop")), Some(JumpView::AppInsights));
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.PowerPlatform/enterprisePolicies/ep-vnet")),
            Some(JumpView::EnterprisePolicies)
        );
        assert_eq!(ServiceType::from_prefix("@ai"), None, "@ai is ambiguous (Foundry or App Insights)");
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.DocumentDB/databaseAccounts/cosmos-prod")),
            Some(JumpView::CosmosAccounts)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.DocumentDB/databaseAccounts/cosmos-prod/sqlDatabases/orders")), None);
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.ContainerRegistry/registries/acrprod")),
            Some(JumpView::Registries)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.ContainerRegistry/registries/acrprod/webhooks/deploy")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Sql/servers/sql-prod/databases/orders")), None);
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.DBforPostgreSQL/flexibleServers/pg-prod")),
            Some(JumpView::PostgresServers)
        );
        assert_eq!(JumpView::for_arm_id(&p("microsoft.dbformysql/FLEXIBLESERVERS/my-shop")), Some(JumpView::MysqlServers));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.DBforPostgreSQL/flexibleServers/pg-prod/databases/orders")), None);
        assert_eq!(
            JumpView::landing_for_arm_id(&p("Microsoft.DBforPostgreSQL/servers/single")),
            Some(JumpView::AllResources),
            "Single Server is retired and not browsed"
        );
        assert_eq!(ServiceType::from_prefix("@pg"), Some((ServiceType::PostgresMysql, None)));
        assert_eq!(ServiceType::from_prefix("@mysql"), Some((ServiceType::PostgresMysql, Some(JumpView::MysqlServers))));
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.ManagedIdentity/userAssignedIdentities/id-app")),
            Some(JumpView::Identities)
        );
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.ManagedIdentity/userAssignedIdentities/id/federatedIdentityCredentials/f")),
            None
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.CognitiveServices/accounts/ai/deployments/d")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/publicIPAddresses/ip")), Some(JumpView::PublicIps));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/loadBalancers/lb")), Some(JumpView::LoadBalancers));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/routeTables/rt")), Some(JumpView::RouteTables));
        assert_eq!(JumpView::for_arm_id(&p("microsoft.network/NATGATEWAYS/n")), Some(JumpView::NatGateways));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/loadBalancers/lb/frontendIPConfigurations/fe")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/publicIPPrefixes/px")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/privateEndpoints/pe")), Some(JumpView::PrivateEndpoints));
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net")),
            Some(JumpView::PrivateDnsZones)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/privateDnsZones/z/A/www")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/dnszones/example.com")), Some(JumpView::DnsZones));
        assert_eq!(JumpView::DnsZones.service(), ServiceType::Dns);
        assert_eq!(JumpView::PrivateDnsZones.service(), ServiceType::Dns, "Private DNS moved to the DNS tab");
        assert_eq!(
            JumpView::landing_for_arm_id(&p("Microsoft.Network/dnsForwardingRulesets/rs")),
            Some(JumpView::DnsForwardingRulesets)
        );
        assert_eq!(ServiceType::from_prefix("@dns"), Some((ServiceType::Dns, None)));
        assert_eq!(ServiceType::Dns.default_view(), JumpView::PrivateDnsZones);
        assert_eq!(ServiceType::from_prefix("@pdns"), Some((ServiceType::Dns, Some(JumpView::PrivateDnsZones))));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/dnsZones/example.com/A/www")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/dnsResolvers/r")), Some(JumpView::DnsResolvers));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/dnsResolvers/r/inboundEndpoints/in")), None);
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/dnsForwardingRulesets/rs")),
            Some(JumpView::DnsForwardingRulesets)
        );
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/dnsResolverPolicies/pol")),
            Some(JumpView::DnsResolverPolicies)
        );
        assert_eq!(
            JumpView::landing_for_arm_id(&p("Microsoft.Network/dnsResolverDomainLists/blocked")),
            Some(JumpView::AllResources)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/virtualNetworks/v/subnets/s/x/y")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.App/containerApps/api")), Some(JumpView::ContainerApps));
        assert_eq!(
            JumpView::for_arm_id(&p("microsoft.app/MANAGEDENVIRONMENTS/cae")),
            Some(JumpView::ContainerAppEnvironments)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.App/jobs/nightly")), Some(JumpView::ContainerAppJobs));
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/applicationSecurityGroups/asg-web")),
            Some(JumpView::ApplicationSecurityGroups)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Compute/galleries/gal_prod")), Some(JumpView::Galleries));
        assert_eq!(ServiceType::from_prefix("@gallery"), Some((ServiceType::VirtualMachines, Some(JumpView::Galleries))));
        // An image definition is a child: in no list of its own.
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Compute/galleries/gal_prod/images/ubuntu")), None);
        assert_eq!(JumpView::for_arm_id("/subscriptions/0000/providers/Microsoft.Consumption/budgets/monthly"), Some(JumpView::Budgets));
        assert_eq!(ServiceType::from_prefix("@budget"), Some((ServiceType::Governance, Some(JumpView::Budgets))));
        assert_eq!(ServiceType::from_prefix("@asg"), Some((ServiceType::VirtualMachines, Some(JumpView::ApplicationSecurityGroups))));
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.ContainerInstance/containerGroups/cg-agents")),
            Some(JumpView::ContainerGroups)
        );
        assert_eq!(ServiceType::from_prefix("@aci"), Some((ServiceType::ContainerApps, Some(JumpView::ContainerGroups))));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Cache/Redis/redis-prod")), Some(JumpView::RedisCaches));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Cache/redisEnterprise/amr-prod")), Some(JumpView::ManagedRedis));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Cache/redisEnterprise/amr-prod/databases/default")), None);
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.ServiceBus/namespaces/sb")),
            Some(JumpView::ServiceBusNamespaces)
        );
        assert_eq!(JumpView::for_arm_id(&p("microsoft.eventhub/NAMESPACES/eh")), Some(JumpView::EventHubNamespaces));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.ServiceBus/namespaces/sb/queues/orders")), None);
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.EventHub/namespaces/eh/eventhubs/telemetry")), None);
        // A dedicated Event Hubs cluster is not browsed: All resources.
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.EventHub/clusters/c")), Some(JumpView::AllResources));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.App/containerApps/api/revisions/api--v1")), None);
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.App/managedEnvironments/cae/certificates/c")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/applicationGateways/agw")), Some(JumpView::AppGateways));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/applicationGateways/agw/httpListeners/l")), None);
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf")),
            Some(JumpView::WafPolicies)
        );
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/frontdoorWebApplicationFirewallPolicies/waf")),
            Some(JumpView::WafPolicies)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Cdn/profiles/afd")), Some(JumpView::FrontDoorProfiles));
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Cdn/profiles/afd/originGroups/og")), None);
        // Classic Front Door is not browsed: All resources.
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Network/frontDoors/fd")), Some(JumpView::AllResources));
        assert_eq!(ServiceType::from_prefix("@agw"), Some((ServiceType::Edge, None)));
        assert_eq!(ServiceType::from_prefix("@afd"), Some((ServiceType::Edge, Some(JumpView::FrontDoorProfiles))));
        assert_eq!(ServiceType::from_prefix("@waf"), Some((ServiceType::Edge, Some(JumpView::WafPolicies))));
        assert_eq!(ServiceType::from_prefix("@pls"), Some((ServiceType::Edge, Some(JumpView::PrivateLinkServices))));
        assert_eq!(ServiceType::from_prefix("@tm"), Some((ServiceType::Dns, Some(JumpView::TrafficManagerProfiles))));
        // A Front Door origin's or a private endpoint's Private Link target.
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/privateLinkServices/pls")),
            Some(JumpView::PrivateLinkServices)
        );
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/trafficManagerProfiles/tm")),
            Some(JumpView::TrafficManagerProfiles)
        );
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Network/privateLinkServices/pls/privateEndpointConnections/c")), None);
        assert_eq!(
            JumpView::for_arm_id(&p("Microsoft.Network/expressRouteCircuits/erc")),
            Some(JumpView::ExpressRouteCircuits)
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/expressRouteCircuits/erc/peerings/AzurePrivatePeering")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/virtualNetworkGateways/vgw")), Some(JumpView::VnetGateways));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/connections/cn")), Some(JumpView::GatewayConnections));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/localNetworkGateways/lgw")), Some(JumpView::LocalGateways));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/virtualWans/vwan")), Some(JumpView::VirtualWans));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/virtualHubs/hub")), Some(JumpView::VirtualHubs));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/vpnGateways/vpngw")), Some(JumpView::VwanVpnGateways));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/expressRouteGateways/ergw")), Some(JumpView::VwanErGateways));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/p2sVpnGateways/p2s")), Some(JumpView::P2sGateways));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/vpnSites/branch")), Some(JumpView::VpnSites));
        // A hub's connection is a child: no list of its own, so no landing.
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Network/virtualHubs/hub/hubVirtualNetworkConnections/c")), None);
        assert_eq!(ServiceType::from_prefix("@er"), Some((ServiceType::Hybrid, None)));
        assert_eq!(ServiceType::from_prefix("@cn"), Some((ServiceType::Hybrid, Some(JumpView::GatewayConnections))));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/azureFirewalls/afw")), Some(JumpView::AzureFirewalls));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/firewallPolicies/fwp")), Some(JumpView::FirewallPolicies));
        assert_eq!(
            JumpView::landing_for_arm_id(&p("Microsoft.Network/firewallPolicies/fwp/ruleCollectionGroups/g")),
            None
        );
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/ipGroups/ipg")), Some(JumpView::IpGroups));
        assert_eq!(JumpView::for_arm_id(&p("PaloAltoNetworks.Cloudngfw/firewalls/ngfw")), Some(JumpView::CloudNgfws));
        assert_eq!(JumpView::for_arm_id(&p("PaloAltoNetworks.Cloudngfw/localRulestacks/lrs")), Some(JumpView::NgfwRulestacks));
        assert_eq!(ServiceType::from_prefix("@fw"), Some((ServiceType::Firewall, None)));
        assert_eq!(ServiceType::from_prefix("@fwp"), Some((ServiceType::Firewall, Some(JumpView::FirewallPolicies))));
        assert_eq!(ServiceType::from_prefix("@ipg"), Some((ServiceType::Firewall, Some(JumpView::IpGroups))));
        assert_eq!(ServiceType::from_prefix("@ngfw"), Some((ServiceType::Firewall, Some(JumpView::CloudNgfws))));
        assert_eq!(ServiceType::from_prefix("@rulestack"), Some((ServiceType::Firewall, Some(JumpView::NgfwRulestacks))));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.RecoveryServices/vaults/rsv")), Some(JumpView::RecoveryVaults));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.DataProtection/backupVaults/bv")), Some(JumpView::BackupVaults));
        assert_eq!(
            JumpView::landing_for_arm_id(&p("Microsoft.RecoveryServices/vaults/rsv/backupPolicies/DefaultPolicy")),
            None
        );
        assert_eq!(ServiceType::from_prefix("@backup"), Some((ServiceType::Backup, None)));
        assert_eq!(ServiceType::from_prefix("@rsv"), Some((ServiceType::Backup, None)));
        assert_eq!(ServiceType::from_prefix("@bvault"), Some((ServiceType::Backup, Some(JumpView::BackupVaults))));
        assert_eq!(JumpView::for_arm_id("garbage"), None);
    }

    #[test]
    fn directory_ids_land_on_their_graph_sub_tabs() {
        let sp = "graph:/servicePrincipals/00af5dfb-85da-4b41-a677-0c6b86dd34f8";
        assert_eq!(JumpView::for_arm_id(sp), None, "not an ARM id");
        assert_eq!(JumpView::landing_for_arm_id(sp), Some(JumpView::ServicePrincipals));
        assert_eq!(
            JumpView::landing_for_arm_id("graph:/applications(appId='11111111-2222-3333-4444-555555555555')"),
            Some(JumpView::AppRegistrations)
        );
        assert_eq!(JumpView::landing_for_arm_id("graph:/users/x"), None);
        assert_eq!(ServiceType::from_prefix("@sp"), Some((ServiceType::Identity, Some(JumpView::ServicePrincipals))));
        assert_eq!(ServiceType::from_prefix("@appreg"), Some((ServiceType::Identity, Some(JumpView::AppRegistrations))));
        assert_eq!(ServiceType::from_prefix("@app"), Some((ServiceType::AppService, None)), "@app stays App Service");
        assert!(!JumpView::ServicePrincipals.is_tenant_scoped(), "cached per subscription: the tenant pseudo-key is not per tenant");
    }
}
