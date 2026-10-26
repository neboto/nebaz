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
    /// Virtual machines, managed disks, NICs.
    VirtualMachines,
    /// Storage accounts + blob containers (via ARM).
    Storage,
    /// Virtual networks, subnets, NSGs, public IPs, load balancers, route
    /// tables, NAT gateways, private endpoints.
    Network,
    /// Private and public DNS zones, the DNS Private Resolver, forwarding
    /// rulesets, DNS security policies. Microsoft.Network, but its own tab
    /// (SERVICES.md says why).
    Dns,
    /// The internet-facing entry points: application gateways, Front Door
    /// Standard / Premium profiles and the WAF policies of both. Its own
    /// tab (SERVICES.md rule 26 says why); backend health is never read.
    Edge,
    /// The hub's security layer: Azure Firewalls, firewall policies (rule
    /// collection groups lazy), IP groups, and Palo Alto Networks Cloud
    /// NGFW firewalls and local rulestacks (rules lazy). Its own tab
    /// (SERVICES.md rule 27 says why).
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
/// or are embedded in one; per-parent lists are lazy sections instead.
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
    // DNS
    PrivateDnsZones,
    /// Public DNS zones (`Microsoft.Network/dnszones`).
    DnsZones,
    DnsResolvers,
    DnsForwardingRulesets,
    /// DNS security policies (`dnsResolverPolicies`).
    DnsResolverPolicies,
    // Edge
    /// `Microsoft.Network/applicationGateways`.
    AppGateways,
    /// Front Door Standard / Premium (`Microsoft.Cdn/profiles`, the classic
    /// CDN SKUs filtered out).
    FrontDoorProfiles,
    /// Application Gateway and Front Door WAF policies, one list of both.
    WafPolicies,
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
    // SQL
    SqlServers,
    // Cosmos DB
    CosmosAccounts,
    // PostgreSQL & MySQL
    PostgresServers,
    MysqlServers,
    // Foundry
    /// Every `Microsoft.CognitiveServices` account, `kind` on the row.
    AiAccounts,
    // Monitor
    LogWorkspaces,
    AppInsights,
    // Power Platform
    EnterprisePolicies,
    // Container Apps
    ContainerApps,
    ContainerAppEnvironments,
    ContainerAppJobs,
    // Redis
    /// Azure Cache for Redis (`Microsoft.Cache/redis`).
    RedisCaches,
    /// Azure Managed Redis (`Microsoft.Cache/redisEnterprise`).
    ManagedRedis,
    // Messaging
    ServiceBusNamespaces,
    EventHubNamespaces,
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
            VirtualMachines | Disks | Nics => ServiceType::VirtualMachines,
            StorageAccounts => ServiceType::Storage,
            VirtualNetworks | Subnets | NetworkSecurityGroups | PublicIps | LoadBalancers | RouteTables
            | NatGateways | PrivateEndpoints => ServiceType::Network,
            PrivateDnsZones | DnsZones | DnsResolvers | DnsForwardingRulesets | DnsResolverPolicies => ServiceType::Dns,
            AppGateways | FrontDoorProfiles | WafPolicies => ServiceType::Edge,
            AzureFirewalls | FirewallPolicies | IpGroups | CloudNgfws | NgfwRulestacks => ServiceType::Firewall,
            KeyVaults => ServiceType::KeyVault,
            Identities | ServicePrincipals | AppRegistrations => ServiceType::Identity,
            Clusters | NodePools => ServiceType::Aks,
            Registries => ServiceType::ContainerRegistry,
            WebApps | FunctionApps | AppServicePlans => ServiceType::AppService,
            SqlServers => ServiceType::Sql,
            CosmosAccounts => ServiceType::Cosmos,
            PostgresServers | MysqlServers => ServiceType::PostgresMysql,
            AiAccounts => ServiceType::Foundry,
            LogWorkspaces | AppInsights => ServiceType::Monitor,
            EnterprisePolicies => ServiceType::PowerPlatform,
            ContainerApps | ContainerAppEnvironments | ContainerAppJobs => ServiceType::ContainerApps,
            RedisCaches | ManagedRedis => ServiceType::Redis,
            ServiceBusNamespaces | EventHubNamespaces => ServiceType::Messaging,
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
            StorageAccounts => "accounts",
            VirtualNetworks => "vnets",
            Subnets => "subnets",
            NetworkSecurityGroups => "nsgs",
            PublicIps => "public-ips",
            LoadBalancers => "load-balancers",
            RouteTables => "route-tables",
            NatGateways => "nat-gateways",
            PrivateEndpoints => "private-endpoints",
            PrivateDnsZones => "private-dns-zones",
            DnsZones => "dns-zones",
            DnsResolvers => "dns-resolvers",
            DnsForwardingRulesets => "dns-forwarding-rulesets",
            DnsResolverPolicies => "dns-resolver-policies",
            AppGateways => "app-gateways",
            FrontDoorProfiles => "front-door-profiles",
            WafPolicies => "waf-policies",
            AzureFirewalls => "azure-firewalls",
            FirewallPolicies => "firewall-policies",
            IpGroups => "ip-groups",
            CloudNgfws => "cloud-ngfws",
            NgfwRulestacks => "ngfw-rulestacks",
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
            SqlServers => "sql-servers",
            CosmosAccounts => "cosmos-accounts",
            PostgresServers => "postgres-servers",
            MysqlServers => "mysql-servers",
            AiAccounts => "ai-accounts",
            LogWorkspaces => "log-workspaces",
            AppInsights => "app-insights",
            EnterprisePolicies => "enterprise-policies",
            ContainerApps => "container-apps",
            ContainerAppEnvironments => "container-app-environments",
            ContainerAppJobs => "container-app-jobs",
            RedisCaches => "redis-caches",
            ManagedRedis => "managed-redis",
            ServiceBusNamespaces => "servicebus-namespaces",
            EventHubNamespaces => "eventhub-namespaces",
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
            StorageAccounts => "Accounts",
            VirtualNetworks => "VNets",
            Subnets => "Subnets",
            NetworkSecurityGroups => "NSGs",
            PublicIps => "Public IPs",
            LoadBalancers => "LBs",
            RouteTables => "Routes",
            NatGateways => "NAT",
            PrivateEndpoints => "PEs",
            PrivateDnsZones => "Private DNS",
            DnsZones => "DNS zones",
            DnsResolvers => "Resolvers",
            DnsForwardingRulesets => "Rulesets",
            DnsResolverPolicies => "DNS policies",
            AppGateways => "App gateways",
            FrontDoorProfiles => "Front Door",
            WafPolicies => "WAF policies",
            AzureFirewalls => "Firewalls",
            FirewallPolicies => "Policies",
            IpGroups => "IP groups",
            CloudNgfws => "Cloud NGFW",
            NgfwRulestacks => "Rulestacks",
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
            SqlServers => "Servers",
            CosmosAccounts => "Accounts",
            PostgresServers => "PostgreSQL",
            MysqlServers => "MySQL",
            AiAccounts => "Resources",
            LogWorkspaces => "Workspaces",
            AppInsights => "App Insights",
            EnterprisePolicies => "Enterprise policies",
            ContainerApps => "Apps",
            ContainerAppEnvironments => "Environments",
            ContainerAppJobs => "Jobs",
            RedisCaches => "Caches",
            ManagedRedis => "Managed Redis",
            ServiceBusNamespaces => "Service Bus",
            EventHubNamespaces => "Event Hubs",
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
            ("microsoft.storage", ["storageaccounts"]) => JumpView::StorageAccounts,
            ("microsoft.network", ["virtualnetworks"]) => JumpView::VirtualNetworks,
            ("microsoft.network", ["virtualnetworks", "subnets"]) => JumpView::Subnets,
            ("microsoft.network", ["networksecuritygroups"]) => JumpView::NetworkSecurityGroups,
            ("microsoft.network", ["publicipaddresses"]) => JumpView::PublicIps,
            ("microsoft.network", ["loadbalancers"]) => JumpView::LoadBalancers,
            ("microsoft.network", ["routetables"]) => JumpView::RouteTables,
            ("microsoft.network", ["natgateways"]) => JumpView::NatGateways,
            ("microsoft.network", ["privateendpoints"]) => JumpView::PrivateEndpoints,
            ("microsoft.network", ["privatednszones"]) => JumpView::PrivateDnsZones,
            ("microsoft.network", ["dnszones"]) => JumpView::DnsZones,
            ("microsoft.network", ["dnsresolvers"]) => JumpView::DnsResolvers,
            ("microsoft.network", ["dnsforwardingrulesets"]) => JumpView::DnsForwardingRulesets,
            ("microsoft.network", ["dnsresolverpolicies"]) => JumpView::DnsResolverPolicies,
            ("microsoft.network", ["applicationgateways"]) => JumpView::AppGateways,
            ("microsoft.network", ["applicationgatewaywebapplicationfirewallpolicies"])
            | ("microsoft.network", ["frontdoorwebapplicationfirewallpolicies"]) => JumpView::WafPolicies,
            // Classic CDN profiles share the type; the list keeps Front
            // Door Standard / Premium only, so a classic one is not found.
            ("microsoft.cdn", ["profiles"]) => JumpView::FrontDoorProfiles,
            ("microsoft.network", ["azurefirewalls"]) => JumpView::AzureFirewalls,
            ("microsoft.network", ["firewallpolicies"]) => JumpView::FirewallPolicies,
            ("microsoft.network", ["ipgroups"]) => JumpView::IpGroups,
            ("paloaltonetworks.cloudngfw", ["firewalls"]) => JumpView::CloudNgfws,
            ("paloaltonetworks.cloudngfw", ["localrulestacks"]) => JumpView::NgfwRulestacks,
            ("microsoft.keyvault", ["vaults"]) => JumpView::KeyVaults,
            ("microsoft.managedidentity", ["userassignedidentities"]) => JumpView::Identities,
            ("microsoft.containerservice", ["managedclusters"]) => JumpView::Clusters,
            ("microsoft.containerservice", ["managedclusters", "agentpools"]) => JumpView::NodePools,
            ("microsoft.containerregistry", ["registries"]) => JumpView::Registries,
            // A site's id does not say its kind; Apps lists every site.
            ("microsoft.web", ["sites"]) => JumpView::WebApps,
            ("microsoft.web", ["serverfarms"]) => JumpView::AppServicePlans,
            ("microsoft.sql", ["servers"]) => JumpView::SqlServers,
            ("microsoft.documentdb", ["databaseaccounts"]) => JumpView::CosmosAccounts,
            ("microsoft.dbforpostgresql", ["flexibleservers"]) => JumpView::PostgresServers,
            ("microsoft.dbformysql", ["flexibleservers"]) => JumpView::MysqlServers,
            ("microsoft.cognitiveservices", ["accounts"]) => JumpView::AiAccounts,
            ("microsoft.operationalinsights", ["workspaces"]) => JumpView::LogWorkspaces,
            ("microsoft.insights", ["components"]) => JumpView::AppInsights,
            ("microsoft.powerplatform", ["enterprisepolicies"]) => JumpView::EnterprisePolicies,
            ("microsoft.app", ["containerapps"]) => JumpView::ContainerApps,
            ("microsoft.app", ["managedenvironments"]) => JumpView::ContainerAppEnvironments,
            ("microsoft.app", ["jobs"]) => JumpView::ContainerAppJobs,
            ("microsoft.cache", ["redis"]) => JumpView::RedisCaches,
            ("microsoft.cache", ["redisenterprise"]) => JumpView::ManagedRedis,
            ("microsoft.servicebus", ["namespaces"]) => JumpView::ServiceBusNamespaces,
            ("microsoft.eventhub", ["namespaces"]) => JumpView::EventHubNamespaces,
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
        JumpView::for_arm_id(id).or_else(|| match arm_type_chain(id) {
            Some((_, chain)) if chain.len() == 1 && resource_group_of(id).is_some() => Some(JumpView::AllResources),
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
    /// lists (subscriptions, and the directory's service principals and app
    /// registrations: the same rows from every subscription of a tenant),
    /// nor `@changes` (one list per time window, its sub-tabs filter it,
    /// and each subscription's Activity Log read is the costliest list),
    /// nor a virtual service's (`@audit`: computed, never listed).
    pub fn fans_out(&self) -> bool {
        use JumpView::*;
        !self.is_tenant_scoped()
            && !self.service().is_virtual()
            && !matches!(
                self,
                ServicePrincipals | AppRegistrations | ChangesAll | ChangesActivity | ChangesDeployments | ChangesHealth
            )
    }
}

impl ServiceType {
    pub fn all() -> Vec<ServiceType> {
        vec![
            ServiceType::Subscriptions,
            ServiceType::VirtualMachines,
            ServiceType::Storage,
            ServiceType::Network,
            ServiceType::Dns,
            ServiceType::Edge,
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
            ServiceType::ContainerApps,
            ServiceType::Redis,
            ServiceType::Messaging,
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
            ServiceType::Network => "Networking",
            ServiceType::Dns => "Networking",
            ServiceType::Edge => "Networking",
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
            ServiceType::ContainerApps => "Containers",
            ServiceType::Redis => "Databases",
            ServiceType::Messaging => "Integration",
            ServiceType::Changes => "Monitoring",
            ServiceType::Audit => "Security",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "Subscriptions",
            ServiceType::VirtualMachines => "Virtual Machines",
            ServiceType::Storage => "Storage",
            ServiceType::Network => "Virtual Network",
            ServiceType::Dns => "DNS",
            ServiceType::Edge => "Edge",
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
            ServiceType::ContainerApps => "Container Apps",
            ServiceType::Redis => "Redis",
            ServiceType::Messaging => "Messaging",
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
            ServiceType::Network => "VNet",
            ServiceType::Dns => "DNS",
            ServiceType::Edge => "Edge",
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
            ServiceType::ContainerApps => "ACA",
            ServiceType::Redis => "Redis",
            ServiceType::Messaging => "Messaging",
            ServiceType::Changes => "Changes",
            ServiceType::Audit => "Audit",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "Subscriptions, groups & all resources",
            ServiceType::VirtualMachines => "Virtual Machines, Disks & NICs",
            ServiceType::Storage => "Storage Accounts & Containers",
            ServiceType::Network => "VNets, NSGs, IPs, LBs & NAT",
            ServiceType::Dns => "DNS zones, Private Resolver & rulesets",
            ServiceType::Edge => "App gateways, Front Door & WAF policies",
            ServiceType::Firewall => "Azure Firewall, policies, IP groups & Cloud NGFW",
            ServiceType::KeyVault => "Key Vaults (metadata only)",
            ServiceType::Identity => "Managed identities, service principals & app registrations",
            ServiceType::Aks => "Kubernetes Clusters & Node Pools",
            ServiceType::ContainerRegistry => "Container registries",
            ServiceType::AppService => "Web & function apps, plans",
            ServiceType::Sql => "SQL servers & databases",
            ServiceType::Cosmos => "Cosmos DB accounts",
            ServiceType::PostgresMysql => "PostgreSQL & MySQL flexible servers",
            ServiceType::Foundry => "Foundry, AI Services & OpenAI (metadata only)",
            ServiceType::Monitor => "Log Analytics & App Insights",
            ServiceType::PowerPlatform => "Power Platform enterprise policies",
            ServiceType::ContainerApps => "Container apps, environments & jobs",
            ServiceType::Redis => "Azure Cache for Redis & Managed Redis",
            ServiceType::Messaging => "Service Bus & Event Hubs namespaces",
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
            ServiceType::VirtualMachines => &[VirtualMachines, Disks, Nics],
            ServiceType::Storage => &[StorageAccounts],
            ServiceType::Network => &[
                VirtualNetworks,
                Subnets,
                NetworkSecurityGroups,
                PublicIps,
                LoadBalancers,
                RouteTables,
                NatGateways,
                PrivateEndpoints,
            ],
            ServiceType::Dns => &[PrivateDnsZones, DnsZones, DnsResolvers, DnsForwardingRulesets, DnsResolverPolicies],
            ServiceType::Edge => &[AppGateways, FrontDoorProfiles, WafPolicies],
            ServiceType::Firewall => &[AzureFirewalls, FirewallPolicies, IpGroups, CloudNgfws, NgfwRulestacks],
            ServiceType::KeyVault => &[KeyVaults],
            ServiceType::Identity => &[Identities, ServicePrincipals, AppRegistrations],
            ServiceType::Aks => &[Clusters, NodePools],
            ServiceType::ContainerRegistry => &[Registries],
            ServiceType::AppService => &[WebApps, FunctionApps, AppServicePlans],
            ServiceType::Sql => &[SqlServers],
            ServiceType::Cosmos => &[CosmosAccounts],
            ServiceType::PostgresMysql => &[PostgresServers, MysqlServers],
            ServiceType::Foundry => &[AiAccounts],
            ServiceType::Monitor => &[LogWorkspaces, AppInsights],
            ServiceType::PowerPlatform => &[EnterprisePolicies],
            ServiceType::ContainerApps => &[ContainerApps, ContainerAppEnvironments, ContainerAppJobs],
            ServiceType::Redis => &[RedisCaches, ManagedRedis],
            ServiceType::Messaging => &[ServiceBusNamespaces, EventHubNamespaces],
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
            "st" | "storage" | "blob" | "blobs" | "storageaccounts" => (ServiceType::Storage, None),
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
            "cosmos" | "cosmosdb" | "documentdb" | "docdb" => (ServiceType::Cosmos, None),
            "pg" | "postgres" | "postgresql" | "psql" | "flexibleserver" | "flexibleservers" => {
                (ServiceType::PostgresMysql, None)
            }
            "mysql" | "mysqlserver" | "mysqlservers" => (ServiceType::PostgresMysql, Some(JumpView::MysqlServers)),
            "plan" | "plans" | "asp" | "serverfarm" | "serverfarms" => {
                (ServiceType::AppService, Some(JumpView::AppServicePlans))
            }
            "foundry" | "aifoundry" | "aiservices" | "openai" | "aoai" | "cognitive" | "cognitiveservices" | "cog" => {
                (ServiceType::Foundry, None)
            }
            "monitor" | "monitoring" => (ServiceType::Monitor, None),
            "law" | "laws" | "loganalytics" | "workspace" | "workspaces" => {
                (ServiceType::Monitor, Some(JumpView::LogWorkspaces))
            }
            "appi" | "insights" | "appinsights" | "applicationinsights" | "component" | "components" => {
                (ServiceType::Monitor, Some(JumpView::AppInsights))
            }
            "pp" | "powerplatform" | "enterprisepolicy" | "enterprisepolicies" => {
                (ServiceType::PowerPlatform, None)
            }
            "aca" | "containerapp" | "containerapps" => (ServiceType::ContainerApps, None),
            "acaenv" | "acaenvs" | "cae" | "managedenvironment" | "managedenvironments" => {
                (ServiceType::ContainerApps, Some(JumpView::ContainerAppEnvironments))
            }
            "acajob" | "acajobs" | "containerappjob" | "containerappjobs" => {
                (ServiceType::ContainerApps, Some(JumpView::ContainerAppJobs))
            }
            "redis" | "cache" | "caches" | "rediscache" | "azurecache" => (ServiceType::Redis, None),
            "amr" | "managedredis" | "redisenterprise" => (ServiceType::Redis, Some(JumpView::ManagedRedis)),
            "sb" | "servicebus" | "messaging" | "msg" => (ServiceType::Messaging, None),
            "eh" | "eventhub" | "eventhubs" | "kafka" => (ServiceType::Messaging, Some(JumpView::EventHubNamespaces)),
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
            ServiceType::Network => "@vnet",
            ServiceType::Dns => "@dns",
            ServiceType::Edge => "@agw",
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
            ServiceType::ContainerApps => "@aca",
            ServiceType::Redis => "@redis",
            ServiceType::Messaging => "@sb",
            ServiceType::Changes => "@changes",
            ServiceType::Audit => "@audit",
        }
    }

    /// The routing prefixes, in service order, for `@` completion: each
    /// selects a service *and* a sub-tab.
    pub const ROUTING_PREFIXES: &'static [&'static str] =
        &["@rg", "@all", "@disk", "@nic", "@subnet", "@nsg", "@pip", "@lb", "@rt", "@nat", "@pe", "@pdns", "@dnsz", "@dnsr", "@dnsfr", "@dnsp", "@afd", "@waf", "@fwp", "@ipg", "@ngfw", "@rulestack", "@sp", "@appreg", "@pool", "@func", "@plan", "@mysql", "@law", "@appi", "@acaenv", "@acajob", "@amr", "@eh", "@activity", "@deploys", "@health"];

    /// Every completable prefix: the canonical ones, then the routing
    /// prefixes.
    pub fn completion_prefixes() -> Vec<&'static str> {
        let mut all: Vec<&'static str> = vec!["@sub", "@vm", "@storage", "@vnet", "@dns", "@agw", "@fw", "@kv", "@id", "@aks", "@acr", "@app", "@sql", "@cosmos", "@pg", "@foundry", "@monitor", "@pp", "@aca", "@redis", "@sb", "@changes", "@audit"];
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
    fn for_arm_id_routes_on_namespace_and_type_chain() {
        let rg = "/subscriptions/0/resourceGroups/rg";
        assert_eq!(JumpView::for_arm_id("/subscriptions/0"), Some(JumpView::Subscriptions));
        assert_eq!(JumpView::for_arm_id(rg), Some(JumpView::ResourceGroups));
        let p = |t: &str| format!("{}/providers/{}", rg, t);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Compute/virtualMachines/vm")), Some(JumpView::VirtualMachines));
        assert_eq!(JumpView::for_arm_id(&p("microsoft.compute/DISKS/d")), Some(JumpView::Disks));
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/networkInterfaces/n")), Some(JumpView::Nics));
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
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Web/staticSites/docs")), None);
        assert_eq!(JumpView::landing_for_arm_id(&p("Microsoft.Web/staticSites/docs")), Some(JumpView::AllResources));
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
