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
    /// Virtual networks, subnets, network security groups.
    Network,
    /// Key vaults — metadata and secret/key *names* only, never values.
    KeyVault,
    /// AKS managed clusters + node pools.
    Aks,
    /// Foundry / AI Services / Azure OpenAI accounts; deployments and
    /// projects as lazy sections. Metadata only, never keys.
    Foundry,
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
    // Key Vault
    KeyVaults,
    // AKS
    Clusters,
    /// Embedded in the cluster list (the API says agent pool).
    NodePools,
    // Foundry
    /// Every `Microsoft.CognitiveServices` account, `kind` on the row.
    AiAccounts,
}

impl JumpView {
    /// The service this sub-tab belongs to.
    pub fn service(&self) -> ServiceType {
        use JumpView::*;
        match self {
            Subscriptions | ResourceGroups => ServiceType::Subscriptions,
            VirtualMachines | Disks | Nics => ServiceType::VirtualMachines,
            StorageAccounts => ServiceType::Storage,
            VirtualNetworks | Subnets | NetworkSecurityGroups => ServiceType::Network,
            KeyVaults => ServiceType::KeyVault,
            Clusters | NodePools => ServiceType::Aks,
            AiAccounts => ServiceType::Foundry,
        }
    }

    /// The list-cache variant: stable, never shown to the user.
    pub fn as_str(&self) -> &'static str {
        use JumpView::*;
        match self {
            Subscriptions => "subscriptions",
            ResourceGroups => "resource-groups",
            VirtualMachines => "vms",
            Disks => "disks",
            Nics => "nics",
            StorageAccounts => "accounts",
            VirtualNetworks => "vnets",
            Subnets => "subnets",
            NetworkSecurityGroups => "nsgs",
            KeyVaults => "vaults",
            Clusters => "clusters",
            NodePools => "node-pools",
            AiAccounts => "ai-accounts",
        }
    }

    /// Sub-tab chip label.
    pub fn label(&self) -> &'static str {
        use JumpView::*;
        match self {
            Subscriptions => "Subscriptions",
            ResourceGroups => "Resource Groups",
            VirtualMachines => "VMs",
            Disks => "Disks",
            Nics => "NICs",
            StorageAccounts => "Accounts",
            VirtualNetworks => "VNets",
            Subnets => "Subnets",
            NetworkSecurityGroups => "NSGs",
            KeyVaults => "Vaults",
            Clusters => "Clusters",
            NodePools => "Node pools",
            AiAccounts => "Resources",
        }
    }

    /// The sub-tab that lists an ARM id's type, from its resource-provider
    /// namespace and type chain — the jump router (ticket 06). `None` for
    /// a type nebaz does not browse (a public IP, a route table).
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
            ("microsoft.keyvault", ["vaults"]) => JumpView::KeyVaults,
            ("microsoft.containerservice", ["managedclusters"]) => JumpView::Clusters,
            ("microsoft.containerservice", ["managedclusters", "agentpools"]) => JumpView::NodePools,
            ("microsoft.cognitiveservices", ["accounts"]) => JumpView::AiAccounts,
            _ => return None,
        })
    }

    /// Whether this sub-tab's list has no subscription in its path. Only
    /// the subscription list itself: its rows belong to the tenant, so a
    /// subscription switch never invalidates them.
    pub fn is_tenant_scoped(&self) -> bool {
        matches!(self, JumpView::Subscriptions)
    }
}

impl ServiceType {
    pub fn all() -> Vec<ServiceType> {
        vec![
            ServiceType::Subscriptions,
            ServiceType::VirtualMachines,
            ServiceType::Storage,
            ServiceType::Network,
            ServiceType::KeyVault,
            ServiceType::Aks,
            ServiceType::Foundry,
        ]
    }

    /// Ordered picker categories. Every `category()` value must appear here.
    pub const CATEGORIES: &'static [&'static str] =
        &["Management", "Compute", "Storage", "Networking", "Security", "Containers", "AI"];

    pub fn category(&self) -> &'static str {
        match self {
            ServiceType::Subscriptions => "Management",
            ServiceType::VirtualMachines => "Compute",
            ServiceType::Storage => "Storage",
            ServiceType::Network => "Networking",
            ServiceType::KeyVault => "Security",
            ServiceType::Aks => "Containers",
            ServiceType::Foundry => "AI",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "Subscriptions",
            ServiceType::VirtualMachines => "Virtual Machines",
            ServiceType::Storage => "Storage",
            ServiceType::Network => "Virtual Network",
            ServiceType::KeyVault => "Key Vault",
            ServiceType::Aks => "AKS",
            ServiceType::Foundry => "Foundry",
        }
    }

    /// Tab-strip / picker label (≤ 10 chars).
    pub fn short_name(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "Subs",
            ServiceType::VirtualMachines => "VMs",
            ServiceType::Storage => "Storage",
            ServiceType::Network => "VNet",
            ServiceType::KeyVault => "Key Vault",
            ServiceType::Aks => "AKS",
            ServiceType::Foundry => "Foundry",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            ServiceType::Subscriptions => "Subscriptions & Resource Groups",
            ServiceType::VirtualMachines => "Virtual Machines, Disks & NICs",
            ServiceType::Storage => "Storage Accounts & Containers",
            ServiceType::Network => "Virtual Networks, Subnets & NSGs",
            ServiceType::KeyVault => "Key Vaults (metadata only)",
            ServiceType::Aks => "Kubernetes Clusters & Node Pools",
            ServiceType::Foundry => "Foundry, AI Services & OpenAI (metadata only)",
        }
    }

    /// The service's sub-tabs in display order (ticket 04's table). A
    /// single-entry service hides the sub-tab bar.
    pub fn views(&self) -> &'static [JumpView] {
        use JumpView::*;
        match self {
            ServiceType::Subscriptions => &[Subscriptions, ResourceGroups],
            ServiceType::VirtualMachines => &[VirtualMachines, Disks, Nics],
            ServiceType::Storage => &[StorageAccounts],
            ServiceType::Network => &[VirtualNetworks, Subnets, NetworkSecurityGroups],
            ServiceType::KeyVault => &[KeyVaults],
            ServiceType::Aks => &[Clusters, NodePools],
            ServiceType::Foundry => &[AiAccounts],
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
            "vm" | "vms" | "compute" | "virtualmachines" => (ServiceType::VirtualMachines, None),
            "disk" | "disks" => (ServiceType::VirtualMachines, Some(JumpView::Disks)),
            "nic" | "nics" => (ServiceType::VirtualMachines, Some(JumpView::Nics)),
            "st" | "storage" | "blob" | "blobs" | "storageaccounts" => (ServiceType::Storage, None),
            "vnet" | "vnets" | "net" | "network" => (ServiceType::Network, None),
            "subnet" | "subnets" => (ServiceType::Network, Some(JumpView::Subnets)),
            "nsg" | "nsgs" => (ServiceType::Network, Some(JumpView::NetworkSecurityGroups)),
            "kv" | "keyvault" | "keyvaults" | "vault" | "vaults" => (ServiceType::KeyVault, None),
            "aks" | "k8s" | "kubernetes" | "cluster" | "clusters" => (ServiceType::Aks, None),
            "pool" | "pools" | "nodepool" | "nodepools" => (ServiceType::Aks, Some(JumpView::NodePools)),
            "foundry" | "aifoundry" | "aiservices" | "openai" | "aoai" | "cognitive" | "cognitiveservices" | "cog" => {
                (ServiceType::Foundry, None)
            }
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
            ServiceType::KeyVault => "@kv",
            ServiceType::Aks => "@aks",
            ServiceType::Foundry => "@foundry",
        }
    }

    /// The routing prefixes, in service order, for `@` completion: each
    /// selects a service *and* a sub-tab.
    pub const ROUTING_PREFIXES: &'static [&'static str] =
        &["@rg", "@disk", "@nic", "@subnet", "@nsg", "@pool"];

    /// Every completable prefix: the canonical ones, then the routing
    /// prefixes.
    pub fn completion_prefixes() -> Vec<&'static str> {
        let mut all: Vec<&'static str> = vec!["@sub", "@vm", "@storage", "@vnet", "@kv", "@aks", "@foundry"];
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
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.CognitiveServices/accounts/ai/deployments/d")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/publicIPAddresses/ip")), None);
        assert_eq!(JumpView::for_arm_id(&p("Microsoft.Network/virtualNetworks/v/subnets/s/x/y")), None);
        assert_eq!(JumpView::for_arm_id("garbage"), None);
    }
}
