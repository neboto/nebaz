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
        ]
    }

    /// Ordered picker categories. Every `category()` value must appear here.
    pub const CATEGORIES: &'static [&'static str] =
        &["Management", "Compute", "Storage", "Networking", "Security", "Containers"];

    pub fn category(&self) -> &'static str {
        match self {
            ServiceType::Subscriptions => "Management",
            ServiceType::VirtualMachines => "Compute",
            ServiceType::Storage => "Storage",
            ServiceType::Network => "Networking",
            ServiceType::KeyVault => "Security",
            ServiceType::Aks => "Containers",
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
        }
    }

    /// Whether the list is tenant-scoped rather than subscription-scoped —
    /// only the subscription list itself. The cache keys such lists under
    /// a fixed pseudo-subscription so a subscription switch doesn't refetch
    /// them (the analog of neboto's `is_global()` → `us-east-1` pinning).
    pub fn is_tenant_scoped(&self) -> bool {
        matches!(self, ServiceType::Subscriptions)
    }

    /// Parse a `@prefix` (with or without the `@`) or any accepted alias.
    pub fn from_prefix(s: &str) -> Option<ServiceType> {
        let s = s.trim().trim_start_matches('@').to_lowercase();
        match s.as_str() {
            "sub" | "subs" | "subscription" | "subscriptions" | "rg" | "rgs"
            | "resourcegroup" | "resourcegroups" => Some(ServiceType::Subscriptions),
            "vm" | "vms" | "compute" | "virtualmachines" | "disk" | "disks" | "nic"
            | "nics" => Some(ServiceType::VirtualMachines),
            "st" | "storage" | "blob" | "blobs" | "storageaccounts" => {
                Some(ServiceType::Storage)
            }
            "vnet" | "vnets" | "net" | "network" | "subnet" | "subnets" | "nsg" | "nsgs" => {
                Some(ServiceType::Network)
            }
            "kv" | "keyvault" | "keyvaults" | "vault" | "vaults" => Some(ServiceType::KeyVault),
            "aks" | "k8s" | "kubernetes" | "cluster" | "clusters" => Some(ServiceType::Aks),
            _ => None,
        }
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
        }
    }
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// One provider per `ServiceType`. Identical to neboto's `AwsService`
/// minus `execute_action` (a write hook that a read-only app never
/// implemented — dropped rather than ported).
#[async_trait]
pub trait AzureService: Send + Sync {
    /// Service identifier
    #[allow(dead_code)]
    fn service_type(&self) -> ServiceType;

    /// Human-readable name
    #[allow(dead_code)]
    fn name(&self) -> &str;

    /// List all resources for this service
    async fn list_resources(&self) -> Result<Vec<Box<dyn Resource>>>;

    /// List resources with incremental updates via events. Default
    /// implementation falls back to `list_resources()`; real providers
    /// override it to stream one ARM page (`nextLink`) per batch.
    async fn list_resources_streaming(
        &self,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        match self.list_resources().await {
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
    fn every_prefix_round_trips() {
        for s in ServiceType::all() {
            assert_eq!(ServiceType::from_prefix(s.prefix()), Some(s), "{:?}", s);
        }
    }

    #[test]
    fn aliases_resolve_and_junk_does_not() {
        assert_eq!(ServiceType::from_prefix("rg"), Some(ServiceType::Subscriptions));
        assert_eq!(ServiceType::from_prefix("@K8S"), Some(ServiceType::Aks));
        assert_eq!(ServiceType::from_prefix("ec2"), None);
    }
}
