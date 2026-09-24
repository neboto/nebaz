//! The AKS service (ticket 06): managed clusters from the subscription-wide
//! list and their embedded node pools (own sub-tab, named `cluster/pool`,
//! inheriting the cluster's location). The list's `agentPoolProfiles` is
//! the full agent-pool property set, so node pools need no lazy call.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{arm_row, finish_stream, json, overview_rows, related_rows, tag_rows, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub const AKS_API_VERSION: &str = "2026-06-01";
const CLUSTERS_PATH: &str = "/providers/Microsoft.ContainerService/managedClusters";

crate::sections! {
    pub enum ClusterDetailSection,
    pub static CLUSTER_SECTIONS = [
        Overview "Overview",
        Network "Network",
        Access "Access",
        NodePools "Node pools",
        AddOns "Add-ons",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum NodePoolDetailSection,
    pub static NODE_POOL_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

/// `powerState.code` → bucket, shared by clusters and pools.
fn power_runtime(power: Option<&str>) -> Option<(ResourceState, &str)> {
    power.map(|p| {
        let bucket = match p.to_lowercase().as_str() {
            "running" => ResourceState::Running,
            "stopped" => ResourceState::Stopped,
            other => ResourceState::Unknown(other.to_string()),
        };
        (bucket, p)
    })
}

// ── Managed cluster ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ClusterRow {
    pub base: ArmBase,
    pub kubernetes_version: Option<String>,
    pub current_kubernetes_version: Option<String>,
    pub fqdn: Option<String>,
    pub private_fqdn: Option<String>,
    pub dns_prefix: Option<String>,
    pub sku: Option<String>,
    pub sku_tier: Option<String>,
    pub node_resource_group: Option<String>,
    pub power: Option<String>,
    pub support_plan: Option<String>,
    pub upgrade_channel: Option<String>,
    /// `(label, value)` of the network profile, in display order.
    pub network: Vec<(String, String)>,
    pub private_cluster: Option<bool>,
    pub authorized_ip_ranges: Vec<String>,
    pub enable_rbac: Option<bool>,
    pub aad_managed: Option<bool>,
    pub azure_rbac: Option<bool>,
    pub identity_type: Option<String>,
    /// The cluster's user-assigned control-plane identities.
    pub user_identity_ids: Vec<String>,
    /// `identityProfile.kubeletidentity.resourceId`: what the nodes pull
    /// images and reach Azure as.
    pub kubelet_identity_id: Option<String>,
    pub oidc_issuer: Option<String>,
    pub workload_identity: Option<bool>,
    /// `(name, enabled)`.
    pub addons: Vec<(String, bool)>,
    pub pools: Vec<NodePoolRow>,
}

impl ClusterRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ClusterRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let np = format!("{}/networkProfile", p);
        let network = [
            ("Plugin", "networkPlugin"),
            ("Plugin mode", "networkPluginMode"),
            ("Policy", "networkPolicy"),
            ("Dataplane", "networkDataplane"),
            ("Service CIDR", "serviceCidr"),
            ("DNS service IP", "dnsServiceIP"),
            ("Pod CIDR", "podCidr"),
            ("Load balancer SKU", "loadBalancerSku"),
            ("Outbound type", "outboundType"),
        ]
        .iter()
        .filter_map(|(label, key)| json::str_at(v, &format!("{}/{}", np, key)).map(|val| (label.to_string(), val)))
        .collect();
        let addons = v
            .pointer(&format!("{}/addonProfiles", p))
            .and_then(|a| a.as_object())
            .map(|o| {
                let mut v: Vec<(String, bool)> = o
                    .iter()
                    .map(|(k, a)| (k.clone(), json::bool_at(a, "/enabled").unwrap_or(false)))
                    .collect();
                v.sort();
                v
            })
            .unwrap_or_default();
        let pools = json::arr(v, &format!("{}/agentPoolProfiles", p))
            .iter()
            .filter_map(|ap| NodePoolRow::from_profile(ap, &base))
            .collect();
        Some(ClusterRow {
            kubernetes_version: json::str_at(v, &format!("{}/kubernetesVersion", p)),
            current_kubernetes_version: json::str_at(v, &format!("{}/currentKubernetesVersion", p)),
            fqdn: json::str_at(v, &format!("{}/fqdn", p)),
            private_fqdn: json::str_at(v, &format!("{}/privateFQDN", p)),
            dns_prefix: json::str_at(v, &format!("{}/dnsPrefix", p)),
            sku: json::str_at(v, "/sku/name"),
            sku_tier: json::str_at(v, "/sku/tier"),
            node_resource_group: json::str_at(v, &format!("{}/nodeResourceGroup", p)),
            power: json::str_at(v, &format!("{}/powerState/code", p)),
            support_plan: json::str_at(v, &format!("{}/supportPlan", p)),
            upgrade_channel: json::str_at(v, &format!("{}/autoUpgradeProfile/upgradeChannel", p)),
            network,
            private_cluster: json::bool_at(v, &format!("{}/apiServerAccessProfile/enablePrivateCluster", p)),
            authorized_ip_ranges: json::strings_at(v, &format!("{}/apiServerAccessProfile/authorizedIPRanges", p)),
            enable_rbac: json::bool_at(v, &format!("{}/enableRBAC", p)),
            aad_managed: json::bool_at(v, &format!("{}/aadProfile/managed", p)),
            azure_rbac: json::bool_at(v, &format!("{}/aadProfile/enableAzureRBAC", p)),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            kubelet_identity_id: json::arm_id(json::str_at(v, &format!("{}/identityProfile/kubeletidentity/resourceId", p))),
            oidc_issuer: json::bool_at(v, &format!("{}/oidcIssuerProfile/enabled", p))
                .filter(|e| *e)
                .and_then(|_| json::str_at(v, &format!("{}/oidcIssuerProfile/issuerURL", p))),
            workload_identity: json::bool_at(v, &format!("{}/securityProfile/workloadIdentity/enabled", p)),
            addons,
            pools,
            base,
        })
    }

    fn ladder(&self) -> (ResourceState, String) {
        state_ladder(self.base.provisioning_state.as_deref(), power_runtime(self.power.as_deref()))
    }

    fn node_resource_group_id(&self) -> Option<String> {
        Some(format!(
            "/subscriptions/{}/resourceGroups/{}",
            subscription_of(&self.base.id)?,
            self.node_resource_group.as_deref()?
        ))
    }
}

impl Resource for ClusterRow {
    arm_row!("Managed Cluster");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&CLUSTER_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.kubernetes_version.clone()),
            json::opt(self.fqdn.clone()),
            json::opt(self.power.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Power".into(), json::opt(self.power.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            (
                "Kubernetes".into(),
                match (&self.kubernetes_version, &self.current_kubernetes_version) {
                    (Some(k), Some(c)) if k != c => format!("{} (running {})", k, c),
                    (Some(k), _) => k.clone(),
                    (None, c) => json::opt(c.clone()),
                },
            ),
            ("FQDN".into(), json::opt(self.fqdn.clone().or_else(|| self.private_fqdn.clone()))),
            ("DNS prefix".into(), json::opt(self.dns_prefix.clone())),
            ("SKU".into(), format!("{} · {}", json::opt(self.sku.clone()), json::opt(self.sku_tier.clone()))),
            ("Node resource group".into(), json::opt(self.node_resource_group.clone())),
            ("Node pools".into(), self.pools.len().to_string()),
            ("Support plan".into(), json::opt(self.support_plan.clone())),
            ("Auto-upgrade channel".into(), json::opt(self.upgrade_channel.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let (Some(rg), Some(id)) = (&self.node_resource_group, self.node_resource_group_id()) {
            v.push((format!("Node resource group {}", rg), id));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        if let Some(k) = &self.kubelet_identity_id {
            v.push((format!("Kubelet identity {}", name_of_id(k)), k.clone()));
        }
        v
    }
    /// `az aks show` takes no `--ids` (checked on the Azure machine,
    /// 2026-09-23), so the name form carries `--subscription` itself.
    fn cli_command(&self) -> Option<String> {
        Some(format!(
            "az aks show -n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

pub fn cluster_section_lines(r: &ClusterRow, section: ClusterDetailSection) -> Vec<(String, String)> {
    match section {
        ClusterDetailSection::Overview => overview_rows(r),
        ClusterDetailSection::Network => {
            let mut lines = r.network.clone();
            lines.push(("Private cluster".into(), json::yes_no(r.private_cluster)));
            lines.push(("Authorised IP ranges".into(), json::join(&r.authorized_ip_ranges)));
            if lines.len() == 2 {
                lines.insert(0, (String::new(), "No network profile".into()));
            }
            lines
        }
        ClusterDetailSection::Access => {
            let mut lines = vec![
                ("Kubernetes RBAC".into(), json::yes_no(r.enable_rbac)),
                ("Entra integration".into(), json::yes_no(r.aad_managed)),
                ("Azure RBAC for Kubernetes".into(), json::yes_no(r.azure_rbac)),
                ("Identity".into(), json::opt(r.identity_type.clone())),
                ("Workload identity".into(), json::yes_no(r.workload_identity)),
                ("OIDC issuer".into(), json::opt(r.oidc_issuer.clone())),
            ];
            for id in &r.user_identity_ids {
                lines.push((format!("User identity · {}", name_of_id(id)), id.clone()));
            }
            if let Some(k) = &r.kubelet_identity_id {
                lines.push((format!("Kubelet identity · {}", name_of_id(k)), k.clone()));
            }
            lines
        }
        ClusterDetailSection::NodePools => {
            if r.pools.is_empty() {
                return vec![(String::new(), "No node pools".into())];
            }
            r.pools
                .iter()
                .map(|p| {
                    (
                        format!(
                            "{} · {} · {} × {}",
                            p.name,
                            json::opt(p.mode.clone()).to_lowercase(),
                            json::num(p.count),
                            json::opt(p.vm_size.clone())
                        ),
                        p.id.clone(),
                    )
                })
                .collect()
        }
        ClusterDetailSection::AddOns => {
            let enabled: Vec<(String, String)> = r
                .addons
                .iter()
                .map(|(n, e)| (n.clone(), if *e { "enabled".into() } else { "disabled".into() }))
                .collect();
            if enabled.is_empty() {
                vec![(String::new(), "No add-on profiles".into())]
            } else {
                enabled
            }
        }
        ClusterDetailSection::Related => related_rows(r),
        ClusterDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Node pool (embedded child) ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NodePoolRow {
    /// `{cluster}/agentPools/{name}` — the ARM id the `agentPools` GET
    /// answers to.
    pub id: String,
    /// The bare pool name; `name()` is `cluster/pool`.
    pub name: String,
    display_name: String,
    pub cluster_id: String,
    pub cluster_name: String,
    pub location: Option<String>,
    tenant: Option<String>,
    raw: String,
    tags: HashMap<String, String>,
    pub provisioning_state: Option<String>,
    pub power: Option<String>,
    pub mode: Option<String>,
    pub count: Option<i64>,
    pub vm_size: Option<String>,
    pub os_type: Option<String>,
    pub os_sku: Option<String>,
    pub os_disk_gb: Option<i64>,
    pub orchestrator_version: Option<String>,
    pub current_orchestrator_version: Option<String>,
    pub node_image_version: Option<String>,
    pub autoscale: Option<bool>,
    pub min_count: Option<i64>,
    pub max_count: Option<i64>,
    pub max_pods: Option<i64>,
    pub zones: Vec<String>,
    pub priority: Option<String>,
    pub taints: Vec<String>,
    pub labels: Vec<(String, String)>,
}

impl NodePoolRow {
    /// One element of a cluster's embedded `agentPoolProfiles[]` (flat
    /// properties, no `id`).
    pub fn from_profile(v: &Value, cluster: &ArmBase) -> Option<NodePoolRow> {
        let name = json::str_at(v, "/name")?;
        let id = format!("{}/agentPools/{}", cluster.id.trim_end_matches('/'), name);
        Self::parse(v, v, id, name, &cluster.id, &cluster.name, Some(cluster.location.clone()), cluster.tenant.as_deref())
    }

    /// A standalone agent-pool body (`GET …/agentPools/{name}`), fields
    /// under `properties`, the cluster read from the id.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<NodePoolRow> {
        let id = json::str_at(v, "/id")?;
        let name = json::str_at(v, "/name").unwrap_or_else(|| name_of_id(&id).to_string());
        let pos = id.to_lowercase().rfind("/agentpools/")?;
        let cluster_id = id[..pos].to_string();
        let cluster_name = name_of_id(&cluster_id).to_string();
        let props = v.get("properties").unwrap_or(v);
        Self::parse(props, v, id.clone(), name, &cluster_id, &cluster_name, None, tenant)
    }

    #[allow(clippy::too_many_arguments)]
    fn parse(
        p: &Value,
        raw: &Value,
        id: String,
        name: String,
        cluster_id: &str,
        cluster_name: &str,
        location: Option<String>,
        tenant: Option<&str>,
    ) -> Option<NodePoolRow> {
        let labels = p
            .get("nodeLabels")
            .and_then(|l| l.as_object())
            .map(|o| {
                let mut v: Vec<(String, String)> = o
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect();
                v.sort();
                v
            })
            .unwrap_or_default();
        Some(NodePoolRow {
            display_name: format!("{}/{}", cluster_name, name),
            cluster_id: cluster_id.to_string(),
            cluster_name: cluster_name.to_string(),
            location: location.filter(|l| !l.is_empty()),
            tenant: tenant.map(str::to_string),
            raw: serde_json::to_string_pretty(raw).unwrap_or_default(),
            tags: json::tags_of(p),
            provisioning_state: json::str_at(p, "/provisioningState"),
            power: json::str_at(p, "/powerState/code"),
            mode: json::str_at(p, "/mode"),
            count: json::int_at(p, "/count"),
            vm_size: json::str_at(p, "/vmSize"),
            os_type: json::str_at(p, "/osType"),
            os_sku: json::str_at(p, "/osSKU"),
            os_disk_gb: json::int_at(p, "/osDiskSizeGB"),
            orchestrator_version: json::str_at(p, "/orchestratorVersion"),
            current_orchestrator_version: json::str_at(p, "/currentOrchestratorVersion"),
            node_image_version: json::str_at(p, "/nodeImageVersion"),
            autoscale: json::bool_at(p, "/enableAutoScaling"),
            min_count: json::int_at(p, "/minCount"),
            max_count: json::int_at(p, "/maxCount"),
            max_pods: json::int_at(p, "/maxPods"),
            zones: json::strings_at(p, "/availabilityZones"),
            priority: json::str_at(p, "/scaleSetPriority"),
            taints: json::strings_at(p, "/nodeTaints"),
            labels,
            id,
            name,
        })
    }

    fn ladder(&self) -> (ResourceState, String) {
        state_ladder(self.provisioning_state.as_deref(), power_runtime(self.power.as_deref()))
    }
}

impl Resource for NodePoolRow {
    fn id(&self) -> &str {
        &self.id
    }
    /// `cluster/pool` on the sub-tab; the bare `name` field inside the
    /// cluster's own section.
    #[allow(clippy::misnamed_getters)]
    fn name(&self) -> &str {
        &self.display_name
    }
    fn resource_type(&self) -> &str {
        "Node Pool"
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&NODE_POOL_SECTIONS)
    }
    fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }
    fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }
    fn tenant_id(&self) -> Option<&str> {
        self.tenant.as_deref()
    }
    fn raw_content(&self) -> Option<String> {
        Some(self.raw.clone())
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.id,
            self.display_name,
            self.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.vm_size.clone()),
            json::opt(self.mode.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.name.clone()),
            ("Cluster".into(), self.cluster_name.clone()),
            ("Id".into(), self.id.clone()),
            ("Location".into(), self.location.clone().unwrap_or_else(|| "(the cluster's)".into())),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Power".into(), json::opt(self.power.clone())),
            ("Provisioning state".into(), json::opt(self.provisioning_state.clone())),
            ("Mode".into(), json::opt(self.mode.clone())),
            ("Count".into(), json::num(self.count)),
            (
                "Autoscale".into(),
                match (self.autoscale, self.min_count, self.max_count) {
                    (Some(true), min, max) => format!("{} – {}", json::num(min), json::num(max)),
                    (b, _, _) => json::yes_no(b),
                },
            ),
            ("VM size".into(), json::opt(self.vm_size.clone())),
            (
                "OS".into(),
                format!("{} · {}", json::opt(self.os_type.clone()), json::opt(self.os_sku.clone())),
            ),
            ("OS disk".into(), self.os_disk_gb.map(|g| format!("{} GB", g)).unwrap_or_else(|| "-".into())),
            (
                "Kubernetes".into(),
                match (&self.orchestrator_version, &self.current_orchestrator_version) {
                    (Some(k), Some(c)) if k != c => format!("{} (running {})", k, c),
                    (Some(k), _) => k.clone(),
                    (None, c) => json::opt(c.clone()),
                },
            ),
            ("Node image".into(), json::opt(self.node_image_version.clone())),
            ("Max pods".into(), json::num(self.max_pods)),
            ("Zones".into(), json::join(&self.zones)),
            ("Priority".into(), json::opt(self.priority.clone())),
            ("Taints".into(), json::join(&self.taints)),
            (
                "Labels".into(),
                if self.labels.is_empty() {
                    "-".into()
                } else {
                    self.labels.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(", ")
                },
            ),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.id);
        v.push((format!("Cluster {}", self.cluster_name), self.cluster_id.clone()));
        v
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    /// No `--ids` on `az aks nodepool show` either: cluster, group and
    /// pool by name.
    fn cli_command(&self) -> Option<String> {
        Some(format!(
            "az aks nodepool show --cluster-name {} -g {} -n {} --subscription {}",
            shell_quote(&self.cluster_name),
            shell_quote(resource_group_of(&self.id)?),
            shell_quote(&self.name),
            shell_quote(subscription_of(&self.id)?)
        ))
    }
}

pub fn node_pool_section_lines(r: &NodePoolRow, section: NodePoolDetailSection) -> Vec<(String, String)> {
    match section {
        NodePoolDetailSection::Overview => overview_rows(r),
        NodePoolDetailSection::Related => related_rows(r),
        NodePoolDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct AksService {
    scope: Scope,
}

impl AksService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<R: Resource + 'static>(rows: Vec<R>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn pools_of(page: &[Value], tenant: Option<&str>) -> Vec<NodePoolRow> {
        page.iter()
            .filter_map(|v| ClusterRow::from_json(v, tenant))
            .flat_map(|c| c.pools)
            .collect()
    }
}

#[async_trait]
impl AzureService for AksService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Aks
    }

    fn name(&self) -> &str {
        "AKS"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        let page = self.scope.list(CLUSTERS_PATH, AKS_API_VERSION).await?;
        Ok(match view {
            JumpView::NodePools => Self::boxed(Self::pools_of(&page, tenant)),
            _ => Self::boxed(page.iter().filter_map(|v| ClusterRow::from_json(v, tenant)).collect()),
        })
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let r = match view {
            JumpView::NodePools => {
                self.scope
                    .stream(CLUSTERS_PATH, AKS_API_VERSION, &[], service_type, "Listing node pools…", &event_tx, |page| {
                        Self::boxed(Self::pools_of(&page, tenant.as_deref()))
                    })
                    .await
            }
            _ => {
                self.scope
                    .stream(CLUSTERS_PATH, AKS_API_VERSION, &[], service_type, "Listing clusters…", &event_tx, |page| {
                        Self::boxed(page.iter().filter_map(|v| ClusterRow::from_json(v, tenant.as_deref())).collect())
                    })
                    .await
            }
        };
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let tenant = self.scope.tenant();
        let not_found = || Error::ResourceNotFound(id.to_string());
        let v = self.scope.get(id, AKS_API_VERSION).await?;
        match JumpView::for_arm_id(id) {
            Some(JumpView::Clusters) => Ok(Box::new(ClusterRow::from_json(&v, tenant).ok_or_else(not_found)?)),
            Some(JumpView::NodePools) => Ok(Box::new(NodePoolRow::from_json(&v, tenant).ok_or_else(not_found)?)),
            _ => Err(not_found()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster_json() -> Value {
        serde_json::json!({
            "id": "/subscriptions/0000/resourceGroups/rg-aks/providers/Microsoft.ContainerService/managedClusters/aks-prod",
            "name": "aks-prod",
            "location": "westeurope",
            "sku": {"name": "Base", "tier": "Standard"},
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                "/subscriptions/0000/resourceGroups/rg-id/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-aks": {}
            }},
            "properties": {
                "provisioningState": "Succeeded",
                "powerState": {"code": "Running"},
                "identityProfile": {"kubeletidentity": {
                    "resourceId": "/subscriptions/0000/resourceGroups/MC_rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-prod-agentpool",
                    "clientId": "c", "objectId": "o"
                }},
                "kubernetesVersion": "1.31.2",
                "currentKubernetesVersion": "1.31.2",
                "fqdn": "aks-prod-abc.hcp.westeurope.azmk8s.io",
                "nodeResourceGroup": "MC_rg-aks_aks-prod_westeurope",
                "enableRBAC": true,
                "aadProfile": {"managed": true, "enableAzureRBAC": true},
                "oidcIssuerProfile": {"enabled": true, "issuerURL": "https://oidc.example/"},
                "networkProfile": {"networkPlugin": "azure", "networkPolicy": "cilium", "serviceCidr": "10.2.0.0/16", "loadBalancerSku": "standard", "outboundType": "loadBalancer"},
                "apiServerAccessProfile": {"enablePrivateCluster": false, "authorizedIPRanges": ["1.2.3.4/32"]},
                "addonProfiles": {"omsagent": {"enabled": true}, "azurepolicy": {"enabled": false}},
                "agentPoolProfiles": [
                    {"name": "system", "mode": "System", "count": 3, "vmSize": "Standard_D4s_v5", "osType": "Linux", "osSKU": "AzureLinux",
                     "orchestratorVersion": "1.31.2", "currentOrchestratorVersion": "1.31.2", "nodeImageVersion": "AKSAzureLinux-V2gen2-202409.01.0",
                     "enableAutoScaling": true, "minCount": 3, "maxCount": 6, "maxPods": 110, "availabilityZones": ["1", "2", "3"],
                     "powerState": {"code": "Running"}, "provisioningState": "Succeeded", "nodeLabels": {"role": "system"}},
                    {"name": "spot", "mode": "User", "count": 0, "vmSize": "Standard_D8s_v5", "scaleSetPriority": "Spot",
                     "powerState": {"code": "Stopped"}, "provisioningState": "Upgrading", "nodeTaints": ["kubernetes.azure.com/scalesetpriority=spot:NoSchedule"]}
                ]
            }
        })
    }

    #[test]
    fn cluster_row_reads_power_access_network_and_embeds_node_pools() {
        let row = ClusterRow::from_json(&cluster_json(), Some("t-1")).unwrap();
        assert_eq!(row.state(), ResourceState::Running);
        assert_eq!(row.state_label(), "Running".to_lowercase());
        assert_eq!(row.pools.len(), 2);
        let related = row.related();
        assert_eq!(related[2].0, "Node resource group MC_rg-aks_aks-prod_westeurope");
        assert_eq!(related[2].1, "/subscriptions/0000/resourceGroups/MC_rg-aks_aks-prod_westeurope");
        let access = cluster_section_lines(&row, ClusterDetailSection::Access);
        assert!(access.iter().any(|(k, v)| k == "Azure RBAC for Kubernetes" && v == "yes"));
        assert!(access.iter().any(|(k, v)| k == "OIDC issuer" && v == "https://oidc.example/"));
        assert!(access.iter().any(|(k, _)| k == "User identity · id-aks"));
        assert!(access.iter().any(|(k, _)| k == "Kubelet identity · aks-prod-agentpool"));
        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        assert!(related.iter().any(|l| l == "Identity id-aks"), "{related:?}");
        assert!(related.iter().any(|l| l == "Kubelet identity aks-prod-agentpool"), "{related:?}");
        let net = cluster_section_lines(&row, ClusterDetailSection::Network);
        assert_eq!(net[0], ("Plugin".to_string(), "azure".to_string()));
        assert!(net.iter().any(|(k, v)| k == "Authorised IP ranges" && v == "1.2.3.4/32"));
        let pools = cluster_section_lines(&row, ClusterDetailSection::NodePools);
        assert_eq!(pools[0].0, "system · system · 3 × Standard_D4s_v5");
        assert!(pools[0].1.ends_with("/managedClusters/aks-prod/agentPools/system"));
        let addons = cluster_section_lines(&row, ClusterDetailSection::AddOns);
        assert_eq!(addons, vec![("azurepolicy".to_string(), "disabled".to_string()), ("omsagent".to_string(), "enabled".to_string())]);
        assert_eq!(row.cli_command().as_deref(), Some("az aks show -n aks-prod -g rg-aks --subscription 0000"));
    }

    #[test]
    fn node_pools_are_named_cluster_pool_inherit_location_and_follow_the_ladder() {
        let row = ClusterRow::from_json(&cluster_json(), Some("t-1")).unwrap();
        let system = &row.pools[0];
        assert_eq!(system.name(), "aks-prod/system");
        assert_eq!(system.name, "system");
        assert_eq!(system.location(), Some("westeurope"));
        assert_eq!(system.resource_group(), Some("rg-aks"));
        assert_eq!(system.state(), ResourceState::Running);
        assert!(system.details().iter().any(|(k, v)| k == "Autoscale" && v == "3 – 6"));
        assert!(system.details().iter().any(|(k, v)| k == "Labels" && v == "role=system"));
        assert!(system.related().iter().any(|(l, id)| l == "Cluster aks-prod" && id == row.id()));
        assert_eq!(
            system.cli_command().as_deref(),
            Some("az aks nodepool show --cluster-name aks-prod -g rg-aks -n system --subscription 0000")
        );
        let spot = &row.pools[1];
        assert_eq!(spot.state(), ResourceState::Pending);
        assert_eq!(spot.state_label(), "upgrading");
        assert!(spot.details().iter().any(|(k, v)| k == "Taints" && v.contains("spot:NoSchedule")));

        // The standalone GET shape: fields under `properties`.
        let standalone = serde_json::json!({
            "id": format!("{}/agentPools/system", row.id()),
            "name": "system",
            "properties": {"mode": "System", "count": 3, "vmSize": "Standard_D4s_v5", "powerState": {"code": "Stopped"}}
        });
        let pool = NodePoolRow::from_json(&standalone, None).unwrap();
        assert_eq!(pool.cluster_name, "aks-prod");
        assert_eq!(pool.name(), "aks-prod/system");
        assert_eq!(pool.state(), ResourceState::Stopped);
        assert_eq!(pool.location(), None);
    }
}
