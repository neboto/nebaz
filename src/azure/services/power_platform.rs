//! The Power Platform service (issue #77): enterprise policies
//! (`Microsoft.PowerPlatform/enterprisePolicies`), one subscription-wide
//! list. A policy is the ARM half of a Power Platform environment's
//! network, key or identity setup; the `kind` says which:
//!
//! - `NetworkInjection` names a VNet and a subnet per region of the
//!   environment's region pair (subnets delegated to
//!   `Microsoft.PowerPlatform/enterprisePolicies`), so connectors and
//!   plug-ins reach private endpoints;
//! - `Encryption` names a key vault key (customer-managed key);
//! - `Identity` carries a system-assigned identity.
//!
//! The environments a policy is linked to live in the Power Platform admin
//! API, not ARM: nebaz never calls it (the guard forbids its hosts) and
//! shows the policy's `systemId`, the id environments link to, as text. A
//! delegated subnet links back here from its own Related section, matched
//! against the warm policies list (`subnet_policy_lines`), with no call of
//! its own.
//!
//! The RP publishes only a preview api-version, and its policies carry no
//! `provisioningState`; `healthStatus` is the runtime rung. A policy's
//! location is a Power Platform geography, not an Azure region, so the row
//! passes every `R` filter (`filter_location`).

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::network::SubnetRow;
use crate::azure::services::{arm_row, finish_stream, json, overview_rows, related_rows, tag_rows, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The only version in azure-rest-api-specs and the ARM template reference
/// (checked 2026-10-23). Microsoft's own enterprise-policy PowerShell
/// module deploys with `2020-10-30`, which neither documents; not yet
/// tried live.
pub const POWER_PLATFORM_API_VERSION: &str = "2020-10-30-preview";
const POLICIES_PATH: &str = "/providers/Microsoft.PowerPlatform/enterprisePolicies";

/// The `serviceName` of a subnet delegation to Power Platform.
pub const POWER_PLATFORM_DELEGATION: &str = "Microsoft.PowerPlatform/enterprisePolicies";

crate::sections! {
    pub enum EnterprisePolicyDetailSection,
    pub static ENTERPRISE_POLICY_SECTIONS = [
        Overview "Overview",
        NetworkInjection "Network injection",
        Encryption "Encryption",
        Identity "Identity",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

/// One `networkInjection.virtualNetworks[]` entry: a VNet and the name of
/// its delegated subnet.
#[derive(Debug, Clone)]
pub struct InjectedNetwork {
    pub vnet_id: String,
    pub subnet: Option<String>,
}

impl InjectedNetwork {
    pub fn subnet_id(&self) -> Option<String> {
        self.subnet
            .as_ref()
            .map(|s| format!("{}/subnets/{}", self.vnet_id.trim_end_matches('/'), s))
    }
}

#[derive(Debug, Clone)]
pub struct EnterprisePolicyRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    /// `/regions/{geo}/providers/Microsoft.PowerPlatform/enterprisePolicies/{guid}`:
    /// what an environment links to. Not an ARM id.
    pub system_id: Option<String>,
    pub health: Option<String>,
    pub lockbox_state: Option<String>,
    /// In the order the policy lists them (the environment's region pair).
    pub networks: Vec<InjectedNetwork>,
    /// Documented as the vault's "Uri"; Microsoft's scripts pass the ARM id.
    pub key_vault: Option<String>,
    pub key_name: Option<String>,
    pub key_version: Option<String>,
    pub encryption_state: Option<String>,
    pub identity_type: Option<String>,
    pub principal_id: Option<String>,
    pub identity_tenant: Option<String>,
}

impl EnterprisePolicyRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<EnterprisePolicyRow> {
        let mut base = ArmBase::from_json(v, tenant)?;
        // The spec's example says `East US`; keep `R` matching `eastus`.
        base.location = base.location.replace(' ', "");
        let p = "/properties";
        let e = format!("{}/encryption", p);
        Some(EnterprisePolicyRow {
            kind: json::str_at(v, "/kind"),
            system_id: json::str_at(v, &format!("{}/systemId", p)),
            health: json::str_at(v, &format!("{}/healthStatus", p)),
            lockbox_state: json::str_at(v, &format!("{}/lockbox/state", p)),
            networks: json::arr(v, &format!("{}/networkInjection/virtualNetworks", p))
                .iter()
                .filter_map(|n| {
                    Some(InjectedNetwork {
                        vnet_id: json::arm_id(json::str_at(n, "/id"))?,
                        subnet: json::str_at(n, "/subnet/name"),
                    })
                })
                .collect(),
            key_vault: json::str_at(v, &format!("{}/keyVault/id", e)),
            key_name: json::str_at(v, &format!("{}/keyVault/key/name", e)),
            key_version: json::str_at(v, &format!("{}/keyVault/key/version", e)),
            encryption_state: json::str_at(v, &format!("{}/state", e)),
            identity_type: json::str_at(v, "/identity/type"),
            principal_id: json::str_at(v, "/identity/systemAssignedIdentityPrincipalId"),
            identity_tenant: json::str_at(v, "/identity/tenantId"),
            base,
        })
    }

    /// Whether this policy's network injection names `subnet_id`.
    pub fn uses_subnet(&self, subnet_id: &str) -> bool {
        self.networks
            .iter()
            .filter_map(InjectedNetwork::subnet_id)
            .any(|s| s.eq_ignore_ascii_case(subnet_id.trim_end_matches('/')))
    }

    /// The key vault's ARM id, when the policy names it by one.
    fn key_vault_id(&self) -> Option<String> {
        json::arm_id(self.key_vault.clone())
    }

    /// Rung 2: `healthStatus` (`Healthy`, `Warning`, `Unhealthy`,
    /// `Undetermined`, which stays stateless with its word).
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.health.as_deref().map(|h| {
            let bucket = match h.to_lowercase().as_str() {
                "healthy" => ResourceState::Available,
                "warning" => ResourceState::Pending,
                "unhealthy" => ResourceState::Unavailable,
                _ => ResourceState::stateless(),
            };
            (bucket, h)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for EnterprisePolicyRow {
    arm_row!("Enterprise Policy");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ENTERPRISE_POLICY_SECTIONS)
    }
    /// A policy's location is a Power Platform geography (`unitedstates`,
    /// `europe`), never an Azure region: the row passes every `R` filter
    /// and stays out of its picker, while `location()` still shows it.
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// The kind, the system id (what an environment's settings show) and
    /// the identity's principal id are searchable.
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.kind.clone()),
            json::opt(self.system_id.clone()),
            json::opt(self.principal_id.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut d = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Kind".into(), json::opt(self.kind.clone())),
            ("System id".into(), json::opt(self.system_id.clone())),
            ("Health".into(), json::opt(self.health.clone())),
        ];
        if let Some(l) = &self.lockbox_state {
            d.push(("Lockbox".into(), l.clone()));
        }
        d
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for n in &self.networks {
            if !v.iter().any(|(_, id)| id.eq_ignore_ascii_case(&n.vnet_id)) {
                v.push((format!("Virtual network {}", name_of_id(&n.vnet_id)), n.vnet_id.clone()));
            }
            if let (Some(id), Some(s)) = (n.subnet_id(), &n.subnet) {
                v.push((format!("Subnet {}/{}", name_of_id(&n.vnet_id), s), id));
            }
        }
        if let Some(kv) = self.key_vault_id() {
            v.push((format!("Key vault {}", name_of_id(&kv)), kv));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az resource show --ids {}", shell_quote(&self.base.id)))
    }
}

/// Body lines for one section of an enterprise policy row.
pub fn enterprise_policy_section_lines(
    r: &EnterprisePolicyRow,
    section: EnterprisePolicyDetailSection,
) -> Vec<(String, String)> {
    let kind = json::opt(r.kind.clone());
    match section {
        EnterprisePolicyDetailSection::Overview => overview_rows(r),
        EnterprisePolicyDetailSection::NetworkInjection => {
            if r.networks.is_empty() {
                return vec![(String::new(), format!("No network injection (kind {})", kind))];
            }
            let mut lines = vec![(
                String::new(),
                "Delegated subnets, in the order the policy lists them (the environment's region pair)".into(),
            )];
            for (i, n) in r.networks.iter().enumerate() {
                lines.push((String::new(), String::new()));
                lines.push((format!("Virtual network {}", i + 1), n.vnet_id.clone()));
                lines.push(("  Subnet".into(), n.subnet_id().unwrap_or_else(|| "-".into())));
            }
            lines
        }
        EnterprisePolicyDetailSection::Encryption => {
            if r.key_vault.is_none() && r.encryption_state.is_none() {
                return vec![(String::new(), format!("No customer-managed key (kind {})", kind))];
            }
            vec![
                ("Key vault".into(), json::opt(r.key_vault.clone())),
                ("Key".into(), json::opt(r.key_name.clone())),
                ("Version".into(), json::opt(r.key_version.clone())),
                ("State".into(), json::opt(r.encryption_state.clone())),
            ]
        }
        EnterprisePolicyDetailSection::Identity => {
            if r.identity_type.is_none() && r.principal_id.is_none() {
                return vec![(String::new(), "No identity".into())];
            }
            vec![
                ("Type".into(), json::opt(r.identity_type.clone())),
                ("Principal id".into(), json::opt(r.principal_id.clone())),
                ("Tenant".into(), json::opt(r.identity_tenant.clone())),
            ]
        }
        EnterprisePolicyDetailSection::Access => crate::azure::services::rendered_by_app(),
        EnterprisePolicyDetailSection::Activity => crate::azure::services::rendered_by_app(),
        EnterprisePolicyDetailSection::Related => {
            let mut lines = related_rows(r);
            lines.push((
                String::new(),
                "· linked environments live in the Power Platform admin API, not ARM (System id in Overview)".into(),
            ));
            lines
        }
        EnterprisePolicyDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// A subnet's Related lines for Power Platform: each policy in the warm
/// policies list (`policies`, `None` while it is cold) whose network
/// injection names the subnet; else, for a subnet delegated to Power
/// Platform, a note saying so. No call of its own.
pub fn subnet_policy_lines(subnet: &SubnetRow, policies: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
    let mut lines: Vec<(String, String)> = policies
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r.as_any().downcast_ref::<EnterprisePolicyRow>())
        .filter(|p| p.uses_subnet(&subnet.id))
        .map(|p| (format!("Power Platform policy {}", p.base.name), p.base.id.clone()))
        .collect();
    let delegated = subnet
        .delegations
        .iter()
        .any(|d| d.eq_ignore_ascii_case(POWER_PLATFORM_DELEGATION));
    if lines.is_empty() && delegated {
        lines.push((
            String::new(),
            match policies {
                None => "· delegated to Power Platform (list Power Platform › Enterprise policies to link the policy)".into(),
                Some(_) => "· delegated to Power Platform; no enterprise policy in this subscription names it".into(),
            },
        ));
    }
    lines
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct PowerPlatformService {
    scope: Scope,
}

impl PowerPlatformService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for PowerPlatformService {
    fn service_type(&self) -> ServiceType {
        ServiceType::PowerPlatform
    }

    fn name(&self) -> &str {
        "Power Platform"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(POLICIES_PATH, POWER_PLATFORM_API_VERSION)
            .await?
            .iter()
            .filter_map(|v| EnterprisePolicyRow::from_json(v, tenant))
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .collect())
    }

    async fn list_resources_streaming(
        &self,
        _view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(
                POLICIES_PATH,
                POWER_PLATFORM_API_VERSION,
                &[],
                service_type,
                "Listing Power Platform enterprise policies…",
                &event_tx,
                |page| {
                    page.iter()
                        .filter_map(|v| EnterprisePolicyRow::from_json(v, tenant.as_deref()))
                        .map(|r| Box::new(r) as Box<dyn Resource>)
                        .collect()
                },
            )
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, POWER_PLATFORM_API_VERSION).await?;
        EnterprisePolicyRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-pp";

    fn vnet(name: &str) -> String {
        format!("{}/providers/Microsoft.Network/virtualNetworks/{}", RG, name)
    }

    /// The documented shape (azure-rest-api-specs `2020-10-30-preview`,
    /// the ARM template reference), with the `systemId` form Microsoft's
    /// enterprise-policy module tests use. Not a captured live body.
    fn network_policy_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.PowerPlatform/enterprisePolicies/ep-vnet", RG),
            "name": "ep-vnet",
            "type": "Microsoft.PowerPlatform/enterprisePolicies",
            "kind": "NetworkInjection",
            "location": "unitedstates",
            "tags": {"team": "platform"},
            "properties": {
                "systemId": "/regions/unitedstates/providers/Microsoft.PowerPlatform/enterprisePolicies/44444444-4444-4444-4444-444444444444",
                "healthStatus": "Healthy",
                "networkInjection": {
                    "virtualNetworks": [
                        {"id": vnet("vnet-eastus"), "subnet": {"name": "snet-pp"}},
                        {"id": vnet("vnet-westus"), "subnet": {"name": "snet-pp"}}
                    ]
                }
            }
        })
    }

    fn encryption_policy_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.PowerPlatform/enterprisePolicies/ep-cmk", RG),
            "name": "ep-cmk",
            "kind": "Encryption",
            "location": "East US",
            "identity": {
                "type": "SystemAssigned",
                "systemAssignedIdentityPrincipalId": "22222222-2222-2222-2222-222222222222",
                "tenantId": "11111111-1111-1111-1111-111111111111"
            },
            "properties": {
                "healthStatus": "Warning",
                "encryption": {
                    "state": "Enabled",
                    "keyVault": {
                        "id": format!("{}/providers/Microsoft.KeyVault/vaults/kv-pp", RG),
                        "key": {"name": "pp-key", "version": "abc123"}
                    }
                }
            }
        })
    }

    fn subnet(vnet_name: &str, delegation: Option<&str>) -> SubnetRow {
        let delegations: Vec<Value> = delegation
            .map(|d| serde_json::json!({"name": "pp", "properties": {"serviceName": d}}))
            .into_iter()
            .collect();
        SubnetRow::from_json(
            &serde_json::json!({
                "id": format!("{}/subnets/snet-pp", vnet(vnet_name)),
                "name": "snet-pp",
                "properties": {"addressPrefix": "10.0.1.0/24", "delegations": delegations}
            }),
            None,
        )
        .unwrap()
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = ENTERPRISE_POLICY_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            ["Overview", "Network injection", "Encryption", "Identity", "Access", "Activity", "Related", "Tags"]
        );
    }

    #[test]
    fn network_injection_policy_parses_kind_system_id_health_and_both_subnets() {
        let row = EnterprisePolicyRow::from_json(&network_policy_json(), Some("t")).unwrap();
        assert_eq!(row.kind.as_deref(), Some("NetworkInjection"));
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "healthy");
        assert!(row.search_text().contains("/regions/unitedstates/"), "system id searchable");
        assert_eq!(row.networks.len(), 2);
        assert_eq!(row.location(), Some("unitedstates"), "the geography still shows");
        let eastus = crate::azure::location::Location::Named("eastus".into());
        assert!(eastus.admits(row.filter_location()), "a geography passes every R filter");
        assert_eq!(
            row.networks[0].subnet_id().unwrap(),
            format!("{}/subnets/snet-pp", vnet("vnet-eastus"))
        );
        assert!(row.uses_subnet(&format!("{}/subnets/SNET-PP", vnet("vnet-westus"))), "ids compare case-insensitively");
        assert!(!row.uses_subnet(&format!("{}/subnets/other", vnet("vnet-westus"))));

        let related = row.related();
        let labels: Vec<&str> = related.iter().map(|(l, _)| l.as_str()).collect();
        assert!(labels.contains(&"Virtual network vnet-eastus"));
        assert!(labels.contains(&"Subnet vnet-westus/snet-pp"));
        assert!(!labels.iter().any(|l| l.starts_with("Key vault")));

        let lines = enterprise_policy_section_lines(&row, EnterprisePolicyDetailSection::NetworkInjection);
        assert!(lines.iter().any(|(k, v)| k == "Virtual network 2" && v == &vnet("vnet-westus")));
        assert!(lines.iter().any(|(k, v)| k == "  Subnet" && v.ends_with("vnet-eastus/subnets/snet-pp")));
        let enc = enterprise_policy_section_lines(&row, EnterprisePolicyDetailSection::Encryption);
        assert_eq!(enc[0].1, "No customer-managed key (kind NetworkInjection)");
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az resource show --ids /subscriptions/0000/resourceGroups/rg-pp/providers/Microsoft.PowerPlatform/enterprisePolicies/ep-vnet")
        );
    }

    #[test]
    fn encryption_policy_shows_the_key_and_identity_and_links_the_vault() {
        let row = EnterprisePolicyRow::from_json(&encryption_policy_json(), None).unwrap();
        assert_eq!(row.base.location, "eastus");
        assert_eq!(row.state(), ResourceState::Pending);
        assert_eq!(row.state_label(), "warning");
        let enc = enterprise_policy_section_lines(&row, EnterprisePolicyDetailSection::Encryption);
        assert!(enc.iter().any(|(k, v)| k == "Key" && v == "pp-key"));
        assert!(enc.iter().any(|(k, v)| k == "State" && v == "Enabled"));
        let id = enterprise_policy_section_lines(&row, EnterprisePolicyDetailSection::Identity);
        assert!(id.iter().any(|(k, v)| k == "Principal id" && v.starts_with("2222")));
        assert!(row.related().iter().any(|(l, v)| l == "Key vault kv-pp" && v.ends_with("/vaults/kv-pp")));
        let net = enterprise_policy_section_lines(&row, EnterprisePolicyDetailSection::NetworkInjection);
        assert_eq!(net[0].1, "No network injection (kind Encryption)");
    }

    #[test]
    fn undetermined_health_is_stateless_with_its_word() {
        let mut v = network_policy_json();
        v["properties"]["healthStatus"] = serde_json::json!("Undetermined");
        let row = EnterprisePolicyRow::from_json(&v, None).unwrap();
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.state_label(), "undetermined");
    }

    #[test]
    fn a_delegated_subnet_links_to_the_policy_from_the_warm_list_or_says_it_is_delegated() {
        let policies: Vec<Box<dyn Resource>> = vec![
            Box::new(EnterprisePolicyRow::from_json(&network_policy_json(), None).unwrap()),
            Box::new(EnterprisePolicyRow::from_json(&encryption_policy_json(), None).unwrap()),
        ];
        let used = subnet("vnet-eastus", Some(POWER_PLATFORM_DELEGATION));
        let lines = subnet_policy_lines(&used, Some(&policies));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, "Power Platform policy ep-vnet");
        assert!(lines[0].1.ends_with("/enterprisePolicies/ep-vnet"));

        let cold = subnet_policy_lines(&used, None);
        assert!(cold[0].0.is_empty() && cold[0].1.starts_with("· delegated to Power Platform"));

        let orphan = subnet("vnet-other", Some("microsoft.powerplatform/enterprisepolicies"));
        let lines = subnet_policy_lines(&orphan, Some(&policies));
        assert!(lines[0].1.contains("no enterprise policy in this subscription"));

        let plain = subnet("vnet-other", Some("Microsoft.Web/serverFarms"));
        assert!(subnet_policy_lines(&plain, None).is_empty());
    }
}
