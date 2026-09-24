//! The Container Registry service (issue #7): registries, one
//! subscription-wide list, metadata only. Replications and webhooks are
//! lazy sections, one call per registry each; replications only for a
//! Premium registry, the one SKU that geo-replicates.
//!
//! Repositories, tags and manifests live on the registry's own host (the
//! login server), which is data plane: shown as text, never requested.
//! `listCredentials` and a webhook's `getCallbackConfig` are POSTs and
//! return the admin passwords and the webhook's service URI; nebaz calls
//! neither, and the webhook list carries no URI.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable version (checked against azure-rest-api-specs,
/// 2026-09-24).
pub const ACR_API_VERSION: &str = "2025-11-01";
const REGISTRIES_PATH: &str = "/providers/Microsoft.ContainerRegistry/registries";

crate::sections! {
    pub enum RegistryDetailSection,
    pub static REGISTRY_SECTIONS = [
        Overview "Overview",
        Security "Security",
        Replications "Replications" => crate::app::App::trigger_acr_replications,
        Webhooks "Webhooks" => crate::app::App::trigger_acr_webhooks,
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct RegistryRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    /// The registry's own host (data plane): text only, never requested.
    pub login_server: Option<String>,
    pub created: Option<String>,
    pub admin_user_enabled: Option<bool>,
    pub anonymous_pull_enabled: Option<bool>,
    pub public_network_access: Option<String>,
    pub network_default_action: Option<String>,
    pub network_bypass: Option<String>,
    /// `(action, value)` per IP rule.
    pub ip_rules: Vec<(String, String)>,
    pub encryption_status: Option<String>,
    /// A Key Vault key URL (customer-managed encryption), not an ARM id.
    pub encryption_key: Option<String>,
    pub zone_redundancy: Option<String>,
    pub data_endpoint_enabled: Option<bool>,
    pub retention_status: Option<String>,
    pub retention_days: Option<i64>,
    pub role_assignment_mode: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub private_endpoint_ids: Vec<String>,
}

impl RegistryRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<RegistryRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let n = format!("{}/networkRuleSet", p);
        let r = format!("{}/policies/retentionPolicy", p);
        Some(RegistryRow {
            sku: json::str_at(v, "/sku/name"),
            login_server: json::str_at(v, &format!("{}/loginServer", p)),
            created: json::str_at(v, &format!("{}/creationDate", p)),
            admin_user_enabled: json::bool_at(v, &format!("{}/adminUserEnabled", p)),
            anonymous_pull_enabled: json::bool_at(v, &format!("{}/anonymousPullEnabled", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            network_default_action: json::str_at(v, &format!("{}/defaultAction", n)),
            network_bypass: json::str_at(v, &format!("{}/networkRuleBypassOptions", p)),
            ip_rules: json::arr(v, &format!("{}/ipRules", n))
                .iter()
                .map(|rule| (json::text(rule, "/action"), json::text(rule, "/value")))
                .collect(),
            encryption_status: json::str_at(v, &format!("{}/encryption/status", p)),
            encryption_key: json::str_at(v, &format!("{}/encryption/keyVaultProperties/keyIdentifier", p))
                .filter(|k| !k.is_empty()),
            zone_redundancy: json::str_at(v, &format!("{}/zoneRedundancy", p)),
            data_endpoint_enabled: json::bool_at(v, &format!("{}/dataEndpointEnabled", p)),
            retention_status: json::str_at(v, &format!("{}/status", r)),
            retention_days: json::int_at(v, &format!("{}/days", r)),
            role_assignment_mode: json::str_at(v, &format!("{}/roleAssignmentMode", p)),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            private_endpoint_ids: json::arr(v, &format!("{}/privateEndpointConnections", p))
                .iter()
                .filter_map(|c| json::arm_id(json::id_at(c, "/properties/privateEndpoint")))
                .collect(),
            base,
        })
    }

    /// Only Premium geo-replicates; for any other SKU the Replications
    /// section says so instead of calling.
    pub fn is_premium(&self) -> bool {
        self.sku.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("premium"))
    }

    /// `-r {registry} -g {rg} --subscription {sub}`: what `az acr
    /// replication list` and `az acr webhook list` take.
    fn registry_args(&self) -> Option<String> {
        Some(format!(
            "-r {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }

    fn retention(&self) -> String {
        match (self.retention_status.as_deref(), self.retention_days) {
            (Some(s), Some(d)) if s.eq_ignore_ascii_case("enabled") => format!("untagged manifests, {} days", d),
            (Some(s), _) => s.to_string(),
            _ => "-".into(),
        }
    }
}

impl Resource for RegistryRow {
    arm_row!("Container Registry");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&REGISTRY_SECTIONS)
    }
    /// The login server is searchable: an image reference pasted from a
    /// manifest finds its registry.
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.login_server.clone()),
            json::opt(self.sku.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Login server".into(), json::opt(self.login_server.clone())),
            ("Created".into(), json::time(self.created.clone())),
            ("Retention".into(), self.retention()),
            ("Data endpoint".into(), json::yes_no(self.data_endpoint_enabled)),
            ("Role assignment mode".into(), json::opt(self.role_assignment_mode.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for pe in &self.private_endpoint_ids {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    /// `az acr show` takes no `--ids` (no `id_part` on the registry name).
    fn cli_command(&self) -> Option<String> {
        Some(format!(
            "az acr show -n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

pub fn registry_section_lines(
    r: &RegistryRow,
    section: RegistryDetailSection,
    replications: Option<&Lazy<Vec<Value>>>,
    webhooks: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        RegistryDetailSection::Overview => overview_rows(r),
        RegistryDetailSection::Security => security_rows(r),
        RegistryDetailSection::Replications if !r.is_premium() => vec![(
            String::new(),
            format!("Geo-replication needs Premium; this registry is {}", json::opt(r.sku.clone())),
        )],
        RegistryDetailSection::Replications => {
            lazy_list_rows(replications, "Replications", |items| replication_rows(items, r))
        }
        RegistryDetailSection::Webhooks => lazy_list_rows(webhooks, "Webhooks", |items| webhook_rows(items, r)),
        RegistryDetailSection::Related => related_rows(r),
        RegistryDetailSection::Tags => tag_rows(r.tags()),
    }
}

fn security_rows(r: &RegistryRow) -> Vec<(String, String)> {
    let enabled = |b: Option<bool>, warn: &str| match b {
        Some(true) => format!("yes · {}", warn),
        other => json::yes_no(other),
    };
    let mut lines = vec![
        ("Admin user".into(), enabled(r.admin_user_enabled, "⚠ a shared username and password")),
        ("Anonymous pull".into(), enabled(r.anonymous_pull_enabled, "⚠ anyone can pull")),
        ("Public network access".into(), json::opt(r.public_network_access.clone())),
        ("Network default action".into(), json::opt(r.network_default_action.clone())),
        ("Trusted services bypass".into(), json::opt(r.network_bypass.clone())),
    ];
    if r.ip_rules.is_empty() {
        lines.push(("IP rules".into(), "-".into()));
    }
    for (action, value) in &r.ip_rules {
        lines.push((format!("IP rule · {}", action), value.clone()));
    }
    lines.push((
        "Encryption".into(),
        // `enabled` means a customer-managed key; the default is disabled.
        if r.encryption_status.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("enabled")) || r.encryption_key.is_some() {
            "customer-managed"
        } else {
            "service-managed"
        }
        .into(),
    ));
    if let Some(k) = &r.encryption_key {
        lines.push(("  Key".into(), k.clone()));
    }
    lines.push(("Zone redundancy".into(), json::opt(r.zone_redundancy.clone())));
    lines.push(("Identity".into(), json::opt(r.identity_type.clone())));
    for pe in &r.private_endpoint_ids {
        lines.push((format!("Private endpoint · {}", name_of_id(pe)), pe.clone()));
    }
    lines
}

/// The Replications section body from `GET {registry}/replications`. The
/// home region is listed too; it is the one in the registry's location.
pub fn replication_rows(items: &[Value], r: &RegistryRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No replications".into()));
    }
    for rep in items {
        let p = "/properties";
        let location = json::str_at(rep, "/location").unwrap_or_default().to_lowercase();
        let home = if location == r.base.location { " (home)" } else { "" };
        lines.push((String::new(), String::new()));
        lines.push((format!("{}{}", json::text(rep, "/name"), home), String::new()));
        lines.push(("  Location".into(), location));
        lines.push(("  Status".into(), json::text(rep, &format!("{}/status/displayStatus", p))));
        lines.push(("  Zone redundancy".into(), json::text(rep, &format!("{}/zoneRedundancy", p))));
        lines.push((
            "  Regional endpoint".into(),
            json::yes_no(json::bool_at(rep, &format!("{}/regionEndpointEnabled", p))),
        ));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az acr replication list {}", r.registry_args().unwrap_or_default()),
    ));
    lines
}

/// The Webhooks section body from `GET {registry}/webhooks`. The service
/// URI is only in `getCallbackConfig` (a POST), so it is never here.
pub fn webhook_rows(items: &[Value], r: &RegistryRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No webhooks".into()));
    }
    for hook in items {
        let p = "/properties";
        let scope = json::str_at(hook, &format!("{}/scope", p))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "every repository".into());
        lines.push((String::new(), String::new()));
        lines.push((json::text(hook, "/name"), String::new()));
        lines.push(("  Status".into(), json::text(hook, &format!("{}/status", p))));
        lines.push(("  Actions".into(), json::join(&json::strings_at(hook, &format!("{}/actions", p)))));
        lines.push(("  Scope".into(), scope));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az acr webhook list {}", r.registry_args().unwrap_or_default()),
    ));
    lines
}

/// The ARM path of a registry's child list (`replications`, `webhooks`).
pub fn registry_child_path(registry_id: &str, child: &str) -> String {
    format!("{}/{}", registry_id.trim_end_matches('/'), child)
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct ContainerRegistryService {
    scope: Scope,
}

impl ContainerRegistryService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for ContainerRegistryService {
    fn service_type(&self) -> ServiceType {
        ServiceType::ContainerRegistry
    }

    fn name(&self) -> &str {
        "Container Registry"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(REGISTRIES_PATH, ACR_API_VERSION)
            .await?
            .iter()
            .filter_map(|v| RegistryRow::from_json(v, tenant))
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
            .stream(REGISTRIES_PATH, ACR_API_VERSION, &[], service_type, "Listing container registries…", &event_tx, |page| {
                page.iter()
                    .filter_map(|v| RegistryRow::from_json(v, tenant.as_deref()))
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, ACR_API_VERSION).await?;
        RegistryRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-apps";

    fn registry_json(sku: &str) -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.ContainerRegistry/registries/acrprod", RG),
            "name": "acrprod",
            "location": "westeurope",
            "sku": {"name": sku, "tier": sku},
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-acr", RG): {}
            }},
            "properties": {
                "loginServer": "acrprod.registry.example",
                "creationDate": "2025-03-01T10:20:30.1234567Z",
                "provisioningState": "Succeeded",
                "adminUserEnabled": true,
                "anonymousPullEnabled": false,
                "networkRuleSet": {"defaultAction": "Deny", "ipRules": [{"action": "Allow", "value": "203.0.113.0/24"}]},
                "policies": {"retentionPolicy": {"days": 7, "status": "enabled"}},
                "encryption": {"status": "enabled", "keyVaultProperties": {"keyIdentifier": "https://kv.example/keys/acr"}},
                "publicNetworkAccess": "Enabled",
                "networkRuleBypassOptions": "AzureServices",
                "zoneRedundancy": "Enabled",
                "dataEndpointEnabled": false,
                "roleAssignmentMode": "AbacRepositoryPermissions",
                "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-acr", RG)}}}]
            }
        })
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = REGISTRY_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Security", "Replications", "Webhooks", "Related", "Tags"]);
    }

    #[test]
    fn registry_row_reads_overview_security_and_related() {
        let row = RegistryRow::from_json(&registry_json("Premium"), None).unwrap();
        assert_eq!(row.state(), ResourceState::stateless(), "Succeeded alone is the ladder's stateless rung");
        assert!(row.details().iter().any(|(k, v)| k == "Retention" && v == "untagged manifests, 7 days"));
        assert!(row.details().iter().any(|(k, v)| k == "Created" && v == "2025-03-01 10:20:30"));
        assert!(row.search_text().contains("acrprod.registry.example"));
        let sec = registry_section_lines(&row, RegistryDetailSection::Security, None, None);
        assert!(sec[0].1.starts_with("yes · ⚠"), "admin user flagged: {:?}", sec[0]);
        assert_eq!(sec[1], ("Anonymous pull".to_string(), "no".to_string()));
        assert!(sec.iter().any(|(k, v)| k == "IP rule · Allow" && v == "203.0.113.0/24"));
        assert!(sec.iter().any(|(k, v)| k == "Encryption" && v == "customer-managed"));
        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        assert!(related.iter().any(|l| l == "Private endpoint pe-acr"));
        assert!(related.iter().any(|l| l == "Identity id-acr"));
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az acr show -n acrprod -g rg-apps --subscription 0000")
        );
    }

    #[test]
    fn replications_are_premium_only_and_mark_the_home_region() {
        let basic = RegistryRow::from_json(&registry_json("Basic"), None).unwrap();
        assert!(!basic.is_premium());
        let lines = registry_section_lines(&basic, RegistryDetailSection::Replications, None, None);
        assert_eq!(lines[0].1, "Geo-replication needs Premium; this registry is Basic");

        let row = RegistryRow::from_json(&registry_json("Premium"), None).unwrap();
        let items = vec![
            serde_json::json!({"name": "westeurope", "location": "westeurope",
                "properties": {"status": {"displayStatus": "Ready"}, "zoneRedundancy": "Enabled", "regionEndpointEnabled": true}}),
            serde_json::json!({"name": "eastus", "location": "eastus",
                "properties": {"status": {"displayStatus": "Syncing"}, "zoneRedundancy": "Disabled", "regionEndpointEnabled": false}}),
        ];
        let lines = registry_section_lines(&row, RegistryDetailSection::Replications, Some(&Lazy::Loaded(items)), None);
        assert!(lines.iter().any(|(k, _)| k == "westeurope (home)"));
        assert!(lines.iter().any(|(k, v)| k == "  Status" && v == "Syncing"));
        assert_eq!(lines.last().unwrap().1, "az acr replication list -r acrprod -g rg-apps --subscription 0000");
    }

    #[test]
    fn webhooks_show_actions_and_scope_but_no_uri() {
        let row = RegistryRow::from_json(&registry_json("Standard"), None).unwrap();
        let items = vec![serde_json::json!({"name": "deploy",
            "properties": {"status": "enabled", "scope": "", "actions": ["push", "delete"],
                // Not in a real list body; a stray one must not render.
                "serviceUri": "https://hooks.example/secret-token"}})];
        let lines = registry_section_lines(&row, RegistryDetailSection::Webhooks, None, Some(&Lazy::Loaded(items)));
        assert!(lines.iter().any(|(k, v)| k == "  Actions" && v == "push, delete"));
        assert!(lines.iter().any(|(k, v)| k == "  Scope" && v == "every repository"));
        assert!(!lines.iter().any(|(_, v)| v.contains("secret-token")));
        assert_eq!(lines.last().unwrap().1, "az acr webhook list -r acrprod -g rg-apps --subscription 0000");
        assert_eq!(
            registry_child_path(&row.base.id, "webhooks"),
            format!("{}/webhooks", row.base.id)
        );
    }
}
