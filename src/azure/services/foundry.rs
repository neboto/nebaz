//! The Foundry service (issue #12): every `Microsoft.CognitiveServices`
//! account from the subscription-wide list — Foundry resources (`kind`
//! `AIServices`), Azure OpenAI and the single-purpose kinds alike, `kind`
//! telling them apart. Model deployments and Foundry projects are
//! per-account lists, so they are lazy sections, never sub-tabs.
//!
//! Control plane only. Keys (`listKeys`), connection secrets and pausing a
//! deployment are all `POST`, and anything that calls a model is a data
//! plane host; the read-only guard names both. The endpoint is shown as a
//! string, never requested.

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

/// The newest stable version with a few months behind it (checked against
/// azure-rest-api-specs, 2026-09-24); `accounts/projects` needs ≥ 2025-06-01.
pub const FOUNDRY_API_VERSION: &str = "2026-07-01";
const ACCOUNTS_PATH: &str = "/providers/Microsoft.CognitiveServices/accounts";

const NEVER_KEYS: &str = "metadata from ARM; keys and model calls are never fetched";

crate::sections! {
    pub enum FoundryDetailSection,
    pub static FOUNDRY_SECTIONS = [
        Overview "Overview",
        Deployments "Deployments" => crate::app::App::trigger_foundry_deployments,
        Projects "Projects" => crate::app::App::trigger_foundry_projects,
        Network "Network",
        Security "Security",
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct FoundryRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    pub sku: Option<String>,
    pub endpoint: Option<String>,
    pub custom_subdomain: Option<String>,
    pub created: Option<String>,
    pub allow_project_management: Option<bool>,
    pub default_project: Option<String>,
    pub public_network_access: Option<String>,
    pub acl_default_action: Option<String>,
    pub acl_bypass: Option<String>,
    pub ip_rules: Vec<String>,
    pub vnet_rule_ids: Vec<String>,
    pub private_endpoint_ids: Vec<String>,
    pub restrict_outbound: Option<bool>,
    pub allowed_fqdns: Vec<String>,
    /// Agent-service subnets (`networkInjections[].subnetArmId`).
    pub injected_subnet_ids: Vec<String>,
    pub disable_local_auth: Option<bool>,
    pub encryption_key_source: Option<String>,
    pub key_vault_uri: Option<String>,
    pub key_name: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub user_owned_storage_ids: Vec<String>,
}

impl FoundryRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<FoundryRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(FoundryRow {
            kind: json::str_at(v, "/kind"),
            sku: json::str_at(v, "/sku/name"),
            endpoint: json::str_at(v, &format!("{}/endpoint", p)),
            custom_subdomain: json::str_at(v, &format!("{}/customSubDomainName", p)),
            created: json::str_at(v, &format!("{}/dateCreated", p)),
            allow_project_management: json::bool_at(v, &format!("{}/allowProjectManagement", p)),
            default_project: json::str_at(v, &format!("{}/defaultProject", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            acl_default_action: json::str_at(v, &format!("{}/networkAcls/defaultAction", p)),
            acl_bypass: json::str_at(v, &format!("{}/networkAcls/bypass", p)),
            ip_rules: json::arr(v, &format!("{}/networkAcls/ipRules", p))
                .iter()
                .filter_map(|r| json::str_at(r, "/value"))
                .collect(),
            vnet_rule_ids: json::ids_at(v, &format!("{}/networkAcls/virtualNetworkRules", p)),
            private_endpoint_ids: json::arr(v, &format!("{}/privateEndpointConnections", p))
                .iter()
                .filter_map(|c| json::arm_id(json::id_at(c, "/properties/privateEndpoint")))
                .collect(),
            restrict_outbound: json::bool_at(v, &format!("{}/restrictOutboundNetworkAccess", p)),
            allowed_fqdns: json::strings_at(v, &format!("{}/allowedFqdnList", p)),
            injected_subnet_ids: json::arr(v, &format!("{}/networkInjections", p))
                .iter()
                .filter_map(|n| json::arm_id(json::str_at(n, "/subnetArmId")))
                .collect(),
            disable_local_auth: json::bool_at(v, &format!("{}/disableLocalAuth", p)),
            encryption_key_source: json::str_at(v, &format!("{}/encryption/keySource", p)),
            key_vault_uri: json::str_at(v, &format!("{}/encryption/keyVaultProperties/keyVaultUri", p)),
            key_name: json::str_at(v, &format!("{}/encryption/keyVaultProperties/keyName", p)),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            user_owned_storage_ids: json::arr(v, &format!("{}/userOwnedStorage", p))
                .iter()
                .filter_map(|s| json::arm_id(json::str_at(s, "/resourceId")))
                .collect(),
            base,
        })
    }

    /// What the `kind` means to a reader: a Foundry resource is an
    /// `AIServices` account that can hold projects.
    pub fn kind_label(&self) -> String {
        match (self.kind.as_deref(), self.allow_project_management) {
            (Some("AIServices"), Some(true)) => "Foundry resource (AIServices)".into(),
            (Some("AIServices"), _) => "AI Services (AIServices)".into(),
            (Some("OpenAI"), _) => "Azure OpenAI (OpenAI)".into(),
            (Some(k), _) => k.to_string(),
            (None, _) => "-".into(),
        }
    }

    /// Whether the account can hold projects — the Projects section's
    /// only precondition (no call is made otherwise).
    pub fn holds_projects(&self) -> bool {
        self.allow_project_management == Some(true)
    }

    /// `-n {account} -g {rg} --subscription {sub}`: every
    /// `az cognitiveservices account …` command takes the name form; none
    /// takes `--ids` (the account name argument has no `id_part` in the
    /// CLI's parameter table, checked 2026-09-24).
    fn name_args(&self) -> Option<String> {
        Some(format!(
            "-n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

impl Resource for FoundryRow {
    arm_row!("AI account");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&FOUNDRY_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.kind.clone()),
            self.kind_label(),
            json::opt(self.custom_subdomain.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let projects = if self.holds_projects() {
            match &self.default_project {
                Some(d) => format!("yes · default {}", d),
                None => "yes".into(),
            }
        } else {
            json::yes_no(self.allow_project_management)
        };
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Kind".into(), self.kind_label()),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Projects".into(), projects),
            ("Custom subdomain".into(), json::opt(self.custom_subdomain.clone())),
            ("Endpoint".into(), json::opt(self.endpoint.clone())),
            ("Created".into(), json::time(self.created.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for s in &self.vnet_rule_ids {
            v.push((format!("Network rule subnet {}", name_of_id(s)), s.clone()));
        }
        for s in &self.injected_subnet_ids {
            v.push((format!("Agent subnet {}", name_of_id(s)), s.clone()));
        }
        for pe in &self.private_endpoint_ids {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        for st in &self.user_owned_storage_ids {
            v.push((format!("Storage {}", name_of_id(st)), st.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az cognitiveservices account show {}", self.name_args()?))
    }
}

/// Body lines for one section of an account row.
pub fn foundry_section_lines(
    r: &FoundryRow,
    section: FoundryDetailSection,
    deployments: Option<&Lazy<Vec<Value>>>,
    projects: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        FoundryDetailSection::Overview => overview_rows(r),
        FoundryDetailSection::Deployments => {
            lazy_list_rows(deployments, "Deployments", |items| deployment_rows(items, r))
        }
        FoundryDetailSection::Projects => {
            if !r.holds_projects() {
                return vec![
                    (String::new(), "Not a Foundry resource: project management is off".into()),
                    (String::new(), format!("· kind {}", r.kind_label())),
                ];
            }
            lazy_list_rows(projects, "Projects", |items| project_rows(items, r))
        }
        FoundryDetailSection::Network => {
            let mut lines = vec![
                ("Public network access".into(), json::opt(r.public_network_access.clone())),
                ("Default action".into(), json::opt(r.acl_default_action.clone())),
                ("Bypass".into(), json::opt(r.acl_bypass.clone())),
                ("IP rules".into(), json::join(&r.ip_rules)),
                ("Restrict outbound".into(), json::yes_no(r.restrict_outbound)),
            ];
            if r.restrict_outbound == Some(true) {
                lines.push(("Allowed FQDNs".into(), json::join(&r.allowed_fqdns)));
            }
            for s in &r.vnet_rule_ids {
                lines.push((format!("VNet rule · {}", name_of_id(s)), s.clone()));
            }
            for s in &r.injected_subnet_ids {
                lines.push((format!("Agent subnet · {}", name_of_id(s)), s.clone()));
            }
            for pe in &r.private_endpoint_ids {
                lines.push((format!("Private endpoint · {}", name_of_id(pe)), pe.clone()));
            }
            lines
        }
        FoundryDetailSection::Security => {
            let key_auth = match r.disable_local_auth {
                Some(true) => "disabled (Entra ID only)".to_string(),
                Some(false) => "enabled".to_string(),
                None => "-".to_string(),
            };
            let mut lines = vec![
                ("Key auth".into(), key_auth),
                ("Identity".into(), json::opt(r.identity_type.clone())),
                ("Encryption".into(), json::opt(r.encryption_key_source.clone())),
            ];
            if r.key_vault_uri.is_some() || r.key_name.is_some() {
                lines.push(("  Key vault".into(), json::opt(r.key_vault_uri.clone())));
                lines.push(("  Key".into(), json::opt(r.key_name.clone())));
            }
            for id in &r.user_identity_ids {
                lines.push((format!("User identity · {}", name_of_id(id)), id.clone()));
            }
            lines.push((String::new(), String::new()));
            lines.push((String::new(), NEVER_KEYS.into()));
            lines
        }
        FoundryDetailSection::Related => related_rows(r),
        FoundryDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// A deployment's capacity in its SKU's unit: provisioned SKUs count PTUs;
/// the rest are the SKU's own capacity number (the rate limits line says
/// what it buys).
fn capacity_text(sku: &str, capacity: Option<i64>) -> String {
    match capacity {
        Some(c) if sku.contains("Provisioned") => format!("{} PTU", c),
        Some(c) => format!("capacity {}", c),
        None => "capacity -".into(),
    }
}

/// `rateLimits` as `request 50 / 10 s · token 50000 / 60 s`.
fn rate_limits_text(d: &Value) -> String {
    let limits: Vec<String> = json::arr(d, "/properties/rateLimits")
        .iter()
        .map(|l| {
            format!(
                "{} {} / {} s",
                json::text(l, "/key"),
                json::text(l, "/count"),
                json::text(l, "/renewalPeriod")
            )
        })
        .collect();
    json::join(&limits)
}

/// The Deployments section body from the ARM `deployments` list.
pub fn deployment_rows(items: &[Value], r: &FoundryRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No model deployments".into()));
    }
    for d in items {
        let p = "/properties";
        let sku = json::text(d, "/sku/name");
        let model = format!(
            "{} {} · {}",
            json::text(d, &format!("{}/model/name", p)),
            json::text(d, &format!("{}/model/version", p)),
            json::text(d, &format!("{}/model/format", p)),
        );
        let state = match (
            json::str_at(d, &format!("{}/provisioningState", p)),
            json::str_at(d, &format!("{}/deploymentState", p)),
        ) {
            (Some(ps), Some(ds)) if ps == "Succeeded" => ds.to_lowercase(),
            (Some(ps), _) => ps.to_lowercase(),
            (None, Some(ds)) => ds.to_lowercase(),
            (None, None) => "-".into(),
        };
        lines.push((String::new(), String::new()));
        lines.push((json::text(d, "/name"), String::new()));
        lines.push(("  Model".into(), model));
        lines.push(("  SKU".into(), format!("{} · {}", sku, capacity_text(&sku, json::int_at(d, "/sku/capacity")))));
        lines.push(("  Rate limits".into(), rate_limits_text(d)));
        lines.push(("  State".into(), state));
        lines.push(("  Upgrade".into(), json::text(d, &format!("{}/versionUpgradeOption", p))));
        lines.push(("  RAI policy".into(), json::text(d, &format!("{}/raiPolicyName", p))));
        if let Some(spill) = json::str_at(d, &format!("{}/spilloverDeploymentName", p)) {
            lines.push(("  Spillover to".into(), spill));
        }
        lines.push(("  Id".into(), json::text(d, "/id")));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az cognitiveservices account deployment list {}", r.name_args().unwrap_or_default()),
    ));
    lines
}

/// The Projects section body from the ARM `projects` list.
pub fn project_rows(items: &[Value], r: &FoundryRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No projects".into()));
    }
    for pr in items {
        let p = "/properties";
        let id = json::text(pr, "/id");
        let name = name_of_id(&id).to_string();
        let default = json::bool_at(pr, &format!("{}/isDefault", p)) == Some(true)
            || r.default_project.as_deref() == Some(name.as_str());
        lines.push((String::new(), String::new()));
        lines.push((if default { format!("{} (default)", name) } else { name }, String::new()));
        lines.push(("  Display name".into(), json::text(pr, &format!("{}/displayName", p))));
        lines.push(("  Description".into(), json::text(pr, &format!("{}/description", p))));
        lines.push((
            "  State".into(),
            json::str_at(pr, &format!("{}/provisioningState", p))
                .map(|s| s.to_lowercase())
                .unwrap_or_else(|| "-".into()),
        ));
        lines.push(("  Identity".into(), json::text(pr, "/identity/type")));
        lines.push(("  Id".into(), id));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az cognitiveservices account project list {}", r.name_args().unwrap_or_default()),
    ));
    lines
}

/// The ARM path of an account's child list (`deployments`, `projects`).
pub fn child_path(account_id: &str, kind: &str) -> String {
    format!("{}/{}", account_id.trim_end_matches('/'), kind)
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct FoundryService {
    scope: Scope,
}

impl FoundryService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for FoundryService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Foundry
    }

    fn name(&self) -> &str {
        "Foundry"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(ACCOUNTS_PATH, FOUNDRY_API_VERSION)
            .await?
            .iter()
            .filter_map(|v| FoundryRow::from_json(v, tenant))
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
            .stream(ACCOUNTS_PATH, FOUNDRY_API_VERSION, &[], service_type, "Listing AI accounts…", &event_tx, |page| {
                page.iter()
                    .filter_map(|v| FoundryRow::from_json(v, tenant.as_deref()))
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, FOUNDRY_API_VERSION).await?;
        FoundryRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg";

    fn account_json(kind: &str, projects: bool) -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.CognitiveServices/accounts/ai-prod", RG),
            "name": "ai-prod",
            "location": "swedencentral",
            "kind": kind,
            "sku": {"name": "S0"},
            "identity": {
                "type": "SystemAssigned, UserAssigned",
                "userAssignedIdentities": {
                    format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-ai", RG): {}
                }
            },
            "properties": {
                "provisioningState": "Succeeded",
                "endpoint": "https://ai-prod.cognitiveservices.azure.com/",
                "customSubDomainName": "ai-prod",
                "dateCreated": "2026-03-01T10:00:00Z",
                "allowProjectManagement": projects,
                "defaultProject": "proj-a",
                "publicNetworkAccess": "Disabled",
                "disableLocalAuth": true,
                "restrictOutboundNetworkAccess": true,
                "allowedFqdnList": ["api.example.com"],
                "networkAcls": {"defaultAction": "Deny", "ipRules": [{"value": "1.2.3.4"}],
                    "virtualNetworkRules": [{"id": format!("{}/providers/Microsoft.Network/virtualNetworks/v/subnets/s", RG)}]},
                "networkInjections": [{"scenario": "agent", "subnetArmId": format!("{}/providers/Microsoft.Network/virtualNetworks/v/subnets/agents", RG)}],
                "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-ai", RG)}}}],
                "encryption": {"keySource": "Microsoft.KeyVault", "keyVaultProperties": {"keyName": "cmk", "keyVaultUri": "https://kv.example/"}}
            }
        })
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = FOUNDRY_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Deployments", "Projects", "Network", "Security", "Related", "Tags"]);
    }

    #[test]
    fn account_row_reads_kind_network_security_and_the_name_form_command() {
        let row = FoundryRow::from_json(&account_json("AIServices", true), Some("t-1")).unwrap();
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.kind_label(), "Foundry resource (AIServices)");
        assert!(row.details().iter().any(|(k, v)| k == "Projects" && v == "yes · default proj-a"));
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az cognitiveservices account show -n ai-prod -g rg --subscription 0000")
        );
        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        for want in ["Network rule subnet s", "Agent subnet agents", "Private endpoint pe-ai", "Identity id-ai"] {
            assert!(related.iter().any(|l| l == want), "{want} in {related:?}");
        }
        let net = foundry_section_lines(&row, FoundryDetailSection::Network, None, None);
        assert!(net.iter().any(|(k, v)| k == "Allowed FQDNs" && v == "api.example.com"));
        let sec = foundry_section_lines(&row, FoundryDetailSection::Security, None, None);
        assert_eq!(sec[0], ("Key auth".to_string(), "disabled (Entra ID only)".to_string()));
        assert!(sec.iter().any(|(k, v)| k == "  Key" && v == "cmk"));
        assert_eq!(sec.last().unwrap().1, NEVER_KEYS);

        let openai = FoundryRow::from_json(&account_json("OpenAI", false), None).unwrap();
        assert_eq!(openai.kind_label(), "Azure OpenAI (OpenAI)");
        assert!(!openai.holds_projects());
    }

    #[test]
    fn deployments_show_model_sku_capacity_and_rate_limits() {
        let row = FoundryRow::from_json(&account_json("AIServices", true), None).unwrap();
        let items = vec![
            serde_json::json!({
                "id": format!("{}/providers/Microsoft.CognitiveServices/accounts/ai-prod/deployments/gpt", RG),
                "name": "gpt",
                "sku": {"name": "GlobalStandard", "capacity": 50},
                "properties": {
                    "provisioningState": "Succeeded", "deploymentState": "Running",
                    "model": {"format": "OpenAI", "name": "gpt-4o", "version": "2024-11-20"},
                    "versionUpgradeOption": "OnceNewDefaultVersionAvailable",
                    "raiPolicyName": "Microsoft.DefaultV2",
                    "rateLimits": [{"key": "request", "renewalPeriod": 10, "count": 50},
                                   {"key": "token", "renewalPeriod": 60, "count": 50000}]
                }
            }),
            serde_json::json!({
                "name": "ptu",
                "sku": {"name": "ProvisionedManaged", "capacity": 100},
                "properties": {"provisioningState": "Creating", "model": {"format": "OpenAI", "name": "gpt-4.1", "version": "1"}}
            }),
        ];
        let lines = foundry_section_lines(&row, FoundryDetailSection::Deployments, Some(&Lazy::Loaded(items)), None);
        let get = |k: &str| lines.iter().filter(|(key, _)| key == k).map(|(_, v)| v.as_str()).collect::<Vec<_>>();
        assert_eq!(get("  Model"), ["gpt-4o 2024-11-20 · OpenAI", "gpt-4.1 1 · OpenAI"]);
        assert_eq!(get("  SKU"), ["GlobalStandard · capacity 50", "ProvisionedManaged · 100 PTU"]);
        assert_eq!(get("  Rate limits")[0], "request 50 / 10 s, token 50000 / 60 s");
        assert_eq!(get("  State"), ["running", "creating"]);
        assert!(lines.last().unwrap().1.starts_with("az cognitiveservices account deployment list -n ai-prod -g rg"));
        assert!(!lines.iter().any(|(k, _)| k.to_lowercase().contains("key ")));
    }

    #[test]
    fn projects_are_fetched_only_for_foundry_resources() {
        let openai = FoundryRow::from_json(&account_json("OpenAI", false), None).unwrap();
        let lines = foundry_section_lines(&openai, FoundryDetailSection::Projects, None, None);
        assert!(lines[0].1.starts_with("Not a Foundry resource"));

        let row = FoundryRow::from_json(&account_json("AIServices", true), None).unwrap();
        let items = vec![serde_json::json!({
            "id": format!("{}/providers/Microsoft.CognitiveServices/accounts/ai-prod/projects/proj-a", RG),
            "name": "ai-prod/proj-a",
            "identity": {"type": "SystemAssigned"},
            "properties": {"provisioningState": "Succeeded", "displayName": "Project A", "description": "demo"}
        })];
        let lines = foundry_section_lines(&row, FoundryDetailSection::Projects, None, Some(&Lazy::Loaded(items)));
        assert!(lines.iter().any(|(k, v)| k == "proj-a (default)" && v.is_empty()));
        assert!(lines.iter().any(|(k, v)| k == "  Display name" && v == "Project A"));
        assert!(lines.last().unwrap().1.starts_with("az cognitiveservices account project list -n ai-prod"));
        let loading = foundry_section_lines(&row, FoundryDetailSection::Projects, None, Some(&Lazy::Loading));
        assert_eq!(loading[0].1, "Loading…");
        assert_eq!(
            child_path(&row.base.id, "deployments"),
            format!("{}/providers/Microsoft.CognitiveServices/accounts/ai-prod/deployments", RG)
        );
    }
}
