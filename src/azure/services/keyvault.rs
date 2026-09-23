//! The Key Vault service (ticket 06): vault metadata from the
//! subscription-wide list; secret and key **names** as lazy sections
//! through ARM's `Secrets_List` / `Keys_List`, which cannot return a value
//! by construction. No certificates: ARM has no list for them, and the
//! data plane is deliberately not touched.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
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

pub const VAULTS_API_VERSION: &str = "2024-11-01";
/// The `secrets` / `keys` lists live in a newer stable version.
pub const VAULT_NAMES_API_VERSION: &str = "2026-05-15";
const VAULTS_PATH: &str = "/providers/Microsoft.KeyVault/vaults";

const NEVER_VALUES: &str = "names and attributes from ARM; values are never fetched";

crate::sections! {
    pub enum VaultDetailSection,
    pub static VAULT_SECTIONS = [
        Overview "Overview",
        Access "Access",
        Network "Network",
        Secrets "Secrets" => crate::app::App::trigger_vault_secrets,
        Keys "Keys" => crate::app::App::trigger_vault_keys,
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub tenant_id: String,
    pub object_id: String,
    pub application_id: Option<String>,
    pub keys: Vec<String>,
    pub secrets: Vec<String>,
    pub certificates: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VaultRow {
    pub base: ArmBase,
    pub vault_uri: Option<String>,
    pub sku: Option<String>,
    pub vault_tenant: Option<String>,
    pub rbac_authorization: Option<bool>,
    pub soft_delete: Option<bool>,
    pub retention_days: Option<i64>,
    pub purge_protection: Option<bool>,
    pub for_deployment: Option<bool>,
    pub for_disk_encryption: Option<bool>,
    pub for_template_deployment: Option<bool>,
    pub public_network_access: Option<String>,
    pub acl_default_action: Option<String>,
    pub acl_bypass: Option<String>,
    pub ip_rules: Vec<String>,
    pub vnet_rule_ids: Vec<String>,
    pub private_endpoint_ids: Vec<String>,
    pub access_policies: Vec<AccessPolicy>,
}

impl VaultRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<VaultRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let policies = json::arr(v, &format!("{}/accessPolicies", p))
            .iter()
            .map(|ap| AccessPolicy {
                tenant_id: json::text(ap, "/tenantId"),
                object_id: json::text(ap, "/objectId"),
                application_id: json::str_at(ap, "/applicationId"),
                keys: json::strings_at(ap, "/permissions/keys"),
                secrets: json::strings_at(ap, "/permissions/secrets"),
                certificates: json::strings_at(ap, "/permissions/certificates"),
            })
            .collect();
        Some(VaultRow {
            vault_uri: json::str_at(v, &format!("{}/vaultUri", p)),
            sku: json::str_at(v, &format!("{}/sku/name", p)),
            vault_tenant: json::str_at(v, &format!("{}/tenantId", p)),
            rbac_authorization: json::bool_at(v, &format!("{}/enableRbacAuthorization", p)),
            soft_delete: json::bool_at(v, &format!("{}/enableSoftDelete", p)),
            retention_days: json::int_at(v, &format!("{}/softDeleteRetentionInDays", p)),
            purge_protection: json::bool_at(v, &format!("{}/enablePurgeProtection", p)),
            for_deployment: json::bool_at(v, &format!("{}/enabledForDeployment", p)),
            for_disk_encryption: json::bool_at(v, &format!("{}/enabledForDiskEncryption", p)),
            for_template_deployment: json::bool_at(v, &format!("{}/enabledForTemplateDeployment", p)),
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
            access_policies: policies,
            base,
        })
    }

    fn access_model(&self) -> &'static str {
        match self.rbac_authorization {
            Some(true) => "Azure RBAC",
            _ => "access policies",
        }
    }
}

impl Resource for VaultRow {
    arm_row!("Key Vault");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&VAULT_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.vault_uri.clone()),
            self.access_model(),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Vault URI".into(), json::opt(self.vault_uri.clone())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Tenant".into(), json::opt(self.vault_tenant.clone())),
            ("Access model".into(), self.access_model().into()),
            (
                "Soft delete".into(),
                match (self.soft_delete, self.retention_days) {
                    (Some(true), Some(d)) => format!("yes · {} days", d),
                    (b, _) => json::yes_no(b),
                },
            ),
            ("Purge protection".into(), json::yes_no(self.purge_protection)),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("Enabled for deployment".into(), json::yes_no(self.for_deployment)),
            ("Enabled for disk encryption".into(), json::yes_no(self.for_disk_encryption)),
            ("Enabled for template deployment".into(), json::yes_no(self.for_template_deployment)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for s in &self.vnet_rule_ids {
            v.push((format!("Network rule subnet {}", name_of_id(s)), s.clone()));
        }
        for pe in &self.private_endpoint_ids {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az keyvault show --ids {}", shell_quote(&self.base.id)))
    }
}

/// Body lines for one section of a vault row.
pub fn vault_section_lines(
    r: &VaultRow,
    section: VaultDetailSection,
    secrets: Option<&Lazy<Vec<Value>>>,
    keys: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        VaultDetailSection::Overview => overview_rows(r),
        VaultDetailSection::Access => {
            let mut lines = vec![("Access model".into(), r.access_model().into())];
            if r.rbac_authorization == Some(true) {
                lines.push((String::new(), "Permissions are Azure role assignments on the vault".into()));
                if !r.access_policies.is_empty() {
                    lines.push((String::new(), String::new()));
                    lines.push((
                        "Access policies".into(),
                        format!("{} (inactive under RBAC)", r.access_policies.len()),
                    ));
                }
                return lines;
            }
            if r.access_policies.is_empty() {
                lines.push((String::new(), "No access policies".into()));
                return lines;
            }
            for ap in &r.access_policies {
                lines.push((String::new(), String::new()));
                let who = match &ap.application_id {
                    Some(app) => format!("{} · app {}", ap.object_id, app),
                    None => ap.object_id.clone(),
                };
                lines.push(("Principal".into(), who));
                lines.push(("  Tenant".into(), ap.tenant_id.clone()));
                lines.push(("  Keys".into(), json::join(&ap.keys)));
                lines.push(("  Secrets".into(), json::join(&ap.secrets)));
                lines.push(("  Certificates".into(), json::join(&ap.certificates)));
            }
            lines
        }
        VaultDetailSection::Network => {
            let mut lines = vec![
                ("Public network access".into(), json::opt(r.public_network_access.clone())),
                ("Default action".into(), json::opt(r.acl_default_action.clone())),
                ("Bypass".into(), json::opt(r.acl_bypass.clone())),
                ("IP rules".into(), json::join(&r.ip_rules)),
            ];
            for s in &r.vnet_rule_ids {
                lines.push((format!("VNet rule · {}", name_of_id(s)), s.clone()));
            }
            for pe in &r.private_endpoint_ids {
                lines.push((format!("Private endpoint · {}", name_of_id(pe)), pe.clone()));
            }
            lines
        }
        VaultDetailSection::Secrets => {
            lazy_list_rows(secrets, "Secrets", |items| secret_rows(items, &r.base.name))
        }
        VaultDetailSection::Keys => lazy_list_rows(keys, "Keys", |items| key_rows(items, &r.base.name)),
        VaultDetailSection::Related => related_rows(r),
        VaultDetailSection::Tags => tag_rows(r.tags()),
    }
}

fn attribute_line(v: &Value) -> String {
    let a = "/properties/attributes";
    format!(
        "enabled {} · updated {} · expires {}",
        json::yes_no(json::bool_at(v, &format!("{}/enabled", a))),
        json::unix_or_time(v.pointer(&format!("{}/updated", a))),
        json::unix_or_time(v.pointer(&format!("{}/exp", a))),
    )
}

/// The Secrets section body from the ARM `secrets` list.
pub fn secret_rows(items: &[Value], vault: &str) -> Vec<(String, String)> {
    let mut lines = vec![(String::new(), NEVER_VALUES.into()), (String::new(), String::new())];
    if items.is_empty() {
        lines.push((String::new(), "No secrets".into()));
    } else {
        for s in items {
            let mut val = attribute_line(s);
            if let Some(ct) = json::str_at(s, "/properties/contentType") {
                val = format!("{} · {}", ct, val);
            }
            lines.push((json::text(s, "/name"), val));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az keyvault secret list --vault-name {}", shell_quote(vault)),
    ));
    lines
}

/// The Keys section body from the ARM `keys` list.
pub fn key_rows(items: &[Value], vault: &str) -> Vec<(String, String)> {
    let mut lines = vec![(String::new(), NEVER_VALUES.into()), (String::new(), String::new())];
    if items.is_empty() {
        lines.push((String::new(), "No keys".into()));
    } else {
        for k in items {
            let p = "/properties";
            let kind = match (json::str_at(k, &format!("{}/curveName", p)), json::int_at(k, &format!("{}/keySize", p))) {
                (Some(curve), _) => format!("{} {}", json::text(k, &format!("{}/kty", p)), curve),
                (None, Some(size)) => format!("{} {}", json::text(k, &format!("{}/kty", p)), size),
                (None, None) => json::text(k, &format!("{}/kty", p)),
            };
            let ops = json::strings_at(k, &format!("{}/keyOps", p));
            lines.push((
                json::text(k, "/name"),
                format!(
                    "{} · ops {} · {}",
                    kind,
                    if ops.is_empty() { "-".to_string() } else { ops.join("/") },
                    attribute_line(k)
                ),
            ));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az keyvault key list --vault-name {}", shell_quote(vault)),
    ));
    lines
}

/// The ARM path of a vault's secret or key names list.
pub fn names_path(vault_id: &str, kind: &str) -> String {
    format!("{}/{}", vault_id.trim_end_matches('/'), kind)
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct KeyVaultService {
    scope: Scope,
}

impl KeyVaultService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for KeyVaultService {
    fn service_type(&self) -> ServiceType {
        ServiceType::KeyVault
    }

    fn name(&self) -> &str {
        "Key Vault"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(VAULTS_PATH, VAULTS_API_VERSION)
            .await?
            .iter()
            .filter_map(|v| VaultRow::from_json(v, tenant))
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
            .stream(VAULTS_PATH, VAULTS_API_VERSION, &[], service_type, "Listing key vaults…", &event_tx, |page| {
                page.iter()
                    .filter_map(|v| VaultRow::from_json(v, tenant.as_deref()))
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, VAULTS_API_VERSION).await?;
        VaultRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_json(rbac: bool) -> Value {
        serde_json::json!({
            "id": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-prod",
            "name": "kv-prod",
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "vaultUri": "https://kv-prod.vault.azure.net/",
                "sku": {"family": "A", "name": "standard"},
                "tenantId": "t-1",
                "enableRbacAuthorization": rbac,
                "enableSoftDelete": true,
                "softDeleteRetentionInDays": 90,
                "enablePurgeProtection": true,
                "publicNetworkAccess": "Enabled",
                "networkAcls": {"defaultAction": "Deny", "bypass": "AzureServices", "ipRules": [{"value": "1.2.3.4/32"}],
                    "virtualNetworkRules": [{"id": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"}]},
                "accessPolicies": [{"tenantId": "t-1", "objectId": "obj-1", "permissions": {"keys": ["get"], "secrets": ["get", "list"], "certificates": []}}]
            }
        })
    }

    #[test]
    fn vault_row_reads_the_access_model_and_network_rules() {
        let row = VaultRow::from_json(&vault_json(false), Some("t-1")).unwrap();
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.access_model(), "access policies");
        let access = vault_section_lines(&row, VaultDetailSection::Access, None, None);
        assert!(access.iter().any(|(k, v)| k == "Principal" && v == "obj-1"));
        assert!(access.iter().any(|(k, v)| k == "  Secrets" && v == "get, list"));
        assert!(access.iter().any(|(k, v)| k == "  Certificates" && v == "-"));
        let net = vault_section_lines(&row, VaultDetailSection::Network, None, None);
        assert_eq!(net[1], ("Default action".to_string(), "Deny".to_string()));
        assert!(net.iter().any(|(k, _)| k == "VNet rule · s"));
        assert!(row.related().iter().any(|(l, _)| l == "Network rule subnet s"));
        assert!(row.details().iter().any(|(k, v)| k == "Soft delete" && v == "yes · 90 days"));

        let rbac = VaultRow::from_json(&vault_json(true), None).unwrap();
        let access = vault_section_lines(&rbac, VaultDetailSection::Access, None, None);
        assert_eq!(access[0].1, "Azure RBAC");
        assert!(access.iter().any(|(k, v)| k == "Access policies" && v == "1 (inactive under RBAC)"));
    }

    #[test]
    fn secret_and_key_sections_never_show_a_value_and_name_the_read_commands() {
        let row = VaultRow::from_json(&vault_json(true), None).unwrap();
        let secrets = vec![serde_json::json!({
            "name": "db-password",
            "properties": {"contentType": "text/plain", "attributes": {"enabled": true, "updated": 1_700_000_000, "exp": 1_800_000_000}}
        })];
        let lines = vault_section_lines(&row, VaultDetailSection::Secrets, Some(&Lazy::Loaded(secrets)), None);
        assert_eq!(lines[0].1, NEVER_VALUES);
        assert_eq!(lines[2].0, "db-password");
        assert_eq!(lines[2].1, "text/plain · enabled yes · updated 2023-11-14 22:13 · expires 2027-01-15 08:00");
        assert!(lines.last().unwrap().1.contains("az keyvault secret list --vault-name kv-prod"));
        // The list body carries no `value` field and the section never invents one.
        assert!(!lines.iter().any(|(k, _)| k.eq_ignore_ascii_case("value")));

        let keys = vec![serde_json::json!({
            "name": "signing",
            "properties": {"kty": "EC", "curveName": "P-256", "keyOps": ["sign", "verify"], "attributes": {"enabled": true}}
        })];
        let lines = vault_section_lines(&row, VaultDetailSection::Keys, None, Some(&Lazy::Loaded(keys)));
        assert_eq!(lines[2].0, "signing");
        assert!(lines[2].1.starts_with("EC P-256 · ops sign/verify · enabled yes"));
        let failed = vault_section_lines(&row, VaultDetailSection::Keys, None, Some(&Lazy::Error("403".into())));
        assert!(failed.last().unwrap().1.contains("403"));
        assert_eq!(
            names_path("/subscriptions/0/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv", "secrets"),
            "/subscriptions/0/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv/secrets"
        );
    }
}
