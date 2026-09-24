//! The SQL service (issue #5): Azure SQL logical servers, one
//! subscription-wide list. There is no subscription-wide database list,
//! so a server's databases and firewall rules are lazy sections, one call
//! per server each (CLAUDE.md: a sub-tab is one subscription-wide list).
//!
//! Servers carry no `provisioningState`; their `state` (`Ready`) is the
//! runtime rung. `administratorLoginPassword` is write-only in the API and
//! has no field here, so it can never be rendered. The server FQDN is a
//! data-plane host, shown as text and never requested.

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
pub const SQL_API_VERSION: &str = "2025-01-01";
const SERVERS_PATH: &str = "/providers/Microsoft.Sql/servers";

/// The rule ARM creates for "Allow Azure services and resources to access
/// this server": 0.0.0.0–0.0.0.0, which admits every Azure tenant.
const ALLOW_AZURE_RULE: &str = "AllowAllWindowsAzureIps";

crate::sections! {
    pub enum SqlServerDetailSection,
    pub static SQL_SERVER_SECTIONS = [
        Overview "Overview",
        Security "Security",
        Databases "Databases" => crate::app::App::trigger_sql_databases,
        Firewall "Firewall" => crate::app::App::trigger_sql_firewall,
        Networking "Networking",
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct SqlServerRow {
    pub base: ArmBase,
    pub version: Option<String>,
    pub state: Option<String>,
    pub fqdn: Option<String>,
    pub admin_login: Option<String>,
    pub entra_admin: Option<String>,
    pub entra_admin_type: Option<String>,
    pub entra_only: Option<bool>,
    pub min_tls: Option<String>,
    pub public_network_access: Option<String>,
    pub restrict_outbound: Option<String>,
    pub ipv6: Option<String>,
    /// A Key Vault key URL (customer-managed TDE), not an ARM id.
    pub key_id: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub primary_identity_id: Option<String>,
    pub private_endpoint_ids: Vec<String>,
}

impl SqlServerRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<SqlServerRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let a = format!("{}/administrators", p);
        Some(SqlServerRow {
            version: json::str_at(v, &format!("{}/version", p)),
            state: json::str_at(v, &format!("{}/state", p)),
            fqdn: json::str_at(v, &format!("{}/fullyQualifiedDomainName", p)),
            admin_login: json::str_at(v, &format!("{}/administratorLogin", p)),
            entra_admin: json::str_at(v, &format!("{}/login", a)),
            entra_admin_type: json::str_at(v, &format!("{}/principalType", a)),
            entra_only: json::bool_at(v, &format!("{}/azureADOnlyAuthentication", a)),
            min_tls: json::str_at(v, &format!("{}/minimalTlsVersion", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            restrict_outbound: json::str_at(v, &format!("{}/restrictOutboundNetworkAccess", p)),
            ipv6: json::str_at(v, &format!("{}/isIPv6Enabled", p)),
            key_id: json::str_at(v, &format!("{}/keyId", p)).filter(|k| !k.is_empty()),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            primary_identity_id: json::arm_id(json::str_at(v, &format!("{}/primaryUserAssignedIdentityId", p))),
            private_endpoint_ids: json::arr(v, &format!("{}/privateEndpointConnections", p))
                .iter()
                .filter_map(|c| json::arm_id(json::id_at(c, "/properties/privateEndpoint")))
                .collect(),
            base,
        })
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "ready" => ResourceState::Available,
                "disabled" => ResourceState::Unavailable,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// `-s {server} -g {rg} --subscription {sub}`: what `az sql db list`
    /// and `az sql server firewall-rule list` take.
    fn server_args(&self) -> Option<String> {
        Some(format!(
            "-s {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

impl Resource for SqlServerRow {
    arm_row!("SQL Server");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SQL_SERVER_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.fqdn.clone()),
            json::opt(self.entra_admin.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("State".into(), json::opt(self.state.clone())),
            ("Version".into(), json::opt(self.version.clone())),
            ("FQDN".into(), json::opt(self.fqdn.clone())),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("Min TLS".into(), json::opt(self.min_tls.clone())),
            ("Entra-only auth".into(), json::yes_no(self.entra_only)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for pe in &self.private_endpoint_ids {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        let mut identities = self.user_identity_ids.clone();
        if let Some(primary) = &self.primary_identity_id {
            if !identities.iter().any(|i| i.eq_ignore_ascii_case(primary)) {
                identities.push(primary.clone());
            }
        }
        for id in &identities {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az sql server show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn sql_server_section_lines(
    r: &SqlServerRow,
    section: SqlServerDetailSection,
    databases: Option<&Lazy<Vec<Value>>>,
    firewall: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        SqlServerDetailSection::Overview => overview_rows(r),
        SqlServerDetailSection::Security => {
            let entra = match (&r.entra_admin, &r.entra_admin_type) {
                (Some(login), Some(kind)) => format!("{} ({})", login, kind),
                (login, _) => json::opt(login.clone()),
            };
            let mut lines = vec![
                ("Entra admin".into(), entra),
                ("Entra-only auth".into(), json::yes_no(r.entra_only)),
                ("SQL admin login".into(), json::opt(r.admin_login.clone())),
                ("Min TLS".into(), json::opt(r.min_tls.clone())),
                (
                    "TDE key".into(),
                    if r.key_id.is_some() { "customer-managed" } else { "service-managed" }.into(),
                ),
            ];
            if let Some(k) = &r.key_id {
                lines.push(("  Key".into(), k.clone()));
            }
            lines.push(("Identity".into(), json::opt(r.identity_type.clone())));
            if let Some(primary) = &r.primary_identity_id {
                lines.push((format!("Primary identity · {}", name_of_id(primary)), primary.clone()));
            }
            lines
        }
        SqlServerDetailSection::Databases => {
            lazy_list_rows(databases, "Databases", |items| database_rows(items, r))
        }
        SqlServerDetailSection::Firewall => lazy_list_rows(firewall, "Firewall", |items| firewall_rows(items, r)),
        SqlServerDetailSection::Networking => {
            let mut lines = vec![
                ("Public network access".into(), json::opt(r.public_network_access.clone())),
                ("Restrict outbound".into(), json::opt(r.restrict_outbound.clone())),
                ("IPv6".into(), json::opt(r.ipv6.clone())),
            ];
            if r.private_endpoint_ids.is_empty() {
                lines.push(("Private endpoints".into(), "-".into()));
            }
            for pe in &r.private_endpoint_ids {
                lines.push((format!("Private endpoint · {}", name_of_id(pe)), pe.clone()));
            }
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "· IP rules are in Firewall".into()));
            lines
        }
        SqlServerDetailSection::Related => related_rows(r),
        SqlServerDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// Bytes as GB, the unit SQL sizes are sold in.
fn gb(bytes: Option<i64>) -> String {
    match bytes {
        Some(b) => format!("{} GB", b / (1024 * 1024 * 1024)),
        None => "-".into(),
    }
}

/// The Databases section body from `GET {server}/databases`. `master` is
/// a system database: listed last, dimmed.
pub fn database_rows(items: &[Value], r: &SqlServerRow) -> Vec<(String, String)> {
    let is_system = |d: &Value| {
        json::str_at(d, "/kind").is_some_and(|k| k.contains("system")) || json::text(d, "/name") == "master"
    };
    let ordered: Vec<&Value> = items.iter().filter(|d| !is_system(d)).collect();
    let system: Vec<&Value> = items.iter().filter(|d| is_system(d)).collect();
    let mut lines = Vec::new();
    if ordered.is_empty() {
        lines.push((String::new(), "No user databases".into()));
    }
    for d in ordered {
        let p = "/properties";
        let sku = format!(
            "{} · {} · capacity {}",
            json::text(d, "/sku/name"),
            json::text(d, "/sku/tier"),
            json::text(d, "/sku/capacity")
        );
        lines.push((String::new(), String::new()));
        lines.push((json::text(d, "/name"), String::new()));
        lines.push(("  SKU".into(), sku));
        lines.push(("  Status".into(), json::text(d, &format!("{}/status", p))));
        lines.push(("  Max size".into(), gb(json::int_at(d, &format!("{}/maxSizeBytes", p)))));
        lines.push(("  Zone redundant".into(), json::yes_no(json::bool_at(d, &format!("{}/zoneRedundant", p)))));
        lines.push(("  Backup redundancy".into(), json::text(d, &format!("{}/currentBackupStorageRedundancy", p))));
        // Serverless: -1 means auto-pause is off.
        if let Some(delay) = json::int_at(d, &format!("{}/autoPauseDelay", p)) {
            let text = if delay < 0 { "off".to_string() } else { format!("after {} min", delay) };
            lines.push(("  Auto-pause".into(), text));
        }
        if let Some(pool) = json::arm_id(json::str_at(d, &format!("{}/elasticPoolId", p))) {
            lines.push((format!("  Elastic pool · {}", name_of_id(&pool)), pool));
        }
        lines.push(("  Id".into(), json::text(d, "/id")));
    }
    if !system.is_empty() {
        lines.push((String::new(), String::new()));
        let names: Vec<String> = system.iter().map(|d| json::text(d, "/name")).collect();
        lines.push((String::new(), format!("· system: {}", names.join(", "))));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az sql db list {}", r.server_args().unwrap_or_default()),
    ));
    lines
}

/// The Firewall section body from `GET {server}/firewallRules`, the
/// allow-all-Azure rule flagged.
pub fn firewall_rows(items: &[Value], r: &SqlServerRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No IP rules".into()));
    }
    for rule in items {
        let name = json::text(rule, "/name");
        let start = json::text(rule, "/properties/startIpAddress");
        let end = json::text(rule, "/properties/endIpAddress");
        let range = if start == end { start } else { format!("{} – {}", start, end) };
        if name == ALLOW_AZURE_RULE {
            lines.push((name, "⚠ allows every Azure service, in any tenant".into()));
        } else {
            lines.push((name, range));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az sql server firewall-rule list {}", r.server_args().unwrap_or_default()),
    ));
    lines
}

/// The ARM path of a server's child list (`databases`, `firewallRules`).
pub fn server_child_path(server_id: &str, child: &str) -> String {
    format!("{}/{}", server_id.trim_end_matches('/'), child)
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct SqlService {
    scope: Scope,
}

impl SqlService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for SqlService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Sql
    }

    fn name(&self) -> &str {
        "SQL"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(SERVERS_PATH, SQL_API_VERSION)
            .await?
            .iter()
            .filter_map(|v| SqlServerRow::from_json(v, tenant))
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
            .stream(SERVERS_PATH, SQL_API_VERSION, &[], service_type, "Listing SQL servers…", &event_tx, |page| {
                page.iter()
                    .filter_map(|v| SqlServerRow::from_json(v, tenant.as_deref()))
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, SQL_API_VERSION).await?;
        SqlServerRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-data";

    fn server_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.Sql/servers/sql-prod", RG),
            "name": "sql-prod",
            "location": "westeurope",
            "kind": "v12.0",
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-sql", RG): {}
            }},
            "properties": {
                "administratorLogin": "sqladmin",
                // Write-only in the API; a body carrying it must not leak.
                "administratorLoginPassword": "hunter2",
                "version": "12.0",
                "state": "Ready",
                "fullyQualifiedDomainName": "sql-prod.example.net",
                "minimalTlsVersion": "1.2",
                "publicNetworkAccess": "Disabled",
                "restrictOutboundNetworkAccess": "Enabled",
                "primaryUserAssignedIdentityId": format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-sql", RG),
                "keyId": "https://kv.example/keys/tde/1",
                "administrators": {"administratorType": "ActiveDirectory", "principalType": "Group",
                    "login": "sql-admins", "sid": "s", "tenantId": "t", "azureADOnlyAuthentication": true},
                "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-sql", RG)}}}]
            }
        })
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = SQL_SERVER_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Security", "Databases", "Firewall", "Networking", "Related", "Tags"]);
    }

    #[test]
    fn server_row_reads_state_security_and_never_the_password() {
        let row = SqlServerRow::from_json(&server_json(), None).unwrap();
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "ready");
        let sec = sql_server_section_lines(&row, SqlServerDetailSection::Security, None, None);
        assert_eq!(sec[0], ("Entra admin".to_string(), "sql-admins (Group)".to_string()));
        assert!(sec.iter().any(|(k, v)| k == "TDE key" && v == "customer-managed"));
        let everything: String = SQL_SERVER_SECTIONS
            .sections
            .iter()
            .enumerate()
            .flat_map(|(i, _)| sql_server_section_lines(&row, SqlServerDetailSection::from_index(i), None, None))
            .map(|(k, v)| format!("{k}{v}"))
            .collect::<String>()
            + &row.search_text();
        assert!(!everything.contains("hunter2"), "the admin password leaked");
        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        assert_eq!(related.iter().filter(|l| *l == "Identity id-sql").count(), 1, "primary identity deduplicated");
        assert!(related.iter().any(|l| l == "Private endpoint pe-sql"));
        assert!(row.cli_command().unwrap().starts_with("az sql server show --ids "));
    }

    #[test]
    fn databases_list_user_databases_first_and_system_ones_as_a_note() {
        let row = SqlServerRow::from_json(&server_json(), None).unwrap();
        let items = vec![
            serde_json::json!({"name": "master", "kind": "v12.0,system", "sku": {"name": "System", "tier": "System", "capacity": 0},
                "properties": {"status": "Online"}}),
            serde_json::json!({
                "id": format!("{}/providers/Microsoft.Sql/servers/sql-prod/databases/orders", RG),
                "name": "orders", "kind": "v12.0,user,vcore,serverless",
                "sku": {"name": "GP_S_Gen5", "tier": "GeneralPurpose", "capacity": 2},
                "properties": {"status": "Paused", "maxSizeBytes": 34359738368i64, "zoneRedundant": false,
                    "currentBackupStorageRedundancy": "Geo", "autoPauseDelay": 60,
                    "elasticPoolId": format!("{}/providers/Microsoft.Sql/servers/sql-prod/elasticPools/pool", RG)}
            }),
        ];
        let lines = sql_server_section_lines(&row, SqlServerDetailSection::Databases, Some(&Lazy::Loaded(items)), None);
        assert_eq!(lines[1], ("orders".to_string(), String::new()), "user databases come first");
        assert!(lines.iter().any(|(k, v)| k == "  SKU" && v == "GP_S_Gen5 · GeneralPurpose · capacity 2"));
        assert!(lines.iter().any(|(k, v)| k == "  Status" && v == "Paused"));
        assert!(lines.iter().any(|(k, v)| k == "  Max size" && v == "32 GB"));
        assert!(lines.iter().any(|(k, v)| k == "  Auto-pause" && v == "after 60 min"));
        assert!(lines.iter().any(|(k, _)| k == "  Elastic pool · pool"));
        assert!(lines.iter().any(|(_, v)| v == "· system: master"));
        assert_eq!(lines.last().unwrap().1, "az sql db list -s sql-prod -g rg-data --subscription 0000");
    }

    #[test]
    fn firewall_flags_the_allow_azure_rule() {
        let row = SqlServerRow::from_json(&server_json(), None).unwrap();
        let items = vec![
            serde_json::json!({"name": "office", "properties": {"startIpAddress": "203.0.113.0", "endIpAddress": "203.0.113.255"}}),
            serde_json::json!({"name": "ci", "properties": {"startIpAddress": "198.51.100.7", "endIpAddress": "198.51.100.7"}}),
            serde_json::json!({"name": "AllowAllWindowsAzureIps", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}),
        ];
        let lines = sql_server_section_lines(&row, SqlServerDetailSection::Firewall, None, Some(&Lazy::Loaded(items)));
        assert_eq!(lines[0], ("office".to_string(), "203.0.113.0 – 203.0.113.255".to_string()));
        assert_eq!(lines[1].1, "198.51.100.7");
        assert!(lines[2].1.starts_with("⚠ allows every Azure service"));
        assert_eq!(lines.last().unwrap().1, "az sql server firewall-rule list -s sql-prod -g rg-data --subscription 0000");
        assert_eq!(
            server_child_path(&row.base.id, "firewallRules"),
            format!("{}/providers/Microsoft.Sql/servers/sql-prod/firewallRules", RG)
        );
    }
}
