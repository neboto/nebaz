//! The Identity service (issue #6): user-assigned managed identities, one
//! subscription-wide list. Federated credentials (workload identity
//! federation: issuer, subject, audiences) are a lazy section, one list
//! per identity. The other half of the issue lives in the services that
//! *use* identities: VMs, AKS and Foundry list them in Related, and
//! `for_arm_id` makes those lines jump here.
//!
//! Identities carry no `provisioningState`, so every row is stateless.
//! What they can *do* (role assignments) is a lens for later, not a list.

use crate::azure::resource::{resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource, ResourceState};
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
pub const IDENTITY_API_VERSION: &str = "2024-11-30";
const IDENTITIES_PATH: &str = "/providers/Microsoft.ManagedIdentity/userAssignedIdentities";

crate::sections! {
    pub enum IdentityDetailSection,
    pub static IDENTITY_SECTIONS = [
        Overview "Overview",
        FederatedCredentials "Federated credentials" => crate::app::App::trigger_federated_credentials,
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct IdentityRow {
    pub base: ArmBase,
    pub client_id: Option<String>,
    pub principal_id: Option<String>,
    pub identity_tenant: Option<String>,
    pub isolation_scope: Option<String>,
}

impl IdentityRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<IdentityRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(IdentityRow {
            client_id: json::str_at(v, &format!("{}/clientId", p)),
            principal_id: json::str_at(v, &format!("{}/principalId", p)),
            identity_tenant: json::str_at(v, &format!("{}/tenantId", p)),
            isolation_scope: json::str_at(v, &format!("{}/isolationScope", p)),
            base,
        })
    }
}

impl Resource for IdentityRow {
    arm_row!("Managed Identity");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&IDENTITY_SECTIONS)
    }
    /// Both GUIDs are searchable: a principal id pasted from a role
    /// assignment finds its identity.
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.client_id.clone()),
            json::opt(self.principal_id.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Client id".into(), json::opt(self.client_id.clone())),
            ("Principal id".into(), json::opt(self.principal_id.clone())),
            ("Tenant".into(), json::opt(self.identity_tenant.clone())),
            ("Isolation scope".into(), json::opt(self.isolation_scope.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az identity show --ids {}", shell_quote(&self.base.id)))
    }
}

/// Body lines for one section of an identity row.
pub fn identity_section_lines(
    r: &IdentityRow,
    section: IdentityDetailSection,
    federated: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        IdentityDetailSection::Overview => overview_rows(r),
        IdentityDetailSection::FederatedCredentials => {
            lazy_list_rows(federated, "Federated credentials", |items| federated_rows(items, r))
        }
        IdentityDetailSection::Related => {
            let mut lines = related_rows(r);
            lines.push((
                String::new(),
                "· resources using this identity list it in their own Related".into(),
            ));
            lines
        }
        IdentityDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The Federated credentials section body from the ARM list.
pub fn federated_rows(items: &[Value], r: &IdentityRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No federated credentials".into()));
    }
    for fc in items {
        let p = "/properties";
        lines.push((String::new(), String::new()));
        lines.push((json::text(fc, "/name"), String::new()));
        lines.push(("  Issuer".into(), json::text(fc, &format!("{}/issuer", p))));
        lines.push(("  Subject".into(), json::text(fc, &format!("{}/subject", p))));
        lines.push(("  Audiences".into(), json::join(&json::strings_at(fc, &format!("{}/audiences", p)))));
    }
    if let (Some(rg), Some(sub)) = (resource_group_of(&r.base.id), subscription_of(&r.base.id)) {
        lines.push((String::new(), String::new()));
        lines.push((
            "Read command".into(),
            format!(
                "az identity federated-credential list --identity-name {} -g {} --subscription {}",
                shell_quote(&r.base.name),
                shell_quote(rg),
                shell_quote(sub)
            ),
        ));
    }
    lines
}

/// The ARM path of an identity's federated credentials.
pub fn federated_credentials_path(identity_id: &str) -> String {
    format!("{}/federatedIdentityCredentials", identity_id.trim_end_matches('/'))
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct IdentityService {
    scope: Scope,
}

impl IdentityService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for IdentityService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn name(&self) -> &str {
        "Managed Identity"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(IDENTITIES_PATH, IDENTITY_API_VERSION)
            .await?
            .iter()
            .filter_map(|v| IdentityRow::from_json(v, tenant))
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
            .stream(IDENTITIES_PATH, IDENTITY_API_VERSION, &[], service_type, "Listing managed identities…", &event_tx, |page| {
                page.iter()
                    .filter_map(|v| IdentityRow::from_json(v, tenant.as_deref()))
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, IDENTITY_API_VERSION).await?;
        IdentityRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_json() -> Value {
        serde_json::json!({
            "id": "/subscriptions/0000/resourceGroups/rg-id/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-app",
            "name": "id-app",
            "location": "westeurope",
            "tags": {"team": "platform"},
            "properties": {
                "tenantId": "11111111-1111-1111-1111-111111111111",
                "principalId": "22222222-2222-2222-2222-222222222222",
                "clientId": "33333333-3333-3333-3333-333333333333",
                "isolationScope": "None"
            }
        })
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = IDENTITY_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Federated credentials", "Related", "Tags"]);
    }

    #[test]
    fn identity_row_is_stateless_and_searchable_by_both_ids() {
        let row = IdentityRow::from_json(&identity_json(), Some("t")).unwrap();
        assert_eq!(row.state(), ResourceState::stateless());
        assert!(row.search_text().contains("22222222-2222-2222-2222-222222222222"), "principal id");
        assert!(row.search_text().contains("33333333-3333-3333-3333-333333333333"), "client id");
        assert!(row.details().iter().any(|(k, v)| k == "Principal id" && v.starts_with("2222")));
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az identity show --ids /subscriptions/0000/resourceGroups/rg-id/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-app")
        );
    }

    #[test]
    fn federated_credentials_show_issuer_subject_audiences_and_the_read_command() {
        let row = IdentityRow::from_json(&identity_json(), None).unwrap();
        let items = vec![serde_json::json!({
            "name": "aks-app",
            "properties": {
                "issuer": "https://oidc.example/issuer/",
                "subject": "system:serviceaccount:app:api",
                "audiences": ["api://AzureADTokenExchange"]
            }
        })];
        let lines = identity_section_lines(&row, IdentityDetailSection::FederatedCredentials, Some(&Lazy::Loaded(items)));
        assert!(lines.iter().any(|(k, v)| k == "aks-app" && v.is_empty()));
        assert!(lines.iter().any(|(k, v)| k == "  Subject" && v == "system:serviceaccount:app:api"));
        assert!(lines.iter().any(|(k, v)| k == "  Audiences" && v == "api://AzureADTokenExchange"));
        assert_eq!(
            lines.last().unwrap().1,
            "az identity federated-credential list --identity-name id-app -g rg-id --subscription 0000"
        );
        let none = identity_section_lines(&row, IdentityDetailSection::FederatedCredentials, Some(&Lazy::Loaded(vec![])));
        assert_eq!(none[0].1, "No federated credentials");
        assert_eq!(
            federated_credentials_path(&row.base.id),
            format!("{}/federatedIdentityCredentials", row.base.id)
        );
    }
}
