//! The Subscriptions service: the scoping rows. Two sub-tabs (ADR 0002):
//!
//! - **Subscriptions** — every entry `az account list` knows, all tenants,
//!   no ARM call. Tenant-scoped, so a subscription switch never refetches
//!   it. Per row, the ARM subscription object and its locations list are
//!   lazy sections.
//! - **Resource Groups** — `GET /subscriptions/{sub}/resourcegroups` for
//!   the current subscription, streamed one page at a time.
//!
//! The row shapes here are ticket 06's raw material (state vocabulary,
//! `is_noise`, the exact section tables): they follow the skeleton's
//! conventions and are expected to be tuned there, not frozen here.

use crate::azure::auth::SubscriptionEntry;
use crate::azure::location::LocationInfo;
use crate::azure::resource::{resource_group_of, shell_quote, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{error_rows, finish_stream, json, overview_rows, related_rows, tag_rows, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::mpsc;

/// `GET /subscriptions/{id}` api-version.
pub const SUBSCRIPTIONS_API_VERSION: &str = "2022-12-01";
/// `GET /subscriptions/{id}/resourcegroups` api-version.
pub const RESOURCE_GROUPS_API_VERSION: &str = "2021-04-01";

crate::sections! {
    pub enum SubscriptionDetailSection,
    pub static SUBSCRIPTION_SECTIONS = [
        Overview "Overview",
        Details "Details" => crate::app::App::trigger_subscription_details,
        Locations "Locations" => crate::app::App::trigger_selected_subscription_locations,
        Related "Related",
        // A subscription's tags live on the ARM object, so this shares
        // the Details fetch.
        Tags "Tags" => crate::app::App::trigger_subscription_details,
    ]
}

crate::sections! {
    pub enum ResourceGroupDetailSection,
    pub static RESOURCE_GROUP_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

// ── Subscription row ──────────────────────────────────────────────────

/// One subscription, from the CLI's account cache.
#[derive(Debug, Clone)]
pub struct SubscriptionRow {
    pub entry: SubscriptionEntry,
    /// `/subscriptions/{id}` — the ARM id.
    id: String,
    tags: HashMap<String, String>,
}

impl SubscriptionRow {
    pub fn new(entry: SubscriptionEntry) -> Self {
        Self {
            id: entry.arm_id(),
            entry,
            tags: HashMap::new(),
        }
    }

    /// The bare subscription id (GUID).
    pub fn subscription_id(&self) -> &str {
        &self.entry.id
    }
}

impl Resource for SubscriptionRow {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.entry.name
    }
    fn resource_type(&self) -> &str {
        "Subscription"
    }
    /// `Enabled` is the healthy state; everything else is a problem or a
    /// transition, so it colours accordingly.
    fn state(&self) -> ResourceState {
        match self.entry.state.to_lowercase().as_str() {
            "enabled" => ResourceState::Available,
            "disabled" => ResourceState::Unavailable,
            "warned" | "pastdue" => ResourceState::Pending,
            "deleted" => ResourceState::Terminated,
            other => ResourceState::Unknown(other.to_string()),
        }
    }
    fn state_label(&self) -> String {
        self.entry.state.to_lowercase()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SUBSCRIPTION_SECTIONS)
    }
    fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }
    fn tenant_id(&self) -> Option<&str> {
        Some(&self.entry.tenant_id)
    }
    /// The one noise rule in the first release (ticket 06): a subscription
    /// that is not `Enabled` is hidden by `a`.
    fn is_noise(&self) -> bool {
        !self.entry.is_enabled()
    }
    /// The root of the scope tree links to nothing.
    fn related(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.id, self.entry.name, self.entry.tenant_id, self.entry.state,
            self.entry.cloud_name.as_deref().unwrap_or("")
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.entry.name.clone()),
            ("Id".into(), self.entry.id.clone()),
            ("ARM id".into(), self.id.clone()),
            ("State".into(), self.entry.state.clone()),
            ("Tenant".into(), self.entry.tenant_id.clone()),
            ("Cloud".into(), self.entry.cloud_name.clone().unwrap_or_else(|| "-".into())),
            ("CLI default".into(), if self.entry.is_default { "✓ yes".into() } else { "no".into() }),
            ("Signed in as".into(), self.entry.user.clone().unwrap_or_else(|| "-".into())),
        ]
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    /// No `--ids` form exists for `az account show`, so this one carries
    /// `--subscription` itself.
    fn cli_command(&self) -> Option<String> {
        Some(format!("az account show --subscription {}", shell_quote(&self.entry.id)))
    }
}

// ── Resource group row ────────────────────────────────────────────────

/// One resource group, from the ARM list.
#[derive(Debug, Clone)]
pub struct ResourceGroupRow {
    id: String,
    name: String,
    /// The group's **own** location; shown in the pane but never used by
    /// the `R` filter (a group's resources may live anywhere).
    pub location: String,
    tags: HashMap<String, String>,
    pub provisioning_state: Option<String>,
    pub managed_by: Option<String>,
    tenant: Option<String>,
    /// The bare subscription id (GUID) from the ARM id.
    pub subscription: String,
    raw: String,
}

impl ResourceGroupRow {
    /// Parse one element of the list's `value` array (or a `GET` body).
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ResourceGroupRow> {
        let id = v.get("id")?.as_str()?.to_string();
        let name = v
            .get("name")
            .and_then(|n| n.as_str())
            .map(str::to_string)
            .or_else(|| id.rsplit('/').next().map(str::to_string))?;
        let subscription = id
            .trim_start_matches('/')
            .split('/')
            .nth(1)
            .unwrap_or("")
            .to_string();
        let tags = v
            .get("tags")
            .and_then(|t| t.as_object())
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Some(ResourceGroupRow {
            location: v.get("location").and_then(|l| l.as_str()).unwrap_or("").to_string(),
            provisioning_state: v
                .pointer("/properties/provisioningState")
                .and_then(|s| s.as_str())
                .map(str::to_string),
            managed_by: v.get("managedBy").and_then(|s| s.as_str()).map(str::to_string),
            tenant: tenant.map(str::to_string),
            raw: serde_json::to_string_pretty(v).unwrap_or_default(),
            id,
            name,
            tags,
            subscription,
        })
    }
}

impl Resource for ResourceGroupRow {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn resource_type(&self) -> &str {
        "Resource Group"
    }
    /// A group has no lifecycle of its own: `Succeeded` renders as the
    /// stateless dim `○` with a blank label so a column of green
    /// "succeeded" doesn't read as a state. Anything else (`Deleting`,
    /// `Failed`) is worth a colour and an `F` chip.
    fn state(&self) -> ResourceState {
        match self
            .provisioning_state
            .as_deref()
            .unwrap_or("Succeeded")
            .to_lowercase()
            .as_str()
        {
            "succeeded" => ResourceState::stateless(),
            "deleting" => ResourceState::Deleting,
            "failed" | "canceled" => ResourceState::Unavailable,
            "creating" | "accepted" | "updating" => ResourceState::Creating,
            other => ResourceState::Unknown(other.to_string()),
        }
    }
    fn state_label(&self) -> String {
        match self.state() {
            ResourceState::Unknown(s) if s.is_empty() => String::new(),
            _ => self
                .provisioning_state
                .as_deref()
                .unwrap_or("")
                .to_lowercase(),
        }
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&RESOURCE_GROUP_SECTIONS)
    }
    fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }
    /// Group-level rows are never filtered by the `R` slot.
    fn location(&self) -> Option<&str> {
        None
    }
    fn resource_group(&self) -> Option<&str> {
        resource_group_of(&self.id).or(Some(&self.name))
    }
    fn tenant_id(&self) -> Option<&str> {
        self.tenant.as_deref()
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.name.clone()),
            ("Id".into(), self.id.clone()),
            ("Location".into(), self.location.clone()),
            (
                "Provisioning state".into(),
                self.provisioning_state.clone().unwrap_or_else(|| "-".into()),
            ),
            ("Managed by".into(), self.managed_by.clone().unwrap_or_else(|| "-".into())),
            ("Subscription".into(), self.subscription.clone()),
        ]
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn raw_content(&self) -> Option<String> {
        Some(self.raw.clone())
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = vec![("Subscription".to_string(), format!("/subscriptions/{}", self.subscription))];
        if let Some(m) = self.managed_by.as_deref().filter(|m| m.starts_with("/subscriptions/")) {
            v.push((format!("Managed by {}", crate::azure::resource::name_of_id(m)), m.to_string()));
        }
        v
    }
    /// `az group show` has no `--ids`, so `--subscription` rides along.
    fn cli_command(&self) -> Option<String> {
        Some(format!(
            "az group show -n {} --subscription {}",
            shell_quote(&self.name),
            shell_quote(&self.subscription)
        ))
    }
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct SubscriptionsService {
    scope: Scope,
    entries: Vec<SubscriptionEntry>,
}

impl SubscriptionsService {
    pub fn new(scope: Scope, entries: Vec<SubscriptionEntry>) -> Self {
        Self { scope, entries }
    }

    fn subscription_rows(&self) -> Vec<Box<dyn Resource>> {
        self.entries
            .iter()
            .cloned()
            .map(|e| Box::new(SubscriptionRow::new(e)) as Box<dyn Resource>)
            .collect()
    }

    fn rows_from_page(&self, page: Vec<Value>) -> Vec<Box<dyn Resource>> {
        let tenant = self.scope.tenant();
        page.iter()
            .filter_map(|v| ResourceGroupRow::from_json(v, tenant))
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .collect()
    }
}

#[async_trait]
impl AzureService for SubscriptionsService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Subscriptions
    }

    fn name(&self) -> &str {
        "Subscriptions"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        match view {
            JumpView::ResourceGroups => {
                let items = self.scope.list("/resourcegroups", RESOURCE_GROUPS_API_VERSION).await?;
                Ok(self.rows_from_page(items))
            }
            _ => Ok(self.subscription_rows()),
        }
    }

    /// Resource groups stream one ARM page per batch; the subscription
    /// list is local and lands in one event.
    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        if view != JumpView::ResourceGroups {
            let _ = event_tx.send(Event::ResourcesLoaded {
                service: service_type,
                resources: self.subscription_rows(),
            });
            return Ok(());
        }
        let r = self
            .scope
            .stream("/resourcegroups", RESOURCE_GROUPS_API_VERSION, &[], service_type, "Listing resource groups…", &event_tx, |page| {
                self.rows_from_page(page)
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        if resource_group_of(id).is_some() {
            let v = self.scope.get(id, RESOURCE_GROUPS_API_VERSION).await?;
            return ResourceGroupRow::from_json(&v, self.scope.tenant())
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .ok_or_else(|| Error::ResourceNotFound(id.to_string()));
        }
        self.entries
            .iter()
            .find(|e| e.arm_id().eq_ignore_ascii_case(id))
            .cloned()
            .map(|e| Box::new(SubscriptionRow::new(e)) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

// ── Section bodies ────────────────────────────────────────────────────

/// Body lines for one section of a subscription row.
pub fn subscription_section_lines(
    r: &SubscriptionRow,
    section: SubscriptionDetailSection,
    details: Option<&Lazy<Value>>,
    locations: Option<&Lazy<Vec<LocationInfo>>>,
) -> Vec<(String, String)> {
    match section {
        SubscriptionDetailSection::Overview => overview_rows(r),
        SubscriptionDetailSection::Related => related_rows(r),
        SubscriptionDetailSection::Tags => match details {
            None | Some(Lazy::Loading) => vec![("Tags".into(), "Loading…".into())],
            Some(Lazy::Error(e)) => error_rows(e),
            Some(Lazy::Loaded(v)) => tag_rows(&json::tags_of(v)),
        },
        SubscriptionDetailSection::Details => match details {
            None | Some(Lazy::Loading) => vec![("Subscription".into(), "Loading…".into())],
            Some(Lazy::Error(e)) => error_rows(e),
            Some(Lazy::Loaded(v)) => subscription_detail_rows(v),
        },
        SubscriptionDetailSection::Locations => match locations {
            None | Some(Lazy::Loading) => vec![("Locations".into(), "Loading…".into())],
            Some(Lazy::Error(e)) => error_rows(e),
            Some(Lazy::Loaded(infos)) => {
                let mut lines = vec![("Locations".into(), infos.len().to_string())];
                lines.push((String::new(), String::new()));
                for info in infos {
                    let label = info
                        .regional_display_name
                        .clone()
                        .unwrap_or_else(|| info.display_name.clone());
                    let label = match info.region_type.as_deref() {
                        Some(t) if !t.eq_ignore_ascii_case("physical") => {
                            format!("{} · {}", label, t.to_lowercase())
                        }
                        _ => label,
                    };
                    lines.push((info.name.clone(), label));
                }
                lines
            }
        },
    }
}

/// The ARM subscription object, flattened: the fields worth a line.
fn subscription_detail_rows(v: &Value) -> Vec<(String, String)> {
    let s = |p: &str| v.pointer(p).and_then(|x| x.as_str()).map(str::to_string);
    let mut lines = vec![
        ("Display name".into(), s("/displayName").unwrap_or_else(|| "-".into())),
        ("State".into(), s("/state").unwrap_or_else(|| "-".into())),
        ("Tenant".into(), s("/tenantId").unwrap_or_else(|| "-".into())),
        (
            "Authorization source".into(),
            s("/authorizationSource").unwrap_or_else(|| "-".into()),
        ),
        (
            "Location placement".into(),
            s("/subscriptionPolicies/locationPlacementId").unwrap_or_else(|| "-".into()),
        ),
        ("Quota".into(), s("/subscriptionPolicies/quotaId").unwrap_or_else(|| "-".into())),
        (
            "Spending limit".into(),
            s("/subscriptionPolicies/spendingLimit").unwrap_or_else(|| "-".into()),
        ),
    ];
    if let Some(managed) = v.get("managedByTenants").and_then(|m| m.as_array()) {
        let ids: Vec<String> = managed
            .iter()
            .filter_map(|m| m.get("tenantId").and_then(|t| t.as_str()).map(str::to_string))
            .collect();
        lines.push((
            "Managed by tenants".into(),
            if ids.is_empty() { "-".into() } else { ids.join(", ") },
        ));
    }
    lines
}

/// Body lines for one section of a resource-group row.
pub fn resource_group_section_lines(
    r: &ResourceGroupRow,
    section: ResourceGroupDetailSection,
) -> Vec<(String, String)> {
    match section {
        ResourceGroupDetailSection::Overview => overview_rows(r),
        ResourceGroupDetailSection::Related => related_rows(r),
        ResourceGroupDetailSection::Tags => tag_rows(r.tags()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> SubscriptionEntry {
        SubscriptionEntry {
            id: "22222222-2222-2222-2222-222222222222".into(),
            name: "Production".into(),
            tenant_id: "t-1".into(),
            state: "Enabled".into(),
            is_default: true,
            cloud_name: Some("AzureCloud".into()),
            user: Some("me@example.com".into()),
        }
    }

    #[test]
    fn subscription_row_keys_on_the_arm_id_and_carries_its_tenant() {
        let row = SubscriptionRow::new(entry());
        assert_eq!(row.id(), "/subscriptions/22222222-2222-2222-2222-222222222222");
        assert_eq!(row.name(), "Production");
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "enabled");
        assert_eq!(row.location(), None);
        assert_eq!(row.resource_group(), None);
        assert_eq!(
            row.portal_url().as_deref(),
            Some("https://portal.azure.com/#@t-1/resource/subscriptions/22222222-2222-2222-2222-222222222222")
        );
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az account show --subscription 22222222-2222-2222-2222-222222222222")
        );
        assert!(!row.is_noise());
        let mut disabled = entry();
        disabled.state = "Disabled".into();
        let disabled = SubscriptionRow::new(disabled);
        assert_eq!(disabled.state(), ResourceState::Unavailable);
        assert!(disabled.is_noise(), "a non-enabled subscription is the one noise rule");
    }

    #[test]
    fn resource_group_row_parses_the_arm_shape() {
        let v = serde_json::json!({
            "id": "/subscriptions/2222/resourceGroups/rg-prod",
            "name": "rg-prod",
            "location": "westeurope",
            "tags": {"env": "prod", "owner": "platform"},
            "properties": {"provisioningState": "Succeeded"}
        });
        let row = ResourceGroupRow::from_json(&v, Some("t-1")).unwrap();
        assert_eq!(row.id(), "/subscriptions/2222/resourceGroups/rg-prod");
        assert_eq!(row.subscription, "2222");
        assert_eq!(row.resource_group(), Some("rg-prod"));
        // Group rows never take part in the location filter…
        assert_eq!(row.location(), None);
        // …but the pane shows the group's own location.
        assert_eq!(row.location, "westeurope");
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.state_label(), "");
        assert_eq!(row.tags().len(), 2);
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az group show -n rg-prod --subscription 2222")
        );
        assert!(row.raw_content().unwrap().contains("\"provisioningState\""));
        assert_eq!(row.tenant_id(), Some("t-1"));
        assert_eq!(row.related(), vec![("Subscription".to_string(), "/subscriptions/2222".to_string())]);

        let deleting = serde_json::json!({
            "id": "/subscriptions/2222/resourceGroups/rg-old",
            "location": "eastus",
            "properties": {"provisioningState": "Deleting"}
        });
        let row = ResourceGroupRow::from_json(&deleting, None).unwrap();
        assert_eq!(row.name(), "rg-old");
        assert_eq!(row.state(), ResourceState::Deleting);
        assert_eq!(row.state_label(), "deleting");
        assert!(ResourceGroupRow::from_json(&serde_json::json!({"name": "x"}), None).is_none());
    }

    #[test]
    fn section_lines_cover_every_lazy_arm() {
        let row = SubscriptionRow::new(entry());
        let overview = subscription_section_lines(&row, SubscriptionDetailSection::Overview, None, None);
        assert!(overview.iter().any(|(k, _)| k == "CLI"));
        let loading = subscription_section_lines(&row, SubscriptionDetailSection::Details, None, None);
        assert_eq!(loading[0].1, "Loading…");
        let failed = subscription_section_lines(
            &row,
            SubscriptionDetailSection::Details,
            Some(&Lazy::Error("denied".into())),
            None,
        );
        assert!(failed.last().unwrap().1.contains("denied"));
        let loaded = subscription_section_lines(
            &row,
            SubscriptionDetailSection::Details,
            Some(&Lazy::Loaded(serde_json::json!({
                "displayName": "Production",
                "subscriptionPolicies": {"quotaId": "PayAsYouGo_2014-09-01"},
                "managedByTenants": [{"tenantId": "m-1"}],
                "tags": {"cost-center": "42"}
            }))),
            None,
        );
        assert!(loaded.iter().any(|(k, v)| k == "Quota" && v == "PayAsYouGo_2014-09-01"));
        assert!(loaded.iter().any(|(k, v)| k == "Managed by tenants" && v == "m-1"));
        let tags = subscription_section_lines(
            &row,
            SubscriptionDetailSection::Tags,
            Some(&Lazy::Loaded(serde_json::json!({"tags": {"cost-center": "42"}}))),
            None,
        );
        assert_eq!(tags, vec![("cost-center".to_string(), "42".to_string())]);
        assert!(subscription_section_lines(&row, SubscriptionDetailSection::Related, None, None)[0].1.contains("No related"));
        let locs = subscription_section_lines(
            &row,
            SubscriptionDetailSection::Locations,
            None,
            Some(&Lazy::Loaded(vec![LocationInfo {
                name: "eastus".into(),
                display_name: "East US".into(),
                regional_display_name: Some("(US) East US".into()),
                region_type: Some("Physical".into()),
            }])),
        );
        assert_eq!(locs[0], ("Locations".to_string(), "1".to_string()));
        assert_eq!(locs[2], ("eastus".to_string(), "(US) East US".to_string()));
    }
}
