//! All resources (issue #23): every resource in the subscription,
//! whatever its type, from `GET /subscriptions/{sub}/resources`. A sub-tab
//! of Subscriptions. The generic list returns the envelope only (id, name,
//! type, kind, SKU, location, tags, managedBy, identity), never
//! `properties`, so it carries nothing a typed view would have to hide.
//!
//! Enter on a row whose type nebaz browses opens that row in its typed
//! tab (`JumpView::for_arm_id`); any other row focuses the pane as usual,
//! where `y` copies the id. The list's second column is the type, marked
//! `→` when browsed.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::JumpView;
use crate::azure::services::{json, overview_rows, related_rows, tag_rows, ArmBase};
use serde_json::Value;
use std::collections::HashMap;

/// The newest stable version of the generic resources list (checked
/// against azure-rest-api-specs, 2026-09-27).
pub const RESOURCES_API_VERSION: &str = "2025-04-01";
pub const RESOURCES_PATH: &str = "/resources";
/// `provisioningState` only comes back when asked for.
pub const RESOURCES_EXPAND: (&str, &str) = ("$expand", "createdTime,changedTime,provisioningState");

crate::sections! {
    pub enum GenericResourceDetailSection,
    pub static GENERIC_RESOURCE_SECTIONS = [
        Overview "Overview",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct GenericResourceRow {
    pub base: ArmBase,
    /// The ARM type as returned: `Microsoft.Web/staticSites`.
    pub arm_type: String,
    pub kind: Option<String>,
    pub sku: Option<String>,
    pub managed_by: Option<String>,
    pub created: Option<String>,
    pub changed: Option<String>,
    pub identity_type: Option<String>,
    /// The typed sub-tab that lists this row, when nebaz browses the type.
    pub view: Option<JumpView>,
}

impl GenericResourceRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<GenericResourceRow> {
        let mut base = ArmBase::from_json(v, tenant)?;
        // The expanded state is top-level here, not under `properties`.
        base.provisioning_state = json::str_at(v, "/provisioningState").or(base.provisioning_state);
        base.location = base.location.replace(' ', "");
        let sku = match (json::str_at(v, "/sku/name"), json::str_at(v, "/sku/tier")) {
            (Some(n), Some(t)) if !n.eq_ignore_ascii_case(&t) => Some(format!("{} · {}", n, t)),
            (Some(n), _) => Some(n),
            (None, t) => t,
        };
        let view = JumpView::for_arm_id(&base.id);
        Some(GenericResourceRow {
            arm_type: json::str_at(v, "/type").unwrap_or_default(),
            kind: json::str_at(v, "/kind"),
            sku,
            managed_by: json::str_at(v, "/managedBy").filter(|m| !m.is_empty()),
            created: json::str_at(v, "/createdTime"),
            changed: json::str_at(v, "/changedTime"),
            identity_type: json::str_at(v, "/identity/type"),
            view,
            base,
        })
    }

    fn ladder(&self) -> (ResourceState, String) {
        state_ladder(self.base.provisioning_state.as_deref(), None)
    }

    /// `Service › Sub-tab` for a browsed type.
    fn view_label(&self) -> Option<String> {
        self.view.map(|v| format!("{} › {}", v.service().name(), v.label()))
    }
}

impl Resource for GenericResourceRow {
    fn id(&self) -> &str {
        &self.base.id
    }
    fn name(&self) -> &str {
        &self.base.name
    }
    fn resource_type(&self) -> &str {
        &self.arm_type
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&GENERIC_RESOURCE_SECTIONS)
    }
    fn tags(&self) -> &HashMap<String, String> {
        &self.base.tags
    }
    fn location(&self) -> Option<&str> {
        Some(&self.base.location)
    }
    fn tenant_id(&self) -> Option<&str> {
        self.base.tenant.as_deref()
    }
    fn raw_content(&self) -> Option<String> {
        Some(self.base.raw.clone())
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    /// The type, so `staticsites` or `microsoft.web` finds every one.
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.arm_type,
            json::opt(self.kind.clone()),
        )
    }
    fn list_cell(&self) -> String {
        let mark = if self.view.is_some() { "→" } else { "·" };
        format!("{} {}", mark, self.arm_type)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Type".into(), self.arm_type.clone()),
            ("Kind".into(), json::opt(self.kind.clone())),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Identity".into(), json::opt(self.identity_type.clone())),
            ("Managed by".into(), json::opt(self.managed_by.clone())),
            ("Created".into(), json::time(self.created.clone())),
            ("Changed".into(), json::time(self.changed.clone())),
            (
                "In nebaz".into(),
                match self.view_label() {
                    Some(l) => format!("{} (Enter on the list opens it)", l),
                    None => "not browsed yet · y copies the id".into(),
                },
            ),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(label) = self.view_label() {
            v.push((format!("Open in {}", label), self.base.id.clone()));
        }
        if let Some(m) = self.managed_by.as_deref().and_then(|m| json::arm_id(Some(m.to_string()))) {
            v.push((format!("Managed by {}", name_of_id(&m)), m));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az resource show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn generic_resource_section_lines(
    r: &GenericResourceRow,
    section: GenericResourceDetailSection,
) -> Vec<(String, String)> {
    match section {
        GenericResourceDetailSection::Overview => overview_rows(r),
        GenericResourceDetailSection::Access => crate::azure::services::rendered_by_app(),
        GenericResourceDetailSection::Activity => crate::azure::services::rendered_by_app(),
        GenericResourceDetailSection::Related => related_rows(r),
        GenericResourceDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The single-row refresh (`r`): the generic list has no per-type GET, so
/// list the row's resource group filtered to its type and pick the id.
/// Returns `(path, query)`; `None` for an id outside a resource group.
pub fn refresh_query(id: &str) -> Option<(String, Vec<(String, String)>)> {
    let sub = subscription_of(id)?;
    let rg = resource_group_of(id)?;
    let (ns, chain) = crate::azure::resource::arm_type_chain(id)?;
    let arm_type = format!("{}/{}", ns, chain.join("/"));
    Some((
        format!("/subscriptions/{}/resourceGroups/{}/resources", sub, rg),
        vec![
            ("$filter".into(), format!("resourceType eq '{}'", arm_type)),
            (RESOURCES_EXPAND.0.into(), RESOURCES_EXPAND.1.into()),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-web";

    fn row(arm_type: &str, name: &str) -> Value {
        serde_json::json!({
            "id": format!("{}/providers/{}/{}", RG, arm_type, name),
            "name": name,
            "type": arm_type,
            "kind": "app,linux",
            "location": "West Europe",
            "sku": {"name": "Free", "tier": "Free"},
            "managedBy": format!("{}/providers/Microsoft.Web/serverfarms/plan", RG),
            "identity": {"type": "SystemAssigned", "principalId": "p"},
            "tags": {"env": "prod"},
            "createdTime": "2025-01-02T03:04:05.1234567Z",
            "changedTime": "2026-02-03T04:05:06Z",
            "provisioningState": "Succeeded"
        })
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = GENERIC_RESOURCE_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn a_browsed_type_is_marked_and_links_to_its_typed_tab() {
        let r = GenericResourceRow::from_json(&row("Microsoft.Web/sites", "shop"), None).unwrap();
        assert_eq!(r.view, Some(JumpView::WebApps));
        assert_eq!(r.list_cell(), "→ Microsoft.Web/sites");
        assert_eq!(r.base.location, "westeurope");
        assert_eq!(r.state(), ResourceState::stateless());
        let related = r.related();
        assert!(related.iter().any(|(l, id)| l == "Open in App Service › Apps" && id == &r.base.id));
        assert!(related.iter().any(|(l, _)| l == "Managed by plan"));
        assert!(r.search_text().contains("Microsoft.Web/sites"));
        assert_eq!(r.cli_command().unwrap(), format!("az resource show --ids {}/providers/Microsoft.Web/sites/shop", RG));
    }

    #[test]
    fn an_unbrowsed_type_says_so_and_has_no_open_line() {
        let r = GenericResourceRow::from_json(&row("Microsoft.Web/staticSites", "docs"), None).unwrap();
        assert_eq!(r.view, None);
        assert_eq!(r.list_cell(), "· Microsoft.Web/staticSites");
        assert!(r.details().iter().any(|(k, v)| k == "In nebaz" && v.starts_with("not browsed")));
        assert!(!r.related().iter().any(|(l, _)| l.starts_with("Open in")));
        assert!(r.details().iter().any(|(k, v)| k == "SKU" && v == "Free"));
        assert!(r.details().iter().any(|(k, v)| k == "Created" && v == "2025-01-02 03:04:05"));
    }

    #[test]
    fn the_expanded_provisioning_state_drives_the_ladder() {
        let mut v = row("Microsoft.Web/staticSites", "docs");
        v["provisioningState"] = "Failed".into();
        let r = GenericResourceRow::from_json(&v, None).unwrap();
        assert_eq!(r.state_label(), "failed");
    }

    #[test]
    fn refresh_lists_the_group_filtered_to_the_type() {
        let (path, query) = refresh_query(&format!("{}/providers/Microsoft.Web/staticSites/docs", RG)).unwrap();
        assert_eq!(path, "/subscriptions/0000/resourceGroups/rg-web/resources");
        assert_eq!(query[0].1, "resourceType eq 'microsoft.web/staticsites'");
    }
}
