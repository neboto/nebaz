//! Deployment stacks and template specs (#225, SERVICES.md rule 47): the
//! other two sub-tabs of Deployments. The provider is
//! `DeploymentsService` (`deployments.rs`); the rows are here.
//!
//! - **Stacks**: a stack is a deployment that keeps track of what it
//!   created, so it can deny changes to those resources and delete or
//!   detach them when the template stops declaring them. The subscription's
//!   own stacks are one list; a group's are one list per group, read with
//!   the fan-out group deployments use ([`stream_per_group`]).
//!   Management-group stacks are above the subscription and are not read.
//! - **Template specs**: a template stored as a resource, with versions.
//!   One subscription-wide list; the versions are a lazy section.
//!
//! The values rule is the deployments' one: a stack's parameter and output
//! values, its template and a link's SAS query are dropped before
//! `ArmBase` keeps the raw JSON ([`stack_without_values`]). A template
//! spec version's template is never kept at all: [`version_summary`]
//! reduces it to parameter names and types and the resource types it
//! declares (a `defaultValue` or a variable can be a secret).

use crate::azure::resource::{
    name_of_id, provisioning_rung, resource_group_of, scope_related, shell_quote, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::ServiceType;
use crate::azure::services::deployments::{
    error_chain, named, parameters_rows, stream_per_group, without_values, GroupFanOut, Named,
};
use crate::azure::services::{
    arm_row, error_rows, json, overview_rows, related_rows, rendered_by_app, tag_rows, ArmBase, Scope,
};
use crate::azure::timeline::pretty_duration;
use crate::error::Result;
use crate::event::Event;
use crate::lazy::Lazy;
use serde_json::{json, Value};
use std::collections::HashSet;
use tokio::sync::mpsc;

pub const STACKS_API_VERSION: &str = "2024-03-01";
pub const SUBSCRIPTION_STACKS_PATH: &str = "/providers/Microsoft.Resources/deploymentStacks";
pub const TEMPLATE_SPECS_API_VERSION: &str = "2022-02-01";
pub const TEMPLATE_SPECS_PATH: &str = "/providers/Microsoft.Resources/templateSpecs";
/// Versions one Versions read keeps.
pub const MAX_VERSIONS: usize = 200;
/// Managed resources the Related section links.
const MAX_RELATED: usize = 30;

/// `/subscriptions/{s}/resourcegroups/{rg}/providers/Microsoft.Resources/deploymentStacks`.
pub fn rg_stacks_path(subscription: &str, group: &str) -> String {
    format!("/subscriptions/{}/resourcegroups/{}/providers/Microsoft.Resources/deploymentStacks", subscription, group)
}

/// The Related line for a template spec version: the spec itself (a row
/// in Template specs; a version is a child, in no list), labelled with the
/// version.
pub fn spec_link(version_id: &str) -> (String, String) {
    let id = version_id.trim_end_matches('/');
    let lower = id.to_lowercase();
    match lower.rfind("/versions/") {
        Some(i) => {
            let spec = &id[..i];
            (format!("Template spec {} {}", name_of_id(spec), &id[i + "/versions/".len()..]), spec.to_string())
        }
        None => (format!("Template spec {}", name_of_id(id)), id.to_string()),
    }
}

// ── Stacks ────────────────────────────────────────────────────────────

crate::sections! {
    pub enum StackDetailSection,
    pub static STACK_SECTIONS = [
        Overview "Overview",
        Resources "Resources",
        Settings "Settings",
        Parameters "Parameters",
        Error "Error",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

/// A stack without what can hold a secret: what [`without_values`] drops,
/// and the template itself.
pub fn stack_without_values(v: &Value) -> Value {
    let mut out = without_values(v);
    if let Some(props) = out.get_mut("properties").and_then(Value::as_object_mut) {
        props.remove("template");
    }
    out
}

/// One resource a stack manages.
#[derive(Debug, Clone, PartialEq)]
pub struct StackResource {
    pub id: String,
    /// `managed`, `removeDenyFailed`, `deleteFailed`.
    pub status: Option<String>,
    /// `denyDelete`, `denyWriteAndDelete`, `notSupported`, `inapplicable`,
    /// `removedBySystem`, `none`.
    pub deny_status: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StackRow {
    pub base: ArmBase,
    pub description: Option<String>,
    /// The deployment the stack last ran.
    pub deployment_id: Option<String>,
    pub duration: Option<String>,
    pub correlation_id: Option<String>,
    pub template: Option<String>,
    pub template_spec_id: Option<String>,
    /// `actionOnUnmanage`: `delete` or `detach`, per kind.
    pub unmanage_resources: Option<String>,
    pub unmanage_groups: Option<String>,
    pub unmanage_management_groups: Option<String>,
    /// `denySettings.mode`: `none`, `denyDelete`, `denyWriteAndDelete`.
    pub deny_mode: Option<String>,
    pub deny_child_scopes: Option<bool>,
    pub excluded_principals: Vec<String>,
    pub excluded_actions: Vec<String>,
    pub bypass_out_of_sync: Option<bool>,
    pub resources: Vec<StackResource>,
    /// Lowercased ids of `resources`: "is this resource in the stack?"
    /// for the ownership ribbon, asked every frame.
    managed: HashSet<String>,
    pub detached: Vec<String>,
    pub deleted: Vec<String>,
    /// A resource the stack could not deploy or remove, with its error.
    pub failed: Vec<(String, Option<String>)>,
    pub parameters: Vec<Named>,
    pub outputs: Vec<Named>,
    pub error: Option<Value>,
}

fn is(value: &Option<String>, word: &str) -> bool {
    value.as_deref().is_some_and(|v| v.eq_ignore_ascii_case(word))
}

impl StackRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<StackRow> {
        let v = &stack_without_values(raw);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| json::str_at(v, &format!("/properties/{}", f)).filter(|s| !s.is_empty());
        let resources: Vec<StackResource> = json::arr(v, "/properties/resources")
            .iter()
            .filter_map(|r| {
                Some(StackResource {
                    id: json::str_at(r, "/id")?,
                    status: json::str_at(r, "/status"),
                    deny_status: json::str_at(r, "/denyStatus"),
                })
            })
            .collect();
        let failed = json::arr(v, "/properties/failedResources")
            .iter()
            .filter_map(|r| {
                let error = r.get("error").filter(|e| e.is_object()).map(|e| {
                    format!("{}: {}", json::text(e, "/code"), json::text(e, "/message"))
                });
                Some((json::str_at(r, "/id")?, error))
            })
            .collect();
        Some(StackRow {
            description: p("description"),
            deployment_id: p("deploymentId"),
            duration: p("duration").map(|d| pretty_duration(&d)),
            correlation_id: p("correlationId"),
            template: crate::azure::ownership::template_of(v),
            template_spec_id: p("templateLink/id")
                .filter(|id| id.to_lowercase().contains("/microsoft.resources/templatespecs/")),
            unmanage_resources: p("actionOnUnmanage/resources"),
            unmanage_groups: p("actionOnUnmanage/resourceGroups"),
            unmanage_management_groups: p("actionOnUnmanage/managementGroups"),
            deny_mode: p("denySettings/mode"),
            deny_child_scopes: json::bool_at(v, "/properties/denySettings/applyToChildScopes"),
            excluded_principals: json::strings_at(v, "/properties/denySettings/excludedPrincipals"),
            excluded_actions: json::strings_at(v, "/properties/denySettings/excludedActions"),
            bypass_out_of_sync: json::bool_at(v, "/properties/bypassStackOutOfSyncError"),
            managed: resources.iter().map(|r| r.id.trim_end_matches('/').to_lowercase()).collect(),
            resources,
            detached: json::ids_at(v, "/properties/detachedResources"),
            deleted: json::ids_at(v, "/properties/deletedResources"),
            failed,
            parameters: named(v, "/properties/parameters"),
            outputs: named(v, "/properties/outputs"),
            error: v.pointer("/properties/error").filter(|e| e.is_object()).cloned(),
            base,
        })
    }

    /// Whether the stack manages `id` (any case).
    pub fn manages(&self, id: &str) -> bool {
        self.managed.contains(&id.trim_end_matches('/').to_lowercase())
    }

    /// Whether removing something from the template deletes it.
    pub fn deletes_on_unmanage(&self) -> bool {
        [&self.unmanage_resources, &self.unmanage_groups, &self.unmanage_management_groups]
            .into_iter()
            .any(|a| is(a, "delete"))
    }

    /// Whether the stack puts no deny assignment on what it manages.
    pub fn denies_nothing(&self) -> bool {
        self.deny_mode.is_none() || is(&self.deny_mode, "none")
    }

    /// `delete resources and groups, detach management groups`.
    pub fn unmanage_summary(&self) -> String {
        let kinds = [
            ("resources", &self.unmanage_resources),
            ("resource groups", &self.unmanage_groups),
            ("management groups", &self.unmanage_management_groups),
        ];
        let parts: Vec<String> = kinds
            .iter()
            .filter_map(|(kind, action)| action.as_ref().map(|a| format!("{} {}", a.to_lowercase(), kind)))
            .collect();
        if parts.is_empty() {
            "-".into()
        } else {
            parts.join(", ")
        }
    }

    fn ladder(&self) -> (ResourceState, String) {
        let native = self.base.provisioning_state.as_deref();
        let with_failures = native.is_some_and(|s| s.eq_ignore_ascii_case("succeededWithFailures"));
        if !with_failures {
            if let Some(rung) = provisioning_rung(native) {
                return rung;
            }
        }
        if with_failures || !self.failed.is_empty() {
            return (ResourceState::Unavailable, "degraded".into());
        }
        match native {
            Some(_) => (ResourceState::Available, "succeeded".into()),
            None => (ResourceState::stateless(), String::new()),
        }
    }

    fn error_head(&self) -> Option<String> {
        let e = self.error.as_ref()?;
        Some(format!("{}: {}", json::text(e, "/code"), json::text(e, "/message")))
    }

    fn resources_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![(
            "Managed".to_string(),
            match (self.resources.len(), self.failed.len()) {
                (0, 0) => "none".to_string(),
                (n, 0) => format!("{}", n),
                (n, f) => format!("{} · ⚠ {} failed", n, f),
            },
        )];
        for (id, error) in &self.failed {
            lines.push((format!("⚠ {}", name_of_id(id)), id.clone()));
            lines.push(("  Error".into(), error.clone().unwrap_or_else(|| "failed (no error recorded)".into())));
        }
        for r in &self.resources {
            let trouble = r.status.as_deref().is_some_and(|s| !s.eq_ignore_ascii_case("managed"));
            lines.push((format!("{}{}", if trouble { "⚠ " } else { "" }, name_of_id(&r.id)), r.id.clone()));
            lines.push((
                "  Status".into(),
                format!(
                    "{} · deny: {}",
                    r.status.clone().unwrap_or_else(|| "-".into()),
                    r.deny_status.clone().unwrap_or_else(|| "-".into())
                ),
            ));
        }
        let mut group = |title: &str, note: &str, ids: &[String]| {
            if ids.is_empty() {
                return;
            }
            lines.push((String::new(), String::new()));
            lines.push((title.to_string(), format!("{} ({})", ids.len(), note)));
            for id in ids {
                lines.push((name_of_id(id).to_string(), id.clone()));
            }
        };
        group("Detached", "still in Azure, no longer managed by the stack", &self.detached);
        group("Deleted", "removed by the stack's last run", &self.deleted);
        if !self.resources.is_empty() || !self.failed.is_empty() || !self.detached.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "⏎ on a line jumps to it (y copies the id)".into()));
        }
        lines
    }

    fn settings_rows(&self) -> Vec<(String, String)> {
        let action = |a: &Option<String>| a.clone().unwrap_or_else(|| "-".into());
        let mut lines = vec![
            ("When a resource leaves the template".to_string(), String::new()),
            ("  Resources".into(), action(&self.unmanage_resources)),
            ("  Resource groups".into(), action(&self.unmanage_groups)),
            ("  Management groups".into(), action(&self.unmanage_management_groups)),
            (String::new(), String::new()),
            (
                "Deny settings".into(),
                if self.denies_nothing() { "none: nothing stops a change outside the stack".into() } else { String::new() },
            ),
            ("  Mode".into(), action(&self.deny_mode)),
            ("  Applies to child scopes".into(), json::yes_no(self.deny_child_scopes)),
        ];
        let mut list = |title: &str, items: &[String]| {
            lines.push((format!("  {}", title), if items.is_empty() { "none".into() } else { format!("{}", items.len()) }));
            for item in items {
                lines.push((String::new(), format!("  {}", item)));
            }
        };
        list("Excluded principals", &self.excluded_principals);
        list("Excluded actions", &self.excluded_actions);
        lines.push((String::new(), String::new()));
        lines.push(("Bypass the out-of-sync error".into(), json::yes_no(self.bypass_out_of_sync)));
        lines
    }

    fn error_section_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if let Some(e) = &self.error {
            error_chain(e, 0, &mut lines);
        }
        for (id, error) in &self.failed {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push((format!("⚠ {}", name_of_id(id)), id.clone()));
            lines.push(("  Error".into(), error.clone().unwrap_or_else(|| "failed (no error recorded)".into())));
        }
        if lines.is_empty() {
            lines.push((String::new(), "No error".into()));
        }
        lines
    }
}

impl Resource for StackRow {
    fn id(&self) -> &str {
        &self.base.id
    }
    fn name(&self) -> &str {
        &self.base.name
    }
    fn resource_type(&self) -> &str {
        "Deployment stack"
    }
    fn tags(&self) -> &std::collections::HashMap<String, String> {
        &self.base.tags
    }
    /// Like a deployment: a subscription stack's `location` is where its
    /// record is kept, a group stack has none. `R` never hides one.
    fn location(&self) -> Option<&str> {
        None
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
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&STACK_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let mut parts = vec![self.resource_group().unwrap_or("subscription").to_string()];
        parts.push(format!("deny {}", self.deny_mode.clone().unwrap_or_else(|| "none".into())));
        parts.push(match self.failed.len() {
            0 => format!("{} resources", self.resources.len()),
            f => format!("{} resources · ⚠ {} failed", self.resources.len(), f),
        });
        Some(parts.join(" · "))
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut d = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            (
                "Scope".into(),
                match self.resource_group() {
                    Some(rg) => format!("resource group {}", rg),
                    None => "subscription".into(),
                },
            ),
            ("State".into(), json::opt(self.base.provisioning_state.clone())),
            ("Description".into(), json::opt(self.description.clone())),
            ("Resources".into(), format!("{} managed", self.resources.len())),
        ];
        if !self.failed.is_empty() {
            d.push(("Failed".into(), format!("⚠ {} (see Resources)", self.failed.len())));
        }
        if !self.detached.is_empty() {
            d.push(("Detached".into(), format!("{}", self.detached.len())));
        }
        d.extend([
            ("On unmanage".into(), self.unmanage_summary()),
            ("Deny mode".into(), json::opt(self.deny_mode.clone())),
            ("Template".into(), self.template.clone().unwrap_or_else(|| "inline (Bicep or a local file)".into())),
            ("Last deployment".into(), json::opt(self.deployment_id.as_deref().map(|id| name_of_id(id).to_string()))),
            ("Duration".into(), json::opt(self.duration.clone())),
            ("Correlation id".into(), json::opt(self.correlation_id.clone())),
        ]);
        if resource_group_of(&self.base.id).is_none() && !self.base.location.is_empty() {
            d.push(("Record kept in".into(), self.base.location.clone()));
        }
        if let Some(e) = self.error_head() {
            d.push(("Error".into(), format!("⚠ {}", e)));
        }
        d
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut lines = scope_related(&self.base.id);
        if let Some(id) = &self.deployment_id {
            lines.push(("Last deployment".into(), id.clone()));
        }
        if let Some(version) = &self.template_spec_id {
            lines.push(spec_link(version));
        }
        for r in self.resources.iter().take(MAX_RELATED) {
            lines.push((format!("Manages {}", name_of_id(&r.id)), r.id.clone()));
        }
        lines
    }
    fn cli_command(&self) -> Option<String> {
        let sub = shell_quote(subscription_of(&self.base.id)?);
        Some(match resource_group_of(&self.base.id) {
            Some(rg) => format!(
                "az stack group show -g {} -n {} --subscription {}",
                shell_quote(rg),
                shell_quote(&self.base.name),
                sub
            ),
            None => format!("az stack sub show -n {} --subscription {}", shell_quote(&self.base.name), sub),
        })
    }
}

/// Body lines for one section of a stack; `None` for another type.
pub fn stack_section_lines(r: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<StackRow>()?;
    use StackDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Resources => x.resources_rows(),
        S::Settings => x.settings_rows(),
        S::Parameters => parameters_rows(&x.parameters, &x.outputs),
        S::Error => x.error_section_rows(),
        S::Access | S::Activity => rendered_by_app(),
        S::Related => related_rows(x),
        S::Tags => tag_rows(x.tags()),
    })
}

pub fn stack_rows(page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    page.iter()
        .filter_map(|v| StackRow::from_json(v, tenant))
        .map(|r| Box::new(r) as Box<dyn Resource>)
        .collect()
}

/// The stack that manages `id`, among stack rows (the warm Stacks list).
pub fn managing_stack<'a>(stacks: &'a [Box<dyn Resource>], id: &str) -> Option<&'a StackRow> {
    stacks.iter().filter_map(|r| r.as_any().downcast_ref::<StackRow>()).find(|s| s.manages(id))
}

const GROUP_STACKS: GroupFanOut = GroupFanOut {
    noun: "Stacks",
    listing: "stacks",
    path: rg_stacks_path,
    api_version: STACKS_API_VERSION,
    rows: stack_rows,
};

/// The Stacks list: the subscription's own, then every group's. One half
/// failing is a warning; both failing is the list's error.
pub async fn stream_stacks(scope: &Scope, tx: &mpsc::UnboundedSender<Event>, service: ServiceType) -> Result<usize> {
    let tenant = scope.tenant().map(str::to_string);
    let at_subscription = scope
        .stream(SUBSCRIPTION_STACKS_PATH, STACKS_API_VERSION, &[], service, "Listing subscription stacks…", tx, |page| {
            stack_rows(&page, tenant.as_deref())
        })
        .await;
    let already = *at_subscription.as_ref().unwrap_or(&0);
    let in_groups = stream_per_group(scope, tx, service, &GROUP_STACKS, already).await;
    let warn = |what: &str, e: &crate::error::Error| {
        let _ = tx.send(Event::ResourceLoadWarning {
            service,
            warning: format!("{} unread: {}", what, crate::azure::services::deployments::first_line(&e.to_string())),
        });
    };
    match (at_subscription, in_groups) {
        (Ok(a), Ok(b)) => Ok(a + b),
        (Err(e), Ok(b)) => {
            warn("The subscription's own stacks", &e);
            Ok(b)
        }
        (Ok(a), Err(e)) => {
            warn("The resource groups' stacks", &e);
            Ok(a)
        }
        (Err(e), Err(_)) => Err(e),
    }
}

// ── Template specs ────────────────────────────────────────────────────

crate::sections! {
    pub enum TemplateSpecDetailSection,
    pub static TEMPLATE_SPEC_SECTIONS = [
        Overview "Overview",
        Versions "Versions" => crate::app::App::trigger_template_spec_versions,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct TemplateSpecRow {
    pub base: ArmBase,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub modified_by: Option<String>,
}

impl TemplateSpecRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<TemplateSpecRow> {
        let s = |ptr: &str| json::str_at(v, ptr).filter(|s| !s.is_empty());
        Some(TemplateSpecRow {
            base: ArmBase::from_json(v, tenant)?,
            display_name: s("/properties/displayName"),
            description: s("/properties/description"),
            created: s("/systemData/createdAt"),
            modified: s("/systemData/lastModifiedAt"),
            modified_by: s("/systemData/lastModifiedBy"),
        })
    }
}

impl Resource for TemplateSpecRow {
    arm_row!("Template spec");

    fn state(&self) -> ResourceState {
        ResourceState::stateless()
    }
    fn state_label(&self) -> String {
        String::new()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&TEMPLATE_SPEC_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        parts.extend(self.resource_group().map(str::to_string));
        parts.extend(self.display_name.clone().filter(|d| *d != self.base.name));
        parts.extend(self.modified.clone().map(|m| format!("changed {}", json::time(Some(m)))));
        Some(parts.join(" · "))
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Display name".into(), json::opt(self.display_name.clone())),
            ("Description".into(), json::opt(self.description.clone())),
            ("Created".into(), json::time(self.created.clone())),
            ("Last changed".into(), json::time(self.modified.clone())),
            ("Changed by".into(), json::opt(self.modified_by.clone())),
        ]
    }
    /// `az ts show` has no `--ids`: `--template-spec` takes the id.
    fn cli_command(&self) -> Option<String> {
        Some(format!("az ts show --template-spec {}", shell_quote(&self.base.id)))
    }
}

/// `{spec}/versions`.
pub fn versions_path(spec_id: &str) -> String {
    format!("{}/versions", spec_id.trim_end_matches('/'))
}

/// What nebaz keeps of a template spec version: its id, name, description
/// and times, the template's parameter names and types, the resource
/// types it declares and how many linked templates it has. The template
/// itself, its variables, every `defaultValue` and the UI form definition
/// are not kept.
pub fn version_summary(v: &Value) -> Value {
    let template = v.pointer("/properties/mainTemplate");
    let mut parameters: Vec<Named> = template
        .and_then(|t| t.get("parameters"))
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, p)| (k.clone(), json::text(p, "/type"))).collect())
        .unwrap_or_default();
    parameters.sort();
    // `resources` is an array, or an object keyed by symbolic name
    // (languageVersion 2.0).
    let declared: Vec<&Value> = match template.and_then(|t| t.get("resources")) {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Object(o)) => o.values().collect(),
        _ => Vec::new(),
    };
    let mut types: Vec<String> = declared.iter().filter_map(|r| json::str_at(r, "/type")).collect();
    types.sort();
    json!({
        "id": v.get("id"),
        "name": v.get("name"),
        "description": v.pointer("/properties/description"),
        "createdAt": v.pointer("/systemData/createdAt"),
        "lastModifiedAt": v.pointer("/systemData/lastModifiedAt"),
        "lastModifiedBy": v.pointer("/systemData/lastModifiedBy"),
        "parameters": parameters.iter().map(|(n, t)| json!({"name": n, "type": t})).collect::<Vec<_>>(),
        "resourceTypes": types,
        "linkedTemplates": json::arr(v, "/properties/linkedTemplates").len(),
    })
}

/// The Versions section, over [`version_summary`] values: newest first.
pub fn versions_rows(spec: &TemplateSpecRow, versions: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    let versions = match versions {
        None | Some(Lazy::Loading) => return vec![("Versions".into(), "Loading…".into())],
        Some(Lazy::Error(e)) => return error_rows(e),
        Some(Lazy::Loaded(v)) => v,
    };
    let mut sorted: Vec<&Value> = versions.iter().collect();
    sorted.sort_by_key(|v| std::cmp::Reverse(json::str_at(v, "/lastModifiedAt").or_else(|| json::str_at(v, "/createdAt"))));
    let mut lines =
        vec![("Versions".to_string(), if sorted.is_empty() { "none".to_string() } else { format!("{}", sorted.len()) })];
    for v in sorted {
        lines.push((String::new(), String::new()));
        lines.push((json::text(v, "/name"), json::str_at(v, "/description").unwrap_or_default()));
        lines.push(("  Created".into(), json::time(json::str_at(v, "/createdAt"))));
        lines.push(("  Last changed".into(), json::time(json::str_at(v, "/lastModifiedAt"))));
        if let Some(by) = json::str_at(v, "/lastModifiedBy") {
            lines.push(("  Changed by".into(), by));
        }
        let parameters = json::arr(v, "/parameters");
        lines.push(("  Parameters".into(), if parameters.is_empty() { "none".into() } else { format!("{}", parameters.len()) }));
        for p in &parameters {
            lines.push((format!("    {}", json::text(p, "/name")), json::text(p, "/type")));
        }
        // `3 × Microsoft.App/containerApps`, one line per type.
        let types = json::strings_at(v, "/resourceTypes");
        lines.push(("  Declares".into(), if types.is_empty() { "no resources".into() } else { format!("{} resources", types.len()) }));
        let mut seen: Vec<(String, usize)> = Vec::new();
        for t in types {
            match seen.iter_mut().find(|(s, _)| *s == t) {
                Some((_, n)) => *n += 1,
                None => seen.push((t, 1)),
            }
        }
        for (t, n) in seen {
            lines.push((String::new(), if n == 1 { format!("    {}", t) } else { format!("    {} × {}", n, t) }));
        }
        match json::int_at(v, "/linkedTemplates") {
            Some(n) if n > 0 => lines.push(("  Linked templates".into(), format!("{}", n))),
            _ => {}
        }
        if let Some(id) = json::str_at(v, "/id") {
            lines.push(("  Id".into(), id));
        }
    }
    if versions.len() >= MAX_VERSIONS {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("The first {} versions; the read command lists them all", MAX_VERSIONS)));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        String::new(),
        "Names and types only: a version's template is never kept (a default value or a variable can be a secret)".into(),
    ));
    lines.push((
        "Read command".into(),
        format!(
            "az ts list -g {} -n {} --subscription {}",
            shell_quote(spec.resource_group().unwrap_or("-")),
            shell_quote(&spec.base.name),
            shell_quote(subscription_of(&spec.base.id).unwrap_or("-"))
        ),
    ));
    lines
}

/// Body lines for one section of a template spec; `None` for another type.
pub fn template_spec_section_lines(
    r: &dyn Resource,
    idx: usize,
    versions: Option<&Lazy<Vec<Value>>>,
) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<TemplateSpecRow>()?;
    use TemplateSpecDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Versions => versions_rows(x, versions),
        S::Access | S::Activity => rendered_by_app(),
        S::Related => related_rows(x),
        S::Tags => tag_rows(x.tags()),
    })
}

pub fn spec_rows(page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    page.iter()
        .filter_map(|v| TemplateSpecRow::from_json(v, tenant))
        .map(|r| Box::new(r) as Box<dyn Resource>)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-app";

    fn res(kind: &str) -> String {
        format!("{}/providers/{}", RG, kind)
    }

    fn stack_json() -> Value {
        json!({
            "id": res("Microsoft.Resources/deploymentStacks/orders"),
            "name": "orders",
            "tags": {"team": "orders"},
            "properties": {
                "provisioningState": "succeeded",
                "description": "the orders platform",
                "actionOnUnmanage": {"resources": "delete", "resourceGroups": "detach", "managementGroups": "detach"},
                "denySettings": {"mode": "denyDelete", "applyToChildScopes": false,
                    "excludedPrincipals": ["11111111-1111-1111-1111-111111111111"],
                    "excludedActions": ["Microsoft.App/containerApps/write"]},
                "bypassStackOutOfSyncError": false,
                "deploymentId": res("Microsoft.Resources/deployments/orders-26110108"),
                "duration": "PT42.5S",
                "correlationId": "c-9",
                "template": {"variables": {"k": "PLANTED-TEMPLATE"}},
                "templateLink": {"id": res("Microsoft.Resources/templateSpecs/ts-orders/versions/1.4.0"),
                    "uri": "https://st.example/main.json?sig=PLANTED-SAS"},
                "parameters": {"adminPassword": {"type": "securestring", "value": "PLANTED-PASSWORD"}, "sku": {"value": "PLANTED-SKU"}},
                "outputs": {"key": {"type": "String", "value": "PLANTED-KEY"}},
                "resources": [
                    {"id": res("Microsoft.App/containerApps/ca-web"), "status": "managed", "denyStatus": "denyDelete"},
                    {"id": res("Microsoft.Storage/storageAccounts/storders"), "status": "removeDenyFailed", "denyStatus": "none"},
                ],
                "detachedResources": [{"id": res("Microsoft.Network/publicIPAddresses/pip-old")}],
                "deletedResources": [{"id": res("Microsoft.Cache/redis/redis-old")}],
                "failedResources": [],
            }
        })
    }

    fn stack(v: &Value) -> StackRow {
        StackRow::from_json(v, None).unwrap()
    }

    #[test]
    fn section_labels_follow_the_shared_tail() {
        let labels = |d: &crate::sections::SectionDescriptor| d.sections.iter().map(|s| s.label).collect::<Vec<_>>();
        assert_eq!(
            labels(&STACK_SECTIONS),
            ["Overview", "Resources", "Settings", "Parameters", "Error", "Access", "Activity", "Related", "Tags"]
        );
        assert_eq!(labels(&TEMPLATE_SPEC_SECTIONS), ["Overview", "Versions", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn a_stack_keeps_no_value_template_or_sas_token() {
        let s = stack(&stack_json());
        let everything = format!("{:?} {}", s, s.base.raw);
        assert!(!everything.contains("PLANTED"), "a value, the template or a SAS token was kept");
        assert_eq!(
            s.parameters,
            vec![("adminPassword".to_string(), "securestring".to_string()), ("sku".to_string(), "-".to_string())]
        );
        assert_eq!(s.outputs, vec![("key".to_string(), "String".to_string())]);
        assert_eq!(s.template.as_deref(), Some("spec ts-orders 1.4.0"));
    }

    #[test]
    fn a_group_stack_reads_its_settings_state_and_command() {
        let s = stack(&stack_json());
        assert_eq!((s.state(), s.state_label()), (ResourceState::Available, "succeeded".to_string()));
        assert_eq!(s.location(), None);
        assert_eq!(s.list_summary().as_deref(), Some("rg-app · deny denyDelete · 2 resources"));
        assert_eq!(s.cli_command().as_deref(), Some("az stack group show -g rg-app -n orders --subscription 0000"));
        assert!(s.deletes_on_unmanage());
        assert!(!s.denies_nothing());
        assert_eq!(s.unmanage_summary(), "delete resources, detach resource groups, detach management groups");
        let settings = s.settings_rows();
        assert!(settings.contains(&("  Resources".to_string(), "delete".to_string())));
        assert!(settings.contains(&("  Mode".to_string(), "denyDelete".to_string())));
        assert!(settings.contains(&("  Excluded actions".to_string(), "1".to_string())));
        assert!(settings.contains(&(String::new(), "  Microsoft.App/containerApps/write".to_string())));
        assert_eq!(s.error_section_rows(), vec![(String::new(), "No error".to_string())]);
    }

    #[test]
    fn resources_show_status_detached_and_deleted_and_related_links_them() {
        let s = stack(&stack_json());
        let lines = s.resources_rows();
        assert_eq!(lines[0], ("Managed".to_string(), "2".to_string()));
        assert!(lines.contains(&("ca-web".to_string(), res("Microsoft.App/containerApps/ca-web"))));
        assert!(lines.contains(&("  Status".to_string(), "managed · deny: denyDelete".to_string())));
        assert!(lines.contains(&("⚠ storders".to_string(), res("Microsoft.Storage/storageAccounts/storders"))));
        assert!(lines.iter().any(|(k, v)| k == "Detached" && v.starts_with("1 ")));
        assert!(lines.contains(&("pip-old".to_string(), res("Microsoft.Network/publicIPAddresses/pip-old"))));
        assert!(lines.iter().any(|(k, _)| k == "Deleted"));
        let related = s.related();
        assert!(related.contains(&("Last deployment".to_string(), res("Microsoft.Resources/deployments/orders-26110108"))));
        assert!(related.contains(&("Template spec ts-orders 1.4.0".to_string(), res("Microsoft.Resources/templateSpecs/ts-orders"))));
        assert!(related.contains(&("Manages ca-web".to_string(), res("Microsoft.App/containerApps/ca-web"))));
        // The ribbon's lookup ignores case.
        assert!(s.manages(&res("microsoft.app/containerapps/CA-WEB")));
        assert!(!s.manages(&res("Microsoft.App/containerApps/other")));
        let rows = stack_rows(&[stack_json()], None);
        assert_eq!(managing_stack(&rows, &res("Microsoft.App/containerApps/ca-web")).map(|s| s.base.name.as_str()), Some("orders"));
    }

    #[test]
    fn a_stack_with_failed_resources_is_degraded_and_a_subscription_stack_has_its_own_command() {
        let mut v = stack_json();
        v["id"] = json!("/subscriptions/0000/providers/Microsoft.Resources/deploymentStacks/landing-zone");
        v["name"] = json!("landing-zone");
        v["location"] = json!("westeurope");
        v["properties"]["provisioningState"] = json!("succeededWithFailures");
        v["properties"]["denySettings"] = json!({"mode": "none"});
        v["properties"]["failedResources"] = json!([{"id": res("Microsoft.Cache/redis/redis-new"),
            "error": {"code": "SkuNotAvailable", "message": "no capacity"}}]);
        let s = stack(&v);
        assert_eq!((s.state(), s.state_label()), (ResourceState::Unavailable, "degraded".to_string()));
        assert!(s.denies_nothing());
        assert_eq!(s.list_summary().as_deref(), Some("subscription · deny none · 2 resources · ⚠ 1 failed"));
        assert_eq!(s.cli_command().as_deref(), Some("az stack sub show -n landing-zone --subscription 0000"));
        assert_eq!(s.resources_rows()[0].1, "2 · ⚠ 1 failed");
        assert!(s.error_section_rows().contains(&("  Error".to_string(), "SkuNotAvailable: no capacity".to_string())));
        assert!(s.details().iter().any(|(k, v)| k == "Record kept in" && v == "westeurope"));
        // A failure and a transition keep the ladder's words.
        v["properties"]["provisioningState"] = json!("failed");
        assert_eq!(stack(&v).state_label(), "failed");
        v["properties"]["provisioningState"] = json!("deploying");
        assert_eq!(stack(&v).state(), ResourceState::Pending);
    }

    fn spec_json() -> Value {
        json!({
            "id": res("Microsoft.Resources/templateSpecs/ts-orders"),
            "name": "ts-orders", "location": "westeurope",
            "systemData": {"createdAt": "2026-01-02T03:04:05Z", "lastModifiedAt": "2026-10-20T08:00:00Z", "lastModifiedBy": "alex@contoso.com"},
            "properties": {"displayName": "Orders platform", "description": "the orders stack"}
        })
    }

    #[test]
    fn a_template_spec_reads_its_names_times_and_command() {
        let s = TemplateSpecRow::from_json(&spec_json(), None).unwrap();
        assert_eq!(s.state(), ResourceState::stateless());
        assert_eq!(s.location(), Some("westeurope"));
        assert_eq!(s.list_summary().as_deref(), Some("rg-app · Orders platform · changed 2026-10-20 08:00:00"));
        assert_eq!(s.cli_command().unwrap(), format!("az ts show --template-spec {}", res("Microsoft.Resources/templateSpecs/ts-orders")));
        assert!(s.details().contains(&("Changed by".to_string(), "alex@contoso.com".to_string())));
    }

    #[test]
    fn a_version_keeps_names_and_types_and_never_the_template() {
        let version = |name: &str, modified: &str, resources: Value| {
            json!({
                "id": format!("{}/versions/{}", res("Microsoft.Resources/templateSpecs/ts-orders"), name),
                "name": name,
                "systemData": {"createdAt": modified, "lastModifiedAt": modified},
                "properties": {
                    "description": "adds the worker",
                    "linkedTemplates": [{"path": "modules/worker.json", "template": {"variables": {"k": "PLANTED-LINKED"}}}],
                    "uiFormDefinition": {"view": "PLANTED-FORM"},
                    "mainTemplate": {
                        "parameters": {"adminPassword": {"type": "securestring", "defaultValue": "PLANTED-DEFAULT"}, "sku": {"type": "string"}},
                        "variables": {"conn": "PLANTED-VARIABLE"},
                        "resources": resources,
                    }
                }
            })
        };
        let app = json!({"type": "Microsoft.App/containerApps", "properties": {"secret": "PLANTED-RESOURCE"}});
        let kept = vec![
            version_summary(&version("1.3.0", "2026-09-01T08:00:00Z", json!([app.clone()]))),
            // languageVersion 2.0: resources keyed by symbolic name.
            version_summary(&version("1.4.0", "2026-10-20T08:00:00Z", json!({"web": app.clone(), "worker": app, "env": {"type": "Microsoft.App/managedEnvironments"}}))),
        ];
        assert!(!format!("{:?}", kept).contains("PLANTED"), "part of a template was kept");
        let spec = TemplateSpecRow::from_json(&spec_json(), None).unwrap();
        assert_eq!(versions_rows(&spec, None)[0].1, "Loading…");
        let lines = versions_rows(&spec, Some(&Lazy::Loaded(kept)));
        assert_eq!(lines[0], ("Versions".to_string(), "2".to_string()));
        let names: Vec<&str> = lines.iter().filter(|(k, _)| k.starts_with("1.")).map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["1.4.0", "1.3.0"], "newest first");
        assert!(lines.contains(&("    adminPassword".to_string(), "securestring".to_string())));
        assert!(lines.contains(&("  Declares".to_string(), "3 resources".to_string())));
        assert!(lines.contains(&(String::new(), "    2 × Microsoft.App/containerApps".to_string())));
        assert!(lines.contains(&("  Linked templates".to_string(), "1".to_string())));
        assert_eq!(lines.last().unwrap().1, "az ts list -g rg-app -n ts-orders --subscription 0000");
        assert!(versions_rows(&spec, Some(&Lazy::Error("403 AuthorizationFailed".into()))).iter().any(|(_, v)| v.contains("403")));
    }

    #[test]
    fn a_version_id_links_its_spec() {
        let spec = res("Microsoft.Resources/templateSpecs/ts-orders");
        assert_eq!(spec_link(&format!("{}/versions/1.4.0", spec)), ("Template spec ts-orders 1.4.0".to_string(), spec.clone()));
        assert_eq!(spec_link(&spec), ("Template spec ts-orders".to_string(), spec));
    }
}
