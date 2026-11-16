//! Deployments (#225, SERVICES.md rule 47): ARM template and Bicep
//! deployments, the CloudFormation equivalent. Two sub-tabs:
//!
//! - **Group deployments**: a subscription has no list of its groups'
//!   deployments, so the provider lists the resource groups (one call),
//!   then `{group}/providers/Microsoft.Resources/deployments` per group,
//!   [`GROUP_CONCURRENCY`] at a time, at most [`MAX_GROUPS`] groups and
//!   [`MAX_PER_GROUP`] deployments each. A group's batch streams when it
//!   lands; a group that cannot be read is a warning.
//! - **Subscription deployments**: one subscription-wide list.
//!
//! A deployment's **parameter and output values are never kept**: an
//! output can be a `listKeys()` result and a plain-string parameter a
//! password. [`without_values`] drops them (and a template link's SAS
//! query, and an operation's request and response bodies) before
//! `ArmBase` keeps the raw JSON, so `e` cannot show them either. Names
//! and types stay. `exportTemplate`, `whatIf`, `validate` and `cancel`
//! are POSTs and are never sent.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource, ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::subscriptions::RESOURCE_GROUPS_API_VERSION;
use crate::azure::services::{error_rows, finish_stream, json, overview_rows, related_rows, tag_rows, ArmBase, Scope};
use crate::azure::timeline::{parse_ts, pretty_duration, rg_deployments_path, DEPLOYMENTS_API_VERSION};
use crate::error::{Error, Result};
use crate::event::{Event, LoadProgress};
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;

pub const SUBSCRIPTION_DEPLOYMENTS_PATH: &str = "/providers/Microsoft.Resources/deployments";

/// Resource groups whose deployments one load reads; past it a warning
/// says how many were left out.
pub const MAX_GROUPS: usize = 200;
/// Deployments read per group (ARM keeps at most 800 per group).
pub const MAX_PER_GROUP: usize = 200;
/// Group lists in flight at once.
pub const GROUP_CONCURRENCY: usize = 8;
/// Operations one Operations read keeps.
pub const MAX_OPERATIONS: usize = 500;
/// Deployed resources the Related section links.
const MAX_RELATED: usize = 30;

crate::sections! {
    pub enum DeploymentDetailSection,
    pub static DEPLOYMENT_SECTIONS = [
        Overview "Overview",
        Operations "Operations" => crate::app::App::trigger_deployment_operations,
        Resources "Resources",
        Parameters "Parameters",
        Error "Error",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Scrubbing ─────────────────────────────────────────────────────────

/// A deployment (or one of its operations) without what can hold a
/// secret: every parameter's and output's `value`, the query string of a
/// template or parameters link (a SAS token), and an operation's
/// `request` / `response` bodies (present when the deployment ran with a
/// debug setting).
pub fn without_values(v: &Value) -> Value {
    let mut out = v.clone();
    let Some(props) = out.get_mut("properties").and_then(Value::as_object_mut) else {
        return out;
    };
    for key in ["parameters", "outputs"] {
        if let Some(map) = props.get_mut(key).and_then(Value::as_object_mut) {
            for entry in map.values_mut() {
                match entry.as_object_mut() {
                    Some(o) => {
                        o.remove("value");
                    }
                    // Not the `{type, value}` shape: keep the name only.
                    None => *entry = Value::Null,
                }
            }
        }
    }
    for key in ["templateLink", "parametersLink"] {
        if let Some(uri) = props.get_mut(key).and_then(|l| l.get_mut("uri")) {
            if let Some(s) = uri.as_str() {
                *uri = Value::String(s.split('?').next().unwrap_or("").to_string());
            }
        }
    }
    props.remove("request");
    props.remove("response");
    out
}

// ── The row ───────────────────────────────────────────────────────────

/// `name: type` for a parameter or an output.
type Named = (String, String);

#[derive(Debug, Clone)]
pub struct DeploymentRow {
    pub base: ArmBase,
    pub timestamp: Option<String>,
    /// Unix seconds of `timestamp`, for the newest-first order.
    pub ts_secs: i64,
    pub duration: Option<String>,
    pub mode: Option<String>,
    pub correlation_id: Option<String>,
    /// `spec web 1.2`, a linked template's file name, or `None` for an
    /// inline template (Bicep, `-f`).
    pub template: Option<String>,
    /// The template spec version's ARM id, when it came from one.
    pub template_spec_id: Option<String>,
    pub template_hash: Option<String>,
    pub output_resources: Vec<String>,
    /// Each resource the template declared, with what it depends on.
    pub dependencies: Vec<(String, Vec<String>)>,
    pub parameters: Vec<Named>,
    pub outputs: Vec<Named>,
    /// `properties.error`, whole.
    pub error: Option<Value>,
}

fn named(v: &Value, ptr: &str) -> Vec<Named> {
    let mut out: Vec<Named> = v
        .pointer(ptr)
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, p)| (k.clone(), json::text(p, "/type"))).collect())
        .unwrap_or_default();
    out.sort();
    out
}

impl DeploymentRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<DeploymentRow> {
        let v = &without_values(raw);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| json::str_at(v, &format!("/properties/{}", f)).filter(|s| !s.is_empty());
        let timestamp = p("timestamp");
        let dependencies = json::arr(v, "/properties/dependencies")
            .iter()
            .filter_map(|d| Some((json::str_at(d, "/id")?, json::ids_at(d, "/dependsOn"))))
            .collect();
        Some(DeploymentRow {
            ts_secs: timestamp.as_deref().and_then(parse_ts).unwrap_or(0),
            timestamp,
            duration: p("duration").map(|d| pretty_duration(&d)),
            mode: p("mode"),
            correlation_id: p("correlationId"),
            template: crate::azure::ownership::template_of(v),
            template_spec_id: p("templateLink/id")
                .filter(|id| id.to_lowercase().contains("/microsoft.resources/templatespecs/")),
            template_hash: p("templateHash"),
            output_resources: json::ids_at(v, "/properties/outputResources"),
            dependencies,
            parameters: named(v, "/properties/parameters"),
            outputs: named(v, "/properties/outputs"),
            error: v.pointer("/properties/error").filter(|e| e.is_object()).cloned(),
            base,
        })
    }

    /// Whether it ran at the subscription, not in a group.
    pub fn is_subscription_scope(&self) -> bool {
        resource_group_of(&self.base.id).is_none()
    }

    fn succeeded(&self) -> bool {
        self.base.provisioning_state.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("succeeded"))
    }

    /// `DeploymentFailed: At least one resource…`, the top of the error.
    fn error_head(&self) -> Option<String> {
        let e = self.error.as_ref()?;
        Some(format!("{}: {}", json::text(e, "/code"), json::text(e, "/message")))
    }

    fn resources_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.output_resources.is_empty() {
            let why = if self.succeeded() {
                "No resources deployed"
            } else {
                "No resources recorded (a deployment that did not succeed lists none; see Operations)"
            };
            lines.push((String::new(), why.into()));
        }
        for id in &self.output_resources {
            lines.push((format!("Deployed {}", name_of_id(id)), id.clone()));
        }
        if !self.dependencies.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("Dependencies".into(), "what the template declared, and what each waits for".into()));
            for (id, depends_on) in &self.dependencies {
                lines.push((name_of_id(id).to_string(), id.clone()));
                for dep in depends_on {
                    lines.push(("  depends on".into(), dep.clone()));
                }
            }
        }
        if !self.output_resources.is_empty() || !self.dependencies.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "⏎ on a line jumps to it (y copies the id)".into()));
        }
        lines
    }

    fn parameters_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        let mut list = |title: &str, none: &str, items: &[Named]| {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push((title.to_string(), if items.is_empty() { none.to_string() } else { String::new() }));
            for (name, kind) in items {
                lines.push((format!("  {}", name), kind.clone()));
            }
        };
        list("Parameters", "none", &self.parameters);
        list("Outputs", "none", &self.outputs);
        lines.push((String::new(), String::new()));
        lines.push((
            String::new(),
            "Names and types only: values are never kept (an output can be a key, a parameter a password)".into(),
        ));
        lines
    }

    fn error_section_rows(&self) -> Vec<(String, String)> {
        match &self.error {
            None => vec![(String::new(), "No error".into())],
            Some(e) => {
                let mut lines = Vec::new();
                error_chain(e, 0, &mut lines);
                lines
            }
        }
    }

    /// `az deployment operation group list …`, the Operations read.
    fn operations_command(&self) -> String {
        let sub = shell_quote(subscription_of(&self.base.id).unwrap_or("-"));
        match resource_group_of(&self.base.id) {
            Some(rg) => format!(
                "az deployment operation group list -g {} -n {} --subscription {}",
                shell_quote(rg),
                shell_quote(&self.base.name),
                sub
            ),
            None => format!("az deployment operation sub list -n {} --subscription {}", shell_quote(&self.base.name), sub),
        }
    }
}

/// One ARM error and its nested `details`, indented by depth.
fn error_chain(e: &Value, depth: usize, lines: &mut Vec<(String, String)>) {
    // A cyclic or absurdly deep body is not worth the screen.
    if depth > 8 {
        return;
    }
    let pad = "  ".repeat(depth);
    lines.push((format!("{}{}", pad, json::text(e, "/code")), json::text(e, "/message")));
    if let Some(target) = json::str_at(e, "/target") {
        lines.push((format!("{}  target", pad), target));
    }
    for d in json::arr(e, "/details") {
        error_chain(&d, depth + 1, lines);
    }
}

impl Resource for DeploymentRow {
    fn id(&self) -> &str {
        &self.base.id
    }
    fn name(&self) -> &str {
        &self.base.name
    }
    fn resource_type(&self) -> &str {
        "Deployment"
    }
    fn tags(&self) -> &std::collections::HashMap<String, String> {
        &self.base.tags
    }
    /// A deployment belongs to its group or subscription, not a region
    /// (a subscription deployment's `location` is where its record is
    /// kept): the `R` filter never hides one.
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
        state_ladder(self.base.provisioning_state.as_deref(), Some((ResourceState::Available, "Succeeded"))).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), Some((ResourceState::Available, "Succeeded"))).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&DEPLOYMENT_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        parts.extend(self.resource_group().map(str::to_string));
        parts.push(json::time(self.timestamp.clone()));
        parts.extend(self.duration.clone());
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
            ("Timestamp".into(), json::time(self.timestamp.clone())),
            ("Duration".into(), json::opt(self.duration.clone())),
            ("Mode".into(), json::opt(self.mode.clone())),
            ("Template".into(), self.template.clone().unwrap_or_else(|| "inline (Bicep or a local file)".into())),
            ("Template hash".into(), json::opt(self.template_hash.clone())),
            ("Correlation id".into(), json::opt(self.correlation_id.clone())),
            ("Resources".into(), format!("{} deployed", self.output_resources.len())),
        ];
        if self.is_subscription_scope() && !self.base.location.is_empty() {
            d.push(("Record kept in".into(), self.base.location.clone()));
        }
        if let Some(e) = self.error_head() {
            d.push(("Error".into(), format!("⚠ {}", e)));
        }
        d
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut lines = scope_related(&self.base.id);
        if let Some(spec) = &self.template_spec_id {
            lines.push(("Template spec version".into(), spec.clone()));
        }
        for id in self.output_resources.iter().take(MAX_RELATED) {
            lines.push((format!("Deployed {}", name_of_id(id)), id.clone()));
        }
        lines
    }
    fn cli_command(&self) -> Option<String> {
        let sub = shell_quote(subscription_of(&self.base.id)?);
        Some(match resource_group_of(&self.base.id) {
            Some(rg) => format!(
                "az deployment group show -g {} -n {} --subscription {}",
                shell_quote(rg),
                shell_quote(&self.base.name),
                sub
            ),
            None => format!("az deployment sub show -n {} --subscription {}", shell_quote(&self.base.name), sub),
        })
    }
}

/// A deployment row's time, for the newest-first default order.
pub fn time_of(r: &dyn Resource) -> Option<i64> {
    r.as_any().downcast_ref::<DeploymentRow>().map(|d| d.ts_secs)
}

// ── Operations (lazy) ─────────────────────────────────────────────────

/// `{deployment}/operations`.
pub fn operations_path(deployment_id: &str) -> String {
    format!("{}/operations", deployment_id.trim_end_matches('/'))
}

fn operation_failed(op: &Value) -> bool {
    matches!(json::text(op, "/properties/provisioningState").to_lowercase().as_str(), "failed" | "canceled")
}

/// The error an operation ended with: `statusMessage` is an object with
/// an `error` (or is the error), or a plain string.
fn operation_error(op: &Value) -> Option<String> {
    let status = op.pointer("/properties/statusMessage")?;
    if let Some(s) = status.as_str() {
        return Some(s.to_string()).filter(|s| !s.is_empty());
    }
    let e = status.get("error").unwrap_or(status);
    let code = json::str_at(e, "/code")?;
    // The innermost detail is the provider's own words.
    let mut message = json::text(e, "/message");
    if let Some(inner) = json::arr(e, "/details").first().and_then(|d| json::str_at(d, "/message")) {
        message = inner;
    }
    Some(format!("{}: {}", code, message))
}

fn operation_rows(op: &Value) -> Vec<(String, String)> {
    let p = |f: &str| json::str_at(op, &format!("/properties/{}", f)).filter(|s| !s.is_empty());
    let target = p("targetResource/id");
    let what = match &target {
        Some(id) => name_of_id(id).to_string(),
        None => p("provisioningOperation").unwrap_or_else(|| "operation".into()),
    };
    let failed = operation_failed(op);
    let mut head = vec![format!(
        "{}{}",
        if failed { "⚠ " } else { "" },
        p("provisioningState").unwrap_or_else(|| "-".into()).to_lowercase()
    )];
    if target.is_some() {
        head.extend(p("provisioningOperation"));
    }
    head.extend(p("statusCode"));
    head.extend(p("duration").map(|d| pretty_duration(&d)));
    let mut lines = vec![(String::new(), String::new()), (what, head.join(" · "))];
    if let Some(kind) = p("targetResource/resourceType") {
        lines.push(("  Type".into(), kind));
    }
    if let Some(id) = target {
        lines.push(("  Resource".into(), id));
    }
    lines.push(("  Time".into(), json::time(p("timestamp"))));
    if let Some(e) = operation_error(op).filter(|_| failed) {
        lines.push(("  Error".into(), e));
    }
    lines
}

/// The Operations section: what the deployment did to each resource, the
/// failed ones first, then newest first.
pub fn operations_rows(r: &DeploymentRow, operations: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    let ops = match operations {
        None | Some(Lazy::Loading) => return vec![("Operations".into(), "Loading…".into())],
        Some(Lazy::Error(e)) => return error_rows(e),
        Some(Lazy::Loaded(ops)) => ops,
    };
    let mut sorted: Vec<&Value> = ops.iter().collect();
    sorted.sort_by_key(|op| (!operation_failed(op), std::cmp::Reverse(json::str_at(op, "/properties/timestamp"))));
    let failed = sorted.iter().filter(|op| operation_failed(op)).count();
    let mut lines = vec![(
        "Operations".into(),
        match (sorted.len(), failed) {
            (0, _) => "none recorded".into(),
            (n, 0) => format!("{}", n),
            (n, f) => format!("{} · ⚠ {} failed", n, f),
        },
    )];
    for op in sorted {
        lines.extend(operation_rows(op));
    }
    if ops.len() >= MAX_OPERATIONS {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("The first {} operations; the read command lists them all", MAX_OPERATIONS)));
    }
    lines.push((String::new(), String::new()));
    lines.push(("Read command".into(), r.operations_command()));
    lines
}

/// Body lines for one section of a deployment; `None` for another type.
pub fn deployment_section_lines(
    r: &dyn Resource,
    idx: usize,
    operations: Option<&Lazy<Vec<Value>>>,
) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<DeploymentRow>()?;
    use DeploymentDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Operations => operations_rows(x, operations),
        S::Resources => x.resources_rows(),
        S::Parameters => x.parameters_rows(),
        S::Error => x.error_section_rows(),
        S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => related_rows(x),
        S::Tags => tag_rows(x.tags()),
    })
}

pub fn rows(page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    page.iter()
        .filter_map(|v| DeploymentRow::from_json(v, tenant))
        .map(|r| Box::new(r) as Box<dyn Resource>)
        .collect()
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct DeploymentsService {
    scope: Scope,
}

impl DeploymentsService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    /// Every group's deployments, a batch per group as it lands. Returns
    /// how many rows streamed; `Err` only when nothing could (the group
    /// list failed, or every group did).
    async fn stream_groups(&self, tx: &mpsc::UnboundedSender<Event>, service: ServiceType) -> Result<usize> {
        let arm = self.scope.arm()?.clone();
        let sub = self.scope.current()?.id.clone();
        let tenant = self.scope.tenant().map(str::to_string);
        let mut groups: Vec<String> = self
            .scope
            .list("/resourcegroups", RESOURCE_GROUPS_API_VERSION)
            .await?
            .iter()
            .filter_map(|g| json::str_at(g, "/name"))
            .collect();
        groups.sort_by_key(|g| g.to_lowercase());
        let mut warnings = Vec::new();
        if groups.len() > MAX_GROUPS {
            warnings.push(format!(
                "Deployments: {} resource groups, the first {} by name read",
                groups.len(),
                MAX_GROUPS
            ));
            groups.truncate(MAX_GROUPS);
        }
        let total_groups = groups.len();
        let gate = Arc::new(tokio::sync::Semaphore::new(GROUP_CONCURRENCY));
        let mut tasks = tokio::task::JoinSet::new();
        for rg in groups {
            let arm = arm.clone();
            let gate = gate.clone();
            let path = rg_deployments_path(&sub, &rg);
            tasks.spawn(async move {
                let _permit = gate.acquire_owned().await;
                let mut items = Vec::new();
                let r = arm
                    .list_pages_while(&path, DEPLOYMENTS_API_VERSION, &[], |page| {
                        items.extend(page);
                        items.len() < MAX_PER_GROUP
                    })
                    .await;
                (rg, r.map(|_| items))
            });
        }
        let (mut loaded, mut done) = (0usize, 0usize);
        let mut failed: Vec<(String, Error)> = Vec::new();
        let mut capped: Vec<String> = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((rg, result)) = joined else { continue };
            done += 1;
            match result {
                Ok(mut items) => {
                    if items.len() >= MAX_PER_GROUP {
                        items.truncate(MAX_PER_GROUP);
                        capped.push(rg);
                    }
                    let resources = rows(&items, tenant.as_deref());
                    loaded += resources.len();
                    let _ = tx.send(Event::ResourcesPartiallyLoaded {
                        service,
                        resources,
                        progress: LoadProgress {
                            loaded_count: loaded,
                            total_count: None,
                            status_message: Some(format!("Listing deployments… {}/{} groups", done, total_groups)),
                        },
                    });
                }
                Err(e) => failed.push((rg, e)),
            }
        }
        if total_groups > 0 && failed.len() == total_groups {
            failed.sort_by(|a, b| a.0.cmp(&b.0));
            return Err(failed.remove(0).1);
        }
        if !failed.is_empty() {
            failed.sort_by(|a, b| a.0.cmp(&b.0));
            let (rg, e) = &failed[0];
            warnings.push(format!(
                "Deployments unread in {} of {} groups (first: {}: {})",
                failed.len(),
                total_groups,
                rg,
                first_line(&e.to_string())
            ));
        }
        if !capped.is_empty() {
            capped.sort();
            warnings.push(format!(
                "Deployments: the first {} read in {} ({})",
                MAX_PER_GROUP,
                if capped.len() == 1 { "one group".to_string() } else { format!("{} groups", capped.len()) },
                capped.join(", ")
            ));
        }
        for warning in warnings {
            let _ = tx.send(Event::ResourceLoadWarning { service, warning });
        }
        Ok(loaded)
    }
}

fn first_line(e: &str) -> String {
    let first = e.lines().next().unwrap_or(e);
    if first.chars().count() > 160 {
        format!("{}…", first.chars().take(160).collect::<String>())
    } else {
        first.to_string()
    }
}

#[async_trait]
impl AzureService for DeploymentsService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Deployments
    }

    fn name(&self) -> &str {
        "Deployments"
    }

    /// The whole list (headless): the stream, collected.
    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.list_resources_streaming(view, tx, ServiceType::Deployments).await?;
        let mut all = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let Event::ResourcesPartiallyLoaded { resources, .. } = ev {
                all.extend(resources);
            }
        }
        Ok(all)
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let r = match view {
            JumpView::SubscriptionDeployments => {
                let tenant = self.scope.tenant().map(str::to_string);
                self.scope
                    .stream(
                        SUBSCRIPTION_DEPLOYMENTS_PATH,
                        DEPLOYMENTS_API_VERSION,
                        &[],
                        service_type,
                        "Listing subscription deployments…",
                        &event_tx,
                        |page| rows(&page, tenant.as_deref()),
                    )
                    .await
            }
            _ => self.stream_groups(&event_tx, service_type).await,
        };
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, DEPLOYMENTS_API_VERSION).await?;
        rows(std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-app";

    fn app_id() -> String {
        format!("{}/providers/Microsoft.App/containerApps/ca-web", RG)
    }

    fn failed() -> Value {
        json!({
            "id": format!("{}/providers/Microsoft.Resources/deployments/web-v2", RG),
            "name": "web-v2",
            "tags": {"source": "ci"},
            "properties": {
                "provisioningState": "Failed",
                "timestamp": "2026-11-01T10:03:00.1Z",
                "duration": "PT1M10.4S",
                "mode": "Incremental",
                "correlationId": "c-1",
                "templateLink": {"uri": "https://st.example/t/main.json?sv=2024&sig=PLANTED-SAS"},
                "parameters": {
                    "adminPassword": {"type": "String", "value": "PLANTED-PASSWORD"},
                    "sku": {"type": "String", "value": "B1"},
                },
                "outputs": {"storageKey": {"type": "String", "value": "PLANTED-KEY"}},
                "outputResources": [],
                "dependencies": [{"id": app_id(), "dependsOn": [{"id": format!("{}/providers/Microsoft.App/managedEnvironments/env", RG)}]}],
                "error": {"code": "DeploymentFailed", "message": "At least one operation failed.",
                    "details": [{"code": "ContainerAppOperationError", "message": "image not found",
                        "details": [{"code": "Inner", "message": "MANIFEST_UNKNOWN"}]}]},
            }
        })
    }

    fn row(v: &Value) -> DeploymentRow {
        DeploymentRow::from_json(v, None).unwrap()
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = DEPLOYMENT_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Operations", "Resources", "Parameters", "Error", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn values_never_reach_the_row_or_its_raw_json() {
        let r = row(&failed());
        let everything = format!("{:?} {}", r, r.base.raw);
        assert!(!everything.contains("PLANTED"), "a value, key or SAS token was kept");
        assert_eq!(r.parameters, vec![("adminPassword".to_string(), "String".to_string()), ("sku".into(), "String".into())]);
        assert_eq!(r.outputs, vec![("storageKey".to_string(), "String".to_string())]);
        assert_eq!(r.template.as_deref(), Some("main.json"));
        let lines = r.parameters_rows();
        assert!(lines.iter().any(|(k, v)| k == "  adminPassword" && v == "String"));
        // An operation's request and response bodies go too.
        let op = without_values(&json!({"properties": {"request": {"content": {"p": "PLANTED"}}, "response": {"content": "PLANTED"}, "statusCode": "OK"}}));
        assert_eq!(op, json!({"properties": {"statusCode": "OK"}}));
    }

    #[test]
    fn a_group_deployment_reads_its_state_scope_and_command() {
        let r = row(&failed());
        assert_eq!(r.state(), ResourceState::Unavailable);
        assert_eq!(r.state_label(), "failed");
        assert_eq!(r.resource_group(), Some("rg-app"));
        assert_eq!(r.location(), None, "the R filter never hides a deployment");
        assert_eq!(r.list_summary().as_deref(), Some("rg-app · 2026-11-01 10:03:00 · 1m 10s"));
        assert_eq!(r.cli_command().as_deref(), Some("az deployment group show -g rg-app -n web-v2 --subscription 0000"));
        assert!(r.details().iter().any(|(k, v)| k == "Error" && v.starts_with("⚠ DeploymentFailed: ")));
        assert_eq!(time_of(&r), parse_ts("2026-11-01T10:03:00.1Z"));
    }

    #[test]
    fn a_subscription_deployment_succeeds_and_links_what_it_deployed() {
        let rg = "/subscriptions/0000/resourceGroups/rg-net";
        let spec = "/subscriptions/0000/resourceGroups/rg-specs/providers/Microsoft.Resources/templateSpecs/baseline/versions/1.2";
        let r = row(&json!({
            "id": "/subscriptions/0000/providers/Microsoft.Resources/deployments/baseline",
            "name": "baseline", "location": "westeurope",
            "properties": {"provisioningState": "Succeeded", "templateLink": {"id": spec},
                "outputResources": [{"id": rg}]}
        }));
        assert!(r.is_subscription_scope());
        assert_eq!((r.state(), r.state_label()), (ResourceState::Available, "succeeded".to_string()));
        assert_eq!(r.cli_command().as_deref(), Some("az deployment sub show -n baseline --subscription 0000"));
        assert_eq!(r.template.as_deref(), Some("spec baseline 1.2"));
        let related = r.related();
        assert!(related.contains(&("Template spec version".to_string(), spec.to_string())));
        assert!(related.contains(&("Deployed rg-net".to_string(), rg.to_string())));
        assert!(r.details().iter().any(|(k, v)| k == "Record kept in" && v == "westeurope"));
        assert_eq!(r.error_section_rows(), vec![(String::new(), "No error".to_string())]);
    }

    #[test]
    fn the_error_section_walks_the_nested_details() {
        let lines = row(&failed()).error_section_rows();
        let keys: Vec<&str> = lines.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["DeploymentFailed", "  ContainerAppOperationError", "    Inner"]);
        assert_eq!(lines[2].1, "MANIFEST_UNKNOWN");
    }

    #[test]
    fn resources_list_dependencies_and_say_why_a_failure_has_none() {
        let lines = row(&failed()).resources_rows();
        assert!(lines[0].1.starts_with("No resources recorded"));
        assert!(lines.iter().any(|(k, v)| k == "ca-web" && *v == app_id()));
        assert!(lines.iter().any(|(k, v)| k == "  depends on" && v.ends_with("/managedEnvironments/env")));
    }

    #[test]
    fn operations_put_the_failed_first_with_their_error() {
        let r = row(&failed());
        let ops = vec![
            json!({"properties": {"provisioningOperation": "Create", "provisioningState": "Succeeded", "statusCode": "OK",
                "timestamp": "2026-11-01T10:02:00Z", "duration": "PT5S",
                "targetResource": {"id": format!("{}/providers/Microsoft.App/managedEnvironments/env", RG), "resourceType": "Microsoft.App/managedEnvironments"}}}),
            json!({"properties": {"provisioningOperation": "Create", "provisioningState": "Failed", "statusCode": "BadRequest",
                "timestamp": "2026-11-01T10:01:00Z", "duration": "PT1M2.8S",
                "statusMessage": {"status": "Failed", "error": {"code": "ContainerAppOperationError", "message": "image not found"}},
                "targetResource": {"id": app_id(), "resourceType": "Microsoft.App/containerApps"}}}),
            json!({"properties": {"provisioningOperation": "EvaluateDeploymentOutput", "provisioningState": "Succeeded",
                "timestamp": "2026-11-01T10:03:00Z"}}),
        ];
        assert_eq!(operations_rows(&r, None)[0].1, "Loading…");
        let lines = operations_rows(&r, Some(&Lazy::Loaded(ops)));
        assert_eq!(lines[0], ("Operations".to_string(), "3 · ⚠ 1 failed".to_string()));
        let heads: Vec<&str> = lines.iter().filter(|(k, _)| !k.is_empty() && !k.starts_with(' ')).map(|(k, _)| k.as_str()).collect();
        assert_eq!(heads, ["Operations", "ca-web", "EvaluateDeploymentOutput", "env", "Read command"]);
        assert!(lines.iter().any(|(k, v)| k == "ca-web" && v == "⚠ failed · Create · BadRequest · 1m 2s"));
        assert!(lines.iter().any(|(k, v)| k == "  Resource" && *v == app_id()));
        assert!(lines.iter().any(|(k, v)| k == "  Error" && v == "ContainerAppOperationError: image not found"));
        assert_eq!(lines.last().unwrap().1, "az deployment operation group list -g rg-app -n web-v2 --subscription 0000");
        assert!(operations_rows(&r, Some(&Lazy::Error("403 AuthorizationFailed".into()))).iter().any(|(_, v)| v.contains("403")));
    }
}
