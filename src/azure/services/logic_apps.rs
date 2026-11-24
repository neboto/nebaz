//! Logic Apps (#159, SERVICES.md rule 49): the Logic Apps tab in the
//! Integration group. **Workflows** are Consumption logic apps, one
//! subscription-wide list of `Microsoft.Logic/workflows`; a workflow's
//! triggers and its latest runs are lazy sections, one list per workflow
//! each. **API connections** (`Microsoft.Web/connections`, what a
//! workflow's managed connectors sign in with) have no subscription-wide
//! list: ARM lists them per resource group, so the sub-tab asks the
//! generic resources list which groups hold one and lists each, as the
//! Hybrid tab does. Logic Apps Standard are App Service sites and list
//! with the function apps (`@func`), never here.
//!
//! **Never kept** ([`without_secrets`], before a row or the store holds a
//! body): a workflow definition beyond its outline (an action's inputs
//! can carry a password, a key in a header or a `?code=` / `sig=` in a
//! URI: only each step's type, method, stripped URI and connector are
//! kept), every workflow parameter's value (only `$connections`' ids
//! stay), a run's inputs, outputs, their content links (SAS URLs) and
//! tracked properties, a connection's parameter values and test links.
//! **Never read**: a trigger's callback URL (`listCallbackUrl`, a POST
//! that returns a signed URL), trigger histories and action repetitions
//! (their content links are SAS URLs), connection keys and consent links
//! (POSTs). The access endpoint (the workflow's own host) is shown as
//! text, never called.

use crate::azure::resource::{name_of_id, scope_related, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::all_resources::RESOURCES_API_VERSION;
use crate::azure::services::api_management::strip_url;
use crate::azure::services::directory::iso_to_unix;
use crate::azure::services::governance::Warm;
use crate::azure::services::hybrid::groups_of;
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows_with, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::{Event, LoadProgress};
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::{json as j, Map, Value};
use tokio::sync::mpsc;

/// The newest stable version (Microsoft Learn's REST reference lists
/// `2019-05-01` as current, checked 2026-11-24).
pub const LOGIC_API_VERSION: &str = "2019-05-01";
/// `Microsoft.Web/connections`' only stable version.
pub const CONNECTIONS_API_VERSION: &str = "2016-06-01";
const WORKFLOWS_PATH: &str = "/providers/Microsoft.Logic/workflows";
const CONNECTION_TYPE: &str = "Microsoft.Web/connections";

/// The most triggers a workflow's Triggers section reads.
pub const MAX_TRIGGERS: usize = 100;
/// The latest runs the Runs section reads (`$top`, newest first).
pub const MAX_RUNS: usize = 25;

crate::sections! {
    pub enum WorkflowDetailSection,
    pub static WORKFLOW_SECTIONS = [
        Overview "Overview",
        Definition "Definition",
        Network "Network",
        Triggers "Triggers" => crate::app::App::trigger_logic_triggers,
        Runs "Runs" => crate::app::App::trigger_logic_runs,
        Connections "Connections" => crate::app::App::trigger_logic_connection_list,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ConnectionDetailSection,
    pub static CONNECTION_SECTIONS = [
        Overview "Overview",
        Status "Status",
        UsedBy "Used by" => crate::app::App::trigger_logic_workflow_list,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_logic_workflow_list,
        Tags "Tags",
    ]
}

// ── Secrets out ───────────────────────────────────────────────────────

/// The connector key in an `ApiConnection` step's host expression:
/// `@parameters('$connections')['office365']['connectionId']` → `office365`.
fn connector_key(expr: &str) -> Option<String> {
    let rest = expr.split("$connections')").nth(1)?;
    let start = rest.find("['")? + 2;
    let end = rest[start..].find("']")? + start;
    Some(rest[start..end].to_string())
}

/// One trigger or action reduced to what the outline shows: its type and
/// kind, `runAfter`, recurrence, the method, a stripped URI and path, the
/// connector, the authentication *type*, whether its data is secured, and
/// its nested steps. Everything else (bodies, headers, queries, the
/// password, expressions) is gone.
fn outline_step(v: &Value) -> Value {
    let mut out = Map::new();
    for key in ["type", "kind", "runAfter", "recurrence"] {
        if let Some(x) = v.get(key) {
            out.insert(key.into(), x.clone());
        }
    }
    if let Some(inputs) = v.get("inputs").filter(|i| i.is_object()) {
        let mut kept = Map::new();
        if let Some(m) = inputs.get("method").and_then(Value::as_str) {
            kept.insert("method".into(), j!(m));
        }
        for key in ["uri", "path"] {
            if let Some(s) = inputs.get(key).and_then(Value::as_str) {
                kept.insert(key.into(), j!(strip_url(s)));
            }
        }
        if let Some(c) = inputs.pointer("/host/connection/name").and_then(Value::as_str) {
            kept.insert("connector".into(), j!(connector_key(c).unwrap_or_else(|| "?".into())));
        }
        if let Some(t) = inputs.pointer("/authentication/type").and_then(Value::as_str) {
            kept.insert("authentication".into(), j!(t));
        }
        if let Some(w) = inputs.pointer("/host/workflow/id").and_then(Value::as_str) {
            kept.insert("workflow".into(), j!(w));
        }
        if let Some(f) = inputs.pointer("/function/id").and_then(Value::as_str) {
            kept.insert("function".into(), j!(f));
        }
        if !kept.is_empty() {
            out.insert("inputs".into(), Value::Object(kept));
        }
    }
    if v.pointer("/runtimeConfiguration/secureData").is_some() {
        out.insert("secureData".into(), j!(true));
    }
    let nested = |m: Option<&Value>| -> Option<Value> {
        let m = m?.as_object()?;
        Some(Value::Object(m.iter().map(|(k, s)| (k.clone(), outline_step(s))).collect()))
    };
    if let Some(a) = nested(v.get("actions")) {
        out.insert("actions".into(), a);
    }
    if let Some(a) = nested(v.pointer("/else/actions")) {
        out.insert("else".into(), j!({ "actions": a }));
    }
    if let Some(cases) = v.get("cases").and_then(Value::as_object) {
        let kept: Map<String, Value> = cases
            .iter()
            .map(|(k, c)| (k.clone(), j!({ "actions": nested(c.get("actions")).unwrap_or_else(|| j!({})) })))
            .collect();
        out.insert("cases".into(), Value::Object(kept));
    }
    if let Some(a) = nested(v.pointer("/default/actions")) {
        out.insert("default".into(), j!({ "actions": a }));
    }
    Value::Object(out)
}

/// The definition's outline: each trigger and action through
/// [`outline_step`], each parameter by name and type (never a default).
fn outline_definition(d: &Value) -> Value {
    let steps = |key: &str| -> Value {
        Value::Object(
            d.get(key)
                .and_then(Value::as_object)
                .map(|m| m.iter().map(|(k, s)| (k.clone(), outline_step(s))).collect())
                .unwrap_or_default(),
        )
    };
    let params: Map<String, Value> = d
        .get("parameters")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, p)| (k.clone(), j!({ "type": p.get("type").cloned().unwrap_or(Value::Null) }))).collect())
        .unwrap_or_default();
    j!({ "triggers": steps("triggers"), "actions": steps("actions"), "parameters": params })
}

/// The workflow's parameters: each by its type, never its value, except
/// `$connections`, whose entries keep only the connection's id and name.
fn scrub_parameters(p: &Value) -> Value {
    let Some(m) = p.as_object() else { return Value::Null };
    let mut out = Map::new();
    for (k, v) in m {
        let mut kept = Map::new();
        if let Some(t) = v.get("type") {
            kept.insert("type".into(), t.clone());
        }
        if k == "$connections" {
            let entries: Map<String, Value> = v
                .get("value")
                .and_then(Value::as_object)
                .map(|e| {
                    e.iter()
                        .map(|(name, c)| {
                            let mut c2 = Map::new();
                            for f in ["connectionId", "connectionName", "id"] {
                                if let Some(x) = c.get(f).and_then(Value::as_str) {
                                    c2.insert(f.into(), j!(x));
                                }
                            }
                            (name.clone(), Value::Object(c2))
                        })
                        .collect()
                })
                .unwrap_or_default();
            kept.insert("value".into(), Value::Object(entries));
        }
        out.insert(k.clone(), Value::Object(kept));
    }
    Value::Object(out)
}

/// A workflow or a connection with every credential removed: what a row
/// parses and keeps for `e`. A workflow keeps its definition's outline and
/// its parameters' types; a connection loses its parameter values (the
/// non-secret ones keep their names) and its test links.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(props) = v.pointer_mut("/properties").and_then(Value::as_object_mut) {
        if let Some(d) = props.get("definition") {
            let outlined = outline_definition(d);
            props.insert("definition".into(), outlined);
        }
        if let Some(p) = props.get("parameters") {
            let scrubbed = scrub_parameters(p);
            props.insert("parameters".into(), scrubbed);
        }
        for key in ["parameterValues", "customParameterValues", "parameterValueSet", "testLinks", "testRequests"] {
            props.remove(key);
        }
        if let Some(Value::Object(m)) = props.get_mut("nonSecretParameterValues") {
            for val in m.values_mut() {
                *val = j!("");
            }
        }
    }
    v
}

/// A run with only its outcome: status, code, times, error, correlation,
/// and the trigger's name, status and times. Inputs, outputs, their
/// content links (SAS URLs), the response and tracked properties are gone.
pub fn run_outline(v: &Value) -> Value {
    let pick = |src: &Value, keys: &[&str]| -> Map<String, Value> {
        keys.iter().filter_map(|k| src.get(*k).map(|x| (k.to_string(), x.clone()))).collect()
    };
    let p = v.get("properties").cloned().unwrap_or(Value::Null);
    let mut props = pick(&p, &["status", "code", "startTime", "endTime", "waitEndTime", "correlation"]);
    if let Some(e) = p.get("error") {
        props.insert("error".into(), Value::Object(pick(e, &["code", "message"])));
    }
    if let Some(t) = p.get("trigger") {
        let mut trig = pick(t, &["name", "status", "code", "startTime", "endTime", "scheduledTime"]);
        if let Some(e) = t.get("error") {
            trig.insert("error".into(), Value::Object(pick(e, &["code", "message"])));
        }
        props.insert("trigger".into(), Value::Object(trig));
    }
    let mut out = pick(v, &["id", "name", "type"]);
    out.insert("properties".into(), Value::Object(props));
    Value::Object(out)
}

/// A trigger with its state, schedule and last and next fire: nothing of
/// its inputs (a trigger body holds no callback URL, but nothing else is
/// needed either).
pub fn trigger_outline(v: &Value) -> Value {
    let p = v.get("properties").cloned().unwrap_or(Value::Null);
    let props: Map<String, Value> = [
        "provisioningState",
        "state",
        "status",
        "createdTime",
        "changedTime",
        "lastExecutionTime",
        "nextExecutionTime",
        "recurrence",
    ]
    .iter()
    .filter_map(|k| p.get(*k).map(|x| (k.to_string(), x.clone())))
    .collect();
    j!({ "id": v.get("id"), "name": v.get("name"), "properties": props })
}

// ── Workflows ─────────────────────────────────────────────────────────

/// One step of the outline, flattened with its depth.
#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub kind: String,
    pub depth: usize,
    /// `POST https://host/path?…`, `via office365 · /v2/Mail`, `every 15 Minute`.
    pub detail: Option<String>,
    pub secure: bool,
}

/// `every 15 minutes`, `every day`.
fn recurrence_text(r: &Value) -> Option<String> {
    let f = json::str_at(r, "/frequency")?.to_lowercase();
    match json::int_at(r, "/interval").unwrap_or(1) {
        1 => Some(format!("every {}", f)),
        n => Some(format!("every {} {}s", n, f)),
    }
}

fn step_of(name: &str, v: &Value, depth: usize) -> Step {
    let kind = json::str_at(v, "/type").unwrap_or_else(|| "-".into());
    let connector = json::str_at(v, "/inputs/connector");
    let method = json::str_at(v, "/inputs/method");
    let detail = if let Some(c) = &connector {
        Some(match json::str_at(v, "/inputs/path") {
            Some(path) => format!("via {} · {}{}", c, method.map(|m| format!("{} ", m)).unwrap_or_default(), path),
            None => format!("via {}", c),
        })
    } else if let Some(uri) = json::str_at(v, "/inputs/uri") {
        let auth = json::str_at(v, "/inputs/authentication").map(|a| format!(" · {} auth", a)).unwrap_or_default();
        Some(format!("{}{}{}", method.map(|m| format!("{} ", m)).unwrap_or_default(), uri, auth))
    } else if let Some(r) = v.get("recurrence") {
        recurrence_text(r)
    } else if let Some(w) = json::str_at(v, "/inputs/workflow") {
        Some(format!("workflow {}", name_of_id(&w)))
    } else if let Some(f) = json::str_at(v, "/inputs/function") {
        Some(format!("function {}", name_of_id(&f)))
    } else {
        json::str_at(v, "/kind").map(|k| format!("kind {}", k))
    };
    Step { name: name.to_string(), kind, depth, detail, secure: json::bool_at(v, "/secureData") == Some(true) }
}

/// The steps of a `{name: step}` map in run order: a step after the ones
/// it runs after (ties by name), each followed by its nested branches.
fn flatten(m: Option<&Value>, depth: usize, out: &mut Vec<Step>) {
    let Some(m) = m.and_then(Value::as_object) else { return };
    let mut left: Vec<(&String, &Value)> = m.iter().collect();
    left.sort_by_key(|(k, _)| k.to_lowercase());
    let mut placed: Vec<String> = Vec::new();
    while !left.is_empty() {
        let ready = left.iter().position(|(_, s)| {
            s.get("runAfter")
                .and_then(Value::as_object)
                .is_none_or(|r| r.keys().all(|k| placed.contains(k) || !m.contains_key(k)))
        });
        // A cycle (an invalid definition) falls back to name order.
        let (name, s) = left.remove(ready.unwrap_or(0));
        out.push(step_of(name, s, depth));
        placed.push(name.clone());
        flatten(s.get("actions"), depth + 1, out);
        if let Some(e) = s.pointer("/else/actions") {
            out.push(Step { name: "else".into(), kind: String::new(), depth: depth + 1, detail: None, secure: false });
            flatten(Some(e), depth + 2, out);
        }
        if let Some(cases) = s.get("cases").and_then(Value::as_object) {
            for (k, c) in cases {
                out.push(Step { name: format!("case {}", k), kind: String::new(), depth: depth + 1, detail: None, secure: false });
                flatten(c.get("actions"), depth + 2, out);
            }
        }
        if let Some(d) = s.pointer("/default/actions") {
            out.push(Step { name: "default".into(), kind: String::new(), depth: depth + 1, detail: None, secure: false });
            flatten(Some(d), depth + 2, out);
        }
    }
}

/// One `$connections` entry: the connector key the steps name, the
/// connection's ARM id.
#[derive(Debug, Clone)]
pub struct ConnectionRef {
    pub key: String,
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct WorkflowRow {
    pub base: ArmBase,
    pub state: Option<String>,
    pub sku: Option<String>,
    pub version: Option<String>,
    pub created: Option<String>,
    pub changed: Option<String>,
    pub access_endpoint: Option<String>,
    pub integration_account: Option<String>,
    pub ise: Option<String>,
    pub triggers: Vec<Step>,
    pub actions: Vec<Step>,
    /// `(name, type)` of each definition parameter.
    pub parameters: Vec<(String, String)>,
    pub connections: Vec<ConnectionRef>,
    pub trigger_callers: Vec<String>,
    pub trigger_policies: Vec<String>,
    pub content_callers: Vec<String>,
    pub action_callers: Vec<String>,
    pub management_callers: Vec<String>,
    pub access_ips: Vec<String>,
    pub outgoing_ips: Vec<String>,
    pub connector_ips: Vec<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
}

fn addresses(v: &Value, ptr: &str, field: &str) -> Vec<String> {
    json::arr(v, ptr).iter().filter_map(|a| json::str_at(a, field)).collect()
}

impl WorkflowRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<WorkflowRow> {
        let v = &without_secrets(raw);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| format!("/properties/{}", f);
        let s = |f: &str| json::str_at(v, &p(f)).filter(|s| !s.is_empty());
        let mut triggers = Vec::new();
        flatten(v.pointer(&p("definition/triggers")), 0, &mut triggers);
        let mut actions = Vec::new();
        flatten(v.pointer(&p("definition/actions")), 0, &mut actions);
        let mut parameters: Vec<(String, String)> = v
            .pointer(&p("definition/parameters"))
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, t)| (k.clone(), json::text(t, "/type"))).collect())
            .unwrap_or_default();
        parameters.sort();
        let mut connections: Vec<ConnectionRef> = v
            .pointer(&p("parameters/$connections/value"))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, c)| Some(ConnectionRef { key: k.clone(), id: json::arm_id(json::str_at(c, "/connectionId"))? }))
                    .collect()
            })
            .unwrap_or_default();
        connections.sort_by(|a, b| a.key.cmp(&b.key));
        let ac = |which: &str| addresses(v, &p(&format!("accessControl/{}/allowedCallerIpAddresses", which)), "/addressRange");
        let mut trigger_policies: Vec<String> = v
            .pointer(&p("accessControl/triggers/openAuthenticationPolicies/policies"))
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        trigger_policies.sort();
        Some(WorkflowRow {
            state: s("state"),
            sku: s("sku/name"),
            version: s("version"),
            created: s("createdTime"),
            changed: s("changedTime"),
            access_endpoint: s("accessEndpoint"),
            integration_account: json::arm_id(json::id_at(v, &p("integrationAccount"))),
            ise: json::arm_id(json::id_at(v, &p("integrationServiceEnvironment"))),
            triggers,
            actions,
            parameters,
            connections,
            trigger_callers: ac("triggers"),
            trigger_policies,
            content_callers: ac("contents"),
            action_callers: ac("actions"),
            management_callers: ac("workflowManagement"),
            access_ips: addresses(v, &p("endpointsConfiguration/workflow/accessEndpointIpAddresses"), "/address"),
            outgoing_ips: addresses(v, &p("endpointsConfiguration/workflow/outgoingIpAddresses"), "/address"),
            connector_ips: addresses(v, &p("endpointsConfiguration/connector/outgoingIpAddresses"), "/address"),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.state.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("enabled"))
    }

    /// The `Request` triggers: called on a signed URL.
    pub fn request_triggers(&self) -> Vec<&Step> {
        self.triggers.iter().filter(|t| t.kind.eq_ignore_ascii_case("request")).collect()
    }

    /// A request trigger callable from anywhere with the URL alone: no
    /// caller IP range and no Entra ID (OAuth) policy. What `@audit`'s
    /// `logic-trigger-sas-only` reads.
    pub fn trigger_open(&self) -> bool {
        !self.request_triggers().is_empty() && self.trigger_callers.is_empty() && self.trigger_policies.is_empty()
    }

    fn step_lines(steps: &[Step], lines: &mut Vec<(String, String)>) {
        for s in steps {
            let indent = "  ".repeat(s.depth + 1);
            if s.kind.is_empty() {
                // A branch of the step above (`else`, `case …`, `default`).
                lines.push((format!("{}{}", indent, s.name), "branch".into()));
                continue;
            }
            let mut value = s.kind.clone();
            if let Some(d) = &s.detail {
                value.push_str(&format!(" · {}", d));
            }
            if s.secure {
                value.push_str(" · secured inputs/outputs");
            }
            lines.push((format!("{}{}", indent, s.name), value));
        }
    }

    pub fn definition_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("Triggers".to_string(), self.triggers.len().to_string())];
        Self::step_lines(&self.triggers, &mut lines);
        lines.push((String::new(), String::new()));
        lines.push(("Actions".into(), self.actions.iter().filter(|s| !s.kind.is_empty()).count().to_string()));
        Self::step_lines(&self.actions, &mut lines);
        if !self.parameters.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("Parameters".into(), self.parameters.len().to_string()));
            for (n, t) in &self.parameters {
                lines.push((format!("  {}", n), t.clone()));
            }
        }
        lines.push((String::new(), String::new()));
        lines.push((
            String::new(),
            "the outline only: inputs, headers, bodies and parameter values are never kept".into(),
        ));
        lines
    }

    fn callers(list: &[String], none: &str) -> String {
        if list.is_empty() {
            none.to_string()
        } else {
            list.join(", ")
        }
    }

    pub fn network_rows(&self) -> Vec<(String, String)> {
        let open = if self.request_triggers().is_empty() {
            "any (no request trigger)".to_string()
        } else {
            "⚠ any IP with the signed URL".to_string()
        };
        let mut lines = vec![("Trigger callers".into(), Self::callers(&self.trigger_callers, &open))];
        if !self.trigger_policies.is_empty() {
            lines.push(("Trigger Entra ID policies".into(), self.trigger_policies.join(", ")));
        }
        lines.push(("Run history callers".into(), Self::callers(&self.content_callers, "any")));
        if !self.action_callers.is_empty() {
            lines.push(("Action callers".into(), self.action_callers.join(", ")));
        }
        if !self.management_callers.is_empty() {
            lines.push(("Management callers".into(), self.management_callers.join(", ")));
        }
        lines.push((String::new(), String::new()));
        lines.push(("Access endpoint".into(), json::opt(self.access_endpoint.clone())));
        lines.push(("Inbound IPs".into(), json::join(&self.access_ips)));
        lines.push(("Outbound IPs".into(), json::join(&self.outgoing_ips)));
        lines.push(("Connector outbound IPs".into(), json::join(&self.connector_ips)));
        if let Some(ia) = &self.integration_account {
            lines.push((format!("Integration account · {}", name_of_id(ia)), ia.clone()));
        }
        if let Some(ise) = &self.ise {
            lines.push((format!("Integration service environment · {} (retired)", name_of_id(ise)), ise.clone()));
        }
        lines
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.state.as_deref().map(|s| {
            let bucket = match s.to_ascii_lowercase().as_str() {
                "enabled" => ResourceState::Running,
                "disabled" => ResourceState::Stopped,
                "suspended" => ResourceState::Unavailable,
                "deleted" | "completed" => ResourceState::Terminated,
                _ => ResourceState::stateless(),
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for WorkflowRow {
    arm_row!("Logic app workflow");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&WORKFLOW_SECTIONS)
    }
    /// `Request → 6 actions · 2 connections`.
    fn list_summary(&self) -> Option<String> {
        let trig: Vec<&str> = self.triggers.iter().filter(|t| t.depth == 0).map(|t| t.kind.as_str()).collect();
        let n = self.actions.iter().filter(|s| !s.kind.is_empty()).count();
        let mut s = format!("{} → {} action{}", json::join(&trig.iter().map(|t| t.to_string()).collect::<Vec<_>>()), n, if n == 1 { "" } else { "s" });
        if !self.connections.is_empty() {
            let c = self.connections.len();
            s.push_str(&format!(" · {} connection{}", c, if c == 1 { "" } else { "s" }));
        }
        Some(s)
    }
    fn details(&self) -> Vec<(String, String)> {
        let trig: Vec<String> = self.triggers.iter().filter(|t| t.depth == 0).map(|t| format!("{} ({})", t.name, t.kind)).collect();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("State".into(), json::opt(self.state.clone())),
            ("Plan".into(), self.sku.clone().unwrap_or_else(|| "Consumption".into())),
            ("Triggers".into(), json::join(&trig)),
            ("Actions".into(), self.actions.iter().filter(|s| !s.kind.is_empty()).count().to_string()),
            ("Connections".into(), json::join(&self.connections.iter().map(|c| c.key.clone()).collect::<Vec<_>>())),
            ("Identity".into(), json::opt(self.identity_type.clone())),
            ("Version".into(), json::opt(self.version.clone())),
            ("Created".into(), json::time(self.created.clone())),
            ("Changed".into(), json::time(self.changed.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for c in &self.connections {
            v.push((format!("Connection {}", name_of_id(&c.id)), c.id.clone()));
        }
        if let Some(ia) = &self.integration_account {
            v.push((format!("Integration account {}", name_of_id(ia)), ia.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    /// `az logic workflow show --ids` (the `logic` extension; `name` has
    /// `id_part="name"`, checked 2026-11-24).
    fn cli_command(&self) -> Option<String> {
        Some(format!("az logic workflow show --ids {}", crate::azure::resource::shell_quote(&self.base.id)))
    }
}

/// The Triggers body: each trigger's state, schedule, last and next fire.
pub fn trigger_rows(items: &[Value]) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No triggers".into()));
    }
    for t in items {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        let state = json::text(t, &p("state"));
        let flagged = if state.eq_ignore_ascii_case("disabled") { format!("⚠ {}", state) } else { state };
        lines.push((json::text(t, "/name"), flagged));
        if let Some(r) = t.pointer(&p("recurrence")).and_then(recurrence_text) {
            let tz = json::str_at(t, &p("recurrence/timeZone")).map(|z| format!(" ({})", z)).unwrap_or_default();
            lines.push(("  Schedule".into(), format!("{}{}", r, tz)));
        }
        let status = json::str_at(t, &p("status"));
        if let Some(s) = status.filter(|s| !s.eq_ignore_ascii_case("notspecified")) {
            let bad = matches!(s.to_ascii_lowercase().as_str(), "failed" | "faulted" | "timedout" | "aborted");
            lines.push(("  Last status".into(), if bad { format!("⚠ {}", s) } else { s }));
        }
        lines.push(("  Last fired".into(), json::time(json::str_at(t, &p("lastExecutionTime")))));
        if let Some(n) = json::str_at(t, &p("nextExecutionTime")) {
            lines.push(("  Next".into(), json::time(Some(n))));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "callback URLs are never read (each carries its key)".into()));
    lines
}

fn is_failed(status: &str) -> bool {
    matches!(status.to_ascii_lowercase().as_str(), "failed" | "faulted" | "timedout" | "aborted")
}

fn duration_text(start: Option<&str>, end: Option<&str>) -> Option<String> {
    let secs = iso_to_unix(end?)? - iso_to_unix(start?)?;
    Some(match secs {
        s if s < 60 => format!("{}s", s.max(0)),
        s if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        s => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    })
}

/// The Runs body: a tally, then each run newest first: its status (`⚠`
/// when it failed), duration, trigger and error.
pub fn run_rows(items: &[Value]) -> Vec<(String, String)> {
    if items.is_empty() {
        return vec![(String::new(), "No runs".into())];
    }
    let status = |r: &Value| json::text(r, "/properties/status");
    let failed = items.iter().filter(|r| is_failed(&status(r))).count();
    let mut tally: Vec<(String, usize)> = Vec::new();
    for r in items {
        let s = status(r).to_lowercase();
        match tally.iter_mut().find(|(k, _)| *k == s) {
            Some((_, n)) => *n += 1,
            None => tally.push((s, 1)),
        }
    }
    let summary: Vec<String> = tally.iter().map(|(k, n)| format!("{} {}", n, k)).collect();
    let head = if failed > 0 { format!("⚠ {}", summary.join(" · ")) } else { summary.join(" · ") };
    let mut lines = vec![(format!("Latest {}", items.len()), head)];
    for r in items {
        let p = |f: &str| format!("/properties/{}", f);
        let st = status(r);
        let start = json::str_at(r, &p("startTime"));
        let dur = duration_text(start.as_deref(), json::str_at(r, &p("endTime")).as_deref());
        let shown = match dur {
            Some(d) => format!("{} · {}", st, d),
            None => st.clone(),
        };
        lines.push((String::new(), String::new()));
        lines.push((json::time(start), if is_failed(&st) { format!("⚠ {}", shown) } else { shown }));
        if let Some(t) = json::str_at(r, &p("trigger/name")) {
            lines.push(("  Trigger".into(), t));
        }
        let code = json::str_at(r, &p("error/code")).or_else(|| json::str_at(r, &p("trigger/error/code")));
        if let Some(c) = code {
            let msg = json::str_at(r, &p("error/message")).or_else(|| json::str_at(r, &p("trigger/error/message")));
            lines.push(("  Error".into(), match msg {
                Some(m) => format!("{}: {}", c, m),
                None => c,
            }));
        }
        if let Some(id) = json::str_at(r, &p("correlation/clientTrackingId")) {
            lines.push(("  Tracking id".into(), id));
        }
    }
    if items.len() >= MAX_RUNS {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("the latest {} runs only", MAX_RUNS)));
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "outcomes only: run inputs and outputs are never read".into()));
    lines
}

/// The Connections body: each `$connections` entry with the connection's
/// status from the warm API connections list.
pub fn workflow_connection_rows(x: &WorkflowRow, warm: Warm) -> Vec<(String, String)> {
    if x.connections.is_empty() {
        return vec![(String::new(), "No API connections (no managed connector steps)".into())];
    }
    let Some(rows) = warm.rows() else {
        return warm.waiting("API connections (@apiconn)");
    };
    let mut lines = Vec::new();
    for c in &x.connections {
        let found = rows
            .iter()
            .filter_map(|r| r.as_any().downcast_ref::<ApiConnectionRow>())
            .find(|r| r.base.id.eq_ignore_ascii_case(&c.id));
        let status = match found {
            Some(r) => r.status_text(),
            None => "not in this subscription's connections".into(),
        };
        lines.push((format!("{} · {}", c.key, found.map(|r| r.api_label()).unwrap_or_else(|| "-".into())), status));
        lines.push((format!("  {}", name_of_id(&c.id)), c.id.clone()));
    }
    lines
}

// ── API connections ───────────────────────────────────────────────────

/// One `statuses` entry.
#[derive(Debug, Clone)]
pub struct ConnectionStatus {
    pub status: String,
    pub target: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApiConnectionRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    pub display_name: Option<String>,
    pub api_name: Option<String>,
    pub api_display: Option<String>,
    pub api_id: Option<String>,
    pub statuses: Vec<ConnectionStatus>,
    pub overall: Option<String>,
    pub created: Option<String>,
    pub changed: Option<String>,
    pub authenticated_user: Option<String>,
    /// The non-secret parameters, by name (their values are dropped).
    pub parameters: Vec<String>,
}

impl ApiConnectionRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<ApiConnectionRow> {
        let v = &without_secrets(raw);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| format!("/properties/{}", f);
        let s = |f: &str| json::str_at(v, &p(f)).filter(|s| !s.is_empty());
        let mut parameters: Vec<String> = v
            .pointer(&p("nonSecretParameterValues"))
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        parameters.sort();
        Some(ApiConnectionRow {
            kind: json::str_at(v, "/kind"),
            display_name: s("displayName"),
            api_name: s("api/name"),
            api_display: s("api/displayName"),
            api_id: s("api/id"),
            statuses: json::arr(v, &p("statuses"))
                .iter()
                .map(|st| ConnectionStatus {
                    status: json::text(st, "/status"),
                    target: json::str_at(st, "/target"),
                    code: json::str_at(st, "/error/code"),
                    message: json::str_at(st, "/error/message"),
                })
                .collect(),
            overall: s("overallStatus"),
            created: s("createdTime"),
            changed: s("changedTime"),
            authenticated_user: s("authenticatedUser/name"),
            parameters,
            base,
        })
    }

    /// Any status other than `Connected` (or `Ready`, which a few
    /// connectors report): what `@audit`'s `logic-connection-error` reads.
    pub fn broken(&self) -> Vec<&ConnectionStatus> {
        self.statuses
            .iter()
            .filter(|s| !s.status.eq_ignore_ascii_case("connected") && !s.status.eq_ignore_ascii_case("ready"))
            .collect()
    }

    /// `Office 365 Outlook`, or the API's name.
    pub fn api_label(&self) -> String {
        self.api_display.clone().or_else(|| self.api_name.clone()).unwrap_or_else(|| "-".into())
    }

    /// `Connected`, `⚠ Error (Unauthenticated: …)`.
    pub fn status_text(&self) -> String {
        match self.broken().first() {
            Some(b) => {
                let why = match (&b.code, &b.message) {
                    (Some(c), Some(m)) => format!(" ({}: {})", c, m),
                    (Some(c), None) => format!(" ({})", c),
                    (None, Some(m)) => format!(" ({})", m),
                    (None, None) => String::new(),
                };
                format!("⚠ {}{}", b.status, why)
            }
            None => self.statuses.first().map(|s| s.status.clone()).or_else(|| self.overall.clone()).unwrap_or_else(|| "-".into()),
        }
    }

    pub fn status_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.statuses.is_empty() {
            lines.push(("Status".into(), json::opt(self.overall.clone())));
        }
        for s in &self.statuses {
            let bad = !s.status.eq_ignore_ascii_case("connected") && !s.status.eq_ignore_ascii_case("ready");
            let label = match &s.target {
                Some(t) => format!("Status · {}", t),
                None => "Status".into(),
            };
            lines.push((label, if bad { format!("⚠ {}", s.status) } else { s.status.clone() }));
            if let Some(c) = &s.code {
                lines.push(("  Error".into(), c.clone()));
            }
            if let Some(m) = &s.message {
                lines.push(("  Message".into(), m.clone()));
            }
        }
        lines.push(("Authenticated as".into(), json::opt(self.authenticated_user.clone())));
        if !self.parameters.is_empty() {
            lines.push(("Parameters".into(), self.parameters.join(", ")));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "parameter values, keys and consent links are never read".into()));
        lines
    }

    fn workflows<'a>(&self, warm: &'a [Box<dyn Resource>]) -> Vec<&'a WorkflowRow> {
        let mut found: Vec<&WorkflowRow> = warm
            .iter()
            .filter_map(|r| r.as_any().downcast_ref::<WorkflowRow>())
            .filter(|w| w.connections.iter().any(|c| c.id.eq_ignore_ascii_case(&self.base.id)))
            .collect();
        found.sort_by_key(|w| w.base.name.to_lowercase());
        found
    }

    pub fn used_by_rows(&self, warm: Warm) -> Vec<(String, String)> {
        let Some(rows) = warm.rows() else {
            return warm.waiting("Workflows (@logic)");
        };
        let found = self.workflows(rows);
        if found.is_empty() {
            return vec![(String::new(), "No workflow in this subscription uses it".into())];
        }
        found
            .iter()
            .map(|w| (format!("{} ({})", w.base.name, json::opt(w.state.clone()).to_lowercase()), w.base.id.clone()))
            .collect()
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = match (self.broken().first(), self.statuses.first()) {
            (Some(b), _) => Some((ResourceState::Unavailable, b.status.as_str())),
            (None, Some(s)) => Some((ResourceState::Available, s.status.as_str())),
            _ => None,
        };
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for ApiConnectionRow {
    arm_row!("API connection");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&CONNECTION_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        Some(self.api_label())
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Display name".into(), json::opt(self.display_name.clone())),
            ("API".into(), self.api_label()),
            ("Status".into(), self.status_text()),
        ];
        if let Some(id) = &self.api_id {
            // A managed API (`…/locations/{l}/managedApis/{name}`): in no
            // list, so `⏎` copies it.
            lines.push(("Managed API".into(), id.clone()));
        }
        lines.push(("Kind".into(), json::opt(self.kind.clone())));
        lines.push(("Created".into(), json::time(self.created.clone())));
        lines.push(("Changed".into(), json::time(self.changed.clone())));
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az resource show --ids {}", crate::azure::resource::shell_quote(&self.base.id)))
    }
}

// ── Sections ──────────────────────────────────────────────────────────

/// What the sections read beyond the row.
pub struct LogicContext<'a> {
    pub triggers: Option<&'a Lazy<Vec<Value>>>,
    pub runs: Option<&'a Lazy<Vec<Value>>>,
    pub connections: Warm<'a>,
    pub workflows: Warm<'a>,
}

/// Body lines for one section of a workflow or an API connection; `None`
/// for another type.
pub fn logic_section_lines(r: &dyn Resource, idx: usize, cx: &LogicContext) -> Option<Vec<(String, String)>> {
    if let Some(x) = r.as_any().downcast_ref::<WorkflowRow>() {
        use WorkflowDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Definition => x.definition_rows(),
            S::Network => x.network_rows(),
            S::Triggers => lazy_list_rows(cx.triggers, "Triggers", trigger_rows),
            S::Runs => lazy_list_rows(cx.runs, "Runs", run_rows),
            S::Connections => workflow_connection_rows(x, cx.connections),
            S::Access | S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_rows_with(x, Vec::new()),
            S::Tags => tag_rows(x.tags()),
        });
    }
    let x = r.as_any().downcast_ref::<ApiConnectionRow>()?;
    use ConnectionDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Status => x.status_rows(),
        S::UsedBy => x.used_by_rows(cx.workflows),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => {
            let extra = cx
                .workflows
                .rows()
                .map(|w| x.workflows(w).iter().map(|w| (format!("Workflow {}", w.base.name), w.base.id.clone())).collect())
                .unwrap_or_default();
            related_rows_with(x, extra)
        }
        S::Tags => tag_rows(x.tags()),
    })
}

/// The ARM path of a workflow's child list (`triggers`, `runs`).
pub fn child_path(workflow_id: &str, child: &str) -> String {
    format!("{}/{}", workflow_id.trim_end_matches('/'), child)
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct LogicAppsService {
    scope: Scope,
}

impl LogicAppsService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::ApiConnections => page
                .iter()
                .filter_map(|v| ApiConnectionRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
            _ => page
                .iter()
                .filter_map(|v| WorkflowRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
        }
    }

    /// The groups holding an API connection: one generic resources call.
    async fn connection_groups(&self) -> Result<Vec<String>> {
        let filter = format!("resourceType eq '{}'", CONNECTION_TYPE);
        let items = self
            .scope
            .list_query("/resources", RESOURCES_API_VERSION, &[("$filter", filter.as_str())])
            .await?;
        Ok(groups_of(&items))
    }

    fn group_suffix(rg: &str) -> String {
        format!("/resourceGroups/{}/providers/{}", rg, CONNECTION_TYPE)
    }
}

#[async_trait]
impl AzureService for LogicAppsService {
    fn service_type(&self) -> ServiceType {
        ServiceType::LogicApps
    }

    fn name(&self) -> &str {
        "Logic Apps"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        if view != JumpView::ApiConnections {
            return Ok(Self::rows(view, &self.scope.list(WORKFLOWS_PATH, LOGIC_API_VERSION).await?, tenant));
        }
        let groups = self.connection_groups().await?;
        let mut out = Vec::new();
        let mut first_err = None;
        for rg in &groups {
            match self.scope.list(&Self::group_suffix(rg), CONNECTIONS_API_VERSION).await {
                Ok(page) => out.extend(Self::rows(view, &page, tenant)),
                Err(e) => first_err = first_err.or(Some(e)),
            }
        }
        match first_err {
            Some(e) if out.is_empty() => Err(e),
            _ => Ok(out),
        }
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        if view != JumpView::ApiConnections {
            let r = self
                .scope
                .stream(WORKFLOWS_PATH, LOGIC_API_VERSION, &[], service_type, "Listing Logic Apps workflows…", &event_tx, |page| {
                    Self::rows(view, &page, tenant.as_deref())
                })
                .await;
            return finish_stream(service_type, r, &event_tx);
        }
        let _ = event_tx.send(Event::ResourcesPartiallyLoaded {
            service: service_type,
            resources: Vec::new(),
            progress: LoadProgress {
                loaded_count: 0,
                total_count: None,
                status_message: Some("Finding the resource groups with API connections…".into()),
            },
        });
        let groups = match self.connection_groups().await {
            Ok(g) => g,
            Err(e) => return finish_stream(service_type, Err(e), &event_tx),
        };
        let mut total = 0usize;
        let mut failures = Vec::new();
        for rg in &groups {
            let label = format!("Listing API connections in {}…", rg);
            let r = self
                .scope
                .stream(&Self::group_suffix(rg), CONNECTIONS_API_VERSION, &[], service_type, &label, &event_tx, |page| {
                    Self::rows(view, &page, tenant.as_deref())
                })
                .await;
            match r {
                Ok(n) => total += n,
                Err(e) => failures.push((rg.clone(), e)),
            }
        }
        // A group that fails beside one that streamed is a warning; only
        // every group failing is the list's error.
        if !groups.is_empty() && failures.len() == groups.len() {
            return finish_stream(service_type, Err(failures.remove(0).1), &event_tx);
        }
        for (rg, e) in failures {
            let _ = event_tx.send(Event::ResourceLoadWarning { service: service_type, warning: format!("{}: {}", rg, e) });
        }
        finish_stream(service_type, Ok(total), &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::LogicWorkflows);
        let version = if view == JumpView::ApiConnections { CONNECTIONS_API_VERSION } else { LOGIC_API_VERSION };
        let v = self.scope.get(id, version).await?;
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-flow";

    fn conn_id(name: &str) -> String {
        format!("{}/providers/Microsoft.Web/connections/{}", RG, name)
    }

    fn workflow(access: Value) -> WorkflowRow {
        WorkflowRow::from_json(
            &json!({
                "id": format!("{}/providers/Microsoft.Logic/workflows/la-intake", RG), "name": "la-intake", "location": "westeurope",
                "identity": {"type": "SystemAssigned"},
                "properties": {
                    "provisioningState": "Succeeded", "state": "Enabled",
                    "accessEndpoint": "https://prod-01.westeurope.logic.example:443/workflows/abc",
                    "accessControl": access,
                    "definition": {
                        "parameters": {"$connections": {"type": "Object", "defaultValue": {}},
                                       "apiKey": {"type": "SecureString", "defaultValue": "planted-default"}},
                        "triggers": {"manual": {"type": "Request", "kind": "Http", "inputs": {"schema": {"secret": "planted-schema"}}}},
                        "actions": {
                            "Send_mail": {"type": "ApiConnection", "runAfter": {"Call_api": ["Succeeded"]},
                                          "inputs": {"host": {"connection": {"name": "@parameters('$connections')['office365']['connectionId']"}},
                                                     "method": "post", "path": "/v2/Mail", "body": {"To": "planted-body"}}},
                            "Call_api": {"type": "Http", "inputs": {"method": "POST", "uri": "https://func.example/api/orders?code=planted-code",
                                                                     "headers": {"x-key": "planted-header"},
                                                                     "authentication": {"type": "Basic", "username": "u", "password": "planted-pw"}},
                                         "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}}},
                            "Check": {"type": "If", "runAfter": {"Send_mail": ["Succeeded"]}, "expression": {"and": [{"equals": ["planted-expr", 1]}]},
                                      "actions": {"Done": {"type": "Response", "inputs": {"statusCode": 200, "body": "planted-response"}}},
                                      "else": {"actions": {"Fail": {"type": "Terminate"}}}}
                        }
                    },
                    "parameters": {
                        "$connections": {"value": {"office365": {"connectionId": conn_id("office365-orders"), "connectionName": "office365-orders",
                                                                 "id": "/subscriptions/0000/providers/Microsoft.Web/locations/westeurope/managedApis/office365"}}},
                        "apiKey": {"type": "SecureString", "value": "planted-param"}
                    }
                }
            }),
            None,
        )
        .unwrap()
    }

    fn get<'a>(lines: &'a [(String, String)], key: &str) -> Option<&'a str> {
        lines.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn section_labels_keep_the_shared_order() {
        let w: Vec<&str> = WORKFLOW_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(w, ["Overview", "Definition", "Network", "Triggers", "Runs", "Connections", "Access", "Activity", "Related", "Tags"]);
        let c: Vec<&str> = CONNECTION_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(c, ["Overview", "Status", "Used by", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn a_workflow_keeps_its_outline_and_never_a_value_header_or_key() {
        let row = workflow(json!({}));
        for planted in [
            "planted-default",
            "planted-schema",
            "planted-body",
            "planted-code",
            "planted-header",
            "planted-pw",
            "planted-expr",
            "planted-response",
            "planted-param",
        ] {
            // Never print the body: on a failure it would hold the value.
            assert!(!row.base.raw.contains(planted), "{planted} survived the scrub");
        }
        let names: Vec<(&str, usize)> = row.actions.iter().map(|s| (s.name.as_str(), s.depth)).collect();
        assert_eq!(names, [("Call_api", 0), ("Send_mail", 0), ("Check", 0), ("Done", 1), ("else", 1), ("Fail", 2)], "run order, nested");
        let call = &row.actions[0];
        assert_eq!(call.detail.as_deref(), Some("POST https://func.example/api/orders?… · Basic auth"));
        assert!(call.secure);
        let def = row.definition_rows();
        assert_eq!(get(&def, "  Call_api"), Some("Http · POST https://func.example/api/orders?… · Basic auth · secured inputs/outputs"));
        assert_eq!(get(&def, "    else"), Some("branch"));
        assert_eq!(row.actions[1].detail.as_deref(), Some("via office365 · post /v2/Mail"));
        assert_eq!(row.connections.len(), 1);
        assert_eq!(row.connections[0].key, "office365");
        assert_eq!(row.parameters, [("$connections".to_string(), "Object".to_string()), ("apiKey".to_string(), "SecureString".to_string())]);
        assert_eq!(row.list_summary().as_deref(), Some("Request → 5 actions · 1 connection"));
        assert_eq!(row.state(), ResourceState::Running);
        assert_eq!(row.state_label(), "enabled");
        assert!(row.cli_command().unwrap().starts_with("az logic workflow show --ids /subscriptions/0000/"));
        assert!(row.related().iter().any(|(_, id)| *id == conn_id("office365-orders")));
    }

    #[test]
    fn a_request_trigger_without_caller_ranges_or_a_policy_is_open() {
        let open = workflow(json!({}));
        assert!(open.trigger_open());
        assert_eq!(get(&open.network_rows(), "Trigger callers"), Some("⚠ any IP with the signed URL"));
        let ranged = workflow(json!({"triggers": {"allowedCallerIpAddresses": [{"addressRange": "10.0.0.0/24"}]}}));
        assert!(!ranged.trigger_open());
        assert_eq!(get(&ranged.network_rows(), "Trigger callers"), Some("10.0.0.0/24"));
        let policy = workflow(json!({"triggers": {"openAuthenticationPolicies": {"policies": {"entra": {"type": "AAD"}}}}}));
        assert!(!policy.trigger_open());
    }

    #[test]
    fn runs_keep_their_outcome_and_never_a_content_link() {
        let raw = json!({"id": "r1", "name": "r1", "properties": {
            "status": "Failed", "startTime": "2026-11-24T01:00:00Z", "endTime": "2026-11-24T01:01:05Z",
            "error": {"code": "ActionFailed", "message": "An action failed."},
            "outputs": {"result": {"type": "String", "value": "planted-output"}},
            "trigger": {"name": "manual", "status": "Succeeded",
                        "inputsLink": {"uri": "https://prod-01.logic.example/runs/r1/contents/TriggerInputs?sig=planted-sig"},
                        "outputs": {"body": "planted-trigger-output"}, "trackedProperties": {"x": "planted-tracked"}},
            "response": {"outputsLink": {"uri": "https://x?sig=planted-response"}}}});
        let kept = run_outline(&raw);
        let text = kept.to_string();
        for planted in ["planted-output", "planted-sig", "planted-trigger-output", "planted-tracked", "planted-response"] {
            assert!(!text.contains(planted), "{planted} survived the scrub");
        }
        let ok = json!({"name": "r0", "properties": {"status": "Succeeded", "startTime": "2026-11-24T00:00:00Z", "endTime": "2026-11-24T00:00:04Z"}});
        let lines = run_rows(&[kept, run_outline(&ok)]);
        assert_eq!(lines[0], ("Latest 2".into(), "⚠ 1 failed · 1 succeeded".into()));
        assert_eq!(get(&lines, "2026-11-24 01:00:00"), Some("⚠ Failed · 1m 5s"));
        assert_eq!(get(&lines, "  Error"), Some("ActionFailed: An action failed."));
        assert_eq!(get(&lines, "2026-11-24 00:00:00"), Some("Succeeded · 4s"));
    }

    fn connection(status: Value) -> ApiConnectionRow {
        ApiConnectionRow::from_json(
            &json!({
                "id": conn_id("office365-orders"), "name": "office365-orders", "location": "westeurope", "kind": "V1",
                "properties": {"displayName": "orders@contoso.example",
                               "api": {"name": "office365", "displayName": "Office 365 Outlook",
                                       "id": "/subscriptions/0000/providers/Microsoft.Web/locations/westeurope/managedApis/office365"},
                               "statuses": [status],
                               "parameterValues": {"token": "planted-token"}, "customParameterValues": {"k": "planted-custom"},
                               "nonSecretParameterValues": {"server": "planted-server"},
                               "testLinks": [{"requestUri": "https://management.example/x?sig=planted-test", "method": "get"}]}
            }),
            None,
        )
        .unwrap()
    }

    #[test]
    fn a_connection_drops_its_parameter_values_and_flags_an_error() {
        let bad = connection(json!({"status": "Error", "target": "token", "error": {"code": "Unauthenticated", "message": "Sign in again."}}));
        for planted in ["planted-token", "planted-custom", "planted-server", "planted-test"] {
            assert!(!bad.base.raw.contains(planted), "{planted} survived the scrub");
        }
        assert_eq!(bad.parameters, ["server"]);
        assert_eq!(bad.state(), ResourceState::Unavailable);
        assert_eq!(bad.state_label(), "error");
        assert_eq!(bad.status_text(), "⚠ Error (Unauthenticated: Sign in again.)");
        assert_eq!(get(&bad.status_rows(), "Status · token"), Some("⚠ Error"));
        let ok = connection(json!({"status": "Connected"}));
        assert!(ok.broken().is_empty());
        assert_eq!(ok.state(), ResourceState::Available);
        assert_eq!(ok.list_summary().as_deref(), Some("Office 365 Outlook"));
    }

    #[test]
    fn a_workflow_names_its_connections_status_and_a_connection_its_workflows() {
        let wf: Vec<Box<dyn Resource>> = vec![Box::new(workflow(json!({})))];
        let conns: Vec<Box<dyn Resource>> = vec![Box::new(connection(json!({"status": "Error", "error": {"code": "Unauthenticated"}})))];
        let w = wf[0].as_any().downcast_ref::<WorkflowRow>().unwrap();
        let lines = workflow_connection_rows(w, Warm::Rows(&conns));
        assert_eq!(get(&lines, "office365 · Office 365 Outlook"), Some("⚠ Error (Unauthenticated)"));
        assert_eq!(get(&lines, "  office365-orders"), Some(conn_id("office365-orders").as_str()));
        assert_eq!(workflow_connection_rows(w, Warm::Cold)[0].1, "Open the API connections (@apiconn) sub-tab to load them");
        let c = conns[0].as_any().downcast_ref::<ApiConnectionRow>().unwrap();
        let used = c.used_by_rows(Warm::Rows(&wf));
        assert_eq!(used[0].0, "la-intake (enabled)");
        let cx = LogicContext { triggers: None, runs: Some(&Lazy::Loading), connections: Warm::Cold, workflows: Warm::Rows(&wf) };
        let related = logic_section_lines(c, ConnectionDetailSection::Related as usize, &cx).unwrap();
        assert!(related.iter().any(|(l, _)| l == "Workflow la-intake"));
        let runs = logic_section_lines(w, WorkflowDetailSection::Runs as usize, &cx).unwrap();
        assert_eq!(runs[0].1, "Loading…");
    }

    #[test]
    fn triggers_show_their_schedule_and_flag_a_disabled_one() {
        let raw = json!({"name": "Recurrence", "properties": {"state": "Disabled", "status": "Succeeded",
            "recurrence": {"frequency": "Minute", "interval": 15, "timeZone": "UTC"},
            "lastExecutionTime": "2026-11-24T01:00:00Z", "nextExecutionTime": "2026-11-24T01:15:00Z", "inputs": {"x": "planted"}}});
        let kept = trigger_outline(&raw);
        assert!(!kept.to_string().contains("planted"));
        let lines = trigger_rows(&[kept]);
        assert_eq!(get(&lines, "Recurrence"), Some("⚠ Disabled"));
        assert_eq!(get(&lines, "  Schedule"), Some("every 15 minutes (UTC)"));
        assert_eq!(get(&lines, "  Next"), Some("2026-11-24 01:15:00"));
        assert_eq!(child_path(&format!("{}/providers/Microsoft.Logic/workflows/la", RG), "runs"), format!("{}/providers/Microsoft.Logic/workflows/la/runs", RG));
    }
}
