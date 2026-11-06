//! Alert rules and fired alerts (issue #194), Monitor sub-tabs beside Log
//! Analytics and App Insights (SERVICES.md rule 36): metric alerts
//! (`Microsoft.Insights/metricAlerts`), log search alerts
//! (`scheduledQueryRules`), activity log alerts (`activityLogAlerts`,
//! Service Health among them), action groups (`actionGroups`, who gets
//! told), alert processing rules (`Microsoft.AlertsManagement/actionRules`,
//! what suppresses or adds to them) and the alerts that fired in the last
//! 30 days (`Microsoft.AlertsManagement/alerts`).
//!
//! **One subscription-wide list each**, no lazy calls. The joins are over
//! the warm lists: an action group's Used by (every rule and processing
//! rule naming it), and, on **every** type's Related, the alert rules that
//! watch the row ([`rules_watching`], spliced in by the app the way a
//! backup vault is). A rule watches a resource its scopes name, or one in
//! a scope it names (a group, the subscription) when it also names the
//! resource's type: a subscription-wide Service Health alert is not on
//! every row.
//!
//! **Secrets never.** A receiver URL (webhook, Logic App callback, Function
//! trigger, Automation webhook) keeps its scheme and host only: their
//! tokens sit in the query string or, for a Slack-style webhook, the path.
//! The free-form `webHookProperties`, `customProperties` and
//! `actionProperties` maps and an ITSM receiver's ticket configuration are
//! dropped; a phone number is masked to its last four digits. All of it
//! before the row keeps its JSON. An alert's state change is a POST
//! (`changestate`): never sent, never offered.

use crate::azure::resource::{
    arm_type_chain, name_of_id, portal_url_for, scope_related, shell_quote, state_ladder, Resource, ResourceState,
};
use crate::azure::service::{JumpView, ServiceType};
use crate::azure::services::governance::Warm;
use crate::azure::services::{arm_row, finish_stream, json, overview_rows, related_rows_with, tag_rows, ArmBase, Scope};
use crate::azure::timeline::ALERTS_API_VERSION;
use crate::error::{Error, Result};
use crate::event::Event;
use serde_json::Value;
use tokio::sync::mpsc;

/// The established stable versions: each type has a newer stable (2026),
/// not yet everywhere the older one is.
pub const METRIC_ALERTS_API_VERSION: &str = "2018-03-01";
pub const LOG_ALERTS_API_VERSION: &str = "2023-12-01";
pub const ACTIVITY_LOG_ALERTS_API_VERSION: &str = "2020-10-01";
pub const ACTION_GROUPS_API_VERSION: &str = "2023-01-01";
pub const PROCESSING_RULES_API_VERSION: &str = "2021-08-08";

const METRIC_ALERTS_PATH: &str = "/providers/Microsoft.Insights/metricAlerts";
const LOG_ALERTS_PATH: &str = "/providers/Microsoft.Insights/scheduledQueryRules";
const ACTIVITY_LOG_ALERTS_PATH: &str = "/providers/Microsoft.Insights/activityLogAlerts";
const ACTION_GROUPS_PATH: &str = "/providers/Microsoft.Insights/actionGroups";
const PROCESSING_RULES_PATH: &str = "/providers/Microsoft.AlertsManagement/actionRules";
const FIRED_ALERTS_PATH: &str = "/providers/Microsoft.AlertsManagement/alerts";

/// The fired-alert window: the longest the list allows.
const FIRED_ALERTS_QUERY: &[(&str, &str)] = &[("timeRange", "30d"), ("sortBy", "startDateTime"), ("sortOrder", "desc")];

crate::sections! {
    pub enum MetricAlertDetailSection,
    pub static METRIC_ALERT_SECTIONS = [
        Overview "Overview",
        Condition "Condition",
        Scopes "Scopes",
        Actions "Actions",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum LogAlertDetailSection,
    pub static LOG_ALERT_SECTIONS = [
        Overview "Overview",
        Condition "Condition",
        Scopes "Scopes",
        Actions "Actions",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ActivityLogAlertDetailSection,
    pub static ACTIVITY_LOG_ALERT_SECTIONS = [
        Overview "Overview",
        Condition "Condition",
        Scopes "Scopes",
        Actions "Actions",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ActionGroupDetailSection,
    pub static ACTION_GROUP_SECTIONS = [
        Overview "Overview",
        Receivers "Receivers",
        UsedBy "Used by" => crate::app::App::trigger_alert_rule_lists,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_alert_rule_lists,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ProcessingRuleDetailSection,
    pub static PROCESSING_RULE_SECTIONS = [
        Overview "Overview",
        Rule "Rule",
        Scopes "Scopes",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum FiredAlertDetailSection,
    pub static FIRED_ALERT_SECTIONS = [
        Overview "Overview",
        Alert "Alert",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

/// A fired alert: no RBAC or tags of its own (an AlertsManagement record
/// at the subscription), so its tail is Activity, Related.
pub fn is_fired_alert_id(id: &str) -> bool {
    matches!(JumpView::for_arm_id(id), Some(JumpView::FiredAlerts))
}

// ── Secrets out of the JSON ───────────────────────────────────────────

/// Receiver fields holding a URL whose token is in its query or path.
const URL_FIELDS: &[&str] = &["serviceUri", "callbackUrl", "httpTriggerUrl"];
/// Free-form maps a user fills (a webhook's payload, a rule's custom
/// properties), and an ITSM receiver's ticket configuration: dropped.
const DROPPED_FIELDS: &[&str] = &["webHookProperties", "webhookProperties", "customProperties", "actionProperties", "ticketConfiguration"];

/// `https://hooks.slack.com/services/T0/B0/xyz?x=1` → `https://hooks.slack.com/…`.
pub fn url_host_only(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    if scheme.is_empty() {
        format!("{}/…", host)
    } else {
        format!("{}://{}/…", scheme, host)
    }
}

/// `+61 412 345 678` → `****5678`.
pub fn mask_phone(p: &str) -> String {
    let digits: String = p.chars().filter(char::is_ascii_digit).collect();
    if digits.len() <= 4 {
        return "****".into();
    }
    format!("****{}", &digits[digits.len() - 4..])
}

fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !DROPPED_FIELDS.iter().any(|d| d.eq_ignore_ascii_case(k)));
            for (k, val) in map.iter_mut() {
                match val {
                    Value::String(s) if URL_FIELDS.iter().any(|f| f.eq_ignore_ascii_case(k)) => *s = url_host_only(s),
                    Value::String(s) if k.eq_ignore_ascii_case("phoneNumber") => *s = mask_phone(s),
                    _ => scrub(val),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with receiver URLs cut to their host, free-form maps dropped
/// and phone numbers masked: what a row parses and keeps for `e`.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

// ── Small shared readers ──────────────────────────────────────────────

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn push_unique(v: &mut Vec<(String, String)>, label: String, id: String) {
    if !v.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(&id)) {
        v.push((label, id));
    }
}

/// `Sev2`, from 0–4.
fn sev(n: Option<i64>) -> String {
    n.map(|n| format!("Sev{}", n)).unwrap_or_else(|| "-".into())
}

/// `PT5M` → `5m`, `PT1H` → `1h`, `P1D` → `1d`; anything else as sent.
pub fn duration(d: Option<&str>) -> String {
    let Some(d) = d else { return "-".into() };
    let up = d.to_uppercase();
    let Some(rest) = up.strip_prefix('P') else { return d.to_string() };
    let (days, time) = match rest.split_once('T') {
        Some((days, time)) => (days, time),
        None => (rest, ""),
    };
    let mut out = String::new();
    let mut num = String::new();
    for (part, units) in [(days, "D"), (time, "HMS")] {
        for c in part.chars() {
            if c.is_ascii_digit() {
                num.push(c);
            } else if units.contains(c) && !num.is_empty() {
                out.push_str(&num);
                out.push(c.to_ascii_lowercase());
                num.clear();
            } else {
                return d.to_string();
            }
        }
    }
    if out.is_empty() {
        d.to_string()
    } else {
        out
    }
}

/// `GreaterThan` → `>`.
fn op(o: &str) -> &str {
    match o.to_lowercase().as_str() {
        "greaterthan" => ">",
        "greaterthanorequal" => "≥",
        "lessthan" => "<",
        "lessthanorequal" => "≤",
        "equals" => "=",
        "greaterorlessthan" => "> or <",
        _ => o,
    }
}

fn enabled_ladder(base: &ArmBase, enabled: Option<bool>) -> (ResourceState, String) {
    let runtime = match enabled {
        Some(false) => Some((ResourceState::Stopped, "disabled")),
        Some(true) => Some((ResourceState::Running, "enabled")),
        None => None,
    };
    state_ladder(base.provisioning_state.as_deref(), runtime)
}

/// `Microsoft.Compute/virtualMachines` of an id: its last provider and
/// type chain, lowercased (`microsoft.compute/virtualmachines`).
fn arm_type_of(id: &str) -> Option<String> {
    let (ns, chain) = arm_type_chain(id)?;
    Some(format!("{}/{}", ns, chain.join("/")))
}

/// Whether `scope` is `id` or holds it (a parent: a group, the
/// subscription, a parent resource), on a segment boundary.
fn scope_holds(scope: &str, id: &str) -> Option<bool> {
    let (s, i) = (scope.trim_end_matches('/').to_lowercase(), id.trim_end_matches('/').to_lowercase());
    if s == i {
        return Some(true);
    }
    i.strip_prefix(&s).is_some_and(|rest| rest.starts_with('/')).then_some(false)
}

/// The rule-side test every rule type shares: its scopes name `id`, or
/// hold it and `types` (the rule's resource-type filter) names its type.
fn watches(scopes: &[String], types: &[String], id: &str) -> bool {
    let kind = arm_type_of(id);
    scopes.iter().any(|s| match scope_holds(s, id) {
        Some(true) => true,
        Some(false) => kind.as_ref().is_some_and(|k| types.iter().any(|t| same(t, k))),
        None => false,
    })
}

fn scope_rows(scopes: &[String]) -> Vec<(String, String)> {
    if scopes.is_empty() {
        return vec![(String::new(), "No scopes".into())];
    }
    scopes.iter().map(|s| (format!("Scope · {}", name_of_id(s)), s.clone())).collect()
}

fn action_group_rows(ids: &[String], empty: &str) -> Vec<(String, String)> {
    if ids.is_empty() {
        return vec![(String::new(), empty.into())];
    }
    ids.iter().map(|g| (format!("Action group · {}", name_of_id(g)), g.clone())).collect()
}

/// A rule's Related: its scopes and its action groups.
fn rule_related(id: &str, scopes: &[String], groups: &[String]) -> Vec<(String, String)> {
    let mut v = scope_related(id);
    for s in scopes {
        push_unique(&mut v, format!("Watches · {}", name_of_id(s)), s.clone());
    }
    for g in groups {
        push_unique(&mut v, format!("Action group · {}", name_of_id(g)), g.clone());
    }
    v
}

const NO_GROUPS: &str = "⚠ No action groups: the rule fires but tells no one (a processing rule may still add one)";

// ── Metric alert ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetricAlertRow {
    pub base: ArmBase,
    pub description: Option<String>,
    pub severity: Option<i64>,
    pub enabled: Option<bool>,
    pub scopes: Vec<String>,
    pub frequency: Option<String>,
    pub window: Option<String>,
    pub target_type: Option<String>,
    pub target_region: Option<String>,
    /// The short `odata.type`: `SingleResourceMultipleMetricCriteria`,
    /// `MultipleResourceMultipleMetricCriteria`,
    /// `WebtestLocationAvailabilityCriteria`.
    pub criteria_kind: Option<String>,
    pub criteria: Vec<Value>,
    pub web_test_id: Option<String>,
    pub component_id: Option<String>,
    pub failed_locations: Option<i64>,
    pub auto_mitigate: Option<bool>,
    pub action_group_ids: Vec<String>,
    pub last_updated: Option<String>,
}

impl MetricAlertRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<MetricAlertRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(MetricAlertRow {
            description: json::str_at(v, &p("description")).filter(|d| !d.is_empty()),
            severity: json::int_at(v, &p("severity")),
            enabled: json::bool_at(v, &p("enabled")),
            scopes: json::strings_at(v, &p("scopes")),
            frequency: json::str_at(v, &p("evaluationFrequency")),
            window: json::str_at(v, &p("windowSize")),
            target_type: json::str_at(v, &p("targetResourceType")),
            target_region: json::str_at(v, &p("targetResourceRegion")),
            criteria_kind: json::str_at(v, &p("criteria/odata.type"))
                .map(|t| t.rsplit('.').next().unwrap_or(&t).to_string()),
            criteria: json::arr(v, &p("criteria/allOf")),
            web_test_id: json::str_at(v, &p("criteria/webTestId")),
            component_id: json::str_at(v, &p("criteria/componentId")),
            failed_locations: json::int_at(v, &p("criteria/failedLocationCount")),
            auto_mitigate: json::bool_at(v, &p("autoMitigate")),
            action_group_ids: json::arr(v, &p("actions"))
                .iter()
                .filter_map(|a| json::arm_id(json::str_at(a, "/actionGroupId")))
                .collect(),
            last_updated: json::str_at(v, &p("lastUpdatedTime")),
            base,
        })
    }

    fn is_web_test(&self) -> bool {
        self.criteria_kind.as_deref().is_some_and(|k| k.contains("Webtest"))
    }

    /// `Percentage CPU Average > 80` or `dynamic Percentage CPU (Medium)`.
    fn criterion(c: &Value) -> String {
        let metric = json::text(c, "/metricName");
        let agg = json::text(c, "/timeAggregation");
        let o = json::str_at(c, "/operator").unwrap_or_default();
        if json::str_at(c, "/criterionType").is_some_and(|t| t.contains("Dynamic")) {
            format!(
                "{} {} {} dynamic ({} sensitivity)",
                metric,
                agg,
                op(&o),
                json::text(c, "/alertSensitivity")
            )
        } else {
            let threshold = c.pointer("/threshold").map(|t| t.to_string()).unwrap_or_else(|| "-".into());
            format!("{} {} {} {}", metric, agg, op(&o), threshold)
        }
    }

    pub fn condition_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Severity".into(), sev(self.severity)),
            ("Every · over".into(), format!("{} · {}", duration(self.frequency.as_deref()), duration(self.window.as_deref()))),
        ];
        if self.is_web_test() {
            lines.push(("Kind".into(), "availability test".into()));
            if let Some(w) = &self.web_test_id {
                lines.push((format!("Web test · {}", name_of_id(w)), w.clone()));
            }
            if let Some(c) = &self.component_id {
                lines.push((format!("App Insights · {}", name_of_id(c)), c.clone()));
            }
            lines.push(("Failed locations".into(), json::num(self.failed_locations)));
        }
        for c in &self.criteria {
            lines.push((format!("When · {}", json::text(c, "/name")), Self::criterion(c)));
            let dims: Vec<String> = json::arr(c, "/dimensions")
                .iter()
                .map(|d| format!("{} {} {}", json::text(d, "/name"), json::text(d, "/operator"), json::join(&json::strings_at(d, "/values"))))
                .collect();
            if !dims.is_empty() {
                lines.push(("  Dimensions".into(), dims.join("; ")));
            }
            if let Some(n) = json::int_at(c, "/failingPeriods/numberOfEvaluationPeriods") {
                lines.push((
                    "  Failing periods".into(),
                    format!("{} of {}", json::num(json::int_at(c, "/failingPeriods/minFailingPeriodsToAlert")), n),
                ));
            }
        }
        lines.push(("Resource type".into(), json::opt(self.target_type.clone())));
        if self.target_region.is_some() {
            lines.push(("Region".into(), json::opt(self.target_region.clone())));
        }
        lines.push(("Auto-resolve".into(), json::yes_no(self.auto_mitigate)));
        lines.push(("Last updated".into(), json::time(self.last_updated.clone())));
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        lines
    }

    pub fn watches(&self, id: &str) -> bool {
        watches(&self.scopes, &self.target_type.iter().cloned().collect::<Vec<_>>(), id)
    }
}

impl Resource for MetricAlertRow {
    arm_row!("Metric alert");
    /// `Sev2 · Percentage CPU > 80 · vm-1`.
    fn list_summary(&self) -> Option<String> {
        let what = self.criteria.first().map(Self::criterion).unwrap_or_else(|| {
            if self.is_web_test() { "availability test".into() } else { "-".into() }
        });
        let on = match self.scopes.len() {
            0 => "-".to_string(),
            1 => name_of_id(&self.scopes[0]).to_string(),
            n => format!("{} scopes", n),
        };
        Some(format!("{} · {} · {}", sev(self.severity), what, on))
    }
    fn state(&self) -> ResourceState {
        enabled_ladder(&self.base, self.enabled).0
    }
    fn state_label(&self) -> String {
        enabled_ladder(&self.base, self.enabled).1
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&METRIC_ALERT_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Severity".into(), sev(self.severity)),
            ("Enabled".into(), json::yes_no(self.enabled)),
            ("Scopes".into(), self.scopes.len().to_string()),
            ("Action groups".into(), self.action_group_ids.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = rule_related(&self.base.id, &self.scopes, &self.action_group_ids);
        for (label, id) in [("Web test", &self.web_test_id), ("App Insights", &self.component_id)] {
            if let Some(id) = id.as_ref().filter(|i| i.starts_with("/subscriptions/")) {
                push_unique(&mut v, format!("{} · {}", label, name_of_id(id)), id.clone());
            }
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az monitor metrics alert show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Log search alert ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LogAlertRow {
    pub base: ArmBase,
    /// `LogAlert`, `SimpleLogAlert`, `LogToMetric`.
    pub kind: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<i64>,
    pub enabled: Option<bool>,
    pub scopes: Vec<String>,
    pub frequency: Option<String>,
    pub window: Option<String>,
    pub target_types: Vec<String>,
    pub criteria: Vec<Value>,
    pub action_group_ids: Vec<String>,
    pub mute_for: Option<String>,
    pub auto_mitigate: Option<bool>,
}

impl LogAlertRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<LogAlertRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(LogAlertRow {
            kind: json::str_at(v, "/kind"),
            display_name: json::str_at(v, &p("displayName")).filter(|d| !d.is_empty()),
            description: json::str_at(v, &p("description")).filter(|d| !d.is_empty()),
            severity: json::int_at(v, &p("severity")),
            enabled: json::bool_at(v, &p("enabled")),
            scopes: json::strings_at(v, &p("scopes")),
            frequency: json::str_at(v, &p("evaluationFrequency")),
            window: json::str_at(v, &p("windowSize")),
            target_types: json::strings_at(v, &p("targetResourceTypes")),
            criteria: json::arr(v, &p("criteria/allOf")),
            action_group_ids: json::strings_at(v, &p("actions/actionGroups"))
                .into_iter()
                .filter_map(|g| json::arm_id(Some(g)))
                .collect(),
            mute_for: json::str_at(v, &p("muteActionsDuration")),
            auto_mitigate: json::bool_at(v, &p("autoMitigate")),
            base,
        })
    }

    pub fn condition_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Kind".into(), json::opt(self.kind.clone())),
            ("Severity".into(), sev(self.severity)),
            ("Every · over".into(), format!("{} · {}", duration(self.frequency.as_deref()), duration(self.window.as_deref()))),
        ];
        for c in &self.criteria {
            let agg = json::text(c, "/timeAggregation");
            let measure = json::str_at(c, "/metricMeasureColumn").map(|m| format!(" of {}", m)).unwrap_or_default();
            let threshold = c.pointer("/threshold").map(|t| t.to_string()).unwrap_or_else(|| "-".into());
            lines.push((
                "When".into(),
                format!("{}{} {} {}", agg, measure, op(&json::str_at(c, "/operator").unwrap_or_default()), threshold),
            ));
            if let Some(n) = json::int_at(c, "/failingPeriods/numberOfEvaluationPeriods") {
                lines.push((
                    "  Failing periods".into(),
                    format!("{} of {}", json::num(json::int_at(c, "/failingPeriods/minFailingPeriodsToAlert")), n),
                ));
            }
            if let Some(col) = json::str_at(c, "/resourceIdColumn") {
                lines.push(("  Split by resource".into(), col));
            }
            // The query as plain rows: the pane colours code blocks, `y`
            // copies them as they are. Never run.
            lines.push(("  Query".into(), String::new()));
            for q in json::text(c, "/query").lines() {
                lines.push((String::new(), q.to_string()));
            }
        }
        lines.push(("Resource types".into(), json::join(&self.target_types)));
        lines.push(("Mute actions for".into(), duration(self.mute_for.as_deref())));
        lines.push(("Auto-resolve".into(), json::yes_no(self.auto_mitigate)));
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        lines
    }

    pub fn watches(&self, id: &str) -> bool {
        watches(&self.scopes, &self.target_types, id)
    }
}

impl Resource for LogAlertRow {
    arm_row!("Log search alert");
    /// `Sev1 · law-contoso-prod · every 5m`.
    fn list_summary(&self) -> Option<String> {
        let on = match self.scopes.len() {
            0 => "-".to_string(),
            1 => name_of_id(&self.scopes[0]).to_string(),
            n => format!("{} scopes", n),
        };
        Some(format!("{} · {} · every {}", sev(self.severity), on, duration(self.frequency.as_deref())))
    }
    fn state(&self) -> ResourceState {
        enabled_ladder(&self.base, self.enabled).0
    }
    fn state_label(&self) -> String {
        enabled_ladder(&self.base, self.enabled).1
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&LOG_ALERT_SECTIONS)
    }
    fn search_text(&self) -> String {
        let mut parts = vec![self.base.id.clone(), self.base.name.clone(), self.display_name.clone().unwrap_or_default()];
        parts.extend(self.criteria.iter().filter_map(|c| json::str_at(c, "/query")));
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Display name".into(), json::opt(self.display_name.clone())),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Severity".into(), sev(self.severity)),
            ("Enabled".into(), json::yes_no(self.enabled)),
            ("Action groups".into(), self.action_group_ids.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        rule_related(&self.base.id, &self.scopes, &self.action_group_ids)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az monitor scheduled-query show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Activity log alert ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ActivityLogAlertRow {
    pub base: ArmBase,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub scopes: Vec<String>,
    /// `condition.allOf[]`, each a leaf or an `anyOf`.
    pub conditions: Vec<Value>,
    pub action_group_ids: Vec<String>,
}

impl ActivityLogAlertRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ActivityLogAlertRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(ActivityLogAlertRow {
            description: json::str_at(v, &p("description")).filter(|d| !d.is_empty()),
            enabled: json::bool_at(v, &p("enabled")),
            scopes: json::strings_at(v, &p("scopes")),
            conditions: json::arr(v, &p("condition/allOf")),
            action_group_ids: json::arr(v, &p("actions/actionGroups"))
                .iter()
                .filter_map(|a| json::arm_id(json::str_at(a, "/actionGroupId")))
                .collect(),
            base,
        })
    }

    /// The value a leaf condition on `field` requires.
    fn equals(&self, field: &str) -> Option<String> {
        self.conditions
            .iter()
            .find(|c| json::str_at(c, "/field").is_some_and(|f| same(&f, field)))
            .and_then(|c| json::str_at(c, "/equals"))
    }

    /// `ServiceHealth`, `Administrative`, `ResourceHealth`…
    pub fn category(&self) -> Option<String> {
        self.equals("category")
    }

    fn leaf(c: &Value) -> String {
        let f = json::text(c, "/field");
        match json::str_at(c, "/equals") {
            Some(e) => format!("{} = {}", f, e),
            None => format!("{} in {}", f, json::join(&json::strings_at(c, "/containsAny"))),
        }
    }

    pub fn condition_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("Category".into(), json::opt(self.category()))];
        for c in &self.conditions {
            let any = json::arr(c, "/anyOf");
            if any.is_empty() {
                lines.push(("When".into(), Self::leaf(c)));
            } else {
                lines.push(("When any of".into(), any.iter().map(Self::leaf).collect::<Vec<_>>().join("; ")));
            }
        }
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        lines
    }

    pub fn watches(&self, id: &str) -> bool {
        let types: Vec<String> = self.equals("resourceType").into_iter().collect();
        if self.equals("resourceId").is_some_and(|r| same(&r, id)) {
            return true;
        }
        watches(&self.scopes, &types, id)
    }
}

impl Resource for ActivityLogAlertRow {
    arm_row!("Activity log alert");
    /// `ServiceHealth · 1 action group`.
    fn list_summary(&self) -> Option<String> {
        let n = self.action_group_ids.len();
        Some(format!("{} · {} action group{}", self.category().unwrap_or_else(|| "-".into()), n, if n == 1 { "" } else { "s" }))
    }
    fn state(&self) -> ResourceState {
        enabled_ladder(&self.base, self.enabled).0
    }
    fn state_label(&self) -> String {
        enabled_ladder(&self.base, self.enabled).1
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ACTIVITY_LOG_ALERT_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Category".into(), json::opt(self.category())),
            ("Enabled".into(), json::yes_no(self.enabled)),
            ("Action groups".into(), self.action_group_ids.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        rule_related(&self.base.id, &self.scopes, &self.action_group_ids)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az monitor activity-log alert show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Action group ──────────────────────────────────────────────────────

/// Every receiver array, with the word for one of it and how to name it.
const RECEIVERS: &[(&str, &str)] = &[
    ("emailReceivers", "Email"),
    ("smsReceivers", "SMS"),
    ("voiceReceivers", "Voice"),
    ("azureAppPushReceivers", "App push"),
    ("webhookReceivers", "Webhook"),
    ("logicAppReceivers", "Logic App"),
    ("azureFunctionReceivers", "Function"),
    ("automationRunbookReceivers", "Runbook"),
    ("eventHubReceivers", "Event Hub"),
    ("itsmReceivers", "ITSM"),
    ("armRoleReceivers", "ARM role"),
];

#[derive(Debug, Clone)]
pub struct ActionGroupRow {
    pub base: ArmBase,
    pub short_name: Option<String>,
    pub enabled: Option<bool>,
    /// The receivers, already scrubbed: `(kind word, receiver)`.
    pub receivers: Vec<(&'static str, Value)>,
}

impl ActionGroupRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ActionGroupRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let receivers = RECEIVERS
            .iter()
            .flat_map(|(field, word)| json::arr(v, &format!("/properties/{}", field)).into_iter().map(move |r| (*word, r)))
            .collect();
        Some(ActionGroupRow {
            short_name: json::str_at(v, "/properties/groupShortName"),
            enabled: json::bool_at(v, "/properties/enabled"),
            receivers,
            base,
        })
    }

    /// `2 email · 1 webhook`.
    fn receiver_counts(&self) -> String {
        let mut counts: Vec<(&str, usize)> = Vec::new();
        for (word, _) in &self.receivers {
            match counts.iter_mut().find(|(w, _)| w == word) {
                Some((_, n)) => *n += 1,
                None => counts.push((word, 1)),
            }
        }
        if counts.is_empty() {
            return "no receivers".into();
        }
        counts.iter().map(|(w, n)| format!("{} {}", n, w.to_lowercase())).collect::<Vec<_>>().join(" · ")
    }

    /// Where a receiver sends: an address, a masked number, a URL's host,
    /// or the resource it calls (jumpable).
    fn target(word: &str, r: &Value) -> (String, Option<String>) {
        let s = |p: &str| json::str_at(r, p);
        match word {
            "Email" | "App push" => (json::text(r, "/emailAddress"), None),
            "SMS" | "Voice" => (format!("+{} {}", json::text(r, "/countryCode"), json::text(r, "/phoneNumber")), None),
            "Webhook" => (json::text(r, "/serviceUri"), None),
            "Logic App" => (s("/callbackUrl").unwrap_or_else(|| "-".into()), json::arm_id(s("/resourceId"))),
            "Function" => (
                format!("{} · {}", s("/functionAppResourceId").map(|f| name_of_id(&f).to_string()).unwrap_or_else(|| "-".into()), json::text(r, "/functionName")),
                json::arm_id(s("/functionAppResourceId")),
            ),
            "Runbook" => (
                format!("{} · {}", s("/automationAccountId").map(|a| name_of_id(&a).to_string()).unwrap_or_else(|| "-".into()), json::text(r, "/runbookName")),
                json::arm_id(s("/automationAccountId")),
            ),
            "Event Hub" => (format!("{}/{}", json::text(r, "/eventHubNameSpace"), json::text(r, "/eventHubName")), None),
            "ITSM" => (json::text(r, "/connectionId"), None),
            "ARM role" => (json::text(r, "/roleId"), None),
            _ => ("-".into(), None),
        }
    }

    pub fn receiver_rows(&self) -> Vec<(String, String)> {
        if self.receivers.is_empty() {
            return vec![(String::new(), "⚠ No receivers: alerts routed here reach no one".into())];
        }
        let mut lines = Vec::new();
        for (word, r) in &self.receivers {
            let (target, id) = Self::target(word, r);
            let status = json::str_at(r, "/status").filter(|s| !same(s, "Enabled") && !same(s, "NotSpecified"));
            let label = format!("{} · {}", word, json::text(r, "/name"));
            match id {
                Some(id) => {
                    lines.push((label, id));
                    lines.push(("  Calls".into(), target));
                }
                None => lines.push((label, target)),
            }
            if let Some(s) = status {
                lines.push(("  Status".into(), format!("⚠ {}", s)));
            }
            if json::bool_at(r, "/useCommonAlertSchema") == Some(true) {
                lines.push(("  Common schema".into(), "yes".into()));
            }
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· receiver URLs show their host only (their tokens are in the path or query); numbers their last four digits".into()));
        lines
    }

    fn receiver_ids(&self) -> Vec<(String, String)> {
        self.receivers
            .iter()
            .filter_map(|(word, r)| Self::target(word, r).1.map(|id| (format!("{} · {}", word, name_of_id(&id)), id)))
            .collect()
    }
}

impl Resource for ActionGroupRow {
    arm_row!("Action group");
    /// `ops-oncall · 2 email · 1 webhook`.
    fn list_summary(&self) -> Option<String> {
        Some(format!("{} · {}", self.short_name.as_deref().unwrap_or("-"), self.receiver_counts()))
    }
    fn state(&self) -> ResourceState {
        enabled_ladder(&self.base, self.enabled).0
    }
    fn state_label(&self) -> String {
        enabled_ladder(&self.base, self.enabled).1
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ACTION_GROUP_SECTIONS)
    }
    fn search_text(&self) -> String {
        let mut parts = vec![self.base.id.clone(), self.base.name.clone(), self.short_name.clone().unwrap_or_default()];
        parts.extend(self.receivers.iter().filter_map(|(_, r)| json::str_at(r, "/emailAddress")));
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Short name".into(), json::opt(self.short_name.clone())),
            ("Id".into(), self.base.id.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Enabled".into(), json::yes_no(self.enabled)),
            ("Receivers".into(), self.receiver_counts()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for (label, id) in self.receiver_ids() {
            push_unique(&mut v, label, id);
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az monitor action-group show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Alert processing rule ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProcessingRuleRow {
    pub base: ArmBase,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub scopes: Vec<String>,
    pub conditions: Vec<Value>,
    pub schedule: Option<Value>,
    /// `AddActionGroups` or `RemoveAllActionGroups`, per action.
    pub action_types: Vec<String>,
    pub action_group_ids: Vec<String>,
}

impl ProcessingRuleRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ProcessingRuleRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let actions = json::arr(v, &p("actions"));
        Some(ProcessingRuleRow {
            description: json::str_at(v, &p("description")).filter(|d| !d.is_empty()),
            enabled: json::bool_at(v, &p("enabled")),
            scopes: json::strings_at(v, &p("scopes")),
            conditions: json::arr(v, &p("conditions")),
            schedule: v.pointer(&p("schedule")).filter(|s| s.is_object()).cloned(),
            action_types: actions.iter().filter_map(|a| json::str_at(a, "/actionType")).collect(),
            action_group_ids: actions
                .iter()
                .flat_map(|a| json::strings_at(a, "/actionGroupIds"))
                .filter_map(|g| json::arm_id(Some(g)))
                .collect(),
            base,
        })
    }

    pub fn suppresses(&self) -> bool {
        self.action_types.iter().any(|t| same(t, "RemoveAllActionGroups"))
    }

    fn effect(&self) -> String {
        if self.suppresses() {
            "suppress notifications".into()
        } else if !self.action_group_ids.is_empty() {
            let n = self.action_group_ids.len();
            format!("add {} action group{}", n, if n == 1 { "" } else { "s" })
        } else {
            "-".into()
        }
    }

    fn schedule_rows(&self) -> Vec<(String, String)> {
        let Some(s) = &self.schedule else {
            return vec![("Schedule".into(), "always".into())];
        };
        let mut lines = vec![
            ("From · until".into(), format!("{} · {}", json::text(s, "/effectiveFrom"), json::text(s, "/effectiveUntil"))),
            ("Time zone".into(), json::text(s, "/timeZone")),
        ];
        for r in json::arr(s, "/recurrences") {
            let days: Vec<String> = json::strings_at(&r, "/daysOfWeek")
                .into_iter()
                .chain(json::arr(&r, "/daysOfMonth").iter().map(|d| d.to_string()))
                .collect();
            lines.push((
                format!("  {}", json::text(&r, "/recurrenceType")),
                format!("{}–{}{}", json::text(&r, "/startTime"), json::text(&r, "/endTime"), if days.is_empty() { String::new() } else { format!(" · {}", days.join(", ")) }),
            ));
        }
        lines
    }

    pub fn rule_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("Effect".into(), self.effect())];
        for g in &self.action_group_ids {
            lines.push((format!("Adds · {}", name_of_id(g)), g.clone()));
        }
        if self.conditions.is_empty() {
            lines.push(("When".into(), "every alert in scope".into()));
        }
        for c in &self.conditions {
            lines.push((
                "When".into(),
                format!("{} {} {}", json::text(c, "/field"), json::text(c, "/operator"), json::join(&json::strings_at(c, "/values"))),
            ));
        }
        lines.extend(self.schedule_rows());
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        lines
    }
}

impl Resource for ProcessingRuleRow {
    arm_row!("Alert processing rule");
    /// `suppress notifications · 2 conditions`.
    fn list_summary(&self) -> Option<String> {
        let n = self.conditions.len();
        Some(format!("{} · {} condition{}", self.effect(), n, if n == 1 { "" } else { "s" }))
    }
    fn state(&self) -> ResourceState {
        enabled_ladder(&self.base, self.enabled).0
    }
    fn state_label(&self) -> String {
        enabled_ladder(&self.base, self.enabled).1
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&PROCESSING_RULE_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Effect".into(), self.effect()),
            ("Enabled".into(), json::yes_no(self.enabled)),
            ("Scopes".into(), self.scopes.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        rule_related(&self.base.id, &self.scopes, &self.action_group_ids)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az monitor alert-processing-rule show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Fired alert ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FiredAlertRow {
    pub base: ArmBase,
    pub severity: Option<String>,
    pub signal: Option<String>,
    /// `New`, `Acknowledged`, `Closed`.
    pub alert_state: Option<String>,
    /// `Fired`, `Resolved`.
    pub condition: Option<String>,
    pub service: Option<String>,
    pub rule_id: Option<String>,
    pub target_id: Option<String>,
    pub target_type: Option<String>,
    pub started: Option<String>,
    pub modified: Option<String>,
    pub modified_by: Option<String>,
    pub resolved: Option<String>,
    pub description: Option<String>,
    pub suppressed: Option<bool>,
}

impl FiredAlertRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<FiredAlertRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let e = |k: &str| json::str_at(v, &format!("/properties/essentials/{}", k)).filter(|s| !s.is_empty());
        Some(FiredAlertRow {
            severity: e("severity"),
            signal: e("signalType"),
            alert_state: e("alertState"),
            condition: e("monitorCondition"),
            service: e("monitorService"),
            rule_id: json::arm_id(e("alertRule")),
            target_id: json::arm_id(e("targetResource")),
            target_type: e("targetResourceType"),
            started: e("startDateTime"),
            modified: e("lastModifiedDateTime"),
            modified_by: e("lastModifiedUserName"),
            resolved: e("monitorConditionResolvedDateTime"),
            description: e("description"),
            suppressed: json::bool_at(v, "/properties/essentials/actionStatus/isSuppressed"),
            base,
        })
    }

    /// Fired and not closed is the alarm; acknowledged is someone on it;
    /// resolved or closed is over.
    pub fn ladder(&self) -> (ResourceState, String) {
        let state = self.alert_state.as_deref().unwrap_or("");
        let fired = self.condition.as_deref().is_some_and(|c| same(c, "Fired"));
        let (bucket, label) = if same(state, "Closed") {
            (ResourceState::Stopped, "closed")
        } else if !fired {
            (ResourceState::Available, "resolved")
        } else if same(state, "Acknowledged") {
            (ResourceState::Pending, "acknowledged")
        } else {
            (ResourceState::Unavailable, "fired")
        };
        state_ladder(None, Some((bucket, label)))
    }

    pub fn alert_rows(&self, now: i64) -> Vec<(String, String)> {
        let ago = |t: &Option<String>| match t.as_deref().and_then(crate::azure::metrics::parse_iso_utc) {
            Some(secs) => format!("{} ({})", json::time(t.clone()), crate::azure::services::backup::ago(secs, now)),
            None => json::time(t.clone()),
        };
        let mut lines = vec![
            ("Severity".into(), json::opt(self.severity.clone())),
            ("Condition · state".into(), format!("{} · {}", json::opt(self.condition.clone()), json::opt(self.alert_state.clone()))),
            ("Fired".into(), ago(&self.started)),
        ];
        if self.resolved.is_some() {
            lines.push(("Resolved".into(), ago(&self.resolved)));
        }
        lines.push(("Last changed".into(), format!("{} by {}", ago(&self.modified), json::opt(self.modified_by.clone()))));
        lines.push(("Monitor service · signal".into(), format!("{} · {}", json::opt(self.service.clone()), json::opt(self.signal.clone()))));
        if let Some(t) = &self.target_id {
            lines.push((format!("Resource · {}", name_of_id(t)), t.clone()));
        }
        if let Some(r) = &self.rule_id {
            lines.push((format!("Rule · {}", name_of_id(r)), r.clone()));
        }
        if self.suppressed == Some(true) {
            lines.push(("Notifications".into(), "suppressed by an alert processing rule".into()));
        }
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· acknowledging or closing an alert is a POST (changestate): nebaz never sends it".into()));
        lines
    }
}

impl Resource for FiredAlertRow {
    arm_row!("Fired alert");
    /// `Sev1 · vm-jump-01 · Metric`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([
            self.severity.clone(),
            self.target_id.as_deref().map(|t| name_of_id(t).to_string()),
            self.signal.clone(),
        ])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&FIRED_ALERT_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Rule".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Severity".into(), json::opt(self.severity.clone())),
            ("Fired".into(), json::time(self.started.clone())),
            ("Resource".into(), self.target_id.as_deref().map(|t| name_of_id(t).to_string()).unwrap_or_else(|| "-".into())),
            ("Resource type".into(), json::opt(self.target_type.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = Vec::new();
        if let Some(t) = &self.target_id {
            push_unique(&mut v, format!("Resource · {}", name_of_id(t)), t.clone());
        }
        if let Some(r) = &self.rule_id {
            push_unique(&mut v, format!("Alert rule · {}", name_of_id(r)), r.clone());
        }
        v
    }
    /// The alert's own id is no portal page: the resource's is, with its
    /// Alerts blade.
    fn portal_url(&self) -> Option<String> {
        portal_url_for(self.target_id.as_deref().unwrap_or(&self.base.id), self.base.tenant.as_deref())
    }
    /// No `az` command reads a fired alert.
    fn cli_command(&self) -> Option<String> {
        None
    }
}

// ── The joins ─────────────────────────────────────────────────────────

/// The alert rules in the warm lists that watch `id`, as Related lines:
/// what the app splices into every type's Related.
pub fn rules_watching(id: &str, lists: &[&[Box<dyn Resource>]]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for r in lists.iter().flat_map(|l| l.iter()) {
        let any = r.as_any();
        let (word, hit) = if let Some(m) = any.downcast_ref::<MetricAlertRow>() {
            ("Metric alert", m.watches(id))
        } else if let Some(l) = any.downcast_ref::<LogAlertRow>() {
            ("Log alert", l.watches(id))
        } else if let Some(a) = any.downcast_ref::<ActivityLogAlertRow>() {
            ("Activity alert", a.watches(id))
        } else {
            continue;
        };
        if hit && !same(r.id(), id) {
            push_unique(&mut out, format!("{} · {}", word, r.name()), r.id().to_string());
        }
    }
    out
}

/// Every rule and processing rule in the warm lists that names `group`.
fn users_of<'a>(group: &str, lists: &[&'a [Box<dyn Resource>]]) -> Vec<(&'static str, &'a dyn Resource)> {
    let mut out = Vec::new();
    for r in lists.iter().flat_map(|l| l.iter()) {
        let any = r.as_any();
        let (word, ids): (&str, &[String]) = if let Some(m) = any.downcast_ref::<MetricAlertRow>() {
            ("Metric alert", &m.action_group_ids)
        } else if let Some(l) = any.downcast_ref::<LogAlertRow>() {
            ("Log alert", &l.action_group_ids)
        } else if let Some(a) = any.downcast_ref::<ActivityLogAlertRow>() {
            ("Activity alert", &a.action_group_ids)
        } else if let Some(p) = any.downcast_ref::<ProcessingRuleRow>() {
            ("Processing rule", &p.action_group_ids)
        } else {
            continue;
        };
        if ids.iter().any(|g| same(g, group)) {
            out.push((word, r.as_ref()));
        }
    }
    out
}

/// What an Alerts section reads beyond its row: the warm rule lists, or
/// where they stand.
pub struct AlertsContext<'a> {
    pub rule_lists: Vec<&'a [Box<dyn Resource>]>,
    /// The lists a section needs that are not there, by sub-tab label:
    /// loading, failed, or never asked for.
    pub missing: Vec<(&'a str, Warm<'a>)>,
    pub now: i64,
}

fn used_by_rows(g: &ActionGroupRow, cx: &AlertsContext) -> Vec<(String, String)> {
    let found = users_of(&g.base.id, &cx.rule_lists);
    let mut lines: Vec<(String, String)> = found
        .iter()
        .map(|(word, r)| (format!("{} · {}", word, r.name()), r.id().to_string()))
        .collect();
    // A list in flight reads `Loading…`, so `X` waits for it.
    if cx.missing.iter().any(|(_, w)| matches!(w, Warm::Loading)) {
        return vec![("Used by".into(), "Loading…".into())];
    }
    if lines.is_empty() {
        lines.push((String::new(), "No rule in the loaded lists sends to this group".into()));
    }
    for (label, w) in &cx.missing {
        lines.push((String::new(), String::new()));
        match w {
            Warm::Failed(e) => lines.push((String::new(), format!("⚠ {}: {}", label, e))),
            _ => lines.push((String::new(), format!("· {} is not loaded: open it to match its rules", label))),
        }
    }
    lines
}

pub fn alerts_section_lines(r: &dyn Resource, idx: usize, cx: &AlertsContext) -> Option<Vec<(String, String)>> {
    let any = r.as_any();
    let app = crate::azure::services::rendered_by_app;
    macro_rules! rule {
        ($row:ty, $sections:ident) => {
            if let Some(x) = any.downcast_ref::<$row>() {
                use $sections as S;
                return Some(match S::from_index(idx) {
                    S::Overview => overview_rows(x),
                    S::Condition => x.condition_rows(),
                    S::Scopes => scope_rows(&x.scopes),
                    S::Actions => action_group_rows(&x.action_group_ids, NO_GROUPS),
                    S::Access | S::Activity => app(),
                    S::Related => related_rows_with(x, Vec::new()),
                    S::Tags => tag_rows(x.tags()),
                });
            }
        };
    }
    rule!(MetricAlertRow, MetricAlertDetailSection);
    rule!(LogAlertRow, LogAlertDetailSection);
    rule!(ActivityLogAlertRow, ActivityLogAlertDetailSection);
    if let Some(x) = any.downcast_ref::<ActionGroupRow>() {
        use ActionGroupDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Receivers => x.receiver_rows(),
            S::UsedBy => used_by_rows(x, cx),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(
                x,
                users_of(&x.base.id, &cx.rule_lists).iter().map(|(w, r)| (format!("Used by {} · {}", w.to_lowercase(), r.name()), r.id().to_string())).collect(),
            ),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<ProcessingRuleRow>() {
        use ProcessingRuleDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Rule => x.rule_rows(),
            S::Scopes => scope_rows(&x.scopes),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(x, Vec::new()),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<FiredAlertRow>() {
        use FiredAlertDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Alert => x.alert_rows(cx.now),
            S::Activity => app(),
            S::Related => related_rows_with(x, Vec::new()),
        });
    }
    None
}

// ── Provider ──────────────────────────────────────────────────────────

/// A list call: path, version, query, progress words.
pub type ListCall = (&'static str, &'static str, &'static [(&'static str, &'static str)], &'static str);

/// The alert sub-tabs' list call.
pub fn alert_list_of(view: JumpView) -> Option<ListCall> {
    Some(match view {
        JumpView::MetricAlerts => (METRIC_ALERTS_PATH, METRIC_ALERTS_API_VERSION, &[], "Listing metric alerts…"),
        JumpView::LogAlerts => (LOG_ALERTS_PATH, LOG_ALERTS_API_VERSION, &[], "Listing log search alerts…"),
        JumpView::ActivityLogAlerts => (ACTIVITY_LOG_ALERTS_PATH, ACTIVITY_LOG_ALERTS_API_VERSION, &[], "Listing activity log alerts…"),
        JumpView::ActionGroups => (ACTION_GROUPS_PATH, ACTION_GROUPS_API_VERSION, &[], "Listing action groups…"),
        JumpView::AlertProcessingRules => (PROCESSING_RULES_PATH, PROCESSING_RULES_API_VERSION, &[], "Listing alert processing rules…"),
        JumpView::FiredAlerts => (FIRED_ALERTS_PATH, ALERTS_API_VERSION, FIRED_ALERTS_QUERY, "Listing the alerts fired in the last 30 days…"),
        _ => return None,
    })
}

pub fn alert_rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    fn boxed<T: Resource + 'static>(rows: impl Iterator<Item = T>) -> Vec<Box<dyn Resource>> {
        rows.map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }
    match view {
        JumpView::MetricAlerts => boxed(page.iter().filter_map(|v| MetricAlertRow::from_json(v, tenant))),
        JumpView::LogAlerts => boxed(page.iter().filter_map(|v| LogAlertRow::from_json(v, tenant))),
        JumpView::ActivityLogAlerts => boxed(page.iter().filter_map(|v| ActivityLogAlertRow::from_json(v, tenant))),
        JumpView::ActionGroups => boxed(page.iter().filter_map(|v| ActionGroupRow::from_json(v, tenant))),
        JumpView::AlertProcessingRules => boxed(page.iter().filter_map(|v| ProcessingRuleRow::from_json(v, tenant))),
        JumpView::FiredAlerts => boxed(page.iter().filter_map(|v| FiredAlertRow::from_json(v, tenant))),
        _ => Vec::new(),
    }
}

/// The alert sub-tabs inside the Monitor provider.
pub struct AlertLists<'a> {
    pub scope: &'a Scope,
}

impl AlertLists<'_> {
    pub async fn list(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, version, query, _) = alert_list_of(view).ok_or_else(|| Error::ResourceNotFound(view.as_str().into()))?;
        let page = self.scope.list_query(path, version, query).await?;
        Ok(alert_rows(view, &page, self.scope.tenant()))
    }

    pub async fn stream(&self, view: JumpView, event_tx: &mpsc::UnboundedSender<Event>, service_type: ServiceType) -> Result<()> {
        let Some((path, version, query, message)) = alert_list_of(view) else {
            return Ok(());
        };
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(path, version, query, service_type, message, event_tx, |page| alert_rows(view, &page, tenant.as_deref()))
            .await;
        finish_stream(service_type, r, event_tx)
    }

    pub async fn get(&self, id: &str, view: JumpView) -> Result<Box<dyn Resource>> {
        let (_, version, _, _) = alert_list_of(view).ok_or_else(|| Error::ResourceNotFound(id.to_string()))?;
        let v = self.scope.get(id, version).await?;
        alert_rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-app";
    const VM: &str = "/subscriptions/0000/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1";

    fn texts(lines: &[(String, String)]) -> String {
        lines.iter().map(|(l, v)| format!("{} = {}\n", l, v)).collect()
    }

    fn ag() -> String {
        format!("{}/providers/Microsoft.Insights/actionGroups/ag-oncall", RG)
    }

    fn metric(scopes: Value, target_type: &str) -> MetricAlertRow {
        MetricAlertRow::from_json(
            &json!({
                "id": format!("{}/providers/Microsoft.Insights/metricAlerts/cpu-high", RG), "name": "cpu-high", "location": "global",
                "properties": {
                    "severity": 2, "enabled": true, "scopes": scopes, "evaluationFrequency": "PT1M", "windowSize": "PT5M",
                    "targetResourceType": target_type,
                    "criteria": {"odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                                 "allOf": [{"name": "c1", "metricName": "Percentage CPU", "timeAggregation": "Average",
                                            "operator": "GreaterThan", "threshold": 80, "criterionType": "StaticThresholdCriterion"}]},
                    "actions": [{"actionGroupId": ag(), "webHookProperties": {"token": "never-shown"}}]
                }
            }),
            None,
        )
        .unwrap()
    }

    #[test]
    fn a_metric_alert_reads_its_condition_and_drops_the_webhook_payload() {
        let m = metric(json!([VM]), "Microsoft.Compute/virtualMachines");
        assert!(!m.base.raw.contains("never-shown"), "{}", m.base.raw);
        assert_eq!(m.list_summary().unwrap(), "Sev2 · Percentage CPU Average > 80 · vm-1");
        let c = texts(&m.condition_rows());
        assert!(c.contains("Every · over = 1m · 5m"), "{}", c);
        assert_eq!(m.state_label(), "enabled");
    }

    #[test]
    fn a_rule_watches_its_scope_and_a_held_resource_only_of_its_type() {
        let on_vm = metric(json!([VM]), "Microsoft.Compute/virtualMachines");
        assert!(on_vm.watches(VM));
        let on_group = metric(json!([RG]), "Microsoft.Compute/virtualMachines");
        assert!(on_group.watches(VM));
        assert!(!on_group.watches(&format!("{}/providers/Microsoft.Storage/storageAccounts/st1", RG)));
        // A prefix that is not a parent: rg-app is not rg-app-2.
        assert!(!on_group.watches("/subscriptions/0000/resourceGroups/rg-app-2/providers/Microsoft.Compute/virtualMachines/vm-9"));
        let warm: Vec<Box<dyn Resource>> = vec![Box::new(on_vm)];
        assert_eq!(rules_watching(VM, &[&warm]), vec![("Metric alert · cpu-high".to_string(), warm[0].id().to_string())]);
    }

    #[test]
    fn a_subscription_service_health_alert_is_not_on_every_row() {
        let a = ActivityLogAlertRow::from_json(
            &json!({"id": format!("{}/providers/Microsoft.Insights/activityLogAlerts/sh", RG), "name": "sh", "location": "Global",
                    "properties": {"enabled": true, "scopes": ["/subscriptions/0000"],
                                   "condition": {"allOf": [{"field": "category", "equals": "ServiceHealth"}]},
                                   "actions": {"actionGroups": [{"actionGroupId": ag()}]}}}),
            None,
        )
        .unwrap();
        assert_eq!(a.category().as_deref(), Some("ServiceHealth"));
        assert!(!a.watches(VM));
        assert!(a.watches("/subscriptions/0000"));
        assert_eq!(a.list_summary().unwrap(), "ServiceHealth · 1 action group");
    }

    #[test]
    fn receiver_urls_keep_their_host_and_numbers_their_last_digits() {
        let g = ActionGroupRow::from_json(
            &json!({"id": ag(), "name": "ag-oncall", "location": "Global",
                    "properties": {"groupShortName": "oncall", "enabled": true,
                        "emailReceivers": [{"name": "ops", "emailAddress": "ops@contoso.com", "status": "Enabled"}],
                        "smsReceivers": [{"name": "lead", "countryCode": "61", "phoneNumber": "412345678"}],
                        "webhookReceivers": [{"name": "slack", "serviceUri": "https://hooks.slack.com/services/T0/B0/secretpath?x=never-shown"}],
                        "logicAppReceivers": [{"name": "la", "resourceId": format!("{}/providers/Microsoft.Logic/workflows/la-1", RG),
                                               "callbackUrl": "https://prod-1.westeurope.logic.azure.com/workflows/x/triggers/manual/paths/invoke?sig=never-shown"}],
                        "itsmReceivers": [{"name": "snow", "connectionId": "c1", "ticketConfiguration": "{\"secret\": \"never-shown\"}"}]}}),
            None,
        )
        .unwrap();
        assert!(!g.base.raw.contains("never-shown") && !g.base.raw.contains("secretpath") && !g.base.raw.contains("412345"), "{}", g.base.raw);
        assert_eq!(g.list_summary().unwrap(), "oncall · 1 email · 1 sms · 1 webhook · 1 logic app · 1 itsm");
        let r = texts(&g.receiver_rows());
        assert!(r.contains("Webhook · slack = https://hooks.slack.com/…"), "{}", r);
        assert!(r.contains("SMS · lead = +61 ****5678"), "{}", r);
        assert!(r.contains("Logic App · la = ") && r.contains("Calls = https://prod-1.westeurope.logic.azure.com/…"), "{}", r);
    }

    #[test]
    fn an_action_group_finds_the_rules_that_use_it() {
        let g = ActionGroupRow::from_json(&json!({"id": ag(), "name": "ag-oncall", "location": "Global", "properties": {}}), None).unwrap();
        let warm: Vec<Box<dyn Resource>> = vec![Box::new(metric(json!([VM]), "Microsoft.Compute/virtualMachines"))];
        let cx = AlertsContext { rule_lists: vec![&warm], missing: Vec::new(), now: 0 };
        let lines = used_by_rows(&g, &cx);
        assert_eq!(lines[0].0, "Metric alert · cpu-high");
        assert!(texts(&g.receiver_rows()).contains("⚠ No receivers"));
    }

    #[test]
    fn a_processing_rule_says_it_suppresses() {
        let p = ProcessingRuleRow::from_json(
            &json!({"id": format!("{}/providers/Microsoft.AlertsManagement/actionRules/maint", RG), "name": "maint", "location": "Global",
                    "properties": {"enabled": true, "scopes": [RG],
                        "conditions": [{"field": "Severity", "operator": "Equals", "values": ["Sev3", "Sev4"]}],
                        "schedule": {"timeZone": "UTC", "recurrences": [{"recurrenceType": "Weekly", "startTime": "22:00:00", "endTime": "23:59:59", "daysOfWeek": ["Saturday"]}]},
                        "actions": [{"actionType": "RemoveAllActionGroups"}]}}),
            None,
        )
        .unwrap();
        assert!(p.suppresses());
        assert_eq!(p.list_summary().unwrap(), "suppress notifications · 1 condition");
        assert!(texts(&p.rule_rows()).contains("Weekly = 22:00:00–23:59:59 · Saturday"));
    }

    #[test]
    fn a_fired_alert_is_red_until_acknowledged_or_resolved() {
        let fired = |state: &str, cond: &str| {
            FiredAlertRow::from_json(
                &json!({"id": "/subscriptions/0000/providers/Microsoft.AlertsManagement/alerts/a1", "name": "cpu-high",
                        "properties": {"essentials": {"severity": "Sev2", "alertState": state, "monitorCondition": cond,
                                                      "targetResource": VM, "alertRule": format!("{}/providers/Microsoft.Insights/metricAlerts/cpu-high", RG),
                                                      "signalType": "Metric", "startDateTime": "2026-11-05T10:00:00Z"}}}),
                None,
            )
            .unwrap()
        };
        assert_eq!(fired("New", "Fired").state(), ResourceState::Unavailable);
        assert_eq!(fired("Acknowledged", "Fired").state_label(), "acknowledged");
        assert_eq!(fired("New", "Resolved").state_label(), "resolved");
        assert_eq!(fired("Closed", "Fired").state_label(), "closed");
        let a = fired("New", "Fired");
        assert_eq!(a.list_summary().unwrap(), "Sev2 · vm-1 · Metric");
        assert!(a.related().iter().any(|(l, _)| l == "Alert rule · cpu-high"));
        assert!(a.portal_url().unwrap().contains("virtualMachines/vm-1"));
        assert!(is_fired_alert_id(a.id()));
    }

    #[test]
    fn durations_read_short() {
        assert_eq!(duration(Some("PT5M")), "5m");
        assert_eq!(duration(Some("PT1H30M")), "1h30m");
        assert_eq!(duration(Some("P1D")), "1d");
        assert_eq!(duration(Some("weird")), "weird");
    }

    #[test]
    fn section_labels_keep_the_shared_order() {
        for d in [&METRIC_ALERT_SECTIONS, &LOG_ALERT_SECTIONS, &ACTIVITY_LOG_ALERT_SECTIONS, &ACTION_GROUP_SECTIONS, &PROCESSING_RULE_SECTIONS] {
            let labels: Vec<&str> = d.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels[0], "Overview");
            assert_eq!(&labels[labels.len() - 4..], &["Access", "Activity", "Related", "Tags"]);
        }
        let fired: Vec<&str> = FIRED_ALERT_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(fired, ["Overview", "Alert", "Activity", "Related"]);
    }
}
