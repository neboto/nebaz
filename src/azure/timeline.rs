// ported from neboto-tui src/timeline.rs @ ee8eb89 (adapted: the Activity
// Log, Resource Health, fired alerts and ARM deployments in place of
// CloudTrail, alarms, CloudFormation, ECS, Auto Scaling and RDS)
//! The change timeline's row model: what changed around a resource, from
//! several control-plane sources merged newest first, shown by the `W`
//! lens (#52, `ui::widgets::timeline_lens`). It reads the Activity Log
//! through the Activity section's query (`services::activity`).
//!
//! - `ACT`  — Activity Log operations (`eventtypes/management/values`),
//!   collapsed to one row per operation, its final status.
//! - `HLTH` — Resource Health availability transitions
//!   (`Microsoft.ResourceHealth/availabilityStatuses`).
//! - `ALRT` — fired alerts (`Microsoft.AlertsManagement/alerts`): a row
//!   when one fired and another when it resolved, never the rule.
//! - `DEP`  — ARM deployments (`Microsoft.Resources/deployments`), from
//!   the resource group's deployment history.
//!
//! Every row keeps **named fields** only (for `$EDITOR`): never an event's `properties` bag, a deployment's parameters
//! or outputs, or the caller's token claims (rule 12).

use crate::azure::resource::{name_of_id, resource_group_of, subscription_of};
use crate::azure::services::json;
use serde_json::Value;

/// Resource Health: the newest stable version (Microsoft Learn,
/// 2026-10-24; `2025-05-01`).
pub const HEALTH_API_VERSION: &str = "2025-05-01";

/// Alerts Management `alerts`: the only stable version (azure-rest-api-specs
/// `AlertsManagement/stable/2019-03-01`, 2026-10-24; the rest are previews).
pub const ALERTS_API_VERSION: &str = "2019-03-01";

/// `Microsoft.Resources/deployments`: the resources spec's newest stable
/// (Microsoft Learn, 2026-10-24), the version the All resources list uses.
pub const DEPLOYMENTS_API_VERSION: &str = "2025-04-01";

/// The `W` lens stops paging the Activity Log after this many events (the
/// header says so): 90 days of a busy resource is thousands.
pub const TIMELINE_MAX_EVENTS: usize = 1000;

/// …and every other source after this many items.
pub const TIMELINE_MAX_ITEMS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimelineSource {
    Activity,
    Health,
    Alert,
    Deployment,
}

impl TimelineSource {
    /// The filter-cycle order (`f`).
    pub const ALL: [TimelineSource; 4] = [
        TimelineSource::Activity,
        TimelineSource::Health,
        TimelineSource::Alert,
        TimelineSource::Deployment,
    ];

    /// Fixed-width row badge (4 chars).
    pub fn badge(self) -> &'static str {
        match self {
            TimelineSource::Activity => " ACT",
            TimelineSource::Health => "HLTH",
            TimelineSource::Alert => "ALRT",
            TimelineSource::Deployment => " DEP",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TimelineSource::Activity => "Activity Log",
            TimelineSource::Health => "Resource Health",
            TimelineSource::Alert => "Alerts",
            TimelineSource::Deployment => "Deployments",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TimelineRow {
    /// Unix seconds, for the merge (0 when the source had no parseable
    /// time: such rows sink to the bottom).
    pub ts_secs: i64,
    /// `YYYY-MM-DD HH:MM` UTC, one format across sources.
    pub time: String,
    pub source: Option<TimelineSource>,
    /// What happened: the operation, the availability state, the alert
    /// transition, the deployment's state.
    pub what: String,
    /// What it happened to, short: a resource or deployment name.
    pub subject: String,
    /// Who or why: the caller, the health event's cause, the alert's
    /// monitor service, the deployment's name.
    pub who: String,
    /// Trailing context: a sub-status, a summary, an error.
    pub detail: String,
    /// Marks `what` red (a failed operation, an unhealthy transition, a
    /// fired alert, a failed deployment).
    pub failed: bool,
    /// The native status word (the state column of `@changes`).
    pub status: String,
    /// An Activity row that is a change (a write, delete or action that
    /// finished, Succeeded or Failed); every other source's row is one.
    pub change: bool,
    /// The caller, for the noise classification (Activity rows only).
    pub caller: String,
    /// The ARM id the row is about, when there is one.
    pub target: Option<String>,
    /// Labelled ARM ids the row links to (the Related section).
    pub links: Vec<(String, String)>,
    /// Named fields, in order: the editor view and `@changes`'s Overview.
    pub fields: Vec<(String, String)>,
    /// Unique within a source: the row's identity.
    pub key: String,
}

impl TimelineRow {
    pub fn source(&self) -> TimelineSource {
        self.source.unwrap_or(TimelineSource::Activity)
    }

    /// One Activity Log operation (an event of [`collapse_operations`]).
    pub fn from_activity(e: &Value) -> Self {
        let ts_raw = json::str_at(e, "/eventTimestamp");
        let ts = ts_raw.as_deref().and_then(parse_ts).unwrap_or(0);
        let op_value = json::str_at(e, "/operationName/value").unwrap_or_default();
        let operation = json::str_at(e, "/operationName/localizedValue")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| op_value.clone());
        let status = json::str_at(e, "/status/value")
            .or_else(|| json::str_at(e, "/status/localizedValue"))
            .unwrap_or_default();
        let sub_status = json::str_at(e, "/subStatus/localizedValue")
            .filter(|s| !s.is_empty())
            .or_else(|| json::str_at(e, "/subStatus/value"))
            .unwrap_or_default();
        let level = json::str_at(e, "/level").unwrap_or_default();
        let caller = json::str_at(e, "/caller").unwrap_or_default();
        let target = json::arm_id(json::str_at(e, "/resourceId"));
        let correlation = json::str_at(e, "/correlationId").unwrap_or_default();
        let failed = matches!(level.as_str(), "Error" | "Critical") || status.eq_ignore_ascii_case("failed");
        let mut fields = vec![
            ("Time".to_string(), json::time(ts_raw)),
            ("Source".into(), TimelineSource::Activity.label().into()),
            ("Operation".into(), operation.clone()),
            ("Operation name".into(), json::opt(Some(op_value.clone()))),
            ("Status".into(), json::opt(Some(status.clone()))),
        ];
        if !sub_status.is_empty() {
            fields.push(("Detail".into(), sub_status.clone()));
        }
        fields.push(("Caller".into(), json::opt(Some(caller.clone()))));
        fields.push(("Resource".into(), json::opt(target.clone())));
        fields.push(("Correlation id".into(), json::opt(Some(correlation.clone()))));
        fields.push(("Level".into(), json::opt(Some(level))));
        TimelineRow {
            ts_secs: ts,
            time: fmt_ts(ts),
            source: Some(TimelineSource::Activity),
            subject: target.as_deref().map(name_of_id).unwrap_or_default().to_string(),
            what: operation,
            who: caller.clone(),
            detail: sub_status,
            failed,
            change: is_change_operation(&op_value, &status),
            status,
            caller,
            links: target.iter().map(|t| (format!("Resource · {}", name_of_id(t)), t.clone())).collect(),
            target,
            fields,
            key: format!("act:{}:{}", correlation, op_value.to_lowercase()),
        }
    }

    /// One Resource Health availability status (current or historical).
    pub fn from_health(v: &Value) -> Self {
        let p = |f: &str| json::str_at(v, &format!("/properties/{}", f)).filter(|s| !s.is_empty());
        let occurred = p("occuredTime").or_else(|| p("occurredTime"));
        let ts = occurred.as_deref().and_then(parse_ts).unwrap_or(0);
        let state = p("availabilityState").unwrap_or_else(|| "Event".into());
        let target = json::str_at(v, "/id").and_then(|id| health_target(&id));
        let cause = [p("reasonType"), p("context").or_else(|| p("healthEventCause"))]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
        let summary = p("summary").or_else(|| p("title")).unwrap_or_default();
        let failed = matches!(state.to_lowercase().as_str(), "unavailable" | "degraded");
        let mut fields = vec![
            ("Time".to_string(), json::time(occurred)),
            ("Source".into(), TimelineSource::Health.label().into()),
            ("State".into(), state.clone()),
        ];
        for (label, field) in [
            ("Title", "title"),
            ("Summary", "summary"),
            ("Detail", "detailedStatus"),
            ("Reason", "reasonType"),
            ("Cause", "context"),
            ("Category", "category"),
            ("Reported", "reportedTime"),
            ("Resolution ETA", "resolutionETA"),
        ] {
            if let Some(value) = p(field) {
                fields.push((label.into(), value));
            }
        }
        fields.push(("Resource".into(), json::opt(target.clone())));
        TimelineRow {
            ts_secs: ts,
            time: fmt_ts(ts),
            source: Some(TimelineSource::Health),
            subject: target.as_deref().map(name_of_id).unwrap_or_default().to_string(),
            what: state.clone(),
            who: cause,
            detail: summary,
            failed,
            status: state.clone(),
            change: true,
            caller: String::new(),
            links: target.iter().map(|t| (format!("Resource · {}", name_of_id(t)), t.clone())).collect(),
            key: format!("hlth:{}:{}:{}", target.as_deref().unwrap_or("-").to_lowercase(), ts, state),
            target,
            fields,
        }
    }

    /// One fired alert: a row when it fired, and one when it resolved.
    pub fn from_alert(v: &Value) -> Vec<Self> {
        let e = |f: &str| json::str_at(v, &format!("/properties/essentials/{}", f)).filter(|s| !s.is_empty());
        let name = json::str_at(v, "/name").unwrap_or_else(|| "alert".into());
        let severity = e("severity").unwrap_or_default();
        let service = e("monitorService").unwrap_or_default();
        let target = json::arm_id(e("targetResource"));
        let id = json::str_at(v, "/id").unwrap_or_default();
        let mut fields = vec![
            ("Alert".to_string(), name.clone()),
            ("Source".into(), TimelineSource::Alert.label().into()),
            ("Severity".into(), json::opt(Some(severity.clone()))),
            ("Condition".into(), json::opt(e("monitorCondition"))),
            ("State".into(), json::opt(e("alertState"))),
            ("Monitor service".into(), json::opt(Some(service.clone()))),
            ("Signal".into(), json::opt(e("signalType"))),
            ("Fired".into(), json::time(e("startDateTime"))),
            ("Resolved".into(), json::time(e("monitorConditionResolvedDateTime"))),
            ("Resource".into(), json::opt(target.clone())),
        ];
        if let Some(d) = e("description") {
            fields.push(("Description".into(), d));
        }
        let mut links: Vec<(String, String)> =
            target.iter().map(|t| (format!("Resource · {}", name_of_id(t)), t.clone())).collect();
        if let Some(rule) = json::arm_id(e("alertRule")) {
            links.push((format!("Alert rule · {}", name_of_id(&rule)), rule));
        }
        let row = |at: Option<String>, what: &str, failed: bool, status: &str| {
            let ts = at.as_deref().and_then(parse_ts).unwrap_or(0);
            TimelineRow {
                ts_secs: ts,
                time: fmt_ts(ts),
                source: Some(TimelineSource::Alert),
                what: if severity.is_empty() { what.to_string() } else { format!("{} · {}", what, severity) },
                subject: target.as_deref().map(name_of_id).unwrap_or_default().to_string(),
                who: name.clone(),
                detail: service.clone(),
                failed,
                status: status.into(),
                change: true,
                caller: String::new(),
                target: target.clone(),
                links: links.clone(),
                fields: fields.clone(),
                key: format!("alrt:{}:{}", id.to_lowercase(), status),
            }
        };
        let mut rows = vec![row(e("startDateTime"), "Alert fired", true, "fired")];
        if let Some(resolved) = e("monitorConditionResolvedDateTime") {
            rows.push(row(Some(resolved), "Alert resolved", false, "resolved"));
        }
        rows
    }

    /// One ARM deployment (`DeploymentExtended`): its state, what it
    /// touched, its error. Never its parameters or outputs.
    pub fn from_deployment(v: &Value) -> Self {
        let p = |f: &str| json::str_at(v, &format!("/properties/{}", f)).filter(|s| !s.is_empty());
        let name = json::str_at(v, "/name").unwrap_or_else(|| "deployment".into());
        let id = json::str_at(v, "/id").unwrap_or_default();
        let at = p("timestamp");
        let ts = at.as_deref().and_then(parse_ts).unwrap_or(0);
        let state = p("provisioningState").unwrap_or_else(|| "-".into());
        let failed = matches!(state.to_lowercase().as_str(), "failed" | "canceled");
        let outputs = json::ids_at(v, "/properties/outputResources");
        let error = json::str_at(v, "/properties/error/message")
            .or_else(|| json::str_at(v, "/properties/error/details/0/message"))
            .filter(|s| !s.is_empty());
        let duration = p("duration").map(|d| pretty_duration(&d)).unwrap_or_default();
        let detail = match &error {
            Some(e) => e.clone(),
            None => {
                let n = outputs.len();
                let mut s = format!("{} resource{}", n, if n == 1 { "" } else { "s" });
                if !duration.is_empty() {
                    s.push_str(&format!(" · {}", duration));
                }
                s
            }
        };
        let mut fields = vec![
            ("Time".to_string(), json::time(at)),
            ("Source".into(), TimelineSource::Deployment.label().into()),
            ("Deployment".into(), name.clone()),
            ("State".into(), state.clone()),
            ("Duration".into(), json::opt(Some(duration))),
            ("Mode".into(), json::opt(p("mode"))),
            ("Correlation id".into(), json::opt(p("correlationId"))),
        ];
        if let Some(code) = json::str_at(v, "/properties/error/code") {
            fields.push(("Error".into(), format!("{}: {}", code, error.clone().unwrap_or_default())));
        }
        fields.push(("Deployed".into(), json::join(&outputs)));
        fields.push(("Id".into(), id.clone()));
        let rg = resource_group_of(&id).and_then(|rg| {
            subscription_of(&id).map(|s| (rg.to_string(), format!("/subscriptions/{}/resourceGroups/{}", s, rg)))
        });
        let mut links: Vec<(String, String)> = Vec::new();
        if let Some((rg, rg_id)) = &rg {
            links.push((format!("Resource group · {}", rg), rg_id.clone()));
        }
        for out in outputs.iter().take(30) {
            links.push((format!("Deployed · {}", name_of_id(out)), out.clone()));
        }
        TimelineRow {
            ts_secs: ts,
            time: fmt_ts(ts),
            source: Some(TimelineSource::Deployment),
            what: format!("Deployment {}", state.to_lowercase()),
            subject: name.clone(),
            who: name,
            detail,
            failed,
            status: state,
            change: true,
            caller: String::new(),
            target: rg.map(|(_, id)| id),
            links,
            fields,
            key: format!("dep:{}", id.to_lowercase()),
        }
    }

    /// Whether this deployment row touched `id` (its deployed resources).
    pub fn deployed(&self, id: &str) -> bool {
        self.links.iter().any(|(l, v)| l.starts_with("Deployed") && v.eq_ignore_ascii_case(id))
    }

    /// The row as text: `y` copies it, `⏎` opens it in `$EDITOR`.
    pub fn as_text(&self) -> String {
        let width = self.fields.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
        let mut out = String::new();
        for (k, v) in &self.fields {
            out.push_str(&format!("{:width$}  {}\n", k, v, width = width));
        }
        out
    }

    /// One line: time, source, what, subject, who, detail.
    pub fn summary_line(&self) -> String {
        let mut s = format!("{}  {}  {}", self.time, self.source().badge().trim(), self.what);
        for part in [&self.subject, &self.who, &self.detail] {
            if !part.is_empty() {
                s.push_str(&format!("  {}", part));
            }
        }
        s
    }
}

/// An Activity Log operation that changed something: a `write`, `delete`
/// or `action` that finished (`Succeeded` or `Failed`). `Started`,
/// `Accepted` and reads are not.
pub fn is_change_operation(op: &str, status: &str) -> bool {
    let op = op.to_lowercase();
    (op.ends_with("/write") || op.ends_with("/delete") || op.ends_with("/action"))
        && (status.eq_ignore_ascii_case("succeeded") || status.eq_ignore_ascii_case("failed"))
}

/// Activity Log events → rows: one per operation, newest first; only the
/// changes unless `include_all`; only those at or after `since`.
pub fn activity_rows(events: &[Value], since: i64, include_all: bool) -> Vec<TimelineRow> {
    crate::azure::services::activity::collapse_operations(events)
        .into_iter()
        .map(TimelineRow::from_activity)
        .filter(|r| r.ts_secs >= since && (include_all || r.change))
        .collect()
}

/// Resource Health statuses → rows at or after `since`. The `current`
/// status repeats the newest transition, so one per (time, state).
pub fn health_rows(items: &[Value], since: i64) -> Vec<TimelineRow> {
    let mut seen = std::collections::HashSet::new();
    items
        .iter()
        .map(TimelineRow::from_health)
        .filter(|r| r.ts_secs >= since)
        .filter(|r| seen.insert(r.key.clone()))
        .collect()
}

/// Alerts → rows (fired and resolved) at or after `since`.
pub fn alert_rows(items: &[Value], since: i64) -> Vec<TimelineRow> {
    items
        .iter()
        .flat_map(TimelineRow::from_alert)
        .filter(|r| r.ts_secs >= since)
        .collect()
}

/// Deployments → rows at or after `since`; with `touching`, only those
/// that deployed that resource.
pub fn deployment_rows(items: &[Value], since: i64, touching: Option<&str>) -> Vec<TimelineRow> {
    items
        .iter()
        .map(TimelineRow::from_deployment)
        .filter(|r| r.ts_secs >= since)
        .filter(|r| touching.is_none_or(|id| r.deployed(id)))
        .collect()
}

/// Merge per-source lists newest first, keeping only `filter`'s source
/// when set. Stable: rows at the same second keep their source order.
pub fn merge(lists: &[Vec<TimelineRow>], filter: Option<TimelineSource>) -> Vec<TimelineRow> {
    let mut merged: Vec<TimelineRow> = lists
        .iter()
        .flatten()
        .filter(|r| filter.is_none_or(|f| r.source() == f))
        .cloned()
        .collect();
    merged.sort_by_key(|r| std::cmp::Reverse(r.ts_secs));
    merged
}

/// Per-source storage index (lists indexed by [`TimelineSource::ALL`]).
pub fn slot(source: TimelineSource) -> usize {
    source.index()
}

// ── Windows ─────────────────────────────────────────────────────────────

/// The `W` lens's window: `[` / `]`. 90 days is the Activity Log's
/// retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LensWindow {
    #[default]
    Week,
    Month,
    Quarter,
}

impl LensWindow {
    pub fn days(self) -> i64 {
        match self {
            LensWindow::Week => 7,
            LensWindow::Month => 30,
            LensWindow::Quarter => 90,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LensWindow::Week => "7d",
            LensWindow::Month => "30d",
            LensWindow::Quarter => "90d",
        }
    }

    pub fn next(self) -> Self {
        match self {
            LensWindow::Week => LensWindow::Month,
            _ => LensWindow::Quarter,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            LensWindow::Quarter => LensWindow::Month,
            _ => LensWindow::Week,
        }
    }

    /// The alerts API's `timeRange` (it keeps 30 days).
    pub fn alerts_range(self) -> &'static str {
        match self {
            LensWindow::Week => "7d",
            _ => "30d",
        }
    }
}

// ── Paths ───────────────────────────────────────────────────────────────

fn is_resource(id: &str) -> bool {
    id.to_lowercase().contains("/providers/")
}

/// `{id}/providers/Microsoft.ResourceHealth/availabilityStatuses`: the
/// resource's health history. Resources only (not a group or subscription).
pub fn health_path(id: &str) -> Option<String> {
    is_resource(id).then(|| format!("{}/providers/Microsoft.ResourceHealth/availabilityStatuses", id))
}

/// The resource a health status belongs to: its id up to the provider
/// segment.
fn health_target(status_id: &str) -> Option<String> {
    let at = status_id.to_lowercase().find("/providers/microsoft.resourcehealth/")?;
    json::arm_id(Some(status_id[..at].to_string()))
}

/// Fired alerts for a row: the subscription's alerts filtered to the
/// resource, or its group, or none for the subscription itself.
pub fn alerts_request(id: &str, window: LensWindow) -> Option<(String, Vec<(String, String)>)> {
    let sub = subscription_of(id)?;
    let mut query = vec![
        ("timeRange".to_string(), window.alerts_range().to_string()),
        ("sortBy".into(), "startDateTime".into()),
        ("sortOrder".into(), "desc".into()),
    ];
    if is_resource(id) {
        query.push(("targetResource".into(), id.to_string()));
    } else if let Some(rg) = resource_group_of(id) {
        query.push(("targetResourceGroup".into(), rg.to_string()));
    }
    Some((format!("/subscriptions/{}/providers/Microsoft.AlertsManagement/alerts", sub), query))
}

/// The deployment history a row's deployments are in: its resource
/// group's, or the subscription's own for a subscription.
pub fn deployments_path(id: &str) -> Option<String> {
    let sub = subscription_of(id)?;
    Some(match resource_group_of(id) {
        Some(rg) => rg_deployments_path(sub, rg),
        None => format!("/subscriptions/{}/providers/Microsoft.Resources/deployments", sub),
    })
}

pub fn rg_deployments_path(sub: &str, rg: &str) -> String {
    format!("/subscriptions/{}/resourcegroups/{}/providers/Microsoft.Resources/deployments", sub, rg)
}

// ── Time ────────────────────────────────────────────────────────────────

/// An ISO-8601 UTC timestamp → Unix seconds.
pub fn parse_ts(s: &str) -> Option<i64> {
    crate::azure::metrics::parse_iso_utc(s)
}

fn fmt_ts(secs: i64) -> String {
    if secs > 0 {
        json::unix_to_ymdhm(secs)
    } else {
        "-".into()
    }
}

/// `PT1M23.45S` → `1m 23s`.
fn pretty_duration(iso: &str) -> String {
    let Some(rest) = iso.strip_prefix("PT") else {
        return iso.to_string();
    };
    let mut out = Vec::new();
    let mut num = String::new();
    for c in rest.chars() {
        match c {
            'H' | 'M' | 'S' => {
                let n = num.split('.').next().unwrap_or("0");
                if n != "0" || (c == 'S' && out.is_empty()) {
                    out.push(format!("{}{}", n, c.to_ascii_lowercase()));
                }
                num.clear();
            }
            _ => num.push(c),
        }
    }
    if out.is_empty() {
        iso.to_string()
    } else {
        out.join(" ")
    }
}

/// Unix seconds now.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub const VM: &str = "/subscriptions/0000/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1";
    const RG: &str = "/subscriptions/0000/resourceGroups/rg-app";

    pub fn event(ts: &str, corr: &str, op: &str, status: &str, caller: &str) -> Value {
        json!({
            "eventTimestamp": ts,
            "correlationId": corr,
            "operationName": {"value": op, "localizedValue": ""},
            "status": {"value": status, "localizedValue": status},
            "caller": caller,
            "level": if status == "Failed" { "Error" } else { "Informational" },
            "resourceId": VM
        })
    }

    pub fn health(ts: &str, state: &str, current: bool) -> Value {
        let leaf = if current { "current".to_string() } else { ts.replace(':', "%3a") };
        json!({
            "id": format!("{}/providers/Microsoft.ResourceHealth/availabilityStatuses/{}", VM, leaf),
            "name": leaf,
            "properties": {"availabilityState": state, "summary": "Disk problems", "reasonType": "Unplanned",
                "context": "Platform Initiated", "occuredTime": ts}
        })
    }

    pub fn alert(fired: &str, resolved: Option<&str>) -> Value {
        json!({
            "id": "/subscriptions/0000/providers/Microsoft.AlertsManagement/alerts/a1",
            "name": "cpu-high",
            "properties": {"essentials": {
                "severity": "Sev2", "monitorCondition": if resolved.is_some() { "Resolved" } else { "Fired" },
                "alertState": "New", "monitorService": "Platform", "targetResource": VM,
                "alertRule": format!("{}/providers/Microsoft.Insights/metricAlerts/cpu-high", RG),
                "startDateTime": fired, "monitorConditionResolvedDateTime": resolved
            }}
        })
    }

    pub fn deployment(name: &str, ts: &str, state: &str, outputs: &[&str]) -> Value {
        json!({
            "id": format!("{}/providers/Microsoft.Resources/deployments/{}", RG, name),
            "name": name,
            "properties": {"timestamp": ts, "provisioningState": state, "duration": "PT1M23.5S",
                "mode": "Incremental", "correlationId": "c-dep",
                "parameters": {"adminPassword": {"type": "SecureString"}},
                "outputResources": outputs.iter().map(|o| json!({"id": o})).collect::<Vec<_>>()}
        })
    }

    #[test]
    fn activity_keeps_finished_changes_newest_first_unless_asked_for_all() {
        let events = vec![
            event("2026-10-20T10:00:00Z", "c1", "Microsoft.Compute/virtualMachines/write", "Started", "a@x.com"),
            event("2026-10-20T10:02:00Z", "c1", "Microsoft.Compute/virtualMachines/write", "Succeeded", "a@x.com"),
            event("2026-10-20T11:00:00Z", "c2", "Microsoft.Compute/virtualMachines/restart/action", "Failed", "a@x.com"),
            event("2026-10-20T12:00:00Z", "c3", "Microsoft.Compute/virtualMachines/read", "Succeeded", "a@x.com"),
            event("2026-10-20T13:00:00Z", "c4", "Microsoft.Compute/virtualMachines/delete", "Accepted", "a@x.com"),
        ];
        let rows = activity_rows(&events, 0, false);
        let whats: Vec<&str> = rows.iter().map(|r| r.what.as_str()).collect();
        assert_eq!(whats, ["Microsoft.Compute/virtualMachines/restart/action", "Microsoft.Compute/virtualMachines/write"]);
        assert!(rows[0].failed && !rows[1].failed);
        assert_eq!(rows[1].status, "Succeeded", "the final status wins");
        assert_eq!(rows[1].time, "2026-10-20 10:02");
        assert_eq!(rows[1].subject, "vm1");
        assert_eq!(activity_rows(&events, 0, true).len(), 4, "a: every operation");
        let since = parse_ts("2026-10-20T10:30:00Z").unwrap();
        assert_eq!(activity_rows(&events, since, false).len(), 1, "the window");
        assert!(!rows[1].fields.iter().any(|(k, _)| k == "Properties" || k == "Claims"));
    }

    #[test]
    fn health_dedupes_the_current_status_and_flags_unhealthy_states() {
        let items = vec![
            health("2026-10-20T09:00:00Z", "Unavailable", true),
            health("2026-10-20T09:00:00Z", "Unavailable", false),
            health("2026-10-19T09:00:00Z", "Available", false),
            health("2020-01-01T00:00:00Z", "Available", false),
        ];
        let rows = health_rows(&items, parse_ts("2026-10-01T00:00:00Z").unwrap());
        assert_eq!(rows.len(), 2);
        assert!(rows[0].failed && !rows[1].failed);
        assert_eq!(rows[0].target.as_deref(), Some(VM));
        assert_eq!(rows[0].who, "Unplanned · Platform Initiated");
    }

    #[test]
    fn an_alert_is_a_fired_row_and_a_resolved_row() {
        let rows = alert_rows(&[alert("2026-10-20T08:00:00Z", Some("2026-10-20T08:30:00Z"))], 0);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].what, "Alert fired · Sev2");
        assert!(rows[0].failed && !rows[1].failed);
        assert_eq!(rows[1].what, "Alert resolved · Sev2");
        assert!(rows[0].links.iter().any(|(l, _)| l == "Alert rule · cpu-high"));
        assert_eq!(alert_rows(&[alert("2026-10-20T08:00:00Z", None)], 0).len(), 1);
    }

    #[test]
    fn deployments_name_what_they_touched_never_their_parameters() {
        let other = "/subscriptions/0000/resourceGroups/rg-app/providers/Microsoft.Web/sites/web";
        let items = vec![
            deployment("main", "2026-10-20T07:00:00Z", "Succeeded", &[VM, other]),
            deployment("web-only", "2026-10-20T06:00:00Z", "Failed", &[other]),
        ];
        let rows = deployment_rows(&items, 0, Some(VM));
        assert_eq!(rows.len(), 1, "only the deployment that touched the VM");
        assert_eq!(rows[0].what, "Deployment succeeded");
        assert_eq!(rows[0].detail, "2 resources · 1m 23s");
        assert!(!rows[0].as_text().contains("adminPassword"));
        assert!(rows[0].links.iter().any(|(l, v)| l == "Resource group · rg-app" && v == RG));
        assert!(deployment_rows(&items, 0, None)[1].failed);
    }

    #[test]
    fn merge_is_newest_first_and_filters_by_source() {
        let lists = vec![
            activity_rows(&[event("2026-10-20T10:00:00Z", "c1", "x/write", "Succeeded", "a@x.com")], 0, false),
            health_rows(&[health("2026-10-20T11:00:00Z", "Degraded", false)], 0),
            alert_rows(&[alert("2026-10-20T09:00:00Z", None)], 0),
            deployment_rows(&[deployment("d", "2026-10-20T12:00:00Z", "Succeeded", &[])], 0, None),
        ];
        let merged = merge(&lists, None);
        let sources: Vec<TimelineSource> = merged.iter().map(|r| r.source()).collect();
        assert_eq!(
            sources,
            [TimelineSource::Deployment, TimelineSource::Health, TimelineSource::Activity, TimelineSource::Alert]
        );
        assert_eq!(merge(&lists, Some(TimelineSource::Health)).len(), 1);
    }

    #[test]
    fn paths_and_windows() {
        assert_eq!(
            health_path(VM).unwrap(),
            format!("{}/providers/Microsoft.ResourceHealth/availabilityStatuses", VM)
        );
        assert!(health_path(RG).is_none());
        let (path, q) = alerts_request(VM, LensWindow::Quarter).unwrap();
        assert_eq!(path, "/subscriptions/0000/providers/Microsoft.AlertsManagement/alerts");
        assert!(q.contains(&("targetResource".into(), VM.into())));
        assert!(q.contains(&("timeRange".into(), "30d".into())), "alerts keep 30 days");
        assert!(alerts_request(RG, LensWindow::Week).unwrap().1.contains(&("targetResourceGroup".into(), "rg-app".into())));
        assert_eq!(
            deployments_path(VM).unwrap(),
            "/subscriptions/0000/resourcegroups/rg-app/providers/Microsoft.Resources/deployments"
        );
        assert_eq!(LensWindow::Week.next().next().next(), LensWindow::Quarter);
        assert_eq!(LensWindow::Quarter.prev().prev().prev(), LensWindow::Week);
        assert_eq!(pretty_duration("PT0S"), "0s");
        assert_eq!(pretty_duration("PT1H2M"), "1h 2m");
    }
}
