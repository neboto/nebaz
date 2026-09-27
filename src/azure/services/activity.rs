//! Activity (issue #25): recent control-plane operations, the "who changed
//! this?" lens every type shares.
//!
//! Like Access, every section descriptor carries an **Activity** section
//! (after Access, before Related), rendered once here by
//! `App::section_lines_for`, matched on the label. One call per row to the
//! subscription's activity log, filtered to the row: `resourceUri eq` for
//! a resource, `resourceGroupName eq` for a group, time alone for a
//! subscription. The last [`ACTIVITY_DAYS`] days (the log keeps 90), at
//! most [`ACTIVITY_MAX_EVENTS`] events.
//!
//! `$select` names the fields read, so `claims` (the caller's token
//! claims), `httpRequest` and `properties` (which can carry request bodies)
//! are never fetched.

use crate::azure::resource::{name_of_id, resource_group_of, shell_quote, subscription_of};
use crate::azure::services::{json, lazy_list_rows};
use crate::lazy::Lazy;
use serde_json::Value;

/// The only stable version of the activity log API (checked against
/// azure-rest-api-specs, 2026-09-27; the newer versions are alert rules).
pub const ACTIVITY_API_VERSION: &str = "2015-04-01";

/// The section label `App::section_lines_for` dispatches on.
pub const ACTIVITY_LABEL: &str = "Activity";

/// How far back the section looks.
pub const ACTIVITY_DAYS: i64 = 7;

/// Stop paging after this many events: a busy subscription's week is
/// thousands of pages of noise.
pub const ACTIVITY_MAX_EVENTS: usize = 500;

const SELECT: &str = "eventTimestamp,operationName,caller,status,subStatus,correlationId,resourceId,level";

/// `/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values`.
pub fn activity_path(id: &str) -> Option<String> {
    subscription_of(id).map(|s| {
        format!("/subscriptions/{}/providers/Microsoft.Insights/eventtypes/management/values", s)
    })
}

/// The row's filter from `now` (Unix seconds): the window, then the scope.
pub fn activity_query(id: &str, now: i64) -> Vec<(String, String)> {
    let since = iso(now - ACTIVITY_DAYS * 86_400);
    let mut filter = format!("eventTimestamp ge '{}'", since);
    match scope_of(id) {
        Scope::Subscription => {}
        Scope::ResourceGroup(rg) => filter.push_str(&format!(" and resourceGroupName eq '{}'", rg)),
        Scope::Resource => filter.push_str(&format!(" and resourceUri eq '{}'", id)),
    }
    vec![("$filter".into(), filter), ("$select".into(), SELECT.into())]
}

enum Scope<'a> {
    Subscription,
    ResourceGroup(&'a str),
    Resource,
}

fn scope_of(id: &str) -> Scope<'_> {
    if id.to_lowercase().contains("/providers/") {
        return Scope::Resource;
    }
    match resource_group_of(id) {
        Some(rg) => Scope::ResourceGroup(rg),
        None => Scope::Subscription,
    }
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:00Z`.
fn iso(secs: i64) -> String {
    format!("{}:00Z", json::unix_to_ymdhm(secs).replacen(' ', "T", 1))
}

/// An ISO timestamp to the minute.
fn minute(ts: Option<String>) -> String {
    let t = json::time(ts);
    t.get(..16).map(str::to_string).unwrap_or(t)
}

/// The Activity section: one entry per operation (its events share a
/// correlation id and operation name; the newest event's status wins),
/// newest first.
pub fn activity_rows(id: &str, events: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    lazy_list_rows(events, "Activity", |items| {
        let mut ops: Vec<&Value> = Vec::new();
        let mut seen: Vec<(String, String)> = Vec::new();
        let mut newest_first: Vec<&Value> = items.iter().collect();
        newest_first.sort_by_key(|e| std::cmp::Reverse(json::text(e, "/eventTimestamp")));
        for e in newest_first {
            let key = (json::text(e, "/correlationId"), json::text(e, "/operationName/value").to_lowercase());
            if key.0.is_empty() || !seen.contains(&key) {
                seen.push(key);
                ops.push(e);
            }
        }
        let mut lines = Vec::new();
        if ops.is_empty() {
            lines.push((String::new(), format!("No operations in the last {} days", ACTIVITY_DAYS)));
        }
        let here_is_a_resource = matches!(scope_of(id), Scope::Resource);
        for e in ops {
            let status = json::str_at(e, "/status/localizedValue")
                .or_else(|| json::str_at(e, "/status/value"))
                .unwrap_or_else(|| "-".into());
            let failed = matches!(json::text(e, "/level").as_str(), "Error" | "Critical")
                || status.eq_ignore_ascii_case("failed");
            let operation = json::str_at(e, "/operationName/localizedValue")
                .filter(|s| !s.is_empty())
                .or_else(|| json::str_at(e, "/operationName/value"))
                .unwrap_or_else(|| "-".into());
            lines.push((String::new(), String::new()));
            lines.push((
                format!("{} · {}{}", minute(json::str_at(e, "/eventTimestamp")), if failed { "⚠ " } else { "" }, status),
                operation,
            ));
            lines.push(("  Caller".into(), json::text(e, "/caller")));
            if let Some(sub) = json::str_at(e, "/subStatus/localizedValue").filter(|s| !s.is_empty()) {
                lines.push(("  Detail".into(), sub));
            }
            // At a group or subscription, each operation names its target.
            if !here_is_a_resource {
                if let Some(rid) = json::arm_id(json::str_at(e, "/resourceId")) {
                    lines.push((format!("  Resource · {}", name_of_id(&rid)), rid));
                }
            }
        }
        lines.push((String::new(), String::new()));
        let cap = if items.len() >= ACTIVITY_MAX_EVENTS {
            format!(", the newest {} events", ACTIVITY_MAX_EVENTS)
        } else {
            String::new()
        };
        lines.push((
            String::new(),
            format!("· the last {} days{}, newest first (the log keeps 90)", ACTIVITY_DAYS, cap),
        ));
        if let Some(cmd) = read_command(id) {
            lines.push(("Read command".into(), cmd));
        }
        lines
    })
}

fn read_command(id: &str) -> Option<String> {
    let sub = subscription_of(id)?;
    let offset = format!("{}d", ACTIVITY_DAYS);
    Some(match scope_of(id) {
        Scope::Resource => format!("az monitor activity-log list --resource-id {} --offset {}", shell_quote(id), offset),
        Scope::ResourceGroup(rg) => format!(
            "az monitor activity-log list -g {} --subscription {} --offset {}",
            shell_quote(rg),
            shell_quote(sub),
            offset
        ),
        Scope::Subscription => {
            format!("az monitor activity-log list --subscription {} --offset {}", shell_quote(sub), offset)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUB: &str = "/subscriptions/0000";
    const RG: &str = "/subscriptions/0000/resourceGroups/rg-app";
    const VM: &str = "/subscriptions/0000/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1";

    fn event(ts: &str, corr: &str, op: &str, status: &str, level: &str) -> Value {
        serde_json::json!({
            "eventTimestamp": ts,
            "correlationId": corr,
            "operationName": {"value": op, "localizedValue": ""},
            "status": {"value": status, "localizedValue": status},
            "caller": "ops@example.com",
            "level": level,
            "resourceId": VM
        })
    }

    #[test]
    fn the_filter_scopes_to_the_row_and_the_window() {
        // 2026-09-27 00:00 UTC.
        let now = 1_790_467_200;
        let q = activity_query(VM, now);
        assert_eq!(
            q[0].1,
            format!("eventTimestamp ge '2026-09-20T00:00:00Z' and resourceUri eq '{}'", VM)
        );
        assert!(!q[1].1.contains("claims") && !q[1].1.contains("properties"), "never the claims or bodies");
        assert!(activity_query(RG, now)[0].1.ends_with("and resourceGroupName eq 'rg-app'"));
        assert_eq!(activity_query(SUB, now)[0].1, "eventTimestamp ge '2026-09-20T00:00:00Z'");
        assert_eq!(
            activity_path(VM).unwrap(),
            "/subscriptions/0000/providers/Microsoft.Insights/eventtypes/management/values"
        );
    }

    #[test]
    fn events_collapse_to_operations_newest_first_with_the_final_status() {
        let items = vec![
            event("2026-09-26T10:00:00.1Z", "c1", "Microsoft.Compute/virtualMachines/write", "Started", "Informational"),
            event("2026-09-26T10:02:00.1Z", "c1", "Microsoft.Compute/virtualMachines/write", "Succeeded", "Informational"),
            event("2026-09-26T12:00:00.1Z", "c2", "Microsoft.Compute/virtualMachines/deallocate/action", "Failed", "Error"),
        ];
        let lines = activity_rows(VM, Some(&Lazy::Loaded(items)));
        let heads: Vec<&(String, String)> = lines.iter().filter(|(k, _)| k.starts_with("2026")).collect();
        assert_eq!(heads.len(), 2, "one entry per operation");
        assert_eq!(heads[0].0, "2026-09-26 12:00 · ⚠ Failed");
        assert_eq!(heads[1].0, "2026-09-26 10:02 · Succeeded");
        assert_eq!(heads[1].1, "Microsoft.Compute/virtualMachines/write");
        assert!(!lines.iter().any(|(k, _)| k.starts_with("  Resource")), "a resource does not name itself");
        assert_eq!(lines.last().unwrap().1, format!("az monitor activity-log list --resource-id {} --offset 7d", VM));
    }

    #[test]
    fn a_group_names_each_target_and_empty_says_so() {
        let items = vec![event("2026-09-26T10:00:00Z", "c1", "Microsoft.Compute/virtualMachines/write", "Succeeded", "Informational")];
        let lines = activity_rows(RG, Some(&Lazy::Loaded(items)));
        assert!(lines.iter().any(|(k, v)| k == "  Resource · vm1" && v == VM));
        assert!(lines.last().unwrap().1.starts_with("az monitor activity-log list -g rg-app --subscription 0000"));
        let none = activity_rows(SUB, Some(&Lazy::Loaded(vec![])));
        assert_eq!(none[0].1, "No operations in the last 7 days");
    }

    #[test]
    fn hitting_the_cap_says_so() {
        let items: Vec<Value> = (0..ACTIVITY_MAX_EVENTS)
            .map(|i| event("2026-09-26T10:00:00Z", &format!("c{}", i), "op", "Succeeded", "Informational"))
            .collect();
        let lines = activity_rows(SUB, Some(&Lazy::Loaded(items)));
        assert!(lines.iter().any(|(_, v)| v.contains("the newest 500 events")));
    }
}
