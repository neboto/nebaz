//! Responses computed per request instead of stored: what a stored body
//! cannot say, because it depends on the query or on every other fixture.
//!
//! - **All resources** (`/resources`, subscription- or group-wide):
//!   derived from every area's bodies (each top-level resource any fixture
//!   returns), so it can never disagree with the typed lists.
//! - **Filtered stores** (`core`'s fixtures, read by file name): the
//!   Activity Log by its `$filter` (window and scope) and `$select`; role
//!   assignments by scope (`atScope()`, a principal, or at-above-below);
//!   fired alerts by target and time range; Resource Health per resource
//!   (the planted statuses, every other resource Available); a resource
//!   group's GET from the group list; the locations and role definitions
//!   rewritten per subscription.
//! - **Metrics**: series over the asked-for `timespan` and `interval`,
//!   plausible per metric (a day curve, steady gauges), with the story's
//!   shapes: `ca-orders-api`'s requests fall off a cliff when
//!   `DenyAllOutbound` landed, a deallocated VM has no data.

use super::fixtures::AREAS;
use crate::azure::metrics::{curated_metrics, iso_utc, parse_iso_utc};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

/// When the incident's NSG rule landed (seconds before now): the cliff.
const CLIFF_AGO: i64 = 2 * 3600 + 10 * 60;

/// A computed body for this request, with a name for the trace.
pub fn respond(path: &str, query: &str, now: i64) -> Option<(&'static str, String)> {
    let path = percent_decoded(path);
    let path = path.trim_end_matches('/');
    let lower = path.to_lowercase();
    let segs: Vec<&str> = lower.trim_start_matches('/').split('/').collect();
    // Another subscription's paths answer like the stored fixtures do.
    if segs.first() != Some(&"subscriptions") || !segs.get(1).is_some_and(|s| is_demo_sub(s)) {
        return None;
    }
    let q = Query(query);
    let list = |items: Vec<Value>| json!({ "value": items }).to_string();
    match segs.as_slice() {
        ["subscriptions", sub, "resources"] => {
            return Some(("all-resources", list(filter_type(all_resources(sub, None, now), &q))));
        }
        ["subscriptions", sub, "resourcegroups", rg, "resources"] => {
            return Some(("all-resources", list(filter_type(all_resources(sub, Some(rg), now), &q))));
        }
        ["subscriptions", _, "resourcegroups", _] => {
            return resource_group(&lower, now).map(|v| ("resource-group", v.to_string()));
        }
        ["subscriptions", sub, "locations"] => return per_subscription("core/locations.json", sub, now).map(|b| ("locations", b)),
        ["subscriptions", sub, "providers", "microsoft.authorization", "roledefinitions"] => {
            return per_subscription("core/role-definitions.json", sub, now).map(|b| ("role-definitions", b));
        }
        ["subscriptions", sub, "providers", "microsoft.insights", "eventtypes", "management", "values"] => {
            return Some(("activity-log", list(activity(sub, &q, now))));
        }
        ["subscriptions", sub, "providers", "microsoft.alertsmanagement", "alerts"] => {
            return Some(("alerts", list(alerts(sub, &q, now))));
        }
        ["subscriptions", sub, "providers", "microsoft.resourcehealth", "availabilitystatuses"] => {
            return Some(("health", list(subscription_health(sub, now))));
        }
        _ => {}
    }
    let scope_before = |suffix: &str| lower.strip_suffix(suffix).map(|s| &path[..s.len()]);
    if let Some(scope) = scope_before("/providers/microsoft.authorization/roleassignments") {
        return Some(("role-assignments", list(role_assignments(scope, &q, now))));
    }
    if let Some(id) = scope_before("/providers/microsoft.resourcehealth/availabilitystatuses") {
        return Some(("health", list(resource_health(id, now))));
    }
    if let Some(id) = scope_before("/providers/microsoft.insights/metrics") {
        return Some(("metrics", metrics(id, &q, now).to_string()));
    }
    if let Some(id) = scope_before("/providers/microsoft.insights/metricdefinitions") {
        return Some(("metric-definitions", list(metric_definitions(id))));
    }
    None
}

// ── Plumbing ──────────────────────────────────────────────────────────

/// The decoded query (`a=b c&d=e`), read by key.
struct Query<'a>(&'a str);

impl Query<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            k.eq_ignore_ascii_case(key).then_some(v)
        })
    }
}

/// `'…'` after `prefix` in an OData `$filter` (case-insensitive).
fn quoted(filter: &str, prefix: &str) -> Option<String> {
    let at = filter.to_lowercase().find(&prefix.to_lowercase())? + prefix.len();
    let rest = filter[at..].trim_start().strip_prefix('\'')?;
    rest.split_once('\'').map(|(v, _)| v.to_string())
}

fn percent_decoded(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&path[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| path.to_string())
}

/// A stored body by file name (`core/alerts.json`), placeholders filled.
fn stored(file: &str, now: i64) -> Option<Value> {
    let f = AREAS.iter().flat_map(|a| a.iter()).find(|f| f.file == file)?;
    serde_json::from_str(&super::render(f.body, now)).ok()
}

fn stored_items(file: &str, now: i64) -> Vec<Value> {
    stored(file, now)
        .and_then(|v| v.get("value").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

fn text<'a>(v: &'a Value, ptr: &str) -> &'a str {
    v.pointer(ptr).and_then(Value::as_str).unwrap_or("")
}

fn ieq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// `id` is `scope` or below it.
fn within(id: &str, scope: &str) -> bool {
    let (id, scope) = (id.to_lowercase(), scope.trim_end_matches('/').to_lowercase());
    id == scope || id.starts_with(&format!("{scope}/"))
}

/// A steady per-id number (FNV-1a), for the made-up spreads.
fn hash(parts: &[&str]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for b in p.to_lowercase().bytes().chain([0u8]) {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

/// One of the demo's subscriptions (prod or dev).
fn is_demo_sub(sub: &str) -> bool {
    ieq(sub, super::PROD) || ieq(sub, super::DEV)
}

// ── All resources ─────────────────────────────────────────────────────

/// Child types the generic list returns alongside the top-level ones.
const LISTED_CHILD_TYPES: &[&str] = &["microsoft.sql/servers/databases", "microsoft.web/sites/slots"];

/// Types in a body that are not resources the generic list returns.
const NOT_LISTED: &[&str] = &["microsoft.resources/deployments", "microsoft.resources/templatespecs/versions"];

/// Namespaces whose objects are not resources (role assignments at a
/// group, health statuses, fired alerts).
const NOT_LISTED_NAMESPACES: &[&str] = &["microsoft.authorization/", "microsoft.resourcehealth/", "microsoft.alertsmanagement/"];

/// The ARM type of a resource id the generic list would return
/// (`Microsoft.Web/sites`), or `None` for a group, a child, an extension.
fn listed_type(id: &str) -> Option<String> {
    let segs: Vec<&str> = id.trim_matches('/').split('/').collect();
    let shaped = segs.len() >= 8
        && ieq(segs[0], "subscriptions")
        && ieq(segs[2], "resourcegroups")
        && ieq(segs[4], "providers")
        && segs.iter().skip(5).all(|s| !ieq(s, "providers"));
    if !shaped || !segs.len().is_multiple_of(2) {
        return None;
    }
    let mut typ = format!("{}/{}", segs[5], segs[6]);
    for pair in segs[8..].chunks(2) {
        typ.push('/');
        typ.push_str(pair[0]);
    }
    let lower = typ.to_lowercase();
    if NOT_LISTED.contains(&lower.as_str())
        || NOT_LISTED_NAMESPACES.iter().any(|ns| lower.starts_with(ns))
        || (segs.len() > 8 && !LISTED_CHILD_TYPES.contains(&lower.as_str())) {
        return None;
    }
    Some(typ)
}

/// Every resource some fixture returns in `sub` (and `rg`), as the
/// generic list's envelope (`$expand=createdTime,changedTime,provisioningState`).
fn all_resources(sub: &str, rg: Option<&str>, now: i64) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for f in AREAS.iter().flat_map(|a| a.iter()) {
        if f.status != 200 || f.path.starts_with("/v1.0") || f.path.starts_with("/beta") {
            continue;
        }
        let Ok(body) = serde_json::from_str::<Value>(&super::render(f.body, now)) else {
            continue;
        };
        let candidates = match body.get("value").and_then(Value::as_array) {
            Some(items) => items.clone(),
            None => vec![body],
        };
        for c in candidates {
            let id = text(&c, "/id");
            let Some(typ) = listed_type(id) else { continue };
            let segs: Vec<&str> = id.trim_matches('/').split('/').collect();
            if !ieq(segs[1], sub) || rg.is_some_and(|rg| !ieq(segs[3], rg)) || !seen.insert(id.to_lowercase()) {
                continue;
            }
            out.push(envelope(&c, id, &typ, now));
        }
    }
    out.sort_by_key(|v| text(v, "/id").to_lowercase());
    out
}

/// The generic list's view of a resource: the envelope, never `properties`.
fn envelope(c: &Value, id: &str, typ: &str, now: i64) -> Value {
    let mut v = Map::new();
    v.insert("id".into(), json!(id));
    v.insert("name".into(), json!(c.get("name").and_then(Value::as_str).unwrap_or_else(|| id.rsplit('/').next().unwrap_or(""))));
    v.insert("type".into(), json!(c.get("type").and_then(Value::as_str).unwrap_or(typ)));
    for key in ["sku", "kind", "managedBy", "plan", "extendedLocation", "zones"] {
        if let Some(x) = c.get(key).filter(|x| !x.is_null()) {
            v.insert(key.into(), x.clone());
        }
    }
    let location = c.get("location").and_then(Value::as_str).unwrap_or("westeurope");
    v.insert("location".into(), json!(location.to_lowercase().replace(' ', "")));
    if let Some(identity) = c.get("identity").filter(|x| !x.is_null()) {
        v.insert("identity".into(), identity.clone());
    }
    v.insert("tags".into(), c.get("tags").cloned().unwrap_or_else(|| json!({})));
    // When it was made and last touched: the body's own systemData when it
    // has one, else a steady made-up age.
    let h = hash(&[id]);
    let created = c
        .pointer("/systemData/createdAt")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| iso_utc(now - (45 + (h % 400) as i64) * 86_400 - (h % 86_400) as i64));
    let changed = c
        .pointer("/systemData/lastModifiedAt")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| iso_utc(now - (2 + (h >> 16) % 40) as i64 * 86_400 - ((h >> 8) % 86_400) as i64));
    v.insert("createdTime".into(), json!(created));
    v.insert("changedTime".into(), json!(changed));
    let state = c.pointer("/properties/provisioningState").and_then(Value::as_str).unwrap_or("Succeeded");
    v.insert("provisioningState".into(), json!(state));
    Value::Object(v)
}

/// `$filter=resourceType eq '…'` (the single-row refresh).
fn filter_type(items: Vec<Value>, q: &Query) -> Vec<Value> {
    match q.get("$filter").and_then(|f| quoted(f, "resourceType eq")) {
        Some(t) => items.into_iter().filter(|v| ieq(text(v, "/type"), &t)).collect(),
        None => items,
    }
}

/// One resource group's GET, from the group lists.
fn resource_group(id: &str, now: i64) -> Option<Value> {
    ["core/resource-groups-prod.json", "core/resource-groups-dev.json"]
        .iter()
        .flat_map(|f| stored_items(f, now))
        .find(|g| ieq(text(g, "/id"), id))
}

/// A body whose ids name prod, rewritten for the subscription asked about.
fn per_subscription(file: &str, sub: &str, now: i64) -> Option<String> {
    let body = stored(file, now)?.to_string();
    Some(if ieq(sub, super::DEV) { body.replace(super::PROD, super::DEV) } else { body })
}

// ── Activity Log ──────────────────────────────────────────────────────

/// The events in `sub` the `$filter` asks for (the window, then one of
/// `resourceUri` — the resource and what is under it — or
/// `resourceGroupName`), newest first, cut to `$select`.
fn activity(sub: &str, q: &Query, now: i64) -> Vec<Value> {
    let filter = q.get("$filter").unwrap_or("");
    let ts = |s: Option<String>| s.and_then(|s| parse_iso_utc(&s));
    let from = ts(quoted(filter, "eventTimestamp ge")).unwrap_or(now - 90 * 86_400);
    let to = ts(quoted(filter, "eventTimestamp le")).unwrap_or(i64::MAX);
    let uri = quoted(filter, "resourceUri eq").or_else(|| quoted(filter, "resourceId eq"));
    let group = quoted(filter, "resourceGroupName eq");
    let mut events: Vec<Value> = stored_items("core/activity-log.json", now)
        .into_iter()
        .filter(|e| ieq(text(e, "/subscriptionId"), sub))
        .filter(|e| parse_iso_utc(text(e, "/eventTimestamp")).is_some_and(|t| t >= from && t <= to))
        .filter(|e| uri.as_deref().is_none_or(|u| within(text(e, "/resourceId"), u)))
        .filter(|e| group.as_deref().is_none_or(|g| ieq(text(e, "/resourceGroupName"), g)))
        .collect();
    events.sort_by_key(|e| std::cmp::Reverse(parse_iso_utc(text(e, "/eventTimestamp")).unwrap_or(0)));
    if let Some(select) = q.get("$select") {
        let keep: Vec<&str> = select.split(',').map(str::trim).collect();
        for e in &mut events {
            if let Some(o) = e.as_object_mut() {
                o.retain(|k, _| keep.iter().any(|s| ieq(s, k)));
            }
        }
    }
    events
}

// ── Role assignments ──────────────────────────────────────────────────

/// What applies at `scope`: `atScope()` is at and above it; a principal's
/// filter (or none) is at, above and below it.
fn role_assignments(scope: &str, q: &Query, now: i64) -> Vec<Value> {
    let filter = q.get("$filter").unwrap_or("");
    let at_scope = filter.to_lowercase().contains("atscope()");
    let principal = quoted(filter, "principalId eq").or_else(|| quoted(filter, "assignedTo("));
    stored_items("core/role-assignments.json", now)
        .into_iter()
        .filter(|a| {
            let at = text(a, "/properties/scope");
            within(scope, at) || (!at_scope && within(at, scope))
        })
        .filter(|a| principal.as_deref().is_none_or(|p| ieq(text(a, "/properties/principalId"), p)))
        .collect()
}

// ── Alerts ────────────────────────────────────────────────────────────

fn alerts(sub: &str, q: &Query, now: i64) -> Vec<Value> {
    let range = match q.get("timeRange").unwrap_or("1d") {
        "1h" => 3600,
        "1d" => 86_400,
        "7d" => 7 * 86_400,
        _ => 30 * 86_400,
    };
    let target = q.get("targetResource");
    let group = q.get("targetResourceGroup");
    let mut items: Vec<Value> = stored_items("core/alerts.json", now)
        .into_iter()
        .filter(|a| within(text(a, "/id"), &format!("/subscriptions/{sub}")))
        .filter(|a| target.is_none_or(|t| ieq(text(a, "/properties/essentials/targetResource"), t)))
        .filter(|a| group.is_none_or(|g| ieq(text(a, "/properties/essentials/targetResourceGroup"), g)))
        .filter(|a| parse_iso_utc(text(a, "/properties/essentials/startDateTime")).is_some_and(|t| t >= now - range))
        .collect();
    items.sort_by_key(|a| std::cmp::Reverse(parse_iso_utc(text(a, "/properties/essentials/startDateTime")).unwrap_or(0)));
    items
}

// ── Resource Health ───────────────────────────────────────────────────

/// Types Resource Health reports on (a subset of what it supports).
const HEALTH_TYPES: &[&str] = &[
    "microsoft.compute/virtualmachines",
    "microsoft.app/containerapps",
    "microsoft.app/managedenvironments",
    "microsoft.containerservice/managedclusters",
    "microsoft.containerregistry/registries",
    "microsoft.keyvault/vaults",
    "microsoft.storage/storageaccounts",
    "microsoft.sql/servers/databases",
    "microsoft.dbforpostgresql/flexibleservers",
    "microsoft.dbformysql/flexibleservers",
    "microsoft.cache/redis",
    "microsoft.servicebus/namespaces",
    "microsoft.eventhub/namespaces",
    "microsoft.web/sites",
    "microsoft.web/serverfarms",
    "microsoft.documentdb/databaseaccounts",
    "microsoft.network/applicationgateways",
    "microsoft.network/loadbalancers",
    "microsoft.network/natgateways",
    "microsoft.network/dnszones",
    "microsoft.cdn/profiles",
    "microsoft.cognitiveservices/accounts",
    "microsoft.operationalinsights/workspaces",
    "microsoft.insights/components",
];

fn reports_health(id: &str) -> bool {
    listed_type(id).is_some_and(|t| HEALTH_TYPES.contains(&t.to_lowercase().as_str()))
}

fn planted_health(now: i64) -> Vec<Value> {
    stored_items("core/health.json", now)
}

/// The resource a status belongs to.
fn health_target(status: &Value) -> String {
    let id = text(status, "/id");
    let at = id.to_lowercase().find("/providers/microsoft.resourcehealth/").unwrap_or(id.len());
    id[..at].to_string()
}

/// `Available` since a steady made-up time.
fn available(id: &str, location: &str, now: i64) -> Value {
    let since = now - (3 + (hash(&[id, "health"]) % 27) as i64) * 86_400 - (hash(&[id]) % 86_400) as i64;
    json!({
        "id": format!("{id}/providers/Microsoft.ResourceHealth/availabilityStatuses/current"),
        "name": "current",
        "type": "Microsoft.ResourceHealth/AvailabilityStatuses",
        "location": location,
        "properties": {
            "availabilityState": "Available",
            "title": "Available",
            "summary": "There aren't any known Azure platform problems affecting this resource.",
            "reasonType": "",
            "context": "",
            "category": "",
            "reasonChronicity": "Persistent",
            "detailedStatus": "",
            "occuredTime": iso_utc(since),
            "reportedTime": iso_utc(now - 120),
        }
    })
}

/// Every resource's current status in `sub`: the planted ones, every
/// other resource Health reports on Available.
fn subscription_health(sub: &str, now: i64) -> Vec<Value> {
    let planted: Vec<Value> = planted_health(now)
        .into_iter()
        .filter(|s| text(s, "/name") == "current" && within(&health_target(s), &format!("/subscriptions/{sub}")))
        .collect();
    let mut out = planted.clone();
    for r in all_resources(sub, None, now) {
        let id = text(&r, "/id");
        if reports_health(id) && !planted.iter().any(|s| ieq(&health_target(s), id)) {
            out.push(available(id, text(&r, "/location"), now));
        }
    }
    out
}

/// One resource's statuses, current first: the planted history, or
/// Available when nothing is planted.
fn resource_health(id: &str, now: i64) -> Vec<Value> {
    let mut mine: Vec<Value> = planted_health(now).into_iter().filter(|s| ieq(&health_target(s), id)).collect();
    if mine.is_empty() {
        return if reports_health(id) { vec![available(id, "westeurope", now)] } else { Vec::new() };
    }
    mine.sort_by_key(|s| {
        let t = parse_iso_utc(text(s, "/properties/occuredTime")).unwrap_or(0);
        (text(s, "/name") != "current", std::cmp::Reverse(t))
    });
    mine
}

// ── Metrics ───────────────────────────────────────────────────────────

/// How a metric moves.
#[derive(Clone, Copy)]
enum Shape {
    /// A rate per minute that follows the working day; `Total` sums it.
    Traffic(f64),
    /// A level that follows the working day: `base + swing × day`.
    Busy(f64, f64),
    /// A level that barely moves.
    Steady(f64),
    /// Rare events: about this many per hour.
    Rare(f64),
}

/// The unit and shape a metric has, by name.
fn profile(name: &str) -> (&'static str, Shape) {
    use Shape::*;
    match name.to_lowercase().as_str() {
        "percentage cpu" | "cpupercentage" | "cpu_percent" => ("Percent", Busy(12.0, 30.0)),
        "node_cpu_usage_percentage" => ("Percent", Busy(30.0, 25.0)),
        "available memory bytes" => ("Bytes", Steady(2.1e9)),
        "network in total" | "network out total" => ("Bytes", Traffic(4.0e6)),
        "disk read operations/sec" | "disk write operations/sec" => ("CountPerSecond", Busy(2.0, 14.0)),
        "node_memory_working_set_percentage" | "memorypercentage" | "memory_percent" => ("Percent", Busy(52.0, 9.0)),
        "kube_pod_status_ready" => ("Count", Steady(42.0)),
        "kube_node_status_condition" => ("Count", Steady(3.0)),
        "requests" | "totalrequests" | "requestcount" | "requests/count" | "totalcalls" => ("Count", Traffic(1700.0)),
        "replicas" => ("Count", Steady(1.0)),
        "usagenanocores" => ("NanoCores", Busy(6.0e7, 2.4e8)),
        "workingsetbytes" => ("Bytes", Busy(3.1e8, 9.0e7)),
        "restartcount" | "http5xx" | "exceptions/count" | "totalerrors" | "servererrors" | "throttledrequests"
        | "connections_failed" | "aborted_connections" | "failedrequests" | "unhealthyhostcount"
        | "webapplicationfirewallrequestcount" | "requests/failed" => ("Count", Rare(0.6)),
        "httpresponsetime" => ("Seconds", Busy(0.18, 0.12)),
        "cputime" => ("Seconds", Traffic(9.0)),
        "httpqueuelength" => ("Count", Steady(0.0)),
        "dtu_consumption_percent" => ("Percent", Busy(8.0, 30.0)),
        "storage_percent" => ("Percent", Steady(31.0)),
        "connection_successful" => ("Count", Traffic(40.0)),
        "active_connections" | "allconnectedclients" | "connectedclients" => ("Count", Busy(18.0, 30.0)),
        "network_bytes_egress" | "egress" | "bytecount" | "incomingbytes" | "outgoingbytes" => ("Bytes", Traffic(2.6e6)),
        "transactions" | "serviceapihit" | "totalpullcount" | "allcachehits" | "operationspersecond" => ("Count", Traffic(320.0)),
        "totalpushcount" => ("Count", Rare(0.3)),
        "availability" => ("Percent", Steady(100.0)),
        "usedcapacity" => ("Bytes", Steady(5.6e11)),
        "storageused" => ("Bytes", Steady(1.9e10)),
        "serviceapilatency" | "latency" | "totallatency" | "applicationgatewaytotaltime" | "requests/duration" => {
            ("MilliSeconds", Busy(38.0, 30.0))
        }
        "saturationshoebox" => ("Percent", Busy(0.4, 1.2)),
        "totalrequestunits" => ("Count", Traffic(5200.0)),
        "normalizedruconsumption" => ("Percent", Busy(6.0, 22.0)),
        "vipavailability" | "dipavailability" | "datapathavailability" | "originhealthpercentage" => ("Count", Steady(100.0)),
        "snatconnectioncount" => ("Count", Traffic(60.0)),
        "usedsnatports" => ("Count", Busy(40.0, 80.0)),
        "ifunderddosattack" => ("Count", Steady(0.0)),
        "allserverload" | "serverload" => ("Percent", Busy(4.0, 14.0)),
        "allusedmemorypercentage" | "usedmemorypercentage" => ("Percent", Steady(37.0)),
        "allcachemisses" | "cachemisses" => ("Count", Traffic(12.0)),
        "incomingmessages" | "outgoingmessages" => ("Count", Traffic(410.0)),
        "activemessages" => ("Count", Busy(3.0, 25.0)),
        "deadletteredmessages" => ("Count", Steady(1284.0)),
        "healthyhostcount" => ("Count", Steady(1.0)),
        "throughput" => ("BytesPerSecond", Busy(9.0e4, 6.0e5)),
        "percentage4xx" => ("Percent", Busy(0.8, 0.9)),
        "percentage5xx" => ("Percent", Busy(0.02, 0.05)),
        _ => ("Count", Busy(5.0, 10.0)),
    }
}

/// 0.0 at 03:00 UTC, 1.0 at 15:00.
fn working_day(t: i64) -> f64 {
    let hour = (t.rem_euclid(86_400)) as f64 / 3600.0;
    0.5 - 0.5 * (std::f64::consts::TAU * (hour - 3.0) / 24.0).cos()
}

/// A steady jitter in [-1, 1] per resource, metric and time.
fn jitter(id: &str, name: &str, t: i64) -> f64 {
    (hash(&[id, name, &t.to_string()]) % 2001) as f64 / 1000.0 - 1.0
}

fn name_of(id: &str) -> String {
    id.rsplit('/').next().unwrap_or("").to_lowercase()
}

/// The fraction of `[t, t + step)` before `at`.
fn before(t: i64, step: i64, at: i64) -> f64 {
    ((at - t) as f64 / step as f64).clamp(0.0, 1.0)
}

/// One point: `None` is a gap (no data, e.g. a deallocated VM).
fn sample(id: &str, name: &str, aggregation: &str, t: i64, step: i64, now: i64) -> Option<f64> {
    let who = name_of(id);
    let metric = name.to_lowercase();
    if who == "vm-legacy-app-01" {
        return None;
    }
    let minutes = step as f64 / 60.0;
    let day = working_day(t);
    let j = jitter(id, name, t);
    let (_, shape) = profile(name);
    let cliff = now - CLIFF_AGO;
    // The orders path loses Power Platform's traffic at the cliff (what
    // the API, its App Insights and the queue behind it all show).
    let orders_path = matches!(
        (who.as_str(), metric.as_str()),
        ("ca-orders-api", "requests")
            | ("appi-orders", "requests/count")
            | ("appi-orders", "requests/failed")
            | ("sb-orders-prod", "incomingmessages")
            | ("sb-orders-prod", "outgoingmessages")
    );
    let mut level = match shape {
        Shape::Traffic(per_min) => {
            let scale = match who.as_str() {
                "ca-orders-api" | "appi-orders" => 1.0,
                "agw-contoso-prod" | "afd-contoso" => 0.08,
                "ca-orders-api-dev" => 0.01,
                _ => 0.15,
            };
            let rate = per_min * scale * (0.25 + 0.75 * day) * (1.0 + 0.08 * j);
            let rate = if orders_path {
                let after = per_min * 0.005 * (1.0 + 0.3 * j);
                rate * before(t, step, cliff) + after * (1.0 - before(t, step, cliff))
            } else {
                rate
            };
            match aggregation {
                "Total" | "Count" => rate * minutes,
                "Maximum" => rate * 1.3,
                "Minimum" => rate * 0.7,
                _ => rate,
            }
        }
        Shape::Busy(base, swing) => (base + swing * day) * (1.0 + 0.06 * j),
        Shape::Steady(v) => v * (1.0 + 0.002 * j),
        Shape::Rare(per_hour) => {
            let p = per_hour * minutes / 60.0;
            let roll = (hash(&[id, name, "rare", &t.to_string()]) % 10_000) as f64 / 10_000.0;
            if roll < p.min(0.9) {
                1.0 + (roll * 10.0).floor()
            } else {
                0.0
            }
        }
    };
    // The story's other shapes.
    match (who.as_str(), metric.as_str()) {
        ("ca-orders-api", "replicas") => level = 3.0,
        ("ca-orders-worker", "replicas") => level = 2.0,
        (_, "replicas") => level = level.round(),
        ("aks-platform-prod", "node_cpu_usage_percentage") => {
            let spike = now - (2 * 86_400 + 7 * 3600);
            if t + step > spike && t < spike + 40 * 60 {
                level = 91.0 + 3.0 * j;
            }
        }
        ("sb-orders-prod", "deadletteredmessages") => level = 1284.0,
        ("sb-orders-prod", "activemessages") if t >= cliff => level = 0.0,
        ("agw-contoso-prod", "healthyhostcount") => level = 2.0,
        (_, "availability" | "vipavailability" | "dipavailability" | "datapathavailability" | "originhealthpercentage") => {
            level = 100.0
        }
        _ => {}
    }
    let value = match shape {
        Shape::Steady(_) | Shape::Rare(_) => level,
        _ if matches!(metric.as_str(), "kube_pod_status_ready" | "kube_node_status_condition") => level.round(),
        _ => level,
    };
    Some((value * 1000.0).round() / 1000.0)
}

/// `PT1M`, `PT5M`, `PT1H`, `P1D` → seconds.
fn grain(interval: &str) -> i64 {
    let i = interval.to_uppercase();
    let num = |s: &str| s.trim_end_matches(char::is_alphabetic).parse::<i64>().unwrap_or(1);
    if let Some(rest) = i.strip_prefix("PT") {
        match rest.chars().last() {
            Some('M') => num(rest) * 60,
            Some('H') => num(rest) * 3600,
            Some('S') => num(rest),
            _ => 60,
        }
    } else if let Some(rest) = i.strip_prefix('P') {
        num(rest) * 86_400
    } else {
        60
    }
}

/// The ARM type for the response's `namespace`.
fn arm_type(id: &str) -> String {
    listed_type(id).unwrap_or_default()
}

fn metrics(id: &str, q: &Query, now: i64) -> Value {
    let timespan = q.get("timespan").unwrap_or("");
    let (start, end) = timespan
        .split_once('/')
        .and_then(|(a, b)| Some((parse_iso_utc(a)?, parse_iso_utc(b)?)))
        .unwrap_or((now - 3600, now));
    let interval = q.get("interval").unwrap_or("PT1M");
    let step = grain(interval).max(60);
    let aggregations: Vec<&str> = q.get("aggregation").unwrap_or("Average").split(',').map(str::trim).collect();
    let names: Vec<&str> = q.get("metricnames").unwrap_or("").split(',').map(str::trim).filter(|n| !n.is_empty()).collect();
    let first = start + (step - start.rem_euclid(step)) % step;
    let times: Vec<i64> = (0..).map(|i| first + i * step).take_while(|t| *t < end).collect();
    let value: Vec<Value> = names
        .iter()
        .map(|name| {
            let data: Vec<Value> = times
                .iter()
                .map(|&t| {
                    let mut p = Map::new();
                    p.insert("timeStamp".into(), json!(iso_utc(t)));
                    for a in &aggregations {
                        if let Some(v) = sample(id, name, a, t, step, now) {
                            p.insert(a.to_lowercase(), json!(v));
                        }
                    }
                    Value::Object(p)
                })
                .collect();
            json!({
                "id": format!("{id}/providers/Microsoft.Insights/metrics/{name}"),
                "type": "Microsoft.Insights/metrics",
                "name": {"value": name, "localizedValue": name},
                "displayDescription": "",
                "unit": profile(name).0,
                "timeseries": [{"metadatavalues": [], "data": data}],
                "errorCode": "Success",
            })
        })
        .collect();
    json!({
        "cost": times.len() * names.len().max(1),
        "timespan": timespan,
        "interval": interval,
        "value": value,
        "namespace": arm_type(id),
        "resourceregion": "westeurope",
    })
}

/// The `a` picker's list: the type's curated metrics, described.
fn metric_definitions(id: &str) -> Vec<Value> {
    curated_metrics(id)
        .iter()
        .map(|m| {
            let (unit, shape) = profile(m.name);
            let supported = match shape {
                Shape::Traffic(_) | Shape::Rare(_) => json!(["Total", "Count", "Average", "Maximum", "Minimum"]),
                _ => json!(["Average", "Maximum", "Minimum"]),
            };
            json!({
                "id": format!("{id}/providers/microsoft.insights/metricdefinitions/{}", m.name),
                "resourceId": id,
                "namespace": arm_type(id),
                "name": {"value": m.name, "localizedValue": m.label},
                "displayDescription": "",
                "isDimensionRequired": false,
                "unit": unit,
                "primaryAggregationType": m.aggregation.as_param(),
                "supportedAggregationTypes": supported,
                "metricAvailabilities": [
                    {"timeGrain": "PT1M", "retention": "P93D"},
                    {"timeGrain": "PT5M", "retention": "P93D"},
                    {"timeGrain": "PT1H", "retention": "P93D"},
                    {"timeGrain": "P1D", "retention": "P93D"}
                ],
                "dimensions": []
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::{DEV, PROD};

    const NOW: i64 = 1_790_000_000;

    fn ask(path: &str, query: &str) -> Value {
        let (_, body) = respond(path, query, NOW).unwrap_or_else(|| panic!("{path}: not generated"));
        serde_json::from_str(&body).unwrap()
    }

    fn values(v: &Value) -> Vec<Value> {
        v["value"].as_array().cloned().unwrap_or_default()
    }

    fn nsg(name: &str) -> String {
        format!("/subscriptions/{PROD}/resourceGroups/rg-network-prod/providers/Microsoft.Network/networkSecurityGroups/{name}")
    }

    #[test]
    fn the_activity_log_follows_the_filter_and_the_select() {
        let path = format!("/subscriptions/{PROD}/providers/Microsoft.Insights/eventtypes/management/values");
        let since = iso_utc(NOW - 7 * 86_400);
        let q = format!(
            "api-version=2015-04-01&$filter=eventTimestamp ge '{since}' and resourceUri eq '{}'&$select=eventTimestamp,operationName,caller,status,resourceId",
            nsg("nsg-pp-injection")
        );
        let events = values(&ask(&path, &q));
        assert!(!events.is_empty(), "the rule change is under the NSG");
        assert!(events.iter().all(|e| text(e, "/resourceId").contains("nsg-pp-injection/securityRules/DenyAllOutbound")));
        assert!(events.iter().all(|e| e.get("claims").is_none() && e.get("subscriptionId").is_none()), "cut to $select");
        assert_eq!(text(&events[0], "/caller"), "alex.kim@contoso.com");
        // The window: the VM deallocated 40 days ago is outside a week.
        let vm = format!("/subscriptions/{PROD}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vm-legacy-app-01");
        let q = format!("$filter=eventTimestamp ge '{since}' and resourceUri eq '{vm}'");
        assert!(values(&ask(&path, &q)).is_empty());
        let q = format!("$filter=eventTimestamp ge '{}' and resourceUri eq '{vm}'", iso_utc(NOW - 90 * 86_400));
        assert!(!values(&ask(&path, &q)).is_empty());
        // A group, and the other subscription.
        let q = format!("$filter=eventTimestamp ge '{since}' and resourceGroupName eq 'RG-ORDERS-PROD'");
        assert!(values(&ask(&path, &q)).iter().all(|e| ieq(text(e, "/resourceGroupName"), "rg-orders-prod")));
        let dev = format!("/subscriptions/{DEV}/providers/Microsoft.Insights/eventtypes/management/values");
        let all_dev = values(&ask(&dev, &format!("$filter=eventTimestamp ge '{since}'")));
        assert!(!all_dev.is_empty() && all_dev.iter().all(|e| text(e, "/resourceId").contains(DEV)));
    }

    #[test]
    fn role_assignments_apply_from_above_and_principals_reach_below() {
        let kv = format!("/subscriptions/{PROD}/resourceGroups/rg-orders-prod/providers/Microsoft.KeyVault/vaults/kv-orders-prod");
        let at = values(&ask(&format!("{kv}/providers/Microsoft.Authorization/roleAssignments"), "$filter=atScope()"));
        let scopes: HashSet<String> = at.iter().map(|a| text(a, "/properties/scope").to_lowercase()).collect();
        assert!(scopes.contains(&format!("/subscriptions/{PROD}")), "inherited from the subscription");
        assert!(scopes.contains(&kv.to_lowercase()), "made on the vault");
        let sub = format!("/subscriptions/{PROD}/providers/Microsoft.Authorization/roleAssignments");
        let sub_at = values(&ask(&sub, "$filter=atScope()"));
        assert!(sub_at.iter().all(|a| ieq(text(a, "/properties/scope"), &format!("/subscriptions/{PROD}"))));
        let mi = values(&ask(&sub, "$filter=principalId eq '535edf48-335f-4761-b6ed-e0613ed690b3'"));
        assert_eq!(mi.len(), 3, "id-orders-api: AcrPull, Key Vault Secrets User, Service Bus sender");
    }

    #[test]
    fn all_resources_include_the_unbrowsed_ones_and_filter_by_group_and_type() {
        let all = values(&ask(&format!("/subscriptions/{PROD}/resources"), ""));
        let names: Vec<&str> = all.iter().map(|r| text(r, "/name")).collect();
        assert!(names.contains(&"orders-api-requests-dropped") && names.contains(&"NetworkWatcher_westeurope"));
        assert!(all.iter().all(|r| text(r, "/id").contains(PROD) && r.get("properties").is_none()));
        assert!(!names.iter().any(|n| n.starts_with("orders-worker-v1")), "deployments are not resources");
        let rg = values(&ask(
            &format!("/subscriptions/{PROD}/resourceGroups/NetworkWatcherRG/resources"),
            "$filter=resourceType eq 'microsoft.network/networkwatchers'",
        ));
        assert_eq!(rg.len(), 2);
        let group = ask(&format!("/subscriptions/{PROD}/resourceGroups/rg-orders-prod"), "");
        assert_eq!(text(&group, "/name"), "rg-orders-prod");
    }

    #[test]
    fn the_requests_metric_falls_off_a_cliff_at_the_incident() {
        let api = format!("/subscriptions/{PROD}/resourceGroups/rg-orders-prod/providers/Microsoft.App/containerApps/ca-orders-api");
        let q = format!(
            "metricnames=Requests,Replicas&timespan={}/{}&interval=PT5M&aggregation=Total",
            iso_utc(NOW - 6 * 3600),
            iso_utc(NOW)
        );
        let body = ask(&format!("{api}/providers/Microsoft.Insights/metrics"), &q);
        let series = crate::azure::metrics::parse_metrics(
            &body,
            &[crate::azure::metrics::MetricQuery {
                name: "Requests".into(),
                label: "Requests".into(),
                aggregation: crate::azure::metrics::Aggregation::Total,
            }],
        );
        let points = &series[0].points;
        assert_eq!(points.len(), 72);
        let cliff = NOW - CLIFF_AGO;
        let mean = |f: &dyn Fn(i64) -> bool| {
            let v: Vec<f64> = points.iter().filter(|(t, _)| f(*t)).map(|(_, v)| *v).collect();
            v.iter().sum::<f64>() / v.len() as f64
        };
        let (pre, post) = (mean(&|t| t + 300 <= cliff), mean(&|t| t >= cliff));
        assert!(post < pre * 0.05, "before {pre}, after {post}");
        // A deallocated VM has no data; definitions follow the curated set.
        let vm = format!("/subscriptions/{PROD}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vm-legacy-app-01");
        let body = ask(&format!("{vm}/providers/Microsoft.Insights/metrics"), &q.replace("Requests,Replicas", "Percentage CPU"));
        assert!(body["value"][0]["timeseries"][0]["data"].as_array().unwrap().iter().all(|p| p.get("total").is_none()));
        let defs = values(&ask(&format!("{api}/providers/Microsoft.Insights/metricDefinitions"), ""));
        assert_eq!(defs.len(), curated_metrics(&api).len());
    }

    #[test]
    fn health_is_planted_or_available_and_alerts_follow_their_target() {
        let worker = format!("/subscriptions/{PROD}/resourceGroups/rg-orders-prod/providers/Microsoft.App/containerApps/ca-orders-worker");
        let h = values(&ask(&format!("{worker}/providers/Microsoft.ResourceHealth/availabilityStatuses"), ""));
        assert_eq!(text(&h[0], "/properties/availabilityState"), "Degraded");
        let kv = format!("/subscriptions/{PROD}/resourceGroups/rg-orders-prod/providers/Microsoft.KeyVault/vaults/kv-orders-prod");
        let h = values(&ask(&format!("{kv}/providers/Microsoft.ResourceHealth/availabilityStatuses"), ""));
        assert_eq!(text(&h[0], "/properties/availabilityState"), "Available");
        let sub = values(&ask(&format!("/subscriptions/{PROD}/providers/Microsoft.ResourceHealth/availabilityStatuses"), ""));
        assert!(sub.iter().any(|s| text(s, "/properties/availabilityState") == "Degraded"));
        let alerts = format!("/subscriptions/{PROD}/providers/Microsoft.AlertsManagement/alerts");
        let on_nsg = values(&ask(&alerts, &format!("timeRange=7d&targetResource={}", nsg("nsg-pp-injection"))));
        assert_eq!(on_nsg.len(), 1);
        assert_eq!(values(&ask(&alerts, "timeRange=1h")).len(), 0, "the incident's alerts are older than an hour");
        assert!(values(&ask(&alerts, "timeRange=1d&targetResourceGroup=rg-orders-prod")).len() >= 2);
    }
}
