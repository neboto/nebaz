//! Azure Monitor platform metrics (`m`, #51): the curated default set per
//! ARM type, the request builder, the response parsers and the one fetch.
//! The state and the drawing are `ui::widgets::metrics_overlay`; the keys
//! and the task are `app::metrics`.
//!
//! Both calls are control-plane `GET`s on the resource's own id, so
//! `Reader` covers them and the read-only guard is unaffected:
//!
//! - `{id}/providers/Microsoft.Insights/metrics?metricnames=…&timespan=…&interval=…&aggregation=…`
//! - `{id}/providers/Microsoft.Insights/metricDefinitions` (the `a` picker)
//!
//! One call per aggregation (the `aggregation` parameter applies to every
//! name in the call). A call naming a metric the resource does not have
//! fails whole (a vCore database has no `dtu_consumption_percent`), so a
//! failed call of several names is retried one name at a time; whatever
//! still fails is a warning line on that metric, never fatal.

use crate::azure::resource::arm_type_chain;
use serde_json::Value;
use std::future::Future;

/// Metrics - List and Metric Definitions - List: the current stable
/// version of both (Microsoft Learn, `rest-monitor-2023-10-01`).
pub const METRICS_API_VERSION: &str = "2023-10-01";

/// The time window, `[` / `]` or `1`–`4` in the overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MetricWindow {
    #[default]
    OneHour,
    SixHours,
    OneDay,
    SevenDays,
}

impl MetricWindow {
    pub const ALL: [MetricWindow; 4] = [Self::OneHour, Self::SixHours, Self::OneDay, Self::SevenDays];

    pub fn secs(self) -> i64 {
        match self {
            Self::OneHour => 3_600,
            Self::SixHours => 6 * 3_600,
            Self::OneDay => 24 * 3_600,
            Self::SevenDays => 7 * 24 * 3_600,
        }
    }

    /// The time grain asked for: 60, 72, 96 and 168 points. Platform
    /// metrics keep `PT1M` for 93 days; a metric whose finest grain is
    /// coarser (storage capacity, `PT1H`) is adjusted by
    /// `AutoAdjustTimegrain`.
    pub fn interval(self) -> &'static str {
        match self {
            Self::OneHour => "PT1M",
            Self::SixHours => "PT5M",
            Self::OneDay => "PT15M",
            Self::SevenDays => "PT1H",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::SixHours => "6h",
            Self::OneDay => "24h",
            Self::SevenDays => "7d",
        }
    }

    pub fn start_label(self) -> &'static str {
        match self {
            Self::OneHour => "1h ago",
            Self::SixHours => "6h ago",
            Self::OneDay => "24h ago",
            Self::SevenDays => "7d ago",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|w| *w == self).unwrap_or(0)
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    /// `1`–`4`.
    pub fn from_digit(c: char) -> Option<Self> {
        c.to_digit(10).and_then(|d| Self::ALL.get((d as usize).checked_sub(1)?).copied())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aggregation {
    Average,
    Total,
    Maximum,
    Minimum,
    Count,
}

impl Aggregation {
    /// The query parameter value.
    pub fn as_param(self) -> &'static str {
        match self {
            Self::Average => "Average",
            Self::Total => "Total",
            Self::Maximum => "Maximum",
            Self::Minimum => "Minimum",
            Self::Count => "Count",
        }
    }

    /// The data point's field.
    fn field(self) -> &'static str {
        match self {
            Self::Average => "average",
            Self::Total => "total",
            Self::Maximum => "maximum",
            Self::Minimum => "minimum",
            Self::Count => "count",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Self::Average => "avg",
            Self::Total => "sum",
            Self::Maximum => "max",
            Self::Minimum => "min",
            Self::Count => "count",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "average" => Self::Average,
            "total" => Self::Total,
            "maximum" => Self::Maximum,
            "minimum" => Self::Minimum,
            "count" => Self::Count,
            _ => return None,
        })
    }
}

/// One curated metric: its name in the API, a short label, the
/// aggregation that reads well over a window.
#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    pub name: &'static str,
    pub label: &'static str,
    pub aggregation: Aggregation,
}

const fn m(name: &'static str, label: &'static str, aggregation: Aggregation) -> MetricSpec {
    MetricSpec { name, label, aggregation }
}

use Aggregation::{Average as Avg, Count, Maximum as Max, Total};

const VM: &[MetricSpec] = &[
    m("Percentage CPU", "CPU", Avg),
    m("Available Memory Bytes", "Available memory", Avg),
    m("Network In Total", "Network in", Total),
    m("Network Out Total", "Network out", Total),
    m("Disk Read Operations/Sec", "Disk read ops/s", Avg),
    m("Disk Write Operations/Sec", "Disk write ops/s", Avg),
];
const AKS: &[MetricSpec] = &[
    m("node_cpu_usage_percentage", "Node CPU", Avg),
    m("node_memory_working_set_percentage", "Node memory", Avg),
    m("kube_pod_status_ready", "Ready pods", Avg),
    m("kube_node_status_condition", "Node conditions", Avg),
];
const CONTAINER_APP: &[MetricSpec] = &[
    m("Requests", "Requests", Total),
    m("Replicas", "Replicas", Max),
    m("UsageNanoCores", "CPU (nanocores)", Avg),
    m("WorkingSetBytes", "Memory working set", Avg),
    m("RestartCount", "Restarts", Total),
];
const WEB_SITE: &[MetricSpec] = &[
    m("Requests", "Requests", Total),
    m("Http5xx", "HTTP 5xx", Total),
    m("HttpResponseTime", "Response time", Avg),
    m("CpuTime", "CPU time", Total),
];
const APP_SERVICE_PLAN: &[MetricSpec] = &[
    m("CpuPercentage", "CPU", Avg),
    m("MemoryPercentage", "Memory", Avg),
    m("HttpQueueLength", "HTTP queue", Avg),
];
const SQL_DATABASE: &[MetricSpec] = &[
    m("cpu_percent", "CPU", Avg),
    m("dtu_consumption_percent", "DTU", Avg),
    m("storage_percent", "Storage used", Max),
    m("connection_successful", "Connections", Total),
];
const POSTGRES_FLEXIBLE: &[MetricSpec] = &[
    m("cpu_percent", "CPU", Avg),
    m("memory_percent", "Memory", Avg),
    m("storage_percent", "Storage used", Max),
    m("active_connections", "Connections", Avg),
    m("connections_failed", "Failed connections", Total),
    m("network_bytes_egress", "Network out", Total),
];
const MYSQL_FLEXIBLE: &[MetricSpec] = &[
    m("cpu_percent", "CPU", Avg),
    m("memory_percent", "Memory", Avg),
    m("storage_percent", "Storage used", Max),
    m("active_connections", "Connections", Avg),
    m("aborted_connections", "Aborted connections", Total),
    m("network_bytes_egress", "Network out", Total),
];
const STORAGE: &[MetricSpec] = &[
    m("Transactions", "Transactions", Total),
    m("Egress", "Egress", Total),
    m("Availability", "Availability", Avg),
    m("UsedCapacity", "Used capacity", Avg),
];
const KEY_VAULT: &[MetricSpec] = &[
    m("ServiceApiHit", "API hits", Total),
    m("ServiceApiLatency", "API latency", Avg),
    m("Availability", "Availability", Avg),
    m("SaturationShoebox", "Saturation", Avg),
];
const COSMOS: &[MetricSpec] = &[
    m("TotalRequests", "Requests", Count),
    m("TotalRequestUnits", "Request units", Total),
    m("NormalizedRUConsumption", "Normalized RU", Max),
];
const LOAD_BALANCER: &[MetricSpec] = &[
    m("VipAvailability", "Data path availability", Avg),
    m("DipAvailability", "Health probe status", Avg),
    m("SnatConnectionCount", "SNAT connections", Total),
    m("UsedSnatPorts", "Used SNAT ports", Avg),
];
const PUBLIC_IP: &[MetricSpec] = &[
    m("VipAvailability", "Data path availability", Avg),
    m("IfUnderDDoSAttack", "Under DDoS attack", Max),
    m("ByteCount", "Bytes", Total),
];
const NAT_GATEWAY: &[MetricSpec] = &[
    m("DatapathAvailability", "Data path availability", Avg),
    m("SNATConnectionCount", "SNAT connections", Total),
    m("ByteCount", "Bytes", Total),
];
const REGISTRY: &[MetricSpec] = &[
    m("TotalPullCount", "Pulls", Total),
    m("TotalPushCount", "Pushes", Total),
    m("StorageUsed", "Storage used", Avg),
];
const APP_INSIGHTS: &[MetricSpec] = &[
    m("requests/count", "Requests", Count),
    m("requests/failed", "Failed requests", Count),
    m("requests/duration", "Request duration", Avg),
    m("exceptions/count", "Exceptions", Count),
];
const COGNITIVE: &[MetricSpec] = &[
    m("TotalCalls", "Calls", Total),
    m("TotalErrors", "Errors", Total),
    m("Latency", "Latency", Avg),
];

/// Azure Cache for Redis: the `all…` names aggregate every shard, so a
/// clustered cache reads as one.
const REDIS_CACHE: &[MetricSpec] = &[
    m("allserverLoad", "Server load", Max),
    m("allusedmemorypercentage", "Memory used", Max),
    m("allconnectedclients", "Connected clients", Max),
    m("allcachehits", "Cache hits", Total),
    m("allcachemisses", "Cache misses", Total),
];
const MANAGED_REDIS: &[MetricSpec] = &[
    m("serverLoad", "Server load", Max),
    m("usedmemorypercentage", "Memory used", Max),
    m("connectedclients", "Connected clients", Max),
    m("operationsPerSecond", "Operations/s", Max),
    m("cachemisses", "Cache misses/s", Avg),
];
/// Service Bus: what is waiting, what died, and whether the namespace is
/// refusing work.
const SERVICE_BUS: &[MetricSpec] = &[
    m("IncomingMessages", "Incoming messages", Total),
    m("OutgoingMessages", "Outgoing messages", Total),
    m("ActiveMessages", "Active messages", Avg),
    m("DeadletteredMessages", "Dead-lettered", Avg),
    m("ServerErrors", "Server errors", Total),
    m("ThrottledRequests", "Throttled", Total),
];
const EVENT_HUBS: &[MetricSpec] = &[
    m("IncomingMessages", "Incoming events", Total),
    m("OutgoingMessages", "Outgoing events", Total),
    m("IncomingBytes", "Incoming bytes", Total),
    m("OutgoingBytes", "Outgoing bytes", Total),
    m("ThrottledRequests", "Throttled", Total),
    m("ServerErrors", "Server errors", Total),
];
/// Application gateway: traffic, failures, and whether the backends are
/// healthy (the health counts are what backend health would say, without
/// its POST).
const APP_GATEWAY: &[MetricSpec] = &[
    m("TotalRequests", "Requests", Total),
    m("FailedRequests", "Failed requests", Total),
    m("HealthyHostCount", "Healthy hosts", Avg),
    m("UnhealthyHostCount", "Unhealthy hosts", Max),
    m("ApplicationGatewayTotalTime", "Total time", Avg),
    m("Throughput", "Throughput", Avg),
];
/// Front Door Standard / Premium (`Microsoft.Cdn/profiles`).
const FRONT_DOOR: &[MetricSpec] = &[
    m("RequestCount", "Requests", Total),
    m("Percentage4XX", "4xx", Avg),
    m("Percentage5XX", "5xx", Avg),
    m("OriginHealthPercentage", "Origin health", Avg),
    m("TotalLatency", "Total latency", Avg),
    m("WebApplicationFirewallRequestCount", "WAF matches", Total),
];
/// Azure Firewall: health, SNAT port use (the exhaustion that drops
/// outbound flows), throughput and rule hits.
const AZURE_FIREWALL: &[MetricSpec] = &[
    m("FirewallHealth", "Health %", Avg),
    m("SNATPortUtilization", "SNAT ports used %", Max),
    m("Throughput", "Throughput", Avg),
    m("NetworkRuleHit", "Network rule hits", Total),
    m("ApplicationRuleHit", "Application rule hits", Total),
    m("FirewallLatencyPng", "Latency (probe)", Avg),
];

/// The default set for an ARM id, by its provider and type chain; empty
/// for a type with none (the `a` picker still lists what it has).
pub fn curated_metrics(id: &str) -> &'static [MetricSpec] {
    let Some((ns, chain)) = arm_type_chain(id) else {
        return &[];
    };
    let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
    match (ns.as_str(), chain.as_slice()) {
        ("microsoft.compute", ["virtualmachines"]) => VM,
        ("microsoft.containerservice", ["managedclusters"]) => AKS,
        ("microsoft.app", ["containerapps"]) => CONTAINER_APP,
        ("microsoft.web", ["sites"]) | ("microsoft.web", ["sites", "slots"]) => WEB_SITE,
        ("microsoft.web", ["serverfarms"]) => APP_SERVICE_PLAN,
        ("microsoft.sql", ["servers", "databases"]) => SQL_DATABASE,
        ("microsoft.dbforpostgresql", ["flexibleservers"]) => POSTGRES_FLEXIBLE,
        ("microsoft.dbformysql", ["flexibleservers"]) => MYSQL_FLEXIBLE,
        ("microsoft.storage", ["storageaccounts"]) => STORAGE,
        ("microsoft.keyvault", ["vaults"]) => KEY_VAULT,
        ("microsoft.documentdb", ["databaseaccounts"]) => COSMOS,
        ("microsoft.network", ["loadbalancers"]) => LOAD_BALANCER,
        ("microsoft.network", ["publicipaddresses"]) => PUBLIC_IP,
        ("microsoft.network", ["natgateways"]) => NAT_GATEWAY,
        ("microsoft.containerregistry", ["registries"]) => REGISTRY,
        ("microsoft.insights", ["components"]) => APP_INSIGHTS,
        ("microsoft.cognitiveservices", ["accounts"]) => COGNITIVE,
        ("microsoft.cache", ["redis"]) => REDIS_CACHE,
        ("microsoft.cache", ["redisenterprise"]) => MANAGED_REDIS,
        ("microsoft.servicebus", ["namespaces"]) => SERVICE_BUS,
        ("microsoft.eventhub", ["namespaces"]) => EVENT_HUBS,
        ("microsoft.network", ["applicationgateways"]) => APP_GATEWAY,
        ("microsoft.cdn", ["profiles"]) => FRONT_DOOR,
        ("microsoft.network", ["azurefirewalls"]) => AZURE_FIREWALL,
        _ => &[],
    }
}

/// Whether `m` opens on a default chart set (and the status bar says so).
pub fn supports_metrics(id: &str) -> bool {
    !curated_metrics(id).is_empty()
}

/// Whether `m` can try at all: an ARM resource (not a subscription, a
/// group, or a Graph object), so the picker can ask what it has.
pub fn is_arm_resource(id: &str) -> bool {
    arm_type_chain(id).is_some_and(|(_, chain)| !chain.is_empty())
}

/// One metric to chart: a curated spec or one picked from the
/// definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricQuery {
    pub name: String,
    pub label: String,
    pub aggregation: Aggregation,
}

impl From<&MetricSpec> for MetricQuery {
    fn from(s: &MetricSpec) -> Self {
        Self { name: s.name.to_string(), label: s.label.to_string(), aggregation: s.aggregation }
    }
}

pub fn curated_queries(id: &str) -> Vec<MetricQuery> {
    curated_metrics(id).iter().map(MetricQuery::from).collect()
}

pub fn metrics_path(id: &str) -> String {
    format!("{}/providers/Microsoft.Insights/metrics", id.trim_end_matches('/'))
}

pub fn definitions_path(id: &str) -> String {
    format!("{}/providers/Microsoft.Insights/metricDefinitions", id.trim_end_matches('/'))
}

/// The query pairs of one metrics call (`api-version` is added by the
/// constructor): every name, one aggregation, the window ending at `end`
/// (epoch seconds).
pub fn metrics_query(names: &[&str], aggregation: Aggregation, window: MetricWindow, end: i64) -> Vec<(&'static str, String)> {
    vec![
        ("metricnames", names.join(",")),
        ("timespan", format!("{}/{}", iso_utc(end - window.secs()), iso_utc(end))),
        ("interval", window.interval().to_string()),
        ("aggregation", aggregation.as_param().to_string()),
        ("AutoAdjustTimegrain", "true".to_string()),
    ]
}

/// One metric's answer: points as (epoch seconds, value), or why not.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSeries {
    pub name: String,
    pub label: String,
    pub unit: String,
    pub aggregation: Aggregation,
    pub points: Vec<(i64, f64)>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    pub last: f64,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
}

impl MetricSeries {
    fn failed(q: &MetricQuery, error: String) -> Self {
        Self {
            name: q.name.clone(),
            label: q.label.clone(),
            unit: String::new(),
            aggregation: q.aggregation,
            points: Vec::new(),
            error: Some(error),
        }
    }

    pub fn stats(&self) -> Option<Stats> {
        let last = self.points.last()?.1;
        let (mut min, mut max, mut sum) = (f64::MAX, f64::MIN, 0.0);
        for &(_, v) in &self.points {
            min = min.min(v);
            max = max.max(v);
            sum += v;
        }
        Some(Stats { last, min, max, avg: sum / self.points.len() as f64 })
    }

    /// `label · unit agg  last … min … max … avg …` (the `y` copy, the
    /// editor view).
    pub fn summary(&self) -> String {
        let head = format!("{} ({} {})", self.label, self.aggregation.short(), self.name);
        match (&self.error, self.stats()) {
            (Some(e), _) => format!("{}  ! {}", head, e),
            (None, None) => format!("{}  no data in the window", head),
            (None, Some(s)) => format!(
                "{}  last {}  min {}  max {}  avg {}",
                head,
                fmt_value(s.last, &self.unit),
                fmt_value(s.min, &self.unit),
                fmt_value(s.max, &self.unit),
                fmt_value(s.avg, &self.unit)
            ),
        }
    }
}

/// The metrics response, in the order of `queries`; a query the body does
/// not answer is a series with an error.
pub fn parse_metrics(body: &Value, queries: &[MetricQuery]) -> Vec<MetricSeries> {
    let values = body.get("value").and_then(Value::as_array).cloned().unwrap_or_default();
    queries
        .iter()
        .map(|q| {
            let Some(v) = values.iter().find(|v| {
                v.pointer("/name/value").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case(&q.name))
            }) else {
                return MetricSeries::failed(q, "not in the response".into());
            };
            let code = v.get("errorCode").and_then(Value::as_str).unwrap_or("Success");
            let error = (!code.eq_ignore_ascii_case("Success")).then(|| {
                v.get("errorMessage").and_then(Value::as_str).map(|m| format!("{}: {}", code, m)).unwrap_or(code.to_string())
            });
            // No `$filter`, so one series (dimensions aggregated away).
            let field = q.aggregation.field();
            let points = v
                .pointer("/timeseries/0/data")
                .and_then(Value::as_array)
                .map(|data| {
                    data.iter()
                        .filter_map(|p| {
                            let t = parse_iso_utc(p.get("timeStamp")?.as_str()?)?;
                            Some((t, p.get(field)?.as_f64()?))
                        })
                        .collect()
                })
                .unwrap_or_default();
            MetricSeries {
                name: q.name.clone(),
                label: q.label.clone(),
                unit: v.get("unit").and_then(Value::as_str).unwrap_or("").to_string(),
                aggregation: q.aggregation,
                points,
                error,
            }
        })
        .collect()
}

/// One entry of the `a` picker.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricDefinition {
    pub name: String,
    pub label: String,
    pub unit: String,
    pub aggregation: Aggregation,
    pub dimensions: Vec<String>,
}

impl MetricDefinition {
    pub fn query(&self) -> MetricQuery {
        MetricQuery { name: self.name.clone(), label: self.label.clone(), aggregation: self.aggregation }
    }
}

/// The definitions response, sorted by display name.
pub fn parse_definitions(body: &Value) -> Vec<MetricDefinition> {
    let mut defs: Vec<MetricDefinition> = body
        .get("value")
        .and_then(Value::as_array)
        .map(|vs| {
            vs.iter()
                .filter_map(|v| {
                    let name = v.pointer("/name/value")?.as_str()?.to_string();
                    let label = v.pointer("/name/localizedValue").and_then(Value::as_str).unwrap_or(&name).to_string();
                    let aggregation = v
                        .get("primaryAggregationType")
                        .and_then(Value::as_str)
                        .and_then(Aggregation::parse)
                        .unwrap_or(Aggregation::Average);
                    let dimensions = v
                        .get("dimensions")
                        .and_then(Value::as_array)
                        .map(|ds| ds.iter().filter_map(|d| d.get("value")?.as_str().map(str::to_string)).collect())
                        .unwrap_or_default();
                    Some(MetricDefinition {
                        name,
                        label,
                        unit: v.get("unit").and_then(Value::as_str).unwrap_or("").to_string(),
                        aggregation,
                        dimensions,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    defs.sort_by_key(|d| d.label.to_lowercase());
    defs
}

/// Shorten an ARM error for one line: a 403 says which action is missing.
pub fn short_error(e: &str) -> String {
    if e.contains("403") || e.contains("AuthorizationFailed") || e.contains("Forbidden") {
        return "no access (needs Microsoft.Insights/metrics/read, in Reader)".into();
    }
    let first = e.lines().next().unwrap_or(e);
    if first.chars().count() > 160 {
        format!("{}…", first.chars().take(160).collect::<String>())
    } else {
        first.to_string()
    }
}

/// Every query's series, in order: one call per aggregation, and a failed
/// call of several names retried one name at a time (a 403 is not
/// retried: it fails the same for every name). `fetch` takes the query
/// pairs of one call.
pub async fn fetch_series<F, Fut>(queries: &[MetricQuery], window: MetricWindow, end: i64, fetch: F) -> Vec<MetricSeries>
where
    F: Fn(Vec<(&'static str, String)>) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let mut out: Vec<Option<MetricSeries>> = vec![None; queries.len()];
    let mut groups: Vec<(Aggregation, Vec<usize>)> = Vec::new();
    for (i, q) in queries.iter().enumerate() {
        match groups.iter_mut().find(|(a, _)| *a == q.aggregation) {
            Some((_, idx)) => idx.push(i),
            None => groups.push((q.aggregation, vec![i])),
        }
    }
    for (aggregation, idx) in groups {
        let group: Vec<MetricQuery> = idx.iter().map(|&i| queries[i].clone()).collect();
        let names: Vec<&str> = group.iter().map(|q| q.name.as_str()).collect();
        match fetch(metrics_query(&names, aggregation, window, end)).await {
            Ok(body) => {
                for (i, s) in idx.iter().zip(parse_metrics(&body, &group)) {
                    out[*i] = Some(s);
                }
            }
            Err(e) if group.len() > 1 && !short_error(&e).starts_with("no access") => {
                for (&i, q) in idx.iter().zip(&group) {
                    let one = std::slice::from_ref(q);
                    out[i] = Some(match fetch(metrics_query(&[q.name.as_str()], aggregation, window, end)).await {
                        Ok(body) => parse_metrics(&body, one).remove(0),
                        Err(e) => MetricSeries::failed(q, short_error(&e)),
                    });
                }
            }
            Err(e) => {
                let e = short_error(&e);
                for (&i, q) in idx.iter().zip(&group) {
                    out[i] = Some(MetricSeries::failed(q, e.clone()));
                }
            }
        }
    }
    out.into_iter().flatten().collect()
}

/// A value in the metric's unit, short: `12.3%`, `1.5 GiB`, `3.2k`.
pub fn fmt_value(v: f64, unit: &str) -> String {
    let num = |v: f64| {
        let a = v.abs();
        if a >= 1e9 {
            format!("{:.1}G", v / 1e9)
        } else if a >= 1e6 {
            format!("{:.1}M", v / 1e6)
        } else if a >= 1e3 {
            format!("{:.1}k", v / 1e3)
        } else if a >= 10.0 || v == v.trunc() {
            format!("{:.0}", v)
        } else {
            format!("{:.2}", v)
        }
    };
    let bytes = |v: f64| {
        const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
        let mut x = v;
        let mut i = 0;
        while x.abs() >= 1024.0 && i < U.len() - 1 {
            x /= 1024.0;
            i += 1;
        }
        if i == 0 {
            format!("{:.0} B", x)
        } else {
            format!("{:.1} {}", x, U[i])
        }
    };
    match unit {
        "Percent" => format!("{:.1}%", v),
        "Bytes" => bytes(v),
        "BytesPerSecond" => format!("{}/s", bytes(v)),
        "BitsPerSecond" => format!("{}b/s", num(v)),
        "CountPerSecond" => format!("{}/s", num(v)),
        "MilliSeconds" => format!("{} ms", num(v)),
        "Seconds" => format!("{} s", num(v)),
        "NanoCores" => format!("{:.3} cores", v / 1e9),
        "MilliCores" => format!("{:.2} cores", v / 1e3),
        _ => num(v),
    }
}

// ── UTC time without a date crate ───────────────────────────────────────

/// Now, in epoch seconds, floored to the minute (the window's end).
pub fn now_minute() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    secs - secs.rem_euclid(60)
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `2026-10-23T09:00:00Z`.
pub fn iso_utc(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, s / 3600, s % 3600 / 60, s % 60)
}

/// `2026-10-23T09:00:00Z` (fractional seconds and an offset of `Z` or
/// `+00:00` accepted) to epoch seconds.
pub fn parse_iso_utc(s: &str) -> Option<i64> {
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, mo, da) = (d.next()??, d.next()??, d.next()??);
    let time = time.trim_end_matches('Z').trim_end_matches("+00:00");
    let mut t = time.split(':');
    let h: i64 = t.next()?.parse().ok()?;
    let mi: i64 = t.next()?.parse().ok()?;
    let sec: f64 = t.next().unwrap_or("0").parse().ok()?;
    Some(days_from_civil(y, mo, da) * 86_400 + h * 3600 + mi * 60 + sec as i64)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    const VM_ID: &str = "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1";

    #[test]
    fn utc_round_trips() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        let t = parse_iso_utc("2021-04-20T09:00:00Z").unwrap();
        assert_eq!(iso_utc(t), "2021-04-20T09:00:00Z");
        assert_eq!(parse_iso_utc("2024-02-29T23:59:30.500Z").map(iso_utc).as_deref(), Some("2024-02-29T23:59:30Z"));
        assert_eq!(parse_iso_utc("2021-04-20T09:01:00+00:00"), Some(t + 60));
        assert_eq!(parse_iso_utc("nope"), None);
    }

    #[test]
    fn windows_cycle_and_pick_their_grain() {
        assert_eq!(MetricWindow::default().next(), MetricWindow::SixHours);
        assert_eq!(MetricWindow::OneHour.prev(), MetricWindow::SevenDays);
        assert_eq!(MetricWindow::from_digit('3'), Some(MetricWindow::OneDay));
        assert_eq!(MetricWindow::from_digit('5'), None);
        assert_eq!(MetricWindow::from_digit('0'), None);
        for w in MetricWindow::ALL {
            let grain = match w.interval() {
                "PT1M" => 60,
                "PT5M" => 300,
                "PT15M" => 900,
                "PT1H" => 3600,
                other => panic!("{other}"),
            };
            let points = w.secs() / grain;
            assert!((60..=168).contains(&points), "{w:?}: {points} points");
        }
    }

    #[test]
    fn the_request_names_every_metric_one_aggregation_and_the_window() {
        assert_eq!(metrics_path(VM_ID), format!("{}/providers/Microsoft.Insights/metrics", VM_ID));
        assert_eq!(definitions_path(&format!("{}/", VM_ID)), format!("{}/providers/Microsoft.Insights/metricDefinitions", VM_ID));
        let end = parse_iso_utc("2026-10-23T12:00:00Z").unwrap();
        let q = metrics_query(&["Percentage CPU", "Disk Read Operations/Sec"], Aggregation::Average, MetricWindow::SixHours, end);
        assert_eq!(
            q,
            vec![
                ("metricnames", "Percentage CPU,Disk Read Operations/Sec".to_string()),
                ("timespan", "2026-10-23T06:00:00Z/2026-10-23T12:00:00Z".to_string()),
                ("interval", "PT5M".to_string()),
                ("aggregation", "Average".to_string()),
                ("AutoAdjustTimegrain", "true".to_string()),
            ]
        );
    }

    #[test]
    fn curated_sets_follow_the_arm_type() {
        let names = |id: &str| curated_metrics(id).iter().map(|s| s.name).collect::<Vec<_>>();
        assert!(names(VM_ID).contains(&"Percentage CPU"));
        let p = |t: &str| format!("/subscriptions/0000/resourceGroups/rg/providers/{}", t);
        assert!(names(&p("Microsoft.Sql/servers/s/databases/orders")).contains(&"cpu_percent"));
        assert!(names(&p("Microsoft.DBforPostgreSQL/flexibleServers/pg")).contains(&"connections_failed"));
        assert!(names(&p("Microsoft.DBforMySQL/flexibleServers/my")).contains(&"aborted_connections"));
        assert!(names(&p("microsoft.insights/components/ai")).contains(&"requests/failed"));
        assert!(names(&p("Microsoft.Web/sites/app/slots/staging")).contains(&"Http5xx"));
        assert!(names(&p("Microsoft.Cache/Redis/r")).contains(&"allserverLoad"));
        assert!(names(&p("Microsoft.Cache/redisEnterprise/amr")).contains(&"usedmemorypercentage"));
        assert!(names(&p("Microsoft.ServiceBus/namespaces/sb")).contains(&"DeadletteredMessages"));
        assert!(names(&p("microsoft.eventhub/namespaces/eh")).contains(&"IncomingBytes"));
        assert!(!supports_metrics(&p("Microsoft.ServiceBus/namespaces/sb/queues/q")));
        assert!(names(&p("Microsoft.Network/applicationGateways/agw")).contains(&"UnhealthyHostCount"));
        assert!(names(&p("Microsoft.Cdn/profiles/afd")).contains(&"OriginHealthPercentage"));
        assert!(names(&p("Microsoft.Network/azureFirewalls/afw")).contains(&"SNATPortUtilization"));
        assert!(!supports_metrics(&p("Microsoft.Network/firewallPolicies/fwp")));
        assert!(!supports_metrics(&p("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/w")));
        // A child with no set of its own, a group, a subscription.
        assert!(!supports_metrics(&p("Microsoft.Network/virtualNetworks/v/subnets/s")));
        assert!(!supports_metrics("/subscriptions/0000/resourceGroups/rg"));
        assert!(is_arm_resource(&p("Microsoft.Network/virtualNetworks/v")));
        assert!(!is_arm_resource("/subscriptions/0000"));
        for set in [VM, AKS, CONTAINER_APP, WEB_SITE, SQL_DATABASE, POSTGRES_FLEXIBLE, MYSQL_FLEXIBLE, STORAGE, KEY_VAULT, COSMOS, LOAD_BALANCER, PUBLIC_IP, REDIS_CACHE, MANAGED_REDIS, SERVICE_BUS, EVENT_HUBS, APP_GATEWAY, FRONT_DOOR, AZURE_FIREWALL] {
            assert!((2..=6).contains(&set.len()));
        }
    }

    fn queries() -> Vec<MetricQuery> {
        vec![
            MetricQuery { name: "Percentage CPU".into(), label: "CPU".into(), aggregation: Aggregation::Average },
            MetricQuery { name: "Network In Total".into(), label: "Network in".into(), aggregation: Aggregation::Total },
        ]
    }

    /// The documented shape (Metrics - List, 2023-10-01), one series
    /// answered and one with a per-metric error.
    pub(crate) fn fixture() -> Value {
        json!({
            "cost": 59, "timespan": "2026-10-23T11:00:00Z/2026-10-23T12:00:00Z", "interval": "PT1M",
            "value": [
                {"id": format!("{}/providers/Microsoft.Insights/metrics/Percentage CPU", VM_ID), "type": "Microsoft.Insights/metrics",
                 "name": {"value": "Percentage CPU", "localizedValue": "Percentage CPU"}, "unit": "Percent",
                 "timeseries": [{"metadatavalues": [], "data": [
                     {"timeStamp": "2026-10-23T11:00:00Z", "average": 10.0},
                     {"timeStamp": "2026-10-23T11:01:00Z"},
                     {"timeStamp": "2026-10-23T11:02:00Z", "average": 30.0},
                     {"timeStamp": "2026-10-23T11:03:00Z", "average": 20.0}
                 ]}], "errorCode": "Success"},
                {"id": "x", "name": {"value": "Network In Total"}, "unit": "Bytes", "timeseries": [],
                 "errorCode": "InvalidSamplingType", "errorMessage": "Sampling type is not found."}
            ],
            "namespace": "Microsoft.Compute/virtualMachines", "resourceregion": "westeurope"
        })
    }

    #[test]
    fn the_response_parses_into_series_with_stats() {
        let s = parse_metrics(&fixture(), &queries());
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].unit, "Percent");
        assert_eq!(s[0].points.len(), 3, "a point without the aggregation is a gap");
        assert_eq!(s[0].stats(), Some(Stats { last: 20.0, min: 10.0, max: 30.0, avg: 20.0 }));
        assert!(s[0].summary().contains("last 20.0%  min 10.0%  max 30.0%  avg 20.0%"), "{}", s[0].summary());
        assert_eq!(s[1].error.as_deref(), Some("InvalidSamplingType: Sampling type is not found."));
        assert_eq!(s[1].stats(), None);
        // A name the body does not carry.
        let missing = parse_metrics(&json!({"value": []}), &queries()[..1]);
        assert_eq!(missing[0].error.as_deref(), Some("not in the response"));
    }

    #[test]
    fn definitions_parse_sorted_with_their_primary_aggregation() {
        let body = json!({"value": [
            {"name": {"value": "Percentage CPU", "localizedValue": "Percentage CPU"}, "unit": "Percent",
             "primaryAggregationType": "Average", "supportedAggregationTypes": ["None", "Average", "Minimum", "Maximum", "Total", "Count"],
             "metricAvailabilities": [{"timeGrain": "PT1M", "retention": "P93D"}]},
            {"name": {"value": "Inbound Flows", "localizedValue": "Inbound Flows"}, "unit": "Count",
             "primaryAggregationType": "Total", "dimensions": [{"value": "Direction", "localizedValue": "Direction"}]}
        ]});
        let d = parse_definitions(&body);
        assert_eq!(d.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["Inbound Flows", "Percentage CPU"]);
        assert_eq!(d[0].aggregation, Aggregation::Total);
        assert_eq!(d[0].dimensions, ["Direction"]);
        assert_eq!(d[1].query().aggregation, Aggregation::Average);
    }

    #[test]
    fn values_read_in_their_unit() {
        assert_eq!(fmt_value(12.345, "Percent"), "12.3%");
        assert_eq!(fmt_value(1536.0, "Bytes"), "1.5 KiB");
        assert_eq!(fmt_value(3.0 * 1024.0 * 1024.0 * 1024.0, "Bytes"), "3.0 GiB");
        assert_eq!(fmt_value(2500.0, "Count"), "2.5k");
        assert_eq!(fmt_value(4.0, "Count"), "4");
        assert_eq!(fmt_value(0.25, "MilliSeconds"), "0.25 ms");
        assert_eq!(fmt_value(5e8, "NanoCores"), "0.500 cores");
    }

    #[tokio::test]
    async fn one_call_per_aggregation_and_a_failed_group_retries_per_name() {
        use std::sync::Mutex;
        let calls: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let mut qs = queries();
        qs.push(MetricQuery { name: "Bogus".into(), label: "Bogus".into(), aggregation: Aggregation::Average });
        let fetch = |q: Vec<(&'static str, String)>| {
            let names = q[0].1.clone();
            calls.lock().unwrap().push(names.clone());
            async move {
                if names.contains("Bogus") {
                    Err("400 BadRequest: Failed to find metric configuration for provider".to_string())
                } else {
                    Ok(fixture())
                }
            }
        };
        let s = fetch_series(&qs, MetricWindow::OneHour, 0, fetch).await;
        assert_eq!(
            *calls.lock().unwrap(),
            ["Percentage CPU,Bogus", "Percentage CPU", "Bogus", "Network In Total"],
            "the Average group failed whole, then went name by name"
        );
        assert_eq!(s.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["Percentage CPU", "Network In Total", "Bogus"]);
        assert!(s[0].error.is_none() && s[0].points.len() == 3);
        assert!(s[2].error.as_deref().unwrap().starts_with("400 BadRequest"));

        // A 403 is not retried name by name.
        calls.lock().unwrap().clear();
        let denied = |q: Vec<(&'static str, String)>| {
            calls.lock().unwrap().push(q[0].1.clone());
            async { Err::<Value, _>("403 Forbidden AuthorizationFailed".to_string()) }
        };
        let s = fetch_series(&qs, MetricWindow::OneHour, 0, denied).await;
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert!(s.iter().all(|s| s.error.as_deref().unwrap().starts_with("no access")));
    }
}
