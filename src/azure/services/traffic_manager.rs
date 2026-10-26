//! Traffic Manager profiles (#143), a DNS sub-tab (`@tm`): Traffic Manager
//! answers DNS (a CNAME to the endpoint it picks), so it is debugged with
//! the zones and resolvers, not the gateways. One subscription-wide list
//! (`Microsoft.Network/trafficmanagerprofiles`, its own spec and
//! api-version); `location` is `global`. Endpoints are embedded in the list
//! body: no lazy calls.
//!
//! The state is the profile's: `Disabled` → stopped, else the monitor's
//! `profileMonitorStatus` (`Online` → available, `Degraded` and
//! `CheckingEndpoints` → pending, `Inactive` → unavailable). Each
//! endpoint's `endpointMonitorStatus` is on its line, `Degraded` and
//! `Stopped` flagged. An Azure endpoint's target resource jumps (a public
//! IP, an App Service site), a nested endpoint jumps to its child profile,
//! an external endpoint's FQDN or IP is text: nebaz never resolves it.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::services::{arm_row, json, overview_rows, related_rows, tag_rows, ArmBase};
use serde_json::Value;

pub const TRAFFIC_MANAGER_PATH: &str = "/providers/Microsoft.Network/trafficmanagerprofiles";
/// Traffic Manager's own spec: `2022-04-01`, the newest stable for years
/// (azure-rest-api-specs, 2026-10-26). `2026-09-01` landed seven weeks ago
/// (the CLI already uses it) and adds only `recordType`.
pub const TRAFFIC_MANAGER_API_VERSION: &str = "2022-04-01";

crate::sections! {
    pub enum TrafficManagerDetailSection,
    pub static TRAFFIC_MANAGER_SECTIONS = [
        Overview "Overview",
        Routing "Routing",
        Monitor "Monitor",
        Endpoints "Endpoints",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Azure,
    External,
    Nested,
    Other,
}

impl EndpointKind {
    fn of(arm_type: &str) -> Self {
        let t = arm_type.to_ascii_lowercase();
        if t.ends_with("/azureendpoints") {
            EndpointKind::Azure
        } else if t.ends_with("/externalendpoints") {
            EndpointKind::External
        } else if t.ends_with("/nestedendpoints") {
            EndpointKind::Nested
        } else {
            EndpointKind::Other
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            EndpointKind::Azure => "Azure",
            EndpointKind::External => "External",
            EndpointKind::Nested => "Nested",
            EndpointKind::Other => "Endpoint",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TmEndpoint {
    pub name: String,
    pub kind: EndpointKind,
    pub target_resource_id: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub monitor_status: Option<String>,
    pub weight: Option<i64>,
    pub priority: Option<i64>,
    pub location: Option<String>,
    pub geo_mapping: Vec<String>,
    /// `first-last` or `first/scope`, the Subnet method's ranges.
    pub subnets: Vec<String>,
    pub min_child_endpoints: Option<i64>,
    pub always_serve: Option<String>,
}

impl TmEndpoint {
    fn from_json(v: &Value) -> TmEndpoint {
        let p = |s: &str| format!("/properties/{}", s);
        TmEndpoint {
            name: json::text(v, "/name"),
            kind: EndpointKind::of(&json::str_at(v, "/type").unwrap_or_default()),
            target_resource_id: json::arm_id(json::str_at(v, &p("targetResourceId"))),
            target: json::str_at(v, &p("target")),
            status: json::str_at(v, &p("endpointStatus")),
            monitor_status: json::str_at(v, &p("endpointMonitorStatus")),
            weight: json::int_at(v, &p("weight")),
            priority: json::int_at(v, &p("priority")),
            location: json::str_at(v, &p("endpointLocation")),
            geo_mapping: json::strings_at(v, &p("geoMapping")),
            subnets: json::arr(v, &p("subnets"))
                .iter()
                .map(|s| match (json::str_at(s, "/first"), json::str_at(s, "/last"), json::int_at(s, "/scope")) {
                    (Some(f), Some(l), _) => format!("{}-{}", f, l),
                    (Some(f), None, Some(scope)) => format!("{}/{}", f, scope),
                    (Some(f), None, None) => f,
                    _ => "-".into(),
                })
                .collect(),
            min_child_endpoints: json::int_at(v, &p("minChildEndpoints")),
            always_serve: json::str_at(v, &p("alwaysServe")),
        }
    }

    /// Degraded or Stopped: the endpoint is not served (or, Stopped, the
    /// resource behind it is stopped).
    pub fn is_unhealthy(&self) -> bool {
        self.monitor_status
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("degraded") || s.eq_ignore_ascii_case("stopped"))
    }
}

#[derive(Debug, Clone)]
pub struct TrafficManagerRow {
    pub base: ArmBase,
    pub routing_method: Option<String>,
    pub profile_status: Option<String>,
    pub monitor_status: Option<String>,
    pub relative_name: Option<String>,
    pub fqdn: Option<String>,
    pub ttl: Option<i64>,
    pub monitor: Value,
    pub endpoints: Vec<TmEndpoint>,
    pub traffic_view: Option<String>,
    pub max_return: Option<i64>,
}

impl TrafficManagerRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<TrafficManagerRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |s: &str| format!("/properties/{}", s);
        Some(TrafficManagerRow {
            routing_method: json::str_at(v, &p("trafficRoutingMethod")),
            profile_status: json::str_at(v, &p("profileStatus")),
            monitor_status: json::str_at(v, &p("monitorConfig/profileMonitorStatus")),
            relative_name: json::str_at(v, &p("dnsConfig/relativeName")),
            fqdn: json::str_at(v, &p("dnsConfig/fqdn")),
            ttl: json::int_at(v, &p("dnsConfig/ttl")),
            monitor: v.pointer("/properties/monitorConfig").cloned().unwrap_or(Value::Null),
            endpoints: json::arr(v, &p("endpoints")).iter().map(TmEndpoint::from_json).collect(),
            traffic_view: json::str_at(v, &p("trafficViewEnrollmentStatus")),
            max_return: json::int_at(v, &p("maxReturn")),
            base,
        })
    }

    /// Profile status first (a disabled profile answers NXDOMAIN), then
    /// the monitor's verdict over its endpoints.
    fn ladder(&self) -> (ResourceState, String) {
        let disabled = self.profile_status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("disabled"));
        let runtime = if disabled {
            Some((ResourceState::Stopped, "Disabled"))
        } else {
            self.monitor_status.as_deref().map(|s| {
                let bucket = match s.to_ascii_lowercase().as_str() {
                    "online" => ResourceState::Available,
                    "inactive" => ResourceState::Unavailable,
                    "disabled" => ResourceState::Stopped,
                    _ => ResourceState::Pending,
                };
                (bucket, s)
            })
        };
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    fn unhealthy(&self) -> usize {
        self.endpoints.iter().filter(|e| e.is_unhealthy()).count()
    }

    pub fn routing_rows(&self) -> Vec<(String, String)> {
        let method = json::opt(self.routing_method.clone());
        let explain = match self.routing_method.as_deref() {
            Some("Priority") => "the healthy endpoint with the lowest priority number answers; the rest are failover",
            Some("Weighted") => "endpoints answer in proportion to their weight",
            Some("Performance") => "the endpoint closest (by latency) to the caller's resolver",
            Some("Geographic") => "by the caller's region, from each endpoint's geo mapping",
            Some("MultiValue") => "every healthy IP endpoint, up to Max return",
            Some("Subnet") => "by the caller's source address, from each endpoint's ranges",
            _ => "",
        };
        let mut lines = vec![("Routing method".into(), method)];
        if !explain.is_empty() {
            lines.push((String::new(), format!("· {}", explain)));
        }
        if let Some(n) = self.max_return.filter(|_| self.routing_method.as_deref() == Some("MultiValue")) {
            lines.push(("Max return".into(), n.to_string()));
        }
        lines.push((String::new(), String::new()));
        lines.push(("Relative DNS name".into(), json::opt(self.relative_name.clone())));
        lines.push(("FQDN".into(), json::opt(self.fqdn.clone())));
        lines.push((String::new(), "· the name clients CNAME to; text, never resolved".into()));
        lines.push(("TTL".into(), self.ttl.map(|t| format!("{} s", t)).unwrap_or_else(|| "-".into())));
        lines.push(("Profile status".into(), json::opt(self.profile_status.clone())));
        lines.push(("Traffic view".into(), json::opt(self.traffic_view.clone())));
        lines
    }

    pub fn monitor_rows(&self) -> Vec<(String, String)> {
        let m = &self.monitor;
        if m.is_null() {
            return vec![(String::new(), "No monitor configuration".into())];
        }
        let codes: Vec<String> = json::arr(m, "/expectedStatusCodeRanges")
            .iter()
            .map(|r| match (json::int_at(r, "/min"), json::int_at(r, "/max")) {
                (Some(a), Some(b)) if a == b => a.to_string(),
                (Some(a), Some(b)) => format!("{}-{}", a, b),
                _ => "-".into(),
            })
            .collect();
        let headers: Vec<String> = json::arr(m, "/customHeaders")
            .iter()
            .map(|h| format!("{}: {}", json::text(h, "/name"), json::text(h, "/value")))
            .collect();
        let mut lines = vec![
            ("Monitor status".into(), json::opt(self.monitor_status.clone())),
            ("Protocol".into(), json::text(m, "/protocol")),
            ("Port".into(), json::num(json::int_at(m, "/port"))),
            ("Path".into(), json::text(m, "/path")),
            ("Interval".into(), json::int_at(m, "/intervalInSeconds").map(|s| format!("{} s", s)).unwrap_or_else(|| "-".into())),
            ("Timeout".into(), json::int_at(m, "/timeoutInSeconds").map(|s| format!("{} s", s)).unwrap_or_else(|| "-".into())),
            ("Tolerated failures".into(), json::num(json::int_at(m, "/toleratedNumberOfFailures"))),
            (
                "Expected status codes".into(),
                if codes.is_empty() { "200 (default)".into() } else { codes.join(", ") },
            ),
        ];
        if !headers.is_empty() {
            lines.push(("Custom headers".into(), headers.join(", ")));
        }
        lines
    }

    pub fn endpoint_rows(&self) -> Vec<(String, String)> {
        if self.endpoints.is_empty() {
            return vec![(String::new(), "⚠ No endpoints: the profile answers nothing".into())];
        }
        let mut eps: Vec<&TmEndpoint> = self.endpoints.iter().collect();
        eps.sort_by_key(|e| e.priority.unwrap_or(i64::MAX));
        let mut lines = Vec::new();
        for e in eps {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push((format!("{} · {}", e.name, e.kind.label()), String::new()));
            match (&e.target_resource_id, e.kind) {
                (Some(t), EndpointKind::Nested) => lines.push((format!("  Child profile · {}", name_of_id(t)), t.clone())),
                (Some(t), _) => lines.push((format!("  Target resource · {}", name_of_id(t)), t.clone())),
                (None, _) => {}
            }
            if let Some(t) = &e.target {
                lines.push(("  Target".into(), t.clone()));
            }
            let status = json::opt(e.status.clone());
            lines.push(("  Endpoint status".into(), status));
            let monitor = json::opt(e.monitor_status.clone());
            lines.push((
                "  Monitor status".into(),
                if e.is_unhealthy() { format!("⚠ {}: not served", monitor) } else { monitor },
            ));
            if let Some(p) = e.priority {
                lines.push(("  Priority".into(), p.to_string()));
            }
            if let Some(w) = e.weight {
                lines.push(("  Weight".into(), w.to_string()));
            }
            if let Some(l) = &e.location {
                lines.push(("  Location".into(), l.clone()));
            }
            if !e.geo_mapping.is_empty() {
                lines.push(("  Geo mapping".into(), e.geo_mapping.join(", ")));
            }
            if !e.subnets.is_empty() {
                lines.push(("  Subnets".into(), e.subnets.join(", ")));
            }
            if let Some(n) = e.min_child_endpoints {
                lines.push(("  Min child endpoints".into(), n.to_string()));
            }
            if let Some(a) = e.always_serve.as_ref().filter(|a| a.eq_ignore_ascii_case("enabled")) {
                lines.push(("  Always serve".into(), format!("{} (health checks ignored)", a)));
            }
        }
        lines
    }
}

impl Resource for TrafficManagerRow {
    arm_row!("Traffic Manager profile");
    /// `Priority · 2 endpoints · 1 degraded`.
    fn list_summary(&self) -> Option<String> {
        let n = self.endpoints.len();
        crate::azure::resource::summary_of([
            self.routing_method.clone(),
            Some(if n == 1 { "1 endpoint".to_string() } else { format!("{} endpoints", n) }),
            (self.unhealthy() > 0).then(|| format!("{} degraded", self.unhealthy())),
        ])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&TRAFFIC_MANAGER_SECTIONS)
    }
    /// The FQDN and every endpoint target are searchable.
    fn search_text(&self) -> String {
        let mut parts = vec![
            self.base.id.clone(),
            self.base.name.clone(),
            self.resource_group().unwrap_or("").to_string(),
            self.fqdn.clone().unwrap_or_default(),
        ];
        parts.extend(self.endpoints.iter().filter_map(|e| e.target.clone()));
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Profile status".into(), json::opt(self.profile_status.clone())),
            ("Monitor status".into(), json::opt(self.monitor_status.clone())),
            ("Routing method".into(), json::opt(self.routing_method.clone())),
            ("FQDN".into(), json::opt(self.fqdn.clone())),
            ("TTL".into(), json::num(self.ttl)),
            ("Endpoints".into(), format!("{} ({} degraded or stopped)", self.endpoints.len(), self.unhealthy())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for e in &self.endpoints {
            if let Some(t) = &e.target_resource_id {
                if !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(t)) {
                    let what = if e.kind == EndpointKind::Nested { "Child profile" } else { "Endpoint" };
                    v.push((format!("{} {} → {}", what, e.name, name_of_id(t)), t.clone()));
                }
            }
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network traffic-manager profile show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn traffic_manager_section_lines(r: &TrafficManagerRow, section: TrafficManagerDetailSection) -> Vec<(String, String)> {
    match section {
        TrafficManagerDetailSection::Overview => overview_rows(r),
        TrafficManagerDetailSection::Routing => r.routing_rows(),
        TrafficManagerDetailSection::Monitor => r.monitor_rows(),
        TrafficManagerDetailSection::Endpoints => r.endpoint_rows(),
        TrafficManagerDetailSection::Access => crate::azure::services::rendered_by_app(),
        TrafficManagerDetailSection::Activity => crate::azure::services::rendered_by_app(),
        TrafficManagerDetailSection::Related => related_rows(r),
        TrafficManagerDetailSection::Tags => tag_rows(r.tags()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-edge/providers/Microsoft.Network";

    fn tm_json(monitor: &str) -> Value {
        json!({
            "id": format!("{}/trafficManagerProfiles/tm-orders", RG),
            "name": "tm-orders",
            "type": "Microsoft.Network/trafficManagerProfiles",
            "location": "global",
            "properties": {
                "profileStatus": "Enabled",
                "trafficRoutingMethod": "Priority",
                "dnsConfig": {"relativeName": "tm-orders", "fqdn": "tm-orders.trafficmanager.example", "ttl": 30},
                "monitorConfig": {"profileMonitorStatus": monitor, "protocol": "HTTPS", "port": 443, "path": "/healthz",
                    "intervalInSeconds": 30, "timeoutInSeconds": 10, "toleratedNumberOfFailures": 3,
                    "expectedStatusCodeRanges": [{"min": 200, "max": 299}]},
                "endpoints": [
                    {"name": "primary", "type": "Microsoft.Network/trafficManagerProfiles/azureEndpoints",
                     "properties": {"targetResourceId": format!("{}/publicIPAddresses/pip-agw", RG), "target": "agw.example",
                        "endpointStatus": "Enabled", "endpointMonitorStatus": "Online", "priority": 1, "weight": 1}},
                    {"name": "dr", "type": "Microsoft.Network/trafficManagerProfiles/externalEndpoints",
                     "properties": {"target": "dr.contoso.example", "endpointStatus": "Enabled",
                        "endpointMonitorStatus": "Degraded", "priority": 2}},
                    {"name": "child", "type": "Microsoft.Network/trafficManagerProfiles/nestedEndpoints",
                     "properties": {"targetResourceId": format!("{}/trafficManagerProfiles/tm-child", RG),
                        "endpointStatus": "Enabled", "endpointMonitorStatus": "Online", "priority": 3, "minChildEndpoints": 1}}
                ]
            }
        })
    }

    #[test]
    fn a_profile_parses_its_endpoints_and_state() {
        let r = TrafficManagerRow::from_json(&tm_json("Degraded"), None).unwrap();
        assert_eq!(r.base.location, "global");
        assert_eq!(r.state(), ResourceState::Pending);
        assert_eq!(r.state_label(), "degraded");
        assert_eq!(r.list_summary().as_deref(), Some("Priority · 3 endpoints · 1 degraded"));
        let lines = r.endpoint_rows();
        assert!(lines.iter().any(|(k, v)| k == "  Monitor status" && v.starts_with("⚠ Degraded")));
        assert!(lines.iter().any(|(k, v)| k == "  Child profile · tm-child" && v.ends_with("/tm-child")));
        assert!(lines.iter().any(|(k, v)| k == "  Target" && v == "dr.contoso.example"));
        let rel = r.related();
        assert!(rel.iter().any(|(_, v)| v.ends_with("/publicIPAddresses/pip-agw")));
        assert!(rel.iter().any(|(k, _)| k.starts_with("Child profile child")));
    }

    #[test]
    fn a_disabled_profile_is_stopped_and_online_is_available() {
        let mut v = tm_json("Online");
        assert_eq!(TrafficManagerRow::from_json(&v, None).unwrap().state(), ResourceState::Available);
        v["properties"]["profileStatus"] = json!("Disabled");
        let r = TrafficManagerRow::from_json(&v, None).unwrap();
        assert_eq!((r.state(), r.state_label().as_str()), (ResourceState::Stopped, "disabled"));
    }

    #[test]
    fn monitor_and_section_labels() {
        let r = TrafficManagerRow::from_json(&tm_json("Online"), None).unwrap();
        assert!(r.monitor_rows().iter().any(|(k, v)| k == "Expected status codes" && v == "200-299"));
        let labels: Vec<&str> = TRAFFIC_MANAGER_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Routing", "Monitor", "Endpoints", "Access", "Activity", "Related", "Tags"]);
    }
}
