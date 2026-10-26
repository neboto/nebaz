//! The Edge service (issue #31): the internet-facing entry points.
//! Application Gateways (`Microsoft.Network/applicationGateways`), Azure
//! Front Door Standard / Premium profiles (`Microsoft.Cdn/profiles`, the
//! classic CDN SKUs filtered out) and the WAF policies of both
//! (`ApplicationGatewayWebApplicationFirewallPolicies` and
//! `FrontDoorWebApplicationFirewallPolicies`, one sub-tab with a type in
//! the summary). Three subscription-wide lists; its own tab rather than
//! more Network sub-tabs (SERVICES.md rule 26 says why).
//!
//! A gateway's whole configuration (frontends, listeners, rules, pools,
//! settings, probes) is embedded in its list body: no lazy calls. A Front
//! Door profile's is not: endpoints, routes, origin groups, origins,
//! custom domains and security policies are child lists, read together
//! once per profile on demand ([`fetch_afd_topology`]).
//!
//! **Backends are matched, never resolved.** A pool address or an origin
//! host is compared with what the warm lists already hold (a Container
//! App's FQDN or custom domain, an environment's default domain or static
//! IP, an App Service host name, a private endpoint's DNS records, a public
//! IP), so the line jumps when it matches; nothing is looked up in DNS
//! and no call is made ([`BackendTargets`]).
//!
//! **Secrets never.** A gateway certificate's `data` (the PFX) and
//! `password` can come back on a GET body; a WAF policy body embeds whole
//! gateways, certificates included; a custom domain carries its DCV token.
//! [`without_secrets`] strips them before a row keeps its JSON. Front Door
//! `secrets` are never listed: a custom domain names its secret's id only.
//! Backend health is a POST nebaz never sends.

use crate::azure::arm::ArmClient;
use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource, ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::app_service::SiteRow;
use crate::azure::services::container_apps::{ContainerAppRow, EnvironmentRow};
use crate::azure::services::network::NETWORK_API_VERSION;
use crate::azure::services::network_edge::{owner_of, PublicIpRow};
use crate::azure::services::network_private::PrivateEndpointRow;
use crate::azure::services::{arm_row, error_rows, finish_stream, json, overview_rows, related_lines, tag_rows, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::{Lazy, LazyMap};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Application gateways and their WAF policies are Network types: the
/// Network service's version.
pub const AGW_API_VERSION: &str = NETWORK_API_VERSION;
/// `Microsoft.Cdn` (azure-rest-api-specs, checked 2026-10-24): the newest
/// stable a live region is sure to serve. `2026-10-01` landed in the specs
/// two days earlier and is not pinned yet.
pub const CDN_API_VERSION: &str = "2026-07-01";
/// `FrontDoorWebApplicationFirewallPolicies`, its own spec (the classic
/// Front Door one); the newest stable, 2026-10-24.
pub const AFD_WAF_API_VERSION: &str = "2026-04-01";

const APP_GATEWAYS_PATH: &str = "/providers/Microsoft.Network/applicationGateways";
const AGW_WAF_PATH: &str = "/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies";
const AFD_WAF_PATH: &str = "/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies";
const PROFILES_PATH: &str = "/providers/Microsoft.Cdn/profiles";

/// The most endpoints and origin groups whose routes and origins one
/// topology read follows (one call each).
const TOPOLOGY_MAX_PARENTS: usize = 50;

crate::sections! {
    pub enum AppGatewayDetailSection,
    pub static APP_GATEWAY_SECTIONS = [
        Overview "Overview",
        Frontends "Frontends",
        Listeners "Listeners",
        Rules "Rules",
        Backends "Backends",
        Waf "WAF",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum WafPolicyDetailSection,
    pub static WAF_POLICY_SECTIONS = [
        Overview "Overview",
        Settings "Settings",
        ManagedRules "Managed rules",
        CustomRules "Custom rules",
        Associations "Associations",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum FrontDoorDetailSection,
    pub static FRONT_DOOR_SECTIONS = [
        Overview "Overview",
        Endpoints "Endpoints" => crate::app::App::trigger_afd_topology,
        Origins "Origins" => crate::app::App::trigger_afd_topology,
        Domains "Domains" => crate::app::App::trigger_afd_topology,
        Security "Security" => crate::app::App::trigger_afd_topology,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_afd_topology,
        Tags "Tags",
    ]
}

// ── Secrets out of the JSON ───────────────────────────────────────────

/// Fields that hold secret or bulk certificate material: a gateway
/// certificate's PFX (`data`) and its `password`, the certificate blobs
/// beside them, and a custom domain's DCV `validationToken`.
const SECRET_FIELDS: &[&str] = &["data", "password", "publicCertData", "validatedCertData", "validationToken"];

fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !SECRET_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(k)));
            map.values_mut().for_each(scrub);
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with every secret-shaped field removed, at any depth: what a
/// row parses and keeps for `e`, and what a lazy section renders from.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

// ── Small shared readers ──────────────────────────────────────────────

/// The item of a sub-resource collection an id points at, by its last
/// segment (`…/backendAddressPools/pool-1` → `pool-1`).
fn by_ref<'a>(items: &'a [Value], id: Option<&str>) -> Option<&'a Value> {
    let name = name_of_id(id?);
    items.iter().find(|v| json::str_at(v, "/name").is_some_and(|n| n.eq_ignore_ascii_case(name)))
}

/// The name an id points at, `-` without one.
fn ref_name(id: Option<&str>) -> String {
    id.map(|i| name_of_id(i).to_string()).unwrap_or_else(|| "-".into())
}

/// The top-level resource of an ARM id: `…/providers/{ns}/{type}/{name}`,
/// dropping any child segments.
pub fn top_level_of(id: &str) -> Option<String> {
    let lower = id.to_lowercase();
    let at = lower.find("/providers/")?;
    let rest = &id[at + "/providers/".len()..];
    let parts: Vec<&str> = rest.split('/').collect();
    (parts.len() >= 3).then(|| format!("{}/providers/{}/{}/{}", &id[..at], parts[0], parts[1], parts[2]))
}

/// `vnet/subnet` from a subnet id.
fn subnet_label(id: &str) -> String {
    let parts: Vec<&str> = id.trim_end_matches('/').split('/').collect();
    match parts.iter().rposition(|p| p.eq_ignore_ascii_case("subnets")) {
        Some(i) if i >= 2 && i + 1 < parts.len() => format!("{}/{}", parts[i - 1], parts[i + 1]),
        _ => name_of_id(id).to_string(),
    }
}

/// Values sorted by name.
fn sorted_by_name(items: &[Value]) -> Vec<Value> {
    let mut items = items.to_vec();
    items.sort_by_key(|v| json::text(v, "/name").to_lowercase());
    items
}

/// A string cut to `max` characters with `…`.
fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

fn push_unique(v: &mut Vec<(String, String)>, label: String, id: String) {
    if !v.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(&id)) {
        v.push((label, id));
    }
}

fn is_disabled(v: &Value, ptr: &str) -> bool {
    json::str_at(v, ptr).is_some_and(|s| s.eq_ignore_ascii_case("disabled"))
}

// ── Backend matching over the warm lists ──────────────────────────────

/// The warm lists a backend address is matched against. `None` is a list
/// not loaded this session (or past its TTL).
#[derive(Default, Clone, Copy)]
pub struct TargetLists<'a> {
    pub container_apps: Option<&'a [Box<dyn Resource>]>,
    pub environments: Option<&'a [Box<dyn Resource>]>,
    pub sites: Option<&'a [Box<dyn Resource>]>,
    pub private_endpoints: Option<&'a [Box<dyn Resource>]>,
    pub public_ips: Option<&'a [Box<dyn Resource>]>,
}

/// Host names and IPs the warm lists know, each to `(label, ARM id)`.
/// Built from rows already loaded: no DNS lookup, no call.
#[derive(Debug, Default, Clone)]
pub struct BackendTargets {
    hosts: HashMap<String, (String, String)>,
    ips: HashMap<String, (String, String)>,
    /// `.{default domain}` of each Container Apps environment.
    suffixes: Vec<(String, (String, String))>,
    /// Public IP id (lowercased) → its address.
    pip_addresses: HashMap<String, String>,
    /// The routing prefixes of the lists that were not warm.
    pub cold: Vec<&'static str>,
}

fn norm_host(s: &str) -> String {
    s.trim().trim_end_matches('.').to_lowercase()
}

impl BackendTargets {
    pub fn from_lists(l: TargetLists<'_>) -> BackendTargets {
        let mut t = BackendTargets::default();
        let rows = |list: Option<&'_ [Box<dyn Resource>]>| list.unwrap_or_default().to_vec();
        for (list, prefix) in [
            (l.container_apps, "@aca"),
            (l.environments, "@acaenv"),
            (l.sites, "@app"),
            (l.private_endpoints, "@pe"),
            (l.public_ips, "@pip"),
        ] {
            if list.is_none() {
                t.cold.push(prefix);
            }
        }
        for r in rows(l.container_apps) {
            if let Some(a) = r.as_any().downcast_ref::<ContainerAppRow>() {
                let target = (format!("Container App {}", a.base.name), a.base.id.clone());
                if let Some(i) = &a.ingress {
                    if let Some(f) = json::str_at(i, "/fqdn").filter(|f| !f.is_empty()) {
                        t.hosts.entry(norm_host(&f)).or_insert_with(|| target.clone());
                    }
                    for d in json::arr(i, "/customDomains") {
                        if let Some(n) = json::str_at(&d, "/name") {
                            t.hosts.entry(norm_host(&n)).or_insert_with(|| target.clone());
                        }
                    }
                }
            }
        }
        for r in rows(l.sites) {
            if let Some(s) = r.as_any().downcast_ref::<SiteRow>() {
                let target = (format!("App Service {}", s.base.name), s.base.id.clone());
                for h in s.default_host.iter().chain(s.hostnames.iter().map(|h| &h.name)) {
                    t.hosts.entry(norm_host(h)).or_insert_with(|| target.clone());
                }
            }
        }
        for r in rows(l.private_endpoints) {
            if let Some(pe) = r.as_any().downcast_ref::<PrivateEndpointRow>() {
                let fronts = pe.connections.iter().find_map(|c| c.target_id.as_deref()).map(|t| format!(" (→ {})", name_of_id(t)));
                let target = (format!("Private endpoint {}{}", pe.base.name, fronts.unwrap_or_default()), pe.base.id.clone());
                for (fqdn, ips) in &pe.dns_configs {
                    t.hosts.entry(norm_host(fqdn)).or_insert_with(|| target.clone());
                    for ip in ips {
                        t.ips.entry(ip.trim().to_string()).or_insert_with(|| target.clone());
                    }
                }
            }
        }
        for r in rows(l.environments) {
            if let Some(e) = r.as_any().downcast_ref::<EnvironmentRow>() {
                let target = (format!("Container Apps environment {}", e.base.name), e.base.id.clone());
                if let Some(ip) = e.static_ip.as_deref().filter(|s| !s.is_empty()) {
                    t.ips.entry(ip.trim().to_string()).or_insert_with(|| target.clone());
                }
                if let Some(d) = e.default_domain.as_deref().filter(|s| !s.is_empty()) {
                    t.hosts.entry(norm_host(d)).or_insert_with(|| target.clone());
                    t.suffixes.push((format!(".{}", norm_host(d)), target.clone()));
                }
            }
        }
        for r in rows(l.public_ips) {
            if let Some(p) = r.as_any().downcast_ref::<PublicIpRow>() {
                let target = (format!("Public IP {}", p.base.name), p.base.id.clone());
                if let Some(a) = p.address.as_deref().filter(|s| !s.is_empty()) {
                    t.ips.entry(a.to_string()).or_insert_with(|| target.clone());
                    t.pip_addresses.insert(p.base.id.to_lowercase(), a.to_string());
                }
                if let Some(f) = p.fqdn.as_deref().filter(|s| !s.is_empty()) {
                    t.hosts.entry(norm_host(f)).or_insert_with(|| target.clone());
                }
            }
        }
        // Longest suffix first, so a nested domain wins.
        t.suffixes.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        t
    }

    /// What a backend address (a host name or an IP) points at, when a
    /// warm list knows it: `(label, ARM id)`.
    pub fn resolve(&self, address: &str) -> Option<&(String, String)> {
        let a = norm_host(address);
        if a.is_empty() {
            return None;
        }
        if a.parse::<IpAddr>().is_ok() {
            return self.ips.get(&a);
        }
        self.hosts
            .get(&a)
            .or_else(|| self.suffixes.iter().find(|(s, _)| a.ends_with(s.as_str())).map(|(_, t)| t))
    }

    /// A public IP's address, from the warm Public IPs list.
    pub fn public_ip_address(&self, id: &str) -> Option<&str> {
        self.pip_addresses.get(&id.to_lowercase()).map(String::as_str)
    }

    /// The footer naming the lists matching could not read.
    fn cold_note(&self) -> Option<String> {
        (!self.cold.is_empty()).then(|| {
            format!(
                "· matched against the warm lists only; not loaded: {} (open them to match more)",
                self.cold.join(" ")
            )
        })
    }

    /// The section line for one backend address: jumps when it matches.
    fn address_line(&self, indent: &str, address: &str) -> (String, String) {
        match self.resolve(address) {
            Some((label, id)) => (format!("{}{} → {}", indent, address, label), id.clone()),
            None => (format!("{}{}", indent, address), "not matched in the warm lists".into()),
        }
    }
}

/// Whether a matched target routes by the request's host name (a
/// Container App or environment, an App Service): the front end must send
/// the backend's own host, or the platform answers 404.
fn routes_by_host(id: &str) -> bool {
    matches!(
        JumpView::for_arm_id(id),
        Some(JumpView::ContainerApps | JumpView::ContainerAppEnvironments | JumpView::WebApps)
    )
}

// ── Application gateway ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AppGatewayRow {
    pub base: ArmBase,
    pub sku_name: Option<String>,
    pub sku_tier: Option<String>,
    pub capacity: Option<i64>,
    /// Autoscale `(min, max)`.
    pub autoscale: Option<(Option<i64>, Option<i64>)>,
    pub operational_state: Option<String>,
    pub zones: Vec<String>,
    pub http2: Option<bool>,
    pub fips: Option<bool>,
    /// The gateway's own subnet(s) (`gatewayIPConfigurations`).
    pub subnet_ids: Vec<String>,
    pub firewall_policy_id: Option<String>,
    pub force_policy: Option<bool>,
    pub waf_config: Option<Value>,
    pub ssl_policy: Option<Value>,
    pub identity_type: Option<String>,
    pub identity_ids: Vec<String>,
    pub frontends: Vec<Value>,
    pub ports: Vec<Value>,
    /// HTTP listeners, then the layer-4 (TCP / TLS) listeners.
    pub listeners: Vec<Value>,
    pub certificates: Vec<Value>,
    pub trusted_roots: Vec<Value>,
    pub ssl_profiles: Vec<Value>,
    pub pools: Vec<Value>,
    /// HTTP settings, then the layer-4 backend settings.
    pub settings: Vec<Value>,
    pub probes: Vec<Value>,
    /// Request routing rules, then the layer-4 routing rules.
    pub rules: Vec<Value>,
    pub path_maps: Vec<Value>,
    pub redirects: Vec<Value>,
    pub private_links: Vec<Value>,
    pub private_endpoints: Vec<Value>,
}

impl AppGatewayRow {
    /// Parses a gateway with certificate material stripped first.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<AppGatewayRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let both = |a: &str, b: &str| {
            let mut items = json::arr(v, &p(a));
            items.extend(json::arr(v, &p(b)));
            items
        };
        let autoscale = v
            .pointer("/properties/autoscaleConfiguration")
            .filter(|a| a.is_object())
            .map(|a| (json::int_at(a, "/minCapacity"), json::int_at(a, "/maxCapacity")));
        Some(AppGatewayRow {
            sku_name: json::str_at(v, &p("sku/name")),
            sku_tier: json::str_at(v, &p("sku/tier")),
            capacity: json::int_at(v, &p("sku/capacity")),
            autoscale,
            operational_state: json::str_at(v, &p("operationalState")),
            zones: json::strings_at(v, "/zones"),
            http2: json::bool_at(v, &p("enableHttp2")),
            fips: json::bool_at(v, &p("enableFips")),
            subnet_ids: json::arr(v, &p("gatewayIPConfigurations"))
                .iter()
                .filter_map(|c| json::arm_id(json::id_at(c, "/properties/subnet")))
                .collect(),
            firewall_policy_id: json::arm_id(json::id_at(v, &p("firewallPolicy"))),
            force_policy: json::bool_at(v, &p("forceFirewallPolicyAssociation")),
            waf_config: v.pointer(&p("webApplicationFirewallConfiguration")).filter(|w| w.is_object()).cloned(),
            ssl_policy: v.pointer(&p("sslPolicy")).filter(|w| w.is_object()).cloned(),
            identity_type: json::str_at(v, "/identity/type"),
            identity_ids: json::user_identity_ids(v),
            frontends: json::arr(v, &p("frontendIPConfigurations")),
            ports: json::arr(v, &p("frontendPorts")),
            listeners: both("httpListeners", "listeners"),
            certificates: json::arr(v, &p("sslCertificates")),
            trusted_roots: json::arr(v, &p("trustedRootCertificates")),
            ssl_profiles: json::arr(v, &p("sslProfiles")),
            pools: json::arr(v, &p("backendAddressPools")),
            settings: both("backendHttpSettingsCollection", "backendSettingsCollection"),
            probes: json::arr(v, &p("probes")),
            rules: both("requestRoutingRules", "routingRules"),
            path_maps: json::arr(v, &p("urlPathMaps")),
            redirects: json::arr(v, &p("redirectConfigurations")),
            private_links: json::arr(v, &p("privateLinkConfigurations")),
            private_endpoints: json::arr(v, &p("privateEndpointConnections")),
            base,
        })
    }

    fn tier(&self) -> &str {
        self.sku_tier.as_deref().or(self.sku_name.as_deref()).unwrap_or("-")
    }

    fn is_v2(&self) -> bool {
        self.tier().to_lowercase().ends_with("_v2")
    }

    fn capacity_label(&self) -> String {
        match self.autoscale {
            Some((min, max)) => format!(
                "autoscale {}–{}",
                json::num(min),
                max.map(|m| m.to_string()).unwrap_or_else(|| "no cap".into())
            ),
            None => match self.capacity {
                Some(c) => format!("{} instances", c),
                None => "-".into(),
            },
        }
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.operational_state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "running" => ResourceState::Running,
                "stopped" => ResourceState::Stopped,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// The backend addresses of every pool: `(pool, address)`.
    pub fn backend_addresses(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for pool in &self.pools {
            let name = json::text(pool, "/name");
            for a in json::arr(pool, "/properties/backendAddresses") {
                if let Some(addr) = json::str_at(&a, "/fqdn").or_else(|| json::str_at(&a, "/ipAddress")).filter(|s| !s.is_empty()) {
                    out.push((name.clone(), addr));
                }
            }
        }
        out
    }

    /// The NICs behind the pools (their IP configurations' owners).
    fn backend_nics(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for pool in &self.pools {
            for c in json::ids_at(pool, "/properties/backendIPConfigurations") {
                if let Some(nic) = owner_of(&c) {
                    if !out.iter().any(|o| o.eq_ignore_ascii_case(&nic)) {
                        out.push(nic);
                    }
                }
            }
        }
        out
    }

    /// Every WAF policy the gateway, a listener or a path rule names.
    fn waf_policy_ids(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(p) = &self.firewall_policy_id {
            out.push(("gateway".to_string(), p.clone()));
        }
        for l in &self.listeners {
            if let Some(p) = json::arm_id(json::id_at(l, "/properties/firewallPolicy")) {
                out.push((format!("listener {}", json::text(l, "/name")), p));
            }
        }
        for m in &self.path_maps {
            for r in json::arr(m, "/properties/pathRules") {
                if let Some(p) = json::arm_id(json::id_at(&r, "/properties/firewallPolicy")) {
                    out.push((format!("path rule {}/{}", json::text(m, "/name"), json::text(&r, "/name")), p));
                }
            }
        }
        out
    }

    /// A frontend in one line: `public pip-agw` or `private 10.0.0.4`.
    fn frontend_label(&self, fe: Option<&Value>, targets: &BackendTargets) -> String {
        let Some(fe) = fe else { return "-".into() };
        match json::arm_id(json::id_at(fe, "/properties/publicIPAddress")) {
            Some(pip) => match targets.public_ip_address(&pip) {
                Some(a) => format!("public {} ({})", name_of_id(&pip), a),
                None => format!("public {}", name_of_id(&pip)),
            },
            None => format!("private {}", json::text(fe, "/properties/privateIPAddress")),
        }
    }

    fn port_of(&self, listener: &Value) -> String {
        by_ref(&self.ports, json::id_at(listener, "/properties/frontendPort").as_deref())
            .and_then(|p| json::int_at(p, "/properties/port"))
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into())
    }

    fn listener_hosts(listener: &Value) -> String {
        let mut hosts = json::strings_at(listener, "/properties/hostNames");
        if let Some(h) = json::str_at(listener, "/properties/hostName").filter(|h| !h.is_empty()) {
            hosts.insert(0, h);
        }
        if hosts.is_empty() {
            "any host (basic)".into()
        } else {
            hosts.join(", ")
        }
    }

    /// `HTTPS :443 on public pip-agw · api.contoso.com`.
    fn listener_summary(&self, l: &Value, targets: &BackendTargets) -> String {
        let fe = by_ref(&self.frontends, json::id_at(l, "/properties/frontendIPConfiguration").as_deref());
        format!(
            "{} :{} on {} · {}",
            json::text(l, "/properties/protocol"),
            self.port_of(l),
            self.frontend_label(fe, targets),
            Self::listener_hosts(l)
        )
    }

    fn pool_summary(pool: Option<&Value>) -> String {
        let Some(pool) = pool else { return "-".into() };
        let addrs: Vec<String> = json::arr(pool, "/properties/backendAddresses")
            .iter()
            .filter_map(|a| json::str_at(a, "/fqdn").or_else(|| json::str_at(a, "/ipAddress")))
            .collect();
        let nics = json::arr(pool, "/properties/backendIPConfigurations").len();
        match (addrs.len() + nics, addrs.is_empty()) {
            (0, _) => "⚠ empty: no targets".into(),
            (_, false) if nics == 0 => cut(&addrs.join(", "), 80),
            (n, _) => format!("{} targets", n),
        }
    }

    fn settings_summary(&self, s: Option<&Value>) -> String {
        let Some(s) = s else { return "-".into() };
        let host = if json::bool_at(s, "/properties/pickHostNameFromBackendAddress") == Some(true) {
            "host from the backend address".to_string()
        } else if let Some(h) = json::str_at(s, "/properties/hostName").filter(|h| !h.is_empty()) {
            format!("host {}", h)
        } else {
            "the request's host".to_string()
        };
        let probe = json::id_at(s, "/properties/probe").map(|p| format!(" · probe {}", name_of_id(&p))).unwrap_or_default();
        format!("{} :{} · {}{}", json::text(s, "/properties/protocol"), json::text(s, "/properties/port"), host, probe)
    }

    /// The ⚠ for a pool that routes by host behind settings that send the
    /// client's host name unchanged.
    fn host_warning(&self, pool: Option<&Value>, settings: Option<&Value>, targets: &BackendTargets) -> Option<String> {
        let (pool, s) = (pool?, settings?);
        let keeps_host = json::bool_at(s, "/properties/pickHostNameFromBackendAddress") != Some(true)
            && json::str_at(s, "/properties/hostName").is_none_or(|h| h.is_empty());
        if !keeps_host {
            return None;
        }
        let routed = json::arr(pool, "/properties/backendAddresses").iter().any(|a| {
            json::str_at(a, "/fqdn")
                .and_then(|f| targets.resolve(&f).map(|(_, id)| routes_by_host(id)))
                .unwrap_or(false)
        });
        routed.then(|| {
            "⚠ the pool is a Container App or App Service, which routes by host: pick the host name from the backend address or override it".to_string()
        })
    }

    pub fn frontend_rows(&self, targets: &BackendTargets) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.frontends.is_empty() {
            lines.push((String::new(), "No frontend IP configurations".into()));
        }
        for fe in &self.frontends {
            let name = json::text(fe, "/name");
            match json::arm_id(json::id_at(fe, "/properties/publicIPAddress")) {
                Some(pip) => {
                    lines.push((name, "public".into()));
                    lines.push((format!("  Public IP · {}", name_of_id(&pip)), pip.clone()));
                    lines.push((
                        "    Address".into(),
                        targets
                            .public_ip_address(&pip)
                            .map(str::to_string)
                            .unwrap_or_else(|| "- (open @pip to see the address)".into()),
                    ));
                }
                None => {
                    lines.push((
                        name,
                        format!(
                            "private {} · {}",
                            json::text(fe, "/properties/privateIPAddress"),
                            json::text(fe, "/properties/privateIPAllocationMethod").to_lowercase()
                        ),
                    ));
                    if let Some(s) = json::arm_id(json::id_at(fe, "/properties/subnet")) {
                        lines.push((format!("  Subnet · {}", subnet_label(&s)), s));
                    }
                }
            }
            if let Some(pl) = json::id_at(fe, "/properties/privateLinkConfiguration") {
                lines.push(("  Private link".into(), name_of_id(&pl).to_string()));
            }
            let used: Vec<String> = self
                .listeners
                .iter()
                .filter(|l| {
                    json::id_at(l, "/properties/frontendIPConfiguration")
                        .is_some_and(|f| name_of_id(&f).eq_ignore_ascii_case(&json::text(fe, "/name")))
                })
                .map(|l| format!("{} :{}", json::text(l, "/name"), self.port_of(l)))
                .collect();
            lines.push(("  Listeners".into(), json::join(&used)));
        }

        lines.push((String::new(), String::new()));
        lines.push(("Gateway subnet".into(), if self.subnet_ids.is_empty() { "-".into() } else { String::new() }));
        for s in &self.subnet_ids {
            lines.push((format!("  Subnet · {}", subnet_label(s)), s.clone()));
        }
        lines.push((
            String::new(),
            if self.is_v2() {
                "· its NSG must allow GatewayManager in on 65200–65535 and the AzureLoadBalancer tag (N shows the rules)".into()
            } else {
                "· its NSG must allow GatewayManager in on 65503–65534 (v1) and the AzureLoadBalancer tag (N shows the rules)".into()
            },
        ));
        lines.push((String::new(), "· the subnet holds only application gateways; a UDR to a firewall breaks v2 management traffic".into()));

        if !self.private_links.is_empty() || !self.private_endpoints.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("Private link".into(), format!("{} configurations", self.private_links.len())));
            for pl in &self.private_links {
                for c in json::arr(pl, "/properties/ipConfigurations") {
                    if let Some(s) = json::arm_id(json::id_at(&c, "/properties/subnet")) {
                        lines.push((format!("  {} · {}", json::text(pl, "/name"), subnet_label(&s)), s));
                    }
                }
            }
            for c in &self.private_endpoints {
                let status = json::text(c, "/properties/privateLinkServiceConnectionState/status");
                match json::arm_id(json::id_at(c, "/properties/privateEndpoint")) {
                    Some(pe) => lines.push((format!("  Private endpoint · {} · {}", name_of_id(&pe), status), pe)),
                    None => lines.push(("  Private endpoint".into(), status)),
                }
            }
        }
        lines
    }

    pub fn listener_rows(&self, targets: &BackendTargets) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if let Some(p) = &self.ssl_policy {
            let policy = json::str_at(p, "/policyName")
                .or_else(|| json::str_at(p, "/policyType"))
                .unwrap_or_else(|| "-".into());
            lines.push(("TLS policy".into(), format!("{} · min {}", policy, json::text(p, "/minProtocolVersion"))));
        }
        if self.listeners.is_empty() {
            lines.push((String::new(), "No listeners".into()));
        }
        for l in &self.listeners {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push((json::text(l, "/name"), self.listener_summary(l, targets)));
            if let Some(cert) = json::id_at(l, "/properties/sslCertificate") {
                let c = by_ref(&self.certificates, Some(&cert));
                let source = c
                    .and_then(|c| json::str_at(c, "/properties/keyVaultSecretId"))
                    .map(|k| format!("Key Vault {}", k))
                    .unwrap_or_else(|| "uploaded to the gateway (the PFX is never shown)".into());
                lines.push((format!("  Certificate · {}", name_of_id(&cert)), source));
            }
            if json::bool_at(l, "/properties/requireServerNameIndication") == Some(true) {
                lines.push(("  SNI".into(), "required".into()));
            }
            if let Some(sp) = json::id_at(l, "/properties/sslProfile") {
                lines.push(("  TLS profile".into(), name_of_id(&sp).to_string()));
            }
            if let Some(p) = json::arm_id(json::id_at(l, "/properties/firewallPolicy")) {
                lines.push((format!("  WAF policy · {}", name_of_id(&p)), p));
            }
            let rules: Vec<String> = self
                .rules
                .iter()
                .filter(|r| {
                    json::id_at(r, "/properties/httpListener")
                        .or_else(|| json::id_at(r, "/properties/listener"))
                        .is_some_and(|i| name_of_id(&i).eq_ignore_ascii_case(&json::text(l, "/name")))
                })
                .map(|r| json::text(r, "/name"))
                .collect();
            lines.push((
                "  Routed by".into(),
                if rules.is_empty() { "⚠ no rule uses this listener".into() } else { rules.join(", ") },
            ));
        }
        if !self.certificates.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("Certificates".into(), format!("{} (names and Key Vault ids only)", self.certificates.len())));
            for c in &self.certificates {
                lines.push((
                    format!("  {}", json::text(c, "/name")),
                    json::str_at(c, "/properties/keyVaultSecretId").unwrap_or_else(|| "uploaded PFX".into()),
                ));
            }
        }
        if !self.ssl_profiles.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("TLS profiles".into(), self.ssl_profiles.len().to_string()));
            for sp in &self.ssl_profiles {
                let client_certs = json::arr(sp, "/properties/trustedClientCertificates").len();
                lines.push((
                    format!("  {}", json::text(sp, "/name")),
                    format!(
                        "{} · min {}{}",
                        json::str_at(sp, "/properties/sslPolicy/policyName")
                            .or_else(|| json::str_at(sp, "/properties/sslPolicy/policyType"))
                            .unwrap_or_else(|| "-".into()),
                        json::text(sp, "/properties/sslPolicy/minProtocolVersion"),
                        if client_certs > 0 { format!(" · mutual TLS ({} client CAs)", client_certs) } else { String::new() }
                    ),
                ));
            }
        }
        lines
    }

    /// The Rules section: every rule as the chain a request follows,
    /// listener → (path map →) pool via settings, by priority.
    pub fn rule_rows(&self, targets: &BackendTargets) -> Vec<(String, String)> {
        let mut rules = self.rules.clone();
        rules.sort_by_key(|r| (json::int_at(r, "/properties/priority").unwrap_or(i64::MAX), json::text(r, "/name")));
        let mut lines = Vec::new();
        if rules.is_empty() {
            lines.push((String::new(), "No routing rules".into()));
        }
        for r in &rules {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            let prio = json::int_at(r, "/properties/priority").map(|p| format!("{} · ", p)).unwrap_or_default();
            let listener_id = json::id_at(r, "/properties/httpListener").or_else(|| json::id_at(r, "/properties/listener"));
            let listener = by_ref(&self.listeners, listener_id.as_deref());
            let kind = json::text(r, "/properties/ruleType");
            lines.push((format!("{}{}", prio, json::text(r, "/name")), kind));
            lines.push((
                format!("  Listener · {}", ref_name(listener_id.as_deref())),
                listener.map(|l| self.listener_summary(l, targets)).unwrap_or_else(|| "-".into()),
            ));
            if let Some(redirect) = json::id_at(r, "/properties/redirectConfiguration") {
                lines.push(("  → Redirect".into(), self.redirect_summary(by_ref(&self.redirects, Some(&redirect)))));
                continue;
            }
            if let Some(map_id) = json::id_at(r, "/properties/urlPathMap") {
                let map = by_ref(&self.path_maps, Some(&map_id));
                lines.push((format!("  → Path map · {}", name_of_id(&map_id)), String::new()));
                if let Some(map) = map {
                    for pr in json::arr(map, "/properties/pathRules") {
                        let paths = json::strings_at(&pr, "/properties/paths").join(", ");
                        self.push_target(&mut lines, &format!("    {}", paths), &pr, targets);
                    }
                    self.push_target_with(
                        &mut lines,
                        "    (default)",
                        json::id_at(map, "/properties/defaultBackendAddressPool"),
                        json::id_at(map, "/properties/defaultBackendHttpSettings"),
                        json::id_at(map, "/properties/defaultRedirectConfiguration"),
                        targets,
                    );
                }
            } else {
                self.push_target(&mut lines, "  →", r, targets);
            }
            if let Some(rw) = json::id_at(r, "/properties/rewriteRuleSet") {
                lines.push(("  Rewrites".into(), name_of_id(&rw).to_string()));
            }
        }
        lines
    }

    fn redirect_summary(&self, redirect: Option<&Value>) -> String {
        let Some(rd) = redirect else { return "-".into() };
        let to = json::id_at(rd, "/properties/targetListener")
            .map(|l| format!("listener {}", name_of_id(&l)))
            .or_else(|| json::str_at(rd, "/properties/targetUrl"))
            .unwrap_or_else(|| "-".into());
        format!("{} to {}", json::text(rd, "/properties/redirectType"), to)
    }

    /// `label → pool via settings` for a rule or path rule.
    fn push_target(&self, lines: &mut Vec<(String, String)>, label: &str, r: &Value, targets: &BackendTargets) {
        self.push_target_with(
            lines,
            label,
            json::id_at(r, "/properties/backendAddressPool"),
            json::id_at(r, "/properties/backendHttpSettings").or_else(|| json::id_at(r, "/properties/backendSettings")),
            json::id_at(r, "/properties/redirectConfiguration"),
            targets,
        );
    }

    fn push_target_with(
        &self,
        lines: &mut Vec<(String, String)>,
        label: &str,
        pool_id: Option<String>,
        settings_id: Option<String>,
        redirect_id: Option<String>,
        targets: &BackendTargets,
    ) {
        if let Some(rd) = redirect_id {
            lines.push((format!("{} redirect", label), self.redirect_summary(by_ref(&self.redirects, Some(&rd)))));
            return;
        }
        if pool_id.is_none() && settings_id.is_none() {
            return;
        }
        let pool = by_ref(&self.pools, pool_id.as_deref());
        let settings = by_ref(&self.settings, settings_id.as_deref());
        lines.push((
            format!("{} pool {}", label, ref_name(pool_id.as_deref())),
            format!("{} · via {}", Self::pool_summary(pool), ref_name(settings_id.as_deref())),
        ));
        lines.push(("      Settings".into(), self.settings_summary(settings)));
        // A pool with one matched target jumps from the chain too.
        let matched: Vec<&(String, String)> = pool
            .map(|p| json::arr(p, "/properties/backendAddresses"))
            .unwrap_or_default()
            .iter()
            .filter_map(|a| json::str_at(a, "/fqdn").or_else(|| json::str_at(a, "/ipAddress")))
            .filter_map(|a| targets.resolve(&a))
            .collect();
        for (l, id) in matched {
            lines.push((format!("      → {}", l), id.clone()));
        }
        if let Some(w) = self.host_warning(pool, settings, targets) {
            lines.push((String::new(), format!("      {}", w)));
        }
    }

    pub fn backend_rows(&self, targets: &BackendTargets) -> Vec<(String, String)> {
        let mut lines = vec![("Pools".into(), self.pools.len().to_string())];
        for pool in sorted_by_name(&self.pools) {
            let name = json::text(&pool, "/name");
            let addrs = json::arr(&pool, "/properties/backendAddresses");
            let ipcs = json::ids_at(&pool, "/properties/backendIPConfigurations");
            lines.push((String::new(), String::new()));
            lines.push((
                name.clone(),
                if addrs.is_empty() && ipcs.is_empty() { "⚠ empty: no targets".into() } else { format!("{} targets", addrs.len() + ipcs.len()) },
            ));
            for a in &addrs {
                if let Some(addr) = json::str_at(a, "/fqdn").or_else(|| json::str_at(a, "/ipAddress")).filter(|s| !s.is_empty()) {
                    lines.push(targets.address_line("  ", &addr));
                }
            }
            for c in &ipcs {
                if let Some(nic) = owner_of(c) {
                    lines.push((format!("  NIC · {} ({})", name_of_id(&nic), name_of_id(c)), nic));
                }
            }
            let used: Vec<String> = self
                .rules
                .iter()
                .filter(|r| json::id_at(r, "/properties/backendAddressPool").is_some_and(|p| name_of_id(&p).eq_ignore_ascii_case(&name)))
                .map(|r| json::text(r, "/name"))
                .chain(self.path_maps.iter().flat_map(|m| {
                    json::arr(m, "/properties/pathRules")
                        .into_iter()
                        .filter(|r| json::id_at(r, "/properties/backendAddressPool").is_some_and(|p| name_of_id(&p).eq_ignore_ascii_case(&name)))
                        .map(|r| format!("{}/{}", json::text(m, "/name"), json::text(&r, "/name")))
                        .collect::<Vec<_>>()
                }))
                .collect();
            lines.push(("  Used by".into(), json::join(&used)));
        }
        if let Some(note) = targets.cold_note() {
            lines.push((String::new(), note));
        }

        lines.push((String::new(), String::new()));
        lines.push(("Settings".into(), self.settings.len().to_string()));
        for s in sorted_by_name(&self.settings) {
            let p = |k: &str| format!("/properties/{}", k);
            lines.push((
                format!("  {}", json::text(&s, "/name")),
                format!(
                    "{} :{} · timeout {}s",
                    json::text(&s, &p("protocol")),
                    json::text(&s, &p("port")),
                    json::str_at(&s, &p("requestTimeout")).or_else(|| json::str_at(&s, &p("timeout"))).unwrap_or_else(|| "-".into())
                ),
            ));
            let host = if json::bool_at(&s, &p("pickHostNameFromBackendAddress")) == Some(true) {
                "picked from the backend address".to_string()
            } else {
                json::str_at(&s, &p("hostName"))
                    .filter(|h| !h.is_empty())
                    .map(|h| format!("override {}", h))
                    .unwrap_or_else(|| "the request's host, unchanged".into())
            };
            lines.push(("    Host name".into(), host));
            if let Some(path) = json::str_at(&s, &p("path")).filter(|x| !x.is_empty()) {
                lines.push(("    Path override".into(), path));
            }
            if let Some(a) = json::str_at(&s, &p("cookieBasedAffinity")) {
                lines.push(("    Cookie affinity".into(), a));
            }
            lines.push((
                "    Probe".into(),
                json::id_at(&s, &p("probe")).map(|i| name_of_id(&i).to_string()).unwrap_or_else(|| "default probe".into()),
            ));
            let roots: Vec<String> = json::ids_at(&s, &p("trustedRootCertificates")).iter().map(|i| name_of_id(i).to_string()).collect();
            if !roots.is_empty() {
                lines.push(("    Trusted roots".into(), roots.join(", ")));
            }
            if json::bool_at(&s, &p("connectionDraining/enabled")) == Some(true) {
                lines.push(("    Connection draining".into(), format!("{}s", json::text(&s, &p("connectionDraining/drainTimeoutInSec")))));
            }
        }

        if !self.trusted_roots.is_empty() {
            lines.push((
                "  Trusted root certificates".into(),
                self.trusted_roots
                    .iter()
                    .map(|c| match json::str_at(c, "/properties/keyVaultSecretId") {
                        Some(k) => format!("{} (Key Vault {})", json::text(c, "/name"), k),
                        None => json::text(c, "/name"),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }

        lines.push((String::new(), String::new()));
        lines.push(("Probes".into(), if self.probes.is_empty() { "none (each setting uses the default probe)".into() } else { self.probes.len().to_string() }));
        for pr in sorted_by_name(&self.probes) {
            let p = |k: &str| format!("/properties/{}", k);
            let host = if json::bool_at(&pr, &p("pickHostNameFromBackendHttpSettings")) == Some(true)
                || json::bool_at(&pr, &p("pickHostNameFromBackendSettings")) == Some(true)
            {
                "{host from the settings}".to_string()
            } else {
                json::text(&pr, &p("host"))
            };
            lines.push((
                format!("  {}", json::text(&pr, "/name")),
                format!(
                    "{} {}{} · every {}s, timeout {}s, unhealthy after {}",
                    json::text(&pr, &p("protocol")),
                    host,
                    json::str_at(&pr, &p("path")).unwrap_or_default(),
                    json::text(&pr, &p("interval")),
                    json::text(&pr, &p("timeout")),
                    json::text(&pr, &p("unhealthyThreshold"))
                ),
            ));
            let codes = json::strings_at(&pr, &p("match/statusCodes"));
            if !codes.is_empty() {
                lines.push(("    Healthy when".into(), codes.join(", ")));
            }
        }
        lines.push((String::new(), String::new()));
        lines.push((
            String::new(),
            "· backend health is a POST nebaz never sends; C copies the show-backend-health command to run yourself".into(),
        ));
        lines
    }

    pub fn waf_rows(&self, policies: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        let ids = self.waf_policy_ids();
        if ids.is_empty() {
            lines.push((
                "Policy".into(),
                if self.waf_config.is_some() { "none (the classic WAF configuration below)".into() } else { "⚠ none: no WAF in front of this gateway".into() },
            ));
        }
        for (scope, id) in &ids {
            lines.push((format!("Policy ({}) · {}", scope, name_of_id(id)), id.clone()));
            let found = policies.unwrap_or_default().iter().find_map(|r| {
                r.as_any().downcast_ref::<WafPolicyRow>().filter(|w| w.base.id.eq_ignore_ascii_case(id))
            });
            match found {
                Some(w) => {
                    lines.push(("  Mode".into(), w.mode_label()));
                    lines.push(("  Managed rules".into(), w.managed_summary()));
                    lines.push(("  Custom rules".into(), w.custom_rules.len().to_string()));
                }
                None if policies.is_none() => lines.push((String::new(), "  · open @waf to see its mode and rules".into())),
                None => lines.push((String::new(), "  · not in this subscription's WAF policies list".into())),
            }
        }
        if !self.tier().to_lowercase().starts_with("waf") && !ids.is_empty() {
            lines.push((String::new(), format!("⚠ the {} tier runs no WAF: a policy needs WAF_v2", self.tier())));
        }
        if let Some(w) = &self.waf_config {
            lines.push((String::new(), String::new()));
            lines.push((
                "Classic WAF configuration".into(),
                format!(
                    "{} · {} · {} {}",
                    if json::bool_at(w, "/enabled") == Some(true) { "enabled" } else { "disabled" },
                    json::text(w, "/firewallMode"),
                    json::text(w, "/ruleSetType"),
                    json::text(w, "/ruleSetVersion")
                ),
            ));
        }
        lines.push(("Force policy association".into(), json::yes_no(self.force_policy)));
        lines
    }

    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for s in &self.subnet_ids {
            push_unique(&mut v, format!("Gateway subnet {}", subnet_label(s)), s.clone());
        }
        for fe in &self.frontends {
            if let Some(pip) = json::arm_id(json::id_at(fe, "/properties/publicIPAddress")) {
                push_unique(&mut v, format!("Public IP {}", name_of_id(&pip)), pip);
            }
            if let Some(s) = json::arm_id(json::id_at(fe, "/properties/subnet")) {
                push_unique(&mut v, format!("Frontend subnet {}", subnet_label(&s)), s);
            }
        }
        for (scope, p) in self.waf_policy_ids() {
            push_unique(&mut v, format!("WAF policy {} ({})", name_of_id(&p), scope), p);
        }
        for nic in self.backend_nics() {
            push_unique(&mut v, format!("Backend NIC {}", name_of_id(&nic)), nic);
        }
        for c in &self.private_endpoints {
            if let Some(pe) = json::arm_id(json::id_at(c, "/properties/privateEndpoint")) {
                push_unique(&mut v, format!("Private endpoint {}", name_of_id(&pe)), pe);
            }
        }
        for i in &self.identity_ids {
            push_unique(&mut v, format!("Identity {}", name_of_id(i)), i.clone());
        }
        v
    }

    /// The links only the warm lists can make: each matched backend.
    pub fn matched_links(&self, targets: &BackendTargets) -> Vec<(String, String)> {
        let mut v = Vec::new();
        for (pool, addr) in self.backend_addresses() {
            if let Some((label, id)) = targets.resolve(&addr) {
                push_unique(&mut v, format!("Backend {} ({}: {})", label, pool, addr), id.clone());
            }
        }
        v
    }
}

impl Resource for AppGatewayRow {
    arm_row!("Application gateway");
    /// `WAF_v2 · autoscale 2–10`.
    fn list_summary(&self) -> Option<String> {
        Some(format!("{} · {}", self.tier(), self.capacity_label()))
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&APP_GATEWAY_SECTIONS)
    }
    /// Listener host names, frontend private IPs and backend addresses are
    /// searchable: `@*` with a host finds the gateway that serves it.
    fn search_text(&self) -> String {
        let mut parts = vec![
            self.base.id.clone(),
            self.base.name.clone(),
            self.resource_group().unwrap_or("").to_string(),
            self.tier().to_string(),
        ];
        for l in &self.listeners {
            parts.push(Self::listener_hosts(l));
        }
        for fe in &self.frontends {
            parts.extend(json::str_at(fe, "/properties/privateIPAddress"));
        }
        parts.extend(self.backend_addresses().into_iter().map(|(_, a)| a));
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        let sku = match (&self.sku_name, &self.sku_tier) {
            (Some(n), Some(t)) if n != t => format!("{} · {}", n, t),
            _ => self.tier().to_string(),
        };
        let publics = self.frontends.iter().filter(|f| json::id_at(f, "/properties/publicIPAddress").is_some()).count();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Operational state".into(), json::opt(self.operational_state.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), sku),
            ("Capacity".into(), self.capacity_label()),
            ("Zones".into(), json::join(&self.zones)),
            ("HTTP/2".into(), json::yes_no(self.http2)),
            ("FIPS".into(), json::yes_no(self.fips)),
            (
                "Frontends".into(),
                format!("{} public · {} private", publics, self.frontends.len() - publics),
            ),
            ("Listeners".into(), self.listeners.len().to_string()),
            ("Rules".into(), self.rules.len().to_string()),
            ("Backend pools".into(), self.pools.len().to_string()),
            (
                "WAF policy".into(),
                self.firewall_policy_id.as_deref().map(|p| name_of_id(p).to_string()).unwrap_or_else(|| "-".into()),
            ),
            ("Identity".into(), json::opt(self.identity_type.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        AppGatewayRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network application-gateway show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn app_gateway_section_lines(
    r: &AppGatewayRow,
    section: AppGatewayDetailSection,
    targets: &BackendTargets,
    waf_policies: Option<&[Box<dyn Resource>]>,
) -> Vec<(String, String)> {
    match section {
        AppGatewayDetailSection::Overview => overview_rows(r),
        AppGatewayDetailSection::Frontends => r.frontend_rows(targets),
        AppGatewayDetailSection::Listeners => r.listener_rows(targets),
        AppGatewayDetailSection::Rules => r.rule_rows(targets),
        AppGatewayDetailSection::Backends => r.backend_rows(targets),
        AppGatewayDetailSection::Waf => r.waf_rows(waf_policies),
        AppGatewayDetailSection::Access => crate::azure::services::rendered_by_app(),
        AppGatewayDetailSection::Activity => crate::azure::services::rendered_by_app(),
        AppGatewayDetailSection::Related => {
            let mut rel = r.related();
            for (label, id) in r.matched_links(targets) {
                push_unique(&mut rel, label, id);
            }
            related_lines(rel)
        }
        AppGatewayDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── WAF policy (Application Gateway or Front Door) ────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafKind {
    AppGateway,
    FrontDoor,
}

#[derive(Debug, Clone)]
pub struct WafPolicyRow {
    pub base: ArmBase,
    pub kind: WafKind,
    /// Front Door only: `Standard_AzureFrontDoor`, `Premium_AzureFrontDoor`,
    /// `Classic_AzureFrontDoor`.
    pub sku: Option<String>,
    pub enabled: Option<bool>,
    pub mode: Option<String>,
    pub resource_state: Option<String>,
    pub settings: Value,
    pub managed_sets: Vec<Value>,
    pub custom_rules: Vec<Value>,
    pub exclusions: usize,
    /// Every gateway, listener, path rule, profile security policy or
    /// classic endpoint the policy is attached to.
    pub associations: Vec<String>,
}

impl WafPolicyRow {
    /// Parses either kind, by its ARM type; the embedded gateways'
    /// certificate material is stripped first.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<WafPolicyRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let kind = if base.id.to_lowercase().contains("/frontdoorwebapplicationfirewallpolicies/") {
            WafKind::FrontDoor
        } else {
            WafKind::AppGateway
        };
        let p = |k: &str| format!("/properties/{}", k);
        let (enabled_ptr, custom_ptr, links): (&str, &str, &[&str]) = match kind {
            WafKind::AppGateway => (
                "policySettings/state",
                "customRules",
                &["applicationGateways", "httpListeners", "pathBasedRules", "applicationGatewayForContainers"],
            ),
            WafKind::FrontDoor => (
                "policySettings/enabledState",
                "customRules/rules",
                &["frontendEndpointLinks", "routingRuleLinks", "securityPolicyLinks"],
            ),
        };
        let exclusions = json::arr(v, &p("managedRules/exclusions")).len()
            + json::arr(v, &p("managedRules/exceptions")).len()
            + json::arr(v, &p("managedRules/exceptionsList/exceptions")).len();
        Some(WafPolicyRow {
            kind,
            sku: json::str_at(v, "/sku/name"),
            enabled: json::str_at(v, &p(enabled_ptr)).map(|s| s.eq_ignore_ascii_case("enabled")),
            mode: json::str_at(v, &p("policySettings/mode")),
            resource_state: json::str_at(v, &p("resourceState")),
            settings: v.pointer(&p("policySettings")).cloned().unwrap_or(Value::Null),
            managed_sets: json::arr(v, &p("managedRules/managedRuleSets")),
            custom_rules: json::arr(v, &p(custom_ptr)),
            exclusions,
            associations: links.iter().flat_map(|l| json::ids_at(v, &p(l))).collect(),
            base,
        })
    }

    fn kind_label(&self) -> String {
        match self.kind {
            WafKind::AppGateway => "App Gateway".into(),
            WafKind::FrontDoor => match self.sku.as_deref().map(str::to_lowercase).as_deref() {
                Some(s) if s.starts_with("premium") => "Front Door Premium".into(),
                Some(s) if s.starts_with("standard") => "Front Door Standard".into(),
                Some(s) if s.starts_with("classic") => "Front Door classic".into(),
                _ => "Front Door".into(),
            },
        }
    }

    /// `Prevention`, `Detection`, or `off` when the policy is disabled.
    pub fn mode_label(&self) -> String {
        match self.enabled {
            Some(false) => format!("off (disabled; mode {})", json::opt(self.mode.clone())),
            _ => json::opt(self.mode.clone()),
        }
    }

    pub fn managed_summary(&self) -> String {
        let sets: Vec<String> = self
            .managed_sets
            .iter()
            .map(|s| format!("{} {}", json::text(s, "/ruleSetType"), json::text(s, "/ruleSetVersion")))
            .collect();
        if sets.is_empty() {
            "none".into()
        } else {
            sets.join(", ")
        }
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = match self.resource_state.as_deref() {
            Some(s) => Some((
                match s.to_lowercase().as_str() {
                    "enabled" => ResourceState::Available,
                    "disabled" => ResourceState::Stopped,
                    "creating" => ResourceState::Creating,
                    "deleting" => ResourceState::Deleting,
                    _ => ResourceState::Pending,
                },
                s,
            )),
            None => match self.enabled {
                Some(true) => Some((ResourceState::Available, "enabled")),
                Some(false) => Some((ResourceState::Stopped, "disabled")),
                None => None,
            },
        };
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// One association as `(label, the id Enter jumps to)`: a child
    /// (listener, path rule, security policy) jumps to its top resource.
    fn association(id: &str) -> (String, String) {
        let lower = id.to_lowercase();
        let top = top_level_of(id).unwrap_or_else(|| id.to_string());
        let parent = name_of_id(&top).to_string();
        let child = || {
            let tail = &id[top.len().min(id.len())..];
            tail.trim_start_matches('/').split_once('/').map(|(_, rest)| rest).unwrap_or("").replace('/', " ")
        };
        let label = if lower.contains("/httplisteners/") {
            format!("Listener {}/{}", parent, name_of_id(id))
        } else if lower.contains("/pathrules/") {
            format!("Path rule {} · {}", parent, child())
        } else if lower.contains("/microsoft.cdn/profiles/") {
            format!("Front Door {} · security policy {}", parent, name_of_id(id))
        } else if lower.contains("/microsoft.network/frontdoors/") {
            format!("Classic Front Door {} · {}", parent, name_of_id(id))
        } else if lower.contains("/applicationgateways/") {
            format!("Application gateway {}", parent)
        } else if lower.contains("/trafficcontrollers/") {
            format!("App Gateway for Containers {}", parent)
        } else {
            name_of_id(id).to_string()
        };
        (label, top)
    }

    pub fn settings_rows(&self) -> Vec<(String, String)> {
        let s = &self.settings;
        let mut lines = vec![
            ("Kind".into(), self.kind_label()),
            ("State".into(), match self.enabled {
                Some(true) => "enabled".into(),
                Some(false) => "⚠ disabled: nothing is inspected".into(),
                None => "-".into(),
            }),
            ("Mode".into(), match self.mode.as_deref() {
                Some(m) if m.eq_ignore_ascii_case("detection") => "Detection · logs matches, blocks nothing".into(),
                Some(m) if m.eq_ignore_ascii_case("prevention") => "Prevention · blocks matches".into(),
                other => json::opt(other.map(str::to_string)),
            }),
        ];
        match self.kind {
            WafKind::AppGateway => {
                lines.push(("Request body inspection".into(), json::yes_no(json::bool_at(s, "/requestBodyCheck"))));
                lines.push(("  Enforce body limit".into(), json::yes_no(json::bool_at(s, "/requestBodyEnforcement"))));
                lines.push(("  Max body".into(), json::str_at(s, "/maxRequestBodySizeInKb").map(|k| format!("{} KB", k)).unwrap_or_else(|| "-".into())));
                lines.push(("  Inspect limit".into(), json::str_at(s, "/requestBodyInspectLimitInKB").map(|k| format!("{} KB", k)).unwrap_or_else(|| "-".into())));
                lines.push(("File upload limit".into(), json::str_at(s, "/fileUploadLimitInMb").map(|k| format!("{} MB", k)).unwrap_or_else(|| "-".into())));
            }
            WafKind::FrontDoor => {
                lines.push(("Request body inspection".into(), json::text(s, "/requestBodyCheck")));
                if let Some(u) = json::str_at(s, "/redirectUrl").filter(|u| !u.is_empty()) {
                    lines.push(("Redirect URL".into(), u));
                }
            }
        }
        if let Some(code) = json::str_at(s, "/customBlockResponseStatusCode") {
            lines.push(("Block response".into(), format!("HTTP {}", code)));
        }
        lines.push(("Log scrubbing".into(), json::text(s, "/logScrubbing/state")));
        lines
    }

    pub fn managed_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.managed_sets.is_empty() {
            lines.push((String::new(), "⚠ no managed rule set: only the custom rules apply".into()));
        }
        for set in &self.managed_sets {
            let overrides = json::arr(set, "/ruleGroupOverrides");
            let action = json::str_at(set, "/ruleSetAction").map(|a| format!(" · action {}", a)).unwrap_or_default();
            lines.push((
                format!("{} {}", json::text(set, "/ruleSetType"), json::text(set, "/ruleSetVersion")),
                format!("{} group overrides{}", overrides.len(), action),
            ));
            for g in &overrides {
                let rules: Vec<String> = json::arr(g, "/rules")
                    .iter()
                    .map(|r| {
                        let state = json::str_at(r, "/state").or_else(|| json::str_at(r, "/enabledState")).unwrap_or_default();
                        let act = json::str_at(r, "/action").unwrap_or_default();
                        let what = [state, act].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
                        if what.is_empty() { json::text(r, "/ruleId") } else { format!("{} ({})", json::text(r, "/ruleId"), what) }
                    })
                    .collect();
                lines.push((
                    format!("  {}", json::text(g, "/ruleGroupName")),
                    if rules.is_empty() { "whole group".into() } else { cut(&rules.join(", "), 120) },
                ));
            }
        }
        lines.push(("Exclusions".into(), self.exclusions.to_string()));
        lines
    }

    pub fn custom_rows(&self) -> Vec<(String, String)> {
        let mut rules = self.custom_rules.clone();
        rules.sort_by_key(|r| json::int_at(r, "/priority").unwrap_or(i64::MAX));
        let mut lines = Vec::new();
        if rules.is_empty() {
            lines.push((String::new(), "No custom rules".into()));
        }
        for r in &rules {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            let off = json::str_at(r, "/state").or_else(|| json::str_at(r, "/enabledState")).is_some_and(|s| s.eq_ignore_ascii_case("disabled"));
            lines.push((
                format!("{} · {}", json::text(r, "/priority"), json::text(r, "/name")),
                format!("{} · {}{}", json::text(r, "/action"), json::text(r, "/ruleType"), if off { " · disabled" } else { "" }),
            ));
            if let Some(t) = json::int_at(r, "/rateLimitThreshold") {
                let per = json::str_at(r, "/rateLimitDuration")
                    .or_else(|| json::str_at(r, "/rateLimitDurationInMinutes").map(|m| format!("{} min", m)))
                    .unwrap_or_else(|| "-".into());
                lines.push(("  Rate limit".into(), format!("{} requests per {}", t, per)));
            }
            for c in json::arr(r, "/matchConditions") {
                // App Gateway: `matchVariables[]` / `negationConditon` /
                // `matchValues`; Front Door: `matchVariable` /
                // `negateCondition` / `matchValue`.
                let vars: Vec<String> = match json::str_at(&c, "/matchVariable") {
                    Some(v) => vec![match json::str_at(&c, "/selector") {
                        Some(s) => format!("{}[{}]", v, s),
                        None => v,
                    }],
                    None => json::arr(&c, "/matchVariables")
                        .iter()
                        .map(|m| match json::str_at(m, "/selector") {
                            Some(s) => format!("{}[{}]", json::text(m, "/variableName"), s),
                            None => json::text(m, "/variableName"),
                        })
                        .collect(),
                };
                let negate = json::bool_at(&c, "/negationConditon").or_else(|| json::bool_at(&c, "/negateCondition")) == Some(true);
                let mut values = json::strings_at(&c, "/matchValues");
                values.extend(json::strings_at(&c, "/matchValue"));
                let transforms = json::strings_at(&c, "/transforms");
                lines.push((
                    format!("  if {}", vars.join(" or ")),
                    format!(
                        "{}{} {}{}",
                        if negate { "not " } else { "" },
                        json::text(&c, "/operator"),
                        cut(&values.join(", "), 80),
                        if transforms.is_empty() { String::new() } else { format!(" ({})", transforms.join(", ")) }
                    ),
                ));
            }
        }
        lines
    }

    pub fn association_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.associations.is_empty() {
            lines.push((String::new(), "Not attached to anything: the policy protects nothing".into()));
        }
        for a in &self.associations {
            lines.push(Self::association(a));
        }
        if self.kind == WafKind::FrontDoor && !self.associations.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "· a Front Door profile's Security section shows which domains and paths it covers".into()));
        }
        lines
    }
}

impl Resource for WafPolicyRow {
    arm_row!("WAF policy");
    /// `App Gateway · Prevention · 2 custom` (`· not attached` when unused).
    fn list_summary(&self) -> Option<String> {
        let mut s = format!("{} · {}", self.kind_label(), self.mode_label());
        if !self.custom_rules.is_empty() {
            s.push_str(&format!(" · {} custom", self.custom_rules.len()));
        }
        if self.associations.is_empty() {
            s.push_str(" · not attached");
        }
        Some(s)
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&WAF_POLICY_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Kind".into(), self.kind_label()),
            ("Resource state".into(), json::opt(self.resource_state.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Mode".into(), self.mode_label()),
            ("Managed rule sets".into(), self.managed_summary()),
            ("Custom rules".into(), self.custom_rules.len().to_string()),
            ("Associations".into(), self.associations.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for a in &self.associations {
            let (label, top) = Self::association(a);
            push_unique(&mut v, label, top);
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        let id = shell_quote(&self.base.id);
        Some(match self.kind {
            WafKind::AppGateway => format!("az network application-gateway waf-policy show --ids {}", id),
            WafKind::FrontDoor => format!("az network front-door waf-policy show --ids {}", id),
        })
    }
}

pub fn waf_policy_section_lines(r: &WafPolicyRow, section: WafPolicyDetailSection) -> Vec<(String, String)> {
    match section {
        WafPolicyDetailSection::Overview => overview_rows(r),
        WafPolicyDetailSection::Settings => r.settings_rows(),
        WafPolicyDetailSection::ManagedRules => r.managed_rows(),
        WafPolicyDetailSection::CustomRules => r.custom_rows(),
        WafPolicyDetailSection::Associations => r.association_rows(),
        WafPolicyDetailSection::Access => crate::azure::services::rendered_by_app(),
        WafPolicyDetailSection::Activity => crate::azure::services::rendered_by_app(),
        WafPolicyDetailSection::Related => related_lines(r.related()),
        WafPolicyDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Front Door profile ────────────────────────────────────────────────

/// Whether a `Microsoft.Cdn/profiles` body is Front Door Standard or
/// Premium (not a classic CDN profile).
pub fn is_front_door(v: &Value) -> bool {
    json::str_at(v, "/sku/name").is_some_and(|s| {
        let s = s.to_lowercase();
        s == "standard_azurefrontdoor" || s == "premium_azurefrontdoor"
    })
}

#[derive(Debug, Clone)]
pub struct FrontDoorProfileRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub resource_state: Option<String>,
    /// The `X-Azure-FDID` header value an origin can lock to.
    pub front_door_id: Option<String>,
    pub origin_timeout: Option<i64>,
    pub identity_type: Option<String>,
    pub identity_ids: Vec<String>,
    pub log_scrubbing: Option<String>,
}

impl FrontDoorProfileRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<FrontDoorProfileRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        Some(FrontDoorProfileRow {
            sku: json::str_at(v, "/sku/name"),
            resource_state: json::str_at(v, "/properties/resourceState"),
            front_door_id: json::str_at(v, "/properties/frontDoorId"),
            origin_timeout: json::int_at(v, "/properties/originResponseTimeoutSeconds"),
            identity_type: json::str_at(v, "/identity/type"),
            identity_ids: json::user_identity_ids(v),
            log_scrubbing: json::str_at(v, "/properties/logScrubbing/state"),
            base,
        })
    }

    fn tier(&self) -> &str {
        match self.sku.as_deref().map(str::to_lowercase).as_deref() {
            Some(s) if s.starts_with("premium") => "Premium",
            Some(s) if s.starts_with("standard") => "Standard",
            _ => "-",
        }
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.resource_state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "active" => ResourceState::Available,
                "disabled" => ResourceState::Stopped,
                "creating" => ResourceState::Creating,
                "deleting" => ResourceState::Deleting,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for FrontDoorProfileRow {
    arm_row!("Front Door profile");
    fn list_summary(&self) -> Option<String> {
        Some(format!("Front Door {}", self.tier()))
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&FRONT_DOOR_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.tier(),
            self.front_door_id.clone().unwrap_or_default()
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Resource state".into(), json::opt(self.resource_state.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Front Door id".into(), json::opt(self.front_door_id.clone())),
        ];
        if self.front_door_id.is_some() {
            lines.push((String::new(), "· an origin can accept only this profile by checking the X-Azure-FDID header".into()));
        }
        lines.push((
            "Origin response timeout".into(),
            self.origin_timeout.map(|s| format!("{}s", s)).unwrap_or_else(|| "-".into()),
        ));
        lines.push(("Identity".into(), json::opt(self.identity_type.clone())));
        lines.push(("Log scrubbing".into(), json::opt(self.log_scrubbing.clone())));
        if self.tier() == "Standard" {
            lines.push((String::new(), "· Private Link origins and managed WAF rule sets need the Premium tier".into()));
        }
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for i in &self.identity_ids {
            push_unique(&mut v, format!("Identity {}", name_of_id(i)), i.clone());
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az afd profile show --ids {}", shell_quote(&self.base.id)))
    }
}

/// A profile's child lists, read together on demand: every endpoint with
/// its routes, every origin group with its origins, the custom domains
/// and the security policies. Scrubbed.
#[derive(Debug, Clone, Default)]
pub struct AfdTopology {
    pub endpoints: Vec<(Value, Vec<Value>)>,
    pub origin_groups: Vec<(Value, Vec<Value>)>,
    pub domains: Vec<Value>,
    pub security_policies: Vec<Value>,
    /// A child list that failed (the rest still render).
    pub warnings: Vec<String>,
    /// Parents past [`TOPOLOGY_MAX_PARENTS`] whose children were not read.
    pub truncated: Vec<&'static str>,
}

/// `{profile}/{child}`.
pub fn afd_child_path(profile_id: &str, child: &str) -> String {
    format!("{}/{}", profile_id.trim_end_matches('/'), child)
}

/// `2 + endpoints + origin groups + 2` GETs: the endpoints (a failure
/// fails the whole), each one's routes, the origin groups, each one's
/// origins, the custom domains and the security policies (a failure of
/// any of those is a warning line).
pub async fn fetch_afd_topology(arm: Arc<ArmClient>, profile: String) -> std::result::Result<AfdTopology, String> {
    let mut t = AfdTopology::default();
    let scrubbed = |items: Vec<Value>| items.iter().map(without_secrets).collect::<Vec<_>>();
    let endpoints = arm
        .list(&afd_child_path(&profile, "afdEndpoints"), CDN_API_VERSION)
        .await
        .map_err(|e| e.to_string())?;
    if endpoints.len() > TOPOLOGY_MAX_PARENTS {
        t.truncated.push("endpoints");
    }
    for ep in scrubbed(endpoints).into_iter().take(TOPOLOGY_MAX_PARENTS) {
        let routes = match json::str_at(&ep, "/id") {
            Some(id) => match arm.list(&afd_child_path(&id, "routes"), CDN_API_VERSION).await {
                Ok(r) => scrubbed(r),
                Err(e) => {
                    t.warnings.push(format!("routes of {}: {}", name_of_id(&id), e));
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        t.endpoints.push((ep, routes));
    }
    match arm.list(&afd_child_path(&profile, "originGroups"), CDN_API_VERSION).await {
        Ok(groups) => {
            if groups.len() > TOPOLOGY_MAX_PARENTS {
                t.truncated.push("origin groups");
            }
            for g in scrubbed(groups).into_iter().take(TOPOLOGY_MAX_PARENTS) {
                let origins = match json::str_at(&g, "/id") {
                    Some(id) => match arm.list(&afd_child_path(&id, "origins"), CDN_API_VERSION).await {
                        Ok(o) => scrubbed(o),
                        Err(e) => {
                            t.warnings.push(format!("origins of {}: {}", name_of_id(&id), e));
                            Vec::new()
                        }
                    },
                    None => Vec::new(),
                };
                t.origin_groups.push((g, origins));
            }
        }
        Err(e) => t.warnings.push(format!("origin groups: {}", e)),
    }
    match arm.list(&afd_child_path(&profile, "customDomains"), CDN_API_VERSION).await {
        Ok(d) => t.domains = scrubbed(d),
        Err(e) => t.warnings.push(format!("custom domains: {}", e)),
    }
    match arm.list(&afd_child_path(&profile, "securityPolicies"), CDN_API_VERSION).await {
        Ok(p) => t.security_policies = scrubbed(p),
        Err(e) => t.warnings.push(format!("security policies: {}", e)),
    }
    Ok(t)
}

impl AfdTopology {
    fn routes(&self) -> impl Iterator<Item = (&Value, &Value)> {
        self.endpoints.iter().flat_map(|(ep, routes)| routes.iter().map(move |r| (ep, r)))
    }

    /// A custom domain's host name by its id.
    fn domain_host(&self, id: &str) -> String {
        self.domains
            .iter()
            .find(|d| json::str_at(d, "/id").is_some_and(|i| i.eq_ignore_ascii_case(id)))
            .and_then(|d| json::str_at(d, "/properties/hostName"))
            .unwrap_or_else(|| name_of_id(id).to_string())
    }

    /// The warning and truncation lines every section opens with.
    fn notes(&self) -> Vec<(String, String)> {
        let mut lines: Vec<(String, String)> = self.warnings.iter().map(|w| (String::new(), format!("⚠ {}", w))).collect();
        for what in &self.truncated {
            lines.push((String::new(), format!("· more than {} {}: the first {} are followed", TOPOLOGY_MAX_PARENTS, what, TOPOLOGY_MAX_PARENTS)));
        }
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        lines
    }

    /// The links a loaded topology adds to Related (and to `U`): WAF
    /// policies, Azure origins, Private Link targets, DNS zones, origin
    /// auth identities, and each origin host a warm list matches.
    pub fn links(&self, targets: &BackendTargets) -> Vec<(String, String)> {
        let mut v = Vec::new();
        for sp in &self.security_policies {
            if let Some(w) = json::arm_id(json::id_at(sp, "/properties/parameters/wafPolicy")) {
                push_unique(&mut v, format!("WAF policy {}", name_of_id(&w)), w);
            }
        }
        for (g, origins) in &self.origin_groups {
            if let Some(i) = json::arm_id(json::id_at(g, "/properties/authentication/userAssignedIdentity")) {
                push_unique(&mut v, format!("Origin auth identity {}", name_of_id(&i)), i);
            }
            for o in origins {
                let name = json::text(o, "/name");
                if let Some(a) = json::arm_id(json::id_at(o, "/properties/azureOrigin")) {
                    push_unique(&mut v, format!("Origin {} → {}", name, name_of_id(&a)), a);
                } else if let Some((label, id)) = json::str_at(o, "/properties/hostName").and_then(|h| targets.resolve(&h).cloned()) {
                    push_unique(&mut v, format!("Origin {} → {}", name, label), id);
                }
                if let Some(pl) = json::arm_id(json::id_at(o, "/properties/sharedPrivateLinkResource/privateLink")) {
                    push_unique(&mut v, format!("Private Link target {} (origin {})", name_of_id(&pl), name), pl);
                }
            }
        }
        for d in &self.domains {
            if let Some(z) = json::arm_id(json::id_at(d, "/properties/azureDnsZone")) {
                push_unique(&mut v, format!("DNS zone {}", name_of_id(&z)), z);
            }
        }
        v
    }
}

/// The three arms of a lazy topology section.
fn with_topology(
    topo: Option<&Lazy<AfdTopology>>,
    what: &str,
    render: impl FnOnce(&AfdTopology) -> Vec<(String, String)>,
) -> Vec<(String, String)> {
    match topo {
        None | Some(Lazy::Loading) => vec![(what.into(), "Loading…".into())],
        Some(Lazy::Error(e)) => error_rows(e),
        Some(Lazy::Loaded(t)) => {
            let mut lines = t.notes();
            lines.extend(render(t));
            lines
        }
    }
}

/// `--profile-name {p} -g {rg} --subscription {sub}`: the `afd` list
/// commands declare their parents without an `id_part`.
fn profile_args(base: &ArmBase) -> Option<String> {
    Some(format!(
        "--profile-name {} -g {} --subscription {}",
        shell_quote(&base.name),
        shell_quote(resource_group_of(&base.id)?),
        shell_quote(subscription_of(&base.id)?)
    ))
}

fn endpoint_rows(t: &AfdTopology, base: &ArmBase) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if t.endpoints.is_empty() {
        lines.push((String::new(), "No endpoints".into()));
    }
    for (ep, routes) in &t.endpoints {
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        let off = is_disabled(ep, "/properties/enabledState");
        lines.push((
            json::text(ep, "/name"),
            format!(
                "{}{} · {}",
                json::text(ep, "/properties/hostName"),
                if off { " · ⚠ disabled" } else { "" },
                json::text(ep, "/properties/deploymentStatus")
            ),
        ));
        if routes.is_empty() {
            lines.push(("  Routes".into(), "⚠ none: the endpoint serves nothing".into()));
        }
        for r in routes {
            let p = |k: &str| format!("/properties/{}", k);
            let mut domains: Vec<String> = json::ids_at(r, &p("customDomains")).iter().map(|d| t.domain_host(d)).collect();
            if json::str_at(r, &p("linkToDefaultDomain")).is_some_and(|l| l.eq_ignore_ascii_case("enabled")) {
                domains.insert(0, json::text(ep, "/properties/hostName"));
            }
            let group_id = json::id_at(r, &p("originGroup"));
            lines.push((
                format!("  Route · {}", json::text(r, "/name")),
                format!(
                    "{} · {} → origin group {}{}",
                    json::strings_at(r, &p("patternsToMatch")).join(" "),
                    json::strings_at(r, &p("supportedProtocols")).join("/"),
                    ref_name(group_id.as_deref()),
                    if is_disabled(r, &p("enabledState")) { " · ⚠ disabled" } else { "" }
                ),
            ));
            lines.push(("    Domains".into(), json::join(&domains)));
            lines.push((
                "    Forwarding".into(),
                format!(
                    "{} · HTTPS redirect {}{}",
                    json::text(r, &p("forwardingProtocol")),
                    json::text(r, &p("httpsRedirect")).to_lowercase(),
                    json::str_at(r, &p("originPath")).filter(|o| !o.is_empty()).map(|o| format!(" · origin path {}", o)).unwrap_or_default()
                ),
            ));
            let cache = match r.pointer("/properties/cacheConfiguration").filter(|c| c.is_object()) {
                Some(c) => format!(
                    "on · query string {} · compression {}",
                    json::text(c, "/queryStringCachingBehavior"),
                    json::yes_no(json::bool_at(c, "/compressionSettings/isCompressionEnabled"))
                ),
                None => "off".into(),
            };
            lines.push(("    Caching".into(), cache));
            let sets: Vec<String> = json::ids_at(r, &p("ruleSets")).iter().map(|i| name_of_id(i).to_string()).collect();
            if !sets.is_empty() {
                lines.push(("    Rule sets".into(), sets.join(", ")));
            }
            if let Some(g) = group_id.as_deref() {
                let origins: Vec<String> = t
                    .origin_groups
                    .iter()
                    .find(|(og, _)| json::str_at(og, "/name").is_some_and(|n| n.eq_ignore_ascii_case(name_of_id(g))))
                    .map(|(_, os)| os.iter().map(|o| json::text(o, "/properties/hostName")).collect())
                    .unwrap_or_default();
                lines.push(("    → Origins".into(), json::join(&origins)));
            }
        }
    }
    if let Some(args) = profile_args(base) {
        lines.push((String::new(), String::new()));
        lines.push(("Read command".into(), format!("az afd endpoint list {}", args)));
        lines.push((String::new(), "· an endpoint's routes: az afd route list --endpoint-name {endpoint} with the same arguments".into()));
    }
    lines
}

fn origin_rows(t: &AfdTopology, base: &ArmBase, targets: &BackendTargets) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if t.origin_groups.is_empty() {
        lines.push((String::new(), "No origin groups".into()));
    }
    for (g, origins) in &t.origin_groups {
        let p = |k: &str| format!("/properties/{}", k);
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        let gname = json::text(g, "/name");
        let probe = match g.pointer("/properties/healthProbeSettings").filter(|h| h.is_object()) {
            Some(h) => format!(
                "probe {} {} {} every {}s",
                json::text(h, "/probeProtocol"),
                json::text(h, "/probeRequestType"),
                json::text(h, "/probePath"),
                json::text(h, "/probeIntervalInSeconds")
            ),
            None => "no health probe".into(),
        };
        lines.push((gname.clone(), format!("{} origins · {}", origins.len(), probe)));
        lines.push((
            "  Load balancing".into(),
            format!(
                "{} of {} samples · +{} ms latency band",
                json::text(g, &p("loadBalancingSettings/successfulSamplesRequired")),
                json::text(g, &p("loadBalancingSettings/sampleSize")),
                json::text(g, &p("loadBalancingSettings/additionalLatencyInMilliseconds"))
            ),
        ));
        lines.push(("  Session affinity".into(), json::text(g, &p("sessionAffinityState")).to_lowercase()));
        if let Some(a) = g.pointer("/properties/authentication").filter(|a| a.is_object()) {
            match json::arm_id(json::id_at(a, "/userAssignedIdentity")) {
                Some(i) => lines.push((format!("  Origin auth · {} as {}", json::text(a, "/type"), name_of_id(&i)), i)),
                None => lines.push(("  Origin auth".into(), format!("{} · scope {}", json::text(a, "/type"), json::text(a, "/scope")))),
            }
        }
        let routes: Vec<String> = t
            .routes()
            .filter(|(_, r)| json::id_at(r, "/properties/originGroup").is_some_and(|i| name_of_id(&i).eq_ignore_ascii_case(&gname)))
            .map(|(ep, r)| format!("{}/{}", json::text(ep, "/name"), json::text(r, "/name")))
            .collect();
        lines.push(("  Used by routes".into(), if routes.is_empty() { "⚠ none".into() } else { routes.join(", ") }));

        let mut origins = origins.clone();
        origins.sort_by_key(|o| (json::int_at(o, "/properties/priority").unwrap_or(i64::MAX), json::text(o, "/name")));
        for o in &origins {
            let host = json::text(o, &p("hostName"));
            lines.push((
                format!("  Origin · {}", json::text(o, "/name")),
                format!(
                    "{} · priority {} · weight {}{}",
                    host,
                    json::text(o, &p("priority")),
                    json::text(o, &p("weight")),
                    if is_disabled(o, &p("enabledState")) { " · ⚠ disabled" } else { "" }
                ),
            ));
            let header = json::str_at(o, &p("originHostHeader")).filter(|h| !h.is_empty());
            lines.push((
                "    Ports · host header".into(),
                format!(
                    "http {} · https {} · {}",
                    json::text(o, &p("httpPort")),
                    json::text(o, &p("httpsPort")),
                    header.clone().unwrap_or_else(|| "the request's host".into())
                ),
            ));
            lines.push(("    Certificate name check".into(), json::yes_no(json::bool_at(o, &p("enforceCertificateNameCheck")))));
            let azure = json::arm_id(json::id_at(o, &p("azureOrigin")));
            let matched = azure
                .clone()
                .map(|a| (format!("Azure resource {}", name_of_id(&a)), a))
                .or_else(|| targets.resolve(&host).cloned());
            match &matched {
                Some((label, id)) => lines.push((format!("    → {}", label), id.clone())),
                None if !targets.cold.is_empty() => lines.push(("    →".into(), "not matched in the warm lists".into())),
                None => {}
            }
            if let Some((_, id)) = &matched {
                if routes_by_host(id) && header.as_deref().is_some_and(|h| !h.eq_ignore_ascii_case(&host)) {
                    lines.push((String::new(), "    ⚠ the origin host header differs from the origin host; Container Apps and App Service route by host".into()));
                }
                if routes_by_host(id) && header.is_none() {
                    lines.push((String::new(), "    ⚠ no origin host header: the client's host reaches a platform that routes by host".into()));
                }
            }
            if let Some(pl) = o.pointer("/properties/sharedPrivateLinkResource").filter(|s| s.is_object()) {
                match json::arm_id(json::id_at(pl, "/privateLink")) {
                    Some(id) => lines.push((format!("    Private Link · {}", name_of_id(&id)), id)),
                    None => lines.push(("    Private Link".into(), "-".into())),
                }
                let status = json::text(pl, "/status");
                let flag = match status.to_lowercase().as_str() {
                    "approved" => String::new(),
                    "pending" => " · ⚠ approve it on the target's private endpoint connections".into(),
                    _ => " · ⚠ traffic does not flow".into(),
                };
                lines.push(("      Status".into(), format!("{}{}", status, flag)));
                lines.push((
                    "      Location · sub-resource".into(),
                    format!("{} · {}", json::text(pl, "/privateLinkLocation"), json::text(pl, "/groupId")),
                ));
            }
        }
    }
    if let Some(note) = targets.cold_note() {
        lines.push((String::new(), note));
    }
    if let Some(args) = profile_args(base) {
        lines.push((String::new(), String::new()));
        lines.push(("Read command".into(), format!("az afd origin-group list {}", args)));
        lines.push((String::new(), "· a group's origins: az afd origin list --origin-group-name {group} with the same arguments".into()));
    }
    lines
}

fn domain_rows(t: &AfdTopology, base: &ArmBase) -> Vec<(String, String)> {
    let mut lines = vec![(String::new(), "· DCV validation tokens and certificate material are never shown".into())];
    if t.domains.is_empty() {
        lines.push((String::new(), "No custom domains (only the endpoints' own host names)".into()));
    }
    for d in sorted_by_name(&t.domains) {
        let p = |k: &str| format!("/properties/{}", k);
        lines.push((String::new(), String::new()));
        let state = json::text(&d, &p("domainValidationState"));
        let flag = if state.eq_ignore_ascii_case("approved") { "" } else { " · ⚠ not validated" };
        lines.push((json::text(&d, &p("hostName")), format!("validation {}{}", state, flag)));
        let cert = match json::str_at(&d, &p("tlsSettings/certificateType")) {
            Some(c) if c.eq_ignore_ascii_case("ManagedCertificate") => "Front Door managed".to_string(),
            Some(c) => match json::id_at(&d, &p("tlsSettings/secret")) {
                Some(s) => format!("{} · secret {}", c, name_of_id(&s)),
                None => c,
            },
            None => "-".into(),
        };
        lines.push(("  Certificate".into(), format!("{} · min TLS {}", cert, json::text(&d, &p("tlsSettings/minimumTlsVersion")))));
        if let Some(z) = json::arm_id(json::id_at(&d, &p("azureDnsZone"))) {
            lines.push((format!("  Azure DNS zone · {}", name_of_id(&z)), z));
        }
        lines.push(("  Deployment".into(), json::text(&d, &p("deploymentStatus"))));
        let id = json::str_at(&d, "/id").unwrap_or_default();
        let routes: Vec<String> = t
            .routes()
            .filter(|(_, r)| json::ids_at(r, "/properties/customDomains").iter().any(|i| i.eq_ignore_ascii_case(&id)))
            .map(|(ep, r)| format!("{}/{}", json::text(ep, "/name"), json::text(r, "/name")))
            .collect();
        lines.push(("  Routes".into(), if routes.is_empty() { "⚠ none: not served".into() } else { routes.join(", ") }));
        let wafs: Vec<String> = t
            .security_policies
            .iter()
            .filter(|sp| {
                json::arr(sp, "/properties/parameters/associations")
                    .iter()
                    .any(|a| json::ids_at(a, "/domains").iter().any(|i| i.eq_ignore_ascii_case(&id)))
            })
            .filter_map(|sp| json::id_at(sp, "/properties/parameters/wafPolicy").map(|w| name_of_id(&w).to_string()))
            .collect();
        lines.push(("  WAF".into(), if wafs.is_empty() { "none".into() } else { wafs.join(", ") }));
    }
    if let Some(args) = profile_args(base) {
        lines.push((String::new(), String::new()));
        lines.push(("Read command".into(), format!("az afd custom-domain list {}", args)));
    }
    lines
}

fn security_rows(t: &AfdTopology, base: &ArmBase, waf_policies: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if t.security_policies.is_empty() {
        lines.push((String::new(), "⚠ no security policy: no WAF in front of this profile's endpoints".into()));
    }
    for sp in &t.security_policies {
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        lines.push((json::text(sp, "/name"), json::text(sp, "/properties/parameters/type")));
        if let Some(w) = json::arm_id(json::id_at(sp, "/properties/parameters/wafPolicy")) {
            lines.push((format!("  WAF policy · {}", name_of_id(&w)), w.clone()));
            let found = waf_policies.unwrap_or_default().iter().find_map(|r| {
                r.as_any().downcast_ref::<WafPolicyRow>().filter(|p| p.base.id.eq_ignore_ascii_case(&w))
            });
            match found {
                Some(p) => {
                    lines.push(("    Mode".into(), p.mode_label()));
                    lines.push(("    Managed rules".into(), p.managed_summary()));
                }
                None if waf_policies.is_none() => lines.push((String::new(), "    · open @waf to see its mode and rules".into())),
                None => {}
            }
        }
        for a in json::arr(sp, "/properties/parameters/associations") {
            let domains: Vec<String> = json::ids_at(&a, "/domains")
                .iter()
                .map(|d| {
                    if d.to_lowercase().contains("/afdendpoints/") {
                        format!("endpoint {}", name_of_id(d))
                    } else {
                        t.domain_host(d)
                    }
                })
                .collect();
            lines.push((
                "  Applies to".into(),
                format!("{} · {}", json::join(&domains), json::strings_at(&a, "/patternsToMatch").join(" ")),
            ));
        }
    }
    if let Some(args) = profile_args(base) {
        lines.push((String::new(), String::new()));
        lines.push(("Read command".into(), format!("az afd security-policy list {}", args)));
    }
    lines
}

pub fn front_door_section_lines(
    r: &FrontDoorProfileRow,
    section: FrontDoorDetailSection,
    topology: Option<&Lazy<AfdTopology>>,
    targets: &BackendTargets,
    waf_policies: Option<&[Box<dyn Resource>]>,
) -> Vec<(String, String)> {
    match section {
        FrontDoorDetailSection::Overview => overview_rows(r),
        FrontDoorDetailSection::Endpoints => with_topology(topology, "Endpoints", |t| endpoint_rows(t, &r.base)),
        FrontDoorDetailSection::Origins => with_topology(topology, "Origins", |t| origin_rows(t, &r.base, targets)),
        FrontDoorDetailSection::Domains => with_topology(topology, "Domains", |t| domain_rows(t, &r.base)),
        FrontDoorDetailSection::Security => with_topology(topology, "Security", |t| security_rows(t, &r.base, waf_policies)),
        FrontDoorDetailSection::Access => crate::azure::services::rendered_by_app(),
        FrontDoorDetailSection::Activity => crate::azure::services::rendered_by_app(),
        FrontDoorDetailSection::Related => {
            let mut rel = r.related();
            if let Some(Lazy::Loaded(t)) = topology {
                for (label, id) in t.links(targets) {
                    push_unique(&mut rel, label, id);
                }
            }
            related_lines(rel)
        }
        FrontDoorDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The links a row has only through the warm lists or a loaded topology:
/// what `U` adds to the reverse index for the Edge types.
pub fn derived_links(r: &dyn Resource, targets: &BackendTargets, topologies: &LazyMap<AfdTopology>) -> Vec<(String, String)> {
    let any = r.as_any();
    if let Some(g) = any.downcast_ref::<AppGatewayRow>() {
        return g.matched_links(targets);
    }
    if any.downcast_ref::<FrontDoorProfileRow>().is_some() {
        if let Some(Lazy::Loaded(t)) = topologies.get(r.id()) {
            return t.links(targets);
        }
    }
    Vec::new()
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct EdgeService {
    scope: Scope,
}

impl EdgeService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<T: Resource + 'static>(rows: Vec<T>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::WafPolicies => Self::boxed(page.iter().filter_map(|v| WafPolicyRow::from_json(v, tenant)).collect()),
            JumpView::PrivateLinkServices => Self::boxed(
                page.iter()
                    .filter_map(|v| crate::azure::services::private_link::PrivateLinkServiceRow::from_json(v, tenant))
                    .collect(),
            ),
            JumpView::FrontDoorProfiles => Self::boxed(
                page.iter().filter(|v| is_front_door(v)).filter_map(|v| FrontDoorProfileRow::from_json(v, tenant)).collect(),
            ),
            _ => Self::boxed(page.iter().filter_map(|v| AppGatewayRow::from_json(v, tenant)).collect()),
        }
    }

    /// The list (or lists) behind a sub-tab: WAF policies are two.
    fn lists_of(view: JumpView) -> &'static [(&'static str, &'static str, &'static str)] {
        match view {
            JumpView::WafPolicies => &[
                (AGW_WAF_PATH, AGW_API_VERSION, "Listing Application Gateway WAF policies…"),
                (AFD_WAF_PATH, AFD_WAF_API_VERSION, "Listing Front Door WAF policies…"),
            ],
            JumpView::FrontDoorProfiles => &[(PROFILES_PATH, CDN_API_VERSION, "Listing Front Door profiles…")],
            JumpView::PrivateLinkServices => &[(
                crate::azure::services::private_link::PRIVATE_LINK_SERVICES_PATH,
                AGW_API_VERSION,
                "Listing Private Link services…",
            )],
            _ => &[(APP_GATEWAYS_PATH, AGW_API_VERSION, "Listing application gateways…")],
        }
    }

    fn api_version_for(id: &str) -> &'static str {
        let lower = id.to_lowercase();
        if lower.contains("/microsoft.cdn/") {
            CDN_API_VERSION
        } else if lower.contains("/frontdoorwebapplicationfirewallpolicies/") {
            AFD_WAF_API_VERSION
        } else {
            AGW_API_VERSION
        }
    }
}

#[async_trait]
impl AzureService for EdgeService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Edge
    }

    fn name(&self) -> &str {
        "Edge"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        let mut out = Vec::new();
        let mut first_err = None;
        let lists = Self::lists_of(view);
        for (path, version, _) in lists {
            match self.scope.list(path, version).await {
                Ok(page) => out.extend(Self::rows(view, &page, tenant)),
                Err(e) => first_err = first_err.or(Some(e)),
            }
        }
        match first_err {
            // Every list failed: the error. One of two: the rows that came.
            Some(e) if out.is_empty() && lists.len() == 1 => Err(e),
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
        let lists = Self::lists_of(view);
        let mut total = 0usize;
        let mut failures = Vec::new();
        for (path, version, label) in lists {
            let r = self
                .scope
                .stream(path, version, &[], service_type, label, &event_tx, |page| Self::rows(view, &page, tenant.as_deref()))
                .await;
            match r {
                Ok(n) => total += n,
                Err(e) => failures.push(e),
            }
        }
        // A WAF list that fails beside one that streamed is a warning; only
        // nothing streaming at all is the list's error.
        if failures.len() == lists.len() {
            return finish_stream(service_type, Err(failures.remove(0)), &event_tx);
        }
        for e in failures {
            let _ = event_tx.send(Event::ResourceLoadWarning { service: service_type, warning: e.to_string() });
        }
        finish_stream(service_type, Ok(total), &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, Self::api_version_for(id)).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::AppGateways);
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::services::network_private::PrivateEndpointRow;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-edge";

    fn id(path: &str) -> String {
        format!("{}/providers/{}", RG, path)
    }

    fn agw(sub: &str) -> String {
        id(&format!("Microsoft.Network/applicationGateways/agw-prod/{}", sub))
    }

    fn agw_json() -> Value {
        json!({
            "id": id("Microsoft.Network/applicationGateways/agw-prod"),
            "name": "agw-prod",
            "location": "australiaeast",
            "zones": ["1", "2"],
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                id("Microsoft.ManagedIdentity/userAssignedIdentities/id-agw"): {"clientId": "c", "principalId": "p"}
            }},
            "properties": {
                "provisioningState": "Succeeded",
                "operationalState": "Running",
                "sku": {"name": "WAF_v2", "tier": "WAF_v2"},
                "autoscaleConfiguration": {"minCapacity": 2, "maxCapacity": 10},
                "enableHttp2": true,
                "gatewayIPConfigurations": [{"name": "gw", "properties": {"subnet": {"id": id("Microsoft.Network/virtualNetworks/vnet-hub/subnets/snet-agw")}}}],
                "frontendIPConfigurations": [
                    {"name": "fe-public", "id": agw("frontendIPConfigurations/fe-public"), "properties": {
                        "publicIPAddress": {"id": id("Microsoft.Network/publicIPAddresses/pip-agw")}}},
                    {"name": "fe-private", "id": agw("frontendIPConfigurations/fe-private"), "properties": {
                        "privateIPAddress": "10.0.1.10", "privateIPAllocationMethod": "Static",
                        "subnet": {"id": id("Microsoft.Network/virtualNetworks/vnet-hub/subnets/snet-agw")}}}
                ],
                "frontendPorts": [{"name": "p443", "id": agw("frontendPorts/p443"), "properties": {"port": 443}}],
                "sslCertificates": [{"name": "cert-api", "id": agw("sslCertificates/cert-api"), "properties": {
                    "data": "fixture-pfx-blob", "password": "fixture-pfx-pass",
                    "keyVaultSecretId": "https://kv-edge.example/secrets/cert-api"}}],
                "httpListeners": [{"name": "l-api", "id": agw("httpListeners/l-api"), "properties": {
                    "frontendIPConfiguration": {"id": agw("frontendIPConfigurations/fe-public")},
                    "frontendPort": {"id": agw("frontendPorts/p443")},
                    "protocol": "Https", "hostNames": ["api.contoso.example"],
                    "sslCertificate": {"id": agw("sslCertificates/cert-api")},
                    "requireServerNameIndication": true,
                    "firewallPolicy": {"id": id("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-api")}}}],
                "backendAddressPools": [
                    {"name": "pool-aca", "id": agw("backendAddressPools/pool-aca"), "properties": {
                        "backendAddresses": [{"fqdn": "api.happyhill-1.australiaeast.example-aca.io"}]}},
                    {"name": "pool-vm", "id": agw("backendAddressPools/pool-vm"), "properties": {
                        "backendIPConfigurations": [{"id": id("Microsoft.Network/networkInterfaces/nic-web/ipConfigurations/ipconfig1")}]}},
                    {"name": "pool-empty", "id": agw("backendAddressPools/pool-empty"), "properties": {}}
                ],
                "backendHttpSettingsCollection": [{"name": "s-aca", "id": agw("backendHttpSettingsCollection/s-aca"), "properties": {
                    "port": 443, "protocol": "Https", "requestTimeout": 30, "cookieBasedAffinity": "Disabled",
                    "probe": {"id": agw("probes/probe-aca")}}}],
                "probes": [{"name": "probe-aca", "id": agw("probes/probe-aca"), "properties": {
                    "protocol": "Https", "path": "/healthz", "interval": 30, "timeout": 30, "unhealthyThreshold": 3,
                    "pickHostNameFromBackendHttpSettings": true, "match": {"statusCodes": ["200-399"]}}}],
                "requestRoutingRules": [
                    {"name": "r-api", "id": agw("requestRoutingRules/r-api"), "properties": {
                        "ruleType": "PathBasedRouting", "priority": 100,
                        "httpListener": {"id": agw("httpListeners/l-api")},
                        "urlPathMap": {"id": agw("urlPathMaps/map-api")}}}
                ],
                "urlPathMaps": [{"name": "map-api", "id": agw("urlPathMaps/map-api"), "properties": {
                    "defaultBackendAddressPool": {"id": agw("backendAddressPools/pool-vm")},
                    "defaultBackendHttpSettings": {"id": agw("backendHttpSettingsCollection/s-aca")},
                    "pathRules": [{"name": "pr-v1", "properties": {"paths": ["/v1/*"],
                        "backendAddressPool": {"id": agw("backendAddressPools/pool-aca")},
                        "backendHttpSettings": {"id": agw("backendHttpSettingsCollection/s-aca")}}}]}}],
                "firewallPolicy": {"id": id("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-agw")}
            }
        })
    }

    fn env_row() -> Box<dyn Resource> {
        Box::new(
            EnvironmentRow::from_json(
                &json!({"id": id("Microsoft.App/managedEnvironments/cae-prod"), "name": "cae-prod", "location": "Australia East",
                    "properties": {"provisioningState": "Succeeded", "defaultDomain": "happyhill-1.australiaeast.example-aca.io",
                        "staticIp": "10.0.2.50", "vnetConfiguration": {"internal": true}}}),
                None,
            )
            .unwrap(),
        )
    }

    fn app_row() -> Box<dyn Resource> {
        Box::new(
            ContainerAppRow::from_json(
                &json!({"id": id("Microsoft.App/containerApps/api"), "name": "api", "location": "Australia East",
                    "properties": {"provisioningState": "Succeeded",
                        "managedEnvironmentId": id("Microsoft.App/managedEnvironments/cae-prod"),
                        "configuration": {"ingress": {"external": true, "fqdn": "api.happyhill-1.australiaeast.example-aca.io", "targetPort": 8080}}}}),
                None,
            )
            .unwrap(),
        )
    }

    fn pe_row() -> Box<dyn Resource> {
        Box::new(
            PrivateEndpointRow::from_json(
                &json!({"id": id("Microsoft.Network/privateEndpoints/pe-web"), "name": "pe-web", "location": "australiaeast",
                    "properties": {"customDnsConfigs": [{"fqdn": "web-1.privatelink.example", "ipAddresses": ["10.0.3.4"]}],
                        "privateLinkServiceConnections": [{"name": "c", "properties": {
                            "privateLinkServiceId": id("Microsoft.Web/sites/web-1"), "groupIds": ["sites"]}}]}}),
                None,
            )
            .unwrap(),
        )
    }

    fn has(lines: &[(String, String)], k: &str, v: &str) -> bool {
        lines.iter().any(|(a, b)| a == k && b.contains(v))
    }

    fn line<'a>(lines: &'a [(String, String)], k: &str) -> &'a (String, String) {
        lines.iter().find(|(a, _)| a == k).unwrap_or_else(|| panic!("{k:?} in {lines:#?}"))
    }

    #[test]
    fn section_labels_put_overview_first_and_access_activity_related_tags_last() {
        for desc in [&APP_GATEWAY_SECTIONS, &WAF_POLICY_SECTIONS, &FRONT_DOOR_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(&labels[labels.len() - 4..], ["Access", "Activity", "Related", "Tags"]);
            assert!(labels.len() <= 10, "digit keys reach ten sections");
        }
        let agw: Vec<&str> = APP_GATEWAY_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(&agw[1..6], ["Frontends", "Listeners", "Rules", "Backends", "WAF"]);
        let afd: Vec<&str> = FRONT_DOOR_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(&afd[1..5], ["Endpoints", "Origins", "Domains", "Security"]);
    }

    #[test]
    fn a_gateway_parses_state_overview_and_related() {
        let row = AppGatewayRow::from_json(&agw_json(), None).unwrap();
        assert_eq!(row.state(), ResourceState::Running);
        assert_eq!(row.state_label(), "running");
        assert_eq!(row.list_summary().as_deref(), Some("WAF_v2 · autoscale 2–10"));
        assert!(has(&row.details(), "Frontends", "1 public · 1 private"));
        assert!(row.search_text().contains("api.contoso.example"));
        assert!(row.search_text().contains("example-aca.io"));
        let related = row.related();
        let labels: Vec<&str> = related.iter().map(|(l, _)| l.as_str()).collect();
        for want in ["Gateway subnet vnet-hub/snet-agw", "Public IP pip-agw", "WAF policy waf-agw (gateway)", "WAF policy waf-api (listener l-api)", "Backend NIC nic-web", "Identity id-agw"] {
            assert!(labels.contains(&want), "{want} in {labels:?}");
        }
        // The frontend subnet is the gateway subnet: listed once.
        assert_eq!(related.iter().filter(|(_, i)| i.ends_with("snet-agw")).count(), 1);
        let (_, waf) = related.iter().find(|(l, _)| l.starts_with("WAF policy waf-agw")).unwrap();
        assert_eq!(JumpView::for_arm_id(waf), Some(JumpView::WafPolicies));
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az network application-gateway show --ids /subscriptions/0000/resourceGroups/rg-edge/providers/Microsoft.Network/applicationGateways/agw-prod")
        );
        let stopped = {
            let mut v = agw_json();
            v["properties"]["operationalState"] = json!("Stopped");
            AppGatewayRow::from_json(&v, None).unwrap()
        };
        assert_eq!(stopped.state(), ResourceState::Stopped);
    }

    #[test]
    fn certificate_data_and_password_never_reach_a_section_search_or_the_raw_view() {
        let row = AppGatewayRow::from_json(&agw_json(), None).unwrap();
        let targets = BackendTargets::default();
        let mut all: String = (0..APP_GATEWAY_SECTIONS.sections.len())
            .flat_map(|i| app_gateway_section_lines(&row, AppGatewayDetailSection::from_index(i), &targets, None))
            .map(|(k, v)| format!("{k}{v}"))
            .collect();
        all += &row.search_text();
        all += &row.raw_content().unwrap();
        // Name the slot, never the value (CodeQL: no secret in a message).
        assert!(!all.contains("fixture-pfx-blob"), "the certificate's data leaked");
        assert!(!all.contains("fixture-pfx-pass"), "the certificate's password leaked");
        assert!(all.contains("cert-api"), "the certificate's name stays");
        assert!(all.contains("kv-edge.example/secrets/cert-api"), "the Key Vault secret id stays");

        // A WAF policy embeds whole gateways: the same material is stripped.
        let mut waf = waf_agw_json();
        waf["properties"]["applicationGateways"] = json!([agw_json()]);
        let w = WafPolicyRow::from_json(&waf, None).unwrap();
        let raw = w.raw_content().unwrap();
        assert!(!raw.contains("fixture-pfx-blob") && !raw.contains("fixture-pfx-pass"), "a WAF policy kept certificate material");
        // And a domain's DCV token, at any depth.
        let d = without_secrets(&json!({"properties": {"validationProperties": {"validationToken": "tok", "expirationDate": "x"}}}));
        assert_eq!(d, json!({"properties": {"validationProperties": {"expirationDate": "x"}}}));
    }

    #[test]
    fn frontends_listeners_and_the_rule_chain_read_end_to_end() {
        let row = AppGatewayRow::from_json(&agw_json(), None).unwrap();
        let targets = BackendTargets::from_lists(TargetLists {
            container_apps: Some(&[app_row()]),
            environments: Some(&[env_row()]),
            ..Default::default()
        });
        let fe = row.frontend_rows(&targets);
        let (_, pip) = line(&fe, "  Public IP · pip-agw");
        assert_eq!(JumpView::for_arm_id(pip), Some(JumpView::PublicIps));
        assert!(has(&fe, "fe-private", "private 10.0.1.10 · static"));
        assert!(fe.iter().any(|(_, v)| v.contains("65200–65535")));

        let ls = row.listener_rows(&targets);
        assert!(has(&ls, "l-api", "Https :443 on public pip-agw · api.contoso.example"));
        assert!(has(&ls, "  Certificate · cert-api", "Key Vault https://kv-edge.example/secrets/cert-api"));
        assert!(has(&ls, "  SNI", "required"));
        assert!(has(&ls, "  Routed by", "r-api"));

        let rules = row.rule_rows(&targets);
        assert!(has(&rules, "100 · r-api", "PathBasedRouting"));
        assert!(has(&rules, "  → Path map · map-api", ""));
        assert!(has(&rules, "    /v1/* pool pool-aca", "via s-aca"));
        let (_, app) = line(&rules, "      → Container App api");
        assert_eq!(JumpView::for_arm_id(app), Some(JumpView::ContainerApps));
        // The settings keep the client's host: a Container App 404s.
        assert!(rules.iter().any(|(_, v)| v.contains("⚠ the pool is a Container App")));
        assert!(has(&rules, "    (default) pool pool-vm", "1 targets"));
    }

    #[test]
    fn backends_match_warm_targets_and_say_what_is_cold() {
        let row = AppGatewayRow::from_json(&agw_json(), None).unwrap();
        let targets = BackendTargets::from_lists(TargetLists { environments: Some(&[env_row()]), ..Default::default() });
        let lines = row.backend_rows(&targets);
        // Only the environment is warm: the FQDN matches its default domain.
        let (_, env) = line(&lines, "  api.happyhill-1.australiaeast.example-aca.io → Container Apps environment cae-prod");
        assert_eq!(JumpView::for_arm_id(env), Some(JumpView::ContainerAppEnvironments));
        let (_, nic) = line(&lines, "  NIC · nic-web (ipconfig1)");
        assert_eq!(JumpView::for_arm_id(nic), Some(JumpView::Nics));
        assert!(has(&lines, "pool-empty", "⚠ empty"));
        assert!(has(&lines, "  Used by", "map-api/pr-v1"));
        assert!(lines.iter().any(|(_, v)| v.contains("not loaded: @aca @app @pe @pip")));
        assert!(has(&lines, "  probe-aca", "Https {host from the settings}/healthz · every 30s"));
        assert!(has(&lines, "    Healthy when", "200-399"));

        // IPs match too: an environment's static IP, a private endpoint.
        let t = BackendTargets::from_lists(TargetLists { environments: Some(&[env_row()]), private_endpoints: Some(&[pe_row()]), ..Default::default() });
        assert!(t.resolve("10.0.2.50").is_some_and(|(l, _)| l == "Container Apps environment cae-prod"));
        assert!(t.resolve("10.0.3.4").is_some_and(|(l, _)| l == "Private endpoint pe-web (→ web-1)"));
        assert!(t.resolve("WEB-1.privatelink.example.").is_some(), "host names match case- and dot-insensitively");
        assert!(t.resolve("10.9.9.9").is_none());
        // The matched backends join Related.
        let related = app_gateway_section_lines(&row, AppGatewayDetailSection::Related, &targets, None);
        assert!(related.iter().any(|(l, _)| l.starts_with("Backend Container Apps environment cae-prod (pool-aca:")));
    }

    fn waf_agw_json() -> Value {
        json!({
            "id": id("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-agw"),
            "name": "waf-agw", "location": "australiaeast",
            "properties": {
                "provisioningState": "Succeeded", "resourceState": "Enabled",
                "policySettings": {"state": "Enabled", "mode": "Prevention", "requestBodyCheck": true, "maxRequestBodySizeInKb": 128},
                "customRules": [
                    {"name": "BlockBadIps", "priority": 10, "ruleType": "MatchRule", "action": "Block", "state": "Enabled",
                     "matchConditions": [{"matchVariables": [{"variableName": "RemoteAddr"}], "operator": "IPMatch",
                        "negationConditon": false, "matchValues": ["203.0.113.0/24"]}]},
                    {"name": "RateLimit", "priority": 5, "ruleType": "RateLimitRule", "action": "Block",
                     "rateLimitDuration": "OneMin", "rateLimitThreshold": 100,
                     "matchConditions": [{"matchVariables": [{"variableName": "RequestHeaders", "selector": "Host"}], "operator": "Equal",
                        "negationConditon": true, "matchValues": ["api.contoso.example"], "transforms": ["Lowercase"]}]}
                ],
                "managedRules": {"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.2",
                    "ruleGroupOverrides": [{"ruleGroupName": "REQUEST-942-APPLICATION-ATTACK-SQLI",
                        "rules": [{"ruleId": "942100", "state": "Disabled"}]}]}],
                    "exclusions": [{"matchVariable": "RequestHeaderNames"}]},
                "applicationGateways": [{"id": id("Microsoft.Network/applicationGateways/agw-prod")}],
                "httpListeners": [{"id": agw("httpListeners/l-api")}],
                "pathBasedRules": [{"id": agw("urlPathMaps/map-api/pathRules/pr-v1")}]
            }
        })
    }

    fn waf_afd_json() -> Value {
        json!({
            "id": id("Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/wafafd"),
            "name": "wafafd", "location": "Global",
            "sku": {"name": "Premium_AzureFrontDoor"},
            "properties": {
                "provisioningState": "Succeeded", "resourceState": "Enabled",
                "policySettings": {"enabledState": "Enabled", "mode": "Detection", "requestBodyCheck": "Enabled"},
                "customRules": {"rules": [{"name": "geo", "priority": 1, "enabledState": "Enabled", "ruleType": "MatchRule",
                    "action": "Block", "matchConditions": [{"matchVariable": "SocketAddr", "operator": "GeoMatch",
                        "negateCondition": true, "matchValue": ["AU", "NZ"]}]}]},
                "managedRules": {"managedRuleSets": [{"ruleSetType": "Microsoft_DefaultRuleSet", "ruleSetVersion": "2.1", "ruleSetAction": "Block"}]},
                "securityPolicyLinks": [{"id": id("Microsoft.Cdn/profiles/afd-prod/securityPolicies/sp-1")}]
            }
        })
    }

    #[test]
    fn waf_policies_of_both_kinds_parse_into_one_list() {
        let a = WafPolicyRow::from_json(&waf_agw_json(), None).unwrap();
        assert_eq!(a.kind, WafKind::AppGateway);
        assert_eq!(a.state(), ResourceState::Available);
        assert_eq!(a.list_summary().as_deref(), Some("App Gateway · Prevention · 2 custom"));
        assert!(a.cli_command().unwrap().starts_with("az network application-gateway waf-policy show --ids "));
        let custom = a.custom_rows();
        assert_eq!(custom[0].0, "5 · RateLimit", "by priority");
        assert!(has(&custom, "  Rate limit", "100 requests per OneMin"));
        assert!(has(&custom, "  if RequestHeaders[Host]", "not Equal api.contoso.example (Lowercase)"));
        assert!(has(&custom, "  if RemoteAddr", "IPMatch 203.0.113.0/24"));
        let managed = a.managed_rows();
        assert!(has(&managed, "OWASP 3.2", "1 group overrides"));
        assert!(has(&managed, "  REQUEST-942-APPLICATION-ATTACK-SQLI", "942100 (Disabled)"));
        assert!(has(&managed, "Exclusions", "1"));
        let assoc = a.association_rows();
        assert!(has(&assoc, "Application gateway agw-prod", "agw-prod"));
        let (_, listener) = line(&assoc, "Listener agw-prod/l-api");
        assert_eq!(JumpView::for_arm_id(listener), Some(JumpView::AppGateways), "a listener jumps to its gateway");
        assert!(has(&assoc, "Path rule agw-prod · map-api pathRules pr-v1", "agw-prod"));
        assert_eq!(a.related().iter().filter(|(_, i)| i.ends_with("agw-prod")).count(), 1, "one Related line per gateway");

        let f = WafPolicyRow::from_json(&waf_afd_json(), None).unwrap();
        assert_eq!(f.kind, WafKind::FrontDoor);
        assert_eq!(f.list_summary().as_deref(), Some("Front Door Premium · Detection · 1 custom"));
        assert!(f.cli_command().unwrap().starts_with("az network front-door waf-policy show --ids "));
        assert!(has(&f.custom_rows(), "  if SocketAddr", "not GeoMatch AU, NZ"));
        let assoc = f.association_rows();
        let (_, profile) = line(&assoc, "Front Door afd-prod · security policy sp-1");
        assert_eq!(JumpView::for_arm_id(profile), Some(JumpView::FrontDoorProfiles));
        assert!(has(&f.settings_rows(), "Mode", "Detection · logs matches"));

        let mut off = waf_agw_json();
        off["properties"]["policySettings"]["state"] = json!("Disabled");
        off["properties"]["resourceState"] = json!("Disabled");
        off["properties"]["applicationGateways"] = json!([]);
        off["properties"]["httpListeners"] = json!([]);
        off["properties"]["pathBasedRules"] = json!([]);
        let off = WafPolicyRow::from_json(&off, None).unwrap();
        assert_eq!(off.state(), ResourceState::Stopped);
        assert!(off.list_summary().unwrap().ends_with("· not attached"));
        assert!(off.mode_label().starts_with("off"));

        // The gateway's WAF section reads the policy from the warm list.
        let row = AppGatewayRow::from_json(&agw_json(), None).unwrap();
        let warm: Vec<Box<dyn Resource>> = vec![Box::new(a)];
        let lines = row.waf_rows(Some(&warm));
        assert!(has(&lines, "  Mode", "Prevention"));
        assert!(has(&lines, "  Managed rules", "OWASP 3.2"));
        assert!(row.waf_rows(None).iter().any(|(_, v)| v.contains("open @waf")));
    }

    fn profile_json(sku: &str) -> Value {
        json!({
            "id": id("Microsoft.Cdn/profiles/afd-prod"), "name": "afd-prod", "location": "Global",
            "sku": {"name": sku}, "kind": "frontdoor",
            "properties": {"provisioningState": "Succeeded", "resourceState": "Active",
                "frontDoorId": "fd-guid-1", "originResponseTimeoutSeconds": 60}
        })
    }

    fn topology() -> AfdTopology {
        let p = id("Microsoft.Cdn/profiles/afd-prod");
        AfdTopology {
            endpoints: vec![(
                json!({"id": format!("{}/afdEndpoints/ep-1", p), "name": "ep-1",
                    "properties": {"hostName": "ep-1-abc.z01.example-fd.net", "enabledState": "Enabled", "deploymentStatus": "Succeeded"}}),
                vec![json!({"id": format!("{}/afdEndpoints/ep-1/routes/rt-api", p), "name": "rt-api", "properties": {
                    "customDomains": [{"id": format!("{}/customDomains/api", p)}],
                    "originGroup": {"id": format!("{}/originGroups/og-aca", p)},
                    "supportedProtocols": ["Https"], "patternsToMatch": ["/*"], "forwardingProtocol": "HttpsOnly",
                    "linkToDefaultDomain": "Enabled", "httpsRedirect": "Enabled", "enabledState": "Enabled"}})],
            )],
            origin_groups: vec![(
                json!({"id": format!("{}/originGroups/og-aca", p), "name": "og-aca", "properties": {
                    "loadBalancingSettings": {"sampleSize": 4, "successfulSamplesRequired": 3, "additionalLatencyInMilliseconds": 50},
                    "healthProbeSettings": {"probePath": "/healthz", "probeRequestType": "HEAD", "probeProtocol": "Https", "probeIntervalInSeconds": 100},
                    "sessionAffinityState": "Disabled"}}),
                vec![
                    json!({"name": "o-aca", "properties": {"hostName": "api.happyhill-1.australiaeast.example-aca.io",
                        "httpPort": 80, "httpsPort": 443, "priority": 1, "weight": 1000, "enabledState": "Enabled",
                        "originHostHeader": "api.happyhill-1.australiaeast.example-aca.io",
                        "sharedPrivateLinkResource": {"privateLink": {"id": id("Microsoft.App/managedEnvironments/cae-prod")},
                            "privateLinkLocation": "australiaeast", "groupId": "managedEnvironments", "status": "Pending"}}}),
                    json!({"name": "o-web", "properties": {"hostName": "web-1.example-web.net", "priority": 2, "weight": 500,
                        "azureOrigin": {"id": id("Microsoft.Web/sites/web-1")}}})
                ],
            )],
            domains: vec![json!({"id": format!("{}/customDomains/api", p), "name": "api", "properties": {
                "hostName": "api.contoso.example", "domainValidationState": "Pending",
                "validationProperties": {"expirationDate": "2026-11-01"},
                "tlsSettings": {"certificateType": "CustomerCertificate", "minimumTlsVersion": "TLS12",
                    "secret": {"id": format!("{}/secrets/cert-api", p)}},
                "azureDnsZone": {"id": id("Microsoft.Network/dnszones/contoso.example")}, "deploymentStatus": "Succeeded"}})],
            security_policies: vec![json!({"name": "sp-1", "properties": {"parameters": {"type": "WebApplicationFirewall",
                "wafPolicy": {"id": id("Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/wafafd")},
                "associations": [{"domains": [{"id": format!("{}/customDomains/api", p)}], "patternsToMatch": ["/*"]}]}}})],
            warnings: vec!["routes of ep-2: forbidden".into()],
            truncated: vec![],
        }
    }

    #[test]
    fn a_front_door_profile_parses_and_classic_cdn_is_filtered() {
        let row = FrontDoorProfileRow::from_json(&profile_json("Premium_AzureFrontDoor"), None).unwrap();
        assert_eq!(row.base.location, "global");
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.list_summary().as_deref(), Some("Front Door Premium"));
        assert!(has(&row.details(), "Front Door id", "fd-guid-1"));
        assert!(row.cli_command().unwrap().starts_with("az afd profile show --ids "));
        let page = [profile_json("Premium_AzureFrontDoor"), profile_json("Standard_Microsoft"), profile_json("Standard_AzureFrontDoor")];
        assert_eq!(EdgeService::rows(JumpView::FrontDoorProfiles, &page, None).len(), 2, "classic CDN profiles are out");
    }

    #[test]
    fn front_door_sections_follow_route_origin_and_private_link() {
        let row = FrontDoorProfileRow::from_json(&profile_json("Premium_AzureFrontDoor"), None).unwrap();
        let topo = Lazy::Loaded(topology());
        let targets = BackendTargets::from_lists(TargetLists { environments: Some(&[env_row()]), ..Default::default() });
        let s = |sec| front_door_section_lines(&row, sec, Some(&topo), &targets, None);

        let ep = s(FrontDoorDetailSection::Endpoints);
        assert!(ep[0].1.starts_with("⚠ routes of ep-2"), "a failed child list is a warning line");
        assert!(has(&ep, "ep-1", "ep-1-abc.z01.example-fd.net · Succeeded"));
        assert!(has(&ep, "  Route · rt-api", "/* · Https → origin group og-aca"));
        assert!(has(&ep, "    Domains", "ep-1-abc.z01.example-fd.net, api.contoso.example"));
        assert!(has(&ep, "    → Origins", "api.happyhill-1.australiaeast.example-aca.io, web-1.example-web.net"));
        assert!(ep.iter().any(|(_, v)| v.starts_with("az afd endpoint list --profile-name afd-prod -g rg-edge")));

        let og = s(FrontDoorDetailSection::Origins);
        assert!(has(&og, "og-aca", "2 origins · probe Https HEAD /healthz every 100s"));
        assert!(has(&og, "  Used by routes", "ep-1/rt-api"));
        let (_, env) = line(&og, "    → Container Apps environment cae-prod");
        assert_eq!(JumpView::for_arm_id(env), Some(JumpView::ContainerAppEnvironments));
        let (_, pl) = line(&og, "    Private Link · cae-prod");
        assert_eq!(JumpView::for_arm_id(pl), Some(JumpView::ContainerAppEnvironments));
        assert!(has(&og, "      Status", "Pending · ⚠ approve it"));
        let (_, web) = line(&og, "    → Azure resource web-1");
        assert_eq!(JumpView::for_arm_id(web), Some(JumpView::WebApps));
        assert!(og.iter().any(|(_, v)| v.contains("no origin host header")), "o-web sends the client's host to App Service");

        let dom = s(FrontDoorDetailSection::Domains);
        assert!(has(&dom, "api.contoso.example", "validation Pending · ⚠ not validated"));
        assert!(has(&dom, "  Certificate", "CustomerCertificate · secret cert-api · min TLS TLS12"));
        let (_, zone) = line(&dom, "  Azure DNS zone · contoso.example");
        assert_eq!(JumpView::for_arm_id(zone), Some(JumpView::DnsZones));
        assert!(has(&dom, "  Routes", "ep-1/rt-api"));
        assert!(has(&dom, "  WAF", "wafafd"));

        let sec = s(FrontDoorDetailSection::Security);
        let (_, waf) = line(&sec, "  WAF policy · wafafd");
        assert_eq!(JumpView::for_arm_id(waf), Some(JumpView::WafPolicies));
        assert!(has(&sec, "  Applies to", "api.contoso.example · /*"));

        let rel = s(FrontDoorDetailSection::Related);
        let labels: Vec<&str> = rel.iter().map(|(l, _)| l.as_str()).collect();
        for want in ["WAF policy wafafd", "Origin o-web → web-1", "Origin o-aca → Container Apps environment cae-prod", "DNS zone contoso.example"] {
            assert!(labels.contains(&want), "{want} in {labels:?}");
        }
        let loading = front_door_section_lines(&row, FrontDoorDetailSection::Origins, None, &targets, None);
        assert!(has(&loading, "Origins", "Loading…"));
    }

    #[test]
    fn small_readers() {
        assert_eq!(
            top_level_of(&agw("httpListeners/l")).as_deref(),
            Some(id("Microsoft.Network/applicationGateways/agw-prod").as_str())
        );
        assert_eq!(top_level_of("/subscriptions/0/resourceGroups/rg"), None);
        assert_eq!(afd_child_path("/x/p/", "originGroups"), "/x/p/originGroups");
        assert_eq!(EdgeService::api_version_for(&id("Microsoft.Cdn/profiles/p")), CDN_API_VERSION);
        assert_eq!(EdgeService::api_version_for(&id("Microsoft.Network/frontdoorwebapplicationfirewallpolicies/w")), AFD_WAF_API_VERSION);
        assert_eq!(EdgeService::api_version_for(&id("Microsoft.Network/applicationGateways/g")), AGW_API_VERSION);
    }
}
