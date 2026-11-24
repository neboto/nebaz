//! API Management (#159, SERVICES.md rule 48): the API Management tab in
//! the Integration group, one subscription-wide list of
//! `Microsoft.ApiManagement/service`. An instance's APIs, products,
//! backends and named values are lazy sections, one list per instance
//! each (at most [`MAX_CHILDREN`]).
//!
//! Control plane only, and stricter than the GETs allow. **Never kept**:
//! a hostname or CA certificate's password and encoded certificate (ARM
//! should never echo them), a named value's `value` (a plain one comes
//! back in its GET; a secret one is a `listValue` POST), a backend's
//! credential values (its header and query values, the authorization
//! parameter, the proxy password), and the user-info and query string of
//! any URL a body carries (a backend URL can hold a key). All of it is
//! removed before a row or the lazy store keeps the JSON
//! ([`without_secrets`]). Subscriptions (the keys' owners), users, policies
//! and the gateway are never read; the gateway hostnames are shown as
//! text, never requested.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::directory::iso_to_unix;
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows_with, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable version (Microsoft Learn's REST reference lists
/// `2024-05-01` as current with `2025-09-01-preview` after it, checked
/// 2026-11-24).
pub const APIM_API_VERSION: &str = "2024-05-01";
const SERVICES_PATH: &str = "/providers/Microsoft.ApiManagement/service";

/// The most items a lazy list reads (APIs, products, backends, named
/// values) per instance.
pub const MAX_CHILDREN: usize = 500;

/// A custom hostname certificate this close to expiry is flagged.
const EXPIRY_WARN_DAYS: i64 = 30;

const NEVER_SECRETS: &str =
    "metadata from ARM; subscription keys, named value values and backend credentials are never read";

crate::sections! {
    pub enum ApimDetailSection,
    pub static APIM_SECTIONS = [
        Overview "Overview",
        Network "Network",
        Hostnames "Hostnames",
        Security "Security",
        Apis "APIs" => crate::app::App::trigger_apim_apis,
        Products "Products" => crate::app::App::trigger_apim_products,
        Backends "Backends" => crate::app::App::trigger_apim_backends,
        NamedValues "Named values" => crate::app::App::trigger_apim_named_values,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_apim_backends,
        Tags "Tags",
    ]
}

// ── Credentials out ───────────────────────────────────────────────────

/// Removed wherever they sit: a certificate's password and its encoded
/// body (hostname configurations, CA certificates, backend client
/// certificates).
const SECRET_FIELDS: &[&str] = &["certificatePassword", "encodedCertificate", "password"];

/// `https://user:pw@host/path?code=…` → `https://host/path?…`: the
/// user-info dropped, a query string replaced by `?…`.
pub fn strip_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (format!("{}://", s), r),
        None => (String::new(), url),
    };
    let (authority, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let host = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let (path, query) = match tail.split_once('?') {
        Some((p, _)) => (p, "?…"),
        None => (tail, ""),
    };
    let (host, query) = match host.split_once('?') {
        Some((h, _)) => (h, "?…"),
        None => (host, query),
    };
    format!("{}{}{}{}", scheme, host, path, query)
}

fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !SECRET_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(k)));
            for (k, val) in map.iter_mut() {
                if matches!(k.as_str(), "url" | "serviceUrl") {
                    if let Value::String(s) = val {
                        *s = strip_url(s);
                    }
                }
            }
            // A backend's credentials: the header and query *names*, the
            // authorization scheme; never a value or the parameter.
            if let Some(Value::Object(creds)) = map.get_mut("credentials") {
                for kind in ["header", "query"] {
                    if let Some(Value::Object(m)) = creds.get_mut(kind) {
                        for val in m.values_mut() {
                            *val = Value::Array(Vec::new());
                        }
                    }
                }
                if let Some(Value::Object(auth)) = creds.get_mut("authorization") {
                    auth.remove("parameter");
                }
            }
            map.values_mut().for_each(scrub);
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with every credential removed: what a row parses and keeps
/// for `e`, and what each lazy list stores. A named value (its `secret`
/// field says what it is) loses its `value` whether or not it is secret.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(props) = v.pointer_mut("/properties").and_then(Value::as_object_mut) {
        if props.contains_key("secret") {
            props.remove("value");
        }
    }
    scrub(&mut v);
    v
}

// ── The row ───────────────────────────────────────────────────────────

/// One `hostnameConfigurations` entry.
#[derive(Debug, Clone)]
pub struct Hostname {
    pub kind: String,
    pub host: String,
    pub source: Option<String>,
    pub key_vault_id: Option<String>,
    pub subject: Option<String>,
    pub expiry: Option<String>,
    pub thumbprint: Option<String>,
    pub status: Option<String>,
    pub negotiate_client_cert: Option<bool>,
    pub default_ssl: Option<bool>,
}

/// One `additionalLocations` entry.
#[derive(Debug, Clone)]
pub struct ExtraLocation {
    pub location: String,
    pub sku: Option<String>,
    pub capacity: Option<i64>,
    pub subnet_id: Option<String>,
    pub public_ips: Vec<String>,
    pub private_ips: Vec<String>,
    pub gateway_disabled: Option<bool>,
    pub platform: Option<String>,
    pub zones: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ApimServiceRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub capacity: Option<i64>,
    pub platform: Option<String>,
    pub vnet_type: Option<String>,
    pub subnet_id: Option<String>,
    pub public_ip_id: Option<String>,
    pub public_ips: Vec<String>,
    pub private_ips: Vec<String>,
    pub outbound_ips: Vec<String>,
    pub public_network_access: Option<String>,
    pub nat_gateway: Option<String>,
    pub gateway_url: Option<String>,
    pub gateway_regional_url: Option<String>,
    pub developer_portal_url: Option<String>,
    pub management_url: Option<String>,
    pub developer_portal: Option<String>,
    pub legacy_portal: Option<String>,
    pub publisher_name: Option<String>,
    pub publisher_email: Option<String>,
    pub created: Option<String>,
    pub gateway_disabled: Option<bool>,
    pub client_certificate: Option<bool>,
    pub min_api_version: Option<String>,
    pub legacy_config_api: Option<String>,
    pub hostnames: Vec<Hostname>,
    /// `(store, subject, expiry)` of each installed CA certificate.
    pub ca_certificates: Vec<(String, Option<String>, Option<String>)>,
    pub locations: Vec<ExtraLocation>,
    /// `customProperties`: protocol and cipher switches, as sent.
    pub custom: Vec<(String, String)>,
    pub private_endpoints: Vec<(String, Option<String>)>,
    pub zones: Vec<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
}

impl ApimServiceRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<ApimServiceRow> {
        let v = &without_secrets(raw);
        let mut base = ArmBase::from_json(v, tenant)?;
        // The list returns a display-name location (`East US`).
        base.location = base.location.replace(' ', "").to_lowercase();
        let p = |f: &str| format!("/properties/{}", f);
        let s = |f: &str| json::str_at(v, &p(f)).filter(|s| !s.is_empty());
        let mut custom: Vec<(String, String)> = v
            .pointer(&p("customProperties"))
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, val)| (k.clone(), json::str_at(val, "").unwrap_or_default())).collect())
            .unwrap_or_default();
        custom.sort();
        Some(ApimServiceRow {
            sku: json::str_at(v, "/sku/name"),
            capacity: json::int_at(v, "/sku/capacity"),
            platform: s("platformVersion"),
            vnet_type: s("virtualNetworkType"),
            subnet_id: json::arm_id(json::str_at(v, &p("virtualNetworkConfiguration/subnetResourceId"))),
            public_ip_id: json::arm_id(s("publicIpAddressId")),
            public_ips: json::strings_at(v, &p("publicIPAddresses")),
            private_ips: json::strings_at(v, &p("privateIPAddresses")),
            outbound_ips: json::strings_at(v, &p("outboundPublicIPAddresses")),
            public_network_access: s("publicNetworkAccess"),
            nat_gateway: s("natGatewayState"),
            gateway_url: s("gatewayUrl"),
            gateway_regional_url: s("gatewayRegionalUrl"),
            developer_portal_url: s("developerPortalUrl"),
            management_url: s("managementApiUrl"),
            developer_portal: s("developerPortalStatus"),
            legacy_portal: s("legacyPortalStatus"),
            publisher_name: s("publisherName"),
            publisher_email: s("publisherEmail"),
            created: s("createdAtUtc"),
            gateway_disabled: json::bool_at(v, &p("disableGateway")),
            client_certificate: json::bool_at(v, &p("enableClientCertificate")),
            min_api_version: s("apiVersionConstraint/minApiVersion"),
            legacy_config_api: s("configurationApi/legacyApi"),
            hostnames: json::arr(v, &p("hostnameConfigurations"))
                .iter()
                .map(|h| Hostname {
                    kind: json::text(h, "/type"),
                    host: json::text(h, "/hostName"),
                    source: json::str_at(h, "/certificateSource"),
                    key_vault_id: json::str_at(h, "/keyVaultId").filter(|s| !s.is_empty()),
                    subject: json::str_at(h, "/certificate/subject"),
                    expiry: json::str_at(h, "/certificate/expiry"),
                    thumbprint: json::str_at(h, "/certificate/thumbprint"),
                    status: json::str_at(h, "/certificateStatus"),
                    negotiate_client_cert: json::bool_at(h, "/negotiateClientCertificate"),
                    default_ssl: json::bool_at(h, "/defaultSslBinding"),
                })
                .collect(),
            ca_certificates: json::arr(v, &p("certificates"))
                .iter()
                .map(|c| {
                    (
                        json::text(c, "/storeName"),
                        json::str_at(c, "/certificate/subject"),
                        json::str_at(c, "/certificate/expiry"),
                    )
                })
                .collect(),
            locations: json::arr(v, &p("additionalLocations"))
                .iter()
                .map(|l| ExtraLocation {
                    location: json::text(l, "/location"),
                    sku: json::str_at(l, "/sku/name"),
                    capacity: json::int_at(l, "/sku/capacity"),
                    subnet_id: json::arm_id(json::str_at(l, "/virtualNetworkConfiguration/subnetResourceId")),
                    public_ips: json::strings_at(l, "/publicIPAddresses"),
                    private_ips: json::strings_at(l, "/privateIPAddresses"),
                    gateway_disabled: json::bool_at(l, "/disableGateway"),
                    platform: json::str_at(l, "/platformVersion"),
                    zones: json::strings_at(l, "/zones"),
                })
                .collect(),
            custom,
            private_endpoints: json::arr(v, &p("privateEndpointConnections"))
                .iter()
                .filter_map(|c| {
                    Some((
                        json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                        json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
                    ))
                })
                .collect(),
            zones: json::strings_at(v, "/zones"),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    /// `-n {n} -g {rg} --subscription {sub}`: `az apim` takes no `--ids`
    /// (`id_part=None` on `service_name` and `name`, checked 2026-11-24).
    fn name_args(&self) -> Option<String> {
        Some(format!(
            "-n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }

    /// The `--service-name` form the child commands take.
    fn child_args(&self) -> String {
        format!(
            "--service-name {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id).unwrap_or("-")),
            shell_quote(subscription_of(&self.base.id).unwrap_or("-"))
        )
    }

    fn read_command(&self, command: &str) -> (String, String) {
        ("Read command".into(), format!("{} {}", command, self.child_args()))
    }

    /// `Premium ×2`, `Consumption`.
    pub fn sku_text(&self) -> String {
        match (&self.sku, self.capacity) {
            (Some(s), Some(c)) if c > 0 => format!("{} ×{}", s, c),
            (Some(s), _) => s.clone(),
            _ => "-".into(),
        }
    }

    /// The stv1 compute platform was retired on 31 August 2024.
    pub fn on_retired_platform(&self) -> bool {
        self.platform.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("stv1"))
    }

    /// The old protocols (and 3DES) switched on, by their short key
    /// (`Security.Protocols.Tls10`): what `@audit`'s `apim-old-tls` reads.
    pub fn old_protocols_on(&self) -> Vec<String> {
        const OLD: &[&str] = &[
            "Security.Protocols.Tls10",
            "Security.Protocols.Tls11",
            "Security.Protocols.Ssl30",
            "Security.Backend.Protocols.Tls10",
            "Security.Backend.Protocols.Tls11",
            "Security.Backend.Protocols.Ssl30",
            "Security.Ciphers.TripleDes168",
        ];
        self.custom
            .iter()
            .filter_map(|(k, v)| {
                let key = k.strip_prefix("Microsoft.WindowsAzure.ApiManagement.Gateway.")?;
                (OLD.contains(&key) && v.eq_ignore_ascii_case("true")).then(|| key.to_string())
            })
            .collect()
    }

    /// Each custom hostname whose certificate expires within
    /// [`EXPIRY_WARN_DAYS`] of `now` (or has): `(hostname, expiry epoch)`.
    pub fn certificates_expiring(&self, now: i64) -> Vec<(&Hostname, i64)> {
        self.hostnames
            .iter()
            .filter_map(|h| Some((h, iso_to_unix(h.expiry.as_deref()?)?)))
            .filter(|(_, t)| *t - now <= EXPIRY_WARN_DAYS * 86_400)
            .collect()
    }

    fn platform_text(&self) -> String {
        match self.platform.as_deref() {
            Some(p) if self.on_retired_platform() => format!("⚠ {} (retired 31 August 2024: migrate to stv2)", p),
            Some(p) => p.to_string(),
            None => "-".into(),
        }
    }

    /// `none`, `External (snet-apim)`.
    fn vnet_text(&self) -> String {
        match (self.vnet_type.as_deref(), &self.subnet_id) {
            (None | Some("None"), _) => "none".into(),
            (Some(t), Some(sn)) => format!("{} ({})", t, name_of_id(sn)),
            (Some(t), None) => t.to_string(),
        }
    }

    pub fn network_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("VNet mode".into(), self.vnet_text())];
        if let Some(sn) = &self.subnet_id {
            lines.push((format!("Subnet · {}", name_of_id(sn)), sn.clone()));
        }
        if let Some(ip) = &self.public_ip_id {
            lines.push((format!("Public IP · {}", name_of_id(ip)), ip.clone()));
        }
        lines.push(("Public IPs".into(), json::join(&self.public_ips)));
        if !self.private_ips.is_empty() {
            lines.push(("Private IPs".into(), json::join(&self.private_ips)));
        }
        if !self.outbound_ips.is_empty() {
            lines.push(("Outbound IPs".into(), json::join(&self.outbound_ips)));
        }
        lines.push(("Public network access".into(), json::opt(self.public_network_access.clone())));
        lines.push(("NAT gateway".into(), json::opt(self.nat_gateway.clone())));
        lines.push(("Zones".into(), json::join(&self.zones)));
        if self.gateway_disabled == Some(true) {
            lines.push(("Gateway".into(), "disabled in the primary region".into()));
        }
        for (pe, status) in &self.private_endpoints {
            let st = match status.as_deref() {
                Some(s) if s.eq_ignore_ascii_case("approved") => s.to_string(),
                Some(s) => format!("⚠ {}", s),
                None => "-".into(),
            };
            lines.push((format!("Private endpoint · {} ({})", name_of_id(pe), st), pe.clone()));
        }
        for l in &self.locations {
            lines.push((String::new(), String::new()));
            let sku = match (&l.sku, l.capacity) {
                (Some(s), Some(c)) => format!("{} ×{}", s, c),
                (Some(s), None) => s.clone(),
                _ => "-".into(),
            };
            lines.push((format!("Region · {}", l.location), sku));
            if let Some(sn) = &l.subnet_id {
                lines.push((format!("  Subnet · {}", name_of_id(sn)), sn.clone()));
            }
            lines.push(("  Public IPs".into(), json::join(&l.public_ips)));
            if !l.private_ips.is_empty() {
                lines.push(("  Private IPs".into(), json::join(&l.private_ips)));
            }
            if let Some(p) = &l.platform {
                lines.push(("  Platform".into(), p.clone()));
            }
            if !l.zones.is_empty() {
                lines.push(("  Zones".into(), json::join(&l.zones)));
            }
            if l.gateway_disabled == Some(true) {
                lines.push(("  Gateway".into(), "disabled".into()));
            }
        }
        lines
    }

    /// A certificate's expiry with `⚠` when it is past or within
    /// [`EXPIRY_WARN_DAYS`].
    fn expiry_text(expiry: Option<&str>, now: i64) -> String {
        let Some(e) = expiry else { return "-".into() };
        let shown = json::time(Some(e.to_string()));
        match iso_to_unix(e) {
            Some(t) if t <= now => format!("⚠ {} (expired)", shown),
            Some(t) if t - now <= EXPIRY_WARN_DAYS * 86_400 => {
                // Rounded up: 11 days and 20 hours reads "in 12 days".
                format!("⚠ {} (in {} days)", shown, (t - now + 86_399) / 86_400)
            }
            _ => shown,
        }
    }

    pub fn hostname_rows(&self, now: i64) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Gateway".into(), json::opt(self.gateway_url.clone())),
            ("Regional gateway".into(), json::opt(self.gateway_regional_url.clone())),
            ("Developer portal".into(), json::opt(self.developer_portal_url.clone())),
            ("Management API".into(), json::opt(self.management_url.clone())),
        ];
        for h in &self.hostnames {
            lines.push((String::new(), String::new()));
            lines.push((format!("{} · {}", h.kind, h.host), String::new()));
            lines.push(("  Certificate".into(), json::opt(h.source.clone())));
            if h.subject.is_some() || h.expiry.is_some() {
                lines.push(("  Subject".into(), json::opt(h.subject.clone())));
                lines.push(("  Expires".into(), Self::expiry_text(h.expiry.as_deref(), now)));
            }
            if let Some(t) = &h.thumbprint {
                lines.push(("  Thumbprint".into(), t.clone()));
            }
            if let Some(kv) = &h.key_vault_id {
                // A Key Vault secret's URL: shown, never requested.
                lines.push(("  Key Vault secret".into(), kv.clone()));
            }
            if let Some(st) = &h.status {
                let flagged = if st.eq_ignore_ascii_case("failed") { format!("⚠ {}", st) } else { st.clone() };
                lines.push(("  Status".into(), flagged));
            }
            if h.negotiate_client_cert == Some(true) {
                lines.push(("  Client certificate".into(), "negotiated".into()));
            }
            if h.default_ssl == Some(true) {
                lines.push(("  Default SSL binding".into(), "yes".into()));
            }
        }
        lines
    }

    /// The client-side and backend protocol switches and the ciphers, by
    /// their `customProperties` key; `⚠` on an old protocol switched on.
    pub fn security_rows(&self, now: i64) -> Vec<(String, String)> {
        const PREFIX: &str = "Microsoft.WindowsAzure.ApiManagement.Gateway.";
        let mut lines = Vec::new();
        for (k, val) in &self.custom {
            let Some(key) = k.strip_prefix(PREFIX) else { continue };
            let on = val.eq_ignore_ascii_case("true");
            let (label, old) = match key {
                "Security.Protocols.Tls10" => ("Client TLS 1.0".to_string(), true),
                "Security.Protocols.Tls11" => ("Client TLS 1.1".to_string(), true),
                "Security.Protocols.Ssl30" => ("Client SSL 3.0".to_string(), true),
                "Security.Backend.Protocols.Tls10" => ("Backend TLS 1.0".to_string(), true),
                "Security.Backend.Protocols.Tls11" => ("Backend TLS 1.1".to_string(), true),
                "Security.Backend.Protocols.Ssl30" => ("Backend SSL 3.0".to_string(), true),
                "Security.Ciphers.TripleDes168" => ("3DES ciphers".to_string(), true),
                "Protocols.Server.Http2" => ("HTTP/2".to_string(), false),
                other => match other.strip_prefix("Security.Ciphers.") {
                    Some(c) => (format!("Cipher {}", c), false),
                    None => (other.to_string(), false),
                },
            };
            let word = if on { "enabled" } else { "disabled" };
            lines.push((label, if on && old { format!("⚠ {}", word) } else { word.to_string() }));
        }
        if lines.is_empty() {
            lines.push(("Protocols".into(), "the platform defaults (no settings in the body)".into()));
        }
        lines.push((String::new(), String::new()));
        lines.push((
            "Minimum API version".into(),
            match &self.min_api_version {
                Some(v) => v.clone(),
                None => "⚠ none: control-plane clients may use API versions older than 2019-12-01".into(),
            },
        ));
        lines.push(("Legacy configuration API".into(), json::opt(self.legacy_config_api.clone())));
        lines.push(("Developer portal".into(), json::opt(self.developer_portal.clone())));
        lines.push(("Legacy portal".into(), json::opt(self.legacy_portal.clone())));
        if self.client_certificate.is_some() {
            lines.push(("Client certificate required".into(), json::yes_no(self.client_certificate)));
        }
        lines.push(("Identity".into(), json::opt(self.identity_type.clone())));
        for id in &self.user_identity_ids {
            lines.push((format!("User identity · {}", name_of_id(id)), id.clone()));
        }
        for (store, subject, expiry) in &self.ca_certificates {
            lines.push((
                format!("CA certificate · {}", store),
                format!("{} · {}", json::opt(subject.clone()), Self::expiry_text(expiry.as_deref(), now)),
            ));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), NEVER_SECRETS.into()));
        lines
    }
}

impl Resource for ApimServiceRow {
    arm_row!("API Management");
    /// The provisioning ladder, with `Stopped` as stopped rather than a
    /// transition.
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&APIM_SECTIONS)
    }
    /// `Premium ×2 · stv2 · External VNet`.
    fn list_summary(&self) -> Option<String> {
        let mut parts = vec![self.sku_text()];
        if let Some(p) = &self.platform {
            parts.push(if self.on_retired_platform() { format!("⚠ {}", p) } else { p.clone() });
        }
        match self.vnet_type.as_deref() {
            Some("External") | Some("Internal") => parts.push(format!("{} VNet", self.vnet_type.as_deref().unwrap_or(""))),
            _ => {}
        }
        Some(parts.join(" · "))
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("SKU".into(), self.sku_text()),
            ("Platform".into(), self.platform_text()),
            ("VNet mode".into(), self.vnet_text()),
            ("Gateway".into(), json::opt(self.gateway_url.clone())),
            ("Developer portal".into(), json::opt(self.developer_portal_url.clone())),
        ];
        if !self.locations.is_empty() {
            let names: Vec<String> = self.locations.iter().map(|l| l.location.clone()).collect();
            lines.push(("Other regions".into(), names.join(", ")));
        }
        lines.push(("Publisher".into(), json::opt(self.publisher_name.clone())));
        lines.push(("Publisher email".into(), json::opt(self.publisher_email.clone())));
        lines.push(("Created".into(), json::time(self.created.clone())));
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        let mut push = |label: String, id: &String| {
            if !v.iter().any(|(_, e)| e.eq_ignore_ascii_case(id)) {
                v.push((label, id.clone()));
            }
        };
        if let Some(sn) = &self.subnet_id {
            push(format!("Subnet {}", name_of_id(sn)), sn);
        }
        if let Some(ip) = &self.public_ip_id {
            push(format!("Public IP {}", name_of_id(ip)), ip);
        }
        for l in &self.locations {
            if let Some(sn) = &l.subnet_id {
                push(format!("Subnet {} ({})", name_of_id(sn), l.location), sn);
            }
        }
        for (pe, _) in &self.private_endpoints {
            push(format!("Private endpoint {}", name_of_id(pe)), pe);
        }
        for id in &self.user_identity_ids {
            push(format!("Identity {}", name_of_id(id)), id);
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az apim show {}", self.name_args()?))
    }
}

impl ApimServiceRow {
    fn ladder(&self) -> (ResourceState, String) {
        match self.base.provisioning_state.as_deref() {
            Some(p) if p.eq_ignore_ascii_case("stopped") => state_ladder(None, Some((ResourceState::Stopped, "stopped"))),
            p => state_ladder(p, None),
        }
    }
}

// ── The lazy lists ────────────────────────────────────────────────────

/// The ARM path of one of an instance's child lists (`apis`, `products`,
/// `backends`, `namedValues`).
pub fn child_path(service_id: &str, child: &str) -> String {
    format!("{}/{}", service_id.trim_end_matches('/'), child)
}

/// The ARM id inside a backend's `resourceId`, which is a management URL
/// (`https://management.azure.com/subscriptions/…`) or a bare id.
pub fn backend_resource_id(v: &Value) -> Option<String> {
    let r = json::str_at(v, "/properties/resourceId")?;
    let i = r.to_lowercase().find("/subscriptions/")?;
    Some(r[i..].to_string())
}

fn capped_footer(lines: &mut Vec<(String, String)>, n: usize, what: &str) {
    if n >= MAX_CHILDREN {
        lines.push((String::new(), format!("⚠ the first {} {} only", MAX_CHILDREN, what)));
    }
}

/// The APIs body: by path, each with its type, protocols (`⚠` on plain
/// http), backend URL (its query string never kept), version and
/// revision.
pub fn api_rows(items: &[Value], r: &ApimServiceRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No APIs".into()));
    }
    let mut apis: Vec<&Value> = items.iter().collect();
    apis.sort_by_key(|a| json::text(a, "/properties/path").to_lowercase());
    for a in apis {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        let title = json::str_at(a, &p("displayName")).unwrap_or_else(|| json::text(a, "/name"));
        lines.push((title, format!("/{}", json::str_at(a, &p("path")).unwrap_or_default())));
        let kind = json::str_at(a, &p("type")).or_else(|| json::str_at(a, &p("apiType"))).unwrap_or_else(|| "http".into());
        lines.push(("  Type".into(), kind));
        let protocols = json::strings_at(a, &p("protocols"));
        let plain = protocols.iter().any(|p| p.eq_ignore_ascii_case("http"));
        let shown = json::join(&protocols);
        lines.push(("  Protocols".into(), if plain { format!("⚠ {} (plain http accepted)", shown) } else { shown }));
        lines.push(("  Backend".into(), json::opt(json::str_at(a, &p("serviceUrl")))));
        if let Some(v) = json::str_at(a, &p("apiVersion")).filter(|s| !s.is_empty()) {
            lines.push(("  Version".into(), v));
        }
        let rev = json::text(a, &p("apiRevision"));
        let current = json::bool_at(a, &p("isCurrent"));
        lines.push((
            "  Revision".into(),
            match current {
                Some(false) => format!("{} (not current)", rev),
                _ => rev,
            },
        ));
        lines.push(("  Subscription required".into(), json::yes_no(json::bool_at(a, &p("subscriptionRequired")))));
    }
    capped_footer(&mut lines, items.len(), "APIs");
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az apim api list"));
    lines
}

/// The Products body: each product's state and what it asks of a
/// subscriber. Never its subscriptions (they own the keys).
pub fn product_rows(items: &[Value], r: &ApimServiceRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No products".into()));
    }
    for pr in items {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        let title = json::str_at(pr, &p("displayName")).unwrap_or_else(|| json::text(pr, "/name"));
        let state = match json::str_at(pr, &p("state")).as_deref() {
            Some("published") => "published".to_string(),
            Some("notPublished") => "not published".to_string(),
            Some(s) => s.to_string(),
            None => "-".into(),
        };
        lines.push((title, state));
        let required = json::bool_at(pr, &p("subscriptionRequired"));
        lines.push((
            "  Subscription required".into(),
            match required {
                // Open products: anyone can call their APIs, no key.
                Some(false) => "⚠ no (its APIs need no key)".into(),
                other => json::yes_no(other),
            },
        ));
        lines.push(("  Approval required".into(), json::yes_no(json::bool_at(pr, &p("approvalRequired")))));
        if let Some(n) = json::int_at(pr, &p("subscriptionsLimit")) {
            lines.push(("  Subscriptions limit".into(), n.to_string()));
        }
    }
    capped_footer(&mut lines, items.len(), "products");
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az apim product list"));
    lines
}

/// A backend's credential kinds by name: `header Ocp-Key · query code ·
/// Basic authorization · client certificate`. The values were dropped
/// before the store kept the body.
fn credential_kinds(b: &Value) -> Option<String> {
    let c = b.get("properties")?.get("credentials")?;
    let mut parts = Vec::new();
    for kind in ["header", "query"] {
        if let Some(m) = c.get(kind).and_then(Value::as_object) {
            let mut names: Vec<&String> = m.keys().collect();
            names.sort();
            for n in names {
                parts.push(format!("{} {}", kind, n));
            }
        }
    }
    if let Some(s) = json::str_at(c, "/authorization/scheme") {
        parts.push(format!("{} authorization", s));
    }
    if !json::arr(c, "/certificateIds").is_empty() || !json::arr(c, "/certificate").is_empty() {
        parts.push("client certificate".into());
    }
    if c.get("managedIdentity").is_some_and(|m| !m.is_null()) {
        parts.push("managed identity".into());
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// The Backends body: each backend's URL (no query string), the Azure
/// resource it names (jumpable), its credential kinds, TLS checks (`⚠`
/// when one is off), and a pool's members.
/// (`az apim` has no backend commands, so no read command line.)
pub fn backend_rows(items: &[Value]) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No backends".into()));
    }
    for b in items {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        let title = json::str_at(b, &p("title")).filter(|s| !s.is_empty()).unwrap_or_else(|| json::text(b, "/name"));
        lines.push((title, json::str_at(b, &p("type")).unwrap_or_else(|| "Single".into())));
        if let Some(u) = json::str_at(b, &p("url")) {
            lines.push(("  URL".into(), u));
        }
        if let Some(proto) = json::str_at(b, &p("protocol")) {
            lines.push(("  Protocol".into(), proto));
        }
        if let Some(id) = backend_resource_id(b) {
            lines.push((format!("  Resource · {}", name_of_id(&id)), id));
        }
        if let Some(c) = credential_kinds(b) {
            lines.push(("  Credentials".into(), c));
        }
        for (field, label) in [("validateCertificateChain", "  Validates chain"), ("validateCertificateName", "  Validates name")] {
            if let Some(on) = json::bool_at(b, &p(&format!("tls/{}", field))) {
                lines.push((label.into(), if on { "yes".into() } else { "⚠ no".into() }));
            }
        }
        let members = json::arr(b, &p("pool/services"));
        if !members.is_empty() {
            let names: Vec<String> = members.iter().filter_map(|m| json::str_at(m, "/id")).map(|id| name_of_id(&id).to_string()).collect();
            lines.push(("  Pool".into(), names.join(", ")));
        }
        let rules = json::arr(b, &p("circuitBreaker/rules"));
        if !rules.is_empty() {
            lines.push(("  Circuit breaker".into(), format!("{} rule(s)", rules.len())));
        }
    }
    capped_footer(&mut lines, items.len(), "backends");
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "credentials: the kinds only, never a value".into()));
    lines
}

/// The Named values body: each name, whether it is secret or a Key Vault
/// reference (with its last refresh, `⚠` unless it succeeded). Never a
/// value, secret or not.
pub fn named_value_rows(items: &[Value], r: &ApimServiceRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No named values".into()));
    }
    let mut sorted: Vec<&Value> = items.iter().collect();
    sorted.sort_by_key(|n| json::text(n, "/properties/displayName").to_lowercase());
    for n in sorted {
        let p = |f: &str| format!("/properties/{}", f);
        let name = json::str_at(n, &p("displayName")).unwrap_or_else(|| json::text(n, "/name"));
        let kv = json::str_at(n, &p("keyVault/secretIdentifier"));
        let kind = if kv.is_some() {
            "Key Vault"
        } else if json::bool_at(n, &p("secret")) == Some(true) {
            "secret"
        } else {
            "plain"
        };
        lines.push((name, kind.into()));
        if let Some(kv) = kv {
            lines.push(("  Key Vault secret".into(), kv));
            if let Some(code) = json::str_at(n, &p("keyVault/lastStatus/code")) {
                let when = json::time(json::str_at(n, &p("keyVault/lastStatus/timeStampUtc")));
                let ok = code.eq_ignore_ascii_case("success");
                let msg = json::str_at(n, &p("keyVault/lastStatus/message")).filter(|m| !m.is_empty());
                lines.push((
                    "  Last refresh".into(),
                    match (ok, msg) {
                        (true, _) => format!("{} · {}", code, when),
                        (false, Some(m)) => format!("⚠ {} · {}: {}", code, when, m),
                        (false, None) => format!("⚠ {} · {}", code, when),
                    },
                ));
            }
        }
    }
    capped_footer(&mut lines, items.len(), "named values");
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "values are never read, secret or not".into()));
    lines.push(r.read_command("az apim nv list"));
    lines
}

/// What the instance's sections read beyond the row.
pub struct ApimLazy<'a> {
    pub apis: Option<&'a Lazy<Vec<Value>>>,
    pub products: Option<&'a Lazy<Vec<Value>>>,
    pub backends: Option<&'a Lazy<Vec<Value>>>,
    pub named_values: Option<&'a Lazy<Vec<Value>>>,
}

/// Body lines for one section of an API Management instance; `None` for
/// another type.
pub fn apim_section_lines(r: &dyn Resource, idx: usize, lazy: ApimLazy, now: i64) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<ApimServiceRow>()?;
    use ApimDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Network => x.network_rows(),
        S::Hostnames => x.hostname_rows(now),
        S::Security => x.security_rows(now),
        S::Apis => lazy_list_rows(lazy.apis, "APIs", |items| api_rows(items, x)),
        S::Products => lazy_list_rows(lazy.products, "Products", |items| product_rows(items, x)),
        S::Backends => lazy_list_rows(lazy.backends, "Backends", backend_rows),
        S::NamedValues => lazy_list_rows(lazy.named_values, "Named values", |items| named_value_rows(items, x)),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => {
            let extra = match lazy.backends {
                Some(Lazy::Loaded(items)) => items
                    .iter()
                    .filter_map(backend_resource_id)
                    .map(|id| (format!("Backend {}", name_of_id(&id)), id))
                    .collect(),
                _ => Vec::new(),
            };
            related_rows_with(x, extra)
        }
        S::Tags => tag_rows(x.tags()),
    })
}

fn rows(page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    page.iter()
        .filter_map(|v| ApimServiceRow::from_json(v, tenant))
        .map(|r| Box::new(r) as Box<dyn Resource>)
        .collect()
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct ApiManagementService {
    scope: Scope,
}

impl ApiManagementService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for ApiManagementService {
    fn service_type(&self) -> ServiceType {
        ServiceType::ApiManagement
    }

    fn name(&self) -> &str {
        "API Management"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        Ok(rows(&self.scope.list(SERVICES_PATH, APIM_API_VERSION).await?, self.scope.tenant()))
    }

    async fn list_resources_streaming(
        &self,
        _view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(SERVICES_PATH, APIM_API_VERSION, &[], service_type, "Listing API Management instances…", &event_tx, |page| {
                rows(&page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, APIM_API_VERSION).await?;
        rows(std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-api";
    /// 2026-11-24T00:00:00Z.
    const NOW: i64 = 1_795_478_400;

    fn svc_id() -> String {
        format!("{}/providers/Microsoft.ApiManagement/service/apim-shop", RG)
    }

    fn subnet() -> String {
        format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-apim", RG)
    }

    fn service(platform: &str) -> ApimServiceRow {
        ApimServiceRow::from_json(
            &json!({
                "id": svc_id(), "name": "apim-shop", "location": "West Europe",
                "sku": {"name": "Premium", "capacity": 2},
                "identity": {"type": "SystemAssigned"},
                "properties": {
                    "provisioningState": "Succeeded", "platformVersion": platform,
                    "virtualNetworkType": "External",
                    "virtualNetworkConfiguration": {"subnetResourceId": subnet()},
                    "publicIPAddresses": ["20.1.2.3"],
                    "gatewayUrl": "https://apim-shop.gateway.example",
                    "publisherName": "Contoso", "publisherEmail": "api@contoso.example",
                    "hostnameConfigurations": [
                        {"type": "Proxy", "hostName": "apim-shop.gateway.example", "certificateSource": "BuiltIn", "defaultSslBinding": false},
                        {"type": "Proxy", "hostName": "api.contoso.example", "certificateSource": "KeyVault",
                         "keyVaultId": "https://kv-shop.secrets.example/secrets/api-tls",
                         "certificatePassword": "pw-planted", "encodedCertificate": "MIIplanted",
                         "certificate": {"subject": "CN=api.contoso.example", "expiry": "2026-12-04T00:00:00Z", "thumbprint": "AB12"}}
                    ],
                    "certificates": [{"storeName": "Root", "encodedCertificate": "MIIroot", "certificatePassword": "pw2",
                                      "certificate": {"subject": "CN=Contoso Root", "expiry": "2025-01-01T00:00:00Z"}}],
                    "customProperties": {
                        "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10": "True",
                        "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11": "false",
                        "Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2": "true"
                    },
                    "additionalLocations": [{"location": "North Europe", "sku": {"name": "Premium", "capacity": 1},
                                             "publicIPAddresses": ["20.9.9.9"], "disableGateway": true}]
                }
            }),
            Some("t-1"),
        )
        .unwrap()
    }

    fn get<'a>(lines: &'a [(String, String)], key: &str) -> Option<&'a str> {
        lines.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn section_labels_keep_the_shared_order() {
        let labels: Vec<&str> = APIM_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            ["Overview", "Network", "Hostnames", "Security", "APIs", "Products", "Backends", "Named values", "Access", "Activity", "Related", "Tags"]
        );
    }

    #[test]
    fn an_instance_reads_its_sku_platform_and_network_and_the_name_form_command() {
        let row = service("stv2");
        assert_eq!(row.base.location, "westeurope");
        assert_eq!(row.list_summary().as_deref(), Some("Premium ×2 · stv2 · External VNet"));
        assert_eq!(row.cli_command().as_deref(), Some("az apim show -n apim-shop -g rg-api --subscription 0000"));
        assert_eq!(row.state(), ResourceState::stateless());
        let net = row.network_rows();
        assert_eq!(get(&net, "VNet mode"), Some("External (snet-apim)"));
        assert_eq!(get(&net, "Subnet · snet-apim"), Some(subnet().as_str()));
        assert_eq!(get(&net, "Region · North Europe"), Some("Premium ×1"));
        assert_eq!(get(&net, "  Gateway"), Some("disabled"));
        assert!(row.related().iter().any(|(_, id)| *id == subnet()));
    }

    #[test]
    fn stv1_is_flagged_and_a_stopped_instance_reads_stopped() {
        let row = service("stv1");
        assert!(row.on_retired_platform());
        assert!(get(&row.details(), "Platform").unwrap().starts_with("⚠ stv1"));
        assert_eq!(row.list_summary().as_deref(), Some("Premium ×2 · ⚠ stv1 · External VNet"));
        let mut stopped = row.clone();
        stopped.base.provisioning_state = Some("Stopped".into());
        assert_eq!(stopped.state(), ResourceState::Stopped);
        assert_eq!(stopped.state_label(), "stopped");
    }

    #[test]
    fn certificate_passwords_and_bodies_never_reach_the_row() {
        let row = service("stv2");
        for planted in ["pw-planted", "MIIplanted", "MIIroot", "pw2"] {
            assert!(!row.base.raw.contains(planted), "{planted}");
        }
        assert!(row.base.raw.contains("CN=api.contoso.example"), "the certificate's metadata stays");
    }

    #[test]
    fn hostnames_flag_a_certificate_near_expiry_and_security_an_old_protocol() {
        let row = service("stv2");
        let h = row.hostname_rows(NOW);
        assert!(h.iter().any(|(k, _)| k == "Proxy · api.contoso.example"));
        assert_eq!(get(&h, "  Expires"), Some("⚠ 2026-12-04 00:00:00 (in 10 days)"));
        assert_eq!(get(&h, "  Key Vault secret"), Some("https://kv-shop.secrets.example/secrets/api-tls"));
        let s = row.security_rows(NOW);
        assert_eq!(get(&s, "Client TLS 1.0"), Some("⚠ enabled"));
        assert_eq!(get(&s, "Client TLS 1.1"), Some("disabled"));
        assert_eq!(get(&s, "HTTP/2"), Some("enabled"));
        assert!(get(&s, "Minimum API version").unwrap().starts_with("⚠ none"));
        assert_eq!(get(&s, "CA certificate · Root"), Some("CN=Contoso Root · ⚠ 2025-01-01 00:00:00 (expired)"));
    }

    #[test]
    fn urls_lose_their_user_info_and_query_string() {
        assert_eq!(strip_url("https://u:p@fn.example/api/orders?code=abc"), "https://fn.example/api/orders?…");
        assert_eq!(strip_url("https://fn.example?code=abc"), "https://fn.example?…");
        assert_eq!(strip_url("https://fn.example/api"), "https://fn.example/api");
        assert_eq!(strip_url("http://10.0.0.4:8080"), "http://10.0.0.4:8080");
    }

    #[test]
    fn a_backend_keeps_its_credential_names_and_never_a_value() {
        let func = format!("{}/providers/Microsoft.Web/sites/func-orders", RG);
        let raw = json!({"name": "orders-fn", "properties": {
            "url": "https://func-orders.example/api?code=planted-query", "protocol": "http",
            "resourceId": format!("https://management.example{}", func),
            "credentials": {"header": {"x-functions-key": ["planted-header"]}, "query": {"code": ["planted-q2"]},
                            "authorization": {"scheme": "Basic", "parameter": "planted-auth"}},
            "proxy": {"url": "http://proxy.example", "username": "u", "password": "planted-proxy"},
            "tls": {"validateCertificateChain": true, "validateCertificateName": false}
        }});
        let kept = without_secrets(&raw);
        let text = kept.to_string();
        for planted in ["planted-query", "planted-header", "planted-q2", "planted-auth", "planted-proxy"] {
            // Never print the body: on a failure it would hold the value.
            assert!(!text.contains(planted), "{planted} survived the scrub");
        }
        let lines = backend_rows(&[kept]);
        assert_eq!(get(&lines, "  URL"), Some("https://func-orders.example/api?…"));
        assert_eq!(get(&lines, "  Credentials"), Some("header x-functions-key · query code · Basic authorization"));
        assert!(lines.iter().any(|(k, v)| k == "  Resource · func-orders" && *v == func));
        assert_eq!(get(&lines, "  Validates name"), Some("⚠ no"));
    }

    #[test]
    fn a_named_value_never_keeps_its_value_and_a_failed_key_vault_refresh_is_flagged() {
        let plain = json!({"name": "env", "properties": {"displayName": "env", "secret": false, "value": "planted-plain"}});
        let kv = json!({"name": "db", "properties": {"displayName": "db-password", "secret": true,
            "keyVault": {"secretIdentifier": "https://kv-shop.secrets.example/secrets/db",
                         "lastStatus": {"code": "Forbidden", "message": "no access policy", "timeStampUtc": "2026-11-23T08:00:00Z"}}}});
        let items: Vec<Value> = [plain, kv].iter().map(without_secrets).collect();
        assert!(!Value::Array(items.clone()).to_string().contains("planted-plain"));
        let lines = named_value_rows(&items, &service("stv2"));
        assert_eq!(get(&lines, "env"), Some("plain"));
        assert_eq!(get(&lines, "db-password"), Some("Key Vault"));
        assert_eq!(get(&lines, "  Last refresh"), Some("⚠ Forbidden · 2026-11-23 08:00:00: no access policy"));
        assert_eq!(lines.last().unwrap().1, "az apim nv list --service-name apim-shop -g rg-api --subscription 0000");
    }

    #[test]
    fn apis_sort_by_path_and_flag_plain_http_and_products_an_open_one() {
        let row = service("stv2");
        let apis = vec![
            json!({"name": "orders", "properties": {"displayName": "Orders", "path": "orders", "protocols": ["https"],
                   "serviceUrl": "https://ca-orders.example", "apiRevision": "3", "isCurrent": true, "subscriptionRequired": true}}),
            json!({"name": "echo", "properties": {"displayName": "Echo", "path": "echo", "protocols": ["http", "https"],
                   "apiRevision": "1", "isCurrent": true}}),
        ];
        let lines = api_rows(&apis, &row);
        let titles: Vec<&str> = lines.iter().filter(|(k, v)| !k.is_empty() && !k.starts_with(' ') && v.starts_with('/')).map(|(k, _)| k.as_str()).collect();
        assert_eq!(titles, ["Echo", "Orders"]);
        assert!(lines.iter().any(|(k, v)| k == "  Protocols" && v.starts_with("⚠ http, https")));
        let products = vec![json!({"name": "starter", "properties": {"displayName": "Starter", "state": "published",
                                    "subscriptionRequired": false}})];
        let lines = product_rows(&products, &row);
        assert_eq!(get(&lines, "Starter"), Some("published"));
        assert_eq!(get(&lines, "  Subscription required"), Some("⚠ no (its APIs need no key)"));

        let lazy = ApimLazy { apis: Some(&Lazy::Loading), products: None, backends: None, named_values: None };
        let loading = apim_section_lines(&row, ApimDetailSection::Apis as usize, lazy, NOW).unwrap();
        assert_eq!(loading[0].1, "Loading…");
        assert_eq!(child_path(&row.base.id, "apis"), format!("{}/apis", svc_id()));
    }
}
