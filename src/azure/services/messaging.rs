//! The Messaging service (issue #27): Service Bus and Event Hubs
//! namespaces (`Microsoft.ServiceBus`, `Microsoft.EventHub`), two
//! subscription-wide lists. The entities are lazy sections, one call per
//! namespace each: queues and topics, or event hubs. So are the network
//! rule set (`{ns}/networkRuleSets/default`: the IP and VNet rules, the
//! default action and trusted services are not on the namespace body)
//! and the shared access policies (names and rights).
//!
//! **Keys never.** A shared access policy's keys and connection strings
//! come only from `{rule}/listKeys`, a POST nebaz never sends; the guard
//! names the `az … authorization-rule keys` commands forbidden. No GET
//! body carries a key today, but [`without_secrets`] strips any
//! key-shaped field before a row keeps its JSON, so a future api-version
//! that adds one cannot reach a section, search or the raw view (`e`).
//!
//! The namespace endpoint (the AMQP / Kafka / HTTPS host) is data plane:
//! shown as text, never requested.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    arm_row, error_rows, finish_stream, json, lazy_list_rows, overview_rows, related_lines, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable versions (azure-rest-api-specs, checked 2026-10-24;
/// both released there 2026-06-17). The live check confirms them;
/// `2024-01-01` is the previous stable for both.
pub const SERVICEBUS_API_VERSION: &str = "2026-01-01";
pub const EVENTHUB_API_VERSION: &str = "2026-01-01";
const SERVICEBUS_PATH: &str = "/providers/Microsoft.ServiceBus/namespaces";
const EVENTHUB_PATH: &str = "/providers/Microsoft.EventHub/namespaces";

const NEVER_KEYS: &str = "names and rights only; keys and connection strings are never fetched (only a POST returns them)";

crate::sections! {
    pub enum ServiceBusDetailSection,
    pub static SERVICEBUS_SECTIONS = [
        Overview "Overview",
        Network "Network" => crate::app::App::trigger_messaging_network,
        Security "Security",
        Queues "Queues" => crate::app::App::trigger_sb_queues,
        Topics "Topics" => crate::app::App::trigger_sb_topics,
        AuthRules "Access policies" => crate::app::App::trigger_messaging_auth_rules,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_messaging_network,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum EventHubsDetailSection,
    pub static EVENTHUBS_SECTIONS = [
        Overview "Overview",
        Network "Network" => crate::app::App::trigger_messaging_network,
        Security "Security",
        Hubs "Event hubs" => crate::app::App::trigger_eh_hubs,
        AuthRules "Access policies" => crate::app::App::trigger_messaging_auth_rules,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_eh_related,
        Tags "Tags",
    ]
}

// ── Credentials out of the JSON ───────────────────────────────────────

/// Fields that hold a shared access key or a connection string built
/// from one: the `listKeys` response's shape, should any GET ever echo it.
const SECRET_FIELDS: &[&str] = &[
    "primaryKey",
    "secondaryKey",
    "primaryConnectionString",
    "secondaryConnectionString",
    "aliasPrimaryConnectionString",
    "aliasSecondaryConnectionString",
    "connectionString",
    "sasKey",
];

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

/// The body with every key-shaped field removed, at any depth: what a row
/// parses and keeps for `e`, and what a lazy section renders from.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

/// The envelope of a scrubbed body. Both providers return a display-name
/// location (`Australia East`); stored as `australiaeast` so `R` matches.
fn base_of(v: &Value, tenant: Option<&str>) -> Option<ArmBase> {
    let mut base = ArmBase::from_json(v, tenant)?;
    base.location = base.location.replace(' ', "");
    Some(base)
}

/// The api-version for a namespace or one of its children, by provider.
pub fn api_version_for(id: &str) -> &'static str {
    if id.to_ascii_lowercase().contains("/providers/microsoft.eventhub/") {
        EVENTHUB_API_VERSION
    } else {
        SERVICEBUS_API_VERSION
    }
}

/// The ARM path of a namespace's child (`queues`, `topics`, `eventhubs`,
/// `authorizationRules`, `networkRuleSets/default`).
pub fn messaging_child_path(namespace_id: &str, child: &str) -> String {
    format!("{}/{}", namespace_id.trim_end_matches('/'), child)
}

// ── What both namespace kinds share ───────────────────────────────────

#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub id: String,
    pub client_id: Option<String>,
    pub principal_id: Option<String>,
}

/// One private endpoint connection on the namespace body.
#[derive(Debug, Clone)]
pub struct PrivateEndpointConn {
    /// The private endpoint's ARM id (Enter jumps to it).
    pub endpoint_id: Option<String>,
    /// `Approved`, `Pending`, `Rejected`, `Disconnected`.
    pub status: Option<String>,
    pub description: Option<String>,
    pub provisioning: Option<String>,
}

/// One customer-managed key.
#[derive(Debug, Clone)]
pub struct CmKey {
    pub name: String,
    /// A Key Vault URL, not an ARM id: text.
    pub vault_uri: Option<String>,
    pub version: Option<String>,
    /// The user-assigned identity that reads the key.
    pub identity: Option<String>,
}

/// The namespace body both providers share (the same spec shape).
#[derive(Debug, Clone)]
pub struct Namespace {
    pub sku_name: Option<String>,
    pub sku_tier: Option<String>,
    pub capacity: Option<i64>,
    pub status: Option<String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    /// `https://{ns}.{suffix}:443/`: the data plane, text only.
    pub endpoint: Option<String>,
    pub zone_redundant: Option<bool>,
    pub min_tls: Option<String>,
    pub disable_local_auth: Option<bool>,
    pub public_network_access: Option<String>,
    pub alternate_name: Option<String>,
    pub ip_address_type: Option<String>,
    pub key_source: Option<String>,
    pub infrastructure_encryption: Option<bool>,
    pub keys: Vec<CmKey>,
    pub confidential_compute: Option<String>,
    pub private_endpoints: Vec<PrivateEndpointConn>,
    pub identity_type: Option<String>,
    pub principal_id: Option<String>,
    pub user_identities: Vec<UserIdentity>,
    /// `(location, role, state)` for each geo-replication replica.
    pub replicas: Vec<(String, String, String)>,
    pub max_replication_lag: Option<i64>,
}

impl Namespace {
    /// From a scrubbed body.
    fn from_json(v: &Value) -> Namespace {
        let p = |k: &str| format!("/properties/{}", k);
        let mut user_identities: Vec<UserIdentity> = v
            .pointer("/identity/userAssignedIdentities")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(id, u)| UserIdentity {
                        id: id.clone(),
                        client_id: json::str_at(u, "/clientId"),
                        principal_id: json::str_at(u, "/principalId"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        user_identities.sort_by(|a, b| a.id.cmp(&b.id));
        Namespace {
            sku_name: json::str_at(v, "/sku/name"),
            sku_tier: json::str_at(v, "/sku/tier"),
            capacity: json::int_at(v, "/sku/capacity"),
            status: json::str_at(v, &p("status")),
            created: json::str_at(v, &p("createdAt")),
            updated: json::str_at(v, &p("updatedAt")),
            endpoint: json::str_at(v, &p("serviceBusEndpoint")).filter(|s| !s.is_empty()),
            zone_redundant: json::bool_at(v, &p("zoneRedundant")),
            min_tls: json::str_at(v, &p("minimumTlsVersion")),
            disable_local_auth: json::bool_at(v, &p("disableLocalAuth")),
            public_network_access: json::str_at(v, &p("publicNetworkAccess")),
            alternate_name: json::str_at(v, &p("alternateName")).filter(|s| !s.is_empty()),
            ip_address_type: json::str_at(v, &p("ipAddressType")),
            key_source: json::str_at(v, &p("encryption/keySource")),
            infrastructure_encryption: json::bool_at(v, &p("encryption/requireInfrastructureEncryption")),
            keys: json::arr(v, &p("encryption/keyVaultProperties"))
                .iter()
                .map(|k| CmKey {
                    name: json::text(k, "/keyName"),
                    vault_uri: json::str_at(k, "/keyVaultUri").filter(|s| !s.is_empty()),
                    version: json::str_at(k, "/keyVersion").filter(|s| !s.is_empty()),
                    identity: json::arm_id(json::str_at(k, "/identity/userAssignedIdentity")),
                })
                .collect(),
            confidential_compute: json::str_at(v, &p("platformCapabilities/confidentialCompute/mode")),
            private_endpoints: json::arr(v, &p("privateEndpointConnections"))
                .iter()
                .map(|c| PrivateEndpointConn {
                    endpoint_id: json::arm_id(json::id_at(c, "/properties/privateEndpoint")),
                    status: json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
                    description: json::str_at(c, "/properties/privateLinkServiceConnectionState/description")
                        .filter(|s| !s.is_empty()),
                    provisioning: json::str_at(c, "/properties/provisioningState"),
                })
                .collect(),
            identity_type: json::str_at(v, "/identity/type"),
            principal_id: json::str_at(v, "/identity/principalId"),
            user_identities,
            replicas: json::arr(v, &p("geoDataReplication/locations"))
                .iter()
                .map(|l| (json::text(l, "/locationName"), json::text(l, "/roleType"), json::text(l, "/replicaState")))
                .collect(),
            max_replication_lag: json::int_at(v, &p("geoDataReplication/maxReplicationLagDurationInSeconds")),
        }
    }

    /// The endpoint's host, `{ns}.{suffix}`, without scheme or port.
    pub fn host(&self) -> Option<String> {
        let e = self.endpoint.as_deref()?;
        let host = e.split("://").nth(1).unwrap_or(e);
        let host = host.split(['/', ':']).next().unwrap_or(host);
        (!host.is_empty()).then(|| host.to_string())
    }

    /// The private DNS zone a private endpoint caller needs: `privatelink.`
    /// before the endpoint's suffix (built from the body, so a sovereign
    /// cloud's suffix comes out right).
    pub fn private_dns_zone(&self) -> Option<String> {
        let host = self.host()?;
        let (_, suffix) = host.split_once('.')?;
        Some(format!("privatelink.{}", suffix))
    }

    fn ladder(&self, provisioning: Option<&str>) -> (ResourceState, String) {
        let runtime = self.status.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "active" => ResourceState::Available,
                "disabled" | "suspended" => ResourceState::Stopped,
                "failed" | "unknown" => ResourceState::Unavailable,
                "creating" | "activating" | "enabling" => ResourceState::Creating,
                "deleting" | "removing" | "removed" | "softdeleting" | "softdeleted" => ResourceState::Deleting,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(provisioning, runtime)
    }

    fn tier(&self) -> &str {
        self.sku_tier.as_deref().or(self.sku_name.as_deref()).unwrap_or("-")
    }

    fn is_tier(&self, tier: &str) -> bool {
        self.tier().eq_ignore_ascii_case(tier)
    }

    fn private_only(&self) -> bool {
        self.public_network_access.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("disabled"))
    }

    fn local_auth_label(&self) -> String {
        match self.disable_local_auth {
            Some(true) => "disabled · Microsoft Entra ID only; SAS keys and connection strings are refused".into(),
            Some(false) => "enabled · SAS keys and connection strings work alongside Entra ID".into(),
            None => "-".into(),
        }
    }

    fn system_assigned(&self) -> bool {
        self.identity_type.as_deref().is_some_and(|t| t.to_lowercase().contains("systemassigned"))
    }

    /// Scope, private endpoints, user-assigned identities, then a key's
    /// identity the identity block does not already list.
    fn related(&self, id: &str) -> Vec<(String, String)> {
        let mut v = scope_related(id);
        for pe in self.private_endpoints.iter().filter_map(|c| c.endpoint_id.as_ref()) {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        for u in &self.user_identities {
            v.push((format!("Identity {}", name_of_id(&u.id)), u.id.clone()));
        }
        for k in &self.keys {
            if let Some(i) = &k.identity {
                if !v.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(i)) {
                    v.push((format!("Key identity {}", name_of_id(i)), i.clone()));
                }
            }
        }
        v
    }

    /// The Security section: local (SAS) auth, TLS, encryption and the
    /// managed identity (user-assigned lines jump to the Identity row).
    fn security_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Local auth (SAS)".into(), self.local_auth_label()),
            ("Minimum TLS".into(), json::opt(self.min_tls.clone())),
        ];
        lines.push((String::new(), String::new()));
        let cmk = self.key_source.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("Microsoft.KeyVault")) || !self.keys.is_empty();
        lines.push((
            "Encryption".into(),
            if cmk { "customer-managed keys (Key Vault)".into() } else { "Microsoft-managed keys".into() },
        ));
        for k in &self.keys {
            lines.push((
                format!("  Key · {}", k.name),
                format!("version {}", k.version.clone().unwrap_or_else(|| "latest (auto-rotated)".into())),
            ));
            lines.push(("    Vault".into(), json::opt(k.vault_uri.clone())));
            match &k.identity {
                Some(i) => lines.push((format!("    Read by · {}", name_of_id(i)), i.clone())),
                None => lines.push(("    Read by".into(), "system-assigned identity".into())),
            }
        }
        lines.push(("Infrastructure encryption".into(), json::yes_no(self.infrastructure_encryption)));
        if let Some(mode) = &self.confidential_compute {
            lines.push(("Confidential compute".into(), mode.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.extend(self.identity_rows());
        lines
    }

    fn identity_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("Identity".into(), json::opt(self.identity_type.clone()))];
        if self.system_assigned() {
            lines.push(("System-assigned principal".into(), json::opt(self.principal_id.clone())));
        }
        for u in &self.user_identities {
            lines.push((format!("User-assigned · {}", name_of_id(&u.id)), u.id.clone()));
            lines.push(("  Client id".into(), json::opt(u.client_id.clone())));
            lines.push(("  Principal id".into(), json::opt(u.principal_id.clone())));
        }
        if !self.system_assigned() && self.user_identities.is_empty() {
            lines.push((String::new(), "· no managed identity (needed only for customer-managed keys or capture)".into()));
        }
        lines
    }

    /// The Network section: who can reach the data plane, and how a
    /// private caller resolves it. The namespace body gives public
    /// access, private endpoints, TLS and local auth; the rule set
    /// (`rules`, lazy) gives the default action, trusted services and the
    /// IP and VNet rules.
    fn network_rows(&self, family: Family, rules: Option<&Lazy<Value>>, name_args: Option<String>) -> Vec<(String, String)> {
        let rule_set = match rules {
            Some(Lazy::Loaded(v)) => Some(v),
            _ => None,
        };
        let rp = |k: &str| rule_set.and_then(|r| json::str_at(r, &format!("/properties/{}", k)));
        let pna = rp("publicNetworkAccess").or_else(|| self.public_network_access.clone());
        let default_action = rp("defaultAction");
        let trusted = rule_set.and_then(|r| json::bool_at(r, "/properties/trustedServiceAccessEnabled"));
        let ip_rules = rule_set.map(|r| json::arr(r, "/properties/ipRules")).unwrap_or_default();
        let vnet_rules = rule_set.map(|r| json::arr(r, "/properties/virtualNetworkRules")).unwrap_or_default();
        let approved = self
            .private_endpoints
            .iter()
            .filter(|c| c.status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("approved")))
            .count();

        let effective = match pna.as_deref().map(str::to_lowercase).as_deref() {
            Some("disabled") => format!("private endpoints only ({} approved)", approved),
            Some("securedbyperimeter") => "the network security perimeter's access rules decide".to_string(),
            _ => match (rules, default_action.as_deref().map(str::to_lowercase).as_deref()) {
                (None | Some(Lazy::Loading), _) => "public · loading the firewall…".to_string(),
                (Some(Lazy::Error(_)), _) => "public · the firewall could not be read".to_string(),
                (_, Some("deny")) if ip_rules.is_empty() && vnet_rules.is_empty() => {
                    "⚠ every network: Deny is not enforced without at least one IP or VNet rule".to_string()
                }
                (_, Some("deny")) => {
                    let mut parts = vec![format!("{} IP rules", ip_rules.len()), format!("{} VNet subnets", vnet_rules.len())];
                    if approved > 0 {
                        parts.push(format!("{} private endpoints", approved));
                    }
                    if trusted == Some(true) {
                        parts.push("trusted Microsoft services".into());
                    }
                    format!("only {}", parts.join(" · "))
                }
                _ => "every network (the internet), with a key or Entra token".to_string(),
            },
        };

        let mut lines = vec![
            ("Effective access".into(), effective),
            ("Public network access".into(), json::opt(pna.clone())),
        ];
        match rules {
            None | Some(Lazy::Loading) => lines.push(("Firewall".into(), "Loading…".into())),
            Some(Lazy::Error(e)) => lines.extend(error_rows(e)),
            Some(Lazy::Loaded(_)) => {
                let action = match default_action.as_deref() {
                    Some(a) if a.eq_ignore_ascii_case("allow") => {
                        "Allow · every network; the IP and VNet rules below are kept but not enforced".to_string()
                    }
                    Some(a) if a.eq_ignore_ascii_case("deny") => "Deny · only the IP and VNet rules below (and private endpoints)".to_string(),
                    other => json::opt(other.map(str::to_string)),
                };
                lines.push(("Default action".into(), action));
                lines.push((
                    "Trusted services".into(),
                    match trusted {
                        Some(true) => "yes · trusted Microsoft services bypass the firewall".into(),
                        Some(false) => "no".into(),
                        None => "-".into(),
                    },
                ));
                lines.push((String::new(), String::new()));
                lines.push((
                    "IP rules".into(),
                    if ip_rules.is_empty() { "none".into() } else { format!("{}", ip_rules.len()) },
                ));
                for r in &ip_rules {
                    lines.push((
                        format!("  {}", json::str_at(r, "/action").unwrap_or_else(|| "Allow".into()).to_lowercase()),
                        json::text(r, "/ipMask"),
                    ));
                }
                lines.push((
                    "VNet rules".into(),
                    if vnet_rules.is_empty() { "none".into() } else { format!("{}", vnet_rules.len()) },
                ));
                for r in &vnet_rules {
                    match json::arm_id(json::id_at(r, "/subnet")) {
                        // The value is the subnet's ARM id: Enter jumps.
                        Some(s) => lines.push((format!("  Subnet · {}", subnet_label(&s)), s)),
                        None => lines.push(("  Subnet".into(), json::text(r, "/subnet/id"))),
                    }
                    if json::bool_at(r, "/ignoreMissingVnetServiceEndpoint") == Some(true) {
                        lines.push((
                            String::new(),
                            format!("    · kept even if the subnet lacks the {} service endpoint", family.provider()),
                        ));
                    }
                }
                if !vnet_rules.is_empty() {
                    lines.push((
                        String::new(),
                        format!("· a VNet rule admits a subnet only with the {} service endpoint on it", family.provider()),
                    ));
                }
            }
        }

        lines.push((String::new(), String::new()));
        lines.push((
            "Private endpoints".into(),
            if self.private_endpoints.is_empty() { "none".into() } else { self.private_endpoints.len().to_string() },
        ));
        for c in &self.private_endpoints {
            let state = match (&c.status, &c.description) {
                (Some(s), Some(d)) => format!("{} · {}", s, d),
                (Some(s), None) => s.clone(),
                (None, _) => "-".into(),
            };
            match &c.endpoint_id {
                Some(pe) => lines.push((format!("  Private endpoint · {}", name_of_id(pe)), pe.clone())),
                None => lines.push(("  Private endpoint".into(), "-".into())),
            }
            lines.push(("    Connection".into(), state));
            if let Some(p) = c.provisioning.as_deref().filter(|p| !p.eq_ignore_ascii_case("succeeded")) {
                lines.push(("    Provisioning".into(), p.to_string()));
            }
        }

        lines.push((String::new(), String::new()));
        lines.push(("Endpoint".into(), json::opt(self.host())));
        if let (Some(host), Some(zone)) = (self.host(), self.private_dns_zone()) {
            lines.push(("Private DNS zone".into(), zone.clone()));
            if !self.private_endpoints.is_empty() {
                let ns = host.split('.').next().unwrap_or_default();
                lines.push((
                    String::new(),
                    format!("· from a VNet, {} must resolve to the endpoint's private IP: {}.{} linked to the caller's VNet", host, ns, zone),
                ));
                lines.push((
                    String::new(),
                    "· for Container Apps, the environment's VNet; for Power Platform, the VNet of the delegated subnet".into(),
                ));
            }
        }
        lines.push(("IP address type".into(), json::opt(self.ip_address_type.clone())));
        lines.push(("Minimum TLS".into(), json::opt(self.min_tls.clone())));
        lines.push(("Local auth (SAS)".into(), self.local_auth_label()));
        if let Some(note) = family.tier_note(self) {
            lines.push((String::new(), String::new()));
            lines.push((String::new(), note.into()));
        }
        if let Some(args) = name_args {
            lines.push((String::new(), String::new()));
            // Spelled out per family so the guard reads each verb.
            let cmd = match family {
                Family::ServiceBus => format!("az servicebus namespace network-rule-set list {}", args),
                Family::EventHubs => format!("az eventhubs namespace network-rule-set list {}", args),
            };
            lines.push(("Read command".into(), cmd));
        }
        lines
    }
}

/// `vnet/subnet` from a subnet id.
fn subnet_label(id: &str) -> String {
    let parts: Vec<&str> = id.trim_end_matches('/').split('/').collect();
    match parts.iter().rposition(|p| p.eq_ignore_ascii_case("subnets")) {
        Some(i) if i >= 2 && i + 1 < parts.len() => format!("{}/{}", parts[i - 1], parts[i + 1]),
        _ => name_of_id(id).to_string(),
    }
}

/// Which provider a namespace belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    ServiceBus,
    EventHubs,
}

impl Family {
    fn provider(self) -> &'static str {
        match self {
            Family::ServiceBus => "Microsoft.ServiceBus",
            Family::EventHubs => "Microsoft.EventHub",
        }
    }

    /// What the tier cannot do, when it limits the network picture.
    fn tier_note(self, ns: &Namespace) -> Option<&'static str> {
        match self {
            Family::ServiceBus if !ns.is_tier("premium") => {
                Some("· VNet rules and private endpoints need the Premium tier; this namespace is reachable only publicly")
            }
            Family::EventHubs if ns.is_tier("basic") => {
                Some("· the Basic tier has no IP firewall, VNet rules or private endpoints: reachable only publicly")
            }
            _ => None,
        }
    }
}

/// `--namespace-name {n} -g {rg} --subscription {sub}`: the entity and
/// rule-set `list` commands reset `id_part`, so they take the name form.
fn namespace_args(base: &ArmBase) -> Option<String> {
    Some(format!(
        "--namespace-name {} -g {} --subscription {}",
        shell_quote(&base.name),
        shell_quote(resource_group_of(&base.id)?),
        shell_quote(subscription_of(&base.id)?)
    ))
}

/// An ISO-8601 duration as `1m`, `14d`, `1h 30m`; .NET's `TimeSpan.MaxValue`
/// (`P10675199DT2H48M5.4775807S`, the default TTL) as `never`.
pub fn duration(s: Option<String>) -> String {
    let Some(s) = s.filter(|s| !s.is_empty()) else {
        return "-".into();
    };
    let body = match s.strip_prefix('P') {
        Some(b) => b,
        None => return s.clone(),
    };
    let (date, time) = body.split_once('T').unwrap_or((body, ""));
    let mut parts = Vec::new();
    let mut num = String::new();
    for (chunk, units) in [(date, [('Y', "y"), ('M', "mo"), ('W', "w"), ('D', "d")]), (time, [('H', "h"), ('M', "m"), ('S', "s"), ('\0', "")])] {
        for c in chunk.chars() {
            if c.is_ascii_digit() || c == '.' {
                num.push(c);
                continue;
            }
            let Some((_, unit)) = units.iter().find(|(u, _)| *u == c) else {
                return s.clone();
            };
            if c == 'D' && num.parse::<f64>().is_ok_and(|d| d >= 10_675_199.0) {
                return "never".into();
            }
            let n = num.parse::<f64>().map(|n| n.trunc() as i64).unwrap_or(0);
            if n != 0 {
                parts.push(format!("{}{}", n, unit));
            }
            num.clear();
        }
    }
    if parts.is_empty() {
        "0s".into()
    } else {
        parts.join(" ")
    }
}

/// `12.3 MB` from bytes.
fn bytes(n: Option<i64>) -> String {
    match n {
        None => "-".into(),
        Some(b) if b < 1024 => format!("{} B", b),
        Some(b) if b < 1024 * 1024 => format!("{:.1} KB", b as f64 / 1024.0),
        Some(b) if b < 1024 * 1024 * 1024 => format!("{:.1} MB", b as f64 / 1024.0 / 1024.0),
        Some(b) => format!("{:.1} GB", b as f64 / 1024.0 / 1024.0 / 1024.0),
    }
}

/// Items sorted by name, scrubbed.
fn sorted(items: &[Value]) -> Vec<Value> {
    let mut items: Vec<Value> = items.iter().map(without_secrets).collect();
    items.sort_by_key(|v| json::text(v, "/name").to_lowercase());
    items
}

/// `Active` is the norm; anything else is called out.
fn status_note(v: &Value) -> String {
    match json::str_at(v, "/properties/status") {
        Some(s) if s.eq_ignore_ascii_case("active") => String::new(),
        Some(s) => format!(" · ⚠ {}", s),
        None => String::new(),
    }
}

/// The Access policies section (shared access authorization rules):
/// each rule's name and rights. Keys never.
pub fn auth_rule_rows(items: &[Value], ns: &Namespace, family: Family, base: &ArmBase) -> Vec<(String, String)> {
    let mut lines = vec![(String::new(), NEVER_KEYS.into())];
    if ns.disable_local_auth == Some(true) {
        lines.push((String::new(), "· local auth is disabled: these policies are not accepted".into()));
    }
    lines.push((String::new(), String::new()));
    let items = sorted(items);
    if items.is_empty() {
        lines.push((String::new(), "No shared access policies".into()));
    }
    for r in &items {
        let rights = json::strings_at(r, "/properties/rights");
        lines.push((json::text(r, "/name"), json::join(&rights)));
    }
    if let Some(args) = namespace_args(base) {
        lines.push((String::new(), String::new()));
        let cmd = match family {
            Family::ServiceBus => format!("az servicebus namespace authorization-rule list {}", args),
            Family::EventHubs => format!("az eventhubs namespace authorization-rule list {}", args),
        };
        lines.push(("Read command".into(), cmd));
    }
    lines
}

// ── Service Bus namespace ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ServiceBusRow {
    pub base: ArmBase,
    pub ns: Namespace,
    pub premium_partitions: Option<i64>,
}

impl ServiceBusRow {
    /// Parses a namespace with any key-shaped field stripped first.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ServiceBusRow> {
        let v = &without_secrets(v);
        let base = base_of(v, tenant)?;
        Some(ServiceBusRow {
            ns: Namespace::from_json(v),
            premium_partitions: json::int_at(v, "/properties/premiumMessagingPartitions"),
            base,
        })
    }

    fn sku_label(&self) -> String {
        match (self.ns.is_tier("premium"), self.ns.capacity) {
            (true, Some(c)) => format!("{} · {} messaging units", self.ns.tier(), c),
            _ => self.ns.tier().to_string(),
        }
    }
}

impl Resource for ServiceBusRow {
    arm_row!("Service Bus namespace");
    /// `Premium · 2 MU`, `Standard`; `· private` when public access is off.
    fn list_summary(&self) -> Option<String> {
        let mut s = match (self.ns.is_tier("premium"), self.ns.capacity) {
            (true, Some(c)) => format!("{} · {} MU", self.ns.tier(), c),
            _ => self.ns.tier().to_string(),
        };
        if self.ns.private_only() {
            s.push_str(" · private");
        }
        Some(s)
    }
    fn state(&self) -> ResourceState {
        self.ns.ladder(self.base.provisioning_state.as_deref()).0
    }
    fn state_label(&self) -> String {
        self.ns.ladder(self.base.provisioning_state.as_deref()).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SERVICEBUS_SECTIONS)
    }
    /// The endpoint host is searchable: a connection string's host finds
    /// its namespace.
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.ns.host().unwrap_or_default(),
            self.ns.tier(),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Status".into(), json::opt(self.ns.status.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), self.sku_label()),
        ];
        if let Some(p) = self.premium_partitions {
            lines.push(("Messaging partitions".into(), p.to_string()));
        }
        lines.extend(common_details(&self.ns));
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        self.ns.related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az servicebus namespace show --ids {}", shell_quote(&self.base.id)))
    }
}

/// The Overview lines both kinds share, after the SKU.
fn common_details(ns: &Namespace) -> Vec<(String, String)> {
    let mut lines = vec![
        ("Zone redundant".into(), json::yes_no(ns.zone_redundant)),
        ("Endpoint".into(), json::opt(ns.host())),
        ("Public network access".into(), json::opt(ns.public_network_access.clone())),
        ("Private endpoints".into(), ns.private_endpoints.len().to_string()),
        ("Local auth (SAS)".into(), match ns.disable_local_auth {
            Some(true) => "disabled".into(),
            Some(false) => "enabled".into(),
            None => "-".into(),
        }),
        ("Minimum TLS".into(), json::opt(ns.min_tls.clone())),
        ("Identity".into(), json::opt(ns.identity_type.clone())),
    ];
    if let Some(a) = &ns.alternate_name {
        lines.push(("Alternate name (geo-DR)".into(), a.clone()));
    }
    if !ns.replicas.is_empty() {
        let replicas: Vec<String> = ns.replicas.iter().map(|(l, role, state)| format!("{} ({}, {})", l, role, state)).collect();
        lines.push(("Geo-replication".into(), json::join(&replicas)));
        if let Some(lag) = ns.max_replication_lag {
            lines.push(("  Max replication lag".into(), format!("{}s", lag)));
        }
    }
    lines.push(("Created".into(), json::time(ns.created.clone())));
    lines.push(("Updated".into(), json::time(ns.updated.clone())));
    lines
}

pub fn servicebus_section_lines(
    r: &ServiceBusRow,
    section: ServiceBusDetailSection,
    rules: Option<&Lazy<Value>>,
    queues: Option<&Lazy<Vec<Value>>>,
    topics: Option<&Lazy<Vec<Value>>>,
    auth: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        ServiceBusDetailSection::Overview => overview_rows(r),
        ServiceBusDetailSection::Network => r.ns.network_rows(Family::ServiceBus, rules, namespace_args(&r.base)),
        ServiceBusDetailSection::Security => r.ns.security_rows(),
        ServiceBusDetailSection::Queues => lazy_list_rows(queues, "Queues", |items| queue_rows(items, &r.base)),
        ServiceBusDetailSection::Topics => lazy_list_rows(topics, "Topics", |items| topic_rows(items, &r.base)),
        ServiceBusDetailSection::AuthRules => {
            lazy_list_rows(auth, "Access policies", |items| auth_rule_rows(items, &r.ns, Family::ServiceBus, &r.base))
        }
        ServiceBusDetailSection::Access => crate::azure::services::rendered_by_app(),
        ServiceBusDetailSection::Activity => crate::azure::services::rendered_by_app(),
        ServiceBusDetailSection::Related => related_lines(with_rule_subnets(r.related(), rules)),
        ServiceBusDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The Related lines plus each VNet rule's subnet, once the rule set is
/// loaded.
fn with_rule_subnets(mut rel: Vec<(String, String)>, rules: Option<&Lazy<Value>>) -> Vec<(String, String)> {
    if let Some(Lazy::Loaded(r)) = rules {
        for rule in json::arr(r, "/properties/virtualNetworkRules") {
            if let Some(s) = json::arm_id(json::id_at(&rule, "/subnet")) {
                if !rel.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(&s)) {
                    rel.push((format!("VNet rule subnet {}", subnet_label(&s)), s));
                }
            }
        }
    }
    rel
}

/// The Queues section body from `GET {ns}/queues`: counts from the ARM
/// body's `countDetails` (no data plane), with the settings that explain
/// a stuck consumer (lock duration, sessions, max deliveries, forwarding).
pub fn queue_rows(items: &[Value], base: &ArmBase) -> Vec<(String, String)> {
    let items = sorted(items);
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No queues".into()));
    }
    for q in &items {
        let p = |k: &str| format!("/properties/{}", k);
        let active = json::int_at(q, &p("countDetails/activeMessageCount"));
        let dead = json::int_at(q, &p("countDetails/deadLetterMessageCount")).unwrap_or(0);
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        let warn = if dead > 0 { " · ⚠ dead letters" } else { "" };
        lines.push((
            json::text(q, "/name"),
            format!("{} active · {} dead-lettered{}{}", json::num(active), dead, warn, status_note(q)),
        ));
        lines.push((
            "  Scheduled / transfer".into(),
            format!(
                "{} / {} (transfer dead-lettered {})",
                json::num(json::int_at(q, &p("countDetails/scheduledMessageCount"))),
                json::num(json::int_at(q, &p("countDetails/transferMessageCount"))),
                json::num(json::int_at(q, &p("countDetails/transferDeadLetterMessageCount")))
            ),
        ));
        lines.push((
            "  Size".into(),
            format!("{} of {} MB", bytes(json::int_at(q, &p("sizeInBytes"))), json::num(json::int_at(q, &p("maxSizeInMegabytes")))),
        ));
        lines.push(("  Lock duration".into(), duration(json::str_at(q, &p("lockDuration")))));
        lines.push(("  Max deliveries".into(), json::num(json::int_at(q, &p("maxDeliveryCount")))));
        lines.push(("  Sessions".into(), json::yes_no(json::bool_at(q, &p("requiresSession")))));
        lines.push((
            "  Duplicate detection".into(),
            match json::bool_at(q, &p("requiresDuplicateDetection")) {
                Some(true) => format!("yes · {}", duration(json::str_at(q, &p("duplicateDetectionHistoryTimeWindow")))),
                b => json::yes_no(b),
            },
        ));
        lines.push(("  Message TTL".into(), duration(json::str_at(q, &p("defaultMessageTimeToLive")))));
        lines.push((
            "  Dead-letter on expiry".into(),
            json::yes_no(json::bool_at(q, &p("deadLetteringOnMessageExpiration"))),
        ));
        lines.push(("  Partitioned".into(), json::yes_no(json::bool_at(q, &p("enablePartitioning")))));
        for (label, key) in [("  Forward to", "forwardTo"), ("  Forward dead letters to", "forwardDeadLetteredMessagesTo")] {
            if let Some(to) = json::str_at(q, &p(key)).filter(|s| !s.is_empty()) {
                lines.push((label.into(), to));
            }
        }
        lines.push(("  Last accessed".into(), json::time(json::str_at(q, &p("accessedAt")))));
    }
    if let Some(args) = namespace_args(base) {
        lines.push((String::new(), String::new()));
        lines.push(("Read command".into(), format!("az servicebus queue list {}", args)));
    }
    lines
}

/// The Topics section body from `GET {ns}/topics`. A topic's
/// subscriptions are one call per topic, so only their count shows.
pub fn topic_rows(items: &[Value], base: &ArmBase) -> Vec<(String, String)> {
    let items = sorted(items);
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No topics".into()));
    }
    for t in &items {
        let p = |k: &str| format!("/properties/{}", k);
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        lines.push((
            json::text(t, "/name"),
            format!(
                "{} subscriptions · {}{}",
                json::num(json::int_at(t, &p("subscriptionCount"))),
                bytes(json::int_at(t, &p("sizeInBytes"))),
                status_note(t)
            ),
        ));
        lines.push(("  Max size".into(), format!("{} MB", json::num(json::int_at(t, &p("maxSizeInMegabytes"))))));
        lines.push(("  Message TTL".into(), duration(json::str_at(t, &p("defaultMessageTimeToLive")))));
        lines.push(("  Duplicate detection".into(), json::yes_no(json::bool_at(t, &p("requiresDuplicateDetection")))));
        lines.push(("  Ordering".into(), json::yes_no(json::bool_at(t, &p("supportOrdering")))));
        lines.push(("  Partitioned".into(), json::yes_no(json::bool_at(t, &p("enablePartitioning")))));
        lines.push(("  Last accessed".into(), json::time(json::str_at(t, &p("accessedAt")))));
    }
    if let Some(args) = namespace_args(base) {
        lines.push((String::new(), String::new()));
        lines.push(("Read command".into(), format!("az servicebus topic list {}", args)));
        lines.push((
            String::new(),
            "· a topic's subscriptions: az servicebus topic subscription list --topic-name {topic} with the same arguments".into(),
        ));
    }
    lines
}

// ── Event Hubs namespace ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EventHubsRow {
    pub base: ArmBase,
    pub ns: Namespace,
    pub auto_inflate: Option<bool>,
    pub max_throughput_units: Option<i64>,
    pub kafka: Option<bool>,
    /// The dedicated cluster the namespace runs on.
    pub cluster_id: Option<String>,
}

impl EventHubsRow {
    /// Parses a namespace with any key-shaped field stripped first.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<EventHubsRow> {
        let v = &without_secrets(v);
        let base = base_of(v, tenant)?;
        Some(EventHubsRow {
            ns: Namespace::from_json(v),
            auto_inflate: json::bool_at(v, "/properties/isAutoInflateEnabled"),
            max_throughput_units: json::int_at(v, "/properties/maximumThroughputUnits").filter(|n| *n > 0),
            kafka: json::bool_at(v, "/properties/kafkaEnabled"),
            cluster_id: json::arm_id(json::str_at(v, "/properties/clusterArmId")),
            base,
        })
    }

    /// The capacity unit the tier counts in: throughput units (Standard,
    /// Basic), processing units (Premium), capacity units (Dedicated).
    fn unit(&self, short: bool) -> &'static str {
        match (self.ns.tier().to_lowercase().as_str(), short) {
            ("premium", true) => "PU",
            ("premium", false) => "processing units",
            ("dedicated", true) => "CU",
            ("dedicated", false) => "capacity units",
            (_, true) => "TU",
            (_, false) => "throughput units",
        }
    }
}

impl Resource for EventHubsRow {
    arm_row!("Event Hubs namespace");
    /// `Standard · 2 TU`; `· private` when public access is off.
    fn list_summary(&self) -> Option<String> {
        let mut s = match self.ns.capacity {
            Some(c) => format!("{} · {} {}", self.ns.tier(), c, self.unit(true)),
            None => self.ns.tier().to_string(),
        };
        if self.ns.private_only() {
            s.push_str(" · private");
        }
        Some(s)
    }
    fn state(&self) -> ResourceState {
        self.ns.ladder(self.base.provisioning_state.as_deref()).0
    }
    fn state_label(&self) -> String {
        self.ns.ladder(self.base.provisioning_state.as_deref()).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&EVENTHUBS_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.ns.host().unwrap_or_default(),
            self.ns.tier(),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let inflate = match (self.auto_inflate, self.max_throughput_units) {
            (Some(true), Some(max)) => format!("yes · up to {} {}", max, self.unit(false)),
            (b, _) => json::yes_no(b),
        };
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Status".into(), json::opt(self.ns.status.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), self.ns.tier().to_string()),
            (
                format!("Capacity ({})", self.unit(false)),
                json::num(self.ns.capacity),
            ),
            ("Auto-inflate".into(), inflate),
            ("Kafka".into(), json::yes_no(self.kafka)),
        ];
        if let Some(c) = &self.cluster_id {
            lines.push(("Dedicated cluster".into(), name_of_id(c).to_string()));
        }
        lines.extend(common_details(&self.ns));
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = self.ns.related(&self.base.id);
        if let Some(c) = &self.cluster_id {
            v.push((format!("Dedicated cluster {}", name_of_id(c)), c.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az eventhubs namespace show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn eventhubs_section_lines(
    r: &EventHubsRow,
    section: EventHubsDetailSection,
    rules: Option<&Lazy<Value>>,
    hubs: Option<&Lazy<Vec<Value>>>,
    auth: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        EventHubsDetailSection::Overview => overview_rows(r),
        EventHubsDetailSection::Network => r.ns.network_rows(Family::EventHubs, rules, namespace_args(&r.base)),
        EventHubsDetailSection::Security => r.ns.security_rows(),
        EventHubsDetailSection::Hubs => lazy_list_rows(hubs, "Event hubs", |items| hub_rows(items, &r.base)),
        EventHubsDetailSection::AuthRules => {
            lazy_list_rows(auth, "Access policies", |items| auth_rule_rows(items, &r.ns, Family::EventHubs, &r.base))
        }
        EventHubsDetailSection::Access => crate::azure::services::rendered_by_app(),
        EventHubsDetailSection::Activity => crate::azure::services::rendered_by_app(),
        EventHubsDetailSection::Related => {
            let mut rel = with_rule_subnets(r.related(), rules);
            if let Some(Lazy::Loaded(items)) = hubs {
                for (hub, account) in capture_accounts(items) {
                    if !rel.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(&account)) {
                        rel.push((format!("Capture storage {} (from {})", name_of_id(&account), hub), account));
                    }
                }
            }
            related_lines(rel)
        }
        EventHubsDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// `(hub, storage account id)` for every hub that captures to a storage
/// account.
fn capture_accounts(items: &[Value]) -> Vec<(String, String)> {
    items
        .iter()
        .filter(|h| json::bool_at(h, "/properties/captureDescription/enabled") == Some(true))
        .filter_map(|h| {
            json::arm_id(json::str_at(h, "/properties/captureDescription/destination/properties/storageAccountResourceId"))
                .map(|a| (json::text(h, "/name"), a))
        })
        .collect()
}

/// The Event hubs section body from `GET {ns}/eventhubs`: partitions,
/// retention, status and capture (destination account as an ARM id,
/// Enter jumps).
pub fn hub_rows(items: &[Value], base: &ArmBase) -> Vec<(String, String)> {
    let items = sorted(items);
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No event hubs".into()));
    }
    for h in &items {
        let p = |k: &str| format!("/properties/{}", k);
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        let capture_on = json::bool_at(h, &p("captureDescription/enabled")) == Some(true);
        lines.push((
            json::text(h, "/name"),
            format!(
                "{} partitions · capture {}{}",
                json::num(json::int_at(h, &p("partitionCount"))),
                if capture_on { "on" } else { "off" },
                status_note(h)
            ),
        ));
        let retention = match (
            json::int_at(h, &p("retentionDescription/retentionTimeInHours")),
            json::int_at(h, &p("messageRetentionInDays")),
        ) {
            (Some(hours), _) if hours % 24 == 0 => format!("{} days", hours / 24),
            (Some(hours), _) => format!("{} hours", hours),
            (None, Some(days)) => format!("{} days", days),
            (None, None) => "-".into(),
        };
        let policy = json::str_at(h, &p("retentionDescription/cleanupPolicy"))
            .map(|c| format!(" · {}", c.to_lowercase()))
            .unwrap_or_default();
        lines.push(("  Retention".into(), format!("{}{}", retention, policy)));
        if capture_on {
            let c = "captureDescription";
            let d = format!("{}/destination", c);
            lines.push((
                "  Capture".into(),
                format!(
                    "{} · every {}s or {} · {}",
                    json::text(h, &p(&format!("{}/encoding", c))),
                    json::text(h, &p(&format!("{}/intervalInSeconds", c))),
                    bytes(json::int_at(h, &p(&format!("{}/sizeLimitInBytes", c)))),
                    if json::bool_at(h, &p(&format!("{}/skipEmptyArchives", c))) == Some(true) { "skips empty" } else { "writes empty" },
                ),
            ));
            match json::arm_id(json::str_at(h, &p(&format!("{}/properties/storageAccountResourceId", d)))) {
                Some(acct) => lines.push((format!("  → Storage · {}", name_of_id(&acct)), acct)),
                None => {
                    if let Some(lake) = json::str_at(h, &p(&format!("{}/properties/dataLakeAccountName", d))) {
                        lines.push(("  → Data Lake".into(), lake));
                    }
                }
            }
            for (label, key) in [("    Container", "blobContainer"), ("    Folder", "dataLakeFolderPath"), ("    Name format", "archiveNameFormat")] {
                if let Some(v) = json::str_at(h, &p(&format!("{}/properties/{}", d, key))).filter(|s| !s.is_empty()) {
                    lines.push((label.into(), v));
                }
            }
            match (
                json::str_at(h, &p(&format!("{}/identity/type", d))),
                json::arm_id(json::str_at(h, &p(&format!("{}/identity/userAssignedIdentity", d)))),
            ) {
                (_, Some(uami)) => lines.push((format!("    Writes as · {}", name_of_id(&uami)), uami)),
                (Some(t), None) => lines.push(("    Writes as".into(), t)),
                (None, None) => {}
            }
        }
        lines.push(("  Created".into(), json::time(json::str_at(h, &p("createdAt")))));
    }
    if let Some(args) = namespace_args(base) {
        lines.push((String::new(), String::new()));
        lines.push(("Read command".into(), format!("az eventhubs eventhub list {}", args)));
        lines.push((
            String::new(),
            "· a hub's consumer groups: az eventhubs eventhub consumer-group list --eventhub-name {hub} with the same arguments".into(),
        ));
    }
    lines
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct MessagingService {
    scope: Scope,
}

impl MessagingService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::EventHubNamespaces => page
                .iter()
                .filter_map(|v| EventHubsRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
            _ => page
                .iter()
                .filter_map(|v| ServiceBusRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
        }
    }

    fn list_of(view: JumpView) -> (&'static str, &'static str, &'static str) {
        match view {
            JumpView::EventHubNamespaces => (EVENTHUB_PATH, EVENTHUB_API_VERSION, "Listing Event Hubs namespaces…"),
            _ => (SERVICEBUS_PATH, SERVICEBUS_API_VERSION, "Listing Service Bus namespaces…"),
        }
    }
}

#[async_trait]
impl AzureService for MessagingService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Messaging
    }

    fn name(&self) -> &str {
        "Messaging"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, version, _) = Self::list_of(view);
        Ok(Self::rows(view, &self.scope.list(path, version).await?, self.scope.tenant()))
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let (path, version, label) = Self::list_of(view);
        let r = self
            .scope
            .stream(path, version, &[], service_type, label, &event_tx, |page| {
                Self::rows(view, &page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, api_version_for(id)).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::ServiceBusNamespaces);
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-msg";

    fn sb_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.ServiceBus/namespaces/sb-prod", RG),
            "name": "sb-prod",
            "location": "Australia East",
            "sku": {"name": "Premium", "tier": "Premium", "capacity": 2},
            "identity": {
                "type": "SystemAssigned, UserAssigned",
                "principalId": "p-system",
                "userAssignedIdentities": {
                    format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-sb", RG):
                        {"clientId": "c-sb", "principalId": "p-sb"}
                }
            },
            "properties": {
                "provisioningState": "Succeeded",
                "status": "Active",
                "serviceBusEndpoint": "https://sb-prod.servicebus.windows.net:443/",
                "zoneRedundant": true,
                "minimumTlsVersion": "1.2",
                "disableLocalAuth": true,
                "publicNetworkAccess": "Enabled",
                "premiumMessagingPartitions": 1,
                "createdAt": "2026-01-02T03:04:05Z",
                "encryption": {"keySource": "Microsoft.KeyVault", "requireInfrastructureEncryption": true,
                    "keyVaultProperties": [{"keyName": "sb-key", "keyVaultUri": "https://kv-msg.vault.azure.net",
                        "identity": {"userAssignedIdentity": format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-cmk", RG)}}]},
                "privateEndpointConnections": [{
                    "id": format!("{}/providers/Microsoft.ServiceBus/namespaces/sb-prod/privateEndpointConnections/c1", RG),
                    "properties": {
                        "privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-sb", RG)},
                        "privateLinkServiceConnectionState": {"status": "Approved", "description": "auto-approved"},
                        "provisioningState": "Succeeded"
                    }
                }],
                // Not in any GET today; stripped if a version ever adds it.
                "primaryConnectionString": "Endpoint=sb://x/;SharedAccessKey=leaked-key-1",
                "primaryKey": "leaked-key-2"
            }
        })
    }

    fn eh_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.EventHub/namespaces/eh-prod", RG),
            "name": "eh-prod",
            "location": "Australia East",
            "sku": {"name": "Standard", "tier": "Standard", "capacity": 2},
            "properties": {
                "provisioningState": "Succeeded",
                "status": "Active",
                "serviceBusEndpoint": "https://eh-prod.servicebus.windows.net:443/",
                "isAutoInflateEnabled": true,
                "maximumThroughputUnits": 10,
                "kafkaEnabled": true,
                "publicNetworkAccess": "Disabled",
                "disableLocalAuth": false,
                "clusterArmId": "",
                "privateEndpointConnections": []
            }
        })
    }

    fn rules(default_action: &str, ip: bool, vnet: bool) -> Value {
        let mut ip_rules = vec![];
        if ip {
            ip_rules.push(serde_json::json!({"ipMask": "203.0.113.0/24", "action": "Allow"}));
        }
        let mut vnet_rules = vec![];
        if vnet {
            vnet_rules.push(serde_json::json!({
                "subnet": {"id": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-aca/subnets/snet-infra", RG)},
                "ignoreMissingVnetServiceEndpoint": true
            }));
        }
        serde_json::json!({"name": "default", "properties": {
            "publicNetworkAccess": "Enabled",
            "defaultAction": default_action,
            "trustedServiceAccessEnabled": true,
            "ipRules": ip_rules,
            "virtualNetworkRules": vnet_rules
        }})
    }

    fn has(lines: &[(String, String)], k: &str, v: &str) -> bool {
        lines.iter().any(|(a, b)| a == k && b.starts_with(v))
    }

    #[test]
    fn section_labels_put_overview_first_and_access_activity_related_tags_last() {
        for desc in [&SERVICEBUS_SECTIONS, &EVENTHUBS_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(&labels[labels.len() - 4..], ["Access", "Activity", "Related", "Tags"]);
            assert!(labels.contains(&"Network") && labels.contains(&"Security") && labels.contains(&"Access policies"));
        }
        let sb: Vec<&str> = SERVICEBUS_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert!(sb.contains(&"Queues") && sb.contains(&"Topics"));
        assert!(EVENTHUBS_SECTIONS.sections.iter().any(|s| s.label == "Event hubs"));
    }

    #[test]
    fn service_bus_row_reads_state_overview_and_related() {
        let row = ServiceBusRow::from_json(&sb_json(), None).unwrap();
        assert_eq!(row.base.location, "australiaeast");
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "active");
        assert_eq!(row.list_summary().as_deref(), Some("Premium · 2 MU"));
        assert!(has(&row.details(), "SKU", "Premium · 2 messaging units"));
        assert!(has(&row.details(), "Endpoint", "sb-prod.servicebus"));
        assert!(row.search_text().contains("sb-prod.servicebus"));
        let related = row.related();
        let labels: Vec<&str> = related.iter().map(|(l, _)| l.as_str()).collect();
        for want in ["Private endpoint pe-sb", "Identity id-sb", "Key identity id-cmk"] {
            assert!(labels.contains(&want), "{want} in {labels:?}");
        }
        let (_, pe) = related.iter().find(|(l, _)| l == "Private endpoint pe-sb").unwrap();
        assert_eq!(JumpView::for_arm_id(pe), Some(JumpView::PrivateEndpoints));
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az servicebus namespace show --ids /subscriptions/0000/resourceGroups/rg-msg/providers/Microsoft.ServiceBus/namespaces/sb-prod")
        );
    }

    #[test]
    fn no_key_reaches_a_section_search_or_the_raw_view() {
        let row = ServiceBusRow::from_json(&sb_json(), None).unwrap();
        let auth = vec![serde_json::json!({"name": "RootManageSharedAccessKey",
            "properties": {"rights": ["Listen", "Manage", "Send"], "primaryKey": "leaked-key-3"}})];
        let mut all: String = (0..SERVICEBUS_SECTIONS.sections.len())
            .flat_map(|i| {
                servicebus_section_lines(
                    &row,
                    ServiceBusDetailSection::from_index(i),
                    Some(&Lazy::Loaded(rules("Deny", true, true))),
                    Some(&Lazy::Loaded(vec![])),
                    Some(&Lazy::Loaded(vec![])),
                    Some(&Lazy::Loaded(auth.clone())),
                )
            })
            .map(|(k, v)| format!("{k}{v}"))
            .collect();
        all += &row.search_text();
        all += &row.raw_content().unwrap();
        assert!(!all.contains("leaked-key"), "a key leaked");
        assert!(!all.contains("SharedAccessKey="), "a connection string leaked");
        assert!(all.contains("RootManageSharedAccessKey"), "the policy name stays");
        assert!(all.contains("Listen, Manage, Send"), "the rights stay");
        // The scrub reaches any depth.
        let nested = without_secrets(&serde_json::json!({"a": [{"b": {"secondaryKey": "x", "keep": 1}}]}));
        assert_eq!(nested, serde_json::json!({"a": [{"b": {"keep": 1}}]}));
    }

    #[test]
    fn network_explains_effective_access_rules_endpoints_and_dns() {
        let row = ServiceBusRow::from_json(&sb_json(), None).unwrap();
        let net = |r: Option<&Lazy<Value>>| servicebus_section_lines(&row, ServiceBusDetailSection::Network, r, None, None, None);

        let lines = net(Some(&Lazy::Loaded(rules("Deny", true, true))));
        assert!(has(&lines, "Effective access", "only 1 IP rules · 1 VNet subnets · 1 private endpoints · trusted Microsoft services"));
        assert!(has(&lines, "Default action", "Deny"));
        assert!(has(&lines, "Trusted services", "yes"));
        assert!(has(&lines, "  allow", "203.0.113.0/24"));
        let (_, subnet) = lines.iter().find(|(k, _)| k == "  Subnet · vnet-aca/snet-infra").unwrap();
        assert_eq!(JumpView::for_arm_id(subnet), Some(JumpView::Subnets));
        assert!(lines.iter().any(|(_, v)| v.contains("lacks the Microsoft.ServiceBus service endpoint")));
        let (_, pe) = lines.iter().find(|(k, _)| k == "  Private endpoint · pe-sb").unwrap();
        assert_eq!(JumpView::for_arm_id(pe), Some(JumpView::PrivateEndpoints));
        assert!(has(&lines, "    Connection", "Approved · auto-approved"));
        assert!(has(&lines, "Private DNS zone", "privatelink.servicebus.windows.net"));
        assert!(lines.iter().any(|(_, v)| v.contains("sb-prod.privatelink.servicebus.windows.net")));
        assert!(has(&lines, "Minimum TLS", "1.2"));
        assert!(has(&lines, "Local auth (SAS)", "disabled"));
        assert!(lines.last().unwrap().1.starts_with("az servicebus namespace network-rule-set list --namespace-name sb-prod -g rg-msg"));

        // Deny with no rules is not enforced.
        let lines = net(Some(&Lazy::Loaded(rules("Deny", false, false))));
        assert!(has(&lines, "Effective access", "⚠ every network"));
        let lines = net(Some(&Lazy::Loaded(rules("Allow", true, false))));
        assert!(has(&lines, "Effective access", "every network (the internet)"));
        assert!(has(&lines, "Default action", "Allow · every network"));
        let lines = net(None);
        assert!(has(&lines, "Firewall", "Loading…"));
        assert!(has(&lines, "Private endpoints", "1"), "the body's part renders before the rule set loads");

        // The rule set's subnets join Related once loaded.
        let related = servicebus_section_lines(
            &row,
            ServiceBusDetailSection::Related,
            Some(&Lazy::Loaded(rules("Deny", false, true))),
            None,
            None,
            None,
        );
        assert!(related.iter().any(|(l, _)| l == "VNet rule subnet vnet-aca/snet-infra"));
    }

    #[test]
    fn security_names_local_auth_cmk_and_identities() {
        let row = ServiceBusRow::from_json(&sb_json(), None).unwrap();
        let lines = servicebus_section_lines(&row, ServiceBusDetailSection::Security, None, None, None, None);
        assert!(has(&lines, "Local auth (SAS)", "disabled · Microsoft Entra ID only"));
        assert!(has(&lines, "Encryption", "customer-managed"));
        assert!(has(&lines, "  Key · sb-key", "version latest"));
        assert!(has(&lines, "Infrastructure encryption", "yes"));
        assert!(has(&lines, "System-assigned principal", "p-system"));
        let (_, uami) = lines.iter().find(|(k, _)| k == "User-assigned · id-sb").unwrap();
        assert_eq!(JumpView::for_arm_id(uami), Some(JumpView::Identities));
        let (_, cmk) = lines.iter().find(|(k, _)| k == "    Read by · id-cmk").unwrap();
        assert_eq!(JumpView::for_arm_id(cmk), Some(JumpView::Identities));
    }

    #[test]
    fn queues_and_topics_show_counts_and_settings() {
        let row = ServiceBusRow::from_json(&sb_json(), None).unwrap();
        let queues = vec![serde_json::json!({"name": "orders", "properties": {
            "status": "Active", "lockDuration": "PT1M", "requiresSession": true, "maxDeliveryCount": 10,
            "maxSizeInMegabytes": 1024, "sizeInBytes": 2048, "defaultMessageTimeToLive": "P10675199DT2H48M5.4775807S",
            "forwardDeadLetteredMessagesTo": "orders-dlq",
            "countDetails": {"activeMessageCount": 5, "deadLetterMessageCount": 2, "scheduledMessageCount": 0,
                "transferMessageCount": 0, "transferDeadLetterMessageCount": 0}}})];
        let lines = servicebus_section_lines(&row, ServiceBusDetailSection::Queues, None, Some(&Lazy::Loaded(queues)), None, None);
        assert!(has(&lines, "orders", "5 active · 2 dead-lettered · ⚠ dead letters"));
        assert!(has(&lines, "  Lock duration", "1m"));
        assert!(has(&lines, "  Sessions", "yes"));
        assert!(has(&lines, "  Message TTL", "never"));
        assert!(has(&lines, "  Size", "2.0 KB of 1024 MB"));
        assert!(has(&lines, "  Forward dead letters to", "orders-dlq"));
        assert!(lines.last().unwrap().1.starts_with("az servicebus queue list --namespace-name sb-prod"));

        let topics = vec![serde_json::json!({"name": "events", "properties": {"status": "Disabled", "subscriptionCount": 3, "sizeInBytes": 0}})];
        let lines = servicebus_section_lines(&row, ServiceBusDetailSection::Topics, None, None, Some(&Lazy::Loaded(topics)), None);
        assert!(has(&lines, "events", "3 subscriptions · 0 B · ⚠ Disabled"));
        let empty = servicebus_section_lines(&row, ServiceBusDetailSection::Topics, None, None, Some(&Lazy::Loaded(vec![])), None);
        assert_eq!(empty[0].1, "No topics");
    }

    #[test]
    fn event_hubs_row_hubs_capture_and_related() {
        let row = EventHubsRow::from_json(&eh_json(), None).unwrap();
        assert_eq!(row.list_summary().as_deref(), Some("Standard · 2 TU · private"));
        assert!(has(&row.details(), "Auto-inflate", "yes · up to 10 throughput units"));
        assert!(has(&row.details(), "Kafka", "yes"));
        assert!(row.cluster_id.is_none(), "an empty clusterArmId is no link");
        assert!(row.cli_command().unwrap().starts_with("az eventhubs namespace show --ids "));
        let net = eventhubs_section_lines(&row, EventHubsDetailSection::Network, None, None, None);
        assert!(has(&net, "Effective access", "private endpoints only (0 approved)"));

        let storage = format!("{}/providers/Microsoft.Storage/storageAccounts/stcapture", RG);
        let hubs = vec![serde_json::json!({"name": "telemetry", "properties": {
            "partitionCount": 4, "status": "Active",
            "retentionDescription": {"cleanupPolicy": "Delete", "retentionTimeInHours": 168},
            "captureDescription": {"enabled": true, "encoding": "Avro", "intervalInSeconds": 300, "sizeLimitInBytes": 314572800,
                "destination": {"name": "EventHubArchive.AzureBlockBlob", "identity": {"type": "SystemAssigned"},
                    "properties": {"storageAccountResourceId": storage, "blobContainer": "capture"}}}}})];
        let lines = eventhubs_section_lines(&row, EventHubsDetailSection::Hubs, None, Some(&Lazy::Loaded(hubs.clone())), None);
        assert!(has(&lines, "telemetry", "4 partitions · capture on"));
        assert!(has(&lines, "  Retention", "7 days · delete"));
        let (_, acct) = lines.iter().find(|(k, _)| k == "  → Storage · stcapture").unwrap();
        assert_eq!(JumpView::for_arm_id(acct), Some(JumpView::StorageAccounts));
        assert!(has(&lines, "    Container", "capture"));
        let related = eventhubs_section_lines(&row, EventHubsDetailSection::Related, None, Some(&Lazy::Loaded(hubs)), None);
        assert!(related.iter().any(|(l, _)| l == "Capture storage stcapture (from telemetry)"));
        assert_eq!(MessagingService::rows(JumpView::EventHubNamespaces, &[eh_json()], None).len(), 1);
    }

    #[test]
    fn tier_notes_and_durations() {
        let mut basic = sb_json();
        basic["sku"] = serde_json::json!({"name": "Standard", "tier": "Standard"});
        let row = ServiceBusRow::from_json(&basic, None).unwrap();
        let lines = servicebus_section_lines(&row, ServiceBusDetailSection::Network, None, None, None, None);
        assert!(lines.iter().any(|(_, v)| v.contains("need the Premium tier")));
        assert_eq!(duration(Some("PT30S".into())), "30s");
        assert_eq!(duration(Some("P14D".into())), "14d");
        assert_eq!(duration(Some("PT1H30M".into())), "1h 30m");
        assert_eq!(duration(None), "-");
        assert_eq!(api_version_for("/subscriptions/0/resourceGroups/r/providers/microsoft.eventhub/namespaces/x"), EVENTHUB_API_VERSION);
        assert_eq!(messaging_child_path("/x/ns/", "queues"), "/x/ns/queues");
    }
}
