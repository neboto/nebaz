//! Event Grid (#159, SERVICES.md rule 50): the Event Grid tab in the
//! Integration group. **Topics** (custom topics an app publishes to),
//! **System topics** (the events an Azure resource raises: a storage
//! account's blob events, a subscription's resource events) and
//! **Domains** (many topics behind one endpoint), each one
//! subscription-wide list of its `Microsoft.EventGrid` type. Each one's
//! **event subscriptions** are a lazy section (one list per parent): where
//! the events go, which ones, the retry policy and the dead-letter
//! destination. A domain's topics are a second lazy section. Namespaces
//! (MQTT and pull delivery) and partner topics are not browsed yet; they
//! land in All resources.
//!
//! **Never kept** ([`subscription_outline`], before the store holds a
//! body): a webhook's full URL (`endpointUrl`, which can carry a key in its
//! query; only the base URL, stripped of any query, stays) and a static
//! delivery attribute's value (a header such as an API key; only its name
//! stays). **Never read**: a topic's or domain's access keys
//! (`listKeys`, a POST), a webhook's full URL (`getFullUrl`, a POST) and an
//! event subscription's delivery attributes (`getDeliveryAttributes`, a
//! POST). The topic's publish endpoint (its own Event Grid host) is shown
//! as text, never called.

use crate::azure::resource::{name_of_id, scope_related, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::api_management::strip_url;
use crate::azure::services::{
    finish_stream, json, lazy_list_rows, overview_rows, related_rows_with, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::{json as j, Map, Value};
use tokio::sync::mpsc;

/// The newest stable version (Microsoft Learn's REST reference lists
/// `2025-02-15` as current, checked 2026-11-26).
pub const EVENT_GRID_API_VERSION: &str = "2025-02-15";
const TOPICS_PATH: &str = "/providers/Microsoft.EventGrid/topics";
const SYSTEM_TOPICS_PATH: &str = "/providers/Microsoft.EventGrid/systemTopics";
const DOMAINS_PATH: &str = "/providers/Microsoft.EventGrid/domains";

/// The most event subscriptions one parent's section reads (`$top`, the
/// API's page maximum).
pub const MAX_SUBSCRIPTIONS: usize = 100;
/// The most topics a domain's Topics section reads.
pub const MAX_DOMAIN_TOPICS: usize = 200;
/// Event Grid's default delivery attempts and event time to live, when a
/// subscription names no retry policy.
const DEFAULT_ATTEMPTS: i64 = 30;
const DEFAULT_TTL_MINUTES: i64 = 1440;

crate::sections! {
    pub enum TopicDetailSection,
    pub static TOPIC_SECTIONS = [
        Overview "Overview",
        Network "Network",
        Subscriptions "Subscriptions" => crate::app::App::trigger_eg_subscriptions,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum SystemTopicDetailSection,
    pub static SYSTEM_TOPIC_SECTIONS = [
        Overview "Overview",
        Subscriptions "Subscriptions" => crate::app::App::trigger_eg_subscriptions,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum DomainDetailSection,
    pub static DOMAIN_SECTIONS = [
        Overview "Overview",
        Network "Network",
        Topics "Topics" => crate::app::App::trigger_eg_domain_topics,
        Subscriptions "Subscriptions" => crate::app::App::trigger_eg_subscriptions,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Secrets out ───────────────────────────────────────────────────────

fn copy(from: &Value, to: &mut Map<String, Value>, keys: &[&str]) {
    for k in keys {
        if let Some(v) = from.get(*k).filter(|v| !v.is_null()) {
            to.insert((*k).to_string(), v.clone());
        }
    }
}

/// A delivery or dead-letter destination: its type and where it points,
/// never a full webhook URL or a static attribute's value.
fn outline_destination(d: &Value) -> Value {
    let mut out = Map::new();
    copy(d, &mut out, &["endpointType"]);
    let p = d.get("properties").cloned().unwrap_or(Value::Null);
    let mut props = Map::new();
    copy(
        &p,
        &mut props,
        &[
            "resourceId",
            "queueName",
            "blobContainerName",
            "maxEventsPerBatch",
            "preferredBatchSizeInKilobytes",
            "azureActiveDirectoryTenantId",
            "azureActiveDirectoryApplicationIdOrUri",
            "minimumTlsVersionAllowed",
            "actionGroups",
            "severity",
        ],
    );
    if let Some(u) = json::str_at(&p, "/endpointBaseUrl") {
        props.insert("endpointBaseUrl".into(), Value::String(strip_url(&u)));
    }
    let attrs: Vec<Value> = json::arr(&p, "/deliveryAttributeMappings")
        .iter()
        .map(|a| {
            let mut m = Map::new();
            copy(a, &mut m, &["name", "type"]);
            if let Some(f) = json::str_at(a, "/properties/sourceField") {
                m.insert("sourceField".into(), Value::String(f));
            }
            if json::bool_at(a, "/properties/isSecret") == Some(true) {
                m.insert("isSecret".into(), Value::Bool(true));
            }
            Value::Object(m)
        })
        .collect();
    if !attrs.is_empty() {
        props.insert("deliveryAttributeMappings".into(), Value::Array(attrs));
    }
    out.insert("properties".into(), Value::Object(props));
    Value::Object(out)
}

/// An event subscription as the store keeps it: an allowlist of its
/// envelope, filter, retry policy and destinations' outlines.
pub fn subscription_outline(v: &Value) -> Value {
    let mut out = Map::new();
    copy(v, &mut out, &["id", "name", "type"]);
    let p = v.get("properties").cloned().unwrap_or(Value::Null);
    let mut props = Map::new();
    copy(
        &p,
        &mut props,
        &["topic", "provisioningState", "filter", "labels", "expirationTimeUtc", "eventDeliverySchema", "retryPolicy"],
    );
    if let Some(d) = p.get("destination").filter(|d| d.is_object()) {
        props.insert("destination".into(), outline_destination(d));
    }
    if let Some(d) = p.get("deliveryWithResourceIdentity").filter(|d| d.is_object()) {
        let mut m = Map::new();
        copy(d, &mut m, &["identity"]);
        if let Some(dest) = d.get("destination").filter(|d| d.is_object()) {
            m.insert("destination".into(), outline_destination(dest));
        }
        props.insert("deliveryWithResourceIdentity".into(), Value::Object(m));
    }
    if let Some(d) = p.get("deadLetterDestination").filter(|d| d.is_object()) {
        props.insert("deadLetterDestination".into(), outline_destination(d));
    }
    if let Some(d) = p.get("deadLetterWithResourceIdentity").filter(|d| d.is_object()) {
        let mut m = Map::new();
        copy(d, &mut m, &["identity"]);
        if let Some(dest) = d.get("deadLetterDestination").filter(|d| d.is_object()) {
            m.insert("deadLetterDestination".into(), outline_destination(dest));
        }
        props.insert("deadLetterWithResourceIdentity".into(), Value::Object(m));
    }
    out.insert("properties".into(), Value::Object(props));
    Value::Object(out)
}

/// A domain topic: its name, id and provisioning state.
pub fn domain_topic_outline(v: &Value) -> Value {
    j!({
        "id": v.get("id").cloned().unwrap_or(Value::Null),
        "name": v.get("name").cloned().unwrap_or(Value::Null),
        "properties": {"provisioningState": v.pointer("/properties/provisioningState").cloned().unwrap_or(Value::Null)},
    })
}

// ── Event subscriptions ───────────────────────────────────────────────

/// The top-level resource an id names: a Service Bus queue's namespace,
/// a function's site, a storage account itself.
pub fn top_level(id: &str) -> String {
    let parts: Vec<&str> = id.split('/').collect();
    match parts.iter().position(|p| p.eq_ignore_ascii_case("providers")) {
        Some(i) if parts.len() > i + 3 => parts[..i + 4].join("/"),
        _ => id.to_string(),
    }
}

/// One event subscription, read from its outline.
#[derive(Debug, Clone)]
pub struct EventSub {
    pub name: String,
    pub id: String,
    pub provisioning: String,
    pub endpoint_type: String,
    /// The destination resource (a queue, a function, an event hub), or
    /// `None` for a webhook.
    pub target: Option<String>,
    pub queue: Option<String>,
    pub webhook: Option<String>,
    pub entra_app: Option<String>,
    pub event_types: Vec<String>,
    pub subject_begins: Option<String>,
    pub subject_ends: Option<String>,
    pub advanced: Vec<String>,
    pub attempts: i64,
    pub ttl_minutes: i64,
    pub dead_letter: Option<(String, Option<String>)>,
    pub delivery_identity: Option<String>,
    pub schema: Option<String>,
    pub expires: Option<String>,
    pub labels: Vec<String>,
}

fn filter_text(f: &Value) -> String {
    let key = json::text(f, "/key");
    let op = json::text(f, "/operatorType");
    let vals: Vec<String> = match f.get("values").and_then(Value::as_array) {
        Some(a) => a.iter().map(value_text).collect(),
        None => f.get("value").map(value_text).into_iter().collect(),
    };
    match vals.len() {
        0 => format!("{} {}", key, op),
        n if n <= 3 => format!("{} {} [{}]", key, op, vals.join(", ")),
        n => format!("{} {} [{}, … {} more]", key, op, vals[..3].join(", "), n - 3),
    }
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl EventSub {
    pub fn from_outline(v: &Value) -> EventSub {
        let p = |f: &str| format!("/properties/{}", f);
        let dest = v
            .pointer(&p("deliveryWithResourceIdentity/destination"))
            .or_else(|| v.pointer(&p("destination")))
            .cloned()
            .unwrap_or(Value::Null);
        let dl = v
            .pointer(&p("deadLetterWithResourceIdentity/deadLetterDestination"))
            .or_else(|| v.pointer(&p("deadLetterDestination")))
            .cloned()
            .unwrap_or(Value::Null);
        let nonempty = |s: Option<String>| s.filter(|s| !s.is_empty());
        EventSub {
            name: json::text(v, "/name"),
            id: json::text(v, "/id"),
            provisioning: json::text(v, &p("provisioningState")),
            endpoint_type: json::text(&dest, "/endpointType"),
            target: json::arm_id(json::str_at(&dest, "/properties/resourceId")),
            queue: json::str_at(&dest, "/properties/queueName"),
            webhook: json::str_at(&dest, "/properties/endpointBaseUrl"),
            entra_app: json::str_at(&dest, "/properties/azureActiveDirectoryApplicationIdOrUri"),
            event_types: json::strings_at(v, &p("filter/includedEventTypes")),
            subject_begins: nonempty(json::str_at(v, &p("filter/subjectBeginsWith"))),
            subject_ends: nonempty(json::str_at(v, &p("filter/subjectEndsWith"))),
            advanced: json::arr(v, &p("filter/advancedFilters")).iter().map(filter_text).collect(),
            attempts: json::int_at(v, &p("retryPolicy/maxDeliveryAttempts")).unwrap_or(DEFAULT_ATTEMPTS),
            ttl_minutes: json::int_at(v, &p("retryPolicy/eventTimeToLiveInMinutes")).unwrap_or(DEFAULT_TTL_MINUTES),
            dead_letter: json::arm_id(json::str_at(&dl, "/properties/resourceId"))
                .map(|id| (id, json::str_at(&dl, "/properties/blobContainerName"))),
            delivery_identity: json::str_at(v, &p("deliveryWithResourceIdentity/identity/type")),
            schema: json::str_at(v, &p("eventDeliverySchema")),
            expires: json::str_at(v, &p("expirationTimeUtc")),
            labels: json::strings_at(v, &p("labels")),
        }
    }

    /// Provisioning that never finished: `Failed`, or `AwaitingManualAction`
    /// (a webhook that never answered the validation handshake). Either
    /// way nothing is delivered.
    pub fn not_delivering(&self) -> bool {
        matches!(self.provisioning.to_ascii_lowercase().as_str(), "failed" | "awaitingmanualaction" | "canceled")
    }

    /// `ServiceBusQueue → sb-orders-prod/orders`, `WebHook → https://…`.
    pub fn destination_text(&self) -> String {
        let to = match (&self.target, &self.webhook) {
            (Some(t), _) => {
                let top = top_level(t);
                let top_name = name_of_id(&top).to_string();
                let child = name_of_id(t);
                let mut s = if top.len() < t.len() { format!("{}/{}", top_name, child) } else { top_name };
                if let Some(q) = &self.queue {
                    s.push_str(&format!("/{}", q));
                }
                s
            }
            (None, Some(u)) => u.clone(),
            (None, None) => "-".into(),
        };
        format!("{} → {}", if self.endpoint_type.is_empty() { "-" } else { &self.endpoint_type }, to)
    }

    fn ttl_text(&self) -> String {
        match self.ttl_minutes {
            m if m % 1440 == 0 => format!("{}d", m / 1440),
            m if m % 60 == 0 => format!("{}h", m / 60),
            m => format!("{}m", m),
        }
    }

    pub fn dead_letter_text(&self) -> String {
        match &self.dead_letter {
            Some((id, c)) => match c {
                Some(c) => format!("{}/{}", name_of_id(id), c),
                None => name_of_id(id).to_string(),
            },
            None => format!("⚠ none: an event still undelivered after {} attempts or {} is dropped", self.attempts, self.ttl_text()),
        }
    }

    fn lines(&self, out: &mut Vec<(String, String)>) {
        let head = if self.provisioning.eq_ignore_ascii_case("succeeded") || self.provisioning.is_empty() {
            self.destination_text()
        } else {
            format!("⚠ {} · {}", self.provisioning, self.destination_text())
        };
        out.push((String::new(), String::new()));
        out.push((self.name.clone(), head));
        if let Some(t) = &self.target {
            let top = top_level(t);
            out.push((format!("  Destination · {}", name_of_id(&top)), top.clone()));
            if top.len() < t.len() {
                out.push(("  Destination path".into(), t.clone()));
            }
        }
        if self.webhook.is_some() {
            out.push(("  Webhook auth".into(), match &self.entra_app {
                Some(a) => format!("Entra ID token for {}", a),
                None => "none (the URL's own key, if any)".into(),
            }));
        }
        out.push((
            "  Events".into(),
            if self.event_types.is_empty() { "all the topic's event types".into() } else { self.event_types.join(", ") },
        ));
        match (&self.subject_begins, &self.subject_ends) {
            (None, None) => {}
            (b, e) => {
                let mut parts = Vec::new();
                if let Some(b) = b {
                    parts.push(format!("begins {}", b));
                }
                if let Some(e) = e {
                    parts.push(format!("ends {}", e));
                }
                out.push(("  Subject".into(), parts.join(" · ")));
            }
        }
        for f in &self.advanced {
            out.push(("  Filter".into(), f.clone()));
        }
        out.push(("  Retry".into(), format!("{} attempts · {} time to live", self.attempts, self.ttl_text())));
        out.push(("  Dead-letter".into(), self.dead_letter_text()));
        if let Some((id, _)) = &self.dead_letter {
            out.push((format!("  Dead-letter account · {}", name_of_id(id)), id.clone()));
        }
        if let Some(i) = &self.delivery_identity {
            out.push(("  Delivers as".into(), format!("the topic's {} identity", i)));
        }
        if let Some(s) = &self.schema {
            out.push(("  Schema".into(), s.clone()));
        }
        if let Some(e) = &self.expires {
            out.push(("  Expires".into(), json::time(Some(e.clone()))));
        }
        if !self.labels.is_empty() {
            out.push(("  Labels".into(), self.labels.join(", ")));
        }
    }
}

/// The Subscriptions body: a tally, then each event subscription.
pub fn subscription_rows(items: &[Value]) -> Vec<(String, String)> {
    if items.is_empty() {
        return vec![(String::new(), "No event subscriptions: events published here go nowhere".into())];
    }
    let subs: Vec<EventSub> = items.iter().map(EventSub::from_outline).collect();
    let stuck = subs.iter().filter(|s| s.not_delivering()).count();
    let no_dl = subs.iter().filter(|s| s.dead_letter.is_none()).count();
    let mut head = format!("{}", subs.len());
    if stuck > 0 {
        head.push_str(&format!(" · ⚠ {} not delivering", stuck));
    }
    if no_dl > 0 {
        head.push_str(&format!(" · {} without dead-letter", no_dl));
    }
    let mut lines = vec![("Event subscriptions".into(), head)];
    for s in &subs {
        s.lines(&mut lines);
    }
    if items.len() >= MAX_SUBSCRIPTIONS {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("the first {} only", MAX_SUBSCRIPTIONS)));
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "full webhook URLs and delivery attribute values are never read".into()));
    lines
}

/// A domain's Topics body.
pub fn domain_topic_rows(items: &[Value]) -> Vec<(String, String)> {
    if items.is_empty() {
        return vec![(String::new(), "No domain topics yet".into())];
    }
    let mut lines = vec![("Domain topics".to_string(), items.len().to_string())];
    let mut sorted: Vec<&Value> = items.iter().collect();
    sorted.sort_by_key(|t| json::text(t, "/name").to_lowercase());
    for t in sorted {
        let state = json::text(t, "/properties/provisioningState");
        let shown = if state.eq_ignore_ascii_case("succeeded") || state == "-" { state } else { format!("⚠ {}", state) };
        lines.push((format!("  {}", json::text(t, "/name")), shown));
    }
    if items.len() >= MAX_DOMAIN_TOPICS {
        lines.push((String::new(), format!("the first {} only", MAX_DOMAIN_TOPICS)));
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "each topic's own event subscriptions are not read here (one call per topic)".into()));
    lines
}

// ── Rows ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgKind {
    Topic,
    SystemTopic,
    Domain,
}

impl EgKind {
    pub fn of_id(id: &str) -> EgKind {
        let l = id.to_ascii_lowercase();
        if l.contains("/microsoft.eventgrid/systemtopics/") {
            EgKind::SystemTopic
        } else if l.contains("/microsoft.eventgrid/domains/") {
            EgKind::Domain
        } else {
            EgKind::Topic
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventGridRow {
    pub base: ArmBase,
    pub kind: EgKind,
    pub endpoint: Option<String>,
    pub input_schema: Option<String>,
    pub public_network_access: Option<String>,
    pub inbound_ip_rules: Vec<String>,
    pub disable_local_auth: Option<bool>,
    pub min_tls: Option<String>,
    pub data_residency: Option<String>,
    pub private_endpoints: Vec<(String, Option<String>)>,
    pub source: Option<String>,
    pub topic_type: Option<String>,
    pub auto_create_topics: Option<bool>,
    pub auto_delete_topics: Option<bool>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
}

impl EventGridRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<EventGridRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| format!("/properties/{}", f);
        let s = |f: &str| json::str_at(v, &p(f)).filter(|s| !s.is_empty());
        Some(EventGridRow {
            kind: EgKind::of_id(&base.id),
            endpoint: s("endpoint"),
            input_schema: s("inputSchema"),
            public_network_access: s("publicNetworkAccess"),
            inbound_ip_rules: json::arr(v, &p("inboundIpRules")).iter().filter_map(|r| json::str_at(r, "/ipMask")).collect(),
            disable_local_auth: json::bool_at(v, &p("disableLocalAuth")),
            min_tls: s("minimumTlsVersionAllowed"),
            data_residency: s("dataResidencyBoundary"),
            private_endpoints: json::arr(v, &p("privateEndpointConnections"))
                .iter()
                .filter_map(|c| {
                    Some((
                        json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                        json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
                    ))
                })
                .collect(),
            source: json::arm_id(s("source")),
            topic_type: s("topicType"),
            auto_create_topics: json::bool_at(v, &p("autoCreateTopicWithFirstSubscription")),
            auto_delete_topics: json::bool_at(v, &p("autoDeleteTopicWithLastSubscription")),
            identity_type: json::str_at(v, "/identity/type").filter(|t| !t.eq_ignore_ascii_case("none")),
            user_identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    fn public(&self) -> bool {
        !self.public_network_access.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("disabled"))
    }

    fn local_auth(&self) -> bool {
        self.disable_local_auth != Some(true)
    }

    /// A topic or domain that takes an access key (or SAS token) from any
    /// IP: public access on, no inbound IP rule, local auth not disabled.
    /// What `@audit`'s `eventgrid-local-auth-public` reads.
    pub fn open_to_keys(&self) -> bool {
        self.kind != EgKind::SystemTopic && self.public() && self.inbound_ip_rules.is_empty() && self.local_auth()
    }

    pub fn network_rows(&self) -> Vec<(String, String)> {
        let publish = if !self.public() {
            "private endpoints only".to_string()
        } else if self.inbound_ip_rules.is_empty() {
            if self.local_auth() { "⚠ any IP with an access key or SAS token".into() } else { "any IP with an Entra ID token".into() }
        } else {
            self.inbound_ip_rules.join(", ")
        };
        let mut lines = vec![
            ("Publishers".into(), publish),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            (
                "Local auth (keys, SAS)".into(),
                if self.local_auth() { "enabled".into() } else { "disabled (Entra ID only)".into() },
            ),
            ("Minimum TLS".into(), json::opt(self.min_tls.clone())),
            ("Endpoint".into(), json::opt(self.endpoint.clone())),
        ];
        if self.private_endpoints.is_empty() {
            lines.push(("Private endpoints".into(), "none".into()));
        }
        for (pe, status) in &self.private_endpoints {
            lines.push((format!("Private endpoint · {} ({})", name_of_id(pe), json::opt(status.clone())), pe.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "access keys are never read".into()));
        lines
    }

    fn ladder(&self) -> (ResourceState, String) {
        state_ladder(self.base.provisioning_state.as_deref(), None)
    }
}

/// The ARM path of an Event Grid parent's event subscriptions: a system
/// topic's own child list, a topic's or domain's extension list.
pub fn subscriptions_path(id: &str) -> String {
    let id = id.trim_end_matches('/');
    match EgKind::of_id(id) {
        EgKind::SystemTopic => format!("{}/eventSubscriptions", id),
        _ => format!("{}/providers/Microsoft.EventGrid/eventSubscriptions", id),
    }
}

impl Resource for EventGridRow {
    // `arm_row!` without its fixed `resource_type`: one row type, three kinds.
    fn id(&self) -> &str {
        &self.base.id
    }
    fn name(&self) -> &str {
        &self.base.name
    }
    fn tags(&self) -> &std::collections::HashMap<String, String> {
        &self.base.tags
    }
    fn location(&self) -> Option<&str> {
        Some(&self.base.location)
    }
    fn tenant_id(&self) -> Option<&str> {
        self.base.tenant.as_deref()
    }
    fn raw_content(&self) -> Option<String> {
        Some(self.base.raw.clone())
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn resource_type(&self) -> &str {
        match self.kind {
            EgKind::Topic => "Event Grid topic",
            EgKind::SystemTopic => "Event Grid system topic",
            EgKind::Domain => "Event Grid domain",
        }
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(match self.kind {
            EgKind::Topic => &TOPIC_SECTIONS,
            EgKind::SystemTopic => &SYSTEM_TOPIC_SECTIONS,
            EgKind::Domain => &DOMAIN_SECTIONS,
        })
    }
    /// `Microsoft.Storage.StorageAccounts · stcontosoordersprod` for a
    /// system topic; `⚠ keys from any IP` for an open topic.
    fn list_summary(&self) -> Option<String> {
        match self.kind {
            EgKind::SystemTopic => Some(format!(
                "{} · {}",
                json::opt(self.topic_type.clone()),
                self.source.as_deref().map(name_of_id).unwrap_or("-")
            )),
            _ => Some(if self.open_to_keys() {
                "keys from any IP".to_string()
            } else if !self.public() {
                "private".to_string()
            } else if self.local_auth() {
                format!("{} IP rule{}", self.inbound_ip_rules.len(), if self.inbound_ip_rules.len() == 1 { "" } else { "s" })
            } else {
                "Entra ID only".to_string()
            }),
        }
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
        ];
        match self.kind {
            EgKind::SystemTopic => {
                lines.push(("Topic type".into(), json::opt(self.topic_type.clone())));
                // The source is the resource whose events these are; a
                // subscription-scope system topic's source is the subscription.
                lines.push(("Source".into(), json::opt(self.source.clone())));
            }
            EgKind::Topic | EgKind::Domain => {
                lines.push(("Endpoint".into(), json::opt(self.endpoint.clone())));
                lines.push(("Input schema".into(), json::opt(self.input_schema.clone())));
                lines.push(("Public network access".into(), json::opt(self.public_network_access.clone())));
                lines.push((
                    "Local auth".into(),
                    if self.local_auth() { "enabled (keys, SAS)".into() } else { "disabled".into() },
                ));
                if let Some(d) = &self.data_residency {
                    lines.push(("Data residency".into(), d.clone()));
                }
            }
        }
        if self.kind == EgKind::Domain {
            lines.push(("Auto-create topics".into(), json::yes_no(self.auto_create_topics)));
            lines.push(("Auto-delete topics".into(), json::yes_no(self.auto_delete_topics)));
        }
        lines.push(("Identity".into(), json::opt(self.identity_type.clone())));
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(s) = self.source.as_ref().filter(|s| s.contains("/providers/")) {
            v.push((format!("Source {}", name_of_id(s)), s.clone()));
        }
        for (pe, _) in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    /// `az eventgrid topic|system-topic|domain show --ids` (each `name` has
    /// `id_part="name"`, checked 2026-11-26).
    fn cli_command(&self) -> Option<String> {
        let id = crate::azure::resource::shell_quote(&self.base.id);
        Some(match self.kind {
            EgKind::Topic => format!("az eventgrid topic show --ids {}", id),
            EgKind::SystemTopic => format!("az eventgrid system-topic show --ids {}", id),
            EgKind::Domain => format!("az eventgrid domain show --ids {}", id),
        })
    }
}

// ── Sections ──────────────────────────────────────────────────────────

/// What the sections read beyond the row.
pub struct EventGridContext<'a> {
    pub subscriptions: Option<&'a Lazy<Vec<Value>>>,
    pub domain_topics: Option<&'a Lazy<Vec<Value>>>,
}

/// Related, plus each event subscription's destination and dead-letter
/// account once Subscriptions has loaded.
fn related_with_destinations(x: &EventGridRow, cx: &EventGridContext) -> Vec<(String, String)> {
    let mut extra: Vec<(String, String)> = Vec::new();
    if let Some(Lazy::Loaded(items)) = cx.subscriptions {
        for s in items.iter().map(EventSub::from_outline) {
            let mut ids: Vec<String> = s.target.iter().map(|t| top_level(t)).collect();
            ids.extend(s.dead_letter.iter().map(|(id, _)| id.clone()));
            for id in ids {
                if !extra.iter().any(|(_, i)| i.eq_ignore_ascii_case(&id)) {
                    extra.push((format!("Destination {}", name_of_id(&id)), id));
                }
            }
        }
    }
    related_rows_with(x, extra)
}

/// Body lines for one section of a topic, system topic or domain; `None`
/// for another type.
pub fn event_grid_section_lines(r: &dyn Resource, idx: usize, cx: &EventGridContext) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<EventGridRow>()?;
    let subs = || lazy_list_rows(cx.subscriptions, "Event subscriptions", subscription_rows);
    Some(match x.kind {
        EgKind::Topic => {
            use TopicDetailSection as S;
            match S::from_index(idx) {
                S::Overview => overview_rows(x),
                S::Network => x.network_rows(),
                S::Subscriptions => subs(),
                S::Access | S::Activity => crate::azure::services::rendered_by_app(),
                S::Related => related_with_destinations(x, cx),
                S::Tags => tag_rows(x.tags()),
            }
        }
        EgKind::SystemTopic => {
            use SystemTopicDetailSection as S;
            match S::from_index(idx) {
                S::Overview => overview_rows(x),
                S::Subscriptions => subs(),
                S::Access | S::Activity => crate::azure::services::rendered_by_app(),
                S::Related => related_with_destinations(x, cx),
                S::Tags => tag_rows(x.tags()),
            }
        }
        EgKind::Domain => {
            use DomainDetailSection as S;
            match S::from_index(idx) {
                S::Overview => overview_rows(x),
                S::Network => x.network_rows(),
                S::Topics => lazy_list_rows(cx.domain_topics, "Domain topics", domain_topic_rows),
                S::Subscriptions => subs(),
                S::Access | S::Activity => crate::azure::services::rendered_by_app(),
                S::Related => related_with_destinations(x, cx),
                S::Tags => tag_rows(x.tags()),
            }
        }
    })
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct EventGridService {
    scope: Scope,
}

impl EventGridService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn path(view: JumpView) -> &'static str {
        match view {
            JumpView::EventGridSystemTopics => SYSTEM_TOPICS_PATH,
            JumpView::EventGridDomains => DOMAINS_PATH,
            _ => TOPICS_PATH,
        }
    }

    fn label(view: JumpView) -> &'static str {
        match view {
            JumpView::EventGridSystemTopics => "Listing Event Grid system topics…",
            JumpView::EventGridDomains => "Listing Event Grid domains…",
            _ => "Listing Event Grid topics…",
        }
    }

    fn rows(page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        page.iter()
            .filter_map(|v| EventGridRow::from_json(v, tenant))
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .collect()
    }
}

#[async_trait]
impl AzureService for EventGridService {
    fn service_type(&self) -> ServiceType {
        ServiceType::EventGrid
    }

    fn name(&self) -> &str {
        "Event Grid"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        Ok(Self::rows(&self.scope.list(Self::path(view), EVENT_GRID_API_VERSION).await?, self.scope.tenant()))
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(Self::path(view), EVENT_GRID_API_VERSION, &[], service_type, Self::label(view), &event_tx, |page| {
                Self::rows(&page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, EVENT_GRID_API_VERSION).await?;
        Self::rows(std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-ev";

    fn topic(props: Value) -> EventGridRow {
        EventGridRow::from_json(
            &json!({"id": format!("{}/providers/Microsoft.EventGrid/topics/egt-orders", RG), "name": "egt-orders",
                    "location": "westeurope", "properties": props}),
            None,
        )
        .unwrap()
    }

    fn get<'a>(lines: &'a [(String, String)], key: &str) -> Option<&'a str> {
        lines.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn section_labels_keep_the_shared_order() {
        let l = |d: &crate::sections::SectionDescriptor| d.sections.iter().map(|s| s.label).collect::<Vec<_>>();
        assert_eq!(l(&TOPIC_SECTIONS), ["Overview", "Network", "Subscriptions", "Access", "Activity", "Related", "Tags"]);
        assert_eq!(l(&SYSTEM_TOPIC_SECTIONS), ["Overview", "Subscriptions", "Access", "Activity", "Related", "Tags"]);
        assert_eq!(l(&DOMAIN_SECTIONS), ["Overview", "Network", "Topics", "Subscriptions", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn a_topic_open_to_keys_from_anywhere_is_flagged_and_a_ranged_or_entra_one_is_not() {
        let open = topic(json!({"provisioningState": "Succeeded", "publicNetworkAccess": "Enabled",
                                "endpoint": "https://egt-orders.westeurope-1.eventgrid.example/api/events"}));
        assert!(open.open_to_keys());
        assert_eq!(get(&open.network_rows(), "Publishers"), Some("⚠ any IP with an access key or SAS token"));
        assert_eq!(open.list_summary().as_deref(), Some("keys from any IP"));
        let ranged = topic(json!({"publicNetworkAccess": "Enabled", "inboundIpRules": [{"ipMask": "203.0.113.0/24", "action": "Allow"}]}));
        assert!(!ranged.open_to_keys());
        assert_eq!(get(&ranged.network_rows(), "Publishers"), Some("203.0.113.0/24"));
        let entra = topic(json!({"publicNetworkAccess": "Enabled", "disableLocalAuth": true}));
        assert!(!entra.open_to_keys());
        let private = topic(json!({"publicNetworkAccess": "Disabled"}));
        assert!(!private.open_to_keys());
        assert_eq!(private.list_summary().as_deref(), Some("private"));
    }

    #[test]
    fn a_system_topic_names_its_source_and_lists_its_own_subscriptions() {
        let st_id = format!("{}/providers/Microsoft.EventGrid/systemTopics/st-blobs", RG);
        let source = format!("{}/providers/Microsoft.Storage/storageAccounts/stdata", RG);
        let st = EventGridRow::from_json(
            &json!({"id": st_id, "name": "st-blobs", "location": "westeurope",
                    "properties": {"source": source, "topicType": "Microsoft.Storage.StorageAccounts", "provisioningState": "Succeeded"}}),
            None,
        )
        .unwrap();
        assert_eq!(st.kind, EgKind::SystemTopic);
        assert!(!st.open_to_keys());
        assert_eq!(st.list_summary().as_deref(), Some("Microsoft.Storage.StorageAccounts · stdata"));
        assert!(st.related().iter().any(|(l, v)| l == "Source stdata" && *v == source));
        assert_eq!(subscriptions_path(&st.base.id), format!("{}/eventSubscriptions", st_id));
        assert_eq!(
            subscriptions_path(&topic(json!({})).base.id),
            format!("{}/providers/Microsoft.EventGrid/topics/egt-orders/providers/Microsoft.EventGrid/eventSubscriptions", RG)
        );
        assert!(st.cli_command().unwrap().starts_with("az eventgrid system-topic show --ids "));
    }

    #[test]
    fn a_subscription_keeps_no_full_url_or_attribute_value() {
        let raw = json!({
            "id": "x/eventSubscriptions/to-partner", "name": "to-partner",
            "properties": {
                "provisioningState": "AwaitingManualAction",
                "destination": {"endpointType": "WebHook", "properties": {
                    "endpointUrl": "https://partner.example/hook?code=planted-code",
                    "endpointBaseUrl": "https://partner.example/hook?code=planted-base",
                    "deliveryAttributeMappings": [
                        {"name": "x-api-key", "type": "Static", "properties": {"value": "planted-attr", "isSecret": true}},
                        {"name": "x-order", "type": "Dynamic", "properties": {"sourceField": "data.orderId"}}
                    ]}},
                "filter": {"includedEventTypes": ["Orders.Created"], "subjectBeginsWith": "",
                           "advancedFilters": [{"key": "data.region", "operatorType": "StringIn", "values": ["eu", "uk"]}]},
                "retryPolicy": {"maxDeliveryAttempts": 10, "eventTimeToLiveInMinutes": 60},
                "unknownField": "planted-unknown"
            }
        });
        let kept = subscription_outline(&raw);
        let text = kept.to_string();
        assert!(!text.contains("planted"), "{text}");
        assert!(text.contains("x-api-key") && text.contains("data.orderId"));
        let lines = subscription_rows(&[kept]);
        assert_eq!(get(&lines, "Event subscriptions"), Some("1 · ⚠ 1 not delivering · 1 without dead-letter"));
        assert_eq!(get(&lines, "to-partner"), Some("⚠ AwaitingManualAction · WebHook → https://partner.example/hook?…"));
        assert_eq!(get(&lines, "  Events"), Some("Orders.Created"));
        assert_eq!(get(&lines, "  Subject"), None, "an empty prefix is no filter");
        assert_eq!(get(&lines, "  Filter"), Some("data.region StringIn [eu, uk]"));
        assert_eq!(get(&lines, "  Retry"), Some("10 attempts · 1h time to live"));
        assert_eq!(get(&lines, "  Dead-letter"), Some("⚠ none: an event still undelivered after 10 attempts or 1h is dropped"));
    }

    #[test]
    fn a_queue_destination_names_its_namespace_and_jumps_to_it() {
        let ns = format!("{}/providers/Microsoft.ServiceBus/namespaces/sb-orders", RG);
        let st = format!("{}/providers/Microsoft.Storage/storageAccounts/stdl", RG);
        let raw = json!({"id": "x/eventSubscriptions/to-queue", "name": "to-queue", "properties": {
            "provisioningState": "Succeeded",
            "deliveryWithResourceIdentity": {"identity": {"type": "SystemAssigned"},
                "destination": {"endpointType": "ServiceBusQueue", "properties": {"resourceId": format!("{}/queues/orders", ns)}}},
            "deadLetterDestination": {"endpointType": "StorageBlob", "properties": {"resourceId": st, "blobContainerName": "deadletter"}}}});
        let lines = subscription_rows(&[subscription_outline(&raw)]);
        assert_eq!(get(&lines, "to-queue"), Some("ServiceBusQueue → sb-orders/orders"));
        assert_eq!(get(&lines, "  Destination · sb-orders"), Some(ns.as_str()));
        assert_eq!(get(&lines, "  Dead-letter"), Some("stdl/deadletter"));
        assert_eq!(get(&lines, "  Delivers as"), Some("the topic's SystemAssigned identity"));
        assert_eq!(get(&lines, "Event subscriptions"), Some("1"));
        let row = topic(json!({}));
        let cx = EventGridContext { subscriptions: Some(&Lazy::Loaded(vec![subscription_outline(&raw)])), domain_topics: None };
        let related = event_grid_section_lines(&row, TopicDetailSection::Related as usize, &cx).unwrap();
        assert!(related.iter().any(|(l, v)| l == "Destination sb-orders" && *v == ns), "{related:#?}");
        assert!(related.iter().any(|(l, v)| l == "Destination stdl" && *v == st));
    }

    #[test]
    fn top_level_trims_a_child_to_its_resource() {
        assert_eq!(top_level(&format!("{}/providers/Microsoft.Web/sites/f/functions/OnBlob", RG)), format!("{}/providers/Microsoft.Web/sites/f", RG));
        assert_eq!(top_level(&format!("{}/providers/Microsoft.Web/sites/f", RG)), format!("{}/providers/Microsoft.Web/sites/f", RG));
    }

    #[test]
    fn a_domain_lists_its_topics_and_flags_a_failed_one() {
        let lines = domain_topic_rows(&[
            domain_topic_outline(&json!({"id": "d/topics/tenant-b", "name": "tenant-b", "properties": {"provisioningState": "Failed"}})),
            domain_topic_outline(&json!({"id": "d/topics/tenant-a", "name": "tenant-a", "properties": {"provisioningState": "Succeeded"}})),
        ]);
        assert_eq!(get(&lines, "Domain topics"), Some("2"));
        assert_eq!(get(&lines, "  tenant-a"), Some("Succeeded"));
        assert_eq!(get(&lines, "  tenant-b"), Some("⚠ Failed"));
    }
}
