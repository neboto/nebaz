//! The directory half of the Identity tab (issue #78, ADR 0004): service
//! principals and app registrations, read from Microsoft Graph.
//!
//! These rows have **no ARM id**. Each keys on a synthetic id,
//! `graph:/servicePrincipals/{objectId}` or `graph:/applications/{objectId}`
//! (`src/azure/graph.rs`), and also answers to its app-id alias
//! (`graph:/applications(appId='…')`) through `Resource::matches_id`, so a
//! link that only knows the app id can land on it. They have no location
//! (never filtered by `R`), no resource group, no Access or Activity (those
//! are ARM scopes); their portal link is the Entra blade.
//!
//! Service principals are this tenant's own apps' (`appOwnerOrganizationId
//! eq {tenant}`, an advanced query) plus every managed identity's
//! (`servicePrincipalType eq 'ManagedIdentity'`, a default filter): two
//! GETs, merged. Listing every Microsoft first-party principal would bury
//! the useful rows.
//!
//! Credentials show name, key id, start and end, and an expiry state
//! (expired / expiring within 30 days / ok); never a value, a `hint`, or a
//! certificate's key (Graph returns none of them to a plain GET).

use crate::azure::arm::ArmClient;
use crate::azure::graph::{self, DirectoryKind};
use crate::azure::resource::{shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::ServiceType;
use crate::azure::services::{error_rows, finish_stream, json, overview_rows, related_rows};
use crate::error::{Error, Result};
use crate::event::{Event, LoadProgress};
use crate::lazy::{Lazy, LazyMap};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;

/// A credential ending within this many days is "expiring".
pub const EXPIRY_WARN_DAYS: i64 = 30;

/// How many related objects (an API's service principal, a grant's
/// resource) one section resolves through Graph.
pub const FOLLOWUPS_MAX: usize = 30;

crate::sections! {
    pub enum ServicePrincipalDetailSection,
    pub static SERVICE_PRINCIPAL_SECTIONS = [
        Overview "Overview",
        Credentials "Credentials",
        AppRoleAssignments "App role assignments" => crate::app::App::trigger_sp_app_role_assignments,
        OAuth2Grants "OAuth2 grants" => crate::app::App::trigger_sp_oauth2_grants,
        Owners "Owners" => crate::app::App::trigger_directory_owners,
        AzureRoles "Azure roles" => crate::app::App::trigger_sp_azure_roles,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum AppRegistrationDetailSection,
    pub static APP_REGISTRATION_SECTIONS = [
        Overview "Overview",
        Credentials "Credentials",
        FederatedCredentials "Federated credentials" => crate::app::App::trigger_app_federated_credentials,
        ApiPermissions "API permissions" => crate::app::App::trigger_app_api_permissions,
        RedirectUris "Redirect URIs",
        Owners "Owners" => crate::app::App::trigger_directory_owners,
        ExposedApi "Exposed API",
        Related "Related",
        Tags "Tags",
    ]
}

// ── Time and the expiry state ─────────────────────────────────────────

/// Seconds since the epoch, now.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `2025-01-02T03:04:05Z` (fractions and offsets after the seconds are
/// ignored; Graph's times are UTC) → Unix seconds, without a date crate.
pub fn iso_to_unix(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r).and_then(|t| t.parse::<i64>().ok());
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's days-from-civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Where one credential stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    Expired,
    /// Ends within [`EXPIRY_WARN_DAYS`]; the whole days left.
    Expiring(i64),
    Ok,
    /// No parseable end date.
    Unknown,
}

impl Expiry {
    pub fn of(end: Option<&str>, now: i64) -> Expiry {
        let Some(end) = end.and_then(iso_to_unix) else {
            return Expiry::Unknown;
        };
        if end <= now {
            Expiry::Expired
        } else if end - now < EXPIRY_WARN_DAYS * 86_400 {
            Expiry::Expiring((end - now) / 86_400)
        } else {
            Expiry::Ok
        }
    }

    /// The coarse bucket and the row's word (stable, so `F` can filter on
    /// it: `expired` / `expiring` / `ok`).
    pub fn bucket(self) -> Option<(ResourceState, &'static str)> {
        match self {
            Expiry::Expired => Some((ResourceState::Unavailable, "expired")),
            Expiry::Expiring(_) => Some((ResourceState::Pending, "expiring")),
            Expiry::Ok => Some((ResourceState::Available, "ok")),
            Expiry::Unknown => None,
        }
    }

    /// The per-credential line's word: `expired`, `expires in 12 d`, `ok`.
    pub fn describe(self) -> String {
        match self {
            Expiry::Expired => "expired".into(),
            Expiry::Expiring(d) => format!("expires in {} d", d),
            Expiry::Ok => "ok".into(),
            Expiry::Unknown => "-".into(),
        }
    }

    fn rank(self) -> u8 {
        match self {
            Expiry::Expired => 3,
            Expiry::Expiring(_) => 2,
            Expiry::Ok => 1,
            Expiry::Unknown => 0,
        }
    }
}

/// Every secret and certificate on an object (`passwordCredentials`,
/// `keyCredentials`).
fn credentials(v: &Value) -> Vec<Value> {
    let mut all = json::arr(v, "/passwordCredentials");
    all.extend(json::arr(v, "/keyCredentials"));
    all
}

/// The worst credential's expiry, or `Unknown` with none: a row with no
/// credentials is stateless.
pub fn worst_expiry(v: &Value, now: i64) -> Expiry {
    credentials(v)
        .iter()
        .map(|c| Expiry::of(json::str_at(c, "/endDateTime").as_deref(), now))
        .max_by_key(|e| e.rank())
        .unwrap_or(Expiry::Unknown)
}

// ── Rows ──────────────────────────────────────────────────────────────

/// What both directory row types carry.
#[derive(Debug, Clone)]
pub struct DirectoryBase {
    pub kind: DirectoryKind,
    pub id: String,
    pub object_id: String,
    pub app_id: String,
    pub name: String,
    pub tenant: Option<String>,
    pub expiry: Expiry,
    pub json: Value,
    /// Graph tags are a string list, not a map: rendered in Tags, never
    /// the `t:` filter's map.
    no_tags: HashMap<String, String>,
}

impl DirectoryBase {
    fn from_json(kind: DirectoryKind, v: &Value, tenant: Option<&str>, now: i64) -> Option<DirectoryBase> {
        let object_id = json::str_at(v, "/id").filter(|id| graph::is_object_id(id))?;
        let app_id = json::str_at(v, "/appId").unwrap_or_default();
        Some(DirectoryBase {
            kind,
            id: graph::row_id(kind, &object_id),
            name: json::str_at(v, "/displayName").unwrap_or_else(|| object_id.clone()),
            tenant: tenant.map(str::to_string),
            expiry: worst_expiry(v, now),
            json: v.clone(),
            no_tags: HashMap::new(),
            object_id,
            app_id,
        })
    }

    fn matches(&self, id: &str) -> bool {
        self.id.eq_ignore_ascii_case(id)
            || (!self.app_id.is_empty() && graph::row_alias(self.kind, &self.app_id).eq_ignore_ascii_case(id))
    }

    fn state(&self) -> (ResourceState, String) {
        state_ladder(None, self.expiry.bucket())
    }
}

/// The `Resource` methods both directory rows answer the same way.
macro_rules! directory_row {
    ($kind:expr, $search:expr) => {
        fn id(&self) -> &str {
            &self.base.id
        }
        fn matches_id(&self, id: &str) -> bool {
            self.base.matches(id)
        }
        fn name(&self) -> &str {
            &self.base.name
        }
        fn resource_type(&self) -> &str {
            $kind
        }
        fn state(&self) -> ResourceState {
            self.base.state().0
        }
        fn state_label(&self) -> String {
            self.base.state().1
        }
        fn tags(&self) -> &HashMap<String, String> {
            &self.base.no_tags
        }
        fn tenant_id(&self) -> Option<&str> {
            self.base.tenant.as_deref()
        }
        fn raw_content(&self) -> Option<String> {
            Some(serde_json::to_string_pretty(&self.base.json).unwrap_or_default())
        }
        /// The app id: what `az ad` and the portal key on.
        fn list_cell(&self) -> String {
            self.base.app_id.clone()
        }
        /// Also the row's URIs and URLs, so an obscurely named app is
        /// found by the host it signs in to.
        fn search_text(&self) -> String {
            format!(
                "{} {} {} {} {} {}",
                self.base.name,
                self.base.object_id,
                self.base.app_id,
                $kind,
                json::strings_at(&self.base.json, "/tags").join(" "),
                search_fields(&self.base.json, $search)
            )
        }
        fn clone_box(&self) -> Box<dyn Resource> {
            Box::new(self.clone())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    };
}

/// The text at each pointer, string or string list, space-joined.
fn search_fields(v: &Value, pointers: &[&str]) -> String {
    let mut out: Vec<String> = Vec::new();
    for ptr in pointers {
        match v.pointer(ptr) {
            Some(Value::String(s)) => out.push(s.clone()),
            Some(Value::Array(_)) => out.extend(json::strings_at(v, ptr)),
            _ => {}
        }
    }
    out.join(" ")
}

/// What an app registration's search reads beyond the shared fields.
const APP_REGISTRATION_SEARCH: &[&str] = &[
    "/web/redirectUris",
    "/spa/redirectUris",
    "/publicClient/redirectUris",
    "/identifierUris",
    "/web/homePageUrl",
    "/web/logoutUrl",
    "/info/marketingUrl",
    "/info/privacyStatementUrl",
    "/info/supportUrl",
    "/info/termsOfServiceUrl",
    "/publisherDomain",
    "/uniqueName",
    "/description",
    "/notes",
];

/// What a service principal's search reads beyond the shared fields.
const SERVICE_PRINCIPAL_SEARCH: &[&str] = &[
    "/replyUrls",
    "/servicePrincipalNames",
    "/homepage",
    "/loginUrl",
    "/logoutUrl",
    "/appDisplayName",
    "/description",
    "/notes",
];

#[derive(Debug, Clone)]
pub struct ServicePrincipalRow {
    pub base: DirectoryBase,
}

impl ServicePrincipalRow {
    pub fn from_json(v: &Value, tenant: Option<&str>, now: i64) -> Option<ServicePrincipalRow> {
        DirectoryBase::from_json(DirectoryKind::ServicePrincipal, v, tenant, now).map(|base| ServicePrincipalRow { base })
    }

    pub fn sp_type(&self) -> Option<String> {
        json::str_at(&self.base.json, "/servicePrincipalType")
    }

    pub fn is_managed_identity(&self) -> bool {
        self.sp_type().as_deref() == Some("ManagedIdentity")
    }

    /// Registered in this row's own tenant, so its app registration is
    /// in the App registrations list.
    pub fn is_tenant_owned(&self) -> bool {
        match (json::str_at(&self.base.json, "/appOwnerOrganizationId"), self.base.tenant.as_deref()) {
            (Some(owner), Some(tenant)) => owner.eq_ignore_ascii_case(tenant),
            _ => false,
        }
    }

    /// A managed identity's ARM id, from `alternativeNames` (Graph lists
    /// it beside `isExplicit=…`).
    pub fn managed_identity_resource(&self) -> Option<String> {
        json::strings_at(&self.base.json, "/alternativeNames")
            .into_iter()
            .find(|n| n.starts_with("/subscriptions/"))
    }
}

impl Resource for ServicePrincipalRow {
    directory_row!("Service Principal", SERVICE_PRINCIPAL_SEARCH);

    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SERVICE_PRINCIPAL_SECTIONS)
    }

    fn details(&self) -> Vec<(String, String)> {
        let v = &self.base.json;
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Object id".into(), self.base.object_id.clone()),
            ("App id".into(), json::opt(Some(self.base.app_id.clone()))),
            ("Type".into(), json::opt(self.sp_type())),
            ("Owner tenant".into(), json::text(v, "/appOwnerOrganizationId")),
            ("Enabled".into(), json::yes_no(json::bool_at(v, "/accountEnabled"))),
            ("Assignment required".into(), json::yes_no(json::bool_at(v, "/appRoleAssignmentRequired"))),
            ("Sign-in audience".into(), json::text(v, "/signInAudience")),
            ("Names".into(), json::join(&json::strings_at(v, "/servicePrincipalNames"))),
            ("Credentials".into(), credential_summary(v, self.base.expiry)),
            ("Notes".into(), json::text(v, "/notes")),
        ]
    }

    fn portal_url(&self) -> Option<String> {
        Some(format!(
            "https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{}/appId/{}",
            self.base.object_id, self.base.app_id
        ))
    }

    fn related(&self) -> Vec<(String, String)> {
        let mut v = Vec::new();
        if let Some(arm) = self.managed_identity_resource() {
            let label = if arm.to_lowercase().contains("/microsoft.managedidentity/userassignedidentities/") {
                "Managed identity"
            } else {
                "Identity of"
            };
            v.push((label.to_string(), arm));
        }
        if !self.is_managed_identity() && self.is_tenant_owned() && !self.base.app_id.is_empty() {
            v.push(("App registration".into(), graph::row_alias(DirectoryKind::Application, &self.base.app_id)));
        }
        v
    }

    fn cli_command(&self) -> Option<String> {
        (!self.base.app_id.is_empty()).then(|| format!("az ad sp show --id {}", shell_quote(&self.base.app_id)))
    }
}

#[derive(Debug, Clone)]
pub struct AppRegistrationRow {
    pub base: DirectoryBase,
}

impl AppRegistrationRow {
    pub fn from_json(v: &Value, tenant: Option<&str>, now: i64) -> Option<AppRegistrationRow> {
        DirectoryBase::from_json(DirectoryKind::Application, v, tenant, now).map(|base| AppRegistrationRow { base })
    }

    /// The distinct APIs this app asks permissions of, by app id.
    pub fn resource_app_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in json::arr(&self.base.json, "/requiredResourceAccess") {
            if let Some(id) = json::str_at(&r, "/resourceAppId").map(|s| s.to_lowercase()) {
                if graph::is_object_id(&id) && !out.contains(&id) {
                    out.push(id);
                }
            }
        }
        out.truncate(FOLLOWUPS_MAX);
        out
    }
}

impl Resource for AppRegistrationRow {
    directory_row!("App Registration", APP_REGISTRATION_SEARCH);

    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&APP_REGISTRATION_SECTIONS)
    }

    fn details(&self) -> Vec<(String, String)> {
        let v = &self.base.json;
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Object id".into(), self.base.object_id.clone()),
            ("App (client) id".into(), json::opt(Some(self.base.app_id.clone()))),
            ("Sign-in audience".into(), json::text(v, "/signInAudience")),
            ("Publisher domain".into(), json::text(v, "/publisherDomain")),
            ("Created".into(), json::time(json::str_at(v, "/createdDateTime"))),
            ("Public client fallback".into(), json::yes_no(json::bool_at(v, "/isFallbackPublicClient"))),
            ("Credentials".into(), credential_summary(v, self.base.expiry)),
            ("Notes".into(), json::text(v, "/notes")),
        ]
    }

    fn portal_url(&self) -> Option<String> {
        Some(format!(
            "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/{}",
            self.base.app_id
        ))
    }

    fn related(&self) -> Vec<(String, String)> {
        if self.base.app_id.is_empty() {
            return Vec::new();
        }
        vec![("Service principal".into(), graph::row_alias(DirectoryKind::ServicePrincipal, &self.base.app_id))]
    }

    fn cli_command(&self) -> Option<String> {
        (!self.base.app_id.is_empty()).then(|| format!("az ad app show --id {}", shell_quote(&self.base.app_id)))
    }
}

/// `2 secrets, 1 certificate · expiring` for the Overview.
fn credential_summary(v: &Value, expiry: Expiry) -> String {
    let (s, c) = (json::arr(v, "/passwordCredentials").len(), json::arr(v, "/keyCredentials").len());
    if s + c == 0 {
        return "none".into();
    }
    let plural = |n: usize, w: &str| format!("{} {}{}", n, w, if n == 1 { "" } else { "s" });
    format!("{}, {} · {}", plural(s, "secret"), plural(c, "certificate"), expiry.describe())
}

// ── Section bodies ────────────────────────────────────────────────────

/// The lazy state a directory row's sections read.
pub struct DirectoryLazy<'a> {
    /// Per-row child lists, keyed by [`child_key`].
    pub children: &'a LazyMap<Vec<Value>>,
    /// Directory objects by object id (an API's service principal, a
    /// grant's user): the Access principals map.
    pub objects: &'a LazyMap<Value>,
    /// Service principals by app id (an app registration's APIs).
    pub by_app_id: &'a LazyMap<Value>,
    /// The principal's Azure role assignments in the current subscription.
    pub azure_roles: Option<&'a Lazy<Vec<Value>>>,
    pub role_definitions: Option<&'a Lazy<Vec<Value>>>,
    /// `/subscriptions/{current}`, for the Azure roles read command.
    pub subscription_scope: Option<&'a str>,
}

/// The lazy key of one child list: `{row id}/{child}`.
pub fn child_key(row_id: &str, child: &str) -> String {
    format!("{}/{}", row_id, child)
}

/// A Graph lazy list's three arms; a 403 reads as the directory-read
/// warning rather than the raw error.
fn graph_list_rows(
    lazy: Option<&Lazy<Vec<Value>>>,
    what: &str,
    render: impl FnOnce(&[Value]) -> Vec<(String, String)>,
) -> Vec<(String, String)> {
    match lazy {
        None | Some(Lazy::Loading) => vec![(what.into(), "Loading…".into())],
        Some(Lazy::Error(e)) if graph::is_denied(e) => error_rows(graph::DIRECTORY_READ_DENIED),
        Some(Lazy::Error(e)) => error_rows(e),
        Some(Lazy::Loaded(items)) => render(items),
    }
}

/// The Credentials section: secrets, then certificates, each with its
/// expiry. Never a value, a `hint`, or a certificate's key.
pub fn credential_rows(v: &Value, now: i64) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    let groups = [("Secrets", "/passwordCredentials"), ("Certificates", "/keyCredentials")];
    for (title, ptr) in groups {
        let items = json::arr(v, ptr);
        lines.push((format!("{} ({})", title, items.len()), String::new()));
        if items.is_empty() {
            lines.push((String::new(), "none".into()));
        }
        for c in &items {
            let expiry = Expiry::of(json::str_at(c, "/endDateTime").as_deref(), now);
            let name = json::str_at(c, "/displayName").filter(|s| !s.is_empty()).unwrap_or_else(|| "(no name)".into());
            lines.push((format!("  {}", name), expiry.describe()));
            lines.push(("    Key id".into(), json::text(c, "/keyId")));
            if ptr == "/keyCredentials" {
                lines.push((
                    "    Type".into(),
                    format!("{} · {}", json::text(c, "/type"), json::text(c, "/usage")),
                ));
            }
            lines.push(("    Start".into(), json::time(json::str_at(c, "/startDateTime"))));
            lines.push(("    End".into(), json::time(json::str_at(c, "/endDateTime"))));
        }
        lines.push((String::new(), String::new()));
    }
    lines.push((
        String::new(),
        format!("· expiring = ends within {} days; values are never shown (Graph does not return them)", EXPIRY_WARN_DAYS),
    ));
    lines
}

/// An owner or other directory object as a line; a service principal's
/// value is its row id, so Enter jumps.
fn object_line(o: &Value) -> (String, String) {
    let id = json::text(o, "/id");
    let kind = graph::object_kind(o);
    let value = if json::str_at(o, "/@odata.type").as_deref() == Some("#microsoft.graph.servicePrincipal") {
        graph::row_id(DirectoryKind::ServicePrincipal, &id)
    } else {
        id
    };
    (format!("{} · {}", graph::object_display(o), kind), value)
}

fn owner_rows(items: &[Value]) -> Vec<(String, String)> {
    if items.is_empty() {
        return vec![(String::new(), "No owners".into())];
    }
    items.iter().map(object_line).collect()
}

/// A directory object's display name when resolved, else its id.
fn object_name(objects: &LazyMap<Value>, id: &str) -> String {
    match objects.get(&id.to_lowercase()) {
        Some(Lazy::Loaded(o)) => graph::object_display(o),
        _ => id.to_string(),
    }
}

/// The value of a permission id on an API's service principal: an app
/// role (`appRoles`) or a delegated scope (`oauth2PermissionScopes`).
fn permission_value(api: Option<&Value>, ptr: &str, id: &str) -> Option<String> {
    json::arr(api?, ptr)
        .iter()
        .find(|p| json::str_at(p, "/id").is_some_and(|p| p.eq_ignore_ascii_case(id)))
        .and_then(|p| json::str_at(p, "/value"))
}

fn loaded<'a>(map: &'a LazyMap<Value>, key: &str) -> Option<&'a Value> {
    match map.get(&key.to_lowercase()) {
        Some(Lazy::Loaded(v)) => Some(v),
        _ => None,
    }
}

/// App role assignments: what this principal was granted on other APIs
/// (Graph application permissions, a custom API's roles).
fn app_role_assignment_rows(items: &[Value], objects: &LazyMap<Value>) -> Vec<(String, String)> {
    if items.is_empty() {
        return vec![(String::new(), "No app role assignments".into())];
    }
    let mut lines = Vec::new();
    for a in items {
        let resource_id = json::text(a, "/resourceId");
        let role_id = json::text(a, "/appRoleId");
        let role = if role_id == "00000000-0000-0000-0000-000000000000" {
            "default access".to_string()
        } else {
            permission_value(loaded(objects, &resource_id), "/appRoles", &role_id).unwrap_or(role_id)
        };
        lines.push((
            format!("{} · {}", json::text(a, "/resourceDisplayName"), role),
            graph::row_id(DirectoryKind::ServicePrincipal, &resource_id),
        ));
        lines.push(("  Granted".into(), json::time(json::str_at(a, "/createdDateTime"))));
    }
    lines
}

/// OAuth2 grants: delegated permissions consented for this client.
fn oauth2_grant_rows(items: &[Value], objects: &LazyMap<Value>) -> Vec<(String, String)> {
    if items.is_empty() {
        return vec![(String::new(), "No delegated permission grants".into())];
    }
    let mut lines = Vec::new();
    for g in items {
        let resource_id = json::text(g, "/resourceId");
        lines.push((String::new(), String::new()));
        lines.push((object_name(objects, &resource_id), graph::row_id(DirectoryKind::ServicePrincipal, &resource_id)));
        let who = match json::str_at(g, "/consentType").as_deref() {
            Some("AllPrincipals") => "all users (admin consent)".to_string(),
            Some("Principal") => format!("one user · {}", object_name(objects, &json::text(g, "/principalId"))),
            other => json::opt(other.map(str::to_string)),
        };
        lines.push(("  Consent".into(), who));
        lines.push(("  Scopes".into(), json::text(g, "/scope").trim().to_string()));
    }
    lines
}

/// API permissions: `requiredResourceAccess`, each API named and each
/// permission resolved once its service principal has loaded.
fn api_permission_rows(r: &AppRegistrationRow, by_app_id: &LazyMap<Value>) -> Vec<(String, String)> {
    let required = json::arr(&r.base.json, "/requiredResourceAccess");
    if required.is_empty() {
        return vec![(String::new(), "No API permissions requested".into())];
    }
    let mut lines = Vec::new();
    for res in &required {
        let app_id = json::text(res, "/resourceAppId");
        let api = loaded(by_app_id, &app_id);
        let name = api.and_then(|a| json::str_at(a, "/displayName")).unwrap_or_else(|| app_id.clone());
        lines.push((String::new(), String::new()));
        lines.push((name, graph::row_alias(DirectoryKind::ServicePrincipal, &app_id)));
        for access in json::arr(res, "/resourceAccess") {
            let id = json::text(&access, "/id");
            let (kind, ptr) = match json::str_at(&access, "/type").as_deref() {
                Some("Role") => ("application", "/appRoles"),
                _ => ("delegated", "/oauth2PermissionScopes"),
            };
            lines.push((format!("  {}", kind), permission_value(api, ptr, &id).unwrap_or(id)));
        }
    }
    lines.push((String::new(), String::new()));
    // An API with no service principal here (404) is normal: its ids stay
    // ids. Any other failure means the names exist but could not be read.
    let failed = required.iter().find_map(|res| match by_app_id.get(&json::text(res, "/resourceAppId").to_lowercase()) {
        Some(Lazy::Error(e)) if !graph::is_not_found(e) => Some(e.clone()),
        _ => None,
    });
    if let Some(e) = failed {
        let e = if graph::is_denied(&e) { graph::DIRECTORY_READ_DENIED.to_string() } else { e };
        lines.push((String::new(), format!("· ⚠ permission names unavailable, ids shown: {}", e)));
    }
    lines.push((String::new(), "· requested, not necessarily consented: grants are on the service principal".into()));
    lines
}

fn redirect_uri_rows(v: &Value) -> Vec<(String, String)> {
    let groups = [("Web", "/web/redirectUris"), ("SPA", "/spa/redirectUris"), ("Public client", "/publicClient/redirectUris")];
    let mut lines = Vec::new();
    for (label, ptr) in groups {
        for uri in json::strings_at(v, ptr) {
            lines.push((label.to_string(), uri));
        }
    }
    if lines.is_empty() {
        lines.push((String::new(), "No redirect URIs".into()));
    }
    lines
}

fn exposed_api_rows(v: &Value) -> Vec<(String, String)> {
    let mut lines = vec![("Identifier URIs".to_string(), json::join(&json::strings_at(v, "/identifierUris")))];
    let scopes = json::arr(v, "/api/oauth2PermissionScopes");
    lines.push((String::new(), String::new()));
    lines.push((format!("Scopes ({})", scopes.len()), String::new()));
    for s in &scopes {
        let enabled = if json::bool_at(s, "/isEnabled") == Some(false) { " · disabled" } else { "" };
        lines.push((
            format!("  {}", json::text(s, "/value")),
            format!("{} · {}{}", json::text(s, "/adminConsentDisplayName"), json::text(s, "/type"), enabled),
        ));
    }
    let roles = json::arr(v, "/appRoles");
    lines.push((String::new(), String::new()));
    lines.push((format!("App roles ({})", roles.len()), String::new()));
    for r in &roles {
        let enabled = if json::bool_at(r, "/isEnabled") == Some(false) { " · disabled" } else { "" };
        lines.push((
            format!("  {}", json::text(r, "/value")),
            format!(
                "{} · {}{}",
                json::text(r, "/displayName"),
                json::join(&json::strings_at(r, "/allowedMemberTypes")),
                enabled
            ),
        ));
    }
    lines
}

fn federated_rows(items: &[Value]) -> Vec<(String, String)> {
    if items.is_empty() {
        return vec![(String::new(), "No federated credentials".into())];
    }
    let mut lines = Vec::new();
    for fc in items {
        lines.push((String::new(), String::new()));
        lines.push((json::text(fc, "/name"), String::new()));
        lines.push(("  Issuer".into(), json::text(fc, "/issuer")));
        lines.push(("  Subject".into(), json::text(fc, "/subject")));
        lines.push(("  Audiences".into(), json::join(&json::strings_at(fc, "/audiences"))));
    }
    lines
}

fn graph_tag_rows(v: &Value) -> Vec<(String, String)> {
    let tags = json::strings_at(v, "/tags");
    if tags.is_empty() {
        return vec![(String::new(), "No tags".into())];
    }
    tags.into_iter().map(|t| (t, String::new())).collect()
}

pub fn service_principal_section_lines(
    r: &ServicePrincipalRow,
    section: ServicePrincipalDetailSection,
    lazy: &DirectoryLazy,
    now: i64,
) -> Vec<(String, String)> {
    use ServicePrincipalDetailSection as S;
    let child = |c: &str| lazy.children.get(&child_key(&r.base.id, c));
    match section {
        S::Overview => overview_rows(r),
        S::Credentials => credential_rows(&r.base.json, now),
        S::AppRoleAssignments => graph_list_rows(child("appRoleAssignments"), "App role assignments", |items| {
            app_role_assignment_rows(items, lazy.objects)
        }),
        S::OAuth2Grants => graph_list_rows(child("oauth2PermissionGrants"), "OAuth2 grants", |items| {
            oauth2_grant_rows(items, lazy.objects)
        }),
        S::Owners => graph_list_rows(child("owners"), "Owners", owner_rows),
        S::AzureRoles => match lazy.subscription_scope {
            Some(sub) => crate::azure::services::access::can_do_rows(
                Some(&r.base.object_id),
                sub,
                lazy.azure_roles,
                lazy.role_definitions,
            ),
            None => vec![(String::new(), "No subscription selected".into())],
        },
        S::Related => related_rows(r),
        S::Tags => graph_tag_rows(&r.base.json),
    }
}

pub fn app_registration_section_lines(
    r: &AppRegistrationRow,
    section: AppRegistrationDetailSection,
    lazy: &DirectoryLazy,
    now: i64,
) -> Vec<(String, String)> {
    use AppRegistrationDetailSection as S;
    let child = |c: &str| lazy.children.get(&child_key(&r.base.id, c));
    match section {
        S::Overview => overview_rows(r),
        S::Credentials => credential_rows(&r.base.json, now),
        S::FederatedCredentials => graph_list_rows(child("federatedIdentityCredentials"), "Federated credentials", federated_rows),
        S::ApiPermissions => api_permission_rows(r, lazy.by_app_id),
        S::RedirectUris => redirect_uri_rows(&r.base.json),
        S::Owners => graph_list_rows(child("owners"), "Owners", owner_rows),
        S::ExposedApi => exposed_api_rows(&r.base.json),
        S::Related => related_rows(r),
        S::Tags => graph_tag_rows(&r.base.json),
    }
}

/// The directory objects a service principal's loaded sections name by id
/// (an API's service principal, a consenting user), for the app to
/// resolve; bounded by [`FOLLOWUPS_MAX`].
pub fn followup_object_ids(row_id: &str, children: &LazyMap<Vec<Value>>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (child, ptrs) in [("appRoleAssignments", &["/resourceId"][..]), ("oauth2PermissionGrants", &["/resourceId", "/principalId"][..])] {
        if let Some(Lazy::Loaded(items)) = children.get(&child_key(row_id, child)) {
            for item in items {
                for ptr in ptrs {
                    if let Some(id) = json::str_at(item, ptr).map(|s| s.to_lowercase()) {
                        if graph::is_object_id(&id) && !out.contains(&id) {
                            out.push(id);
                        }
                    }
                }
            }
        }
    }
    out.truncate(FOLLOWUPS_MAX);
    out
}

// ── Provider half: the two lists ──────────────────────────────────────

/// Graph's wording for a denied list, made readable.
fn list_error(e: Error) -> Error {
    let text = e.to_string();
    if graph::is_denied(&text) {
        Error::Azure(format!("{} (403)", graph::DIRECTORY_READ_DENIED))
    } else {
        e
    }
}

/// Stream one Graph list as `ResourcesPartiallyLoaded` pages, skipping
/// ids already seen (the two service principal queries overlap).
#[allow(clippy::too_many_arguments)]
async fn stream_list<F>(
    graph: &ArmClient,
    path: &str,
    query: &[(String, String)],
    headers: &[crate::azure::arm::Header],
    service: ServiceType,
    message: &str,
    event_tx: &mpsc::UnboundedSender<Event>,
    seen: &mut HashSet<String>,
    loaded: &mut usize,
    mut rows: F,
) -> Result<()>
where
    F: FnMut(&Value) -> Option<Box<dyn Resource>> + Send,
{
    let query: Vec<(&str, &str)> = query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    graph
        .graph_list_pages_while(path, &query, headers, |page| {
            let resources: Vec<Box<dyn Resource>> = page
                .iter()
                .filter_map(&mut rows)
                .filter(|r| seen.insert(r.id().to_lowercase()))
                .collect();
            *loaded += resources.len();
            let _ = event_tx.send(Event::ResourcesPartiallyLoaded {
                service,
                resources,
                progress: LoadProgress {
                    loaded_count: *loaded,
                    total_count: None,
                    status_message: Some(message.to_string()),
                },
            });
            true
        })
        .await
        .map(|_| ())
        .map_err(list_error)
}

/// The Service principals sub-tab: managed identities (a default filter)
/// then this tenant's own apps (an advanced query). The second failing
/// alone is a warning; the rows already streamed stay.
pub async fn stream_service_principals(
    graph: std::result::Result<std::sync::Arc<ArmClient>, String>,
    tenant: Option<String>,
    service: ServiceType,
    event_tx: mpsc::UnboundedSender<Event>,
) -> Result<()> {
    let graph = match graph {
        Ok(g) => g,
        Err(e) => return finish_stream(service, Err(Error::Azure(e)), &event_tx),
    };
    let now = now_unix();
    let mut seen = HashSet::new();
    let mut loaded = 0usize;
    let t = tenant.clone();
    let first = stream_list(
        &graph,
        graph::SERVICE_PRINCIPALS_PATH,
        &graph::managed_identity_sps_query(),
        &[],
        service,
        "Listing managed identities' service principals…",
        &event_tx,
        &mut seen,
        &mut loaded,
        |v| ServicePrincipalRow::from_json(v, t.as_deref(), now).map(|r| Box::new(r) as Box<dyn Resource>),
    )
    .await;
    if let Err(e) = first {
        return finish_stream(service, Err(e), &event_tx);
    }
    let owned = match tenant.as_deref().and_then(graph::tenant_owned_sps_query) {
        Some(q) => {
            stream_list(
                &graph,
                graph::SERVICE_PRINCIPALS_PATH,
                &q,
                &graph::advanced_query_headers(),
                service,
                "Listing this tenant's service principals…",
                &event_tx,
                &mut seen,
                &mut loaded,
                |v| ServicePrincipalRow::from_json(v, tenant.as_deref(), now).map(|r| Box::new(r) as Box<dyn Resource>),
            )
            .await
        }
        None => Err(Error::Azure("no tenant id for the owner filter".into())),
    };
    if let Err(e) = owned {
        let _ = event_tx.send(Event::ResourceLoadWarning {
            service,
            warning: format!("this tenant's apps' service principals: {}", e),
        });
    }
    finish_stream(service, Ok(loaded), &event_tx)
}

/// The App registrations sub-tab.
pub async fn stream_app_registrations(
    graph: std::result::Result<std::sync::Arc<ArmClient>, String>,
    tenant: Option<String>,
    service: ServiceType,
    event_tx: mpsc::UnboundedSender<Event>,
) -> Result<()> {
    let graph = match graph {
        Ok(g) => g,
        Err(e) => return finish_stream(service, Err(Error::Azure(e)), &event_tx),
    };
    let now = now_unix();
    let mut seen = HashSet::new();
    let mut loaded = 0usize;
    let r = stream_list(
        &graph,
        graph::APPLICATIONS_PATH,
        &graph::applications_query(),
        &[],
        service,
        "Listing app registrations…",
        &event_tx,
        &mut seen,
        &mut loaded,
        |v| AppRegistrationRow::from_json(v, tenant.as_deref(), now).map(|r| Box::new(r) as Box<dyn Resource>),
    )
    .await;
    finish_stream(service, r.map(|_| loaded), &event_tx)
}

/// One directory row by synthetic id (detail-pane `r`).
pub async fn get_directory_row(
    graph: std::result::Result<std::sync::Arc<ArmClient>, String>,
    tenant: Option<&str>,
    id: &str,
) -> Result<Box<dyn Resource>> {
    let graph = graph.map_err(Error::Azure)?;
    let (kind, _) = graph::parse_row_id(id).ok_or_else(|| Error::ResourceNotFound(id.to_string()))?;
    let path = graph::object_path(id, None).ok_or_else(|| Error::ResourceNotFound(id.to_string()))?;
    let v = graph.graph_get(&path, &[]).await.map_err(list_error)?;
    let now = now_unix();
    let row: Option<Box<dyn Resource>> = match kind {
        DirectoryKind::ServicePrincipal => ServicePrincipalRow::from_json(&v, tenant, now).map(|r| Box::new(r) as Box<dyn Resource>),
        DirectoryKind::Application => AppRegistrationRow::from_json(&v, tenant, now).map(|r| Box::new(r) as Box<dyn Resource>),
    };
    row.ok_or_else(|| Error::ResourceNotFound(id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "65415bb1-9267-4313-bbf5-ae259732ee12";
    /// 2026-01-01T00:00:00Z.
    const NOW: i64 = 1_767_225_600;

    fn sp_json() -> Value {
        serde_json::json!({
            "id": "00af5dfb-85da-4b41-a677-0c6b86dd34f8",
            "appId": "11111111-2222-3333-4444-555555555555",
            "displayName": "orders-api",
            "servicePrincipalType": "Application",
            "appOwnerOrganizationId": TENANT,
            "accountEnabled": true,
            "appRoleAssignmentRequired": false,
            "alternativeNames": [],
            "servicePrincipalNames": ["api://orders"],
            "tags": ["WindowsAzureActiveDirectoryIntegratedApp"],
            "keyCredentials": [],
            "passwordCredentials": [
                {"displayName": "ci", "keyId": "aaaaaaaa-0000-0000-0000-000000000001",
                 "startDateTime": "2025-01-01T00:00:00Z", "endDateTime": "2026-01-15T00:00:00Z", "hint": "abc", "secretText": null}
            ]
        })
    }

    fn mi_json() -> Value {
        serde_json::json!({
            "id": "22222222-0000-0000-0000-000000000000",
            "appId": "33333333-0000-0000-0000-000000000000",
            "displayName": "id-app",
            "servicePrincipalType": "ManagedIdentity",
            "alternativeNames": ["isExplicit=True", "/subscriptions/0000/resourcegroups/rg-id/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-app"],
            "keyCredentials": [], "passwordCredentials": []
        })
    }

    fn app_json() -> Value {
        serde_json::json!({
            "id": "44444444-0000-0000-0000-000000000000",
            "appId": "11111111-2222-3333-4444-555555555555",
            "displayName": "orders-api",
            "signInAudience": "AzureADMyOrg",
            "createdDateTime": "2024-05-01T10:00:00Z",
            "identifierUris": ["api://orders"],
            "web": {"redirectUris": ["https://orders.example/signin-oidc"]},
            "spa": {"redirectUris": []},
            "publicClient": {"redirectUris": ["http://localhost"]},
            "api": {"oauth2PermissionScopes": [{"id": "s1", "value": "Orders.Read", "adminConsentDisplayName": "Read orders", "type": "User", "isEnabled": true}]},
            "appRoles": [{"id": "r1", "value": "Orders.Admin", "displayName": "Admins", "allowedMemberTypes": ["User"], "isEnabled": false}],
            "requiredResourceAccess": [{
                "resourceAppId": "00000003-0000-0000-c000-000000000000",
                "resourceAccess": [
                    {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"},
                    {"id": "df021288-bdef-4463-88db-98f22de89214", "type": "Role"}
                ]
            }],
            "passwordCredentials": [
                {"displayName": "old", "keyId": "k1", "startDateTime": "2024-01-01T00:00:00Z", "endDateTime": "2025-06-01T00:00:00Z"}
            ],
            "keyCredentials": [
                {"displayName": "CN=orders", "keyId": "k2", "type": "AsymmetricX509Cert", "usage": "Verify",
                 "startDateTime": "2025-01-01T00:00:00Z", "endDateTime": "2027-01-01T00:00:00Z", "key": null}
            ]
        })
    }

    #[test]
    fn iso_times_parse_to_unix() {
        assert_eq!(iso_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso_to_unix("2026-01-01T00:00:00Z"), Some(NOW));
        assert_eq!(iso_to_unix("2023-11-14T22:13:20.1234567Z"), Some(1_700_000_000));
        assert_eq!(iso_to_unix("garbage"), None);
        assert_eq!(iso_to_unix("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn expiry_is_expired_expiring_within_thirty_days_or_ok() {
        assert_eq!(Expiry::of(Some("2025-12-31T00:00:00Z"), NOW), Expiry::Expired);
        assert_eq!(Expiry::of(Some("2026-01-15T00:00:00Z"), NOW), Expiry::Expiring(14));
        assert_eq!(Expiry::of(Some("2026-03-01T00:00:00Z"), NOW), Expiry::Ok);
        assert_eq!(Expiry::of(None, NOW), Expiry::Unknown);
        assert_eq!(Expiry::Expiring(14).describe(), "expires in 14 d");
        assert_eq!(Expiry::Expired.bucket(), Some((ResourceState::Unavailable, "expired")));
    }

    #[test]
    fn a_row_takes_its_worst_credential_through_the_ladder() {
        let sp = ServicePrincipalRow::from_json(&sp_json(), Some(TENANT), NOW).unwrap();
        assert_eq!(sp.state(), ResourceState::Pending);
        assert_eq!(sp.state_label(), "expiring");
        let app = AppRegistrationRow::from_json(&app_json(), Some(TENANT), NOW).unwrap();
        assert_eq!(app.state_label(), "expired", "one expired secret beats an ok certificate");
        let mi = ServicePrincipalRow::from_json(&mi_json(), Some(TENANT), NOW).unwrap();
        assert_eq!(mi.state(), ResourceState::stateless(), "no credentials: stateless");
    }

    #[test]
    fn service_principal_rows_key_on_a_synthetic_id_and_answer_to_the_app_id() {
        let sp = ServicePrincipalRow::from_json(&sp_json(), Some(TENANT), NOW).unwrap();
        assert_eq!(sp.id(), "graph:/servicePrincipals/00af5dfb-85da-4b41-a677-0c6b86dd34f8");
        assert!(sp.matches_id("graph:/servicePrincipals(appId='11111111-2222-3333-4444-555555555555')"));
        assert!(sp.matches_id("GRAPH:/servicePrincipals/00AF5DFB-85DA-4B41-A677-0C6B86DD34F8"));
        assert!(!sp.matches_id("graph:/applications(appId='11111111-2222-3333-4444-555555555555')"));
        assert_eq!(sp.location(), None, "never filtered by location");
        assert_eq!(sp.resource_group(), None);
        assert_eq!(sp.list_cell(), "11111111-2222-3333-4444-555555555555");
        assert_eq!(sp.cli_command().as_deref(), Some("az ad sp show --id 11111111-2222-3333-4444-555555555555"));
        assert!(sp.portal_url().unwrap().contains("ManagedAppMenuBlade"));
        assert_eq!(
            sp.related(),
            vec![("App registration".to_string(), "graph:/applications(appId='11111111-2222-3333-4444-555555555555')".to_string())]
        );
        let mi = ServicePrincipalRow::from_json(&mi_json(), Some(TENANT), NOW).unwrap();
        assert_eq!(mi.related()[0].0, "Managed identity");
        assert!(mi.related()[0].1.starts_with("/subscriptions/0000/"));
        assert_eq!(mi.related().len(), 1, "a managed identity has no app registration");
        assert!(ServicePrincipalRow::from_json(&serde_json::json!({"id": "../x"}), None, NOW).is_none());
    }

    #[test]
    fn credentials_show_name_key_id_dates_and_expiry_never_a_hint() {
        let sp = ServicePrincipalRow::from_json(&sp_json(), Some(TENANT), NOW).unwrap();
        let lines = credential_rows(&sp.base.json, NOW);
        assert!(lines.iter().any(|(k, v)| k == "  ci" && v == "expires in 14 d"));
        assert!(lines.iter().any(|(k, v)| k == "    Key id" && v == "aaaaaaaa-0000-0000-0000-000000000001"));
        assert!(lines.iter().any(|(k, v)| k == "    End" && v == "2026-01-15 00:00:00"));
        assert!(!lines.iter().any(|(_, v)| v.contains("abc")), "the hint is never shown");
        assert!(lines.iter().any(|(k, _)| k == "Certificates (0)"));
    }

    #[test]
    fn section_labels() {
        let sp: Vec<&str> = SERVICE_PRINCIPAL_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(sp, ["Overview", "Credentials", "App role assignments", "OAuth2 grants", "Owners", "Azure roles", "Related", "Tags"]);
        let app: Vec<&str> = APP_REGISTRATION_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            app,
            ["Overview", "Credentials", "Federated credentials", "API permissions", "Redirect URIs", "Owners", "Exposed API", "Related", "Tags"]
        );
    }

    fn empty_lazy<'a>(children: &'a LazyMap<Vec<Value>>, objects: &'a LazyMap<Value>, by_app_id: &'a LazyMap<Value>) -> DirectoryLazy<'a> {
        DirectoryLazy { children, objects, by_app_id, azure_roles: None, role_definitions: None, subscription_scope: Some("/subscriptions/0000") }
    }

    #[test]
    fn search_reads_redirect_and_identifier_uris() {
        let matcher = crate::search::fuzzy::FuzzyMatcher::new();
        let mut v = app_json();
        v["displayName"] = "xq-7".into();
        v["web"]["homePageUrl"] = "https://zephyr.example".into();
        let mut sp = sp_json();
        sp["displayName"] = "xq-7".into();
        sp["replyUrls"] = serde_json::json!(["https://quokka.example/auth"]);
        let rows: Vec<Box<dyn Resource>> = vec![
            Box::new(AppRegistrationRow::from_json(&v, Some(TENANT), NOW).unwrap()),
            Box::new(ServicePrincipalRow::from_json(&sp, Some(TENANT), NOW).unwrap()),
        ];
        let hits = |q: &str| matcher.filter_resources(q, &rows).into_iter().map(|(i, _)| i).collect::<Vec<_>>();
        assert_eq!(hits("orders.example/signin"), vec![0], "a web redirect URI");
        assert_eq!(hits("api://orders"), vec![0, 1], "an identifier URI, which the service principal also names");
        assert_eq!(hits("zephyr"), vec![0], "the home page");
        assert_eq!(hits("quokka"), vec![1], "a service principal's reply URL");
    }

    #[test]
    fn app_sections_render_permissions_redirects_and_the_exposed_api() {
        let app = AppRegistrationRow::from_json(&app_json(), Some(TENANT), NOW).unwrap();
        let (children, objects) = (LazyMap::default(), LazyMap::default());
        let mut by_app_id: LazyMap<Value> = LazyMap::default();
        assert_eq!(app.resource_app_ids(), ["00000003-0000-0000-c000-000000000000"]);
        let lines = app_registration_section_lines(&app, AppRegistrationDetailSection::ApiPermissions, &empty_lazy(&children, &objects, &by_app_id), NOW);
        assert!(lines.iter().any(|(k, v)| k == "  delegated" && v == "e1fe6dd8-ba31-4d61-89e7-88639da4683d"), "ids until the API loads");
        assert!(!lines.iter().any(|(_, v)| v.contains("⚠")), "loading is not a failure");
        let mut failed: LazyMap<Value> = LazyMap::default();
        failed.apply("00000003-0000-0000-c000-000000000000".into(), Err("Azure error: 500 InternalServerError: boom".into()));
        let lines = app_registration_section_lines(&app, AppRegistrationDetailSection::ApiPermissions, &empty_lazy(&children, &objects, &failed), NOW);
        assert!(lines.iter().any(|(_, v)| v == "· ⚠ permission names unavailable, ids shown: Azure error: 500 InternalServerError: boom"), "{lines:?}");
        let mut absent: LazyMap<Value> = LazyMap::default();
        absent.apply("00000003-0000-0000-c000-000000000000".into(), Err("Azure error: 404 Request_ResourceNotFound: gone".into()));
        let lines = app_registration_section_lines(&app, AppRegistrationDetailSection::ApiPermissions, &empty_lazy(&children, &objects, &absent), NOW);
        assert!(!lines.iter().any(|(_, v)| v.contains("⚠")), "an API with no service principal here is not a failure: {lines:?}");
        by_app_id.apply(
            "00000003-0000-0000-c000-000000000000".into(),
            Ok(serde_json::json!({
                "displayName": "Microsoft Graph",
                "oauth2PermissionScopes": [{"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "value": "User.Read"}],
                "appRoles": [{"id": "df021288-bdef-4463-88db-98f22de89214", "value": "User.Read.All"}]
            })),
        );
        let lines = app_registration_section_lines(&app, AppRegistrationDetailSection::ApiPermissions, &empty_lazy(&children, &objects, &by_app_id), NOW);
        assert!(lines.iter().any(|(k, v)| k == "Microsoft Graph" && v == "graph:/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')"));
        assert!(lines.iter().any(|(k, v)| k == "  delegated" && v == "User.Read"));
        assert!(lines.iter().any(|(k, v)| k == "  application" && v == "User.Read.All"));

        let lazy = empty_lazy(&children, &objects, &by_app_id);
        let redirects = app_registration_section_lines(&app, AppRegistrationDetailSection::RedirectUris, &lazy, NOW);
        assert_eq!(redirects, vec![("Web".into(), "https://orders.example/signin-oidc".into()), ("Public client".into(), "http://localhost".into())]);
        let api = app_registration_section_lines(&app, AppRegistrationDetailSection::ExposedApi, &lazy, NOW);
        assert!(api.iter().any(|(k, v)| k == "  Orders.Read" && v == "Read orders · User"));
        assert!(api.iter().any(|(k, v)| k == "  Orders.Admin" && v.ends_with("disabled")));
        assert_eq!(app.cli_command().as_deref(), Some("az ad app show --id 11111111-2222-3333-4444-555555555555"));
        assert_eq!(app.related()[0].1, "graph:/servicePrincipals(appId='11111111-2222-3333-4444-555555555555')");
    }

    #[test]
    fn sp_lazy_sections_name_their_resources_and_a_403_reads_as_directory_read() {
        let sp = ServicePrincipalRow::from_json(&sp_json(), Some(TENANT), NOW).unwrap();
        let graph_sp = "7408235b-7540-4850-82fe-a5f15ed019e2";
        let mut children: LazyMap<Vec<Value>> = LazyMap::default();
        children.apply(
            child_key(sp.id(), "appRoleAssignments"),
            Ok(vec![serde_json::json!({"resourceId": graph_sp, "resourceDisplayName": "Microsoft Graph", "appRoleId": "r-1", "createdDateTime": "2025-01-01T00:00:00Z"})]),
        );
        children.apply(
            child_key(sp.id(), "oauth2PermissionGrants"),
            Ok(vec![serde_json::json!({"resourceId": graph_sp, "consentType": "AllPrincipals", "scope": " User.Read openid "})]),
        );
        children.apply(child_key(sp.id(), "owners"), Err("403 Forbidden Authorization_RequestDenied".into()));
        assert_eq!(followup_object_ids(sp.id(), &children), [graph_sp]);
        let mut objects: LazyMap<Value> = LazyMap::default();
        objects.apply(
            graph_sp.into(),
            Ok(serde_json::json!({"@odata.type": "#microsoft.graph.servicePrincipal", "displayName": "Microsoft Graph", "appRoles": [{"id": "r-1", "value": "Directory.Read.All"}]})),
        );
        let by_app_id = LazyMap::default();
        let lazy = empty_lazy(&children, &objects, &by_app_id);
        let roles = service_principal_section_lines(&sp, ServicePrincipalDetailSection::AppRoleAssignments, &lazy, NOW);
        assert_eq!(roles[0], ("Microsoft Graph · Directory.Read.All".to_string(), format!("graph:/servicePrincipals/{}", graph_sp)));
        let grants = service_principal_section_lines(&sp, ServicePrincipalDetailSection::OAuth2Grants, &lazy, NOW);
        assert!(grants.iter().any(|(k, v)| k == "  Consent" && v == "all users (admin consent)"));
        assert!(grants.iter().any(|(k, v)| k == "  Scopes" && v == "User.Read openid"));
        let owners = service_principal_section_lines(&sp, ServicePrincipalDetailSection::Owners, &lazy, NOW);
        assert!(owners.iter().any(|(_, v)| v.contains(graph::DIRECTORY_READ_DENIED)), "{:?}", owners);
        let azure = service_principal_section_lines(&sp, ServicePrincipalDetailSection::AzureRoles, &lazy, NOW);
        assert_eq!(azure[0].0, "Can do");
    }
}
