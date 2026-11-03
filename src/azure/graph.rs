//! Microsoft Graph, read-only (ADR 0004): the one module that names a
//! Graph host, path or query. Requests go through the Graph flavour of
//! [`ArmClient`](crate::azure::arm::ArmClient), so the one GET
//! constructor and `ReadOnlyPolicy` cover them; this file only says
//! *what* to GET.
//!
//! The guard (`tests/readonly_guard.rs`) allows the Graph hosts here and
//! nowhere else, and forbids `getByIds` (a `POST`), any `$select` and a
//! `key` field in the literals here: Graph returns a certificate's `key`
//! when `keyCredentials` is selected, so nebaz selects nothing.

use crate::azure::services::json;
use serde_json::Value;

/// The section-level wording for a Graph 403 (a guest, or a tenant that
/// restricts members' directory access).
pub const DIRECTORY_READ_DENIED: &str = "directory read not allowed for this account";

/// The section-level wording for a 403 on a service principal's claims
/// policies: they need a directory role, not plain directory read.
pub const CLAIMS_READ_DENIED: &str = "reading claims policies needs Global Reader or Application Administrator";

/// The Graph base URL for an ARM endpoint, by cloud. `None` for an
/// endpoint whose cloud has no known Graph (a test endpoint, Azure Stack):
/// Graph sections then say so and nothing is requested.
pub fn graph_endpoint_for(arm_endpoint: &str) -> Option<&'static str> {
    let host = arm_endpoint
        .trim()
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    match host.as_str() {
        "management.azure.com" => Some("https://graph.microsoft.com"),
        "management.usgovcloudapi.net" => Some("https://graph.microsoft.us"),
        "management.chinacloudapi.cn" => Some("https://microsoftgraph.chinacloudapi.cn"),
        _ => None,
    }
}

/// The error a Graph fetch returns when the cloud has no Graph endpoint.
pub fn no_graph_for(arm_endpoint: &str) -> String {
    format!("no Microsoft Graph endpoint is known for {}", arm_endpoint)
}

/// Whether a directory object id is safe to put in a path: a GUID's
/// characters only, so an ARM body can never steer the request.
pub fn is_object_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// `GET /v1.0/directoryObjects/{id}`: the typed object (user, group,
/// service principal…) with its `@odata.type`. One per principal; the
/// batch form (`getByIds`) is a `POST` and never used.
pub fn directory_object_path(object_id: &str) -> Option<String> {
    is_object_id(object_id).then(|| format!("/v1.0/directoryObjects/{}", object_id))
}

// ── Service principals and app registrations (issue #78) ──────────────

/// The page size for the two directory lists (Graph's maximum).
const PAGE_SIZE: &str = "999";

/// `GET /v1.0/applications`: every app registration in the tenant.
pub const APPLICATIONS_PATH: &str = "/v1.0/applications";

/// `GET /v1.0/servicePrincipals`, always filtered (see the two queries).
pub const SERVICE_PRINCIPALS_PATH: &str = "/v1.0/servicePrincipals";

pub fn applications_query() -> Vec<(String, String)> {
    vec![("$top".into(), PAGE_SIZE.into())]
}

/// Managed identities' service principals: `servicePrincipalType eq` is a
/// default filter, no advanced query needed.
pub fn managed_identity_sps_query() -> Vec<(String, String)> {
    vec![
        ("$filter".into(), "servicePrincipalType eq 'ManagedIdentity'".into()),
        ("$top".into(), PAGE_SIZE.into()),
    ]
}

/// Service principals of apps registered in this tenant.
/// `appOwnerOrganizationId` filters only as an advanced query: it needs
/// `$count=true` and the [`advanced_query_headers`]. `None` for a tenant
/// id that is not GUID-shaped.
pub fn tenant_owned_sps_query(tenant_id: &str) -> Option<Vec<(String, String)>> {
    is_object_id(tenant_id).then(|| {
        vec![
            ("$filter".into(), format!("appOwnerOrganizationId eq {}", tenant_id)),
            ("$count".into(), "true".into()),
            ("$top".into(), PAGE_SIZE.into()),
        ]
    })
}

/// `ConsistencyLevel: eventual`, which an advanced query requires.
pub fn advanced_query_headers() -> Vec<crate::azure::arm::Header> {
    vec![("consistencylevel", "eventual".to_string())]
}

/// `/v1.0/applications/{id}` or `/v1.0/servicePrincipals/{id}`, and their
/// children (`owners`, `federatedIdentityCredentials`, `appRoleAssignments`,
/// `oauth2PermissionGrants`), from a row's synthetic id.
pub fn object_path(row_id: &str, child: Option<&str>) -> Option<String> {
    let (kind, oid) = parse_row_id(row_id)?;
    let base = format!("/v1.0/{}/{}", kind.collection(), oid);
    Some(match child {
        Some(c) => format!("{}/{}", base, c),
        None => base,
    })
}

/// The lazy child a service principal's claims-mapping policies load
/// under: `GET /v1.0/servicePrincipals/{id}/claimsMappingPolicies`
/// (through [`object_path`]).
pub const CLAIMS_MAPPING_CHILD: &str = "claimsMappingPolicies";

/// The lazy child its custom claims policy loads under.
pub const CLAIMS_POLICY_CHILD: &str = "claimsPolicy";

/// `GET /beta/servicePrincipals/{id}/claimsPolicy`: the custom claims
/// policy, which is what the portal's Attributes & Claims edits. Beta only,
/// and the one `/beta` path nebaz reads (ADR 0004's amendment). `None`
/// for anything but a service principal row.
pub fn claims_policy_path(row_id: &str) -> Option<String> {
    match parse_row_id(row_id)? {
        (DirectoryKind::ServicePrincipal, oid) => Some(format!("/beta/servicePrincipals/{}/{}", oid, CLAIMS_POLICY_CHILD)),
        _ => None,
    }
}

/// `GET /v1.0/servicePrincipals(appId='{appId}')`: an API's service
/// principal by its app id (an app registration's API permissions name
/// the resource only by app id).
pub fn service_principal_by_app_id_path(app_id: &str) -> Option<String> {
    is_object_id(app_id).then(|| format!("/v1.0/servicePrincipals(appId='{}')", app_id))
}

// ── Synthetic row ids ─────────────────────────────────────────────────

/// Directory rows have no ARM id. They key on `graph:/{collection}/{id}`
/// (the object's Graph path), which no ARM id can start with; an alias
/// `graph:/{collection}(appId='{appId}')` names the same row by app id, so
/// a link that only knows the app id (an SP to its app registration) can
/// jump.
pub const ROW_ID_PREFIX: &str = "graph:/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryKind {
    ServicePrincipal,
    Application,
}

impl DirectoryKind {
    pub fn collection(self) -> &'static str {
        match self {
            DirectoryKind::ServicePrincipal => "servicePrincipals",
            DirectoryKind::Application => "applications",
        }
    }
}

/// `graph:/servicePrincipals/{oid}` / `graph:/applications/{oid}`.
pub fn row_id(kind: DirectoryKind, object_id: &str) -> String {
    format!("{}{}/{}", ROW_ID_PREFIX, kind.collection(), object_id)
}

/// `graph:/servicePrincipals(appId='{appId}')`: the app-id alias.
pub fn row_alias(kind: DirectoryKind, app_id: &str) -> String {
    format!("{}{}(appId='{}')", ROW_ID_PREFIX, kind.collection(), app_id)
}

/// The kind and object id of a synthetic row id (not of an alias).
pub fn parse_row_id(id: &str) -> Option<(DirectoryKind, &str)> {
    let rest = id.strip_prefix(ROW_ID_PREFIX)?;
    let (collection, oid) = rest.split_once('/')?;
    let kind = [DirectoryKind::ServicePrincipal, DirectoryKind::Application]
        .into_iter()
        .find(|k| k.collection() == collection)?;
    is_object_id(oid).then_some((kind, oid))
}

/// The kind a synthetic id or alias names, for the jump router.
pub fn kind_of_id(id: &str) -> Option<DirectoryKind> {
    let rest = id.strip_prefix(ROW_ID_PREFIX)?;
    [DirectoryKind::ServicePrincipal, DirectoryKind::Application]
        .into_iter()
        .find(|k| rest.starts_with(&format!("{}/", k.collection())) || rest.starts_with(&format!("{}(", k.collection())))
}

/// Whether a detail value is a synthetic directory id or alias.
pub fn is_row_id(value: &str) -> bool {
    kind_of_id(value).is_some()
}

/// Whether a Graph fetch error is a denied directory read (403).
pub fn is_denied(err: &str) -> bool {
    err.contains("403") || err.contains("Authorization_RequestDenied")
}

/// Whether a Graph fetch error says the object is gone (a role assignment
/// whose principal was deleted).
pub fn is_not_found(err: &str) -> bool {
    err.contains("404") || err.contains("Request_ResourceNotFound")
}

/// The short kind of a directory object from its `@odata.type`.
pub fn object_kind(v: &Value) -> &'static str {
    match json::str_at(v, "/@odata.type").as_deref() {
        Some("#microsoft.graph.user") => "user",
        Some("#microsoft.graph.group") => "group",
        Some("#microsoft.graph.servicePrincipal") => {
            if json::str_at(v, "/servicePrincipalType").as_deref() == Some("ManagedIdentity") {
                "managed identity"
            } else {
                "service principal"
            }
        }
        Some("#microsoft.graph.application") => "app registration",
        Some("#microsoft.graph.device") => "device",
        _ => "directory object",
    }
}

/// A directory object as one line: the display name, plus the UPN for a
/// user (two people can share a display name).
pub fn object_display(v: &Value) -> String {
    let name = json::str_at(v, "/displayName").filter(|s| !s.is_empty());
    let upn = json::str_at(v, "/userPrincipalName").filter(|s| !s.is_empty());
    match (name, upn) {
        (Some(n), Some(u)) if !n.eq_ignore_ascii_case(&u) => format!("{} ({})", n, u),
        (Some(n), _) => n,
        (None, Some(u)) => u,
        (None, None) => json::text(v, "/id"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_follows_the_arm_endpoint_cloud() {
        assert_eq!(graph_endpoint_for("https://management.azure.com"), Some("https://graph.microsoft.com"));
        assert_eq!(graph_endpoint_for("https://management.azure.com/"), Some("https://graph.microsoft.com"));
        assert_eq!(graph_endpoint_for("https://management.usgovcloudapi.net"), Some("https://graph.microsoft.us"));
        assert_eq!(
            graph_endpoint_for("https://management.chinacloudapi.cn"),
            Some("https://microsoftgraph.chinacloudapi.cn")
        );
        assert_eq!(graph_endpoint_for("https://127.0.0.1:9"), None);
    }

    #[test]
    fn only_guid_shaped_ids_make_a_path() {
        assert_eq!(
            directory_object_path("6ea91a8d-e32e-41a1-b7bd-d2d185eed0e0").as_deref(),
            Some("/v1.0/directoryObjects/6ea91a8d-e32e-41a1-b7bd-d2d185eed0e0")
        );
        assert_eq!(directory_object_path("../me"), None);
        assert_eq!(directory_object_path("x?$select=y"), None);
        assert_eq!(directory_object_path(""), None);
    }

    #[test]
    fn objects_render_by_kind() {
        let user = serde_json::json!({
            "@odata.type": "#microsoft.graph.user",
            "id": "u", "displayName": "Conf Room Adams", "userPrincipalName": "Adams@Contoso.com"
        });
        assert_eq!(object_kind(&user), "user");
        assert_eq!(object_display(&user), "Conf Room Adams (Adams@Contoso.com)");
        let mi = serde_json::json!({
            "@odata.type": "#microsoft.graph.servicePrincipal",
            "id": "s", "displayName": "id-app", "servicePrincipalType": "ManagedIdentity"
        });
        assert_eq!(object_kind(&mi), "managed identity");
        assert_eq!(object_display(&mi), "id-app");
        let bare = serde_json::json!({"@odata.type": "#microsoft.graph.group", "id": "g"});
        assert_eq!(object_kind(&bare), "group");
        assert_eq!(object_display(&bare), "g");
    }

    #[test]
    fn row_ids_round_trip_and_aliases_route() {
        let oid = "00af5dfb-85da-4b41-a677-0c6b86dd34f8";
        let id = row_id(DirectoryKind::ServicePrincipal, oid);
        assert_eq!(id, "graph:/servicePrincipals/00af5dfb-85da-4b41-a677-0c6b86dd34f8");
        assert_eq!(parse_row_id(&id), Some((DirectoryKind::ServicePrincipal, oid)));
        assert_eq!(object_path(&id, Some("owners")).as_deref(), Some("/v1.0/servicePrincipals/00af5dfb-85da-4b41-a677-0c6b86dd34f8/owners"));
        let app = row_id(DirectoryKind::Application, oid);
        assert_eq!(object_path(&app, None).as_deref(), Some("/v1.0/applications/00af5dfb-85da-4b41-a677-0c6b86dd34f8"));
        assert_eq!(
            claims_policy_path(&id).as_deref(),
            Some("/beta/servicePrincipals/00af5dfb-85da-4b41-a677-0c6b86dd34f8/claimsPolicy")
        );
        assert_eq!(claims_policy_path(&app), None, "an app registration has no claims policy");
        let alias = row_alias(DirectoryKind::Application, "11111111-2222-3333-4444-555555555555");
        assert_eq!(alias, "graph:/applications(appId='11111111-2222-3333-4444-555555555555')");
        assert_eq!(parse_row_id(&alias), None, "an alias is not fetchable by object id");
        assert_eq!(kind_of_id(&alias), Some(DirectoryKind::Application));
        assert!(is_row_id(&id) && !is_row_id("/subscriptions/0"));
        assert_eq!(parse_row_id("graph:/servicePrincipals/../me"), None);
        assert_eq!(parse_row_id("graph:/users/abc"), None);
    }

    #[test]
    fn list_queries_need_an_advanced_query_only_for_the_owner_filter() {
        assert_eq!(managed_identity_sps_query()[0].1, "servicePrincipalType eq 'ManagedIdentity'");
        let q = tenant_owned_sps_query("65415bb1-9267-4313-bbf5-ae259732ee12").unwrap();
        assert_eq!(q[0].1, "appOwnerOrganizationId eq 65415bb1-9267-4313-bbf5-ae259732ee12");
        assert!(q.iter().any(|(k, v)| k == "$count" && v == "true"));
        assert_eq!(advanced_query_headers()[0], ("consistencylevel", "eventual".to_string()));
        assert_eq!(tenant_owned_sps_query("x' or 1 eq 1"), None);
        assert_eq!(
            service_principal_by_app_id_path("00000003-0000-0000-c000-000000000000").as_deref(),
            Some("/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')")
        );
    }

    #[test]
    fn denied_and_missing_are_recognised() {
        assert!(is_denied("403 Forbidden Authorization_RequestDenied: Insufficient privileges"));
        assert!(is_not_found("404 Not Found Request_ResourceNotFound: Resource 'x' does not exist"));
        assert!(!is_denied("connection failed"));
    }
}
