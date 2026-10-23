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
    fn denied_and_missing_are_recognised() {
        assert!(is_denied("403 Forbidden Authorization_RequestDenied: Insufficient privileges"));
        assert!(is_not_found("404 Not Found Request_ResourceNotFound: Resource 'x' does not exist"));
        assert!(!is_denied("connection failed"));
    }
}
