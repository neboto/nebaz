//! Access (issue #24): role assignments, the RBAC lens every type shares.
//!
//! Every section descriptor carries an **Access** section before Related.
//! It is rendered here, once, by `App::section_lines_for` (matched on the
//! label), never by the type's own `*_section_lines`: the call is the same
//! for every ARM id. `GET {scope}/…/roleAssignments?$filter=atScope()`
//! returns what applies at the scope: assignments made there and those
//! inherited from above (resource group, subscription, management group).
//!
//! Identity rows add **Can do**: the assignments the identity's principal
//! holds anywhere in its subscription.
//!
//! Role names come from the subscription's role definitions, one list per
//! subscription for the session. Principal names come from Microsoft
//! Graph (ADR 0004): one `GET directoryObjects/{id}` per principal, lazily,
//! keyed by object id, for the first [`PRINCIPAL_NAMES_MAX`] principals of
//! a section. Until a name lands (or when directory read is denied) a
//! principal is its type and object id.

use crate::azure::graph;
use crate::azure::resource::{name_of_id, shell_quote, subscription_of};
use crate::azure::services::{json, lazy_list_rows};
use crate::lazy::{Lazy, LazyMap};
use serde_json::Value;
use std::collections::HashMap;

/// The newest stable Microsoft.Authorization version for both lists
/// (checked against azure-rest-api-specs, 2026-09-27).
pub const ACCESS_API_VERSION: &str = "2022-04-01";

/// The section label `App::section_lines_for` dispatches on.
pub const ACCESS_LABEL: &str = "Access";

/// `{scope}/providers/Microsoft.Authorization/roleAssignments`.
pub fn role_assignments_path(scope: &str) -> String {
    format!("{}/providers/Microsoft.Authorization/roleAssignments", scope.trim_end_matches('/'))
}

/// The `$filter` for what applies at a scope (made there or inherited).
pub fn at_scope_filter() -> Vec<(String, String)> {
    vec![("$filter".into(), "atScope()".into())]
}

/// The `$filter` for one principal's assignments.
pub fn principal_filter(principal_id: &str) -> Vec<(String, String)> {
    vec![("$filter".into(), format!("principalId eq '{}'", principal_id))]
}

/// The role-definition list's lazy key and path for the subscription an
/// ARM id lives in: `/subscriptions/{sub}`.
pub fn role_definitions_scope(id: &str) -> Option<String> {
    subscription_of(id).map(|s| format!("/subscriptions/{}", s))
}

pub fn role_definitions_path(sub_scope: &str) -> String {
    format!("{}/providers/Microsoft.Authorization/roleDefinitions", sub_scope.trim_end_matches('/'))
}

/// Role GUID (lowercase) → role name, from a loaded definitions list.
fn role_names(roles: Option<&Lazy<Vec<Value>>>) -> Option<HashMap<String, String>> {
    match roles {
        Some(Lazy::Loaded(items)) => Some(
            items
                .iter()
                .map(|d| (json::text(d, "/name").to_lowercase(), json::text(d, "/properties/roleName")))
                .collect(),
        ),
        _ => None,
    }
}

/// The role an assignment grants: its name when the definitions are
/// loaded, else the GUID.
fn role_of(a: &Value, names: &Option<HashMap<String, String>>) -> String {
    let guid = json::str_at(a, "/properties/roleDefinitionId")
        .map(|id| name_of_id(&id).to_lowercase())
        .unwrap_or_default();
    names
        .as_ref()
        .and_then(|n| n.get(&guid))
        .cloned()
        .unwrap_or_else(|| if guid.is_empty() { "-".into() } else { guid })
}

/// Where an assignment's scope sits relative to the row: `None` when it
/// was made on the row itself.
fn inherited_from(scope: &str, here: &str) -> Option<String> {
    let scope = scope.trim_end_matches('/');
    if scope.eq_ignore_ascii_case(here.trim_end_matches('/')) {
        return None;
    }
    let parts: Vec<&str> = scope.split('/').filter(|p| !p.is_empty()).collect();
    Some(match parts.as_slice() {
        [] => "root".into(),
        ["providers", ns, "managementGroups", mg] if ns.eq_ignore_ascii_case("Microsoft.Management") => {
            format!("management group {}", mg)
        }
        [s, _] if s.eq_ignore_ascii_case("subscriptions") => "subscription".into(),
        [s, _, g, rg] if s.eq_ignore_ascii_case("subscriptions") && g.eq_ignore_ascii_case("resourceGroups") => {
            format!("resource group {}", rg)
        }
        _ => name_of_id(scope).to_string(),
    })
}

/// A scope in words, the way Access names where an assignment comes
/// from: `management group corp`, `subscription`, `resource group rg`, or
/// a resource's name. The Governance rows' Scope column (ADR 0009).
pub fn scope_words(scope: &str) -> String {
    inherited_from(scope, "").unwrap_or_else(|| "-".into())
}

/// How many principals one Access section resolves to names: a bound on
/// the Graph GETs a busy scope (a subscription with hundreds of
/// assignments) can trigger.
pub const PRINCIPAL_NAMES_MAX: usize = 50;

/// The principal ids a loaded Access list resolves, lowercased, unique, in
/// list order, at most [`PRINCIPAL_NAMES_MAX`]: the app triggers exactly
/// these, and the footer counts against them.
pub fn principal_ids(items: &[Value]) -> Vec<String> {
    let mut seen = Vec::new();
    for a in items {
        if let Some(id) = json::str_at(a, "/properties/principalId").map(|s| s.to_lowercase()) {
            if graph::is_object_id(&id) && !seen.contains(&id) {
                seen.push(id);
            }
        }
    }
    seen.truncate(PRINCIPAL_NAMES_MAX);
    seen
}

fn principal(a: &Value, names: &LazyMap<Value>) -> String {
    let kind = json::opt(json::str_at(a, "/properties/principalType"));
    let id = json::text(a, "/properties/principalId");
    match names.get(&id.to_lowercase()) {
        // An assignment made before principalType existed has none: the
        // directory object's own type says it.
        Some(Lazy::Loaded(v)) if kind == "-" => format!("{} · {} · {}", graph::object_kind(v), graph::object_display(v), id),
        Some(Lazy::Loaded(v)) => format!("{} · {} · {}", kind, graph::object_display(v), id),
        Some(Lazy::Error(e)) if graph::is_not_found(e) => format!("{} · not in the directory (deleted?) · {}", kind, id),
        _ => format!("{} · {}", kind, id),
    }
}

/// The footer line on principal names: loading, denied, failed, or capped.
fn names_footer(items: &[Value], names: &LazyMap<Value>) -> Vec<String> {
    let ids = principal_ids(items);
    let states: Vec<Option<&Lazy<Value>>> = ids.iter().map(|id| names.get(id)).collect();
    let mut out = Vec::new();
    let errors: Vec<&String> = states
        .iter()
        .filter_map(|s| match s {
            Some(Lazy::Error(e)) if !graph::is_not_found(e) => Some(e),
            _ => None,
        })
        .collect();
    if errors.iter().any(|e| graph::is_denied(e)) {
        out.push(format!("· ⚠ {}: principals are object ids", graph::DIRECTORY_READ_DENIED));
    } else if let Some(e) = errors.first() {
        out.push(format!("· ⚠ principal names unavailable: {}", e));
    } else if states.iter().any(|s| matches!(s, None | Some(Lazy::Loading))) {
        out.push("· principal names are loading (Microsoft Graph)".into());
    }
    let total = items
        .iter()
        .filter_map(|a| json::str_at(a, "/properties/principalId").map(|s| s.to_lowercase()))
        .collect::<std::collections::HashSet<_>>()
        .len();
    if total > ids.len() {
        out.push(format!("· names resolved for the first {} of {} principals", ids.len(), total));
    }
    out
}

fn condition_line(a: &Value) -> Option<(String, String)> {
    json::str_at(a, "/properties/condition")
        .filter(|c| !c.is_empty())
        .map(|c| ("  Condition".to_string(), c))
}

/// The Access section: what applies at `id`, assignments made here first,
/// then inherited ones, each group by role name.
pub fn access_rows(
    id: &str,
    assignments: Option<&Lazy<Vec<Value>>>,
    roles: Option<&Lazy<Vec<Value>>>,
    principals: &LazyMap<Value>,
) -> Vec<(String, String)> {
    let names = role_names(roles);
    lazy_list_rows(assignments, "Access", |items| {
        let mut sorted: Vec<(bool, String, &Value)> = items
            .iter()
            .map(|a| {
                let scope = json::text(a, "/properties/scope");
                (inherited_from(&scope, id).is_some(), role_of(a, &names), a)
            })
            .collect();
        sorted.sort_by_key(|(inherited, role, _)| (*inherited, role.to_lowercase()));
        let mut lines = Vec::new();
        if sorted.is_empty() {
            lines.push((String::new(), "No role assignments apply here".into()));
        }
        for (_, role, a) in sorted {
            let scope = json::text(a, "/properties/scope");
            lines.push((String::new(), String::new()));
            lines.push((role, String::new()));
            lines.push(("  Principal".into(), principal(a, principals)));
            // A service principal (an app's, or a managed identity's) is a
            // directory row: Enter jumps to it in Identity.
            let pid = json::text(a, "/properties/principalId");
            if json::str_at(a, "/properties/principalType").as_deref() == Some("ServicePrincipal") && graph::is_object_id(&pid) {
                lines.push((
                    "  Service principal".into(),
                    graph::row_id(graph::DirectoryKind::ServicePrincipal, &pid.to_lowercase()),
                ));
            }
            match inherited_from(&scope, id) {
                None => lines.push(("  Scope".into(), "assigned here".into())),
                // An ARM id value, so Enter jumps to where it was made.
                Some(from) => lines.push((format!("  Inherited from · {}", from), scope)),
            }
            lines.extend(condition_line(a));
        }
        footer(&mut lines, &names, roles);
        lines.extend(names_footer(items, principals).into_iter().map(|l| (String::new(), l)));
        lines.push((
            "Read command".into(),
            format!("az role assignment list --scope {} --include-inherited", shell_quote(id)),
        ));
        lines
    })
}

/// The Can do section of an identity: every assignment its principal
/// holds in the identity's subscription, each scope a jumpable id.
pub fn can_do_rows(
    principal_id: Option<&str>,
    identity_id: &str,
    assignments: Option<&Lazy<Vec<Value>>>,
    roles: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    let Some(principal_id) = principal_id else {
        return vec![(String::new(), "No principal id on this identity".into())];
    };
    let names = role_names(roles);
    lazy_list_rows(assignments, "Can do", |items| {
        let mut sorted: Vec<(String, &Value)> = items.iter().map(|a| (role_of(a, &names), a)).collect();
        sorted.sort_by_key(|(role, _)| role.to_lowercase());
        let mut lines = Vec::new();
        if sorted.is_empty() {
            lines.push((String::new(), "No role assignments in this subscription".into()));
        }
        for (role, a) in sorted {
            let scope = json::text(a, "/properties/scope");
            // Relative to nothing, every scope names itself.
            let label = inherited_from(&scope, "").unwrap_or_else(|| "root".into());
            lines.push((format!("{} · {}", role, label), scope));
            lines.extend(condition_line(a));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· direct assignments only; group memberships are not followed".into()));
        footer(&mut lines, &names, roles);
        if let Some(sub) = subscription_of(identity_id) {
            lines.push((
                "Read command".into(),
                format!(
                    "az role assignment list --assignee {} --all --subscription {}",
                    shell_quote(principal_id),
                    shell_quote(sub)
                ),
            ));
        }
        lines
    })
}

/// The role-names footer: loading, or why the roles are GUIDs for good (a
/// failed definitions list must not read as "still loading").
fn footer(lines: &mut Vec<(String, String)>, names: &Option<HashMap<String, String>>, roles: Option<&Lazy<Vec<Value>>>) {
    lines.push((String::new(), String::new()));
    match roles {
        Some(Lazy::Error(e)) => lines.push((String::new(), format!("· ⚠ role names unavailable, GUIDs shown: {}", e))),
        _ if names.is_none() => lines.push((String::new(), "· role names are loading; GUIDs until then".into())),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUB: &str = "/subscriptions/0000";
    const RG: &str = "/subscriptions/0000/resourceGroups/rg-app";
    const KV: &str = "/subscriptions/0000/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-app";
    const READER: &str = "acdd72a7-3385-48ef-bd42-f606fba81ae7";
    const KV_USER: &str = "4633458b-17de-408a-b874-0445c86b69e6";

    fn assignment(scope: &str, role: &str, kind: &str, principal: &str) -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.Authorization/roleAssignments/{}", scope, principal),
            "name": principal,
            "properties": {
                "roleDefinitionId": format!("{}/providers/Microsoft.Authorization/roleDefinitions/{}", SUB, role),
                "principalId": principal,
                "principalType": kind,
                "scope": scope
            }
        })
    }

    fn roles() -> Lazy<Vec<Value>> {
        Lazy::Loaded(vec![
            serde_json::json!({"name": READER, "properties": {"roleName": "Reader", "type": "BuiltInRole"}}),
            serde_json::json!({"name": KV_USER, "properties": {"roleName": "Key Vault Secrets User", "type": "BuiltInRole"}}),
        ])
    }

    #[test]
    fn access_lists_direct_first_then_inherited_with_jumpable_scopes() {
        let mut conditional = assignment(KV, KV_USER, "ServicePrincipal", "sp-1");
        conditional["properties"]["condition"] = "@Resource[x] StringEquals 'y'".into();
        let items = vec![
            assignment(SUB, READER, "Group", "grp-1"),
            assignment(RG, READER, "User", "usr-1"),
            conditional,
        ];
        let lines = access_rows(KV, Some(&Lazy::Loaded(items)), Some(&roles()), &LazyMap::default());
        let roles_in_order: Vec<&str> = lines
            .iter()
            .filter(|(k, v)| !k.is_empty() && !k.starts_with(' ') && v.is_empty())
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(roles_in_order, ["Key Vault Secrets User", "Reader", "Reader"], "direct first");
        assert!(lines.iter().any(|(k, v)| k == "  Scope" && v == "assigned here"));
        assert!(lines.iter().any(|(k, v)| k == "  Inherited from · resource group rg-app" && v == RG));
        assert!(lines.iter().any(|(k, v)| k == "  Inherited from · subscription" && v == SUB));
        assert!(lines.iter().any(|(k, v)| k == "  Principal" && v == "ServicePrincipal · sp-1"));
        assert!(lines.iter().any(|(k, _)| k == "  Condition"));
        assert_eq!(
            lines.last().unwrap().1,
            format!("az role assignment list --scope {} --include-inherited", KV)
        );
    }

    #[test]
    fn role_guids_show_until_the_definitions_load() {
        let items = vec![assignment(SUB, READER, "User", "usr-1")];
        let lines = access_rows(SUB, Some(&Lazy::Loaded(items)), Some(&Lazy::Loading), &LazyMap::default());
        assert!(lines.iter().any(|(k, _)| k == READER));
        assert!(lines.iter().any(|(_, v)| v.contains("role names are loading")));
    }

    #[test]
    fn a_failed_definitions_list_says_so_instead_of_loading_forever() {
        let denied: Lazy<Vec<Value>> = Lazy::Error("Azure error: 403 AuthorizationFailed: no roleDefinitions/read".into());
        let items = vec![assignment(SUB, READER, "User", "usr-1")];
        for lines in [
            access_rows(SUB, Some(&Lazy::Loaded(items.clone())), Some(&denied), &LazyMap::default()),
            can_do_rows(Some("usr-1"), SUB, Some(&Lazy::Loaded(items)), Some(&denied)),
        ] {
            assert!(lines.iter().any(|(k, _)| k.starts_with(READER)), "GUIDs still shown: {:?}", lines);
            assert!(
                lines.iter().any(|(_, v)| v.contains("⚠ role names unavailable") && v.contains("AuthorizationFailed")),
                "{:?}",
                lines
            );
            assert!(!lines.iter().any(|(_, v)| v.contains("role names are loading")), "{:?}", lines);
        }
    }

    #[test]
    fn management_group_scope_is_named_and_empty_says_so() {
        assert_eq!(
            inherited_from("/providers/Microsoft.Management/managementGroups/corp", KV).as_deref(),
            Some("management group corp")
        );
        assert_eq!(inherited_from("/", KV).as_deref(), Some("root"));
        let none = access_rows(KV, Some(&Lazy::Loaded(vec![])), None, &LazyMap::default());
        assert_eq!(none[0].1, "No role assignments apply here");
    }

    #[test]
    fn can_do_lists_each_scope_as_a_jumpable_id() {
        let id = format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-app", RG);
        let items = vec![assignment(KV, KV_USER, "ServicePrincipal", "pid"), assignment(SUB, READER, "ServicePrincipal", "pid")];
        let lines = can_do_rows(Some("pid"), &id, Some(&Lazy::Loaded(items)), Some(&roles()));
        assert_eq!(lines[0], ("Key Vault Secrets User · kv-app".to_string(), KV.to_string()));
        assert_eq!(lines[1], ("Reader · subscription".to_string(), SUB.to_string()));
        assert_eq!(
            lines.last().unwrap().1,
            "az role assignment list --assignee pid --all --subscription 0000"
        );
        assert_eq!(can_do_rows(None, &id, None, None)[0].1, "No principal id on this identity");
    }

    #[test]
    fn principals_resolve_to_names_and_a_denied_read_says_so() {
        let (u, g, s) = (
            "aaaaaaaa-0000-0000-0000-000000000001",
            "aaaaaaaa-0000-0000-0000-000000000002",
            "AAAAAAAA-0000-0000-0000-000000000003",
        );
        let items = vec![assignment(SUB, READER, "User", u), assignment(RG, READER, "Group", g), assignment(KV, READER, "ServicePrincipal", s)];
        assert_eq!(principal_ids(&items), [u, g, &s.to_lowercase()], "unique, lowercased, list order");

        let mut names: LazyMap<Value> = LazyMap::default();
        names.apply(
            u.into(),
            Ok(serde_json::json!({"@odata.type": "#microsoft.graph.user", "id": u, "displayName": "Ada", "userPrincipalName": "ada@contoso.com"})),
        );
        names.insert_loading(g.into());
        names.apply(s.to_lowercase(), Err("404 Not Found Request_ResourceNotFound".into()));
        let lines = access_rows(KV, Some(&Lazy::Loaded(items.clone())), Some(&roles()), &names);
        let principals: Vec<&str> = lines.iter().filter(|(k, _)| k == "  Principal").map(|(_, v)| v.as_str()).collect();
        assert!(principals.contains(&format!("User · Ada (ada@contoso.com) · {}", u).as_str()), "{:?}", principals);
        assert!(principals.contains(&format!("Group · {}", g).as_str()), "loading: the id alone");
        assert!(principals.iter().any(|p| p.contains("not in the directory")), "{:?}", principals);
        assert!(lines.iter().any(|(_, v)| v.contains("principal names are loading")));
        assert!(
            lines.iter().any(|(k, v)| k == "  Service principal" && v == &format!("graph:/servicePrincipals/{}", s.to_lowercase())),
            "a service principal jumps to its directory row"
        );
        assert_eq!(lines.iter().filter(|(k, _)| k == "  Service principal").count(), 1, "users and groups do not");

        let mut denied: LazyMap<Value> = LazyMap::default();
        for id in principal_ids(&items) {
            denied.apply(id, Err("403 Forbidden Authorization_RequestDenied: Insufficient privileges".into()));
        }
        let lines = access_rows(KV, Some(&Lazy::Loaded(items)), Some(&roles()), &denied);
        assert!(lines.iter().any(|(_, v)| v.contains(graph::DIRECTORY_READ_DENIED)), "{:?}", lines);
        assert!(!lines.iter().any(|(_, v)| v.contains("loading (Microsoft Graph)")));
    }

    #[test]
    fn name_resolution_is_bounded_per_section() {
        let items: Vec<Value> = (0..PRINCIPAL_NAMES_MAX + 5)
            .map(|i| assignment(SUB, READER, "User", &format!("00000000-0000-0000-0000-{:012x}", i)))
            .collect();
        assert_eq!(principal_ids(&items).len(), PRINCIPAL_NAMES_MAX);
        let lines = access_rows(SUB, Some(&Lazy::Loaded(items)), Some(&roles()), &LazyMap::default());
        assert!(lines
            .iter()
            .any(|(_, v)| v == &format!("· names resolved for the first {} of {} principals", PRINCIPAL_NAMES_MAX, PRINCIPAL_NAMES_MAX + 5)));
    }

    #[test]
    fn paths_and_filters() {
        assert_eq!(role_assignments_path(KV), format!("{}/providers/Microsoft.Authorization/roleAssignments", KV));
        assert_eq!(role_definitions_scope(KV).as_deref(), Some(SUB));
        assert_eq!(principal_filter("pid")[0].1, "principalId eq 'pid'");
    }
}
