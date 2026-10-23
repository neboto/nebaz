//! Directory rows (Microsoft Graph, ADR 0004) through the real App: their
//! synthetic ids, the expiry state, a lazy Graph section, and jumps by
//! app-id alias and to an ARM id.

use super::mocks::{
    app_federated_credential, app_registration, arm_id, sp_application, sp_managed_identity, Mock, APP_ID,
    SP_OBJECT_ID,
};
use super::*;
use crate::azure::graph::{row_alias, row_id, DirectoryKind};
use crate::azure::services::directory::child_key;

fn mock(view: JumpView, label: &'static str, resource: Box<dyn Resource>) -> Mock {
    Mock { view, label, resource }
}

async fn open_section(h: &mut Harness, name: &str) {
    let idx = h.section_labels().iter().position(|l| *l == name).unwrap_or_else(|| panic!("no {name}"));
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
}

#[tokio::test]
async fn an_app_registration_shows_its_expiring_secret_and_federated_credential() {
    let mut h = Harness::new().await;
    h.install(mock(JumpView::AppRegistrations, "AppRegistrationRow", app_registration())).await;
    let id = row_id(DirectoryKind::Application, "44444444-0000-0000-0000-000000000000");
    assert_eq!(h.selected_id().as_deref(), Some(id.as_str()), "keyed on the synthetic id");
    assert_eq!(h.app.get_selected_resource().unwrap().state_label(), "expiring");
    let screen = h.render();
    assert!(screen.contains("app-orders") && screen.contains(APP_ID), "{screen}");

    h.press(KeyCode::Enter).await;
    open_section(&mut h, "Credentials").await;
    assert!(h.app.get_detail_lines().iter().any(|(k, v)| k == "  deploy" && v.starts_with("expires in")));

    // The section's Graph fetch cannot reach anything offline; land what
    // the real GET would return.
    open_section(&mut h, "Federated credentials").await;
    h.app
        .lazy
        .directory_children
        .apply(child_key(&id, "federatedIdentityCredentials"), Ok(vec![app_federated_credential()]));
    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(k, v)| k == "  Subject" && v == "repo:contoso/orders:ref:refs/heads/main"), "{lines:#?}");
    assert!(h.render().contains("token.actions.githubusercontent.com"));
}

/// The app's Related names its service principal only by app id; the jump
/// lands on the SP row through `Resource::matches_id`.
#[tokio::test]
async fn an_app_jumps_to_its_service_principal_by_app_id() {
    let mut h = Harness::new().await;
    h.install(mock(JumpView::AppRegistrations, "AppRegistrationRow", app_registration())).await;
    h.press(KeyCode::Enter).await;
    open_section(&mut h, "Related").await;
    let alias = row_alias(DirectoryKind::ServicePrincipal, APP_ID);
    h.cursor_to_value(&alias).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::ServicePrincipals);
    assert_eq!(h.app.pending_jump, Some((alias.clone(), true)));

    h.land_page(vec![sp_managed_identity()]).await;
    assert!(h.app.pending_jump.is_some(), "the managed identity is not the target");
    h.land_page(vec![sp_application()]).await;
    assert_eq!(h.app.pending_jump, None);
    assert_eq!(
        h.selected_id(),
        Some(row_id(DirectoryKind::ServicePrincipal, SP_OBJECT_ID)),
        "the alias resolved to the row's own id"
    );
    assert!(h.app.details_focused);
    assert!(h.render().contains("sp-orders"));
}

/// A managed identity's service principal links to the identity's ARM id;
/// directory rows are never hidden by the location filter.
#[tokio::test]
async fn a_managed_identity_sp_jumps_to_its_arm_identity() {
    let mut h = Harness::new().await;
    h.install(mock(JumpView::ServicePrincipals, "ServicePrincipalRow", sp_managed_identity())).await;
    assert_eq!(h.app.get_selected_resource().unwrap().location(), None);
    h.press(KeyCode::Enter).await;
    open_section(&mut h, "Related").await;
    let identity = arm_id("Microsoft.ManagedIdentity/userAssignedIdentities/id-1");
    h.cursor_to_value(&identity).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::Identities);
    assert_eq!(h.app.pending_jump, Some((identity, true)));
}
