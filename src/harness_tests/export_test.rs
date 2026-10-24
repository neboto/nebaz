// ported from neboto-tui src/harness_tests/deep_export_test.rs @ 03760c0
// (the single-X wait tests of bcfb8d1), rewritten around nebaz's lazy maps
//! `X` through the real App (#40): it fires every lazy section, waits for
//! them, writes the same sections in every format, gives up after the
//! limit, and never writes a credential the row stripped.

use super::mocks::{arm_id, Mock};
use super::*;
use crate::azure::services::{container_apps, monitor};
use serde_json::{json, Value};

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The written file with extension `ext`.
pub(super) fn written(h: &Harness, ext: &str) -> String {
    let path = h
        .app
        .last_export_paths
        .iter()
        .find(|p| p.extension().is_some_and(|e| e == ext))
        .unwrap_or_else(|| panic!("no .{ext} in {:?}", h.app.last_export_paths));
    read(path)
}

fn all_written(h: &Harness) -> String {
    h.app.last_export_paths.iter().map(|p| read(p)).collect::<Vec<_>>().join("\n")
}

/// Push the armed export past its wait limit, then run one pass.
pub(super) async fn expire_wait(h: &mut Harness) {
    let pending = h.app.pending_export.as_mut().expect("an export is armed");
    pending.started = Instant::now() - crate::app::export::EXPORT_WAIT_LIMIT - Duration::from_secs(1);
    h.settle().await;
}

/// Land what the VM's lazy sections would fetch: an instance view, a
/// denied Access list, no role names, an empty activity log.
pub(super) fn land_vm_sections(h: &mut Harness, id: &str) {
    let lazy = &mut h.app.lazy;
    lazy.vm_instance_views.apply(
        id.to_string(),
        Ok(json!({"statuses": [{"code": "PowerState/running", "displayStatus": "VM running"}]})),
    );
    lazy.role_assignments.apply(id.to_string(), Err("403 Forbidden: AuthorizationFailed".to_string()));
    lazy.role_definitions.apply(format!("/subscriptions/{}", SUB_DEV), Ok(vec![]));
    lazy.activity.apply(id.to_string(), Ok(vec![]));
}

fn vm_mock(name: &str) -> Mock {
    Mock { view: JumpView::VirtualMachines, label: "VmRow", resource: mocks::vm(name, "westeurope") }
}

#[tokio::test]
async fn x_fires_every_lazy_section_and_writes_once_they_land() {
    let mut h = Harness::new().await;
    h.install(vm_mock("vm-export-wait")).await;
    let id = h.selected_id().unwrap();

    // From the list pane, no section opened: the press arms the wait.
    h.press(KeyCode::Char('X')).await;
    assert!(h.app.pending_export.is_some(), "armed, not written");
    assert!(h.app.last_export_paths.is_empty());
    assert!(h.app.lazy.vm_instance_views.contains(&id), "Instance view fired without opening it");
    assert!(h.app.lazy.role_assignments.contains(&id), "Access fired");
    assert!(h.app.lazy.activity.contains(&id), "Activity fired");
    let progress = h.app.deep_export_progress.clone().unwrap_or_default();
    assert!(progress.contains("Instance view") && progress.contains("Esc"), "{progress}");
    assert!(h.render().contains("Export: waiting on"), "the progress slot shows");

    // A second press neither restarts nor stacks it.
    let started = h.app.pending_export.as_ref().unwrap().started;
    h.press(KeyCode::Char('X')).await;
    assert_eq!(h.app.pending_export.as_ref().unwrap().started, started);

    land_vm_sections(&mut h, &id);
    h.settle().await;
    assert!(h.app.pending_export.is_none(), "written once nothing is loading");
    assert!(h.app.deep_export_progress.is_none());
    assert_eq!(h.app.last_export_paths.len(), 3, "json, csv and md by default");
    let msg = h.app.success_message.clone().unwrap_or_default();
    assert!(msg.starts_with("Exported vm-export-wait →"), "{msg}");

    // Every format carries the landed sections.
    let v: Value = serde_json::from_str(&written(&h, "json")).unwrap();
    assert_eq!(v["resource"]["id"], id);
    assert!(!v["sections"]["Instance view"].is_null(), "{v:#}");
    let csv = written(&h, "csv");
    let md = written(&h, "md");
    assert!(csv.starts_with("ID,Section,Key,Value\n"));
    for needle in ["VM running", "Instance view"] {
        assert!(csv.contains(needle) && md.contains(needle), "{needle}");
    }
    // The denied Access section exports its warning line, not nothing.
    let warning = "⚠ 403 Forbidden: AuthorizationFailed";
    assert_eq!(v["sections"]["Access"]["note"], warning, "{v:#}");
    assert!(csv.contains(warning) && md.contains(warning));
    assert!(!all_written(&h).contains("Loading…"));
}

#[tokio::test]
async fn x_on_a_warm_resource_writes_at_once_from_the_detail_pane() {
    let mut h = Harness::new().await;
    h.install(vm_mock("vm-export-warm")).await;
    let id = h.selected_id().unwrap();
    land_vm_sections(&mut h, &id);
    h.press(KeyCode::Enter).await;
    assert!(h.app.details_focused);

    h.press(KeyCode::Char('X')).await;
    assert!(h.app.pending_export.is_none(), "nothing to wait for");
    assert_eq!(h.app.last_export_paths.len(), 3);
    assert!(h.app.details_focused, "the pane keeps focus");
}

#[tokio::test]
async fn esc_cancels_an_armed_export_from_either_pane() {
    let mut h = Harness::new().await;
    h.install(vm_mock("vm-export-esc")).await;
    h.press(KeyCode::Char('X')).await;
    assert!(h.app.pending_export.is_some());
    h.press(KeyCode::Esc).await;
    assert!(h.app.pending_export.is_none());
    assert!(h.app.deep_export_progress.is_none());
    assert_eq!(h.app.success_message.as_deref(), Some("Export cancelled"));

    // From the detail pane Esc cancels the export first, then leaves.
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('X')).await;
    assert!(h.app.pending_export.is_some());
    h.press(KeyCode::Esc).await;
    assert!(h.app.pending_export.is_none());
    assert!(h.app.details_focused, "the first Esc only cancelled");

    // Nothing landed afterwards writes anything.
    let id = h.selected_id().unwrap();
    land_vm_sections(&mut h, &id);
    h.settle().await;
    assert!(h.app.last_export_paths.is_empty());
}

#[tokio::test]
async fn the_wait_gives_up_after_its_limit_and_says_what_was_still_loading() {
    let mut h = Harness::new().await;
    h.install(vm_mock("vm-export-timeout")).await;
    h.press(KeyCode::Char('X')).await;
    expire_wait(&mut h).await;

    assert!(h.app.pending_export.is_none());
    let msg = h.app.success_message.clone().unwrap_or_default();
    assert!(msg.contains("still loading after 120s") && msg.contains("Instance view"), "{msg}");
    let v: Value = serde_json::from_str(&written(&h, "json")).unwrap();
    assert!(v["sections"]["Instance view"].is_null(), "unloaded is null: {v:#}");
    assert_eq!(v["sections"]["Overview"]["Name"], "vm-export-timeout", "{v:#}");
    assert!(written(&h, "csv").contains("Instance view,,(not loaded)"));
    assert!(written(&h, "md").contains("_Not loaded"));
}

#[tokio::test]
async fn a_subscription_switch_cancels_the_wait() {
    let mut h = Harness::new().await;
    h.install(vm_mock("vm-export-switch")).await;
    h.press(KeyCode::Char('X')).await;
    // What a switch does to the lazy store.
    h.app.lazy = crate::lazy::LazyStore::new(h.app.lazy.epoch() + 1);
    h.settle().await;
    assert!(h.app.pending_export.is_none());
    assert!(h.app.error_message.as_deref().unwrap_or_default().contains("subscription changed"));
    assert!(h.app.last_export_paths.is_empty());
}

/// A Container App's secret values and env values never reach an export:
/// the row strips them before it keeps its JSON, and the export writes
/// only what the panes render.
#[tokio::test]
async fn an_exported_container_app_holds_no_secret_value() {
    let mut h = Harness::new().await;
    let app = container_apps::ContainerAppRow::from_json(
        &json!({
            "id": arm_id("Microsoft.App/containerApps/aca-export"),
            "name": "aca-export",
            "location": "East US",
            "properties": {
                "provisioningState": "Succeeded",
                "runningStatus": "Running",
                "configuration": {
                    "secrets": [{"name": "db-password", "value": "s3cr3t-db-value"}],
                    "registries": [{"server": "acr.example", "username": "u", "passwordSecretRef": "db-password"}]
                },
                "template": {"containers": [{"name": "api", "image": "example/api:1",
                    "env": [{"name": "API_TOKEN", "value": "plain-env-s3cr3t"},
                            {"name": "DB_PASSWORD", "secretRef": "db-password"}]}]}
            }
        }),
        Some(TENANT),
    )
    .expect("from_json");
    h.install(Mock { view: JumpView::ContainerApps, label: "ContainerAppRow", resource: Box::new(app) }).await;
    h.press(KeyCode::Char('X')).await;
    expire_wait(&mut h).await;
    let out = all_written(&h);
    assert!(out.contains("db-password") && out.contains("API_TOKEN"), "names export: {out}");
    for secret in ["s3cr3t-db-value", "plain-env-s3cr3t"] {
        assert!(!out.contains(secret), "{secret} leaked into the export");
    }

    // The list export (Ctrl-X) too.
    h.press_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL)).await;
    let out = all_written(&h);
    assert!(out.contains("aca-export"));
    assert!(!out.contains("s3cr3t"), "{out}");
}

/// The same for an App Insights component's instrumentation key and
/// connection string, which its ARM GET returns.
#[tokio::test]
async fn an_exported_app_insights_component_holds_no_ingestion_key() {
    let mut h = Harness::new().await;
    let row = monitor::ComponentRow::from_json(
        &json!({
            "id": arm_id("Microsoft.Insights/components/appi-export"),
            "name": "appi-export",
            "location": "West Europe",
            "kind": "web",
            "properties": {
                "provisioningState": "Succeeded",
                "InstrumentationKey": "ikey-export-secret",
                "ConnectionString": "InstrumentationKey=ikey-export-secret;IngestionEndpoint=https://ingest.example/"
            }
        }),
        Some(TENANT),
    )
    .expect("from_json");
    h.install(Mock { view: JumpView::AppInsights, label: "ComponentRow", resource: Box::new(row) }).await;
    h.press(KeyCode::Char('X')).await;
    expire_wait(&mut h).await;
    let out = all_written(&h);
    assert!(out.contains("appi-export"));
    assert!(!out.contains("ikey-export-secret"), "{out}");
}

/// The same for a Redis cache: its GET can carry access keys and the
/// persistence storage connection string.
#[tokio::test]
async fn an_exported_redis_cache_holds_no_key() {
    let mut h = Harness::new().await;
    let m = super::mocks::all_mocks().into_iter().find(|m| m.view == JumpView::RedisCaches).unwrap();
    h.install(m).await;
    h.press(KeyCode::Char('X')).await;
    expire_wait(&mut h).await;
    let out = all_written(&h);
    assert!(out.contains("redis-1"));
    assert!(!out.contains("mock-redis-key"), "{out}");
}

/// Directory rows export like ARM rows, under their `graph:/` id.
#[tokio::test]
async fn a_directory_row_exports_under_its_graph_id() {
    let mut h = Harness::new().await;
    h.install(Mock {
        view: JumpView::ServicePrincipals,
        label: "ServicePrincipalRow",
        resource: mocks::sp_application(),
    })
    .await;
    let id = h.selected_id().unwrap();
    assert!(id.starts_with("graph:/"));
    h.press(KeyCode::Char('X')).await;
    expire_wait(&mut h).await;
    let v: Value = serde_json::from_str(&written(&h, "json")).unwrap();
    assert_eq!(v["resource"]["id"], id);
    assert!(v["sections"]["Credentials"].is_object(), "{v:#}");
    assert!(written(&h, "csv").contains(&format!("{id},Credentials,")));
}

/// `export_formats` picks the files; `Ctrl-X` honours it like `X`.
#[tokio::test]
async fn export_formats_choose_the_files_written() {
    let mut h = Harness::new().await;
    h.install(vm_mock("vm-export-formats")).await;
    h.app.export_options.formats = crate::export::ExportFormats { json: false, csv: true, md: false };
    h.press_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL)).await;
    assert_eq!(h.app.last_export_paths.len(), 1);
    let csv = written(&h, "csv");
    assert!(csv.starts_with("Type,ID,Name,State,"), "{csv}");
    assert!(csv.contains("vm-export-formats"));
}
