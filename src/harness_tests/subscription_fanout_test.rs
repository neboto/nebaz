// ported from neboto-tui src/harness_tests/region_fanout_test.rs @ 7fbf5ed
// (regions → subscriptions; the demo account's real SDK calls → results
// delivered as the event the offline fetch would send)
//! #62: opening `P` lists the current sub-tab in each configured
//! subscription (into that subscription's cache slot) and the picker shows
//! the counts; history, the jump list and bookmarks cross subscriptions.

use super::*;
use crate::azure::services::compute;
use crate::ui::widgets::subscription_selector::SubscriptionCount;
use serde_json::json;

/// A third subscription in another tenant, and a disabled one.
const SUB_STAGE: &str = "00000000-0000-0000-0000-0000000000e3";
const SUB_OLD: &str = "00000000-0000-0000-0000-0000000000a4";
const TENANT_B: &str = "00000000-0000-0000-0000-00000000000b";

/// The harness over the fixture account plus Stage (tenant B) and Old
/// (disabled), with config `subscriptions` set to `configured`.
async fn fanout_harness(configured: &[&str]) -> Harness {
    let mut subs = fixture_subscriptions();
    let extra = |id: &str, name: &str, tenant: &str, state: &str| SubscriptionEntry {
        id: id.into(),
        name: name.into(),
        tenant_id: tenant.into(),
        state: state.into(),
        is_default: false,
        cloud_name: Some("AzureCloud".into()),
        user: Some("dev@example.com".into()),
    };
    subs.push(extra(SUB_STAGE, "Stage", TENANT_B, "Enabled"));
    subs.push(extra(SUB_OLD, "Old", TENANT, "Disabled"));
    let mut h = Harness::new().await;
    let clients = AzureClients::new_for_test(subs, Arc::new(OfflineCredential));
    let config = Config {
        subscriptions: Some(configured.iter().map(|s| s.to_string()).collect()),
        ..Config::default()
    };
    h.app = App::from_parts(config, clients, None);
    h.app.bookmarks.clear();
    h.settle().await;
    h
}

/// A VM in subscription `sub`, through the real `from_json`.
fn vm_in(sub: &str, name: &str) -> Box<dyn Resource> {
    let id = format!("/subscriptions/{sub}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/{name}");
    let v = json!({
        "id": id, "name": name, "location": "westeurope",
        "properties": {"provisioningState": "Succeeded", "hardwareProfile": {"vmSize": "Standard_B2s"}},
    });
    Box::new(compute::VmRow::from_json(&v, Some(TENANT)).expect("a VM"))
}

fn landed(h: &Harness, sub: &str, result: std::result::Result<Vec<Box<dyn Resource>>, String>) -> Event {
    Event::SubscriptionFanoutLoaded {
        generation: h.app.fanout_load.generation(),
        view: JumpView::VirtualMachines,
        subscription: sub.to_string(),
        result,
    }
}

fn status(h: &Harness, sub: &str) -> Option<SubscriptionCount> {
    h.app.fanout_status(JumpView::VirtualMachines, sub).map(|(c, _)| *c)
}

fn cached(h: &Harness, sub: &str) -> Option<usize> {
    h.app
        .cache
        .get_ref(&ServiceType::VirtualMachines, sub, Some(JumpView::VirtualMachines.as_str()))
        .map(|r| r.len())
}

fn shift(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::SHIFT)
}

#[tokio::test]
async fn opening_p_counts_the_current_tab_in_each_configured_subscription() {
    let mut h = fanout_harness(&["Prod", "Dev", "Stage", "Old"]).await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm_in(SUB_DEV, "dev-1"), vm_in(SUB_DEV, "dev-2")]).await;

    h.press_key(shift('P')).await;
    assert!(h.app.subscription_selector.visible);
    // Prod and Stage list; Dev is the normal load's; Old is disabled and
    // never called.
    assert_eq!(status(&h, SUB_PROD), Some(SubscriptionCount::Loading));
    assert_eq!(status(&h, SUB_STAGE), Some(SubscriptionCount::Loading));
    assert_eq!(status(&h, SUB_DEV), None);
    assert_eq!(status(&h, SUB_OLD), Some(SubscriptionCount::Disabled));
    assert_eq!(h.app.fanout_load.tasks.len(), 2, "one list per enabled, uncached subscription");
    let counts = h.app.subscription_counts();
    assert_eq!(counts.get(SUB_DEV), Some(&SubscriptionCount::Count(2)));
    assert_eq!(counts.get(SUB_PROD), Some(&SubscriptionCount::Loading));

    // Config order first in the picker, then the rest.
    let order: Vec<String> = h.app.subscription_selector.filtered().iter().map(|e| e.name.clone()).collect();
    assert_eq!(order, ["Prod", "Dev", "Stage", "Old"]);

    let ev = landed(&h, SUB_PROD, Ok(vec![vm_in(SUB_PROD, "prod-1"), vm_in(SUB_PROD, "prod-2"), vm_in(SUB_PROD, "prod-3")]));
    h.send(ev).await;
    assert_eq!(status(&h, SUB_PROD), None, "a success is the cache entry");
    assert_eq!(cached(&h, SUB_PROD), Some(3));
    assert_eq!(h.app.subscription_counts().get(SUB_PROD), Some(&SubscriptionCount::Count(3)));
    assert_eq!(h.visible_names(), ["dev-1", "dev-2"], "a fan-out never touches the list on screen");

    let screen = h.render();
    assert!(screen.contains("VMs per subscription"), "{screen}");
    let row = |name: &str| screen.lines().find(|l| l.contains(name)).unwrap_or_default().to_string();
    assert!(row("Prod ").contains("enabled   3"), "{}", row("Prod "));
    assert!(row("Stage ").contains("enabled   …"), "{}", row("Stage "));
    assert!(row("Old ").contains("disabled  disabled"), "{}", row("Old "));

    // Reopening fetches nothing new: Prod is cached, Stage still loading.
    // (The offline tasks never finish, so the two first ones are still
    // tracked.)
    h.press(KeyCode::Esc).await;
    h.press_key(shift('P')).await;
    assert_eq!(h.app.fanout_load.tasks.len(), 2, "no new list started");

    // Picking Prod lands instantly from the cache, and is a history step.
    h.type_str("Prod").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.subscription_id.as_deref(), Some(SUB_PROD));
    assert!(!h.app.loading, "a cache hit isn't a load");
    assert_eq!(h.visible_names(), ["prod-1", "prod-2", "prod-3"]);
    assert_eq!(h.app.nav_back_hint().as_deref(), Some("VMs dev-1 · Dev"));
    // Another sub-tab counts its own list.
    assert_eq!(h.app.subscription_counts().get(SUB_PROD), Some(&SubscriptionCount::Count(3)));
    h.press(KeyCode::Tab).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    assert!(h.app.subscription_counts().is_empty(), "no disks listed anywhere yet");
}

/// `⌫` back across a subscription switch: the other subscription's list
/// is a cache hit and the row is selected again. The jump list and the
/// bookmarks name the other subscription.
#[tokio::test]
async fn history_jump_list_and_bookmarks_cross_subscriptions() {
    let mut h = fanout_harness(&["Prod"]).await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm_in(SUB_DEV, "dev-1"), vm_in(SUB_DEV, "dev-2")]).await;
    h.press(KeyCode::Char('j')).await;
    assert_eq!(h.visible_names()[h.app.selected_index.unwrap()], "dev-2");
    h.press(KeyCode::Char('B')).await;
    assert_eq!(h.app.bookmarks.len(), 1);
    assert_eq!(h.app.bookmarks[0].subscription.as_deref(), Some(SUB_DEV));

    h.press_key(shift('P')).await;
    h.type_str("Prod").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.subscription_id.as_deref(), Some(SUB_PROD));
    h.land(vec![vm_in(SUB_PROD, "prod-1")]).await;
    assert_eq!(h.app.nav_back_hint().as_deref(), Some("VMs dev-2 · Dev"));

    // The bookmark from Dev names it.
    h.press(KeyCode::Char('\'')).await;
    let screen = h.render();
    assert!(screen.contains("dev-2  ·  Dev"), "{screen}");
    h.press(KeyCode::Esc).await;

    // ⌫: back to Dev, on the row we left.
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.subscription_id.as_deref(), Some(SUB_DEV));
    assert!(!h.app.loading, "Dev's list is cached");
    assert_eq!(h.selected_id().as_deref(), Some(vm_in(SUB_DEV, "dev-2").id()));

    // The jump list names Prod beside the place there.
    h.press(KeyCode::Char('`')).await;
    let screen = h.render();
    assert!(screen.contains("prod-1  ·  Prod"), "{screen}");
    assert!(!screen.contains("dev-2  ·  Dev"), "the current subscription isn't named:\n{screen}");
    h.press(KeyCode::Esc).await;

    // The bookmark restores in Dev; from Prod it switches back first.
    h.press_key(shift('P')).await;
    h.type_str("Prod").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.subscription_id.as_deref(), Some(SUB_PROD));
    h.press(KeyCode::Char('\'')).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.subscription_id.as_deref(), Some(SUB_DEV));
    assert_eq!(h.selected_id().as_deref(), Some(vm_in(SUB_DEV, "dev-2").id()));
}

#[tokio::test]
async fn failures_show_per_row_and_are_never_fatal() {
    let mut h = fanout_harness(&["Prod", "Stage"]).await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm_in(SUB_DEV, "dev-1")]).await;
    h.press_key(shift('P')).await;

    let denied = "Azure error: 403 AuthorizationFailed: The client 'u' does not have authorization to perform action \
                  'Microsoft.Compute/virtualMachines/read' over scope '/subscriptions/x'.";
    let ev = landed(&h, SUB_PROD, Err(denied.into()));
    h.send(ev).await;
    let ev = landed(&h, SUB_STAGE, Err("connection refused (management.azure.com)".into()));
    h.send(ev).await;
    assert_eq!(status(&h, SUB_PROD), Some(SubscriptionCount::Denied));
    assert_eq!(status(&h, SUB_STAGE), Some(SubscriptionCount::Failed));
    assert!(h.app.error_message.is_none(), "{:?}", h.app.error_message);
    assert_eq!(h.visible_names(), ["dev-1"]);
    let screen = h.render();
    let row = |name: &str| screen.lines().find(|l| l.contains(name)).unwrap_or_default().to_string();
    assert!(row("Prod ").contains("denied"), "{}", row("Prod "));
    assert!(row("Stage ").contains("error"), "{}", row("Stage "));

    // Reopening retries the failure, not the 403.
    h.press(KeyCode::Esc).await;
    h.press_key(shift('P')).await;
    assert_eq!(status(&h, SUB_PROD), Some(SubscriptionCount::Denied));
    assert_eq!(status(&h, SUB_STAGE), Some(SubscriptionCount::Loading));
}

/// An auth retry supersedes the fan-out (#57's rule): its tasks are
/// aborted, its late results dropped.
#[tokio::test]
async fn a_superseded_fanout_is_aborted_and_its_results_dropped() {
    let mut h = fanout_harness(&["Prod"]).await;
    h.open(JumpView::VirtualMachines).await;
    h.press_key(shift('P')).await;
    let tasks = h.app.fanout_load.tasks.clone();
    assert_eq!(tasks.len(), 1);
    let stale = landed(&h, SUB_PROD, Ok(vec![vm_in(SUB_PROD, "prod-1")]));

    h.app.supersede_fanout();
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !tasks.iter().all(|t| t.is_finished()) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(stopped.is_ok(), "the fan-out task was aborted");
    h.send(stale).await;
    assert_eq!(cached(&h, SUB_PROD), None, "a superseded result is dropped");
    assert!(!h.app.subscription_counts().contains_key(SUB_PROD));

    // A subscription switch keeps it: the other lists are still theirs.
    h.press_key(shift('P')).await;
    let generation = h.app.fanout_load.generation();
    h.send(Event::SubscriptionSwitchRequested { subscription_id: SUB_PROD.into() }).await;
    assert_eq!(h.app.fanout_load.generation(), generation);
}

#[tokio::test]
async fn no_fanout_without_config_or_for_tenant_wide_sub_tabs() {
    // No config `subscriptions`: `P` is a picker and makes no call.
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.press_key(shift('P')).await;
    assert!(h.app.subscription_fanout.is_empty());
    assert!(h.app.fanout_load.tasks.is_empty());
    assert!(h.app.subscription_counts().is_empty());
    assert!(!h.render().contains("per subscription"));

    // Configured, but the directory's lists are the tenant's, and
    // `@changes` is one list per window.
    let mut h = fanout_harness(&["Prod"]).await;
    for view in [JumpView::ServicePrincipals, JumpView::Subscriptions, JumpView::ChangesAll] {
        h.press(KeyCode::Esc).await;
        h.open(view).await;
        h.press_key(shift('P')).await;
        assert!(h.app.fanout_load.tasks.is_empty(), "{view:?}");
        assert_eq!(h.app.subscription_count_label(), None, "{view:?}");
    }
}

#[tokio::test]
async fn unknown_configured_subscriptions_warn_at_startup() {
    let h = fanout_harness(&["Prod", "nope", "dev"]).await;
    assert_eq!(h.app.configured_subscriptions, [SUB_PROD, SUB_DEV]);
    let warning = h.app.error_message.clone().unwrap_or_default();
    assert!(warning.contains("subscriptions: unknown subscription nope"), "{warning}");
}
