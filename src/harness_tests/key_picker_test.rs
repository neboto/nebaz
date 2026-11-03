// ported from neboto-tui src/harness_tests/command_picker_test.rs @ 66458f6 (rewritten on the nebaz harness; `command_picker` here is the `C` az picker, so this is `key_picker`)
//! `:` lists the keys that run here, by name, and `⏎` replays the row's
//! key through the event channel (#149). The `C` picker has its own tests
//! in `command_picker_test`.

use super::mocks::vm;
use super::*;

fn keys(h: &Harness) -> Vec<&'static str> {
    crate::commands::picker_rows(&h.app, &h.app.key_picker.query).iter().map(|c| c.key).collect()
}

async fn vm_harness() -> Harness {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h
}

#[tokio::test]
async fn colon_runs_a_key_by_name() {
    let mut h = vm_harness().await;

    h.press(KeyCode::Char(':')).await;
    assert!(h.app.key_picker.visible);
    assert!(h.app.command_picker.is_none(), "`:` is not the `C` picker");
    // No query: the keys this VM has lead, list-pane rows only.
    let listed = keys(&h);
    assert!(listed.contains(&"m") && listed.contains(&"W") && listed.contains(&"U") && listed.contains(&"C"), "{listed:?}");
    assert!(listed.contains(&"z") && listed.contains(&"R"), "{listed:?}");
    assert!(!listed.contains(&"Z"), "detail-pane rows stay out of the list pane: {listed:?}");
    assert!(!listed.contains(&"j / k ↑ / ↓"), "not one key: {listed:?}");
    let is_gated = |k: &str| crate::commands::COMMANDS.iter().any(|c| c.key == k && c.gate.is_some());
    let here = listed.iter().take_while(|k| is_gated(k)).count();
    assert!(here >= 4, "the selection's keys lead: {listed:?}");
    assert!(listed[here..].iter().all(|k| !is_gated(k)), "and only they: {listed:?}");

    let screen = h.render();
    assert!(screen.contains("Commands") && screen.contains("here"), "{screen}");
    assert!(screen.contains("metrics (Azure Monitor)"), "{screen}");

    // Typing narrows by key, label and section; an exact key wins.
    h.type_str("metrics").await;
    assert_eq!(keys(&h)[0], "m");
    h.press(KeyCode::Enter).await;
    assert!(!h.app.key_picker.visible);
    // The replayed `m` opened the metrics view, as if pressed.
    assert!(h.app.metrics.is_some(), "m ran");
}

#[tokio::test]
async fn enter_sends_the_key_through_the_channel_so_keycast_sees_it() {
    let mut h = vm_harness().await;
    h.app.keycast = Some(Default::default());
    h.press(KeyCode::Char(':')).await;
    h.type_str("timeline").await;
    h.press(KeyCode::Enter).await;
    let echoed: Vec<String> = h.app.keycast.as_ref().unwrap().entries.iter().map(|e| e.key.clone()).collect();
    assert!(echoed.iter().any(|k| k == "W"), "the replayed key is echoed: {echoed:?}");
    assert!(h.app.timeline.is_some(), "W ran");
}

#[tokio::test]
async fn colon_is_text_in_inputs_and_esc_closes_the_picker() {
    let mut h = vm_harness().await;
    h.press(KeyCode::Char('/')).await;
    h.press(KeyCode::Char(':')).await;
    assert!(!h.app.key_picker.visible);
    assert!(h.app.search_query.ends_with(':'), "{:?}", h.app.search_query);
    h.press(KeyCode::Esc).await;

    // In the picker, `q` is filter text, not quit.
    h.press(KeyCode::Char(':')).await;
    h.type_str("q").await;
    assert!(h.app.running, "q is filter text");
    assert_eq!(h.app.key_picker.query, "q");
    h.press(KeyCode::Esc).await;
    assert!(!h.app.key_picker.visible);

    // The detail-pane filter takes `:` literally too.
    h.app.details_focused = true;
    h.press(KeyCode::Char('/')).await;
    h.press(KeyCode::Char(':')).await;
    assert!(!h.app.key_picker.visible && h.app.detail_search_query.ends_with(':'));
    h.press(KeyCode::Esc).await;

    // From the detail pane, detail rows join and list rows leave.
    h.press(KeyCode::Char(':')).await;
    let listed = keys(&h);
    assert!(listed.contains(&"Z") && !listed.contains(&"z"), "{listed:?}");
}

#[tokio::test]
async fn help_hands_over_to_the_picker_and_calls_it_out() {
    let mut h = vm_harness().await;
    h.press(KeyCode::Char('?')).await;
    assert!(h.render().contains("run any key by name"), "the help's call-out");
    h.press(KeyCode::Char(':')).await;
    assert!(!h.app.help_visible && h.app.key_picker.visible);

    // Mid-filter, `:` is text (a key such as `ctrl: …` can't be typed
    // otherwise).
    h.press(KeyCode::Esc).await;
    h.press(KeyCode::Char('?')).await;
    h.press(KeyCode::Char('a')).await;
    h.press(KeyCode::Char(':')).await;
    assert!(h.app.help_visible && h.app.help_query == "a:");
}

#[tokio::test]
async fn the_picker_owns_the_mouse() {
    let mut h = vm_harness().await;
    h.press(KeyCode::Char(':')).await;
    let at = h.find("metrics (Azure Monitor)");
    h.click(at).await;
    assert!(h.app.key_picker.visible, "a click highlights");
    assert_eq!(keys(&h)[h.app.key_picker.selected_index], "m");
    h.click(at).await;
    assert!(h.app.metrics.is_some(), "a second click runs it, as ⏎ does");

    let mut h = vm_harness().await;
    h.press(KeyCode::Char(':')).await;
    h.right_click((0, 0)).await;
    assert!(!h.app.key_picker.visible, "a right-click closes it");
}
