// ported from neboto-tui src/harness_tests/keycast_test.rs @ b92e140 (the
// behaviours it pins), rewritten on the nebaz harness, plus the mouse
//! Keycast (`--show-keys`, #43) through the real key path: `handle_event`,
//! then the main loop's `keycast_tick` (inside `Harness::settle`), and a
//! rendered frame, so the box is proven to draw, not just to hold entries.

use super::mocks::vm;
use super::*;

async fn vms(keycast: bool) -> Harness {
    let mut h = Harness::new().await;
    h.app.keycast = keycast.then(Default::default);
    h.app.current_location = Location::All;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-a", "westeurope"), vm("vm-b", "westeurope")]).await;
    h
}

fn shown(h: &Harness) -> Vec<(String, Option<String>)> {
    h.app
        .keycast
        .as_ref()
        .expect("keycast is on")
        .entries
        .iter()
        .map(|e| (e.key.clone(), e.action.clone()))
        .collect()
}

fn entry(key: &str, action: Option<&str>) -> (String, Option<String>) {
    (key.to_string(), action.map(str::to_string))
}

#[tokio::test]
async fn off_by_default_and_draws_nothing() {
    let mut h = vms(false).await;
    assert!(h.app.keycast.is_none(), "Config::default() leaves it off");
    h.press(KeyCode::Enter).await;
    assert!(!h.render().contains(" keys "));
}

#[tokio::test]
async fn labels_keys_by_what_they_did_and_draws_the_box() {
    let mut h = vms(true).await;
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('W')).await;
    assert_eq!(shown(&h), vec![entry("⏎", Some("open")), entry("W", Some("change timeline"))]);
    let screen = h.render();
    assert!(screen.contains(" keys "), "the box's title\n{screen}");
    assert!(screen.contains(" W  change timeline"), "{screen}");
}

#[tokio::test]
async fn typed_search_text_never_shows() {
    let mut h = vms(true).await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("vm-b").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(
        shown(&h),
        vec![entry("/", Some("search")), entry("⏎", Some("search"))],
        "the query's letters are not keys to show"
    );
    assert!(!h.render().contains("vm-b ⏎"));

    // The detail filter and the pickers hold back their text the same way.
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("secret").await;
    h.press(KeyCode::Esc).await;
    h.press(KeyCode::Char('R')).await;
    h.type_str("west").await;
    h.press(KeyCode::Esc).await;
    let keys: Vec<String> = shown(&h).into_iter().map(|(k, _)| k).collect();
    assert!(keys.iter().all(|k| !["s", "e", "c", "w"].contains(&k.as_str())), "{keys:?}");
}

#[tokio::test]
async fn a_mouse_gesture_shows_as_the_key_it_replays() {
    let mut h = vms(true).await;
    let list = h.app.list_area.get();
    h.double_click((list.x + 3, list.y + 2)).await;
    assert!(h.app.details_focused, "a double-click is ⏎");
    assert_eq!(shown(&h).last(), Some(&entry("⏎", Some("open"))));
}
