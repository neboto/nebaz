//! The `/` inputs have a cursor (#151, neboto-tui#300): the list search bar
//! and the detail pane's filter edit in the middle, and the bar says `↑`
//! recalls history.

use super::mocks::vm;
use super::*;

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

async fn vm_harness() -> Harness {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h
}

#[tokio::test]
async fn a_recalled_search_can_be_edited_in_the_middle() {
    let mut h = vm_harness().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("prd-api").await;
    h.press(KeyCode::Enter).await;

    // `/` on a confirmed query resumes it; an empty bar is not required to recall.
    h.press(KeyCode::Char('/')).await;
    h.app.search_query.clear();
    h.press(KeyCode::Up).await;
    assert_eq!(h.app.search_query, "prd-api");
    assert_eq!(h.app.search_cursor_back, 0, "recall leaves the cursor at the end");
    for _ in 0..5 {
        h.press(KeyCode::Left).await;
    }
    h.press(KeyCode::Char('o')).await;
    assert_eq!(h.app.search_query, "prod-api");
    h.press(KeyCode::End).await;
    h.type_str("-gw").await;
    assert_eq!(h.app.search_query, "prod-api-gw");
    h.press_key(ctrl('w')).await;
    assert_eq!(h.app.search_query, "", "Ctrl-W takes the space-delimited word");
    h.type_str("prod-").await;
    h.press_key(ctrl('a')).await;
    h.press(KeyCode::Delete).await;
    assert_eq!(h.app.search_query, "rod-");
    h.press_key(ctrl('e')).await;
    h.press_key(ctrl('u')).await;
    assert_eq!(h.app.search_query, "");
    // A Ctrl-letter that is not an editing key is not typed.
    h.press_key(ctrl('x')).await;
    assert_eq!(h.app.search_query, "");
    assert!(h.app.search_active);
}

#[tokio::test]
async fn the_search_cursor_is_drawn_where_it_is_and_multibyte_counts_chars() {
    let mut h = vm_harness().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("café").await;
    let end = h.cursor();
    h.press(KeyCode::Left).await;
    h.press(KeyCode::Left).await;
    assert_eq!(h.cursor(), (end.0 - 2, end.1));
    h.press(KeyCode::Home).await;
    assert_eq!(h.cursor(), (end.0 - 4, end.1));
    h.press(KeyCode::Char('x')).await;
    assert_eq!(h.app.search_query, "xcafé");
    assert_eq!(h.cursor(), (end.0 - 3, end.1));
    // Tab completion and a recall set the query outright: cursor at the end.
    h.app.search_query = "@v".into();
    h.press(KeyCode::Home).await;
    h.press(KeyCode::Tab).await;
    assert_eq!(h.app.search_cursor_back, 0);
}

#[tokio::test]
async fn the_bar_says_up_recalls_history_only_when_it_could() {
    let mut h = vm_harness().await;
    h.press(KeyCode::Char('/')).await;
    assert!(!h.render().contains("↑ history"), "no history yet");
    h.type_str("web").await;
    h.press(KeyCode::Enter).await;

    h.press(KeyCode::Char('/')).await;
    h.app.search_query.clear();
    assert!(h.render().contains("↑ history"));
    h.type_str("w").await;
    assert!(!h.render().contains("↑ history"), "only while the bar is empty");
}

#[tokio::test]
async fn colon_stays_a_literal_in_the_middle_of_a_query() {
    let mut h = vm_harness().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("ab").await;
    h.press(KeyCode::Left).await;
    h.press(KeyCode::Char(':')).await;
    assert!(!h.app.key_picker.visible);
    assert_eq!(h.app.search_query, "a:b");
}

#[tokio::test]
async fn the_detail_filter_edits_in_the_middle_too() {
    let mut h = vm_harness().await;
    h.app.details_focused = true;
    h.press(KeyCode::Char('/')).await;
    h.type_str("subet").await;
    h.press(KeyCode::Left).await;
    h.press(KeyCode::Left).await;
    h.press(KeyCode::Char('n')).await;
    assert_eq!(h.app.detail_search_query, "subnet");
    assert!(h.app.detail_search_active && h.app.details_focused, "arrows stay in the filter");

    // The caret is the reverse-video char under the cursor (`b` here
    // after two steps left), then the block after the text.
    h.press(KeyCode::Left).await;
    h.press(KeyCode::Left).await;
    let at = h.find(" / subnet");
    assert!(h.reversed_at((at.0 + 3 + 2, at.1)), "the caret is on the `b`");
    h.press(KeyCode::End).await;
    assert!(h.render().contains("subnet█"));

    h.press_key(ctrl('a')).await;
    h.press(KeyCode::Delete).await;
    assert_eq!(h.app.detail_search_query, "ubnet");
    h.press_key(ctrl('w')).await;
    assert_eq!(h.app.detail_search_query, "ubnet", "nothing before the cursor");
    h.press_key(ctrl('e')).await;
    h.press_key(ctrl('w')).await;
    assert_eq!(h.app.detail_search_query, "");
    assert!(!h.app.detail_wrap, "Ctrl-W in the filter is a delete");
}

#[tokio::test]
async fn ctrl_a_and_ctrl_w_keep_their_meaning_outside_the_filter() {
    let mut h = vm_harness().await;
    h.app.details_focused = true;
    assert!(!h.app.detail_wrap);
    h.press_key(ctrl('w')).await;
    assert!(h.app.detail_wrap, "Ctrl-W toggles wrap");
    h.press_key(ctrl('a')).await;
    assert!(h.app.detail_visual_anchor.is_some(), "Ctrl-A selects all");
    assert!(!h.app.detail_search_active && h.app.detail_search_query.is_empty());
}
