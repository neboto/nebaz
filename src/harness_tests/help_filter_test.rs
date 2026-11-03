// ported from neboto-tui src/harness_tests/help_filter_test.rs @ 6e0163d (rewritten on the nebaz harness)
//! `?` filters as you type (#150): the table narrows to one full-width
//! column, letters are text (so `q` doesn't quit), `Esc` clears, then closes.

use super::*;

const LONG: &str = "referenced by (warm lists; L loads likely)";

#[tokio::test]
async fn help_filters_as_you_type() {
    let mut h = Harness::sized(90, 40).await;
    h.press(KeyCode::Char('?')).await;
    assert!(h.app.help_visible);
    let before = h.render();
    assert!(before.contains("type to filter keys") && before.contains("toggle banner"), "{before}");
    assert!(!before.contains(LONG), "two columns cut this one off at 90 wide\n{before}");

    h.type_str("referenced").await;
    assert!(h.app.running, "letters are filter text");
    let screen = h.render();
    assert!(screen.contains(LONG), "one full-width column shows it whole\n{screen}");
    assert!(!screen.contains("toggle banner"), "{screen}");

    // `q` and `j` are text while help is open.
    h.press(KeyCode::Char('q')).await;
    assert!(h.app.running && h.app.help_visible);
    assert!(h.render().contains("No keys match \"referencedq\""));
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.help_query, "referenced");

    // `?` is text mid-filter; Esc clears, then closes.
    h.press(KeyCode::Char('?')).await;
    assert!(h.app.help_visible && h.app.help_query.ends_with('?'));
    h.press(KeyCode::Esc).await;
    assert!(h.app.help_visible && h.app.help_query.is_empty());
    h.press(KeyCode::Esc).await;
    assert!(!h.app.help_visible);

    // Reopening starts clean; `?` on an empty filter closes.
    h.press(KeyCode::Char('?')).await;
    assert!(h.app.help_visible && h.app.help_query.is_empty());
    h.press(KeyCode::Char('?')).await;
    assert!(!h.app.help_visible);
}

#[tokio::test]
async fn section_title_matches_and_popup_height_holds() {
    let mut h = Harness::sized(120, 50).await;
    h.press(KeyCode::Char('?')).await;
    let rows = |s: &str| s.lines().filter(|l| l.contains('│') || l.contains('┃')).count();
    let full = rows(&h.render());
    h.type_str("mouse").await;
    let screen = h.render();
    assert!(screen.contains("Shift-drag") && screen.contains("wheel"), "{screen}");
    assert_eq!(rows(&screen), full, "the popup keeps its height\n{screen}");
}

#[tokio::test]
async fn arrows_and_page_keys_scroll_and_typing_resets() {
    let mut h = Harness::sized(120, 20).await;
    h.press(KeyCode::Char('?')).await;
    let _ = h.render(); // records help_max_scroll
    assert!(h.app.help_max_scroll.get() > 0);
    h.press(KeyCode::Down).await;
    assert_eq!(h.app.help_scroll, 1);
    h.press(KeyCode::Char('j')).await;
    assert_eq!(h.app.help_scroll, 0, "j is text and resets the scroll");
    assert_eq!(h.app.help_query, "j");
    h.press(KeyCode::Backspace).await;
    h.press(KeyCode::PageDown).await;
    assert_eq!(h.app.help_scroll, 10.min(h.app.help_max_scroll.get()));
    h.press_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)).await;
    assert_eq!(h.app.help_scroll, 0);
    h.press(KeyCode::End).await;
    assert_eq!(h.app.help_scroll, h.app.help_max_scroll.get());
    h.press(KeyCode::Home).await;
    assert_eq!(h.app.help_scroll, 0);
}

#[tokio::test]
async fn help_counts_as_a_picker_for_keycast() {
    let mut h = Harness::new().await;
    h.app.keycast = Some(Default::default());
    h.press(KeyCode::Char('?')).await;
    h.type_str("zz").await;
    let echoed: Vec<String> =
        h.app.keycast.as_ref().unwrap().entries.iter().map(|e| e.key.clone()).collect();
    assert!(!echoed.iter().any(|k| k == "z"), "typed text is not echoed: {echoed:?}");
}
