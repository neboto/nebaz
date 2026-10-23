//! Registration, the section-order invariant, renderer reach, and the
//! keymap/mouse smash, over every mock.

use super::mocks::all_mocks;
use super::*;
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

#[tokio::test]
async fn every_service_type_is_registered_before_and_after_a_subscription_switch() {
    let mut h = Harness::new().await;
    let check = |app: &App, when: &str| {
        for st in ServiceType::all() {
            assert_eq!(
                app.azure_clients.service(st).service_type(),
                st,
                "client.rs::service({st:?}) builds another service's provider ({when})"
            );
            for view in st.views() {
                assert_eq!(view.service(), st, "{view:?} is listed under {st:?} but routes elsewhere");
            }
        }
    };
    check(&h.app, "at startup");
    h.send(Event::SubscriptionSwitchRequested {
        subscription_id: SUB_PROD.to_string(),
    })
    .await;
    assert_eq!(h.app.subscription_id.as_deref(), Some(SUB_PROD));
    check(&h.app, "after a subscription switch");
}

/// Every sub-tab has a mock, so the checks below cover every list.
#[test]
fn every_sub_tab_has_a_mock() {
    let mocked: Vec<JumpView> = all_mocks().iter().map(|m| m.view).collect();
    for st in ServiceType::all() {
        for view in st.views() {
            // Function apps are the sites list filtered by kind: SiteRow.
            if *view == JumpView::FunctionApps {
                continue;
            }
            assert!(mocked.contains(view), "{view:?} has no mock in harness_tests/mocks.rs");
        }
    }
}

/// For every split pane: focus lands on section 0, digit keys and the Tab
/// cycle walk the descriptor in order, the snapshot (export, `$EDITOR`,
/// flat view) agrees, and the shared tail is Access, Activity, Related,
/// Tags (CLAUDE.md, "Split detail pane").
#[tokio::test]
async fn split_pane_sections_follow_the_descriptor() {
    let mut h = Harness::new().await;
    for mock in all_mocks() {
        let label = mock.label;
        h.install(mock).await;
        h.press(KeyCode::Enter).await;
        assert!(h.app.details_focused, "{label}: Enter focuses the pane");
        assert_eq!(h.app.detail_section_idx, 0, "{label}: focus lands on the first section");

        let labels = h.section_labels();
        let n = labels.len();
        assert!(n >= 5, "{label}: no descriptor, or a short one: {labels:?}");
        assert_eq!(labels[0], "Overview", "{label}: Overview first");
        assert_eq!(&labels[n - 4..], ["Access", "Activity", "Related", "Tags"], "{label}: shared tail");

        let snapshot: Vec<String> = h.app.detail_sections_snapshot().into_iter().map(|(name, _)| name).collect();
        assert_eq!(snapshot, labels, "{label}: snapshot order");

        for (i, name) in labels.iter().enumerate() {
            let Some(c) = crate::sections::key_for(i) else { break };
            h.press(KeyCode::Char(c)).await;
            assert_eq!(h.app.detail_section_idx, i, "{label}: '{c}' should open {name}");
        }

        h.press(KeyCode::Char('1')).await;
        for step in 1..=n {
            h.press(KeyCode::Tab).await;
            assert_eq!(h.app.detail_section_idx, step % n, "{label}: Tab step {step} of {labels:?}");
        }
        h.press(KeyCode::BackTab).await;
        assert_eq!(h.app.detail_section_idx, n - 1, "{label}: Shift-Tab from the first wraps to the last");
    }
}

/// `section_lines_for` is a hand-written downcast chain: a type with a
/// descriptor but no arm silently falls back to the flat `details()` view.
/// Require an answer for every section, and every tab label on screen.
#[tokio::test]
async fn every_split_pane_type_reaches_its_renderer() {
    let mut h = Harness::sized(300, 60).await;
    for mock in all_mocks() {
        let label = mock.label;
        h.install(mock).await;
        h.press(KeyCode::Enter).await;
        let labels = h.section_labels();
        let resource = h.app.get_selected_resource().unwrap();
        for (i, section) in labels.iter().enumerate() {
            assert!(
                h.app.section_lines_for(resource, i).is_some(),
                "{label}: no section_lines_for arm (section {section})"
            );
        }
        let screen = h.render();
        for section in &labels {
            assert!(screen.contains(section), "{label}: tab “{section}” not on screen:\n{screen}");
        }
    }
}

/// Every key the panes answer, in an order that opens and closes each
/// overlay so later keys reach the pane.
fn smash_sequence() -> Vec<KeyEvent> {
    let ctrl = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
    let mut keys = vec![key(KeyCode::Char('l'))];
    keys.extend(('1'..='9').chain(['0']).map(|c| key(KeyCode::Char(c))));
    keys.extend([
        key(KeyCode::Tab),
        key(KeyCode::BackTab),
        key(KeyCode::Char('j')),
        key(KeyCode::Char('j')),
        key(KeyCode::Char('k')),
        key(KeyCode::Char('G')),
        key(KeyCode::Char('g')),
        ctrl('d'),
        ctrl('u'),
        key(KeyCode::Char('V')),
        key(KeyCode::Char('j')),
        key(KeyCode::Char('J')),
        key(KeyCode::Char('K')),
        key(KeyCode::Char('y')),
        ctrl('a'),
        key(KeyCode::Char('y')),
        key(KeyCode::Esc),
        key(KeyCode::Char('\\')),
        key(KeyCode::Char('j')),
        key(KeyCode::Tab),
        key(KeyCode::Char('3')),
        key(KeyCode::Char('G')),
        key(KeyCode::Char('\\')),
        key(KeyCode::Char('Z')),
        key(KeyCode::Char('Z')),
        key(KeyCode::Char('X')),
        key(KeyCode::Char('C')),
        key(KeyCode::Char('O')),
        key(KeyCode::Char('r')),
        key(KeyCode::Enter),
        key(KeyCode::Char('h')),
        key(KeyCode::Char('z')),
        key(KeyCode::Char('F')),
        key(KeyCode::Char('a')),
        key(KeyCode::Char('a')),
        key(KeyCode::Char('w')),
        key(KeyCode::Char('+')),
        key(KeyCode::Char('-')),
        key(KeyCode::Char('w')),
        ctrl('X'),
        key(KeyCode::Char('y')),
        key(KeyCode::Char('/')),
        key(KeyCode::Char('x')),
        key(KeyCode::Esc),
        key(KeyCode::Char('?')),
        key(KeyCode::Char('j')),
        key(KeyCode::Esc),
        key(KeyCode::Char('S')),
        key(KeyCode::Down),
        key(KeyCode::Esc),
        key(KeyCode::Char('R')),
        key(KeyCode::Down),
        key(KeyCode::Esc),
        key(KeyCode::Char('P')),
        key(KeyCode::Down),
        key(KeyCode::Esc),
        key(KeyCode::Char('`')),
        key(KeyCode::Esc),
        key(KeyCode::Char('\'')),
        key(KeyCode::Esc),
        key(KeyCode::Char('M')),
        key(KeyCode::Char('j')),
        key(KeyCode::Esc),
        key(KeyCode::Char('b')),
        key(KeyCode::Char('b')),
        ctrl('o'),
        ctrl('l'),
    ]);
    keys
}

/// Drive the keymap, then click every recorded region and spin the wheel,
/// over every mock, drawing after each event. Nothing may panic.
#[tokio::test]
async fn keymap_and_mouse_smash_never_panics() {
    let mut h = Harness::new().await;
    for mock in all_mocks() {
        let label = mock.label;
        h.install(mock).await;
        // Each press settles, which draws a frame.
        for k in smash_sequence() {
            h.press_key(k).await;
        }
        assert!(!h.app.any_modal_open(), "{label}: the smash left an overlay open");

        let targets: Vec<(u16, u16)> = h
            .app
            .click_regions
            .borrow()
            .iter()
            .map(|r| (r.rect.x + r.rect.width / 2, r.rect.y + r.rect.height / 2))
            .chain([(10, 10), (10, 20), (100, 20)])
            .collect();
        let mouse = |kind, (column, row)| {
            Event::Mouse(MouseEvent {
                kind,
                column,
                row,
                modifiers: KeyModifiers::NONE,
            })
        };
        for at in targets {
            h.send(mouse(MouseEventKind::Down(MouseButton::Left), at)).await;
            h.send(mouse(MouseEventKind::ScrollDown, at)).await;
            h.send(mouse(MouseEventKind::ScrollUp, at)).await;
            h.press(KeyCode::Esc).await;
        }
    }
}
