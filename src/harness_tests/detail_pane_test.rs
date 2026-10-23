//! The detail pane's reading keys (#41): the `/` body filter and `n`/`N`,
//! `[[` / `]]` group jumps, `Ctrl-W` wrap, and `H` / `L` sub-tab steps.
//! The filter narrows the body every key indexes, so the cursor, `y`,
//! `V` and `⏎` act on the line on screen; wrap only changes the screen
//! shape, so they stay on logical rows.

use super::mocks::{all_mocks, arm_id, disk, nic, nic_id, vm};
use super::*;

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

/// A VM with its detail pane focused on `section`.
async fn vm_pane(h: &mut Harness, section: &str) {
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Enter).await;
    let idx = h.section_labels().iter().position(|l| *l == section).unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
}

async fn filter(h: &mut Harness, query: &str) {
    h.press(KeyCode::Char('/')).await;
    h.type_str(query).await;
    h.press(KeyCode::Enter).await;
}

fn flat_headers(h: &Harness) -> Vec<String> {
    h.app
        .detail_body()
        .iter()
        .filter_map(|(k, _)| flat_header_name(k).map(str::to_string))
        .collect()
}

/// The screen with the pane borders dropped and all whitespace squashed,
/// so a value wrapped over several rows reads as one string.
fn squashed(screen: &str) -> String {
    screen.chars().filter(|c| !c.is_whitespace() && *c != '│').collect()
}

#[tokio::test]
async fn slash_filters_the_body_and_keys_act_on_the_visible_line() {
    let mut h = Harness::new().await;
    vm_pane(&mut h, "Related").await;
    let target = nic_id("vm-1-nic");
    let unfiltered = h.app.detail_body().len();

    h.press(KeyCode::Char('/')).await;
    assert!(h.app.detail_search_active);
    h.type_str("vm-1-nic").await;
    let body = h.app.detail_body();
    assert!(body.len() < unfiltered, "{body:#?}");
    assert!(body.iter().all(|(k, v)| k.contains("vm-1-nic") || v.contains("vm-1-nic")), "{body:#?}");
    // The cursor sits on the first match, and the bar counts them.
    assert_eq!(body[h.app.details_scroll].1, target);
    let screen = h.render();
    assert!(screen.contains("/ vm-1-nic") && screen.contains("(1 match)"), "{screen}");

    // ⏎ keeps the filter and returns to the keys: `y` copies the line on
    // screen, not the line at that index in the unfiltered body.
    h.press(KeyCode::Enter).await;
    assert!(!h.app.detail_search_active);
    assert_eq!(h.app.detail_search_query, "vm-1-nic");
    h.press(KeyCode::Char('y')).await;
    assert_eq!(h.app.clipboard.last(), Some(target.as_str()));

    // ⏎ on it jumps to the NIC, and the filter stays behind.
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::Nics);
    assert_eq!(h.app.pending_jump, Some((target, true)));
    assert!(h.app.detail_search_query.is_empty());
}

#[tokio::test]
async fn esc_clears_the_filter_before_it_leaves_the_pane() {
    let mut h = Harness::new().await;
    vm_pane(&mut h, "Related").await;
    filter(&mut h, "vm-1-nic").await;
    h.press(KeyCode::Esc).await;
    assert!(h.app.details_focused, "the first Esc only clears the filter");
    assert!(h.app.detail_search_query.is_empty());
    h.press(KeyCode::Esc).await;
    assert!(!h.app.details_focused);

    // Esc while typing drops the query; leaving the pane drops an applied one.
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("zz").await;
    h.press(KeyCode::Esc).await;
    assert!(!h.app.detail_search_active && h.app.detail_search_query.is_empty());
    assert!(h.app.details_focused);
    filter(&mut h, "disk").await;
    h.press(KeyCode::Char('h')).await;
    assert!(!h.app.details_focused);
    assert!(h.app.detail_search_query.is_empty());
    assert_eq!(h.app.nav_cursor, None, "h is back to the list, never history");
}

/// `N` is the network access lens everywhere; only while a body filter is
/// on does it (with `n`) step the matches instead.
#[tokio::test]
async fn n_steps_matches_under_a_filter_and_n_is_the_lens_without_one() {
    let mut h = Harness::new().await;
    let subnet = all_mocks().into_iter().find(|m| m.label == "SubnetRow").unwrap();
    h.install(subnet).await;
    h.press(KeyCode::Enter).await;
    let tags = h.section_labels().iter().position(|l| *l == "Tags").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(tags).unwrap())).await;

    filter(&mut h, "e").await;
    let matches = h.app.detail_match_rows();
    assert!(!matches.is_empty(), "{:#?}", h.app.detail_body());
    h.press(KeyCode::Char('N')).await;
    assert!(h.app.network_lens.is_none(), "N under a filter steps matches");
    assert_eq!(h.app.details_scroll, *matches.last().unwrap());

    // No filter: `n` does nothing, `N` opens the lens.
    h.press(KeyCode::Esc).await;
    assert!(h.app.detail_search_query.is_empty() && h.app.details_focused);
    let at = h.app.details_scroll;
    h.press(KeyCode::Char('n')).await;
    assert_eq!(h.app.details_scroll, at);
    assert!(h.app.network_lens.is_none());
    h.press(KeyCode::Char('N')).await;
    assert!(h.app.network_lens.is_some(), "N with no filter is the lens");
}

#[tokio::test]
async fn ctrl_w_while_typing_deletes_a_word() {
    let mut h = Harness::new().await;
    vm_pane(&mut h, "Related").await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("os disk").await;
    h.press_key(ctrl('w')).await;
    assert_eq!(h.app.detail_search_query, "os ");
    assert!(!h.app.detail_wrap, "Ctrl-W while typing is not the wrap toggle");
}

/// ⌫ is history back in the pane, but while typing a filter it edits it.
#[tokio::test]
async fn backspace_while_typing_edits_the_filter_not_history() {
    let mut h = Harness::new().await;
    vm_pane(&mut h, "Related").await;
    h.app.jump_to_arm_id(&nic_id("vm-1-nic"), &h.tx);
    h.settle().await;
    h.land(vec![nic("vm-1-nic", "westeurope")]).await;
    assert!(h.app.details_focused && h.app.current_view == JumpView::Nics);

    h.press(KeyCode::Char('/')).await;
    h.type_str("abc").await;
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.detail_search_query, "ab");
    assert_eq!(h.app.current_view, JumpView::Nics, "no history step while typing");

    // With the filter kept, ⌫ goes back and leaves the filter behind.
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert!(h.app.detail_search_query.is_empty());
}

/// Flat view: a match keeps its `━━ Section ━━` header, digits find a
/// section by name in the narrowed body, the tab bar follows, and `n`/`N`
/// step through the matches, wrapping.
#[tokio::test]
async fn flat_filter_keeps_section_headers_and_n_steps_matches() {
    let mut h = Harness::new().await;
    vm_pane(&mut h, "Overview").await;
    h.press(KeyCode::Char('\\')).await;
    assert!(h.app.flat_active());
    filter(&mut h, "vm-1-os").await;

    let headers = flat_headers(&h);
    let labels = h.section_labels();
    assert!(headers.contains(&"Storage".to_string()) && headers.contains(&"Related".to_string()), "{headers:?}");
    assert!(headers.len() < labels.len(), "sections without a match drop out: {headers:?}");

    let matches = h.app.detail_match_rows();
    assert!(matches.len() >= 2, "{:#?}", h.app.detail_body());
    assert_eq!(h.app.details_scroll, matches[0]);
    h.press(KeyCode::Char('n')).await;
    assert_eq!(h.app.details_scroll, matches[1]);
    h.press(KeyCode::Char('N')).await;
    h.press(KeyCode::Char('N')).await;
    assert_eq!(h.app.details_scroll, *matches.last().unwrap(), "N wraps to the last match");

    // A digit lands on its section's header in the filtered body.
    let related = labels.iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    let row = h.app.details_scroll;
    assert_eq!(flat_header_name(&h.app.detail_body()[row].0), Some("Related"));
    assert_eq!(h.app.detail_section_idx, related, "the tab bar follows the cursor");

    // A section the filter emptied says so instead of landing elsewhere.
    let missing = labels.iter().position(|l| !headers.iter().any(|x| x == l)).unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(missing).unwrap())).await;
    assert_eq!(h.app.details_scroll, row);
    assert!(h.app.success_message.as_deref().is_some_and(|m| m.starts_with("No match in")));
}

/// A lazy section that lands after the filter was typed is filtered too.
#[tokio::test]
async fn the_filter_reapplies_when_a_lazy_section_lands() {
    let mut h = Harness::new().await;
    let vault = all_mocks().into_iter().find(|m| m.label == "VaultRow").unwrap();
    let id = vault.resource.id().to_string();
    h.install(vault).await;
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('\\')).await;
    filter(&mut h, "db-pass").await;
    assert!(h.app.detail_match_rows().is_empty(), "{:#?}", h.app.detail_body());
    assert!(h.render().contains("(0 matches)"));

    let secret = serde_json::json!({"name": "db-password", "properties": {"attributes": {"enabled": true}}});
    h.app.lazy.vault_secrets.apply(id, Ok(vec![secret]));
    h.settle().await;
    assert_eq!(h.app.detail_match_rows().len(), 1, "{:#?}", h.app.detail_body());
    assert_eq!(flat_headers(&h), ["Secrets"]);
    let screen = h.render();
    assert!(screen.contains("db-password") && screen.contains("(1 match)"), "{screen}");
    h.press(KeyCode::Char('n')).await;
    let row = h.app.details_scroll;
    assert_eq!(h.app.detail_body()[row].0, "db-password");
}

#[tokio::test]
async fn brackets_jump_between_group_headers() {
    let mut h = Harness::new().await;
    vm_pane(&mut h, "Overview").await;
    h.press(KeyCode::Char('\\')).await;
    let body = h.app.detail_body();
    let groups: Vec<usize> = body
        .iter()
        .enumerate()
        .filter(|(_, (k, v))| !k.is_empty() && v.is_empty() && !k.starts_with(' '))
        .map(|(i, _)| i)
        .collect();
    assert!(groups.len() > 2 && groups[0] == 0, "{body:#?}");

    h.type_str("]]").await;
    assert_eq!(h.app.details_scroll, groups[1]);
    h.type_str("]]").await;
    assert_eq!(h.app.details_scroll, groups[2]);
    h.type_str("[[").await;
    assert_eq!(h.app.details_scroll, groups[1]);

    // One bracket then another key: the chord is dropped, the key acts.
    h.type_str("]j").await;
    assert_eq!(h.app.details_scroll, groups[1] + 1);

    // Under `V` the jump extends the selection.
    h.press(KeyCode::Char('V')).await;
    h.type_str("]]").await;
    assert_eq!(h.app.detail_visual_range(), Some((groups[1] + 1, groups[2])));

    // Past the last header `]]` goes to the last line; `[[` from the top stays.
    h.press(KeyCode::Esc).await;
    h.press(KeyCode::Char('G')).await;
    h.type_str("]]").await;
    assert_eq!(h.app.details_scroll, body.len() - 1);
    h.press(KeyCode::Char('g')).await;
    h.type_str("[[").await;
    assert_eq!(h.app.details_scroll, 0);
}

#[tokio::test]
async fn ctrl_w_wraps_long_values_and_rows_stay_logical() {
    let mut h = Harness::sized(90, 30).await;
    vm_pane(&mut h, "Related").await;
    h.press(KeyCode::Char('Z')).await; // full-width pane: no list beside it
    let target = nic_id("vm-1-nic");
    h.cursor_to_value(&target).await;
    let row = h.app.details_scroll;
    assert!(!squashed(&h.render()).contains(&target), "clipped by default");

    h.press_key(ctrl('w')).await;
    assert!(h.app.detail_wrap);
    let screen = h.render();
    assert!(squashed(&screen).contains(&target), "the whole id on screen:\n{screen}");
    // Continuations hang under the value column.
    let lines: Vec<&str> = screen.lines().collect();
    let first = lines.iter().position(|l| l.contains("NIC (primary)")).unwrap();
    let value_col = lines[first].find(": ").unwrap() + 2;
    let cont = lines[first + 1];
    assert!(cont[..value_col].trim_matches(|c: char| c == ' ' || c == '│').is_empty(), "{screen}");

    // The cursor, `y` and `j` still mean logical rows.
    assert_eq!(h.app.details_scroll, row);
    h.press(KeyCode::Char('y')).await;
    assert_eq!(h.app.clipboard.last(), Some(target.as_str()));
    h.press(KeyCode::Char('j')).await;
    assert_eq!(h.app.details_scroll, row + 1);

    h.press_key(ctrl('w')).await;
    assert!(!h.app.detail_wrap);
    // From the list it reshapes the preview, and is not watch mode.
    h.press(KeyCode::Char('h')).await;
    h.press_key(ctrl('w')).await;
    assert!(h.app.detail_wrap && !h.app.watch.enabled);
}

#[tokio::test]
async fn h_and_l_step_sub_tabs_from_either_pane() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;

    // From the list: the next / previous sub-tab, the list keeps focus.
    h.press(KeyCode::Char('L')).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    h.land(vec![disk("disk-1", "westeurope")]).await;
    assert!(!h.app.details_focused);
    h.press(KeyCode::Char('H')).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);

    // From the pane: a cached tab opens its first row there at once…
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('3')).await;
    h.press(KeyCode::Char('L')).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    assert!(h.app.details_focused);
    assert_eq!(h.app.get_selected_resource().map(|r| r.name().to_string()).as_deref(), Some("disk-1"));
    assert_eq!(h.app.detail_section_idx, 0);

    // …a loading one when its first row lands.
    h.press(KeyCode::Char('L')).await;
    assert_eq!(h.app.current_view, JumpView::Nics);
    assert!(!h.app.details_focused && h.app.loading);
    h.land(vec![nic("vm-1-nic", "westeurope")]).await;
    assert!(h.app.details_focused);
    assert_eq!(h.selected_id(), Some(nic_id("vm-1-nic")));

    // Wrapping round to the first tab.
    h.press(KeyCode::Char('L')).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert!(h.app.details_focused);
    assert_eq!(h.selected_id(), Some(arm_id("Microsoft.Compute/virtualMachines/vm-1")));

    // A tab whose load ends empty leaves the list focused.
    let sub = h.app.subscription_key();
    h.app.cache.invalidate(&ServiceType::VirtualMachines, &sub, Some(JumpView::Disks.as_str()));
    h.press(KeyCode::Char('L')).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    h.land(vec![]).await;
    assert!(!h.app.details_focused);
    assert!(!h.app.pending_detail_focus);

    // A service without sub-tabs: H / L do nothing.
    let vault = all_mocks().into_iter().find(|m| m.label == "VaultRow").unwrap();
    assert_eq!(vault.view.service().views().len(), 1);
    h.install(vault).await;
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('L')).await;
    assert_eq!(h.app.current_view, JumpView::KeyVaults);
    assert!(h.app.details_focused);
}
