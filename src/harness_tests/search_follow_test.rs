//! A `/` search that finds nothing on the current sub-tab follows the
//! matches to the first warm tab that has some, comes back when the starting
//! tab matches again (or on `Esc`), and the tabs with no matches are dimmed
//! (#154, neboto-tui#301). Cold tabs are neither followed nor dimmed.

use super::mocks::{disk, vm};
use super::*;

/// VMs (`web-vm`) and Disks (`payments-disk`) warm, NICs and scale sets cold,
/// on the VMs tab.
async fn warm() -> Harness {
    let mut h = Harness::new().await;
    h.open(JumpView::Disks).await;
    h.land(vec![disk("payments-disk", "westeurope")]).await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("web-vm", "westeurope")]).await;
    h
}

#[tokio::test]
async fn typing_follows_the_matches_and_the_starting_tab_wins_again() {
    let mut h = warm().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("payments").await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    assert_eq!(h.visible_names(), ["payments-disk"]);
    assert_eq!(h.app.sub_tab_match_counts, [Some(0), Some(1), None, None], "NICs and scale sets are cold");
    assert!(!h.app.loading, "following is served from the cache");
    assert!(h.app.search_active && h.app.search_query == "payments");

    // Edit the query so the starting tab matches again: back to it.
    for _ in 0..8 {
        h.press(KeyCode::Backspace).await;
    }
    assert_eq!(h.app.current_view, JumpView::VirtualMachines, "an empty query is home");
    h.type_str("web").await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert_eq!(h.app.sub_tab_match_counts[..2], [Some(1), Some(0)]);
}

#[tokio::test]
async fn the_starting_tab_wins_while_it_has_matches() {
    let mut h = warm().await;
    h.open(JumpView::Disks).await;
    h.press(KeyCode::Char('/')).await;
    // `-` is in both names.
    h.type_str("-").await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    assert_eq!(h.app.sub_tab_match_counts[..2], [Some(1), Some(1)]);
}

#[tokio::test]
async fn a_cold_tab_is_not_followed_and_nothing_is_fetched() {
    let mut h = warm().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("zzz-nowhere").await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines, "no warm tab matches: stay");
    assert!(!h.app.loading);
    assert_eq!(h.app.sub_tab_match_counts[2], None);
}

#[tokio::test]
async fn esc_returns_to_the_starting_tab_and_enter_keeps_the_found_one() {
    let mut h = warm().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("payments").await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    h.press(KeyCode::Esc).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert!(h.app.sub_tab_match_counts.is_empty());
    assert_eq!(h.app.search_query, "");
    assert_eq!(h.visible_names(), ["web-vm"], "the starting tab, unfiltered");

    h.press(KeyCode::Char('/')).await;
    h.type_str("payments").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::Disks, "⏎ keeps the tab it found");
    assert_eq!(h.visible_names(), ["payments-disk"]);
    assert_eq!(h.app.sub_tab_match_counts[0], Some(0), "still dimmed while the query filters");

    // A tab picked by hand afterwards is left alone.
    h.press(KeyCode::Char('1')).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert_eq!(h.visible_names(), ["web-vm"]);
    assert!(h.app.sub_tab_match_counts.is_empty());
}

#[tokio::test]
async fn an_f_state_filter_holds_the_tab_still() {
    let mut h = warm().await;
    h.app.list_state_filter = Some("running".into());
    h.press(KeyCode::Char('/')).await;
    h.type_str("payments").await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert_eq!(h.app.sub_tab_match_counts[1], Some(1), "still counted, so the chip says where");
}

#[tokio::test]
async fn the_location_filter_is_respected_in_the_counts() {
    let mut h = warm().await;
    h.app.current_location = Location::Named("eastus".into());
    h.press(KeyCode::Char('/')).await;
    h.type_str("payments").await;
    assert_eq!(h.app.sub_tab_match_counts[..2], [Some(0), Some(0)]);
    assert_eq!(h.app.current_view, JumpView::VirtualMachines, "nothing matches in eastus: stay");
}

#[tokio::test]
async fn a_service_prefix_or_all_search_never_follows() {
    let mut h = warm().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("@vm payments").await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    h.press(KeyCode::Esc).await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("@* payments").await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert!(h.app.sub_tab_match_counts.is_empty());
}

#[tokio::test]
async fn tabs_with_no_matches_are_dimmed_and_cold_ones_are_not() {
    let mut h = warm().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("payments").await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    let screen = h.render();
    let (vx, vy) = h.find("1 VMs");
    let (nx, ny) = h.find("3 NICs");
    let dim = crate::ui::theme::text_dim();
    let buf = h.terminal.backend().buffer().clone();
    assert_eq!(buf[(vx + 2, vy)].fg, dim, "no matches on VMs:\n{screen}");
    assert_ne!(buf[(nx + 2, ny)].fg, dim, "a cold tab reads as an ordinary one");
    // No counts added to the labels.
    assert!(screen.contains("1 VMs  │ 2 Disks  │ 3 NICs"), "{screen}");
}
