//! The info card (`i`): it opens over a sub-tab that has one, draws the
//! card, copies a numbered link, and closes on `Esc`; a sub-tab without a
//! card says so.

use super::mocks::vnet;
use super::*;

#[tokio::test]
async fn i_opens_the_vnet_card_copies_a_link_and_esc_closes_it() {
    let mut h = Harness::sized(120, 40).await;
    h.open(JumpView::VirtualNetworks).await;
    h.land(vec![vnet("vnet-hub", "westeurope")]).await;
    assert!(h.app.supports_info_card());

    h.press(KeyCode::Char('i')).await;
    assert!(h.app.info_card.is_some());
    let screen = h.render();
    assert!(screen.contains("About · VNets"), "{screen}");
    assert!(screen.contains("Azure Virtual Network"));

    h.press(KeyCode::Char('2')).await;
    let toast = h.app.success_message.clone().unwrap_or_default();
    assert!(toast.starts_with("Copied the link"), "{toast}");
    assert!(h.app.info_card.is_some(), "copying keeps the card open");

    h.press(KeyCode::Esc).await;
    assert!(h.app.info_card.is_none());

    // From the detail pane too.
    h.press(KeyCode::Enter).await;
    assert!(h.app.details_focused);
    h.press(KeyCode::Char('i')).await;
    assert!(h.app.info_card.is_some(), "i works with the detail pane focused");
}

#[tokio::test]
async fn a_sub_tab_without_a_card_says_so() {
    let mut h = Harness::new().await;
    h.open(JumpView::Disks).await;
    assert!(!h.app.supports_info_card());
    h.press(KeyCode::Char('i')).await;
    assert!(h.app.info_card.is_none());
    assert_eq!(h.app.success_message.as_deref(), Some("No info card for Disks yet"));
}

