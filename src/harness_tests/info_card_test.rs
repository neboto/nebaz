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

    // y copies the block under the cursor; V and j select a range.
    h.press(KeyCode::Char('j')).await;
    h.press(KeyCode::Char('y')).await;
    assert!(h.app.success_message.as_deref().unwrap_or_default().starts_with("Copied the line"));
    h.press(KeyCode::Char('V')).await;
    h.press(KeyCode::Char('j')).await;
    h.press(KeyCode::Char('j')).await;
    assert_eq!(h.app.info_card.as_ref().unwrap().range(), (1, 3));
    h.press(KeyCode::Char('y')).await;
    assert!(h.app.success_message.as_deref().unwrap_or_default().starts_with("Copied the selection"));
    assert_eq!(h.app.info_card.as_ref().unwrap().anchor, None, "copying ends the selection");
    h.press_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL)).await;
    h.press(KeyCode::Char('y')).await;
    assert!(h.app.success_message.as_deref().unwrap_or_default().starts_with("Copied the card"));

    // Esc ends a selection first, then closes.
    h.press(KeyCode::Char('V')).await;
    h.press(KeyCode::Esc).await;
    assert!(h.app.info_card.is_some());
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
    // Any sub-tab still without one; once every sub-tab has a card there is nothing to test.
    let Some(view) = ServiceType::all().iter().flat_map(|s| s.views()).copied().find(|v| crate::cards::for_view(*v).is_none())
    else {
        return;
    };
    let mut h = Harness::new().await;
    h.open(view).await;
    assert!(!h.app.supports_info_card());
    h.press(KeyCode::Char('i')).await;
    assert!(h.app.info_card.is_none());
    assert_eq!(h.app.success_message.as_deref(), Some(format!("No info card for {} yet", view.label()).as_str()));
}


#[tokio::test]
async fn the_cursor_scrolls_the_card_and_is_drawn_on_the_selection_bar() {
    let mut h = Harness::sized(100, 24).await;
    h.open(JumpView::VirtualNetworks).await;
    h.land(vec![vnet("vnet-hub", "westeurope")]).await;
    h.press(KeyCode::Char('i')).await;
    h.render();
    h.press(KeyCode::End).await;
    let screen = h.render();
    assert!(h.app.info_card.as_ref().unwrap().scroll.get() > 0, "End scrolled to the last link");
    assert!(screen.contains("5 Limits"), "{screen}");
    let bar = crate::ui::theme::selection_style(true).bg;
    let (x, y) = h.find("5 Limits");
    assert_eq!(h.terminal.backend().buffer()[(x, y)].bg, bar.unwrap(), "the cursor's block is on the selection bar");
    let (x, y) = h.find("4 Peering");
    assert_ne!(Some(h.terminal.backend().buffer()[(x, y)].bg), bar, "the block above is not");
}


#[tokio::test]
async fn o_opens_the_link_under_the_cursor_and_over_ssh_copies_it() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualNetworks).await;
    h.land(vec![vnet("vnet-hub", "westeurope")]).await;
    h.press(KeyCode::Char('i')).await;
    h.press(KeyCode::Char('o')).await;
    assert_eq!(h.app.success_message.as_deref(), Some("Move to a link to open it (1–9 copy one)"));
    assert_eq!(h.app.browser.last(), None);

    h.press(KeyCode::End).await;
    h.press(KeyCode::Char('o')).await;
    let limits = "https://learn.microsoft.com/azure/azure-resource-manager/management/azure-subscription-service-limits";
    assert_eq!(h.app.browser.last(), Some(limits));
    assert_eq!(h.app.success_message.as_deref(), Some("Opened “Limits” in the browser"));

    h.app.remote_session = true;
    h.press(KeyCode::Up).await;
    h.press(KeyCode::Char('o')).await;
    assert_eq!(h.app.browser.last(), Some(limits), "nothing opened over SSH");
    assert!(h.app.success_message.as_deref().unwrap_or_default().contains("SSH session: no browser here"));
}

#[tokio::test]
async fn shift_o_opens_the_portal_page() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualNetworks).await;
    h.land(vec![vnet("vnet-hub", "westeurope")]).await;
    h.press_key(KeyEvent::new(KeyCode::Char('O'), KeyModifiers::SHIFT)).await;
    let url = h.app.browser.last().unwrap_or_default().to_string();
    assert!(url.starts_with("https://portal.azure.com/#@"), "{url}");
    assert!(url.ends_with("/virtualNetworks/vnet-hub"), "{url}");
    assert_eq!(h.app.success_message.as_deref(), Some("Opened the portal in the browser"));
}
