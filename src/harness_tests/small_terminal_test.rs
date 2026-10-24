//! Small terminals (#103): every screen draws inside the frame, whatever
//! its size, instead of panicking on an out-of-bounds buffer write.

use super::*;

/// The sizes the issue names plus a couple of narrower ones.
const SIZES: [(u16, u16); 6] = [(80, 20), (80, 10), (40, 10), (40, 8), (20, 5), (1, 1)];

#[tokio::test]
async fn splash_renders_at_small_sizes() {
    for (w, h) in SIZES {
        let mut harness = Harness::sized(w, h).await;
        assert!(harness.app.current_service.is_none(), "{w}x{h}: on the splash");
        harness.render();
    }
}

#[tokio::test]
async fn splash_keeps_the_menu_when_the_logo_does_not_fit() {
    let mut h = Harness::sized(80, 14).await;
    let screen = h.render();
    assert!(screen.contains("Open the service picker"), "{screen}");
}

/// Each modal and in-pane view opened by its key, drawn, then closed.
const OVERLAY_KEYS: [char; 13] = ['?', 'S', 'R', 'P', '`', '\'', 'M', ',', 'C', 'm', 'N', 'U', 'W'];

async fn open_each_overlay(h: &mut Harness) {
    for c in OVERLAY_KEYS {
        h.press(KeyCode::Char(c)).await;
        h.render();
        h.press(KeyCode::Esc).await;
        h.press(KeyCode::Esc).await;
    }
}

#[tokio::test]
async fn main_screen_and_overlays_render_at_small_sizes() {
    for (w, hgt) in [(40, 10), (20, 5), (1, 1)] {
        // The splash's own overlays first, then a loaded list.
        let mut h = Harness::sized(w, hgt).await;
        open_each_overlay(&mut h).await;
        for (view, resource) in [
            (JumpView::VirtualMachines, mocks::vm("vm-1", "westeurope")),
            (JumpView::VirtualNetworks, mocks::vnet("vnet-1", "westeurope")),
        ] {
            h.install(mocks::Mock { view, label: "small", resource }).await;
            h.render();
            open_each_overlay(&mut h).await;
            // The detail pane, split and flat.
            h.press(KeyCode::Enter).await;
            h.render();
            open_each_overlay(&mut h).await;
            h.press(KeyCode::Char('\\')).await;
            h.render();
            h.press(KeyCode::Char('\\')).await;
            h.press(KeyCode::Esc).await;
        }
    }
}
