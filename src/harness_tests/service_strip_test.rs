//! The service strip's chips and badges.

use super::*;

/// The strip line of a frame (the banner off, so it starts with `nebaz`).
fn strip(h: &mut Harness) -> String {
    h.app.banner_visible = false;
    h.render().lines().find(|l| l.contains("nebaz")).unwrap_or_default().to_string()
}

async fn four_services(width: u16) -> Harness {
    let mut h = Harness::sized(width, 30).await;
    h.open(JumpView::ContainerApps).await;
    h.open(JumpView::ChangesAll).await;
    h.open(JumpView::Subnets).await;
    h.app.switch_service(ServiceType::Audit);
    h.settle().await;
    h
}

/// The hint badge goes before any chip hides: a strip that fits every chip
/// without it shows them all, with no `‹` (the hero once read
/// `nebaz │ ‹ Audit` beside a full hint).
#[tokio::test]
async fn the_hint_goes_before_a_chip_hides() {
    let mut h = four_services(140).await;
    let line = strip(&mut h);
    for chip in ["VNet", "ACA", "Changes", "Audit", "S: services"] {
        assert!(line.contains(chip), "{chip:?} missing: {line}");
    }

    // (117: 110 before the `← →` took 7 columns.)
    let mut h = four_services(117).await;
    let line = strip(&mut h);
    for chip in ["VNet", "ACA", "Changes", "Audit", "Dev ("] {
        assert!(line.contains(chip), "{chip:?} missing: {line}");
    }
    assert!(!line.contains('‹') && !line.contains('›'), "nothing is hidden: {line}");
    assert!(!line.contains("S: services"), "the hint made room: {line}");

    // Narrower: the chips scroll, the active one stays, and a marker shows
    // only on the side that hides a chip.
    let mut h = four_services(95).await;
    let line = strip(&mut h);
    assert!(line.contains('‹') && line.contains("Audit") && !line.contains('›'), "{line}");
}
