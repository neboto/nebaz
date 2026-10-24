//! The update check (#53, ADR 0008) on the real App: turned off, it reads
//! no state and spawns nothing; a newer release shows as the strip's dim
//! chip and the splash's tip line. The harness never spawns the real
//! check (only `main` does), so nothing here reaches the network.

use super::mocks::vm;
use super::*;

#[tokio::test]
async fn disabled_spawns_nothing_and_shows_nothing() {
    let mut h = Harness::new().await;
    h.app.update_check_enabled = false;
    let tx = h.tx.clone();
    assert!(!h.app.spawn_update_check(&tx), "update_check = false: no fetch");
    assert_eq!(h.app.update_available, None, "and no cached announcement either");
    assert!(!h.render().contains('↑'));
}

#[tokio::test]
async fn a_newer_release_shows_on_the_splash_and_the_strip() {
    let mut h = Harness::new().await;
    h.send(Event::UpdateAvailable("9.9.9".into())).await;
    let splash = h.render();
    assert!(splash.contains("nebaz v9.9.9 is out"), "{splash}");
    assert!(splash.contains("install.sh | sh"), "the splash names the upgrade command\n{splash}");

    h.app.current_location = Location::All;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-a", "westeurope")]).await;
    let screen = h.render();
    let strip = screen.lines().find(|l| l.contains('⦿')).expect("the service strip's subscription badge");
    assert!(strip.contains("↑ v9.9.9"), "{screen}");
}
