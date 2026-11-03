// ported from neboto-tui src/harness_tests/status_bar_hints_test.rs @ 77daacc (rewritten on the nebaz harness)
//! The status bar's key hints (#149): `:` / `?` / `q` are pinned and never
//! trimmed; the rest yield from the end on a narrow bar. `j/k`, `H/L` and
//! `'` bookmarks are not on the bar (still in `?` and `:`).

use super::mocks::vm;
use super::*;

async fn vm_harness(width: u16) -> Harness {
    let mut h = Harness::sized(width, 30).await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h
}

/// The status bar: the screen's last row.
fn bar(h: &mut Harness) -> String {
    h.render().lines().last().unwrap().to_string()
}

#[tokio::test]
async fn help_and_commands_survive_a_narrow_bar() {
    for width in [100u16, 140, 220] {
        let mut h = vm_harness(width).await;
        let line = bar(&mut h);
        println!("list {width}: {line}");
        assert!(line.contains(": commands  ·  ? help  ·  q quit"), "{width}: {line}");
        assert!(line.contains("/ search  ·  ⏎ details"), "{width}: {line}");
        assert!(!line.contains("j/k") && !line.contains("H/L") && !line.contains("bookmarks"), "{line}");
    }
    // The selection's own keys come before the every-row ones: at 100
    // columns the first gated hint shows and `y copy id` gives way.
    let mut h = vm_harness(100).await;
    let narrow = bar(&mut h);
    assert!(narrow.contains("N access") && !narrow.contains("copy id"), "{narrow}");
    let mut h = vm_harness(220).await;
    let wide = bar(&mut h);
    assert!(wide.contains("m metrics") && wide.contains("W changes") && wide.contains("y copy id"), "{wide}");
    assert!(wide.contains("U refs") && wide.contains("C copy cmd"), "{wide}");

    for width in [70u16, 100, 140] {
        let mut h = vm_harness(width).await;
        h.app.details_focused = true;
        let line = bar(&mut h);
        println!("detail {width}: {line}");
        assert!(line.contains(": commands  ·  ? help"), "{width}: {line}");
        assert!(line.trim_start().starts_with("m metrics"), "{width}: {line}");
        assert!(!line.contains("q quit") && !line.contains("j/k"), "{line}");
    }
}

#[tokio::test]
async fn the_bar_is_the_tables_gates_and_nothing_else() {
    // A gated key's hint on the bar is exactly its row's gate: change the
    // selection and the hints follow.
    let mut h = vm_harness(220).await;
    let hints = crate::commands::status_hints(&h.app, false);
    let line = bar(&mut h);
    for (key, label) in hints {
        assert!(line.contains(&format!("{key} {label}")), "{key} {label} missing: {line}");
    }
    // @changes shows its window keys, a VM list does not.
    assert!(!line.contains("[/] window"));
    h.open(JumpView::ChangesAll).await;
    h.land(vec![]).await;
    h.finish().await;
    let line = bar(&mut h);
    assert!(line.contains("[/] window"), "{line}");
}

#[tokio::test]
async fn clicking_the_commands_hint_opens_the_picker() {
    let mut h = vm_harness(140).await;
    let line = bar(&mut h);
    let col = line.find(": commands").map(|b| line[..b].chars().count()).unwrap() as u16;
    h.click((col, 29)).await;
    assert!(h.app.key_picker.visible);
}
