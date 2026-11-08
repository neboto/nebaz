//! `|` splits out (neboto #326 / #328): another nebaz in a pane beside this
//! one, started at the same place with `--at`. The launchers never run
//! under test: `crate::split` records them.

use super::mocks::vm;
use super::*;
use crate::azure::metrics::MetricWindow;
use crate::split::{Host, Place};

/// The `--at` value out of a launched shell command.
fn place_in(cmd: &str) -> Place {
    let at = cmd.split_whitespace().skip_while(|w| *w != "--at").nth(1).expect("--at in the command");
    crate::split::decode_place(at.trim_end_matches(';')).unwrap()
}

/// VMs with two rows, the second selected.
async fn vms() -> Harness {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope"), vm("vm-2", "westeurope")]).await;
    h.press(KeyCode::Char('j')).await;
    h
}

/// Press `|` in tmux and hand back the one launch's shell command.
async fn split_in_tmux(h: &mut Harness) -> String {
    crate::split::set_test_host(Some(Host::Tmux));
    h.press(KeyCode::Char('|')).await;
    crate::split::set_test_host(None);
    let launched = crate::split::take_launched();
    assert_eq!(launched.len(), 1, "{:?}", h.app.error_message);
    let (prog, args) = &launched[0];
    assert_eq!(prog, "tmux");
    assert_eq!(&args[..2], ["split-window", "-h"]);
    args.last().unwrap().clone()
}

/// The new pane: a fresh app given `place`, its list landing after the
/// restore (nothing is cached in a new process).
async fn new_pane_at(place: Place) -> Harness {
    let mut h = Harness::new().await;
    h.app.startup_place = Some(place);
    h.app.restore_startup_location(&h.tx);
    h.settle().await;
    h.land(vec![vm("vm-1", "westeurope"), vm("vm-2", "westeurope")]).await;
    h
}

#[tokio::test]
async fn bar_splits_a_tmux_pane_at_this_section_and_the_new_pane_lands_there() {
    let mut h = vms().await;
    let id = h.selected_id().unwrap();
    h.press(KeyCode::Enter).await;
    let tags = h.section_labels().iter().position(|l| *l == "Tags").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(tags).unwrap())).await;

    let cmd = split_in_tmux(&mut h).await;
    assert!(cmd.contains(" -s @vm "), "{cmd}");
    assert!(cmd.contains(&format!(" -p {} ", h.app.subscription_id.clone().unwrap())), "{cmd}");
    assert!(cmd.contains(" -r all "), "{cmd}");
    assert!(cmd.contains("[exited with status"), "a failed start stays readable: {cmd}");
    assert!(h.app.success_message.as_deref().is_some_and(|m| m.contains("tmux pane")), "{:?}", h.app.success_message);

    let place = place_in(&cmd);
    assert_eq!(place.loc.selected_id.as_deref(), Some(id.as_str()));
    assert!(place.loc.details_focused);
    assert_eq!(place.chart_window, None);

    // The section survives the pending jump a new process always takes.
    let other = new_pane_at(place).await;
    assert_eq!(other.selected_id(), Some(id));
    assert!(other.app.details_focused);
    assert_eq!(other.app.detail_section_idx, tags);
}

#[tokio::test]
async fn with_nothing_to_split_the_command_is_copied() {
    let mut h = vms().await;
    crate::split::set_test_host(None);
    h.press(KeyCode::Char('|')).await;
    assert!(crate::split::take_launched().is_empty());
    let copied = h.app.clipboard.last().expect("the command is copied").to_string();
    assert!(copied.contains("--at "), "{copied}");
    assert!(place_in(&copied).loc.selected_id.is_some());
}

#[tokio::test]
async fn bar_from_the_charts_reopens_them_at_their_window() {
    let mut h = vms().await;
    h.press(KeyCode::Char('m')).await;
    h.press(KeyCode::Char(']')).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().window, MetricWindow::SixHours);

    let place = place_in(&split_in_tmux(&mut h).await);
    assert_eq!(place.chart_window, Some(MetricWindow::SixHours));
    assert!(h.app.metrics.is_some(), "this pane's charts stay open");

    let other = new_pane_at(place).await;
    assert_eq!(other.selected_id(), h.selected_id());
    let st = other.app.metrics.as_ref().expect("the charts reopen");
    assert_eq!(st.window, MetricWindow::SixHours);
}

#[tokio::test]
async fn bar_while_searching_is_a_character() {
    let mut h = vms().await;
    h.press(KeyCode::Char('/')).await;
    crate::split::set_test_host(Some(Host::Tmux));
    h.press(KeyCode::Char('|')).await;
    crate::split::set_test_host(None);
    assert!(crate::split::take_launched().is_empty());
    assert_eq!(h.app.search_query, "|");
}

#[tokio::test]
async fn kitty_without_remote_control_opens_a_window_and_says_why() {
    let mut h = vms().await;
    crate::split::set_test_host(Some(Host::Kitty));
    crate::split::set_test_failing(&["kitten"]);
    h.press(KeyCode::Char('|')).await;
    crate::split::set_test_failing(&[]);
    crate::split::set_test_host(None);
    let progs: Vec<String> = crate::split::take_launched().into_iter().map(|(p, _)| p).collect();
    assert_eq!(progs, ["kitten", "kitty"]);
    let msg = h.app.success_message.clone().unwrap_or_default();
    assert!(msg.starts_with("Split out into a new kitty window") && msg.contains("no split: kitten"), "{msg}");
}

#[tokio::test]
async fn when_every_launch_fails_the_reason_shows_and_the_command_is_copied() {
    let mut h = vms().await;
    crate::split::set_test_host(Some(Host::Ghostty));
    crate::split::set_test_failing(&["osascript", "ghostty"]);
    h.press(KeyCode::Char('|')).await;
    crate::split::set_test_failing(&[]);
    crate::split::set_test_host(None);
    assert!(!crate::split::take_launched().is_empty());
    let err = h.app.error_message.clone().unwrap_or_default();
    assert!(err.starts_with("Can't split:") && err.contains("copied"), "{err}");
    assert!(h.app.clipboard.last().is_some_and(|c| c.contains("--at ")));
}

#[tokio::test]
async fn split_command_beats_the_detected_terminal() {
    let mut h = vms().await;
    h.app.split_command = Some("my-term --right -- {cmd}".into());
    crate::split::set_test_host(Some(Host::Tmux));
    h.press(KeyCode::Char('|')).await;
    crate::split::set_test_host(None);
    let launched = crate::split::take_launched();
    assert_eq!(launched.len(), 1);
    assert_eq!(launched[0].0, "sh");
    assert!(launched[0].1[1].starts_with("my-term --right -- '"), "{:?}", launched[0].1);
    assert!(place_in(&launched[0].1[1]).loc.selected_id.is_some());
}
