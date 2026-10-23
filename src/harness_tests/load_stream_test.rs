// ported from neboto-tui src/harness_tests/load_stream_test.rs @ ae78599
// (the stale-generation cases; nebaz's switch is a subscription, not a
// profile or region)
//! Streamed list loads (`Event::LoadStream`): pages accumulate, and a
//! superseded stream's events are dropped when *handled*, not only when
//! forwarded. While `handle_event` works through a switch, the old stream's
//! events can already be queued past the forwarder; without the check at
//! handling time they append the old rows to the new list, and a queued
//! `FullyLoaded` clears `loading` (dropping the new load's pages) and
//! caches the stale rows under the new key.

use super::mocks::{disk, vm};
use super::*;

fn page(service: ServiceType, resources: Vec<Box<dyn Resource>>) -> Event {
    Event::ResourcesPartiallyLoaded {
        service,
        resources,
        progress: LoadProgress {
            loaded_count: 1,
            total_count: None,
            status_message: None,
        },
    }
}

fn tagged(generation: u64, event: Event) -> Event {
    Event::LoadStream {
        generation,
        event: Box::new(event),
    }
}

fn cached(app: &App, view: JumpView, sub: &str) -> Option<usize> {
    app.cache.get(&view.service(), sub, Some(view.as_str())).map(|v| v.len())
}

#[tokio::test]
async fn streamed_pages_accumulate_and_the_end_caches_the_list() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    assert!(h.app.loading && h.app.loading_started, "the load is in flight");

    h.land_page(vec![vm("vm-1", "westeurope"), vm("vm-2", "westeurope")]).await;
    assert!(h.app.loading, "a page does not end the load");
    assert_eq!(h.visible_names(), ["vm-1", "vm-2"]);
    assert_eq!(h.app.selected_index, Some(0), "the first page selects a row");
    let screen = h.render();
    assert!(screen.contains("vm-2"), "{screen}");

    h.press(KeyCode::Char('j')).await;
    h.land_page(vec![vm("vm-3", "eastus")]).await;
    assert_eq!(h.visible_names(), ["vm-1", "vm-2", "vm-3"]);
    assert_eq!(h.selected_id().unwrap(), super::mocks::arm_id("Microsoft.Compute/virtualMachines/vm-2"), "a page keeps the selection");
    assert_eq!(cached(&h.app, JumpView::VirtualMachines, SUB_DEV), None, "nothing cached mid-stream");

    h.finish().await;
    assert!(!h.app.loading && h.app.loading_complete);
    assert_eq!(cached(&h.app, JumpView::VirtualMachines, SUB_DEV), Some(3));
    assert!(h.render().contains("vm-3"));
}

#[tokio::test]
async fn a_superseded_sub_tab_load_is_dropped() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    let stale = h.app.load_generation;

    // Tab to Disks: same service, a fresh load.
    h.press(KeyCode::Tab).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    let fresh = h.app.load_generation;
    assert!(fresh > stale, "the new load has a new generation");

    // The VM stream's queued events: same service, so only the generation
    // keeps them off the disk list.
    h.send(tagged(stale, page(ServiceType::VirtualMachines, vec![vm("vm-1", "westeurope")]))).await;
    h.send(tagged(
        stale,
        Event::ResourcesFullyLoaded {
            service: ServiceType::VirtualMachines,
            total_count: 1,
        },
    ))
    .await;
    assert!(h.app.resources.is_empty(), "a stale page must not land");
    assert!(h.app.loading, "a stale FullyLoaded must not end the fresh load");
    assert_eq!(cached(&h.app, JumpView::Disks, SUB_DEV), None, "nor stamp the cache");

    h.send(tagged(fresh, page(ServiceType::VirtualMachines, vec![disk("disk-1", "westeurope")]))).await;
    h.send(tagged(
        fresh,
        Event::ResourcesFullyLoaded {
            service: ServiceType::VirtualMachines,
            total_count: 1,
        },
    ))
    .await;
    assert_eq!(h.visible_names(), ["disk-1"]);
    assert!(!h.app.loading);
    assert_eq!(cached(&h.app, JumpView::Disks, SUB_DEV), Some(1));
}

/// A queued old-subscription stream must not land on the new
/// subscription's list, its error must not end the new load, and nothing
/// is cached under either subscription.
#[tokio::test]
async fn a_stale_subscription_stream_cannot_land_on_the_new_one() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    let stale = h.app.load_generation;

    h.send(Event::SubscriptionSwitchRequested {
        subscription_id: SUB_PROD.to_string(),
    })
    .await;
    assert_eq!(h.app.subscription_id.as_deref(), Some(SUB_PROD));
    assert!(h.app.loading && h.app.load_generation > stale);

    h.send(tagged(stale, page(ServiceType::VirtualMachines, vec![vm("dev-vm", "westeurope")]))).await;
    h.send(tagged(
        stale,
        Event::ResourceLoadError {
            service: ServiceType::VirtualMachines,
            error: "connection refused".into(),
            auth: None,
        },
    ))
    .await;
    h.send(tagged(
        stale,
        Event::ResourcesFullyLoaded {
            service: ServiceType::VirtualMachines,
            total_count: 1,
        },
    ))
    .await;
    assert!(h.app.resources.is_empty());
    assert!(h.app.loading);
    assert!(h.app.error_message.is_none(), "{:?}", h.app.error_message);
    assert_eq!(cached(&h.app, JumpView::VirtualMachines, SUB_PROD), None);
    assert_eq!(cached(&h.app, JumpView::VirtualMachines, SUB_DEV), None);

    h.land(vec![vm("prod-vm", "westeurope")]).await;
    assert_eq!(h.visible_names(), ["prod-vm"]);
    assert_eq!(cached(&h.app, JumpView::VirtualMachines, SUB_PROD), Some(1));
}

/// A provider that sends without the forwarder (untagged) is current.
#[tokio::test]
async fn untagged_stream_events_take_the_plain_path() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.send(page(ServiceType::VirtualMachines, vec![vm("vm-1", "westeurope")])).await;
    assert_eq!(h.visible_names(), ["vm-1"]);
}
