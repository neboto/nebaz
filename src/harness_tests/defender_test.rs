//! The Defender tab (#156, ADR 0010): a secure score control's
//! Recommendations load the cold Recommendations list for the section,
//! show the unhealthy ones it is made of, and jump to them.

use super::mocks::all_mocks;
use super::*;
use crate::azure::services::defender::{RecommendationRow, ScoreControlRow};
use crate::lazy::Lazy;

fn mock(label: &str) -> super::mocks::Mock {
    all_mocks().into_iter().find(|m| m.label == label).expect("a mock")
}

#[tokio::test]
async fn a_control_loads_the_recommendations_and_jumps_to_one() {
    let mut h = Harness::new().await;
    let mut control = mock("ScoreControlRow");
    {
        let mut c = control.resource.as_any().downcast_ref::<ScoreControlRow>().unwrap().clone();
        c.assessment_keys = vec!["a-1".into()];
        control.resource = Box::new(c);
    }
    h.install(control).await;
    let sub = h.app.subscription_key();
    h.press(KeyCode::Enter).await;
    let idx = h.section_labels().iter().position(|l| *l == "Recommendations").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    let key = format!("{sub}|defender-recommendations");
    assert!(matches!(h.app.lazy.section_lists.get(&key), Some(Lazy::Loading)), "the list read fired");
    assert!(h.app.get_detail_lines().iter().any(|(_, v)| v == "Loading…"));

    let rec = mock("RecommendationRow");
    let id = rec.resource.id().to_string();
    assert!(rec.resource.as_any().downcast_ref::<RecommendationRow>().unwrap().is_unhealthy());
    let rows: Vec<Box<dyn Resource>> = vec![rec.resource];
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| app.lazy.section_lists.apply(key, Ok(rows)));
    let epoch = h.app.lazy.epoch();
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(l, v)| l.starts_with("Management ports") && *v == id), "{lines:#?}");

    h.cursor_to_value(&id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Defender));
    assert_eq!(h.app.current_view, JumpView::DefenderRecommendations);
}
