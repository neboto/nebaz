//! The WAF metrics view (#153; neboto-tui#294 / #296 / #297): `m` on an
//! Application Gateway with WAF, a Front Door profile, or a WAF policy
//! opens the actions chart, the block rate and the rule tables; `⏎` on a
//! rule charts it, `d` goes back, then to the default set, `w` returns,
//! and a policy opens the resource it is attached to with its name pinned.
//! The harness never lets a fetch land: the answers go through the
//! apply-closure event the real task sends, built here by running the real
//! `fetch_waf` over canned bodies.

use super::mocks::{all_mocks, arm_id};
use super::*;
use crate::azure::metrics::{parse_iso_utc, MetricWindow};
use crate::azure::services::edge::WafPolicyRow;
use crate::azure::waf_metrics::{fetch_waf, WafProduct};
use crate::lazy::LazyApply;
use crate::ui::theme;
use serde_json::{json, Value};

const END: &str = "2026-10-23T12:00:00Z";

fn series(dims: &[(&str, &str)], pts: &[f64]) -> Value {
    json!({
        "metadatavalues": dims.iter().map(|(k, v)| json!({"name": {"value": k}, "value": v})).collect::<Vec<_>>(),
        "data": pts.iter().enumerate().map(|(i, v)| json!({"timeStamp": format!("2026-10-23T11:{:02}:00Z", 10 + i * 10), "total": v})).collect::<Vec<_>>()
    })
}

fn body(metric: &str, ts: Vec<Value>) -> Value {
    json!({"value": [{"name": {"value": metric}, "unit": "Count", "errorCode": "Success", "timeseries": ts}]})
}

/// What Azure Monitor would answer a gateway, by the metric asked for.
fn answer(metric: &str) -> std::result::Result<Value, String> {
    Ok(match metric {
        "AzwafTotalRequests" => body(
            metric,
            vec![
                series(&[("action", "Allowed")], &[90.0, 80.0, 100.0]),
                series(&[("action", "Blocked")], &[10.0, 20.0, 0.0]),
                series(&[("action", "Detected")], &[50.0, 50.0, 50.0]),
            ],
        ),
        "AzwafSecRule" => body(
            metric,
            vec![
                series(&[("action", "Blocked"), ("ruleid", "942100"), ("rulegroupid", "REQUEST-942-SQLI"), ("rulesetname", "DRS_2.1")], &[10.0, 20.0, 0.0]),
                series(&[("action", "Detected"), ("ruleid", "941100"), ("rulegroupid", "REQUEST-941-XSS"), ("rulesetname", "DRS_2.1")], &[5.0, 5.0, 5.0]),
            ],
        ),
        "AzwafCustomRule" => body(metric, vec![series(&[("action", "Allowed"), ("customruleid", "AllowCorpProbes")], &[3.0, 3.0, 3.0])]),
        _ => return Err("400 BadRequest: metric not found".into()),
    })
}

/// Land the WAF view's data as the task would, for the open view.
async fn land_waf(h: &mut Harness) {
    let (product, policy, window) = {
        let st = h.app.metrics.as_ref().expect("the view is open");
        let w = st.waf.as_ref().expect("a WAF view");
        (w.product, w.policy.clone(), st.window)
    };
    let end = parse_iso_utc(END).unwrap();
    let fetch = |q: Vec<(&'static str, String)>| {
        let metric = q.iter().find(|(k, _)| *k == "metricnames").map(|(_, v)| v.clone()).unwrap_or_default();
        async move { answer(&metric) }
    };
    let data = fetch_waf(product, policy.as_deref(), window, end, fetch).await;
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        app.metrics.as_mut().expect("the view is open").set_waf(data);
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
}

async fn gateway(width: u16, height: u16) -> Harness {
    let mut h = Harness::sized(width, height).await;
    let mock = all_mocks().into_iter().find(|m| m.view == JumpView::AppGateways).expect("a gateway mock");
    h.install(mock).await;
    h.press(KeyCode::Char('m')).await;
    land_waf(&mut h).await;
    h
}

fn agw_id() -> String {
    arm_id("Microsoft.Network/applicationGateways/agw-1")
}

#[tokio::test]
async fn m_on_a_gateway_with_a_waf_opens_the_waf_view_with_actions_block_rate_and_tables() {
    let mut h = Harness::sized(170, 50).await;
    let mock = all_mocks().into_iter().find(|m| m.view == JumpView::AppGateways).unwrap();
    h.install(mock).await;
    h.press(KeyCode::Char('m')).await;
    let st = h.app.metrics.as_ref().expect("m opens the view");
    assert!(st.waf_on && st.loading, "the WAF view, fetching");
    assert_eq!(st.resource_id, agw_id());
    assert_eq!(st.waf.as_ref().unwrap().policy, None, "a gateway's own view is not pinned to a policy");
    assert_eq!(st.waf.as_ref().unwrap().product, WafProduct::AppGateway);

    land_waf(&mut h).await;
    let screen = h.render();
    for s in ["WAF view", "Allowed", "Blocked", "Detected", "Block rate", "Managed rules", "Custom rules", "942100", "AllowCorpProbes", "REQUEST-942-SQLI"] {
        assert!(screen.contains(s), "{s:?} missing:\n{screen}");
    }
    assert!(!screen.contains("Bot protection"), "a missing bot metric is not shown:\n{screen}");
    // 30 blocked of the 300 that ended (the 150 detected are left out).
    assert!(screen.contains("10.0% of what ended"), "{screen}");
    // Colours that mean something.
    assert!(h.has_fg(theme::error()) && h.has_fg(theme::success()) && h.has_fg(theme::warning()));
}

#[tokio::test]
async fn the_tables_sit_beside_the_chart_when_wide_and_under_it_when_narrow() {
    let mut wide = gateway(170, 50).await;
    wide.press(KeyCode::Char('Z')).await; // full width: the pane is half the terminal otherwise
    let chart = wide.find("App Gateway by action");
    let table = wide.find("Managed rules");
    assert!(table.0 > chart.0 + 40, "beside: the table starts right of the chart title {chart:?} {table:?}");
    assert!(table.1 <= chart.1 + 3, "on the chart's rows");

    let mut narrow = gateway(90, 60).await;
    let chart = narrow.find("App Gateway by action");
    let table = narrow.find("Managed rules");
    assert!(table.1 > chart.1 + 6, "under: below the chart {chart:?} {table:?}");
    assert!(table.0 <= chart.0, "from the chart's left edge: {chart:?} {table:?}");
}

#[tokio::test]
async fn enter_charts_the_rule_d_goes_back_then_to_the_default_set_and_w_returns() {
    let mut h = gateway(170, 50).await;
    // The cursor starts on the biggest managed rule; Tab moves tables.
    h.press(KeyCode::Char('j')).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().waf.as_ref().unwrap().selected_rule().unwrap().rule, "941100");
    h.press(KeyCode::Tab).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().waf.as_ref().unwrap().selected_rule().unwrap().rule, "AllowCorpProbes");
    h.press(KeyCode::Tab).await;
    h.press(KeyCode::Char('g')).await;
    h.press(KeyCode::Enter).await;
    let w = h.app.metrics.as_ref().unwrap().waf.as_ref().unwrap();
    assert_eq!(w.charted_rule().unwrap().rule, "942100");
    let screen = h.render();
    assert!(screen.contains("DRS_2.1 / REQUEST-942-SQLI / 942100") && screen.contains("d back"), "{screen}");
    assert!(!screen.contains("App Gateway by action"), "the chart is the rule's now:\n{screen}");

    // d: back to the whole gateway; Esc would do the same.
    h.press(KeyCode::Char('d')).await;
    assert!(h.app.metrics.as_ref().unwrap().waf.as_ref().unwrap().charted.is_none());
    assert!(h.render().contains("App Gateway by action"));
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Esc).await;
    assert!(h.app.metrics.is_some(), "Esc leaves the chart first");
    assert!(h.app.metrics.as_ref().unwrap().waf.as_ref().unwrap().charted.is_none());

    // d again: the default set; w: the WAF view, refetched.
    h.press(KeyCode::Char('d')).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert!(!st.waf_on && st.curated && st.queries[0].name == "TotalRequests");
    assert!(h.render().contains("default set"));
    h.press(KeyCode::Char('w')).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert!(st.waf_on && st.loading);
    h.press(KeyCode::Esc).await;
    assert!(h.app.metrics.is_none());
}

#[tokio::test]
async fn the_window_keys_refetch_the_waf_view() {
    let mut h = gateway(170, 50).await;
    let generation = h.app.metrics_generation;
    h.press(KeyCode::Char(']')).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert_eq!(st.window, MetricWindow::SixHours);
    assert!(st.loading && st.waf_on);
    assert!(h.app.metrics_generation > generation, "a new fetch supersedes the old");
}

#[tokio::test]
async fn change_markers_still_draw_on_the_waf_chart() {
    let mut h = gateway(170, 50).await;
    let before = h.render();
    assert!(before.contains("loading changes…"), "the legend waits for the timeline:\n{before}");
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        let st = app.chart_timeline.as_mut().expect("m seeds the markers' timeline");
        st.since = 0;
        st.set_activity(
            vec![json!({
                "eventTimestamp": "2026-10-23T11:40:00Z", "correlationId": "c1",
                "operationName": {"value": "Microsoft.Network/applicationGateways/write", "localizedValue": ""},
                "status": {"value": "Failed"}, "caller": "ops@contoso.com", "level": "Error",
                "resourceId": arm_id("Microsoft.Network/applicationGateways/agw-1")
            })],
            false,
        );
        for s in [
            crate::azure::timeline::TimelineSource::Alert,
            crate::azure::timeline::TimelineSource::Health,
            crate::azure::timeline::TimelineSource::Deployment,
        ] {
            st.set_rows(s, vec![]);
        }
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
    let screen = h.render();
    assert!(screen.contains("applicationGateways/write"), "the change is named on the WAF chart:\n{screen}");
    assert!(h.has_fg(theme::error()), "a failed change is error-coloured");
}

fn policy(id_tail: &str, name: &str, attached: Value) -> Box<dyn Resource> {
    Box::new(
        WafPolicyRow::from_json(
            &json!({
                "id": arm_id(id_tail),
                "name": name,
                "location": "eastus",
                "properties": {
                    "provisioningState": "Succeeded", "resourceState": "Enabled",
                    "policySettings": {"state": "Enabled", "mode": "Prevention"},
                    "applicationGateways": attached,
                }
            }),
            None,
        )
        .expect("a policy row"),
    )
}

#[tokio::test]
async fn m_on_a_policy_opens_the_waf_view_of_its_gateway_with_the_policy_pinned() {
    let mut h = Harness::sized(170, 50).await;
    let mock = all_mocks().into_iter().find(|m| m.view == JumpView::WafPolicies).expect("a policy mock");
    h.install(mock).await;
    assert!(h.render().contains("m metrics"), "the status bar offers m on a policy");
    h.press(KeyCode::Char('m')).await;
    let st = h.app.metrics.as_ref().expect("m opens the view on a policy");
    let w = st.waf.as_ref().unwrap();
    assert_eq!(st.resource_id, agw_id(), "the gateway's metrics, not the policy's");
    assert_eq!(w.policy.as_deref(), Some("waf-1"), "PolicyName pinned");
    assert!(st.title.contains("App Gateway · agw-1"), "{}", st.title);
    land_waf(&mut h).await;
    let screen = h.render();
    assert!(screen.contains("policy waf-1") && screen.contains("Managed rules"), "{screen}");
}

#[tokio::test]
async fn a_policy_on_several_gateways_shows_the_first_and_n_steps_through() {
    let mut h = Harness::sized(170, 50).await;
    h.open(JumpView::WafPolicies).await;
    let a = arm_id("Microsoft.Network/applicationGateways/agw-1");
    let b = arm_id("Microsoft.Network/applicationGateways/agw-2");
    h.land(vec![policy(
        "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-2",
        "waf-2",
        json!([{"id": a}, {"id": b}]),
    )])
    .await;
    h.press(KeyCode::Char('m')).await;
    land_waf(&mut h).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().resource_id, a);
    let screen = h.render();
    assert!(screen.contains("1 of 2 attached (n next)"), "{screen}");
    h.press(KeyCode::Char('n')).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert_eq!(st.resource_id, b);
    assert!(st.loading && st.waf.as_ref().unwrap().data.is_none(), "the next gateway is fetched afresh");
    assert!(h.render().contains("2 of 2 attached"));
    h.press(KeyCode::Char('n')).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().resource_id, a, "and it wraps");
}

#[tokio::test]
async fn a_policy_attached_to_nothing_says_so_instead_of_opening_an_empty_view() {
    let mut h = Harness::sized(170, 50).await;
    h.open(JumpView::WafPolicies).await;
    h.land(vec![policy(
        "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-orphan",
        "waf-orphan",
        json!([]),
    )])
    .await;
    h.press(KeyCode::Char('m')).await;
    assert!(h.app.metrics.is_none());
    let e = h.app.error_message.clone().unwrap_or_default();
    assert!(e.contains("waf-orphan") && e.contains("attached to nothing"), "{e}");
}

#[tokio::test]
async fn m_on_a_front_door_profile_opens_its_waf_view() {
    let mut h = Harness::sized(170, 50).await;
    let mock = all_mocks().into_iter().find(|m| m.view == JumpView::FrontDoorProfiles).unwrap();
    h.install(mock).await;
    h.press(KeyCode::Char('m')).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert!(st.waf_on);
    assert_eq!(st.waf.as_ref().unwrap().product, WafProduct::FrontDoor);
    assert!(!st.queries.iter().any(|q| q.name == "WebApplicationFirewallRequestCount"), "the default set no longer carries the unsplit WAF line");
}
