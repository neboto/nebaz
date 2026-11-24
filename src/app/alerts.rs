//! The glue for the alert sub-tabs (#194, SERVICES.md rule 36): the
//! section dispatch, the hook that loads the rule lists an action group's
//! Used by matches in, and the splice that adds the alert rules watching a
//! row to every type's Related. The rows and renderers are
//! `src/azure/services/alerts.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::alerts::{alerts_section_lines, chart_thresholds, rules_watching, AlertsContext};
use crate::azure::services::directory::now_unix;
use crate::azure::services::governance::Warm;
use crate::azure::services::splice_related;
use crate::event::Event;
use crate::ui::widgets::metrics_overlay::ThresholdSource;
use tokio::sync::mpsc;

/// The rule lists a resource's Related reads: the three rule types.
const RULE_VIEWS: [JumpView; 3] = [JumpView::MetricAlerts, JumpView::LogAlerts, JumpView::ActivityLogAlerts];

/// An action group's Used by reads the processing rules too.
const USER_VIEWS: [JumpView; 4] =
    [JumpView::MetricAlerts, JumpView::LogAlerts, JumpView::ActivityLogAlerts, JumpView::AlertProcessingRules];

impl App {
    /// The alerts arm of `section_lines_for`; `None` for another type.
    pub(crate) fn alerts_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let mut rule_lists = Vec::new();
        let mut missing = Vec::new();
        for view in USER_VIEWS {
            match self.section_list(view) {
                Warm::Rows(rows) => rule_lists.push(rows),
                other => missing.push((view.label(), other)),
            }
        }
        let cx = AlertsContext { rule_lists, missing, now: now_unix() };
        alerts_section_lines(resource, idx, &cx)
    }

    /// Every type's Related, plus the alert rules that watch the row, from
    /// the rule lists (loaded on entering Related, [`Self::trigger_alert_rules`]).
    /// `Loading…` while one is in flight, so `X` waits; a failed one is a
    /// warning line.
    pub(crate) fn with_alert_rules(&self, id: &str, lines: Vec<(String, String)>) -> Vec<(String, String)> {
        let mut lists: Vec<&[Box<dyn Resource>]> = Vec::new();
        let mut extra = Vec::new();
        for view in RULE_VIEWS {
            match self.section_list(view) {
                Warm::Rows(rows) => lists.push(rows),
                Warm::Loading => return splice_related(lines, vec![("Alert rules".into(), "Loading…".into())]),
                Warm::Failed(e) => extra.push((String::new(), format!("⚠ {}: {}", view.label(), e))),
                Warm::Cold => {}
            }
        }
        let mut found = rules_watching(id, &lists);
        found.extend(extra);
        splice_related(lines, found)
    }

    /// The metric alert thresholds on the open chart's selected metric
    /// (#230), from the warm metric alert list: `None` with no chart, in
    /// the WAF view, or with nothing to say (the list cold, or no rule on
    /// the metric).
    pub fn threshold_source(&self) -> Option<ThresholdSource> {
        let st = self.metrics.as_ref().filter(|st| !st.waf_view() && st.picker.is_none())?;
        let s = st.selected_series()?;
        let src = match self.section_list(JumpView::MetricAlerts) {
            Warm::Rows(rows) => ThresholdSource {
                rules: chart_thresholds(&st.resource_id, &s.name, s.aggregation, st.window.interval(), &[rows]),
                ..Default::default()
            },
            Warm::Loading => ThresholdSource { loading: true, ..Default::default() },
            Warm::Failed(e) => ThresholdSource { failed: Some(e.to_string()), ..Default::default() },
            Warm::Cold => return None,
        };
        (src.loading || src.failed.is_some() || !src.rules.is_empty()).then_some(src)
    }

    /// The charts' thresholds: the metric alert list, once per subscription.
    pub(super) fn trigger_chart_thresholds(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        self.trigger_section_list(JumpView::MetricAlerts, event_tx);
    }

    /// Every type's Related: the three rule lists, once per subscription.
    pub fn trigger_alert_rules(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        for view in RULE_VIEWS {
            app.trigger_section_list(view, event_tx);
        }
    }

    /// On-enter hook for an action group's Used by and Related: the three
    /// rule lists and the processing rules.
    pub fn trigger_alert_rule_lists(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        for view in USER_VIEWS {
            app.trigger_section_list(view, event_tx);
        }
    }
}
