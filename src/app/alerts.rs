//! The glue for the alert sub-tabs (#194, SERVICES.md rule 36): the
//! section dispatch, the hook that loads the rule lists an action group's
//! Used by matches in, and the splice that adds the alert rules watching a
//! row to every type's Related. The rows and renderers are
//! `src/azure/services/alerts.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::alerts::{alerts_section_lines, rules_watching, AlertsContext};
use crate::azure::services::directory::now_unix;
use crate::azure::services::governance::Warm;
use crate::azure::services::splice_related;
use crate::event::Event;
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
