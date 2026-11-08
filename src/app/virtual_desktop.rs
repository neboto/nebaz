//! The glue for Azure Virtual Desktop (#198, SERVICES.md rule 46): the
//! section dispatch, the lazy reads (a pool's session hosts, a scaling
//! plan's schedules), the scaling plans list a pool's Related reads, and
//! the splice that names a VM's host pool in every type's Related. The
//! rows and renderers are `src/azure/services/virtual_desktop.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::directory::now_unix;
use crate::azure::services::splice_related;
use crate::azure::services::virtual_desktop::{
    avd_section_lines, child_path, pools_hosting, AvdLazy, ScalingPlanRow, AVD_API_VERSION, MAX_SESSION_HOSTS,
};
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The AVD arm of `section_lines_for`; `None` for another type.
    pub(crate) fn avd_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let id = resource.id();
        let lazy = AvdLazy {
            session_hosts: self.lazy.avd_session_hosts.get(id),
            schedules: self.lazy.avd_schedules.get(id),
            scaling_plans: self.section_list(JumpView::ScalingPlans).rows(),
        };
        avd_section_lines(resource, idx, lazy, now_unix())
    }

    /// Every type's Related, plus the host pool a VM is a session host
    /// of, from the session host reads this session made (no call).
    pub(crate) fn with_session_host_pool(&self, id: &str, lines: Vec<(String, String)>) -> Vec<(String, String)> {
        splice_related(lines, pools_hosting(id, self.lazy.avd_session_hosts.iter()))
    }

    /// `GET {pool}/sessionHosts`, capped, for the pool `id`.
    pub(crate) fn trigger_session_hosts_of(&mut self, id: String, event_tx: &mpsc::UnboundedSender<Event>) {
        let fut = self.azure_clients.list_fetch_query_capped(
            &child_path(&id, "sessionHosts"),
            AVD_API_VERSION,
            Vec::new(),
            MAX_SESSION_HOSTS,
        );
        self.trigger_lazy(|s| &mut s.avd_session_hosts, id, event_tx, move || fut);
    }

    /// On-enter hook for a host pool's Session hosts.
    pub fn trigger_avd_session_hosts(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        if let Some(id) = app.get_selected_resource_id() {
            app.trigger_session_hosts_of(id, event_tx);
        }
    }

    /// On-enter hook for a host pool's Related: its session hosts (their
    /// VMs) and the scaling plans list (the plan that scales it).
    pub fn trigger_avd_pool_related(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        Self::trigger_avd_session_hosts(app, event_tx);
        app.trigger_section_list(JumpView::ScalingPlans, event_tx);
    }

    /// On-enter hook for a scaling plan's Schedules: the pooled or the
    /// personal schedules, by the plan's host pool type.
    pub fn trigger_avd_schedules(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(child) = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<ScalingPlanRow>())
            .map(ScalingPlanRow::schedules_child)
        else {
            return;
        };
        app.trigger_selected(
            |s| &mut s.avd_schedules,
            event_tx,
            |c, id| c.list_fetch(&child_path(id, child), AVD_API_VERSION),
        );
    }
}
