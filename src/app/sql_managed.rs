//! The glue for SQL Managed Instance (#195, SERVICES.md rule 37): the
//! section dispatch and the two lazy reads per instance (its databases,
//! the failover groups of its group and region). The rows and renderers
//! are `src/azure/services/sql_managed.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::sql::SQL_API_VERSION;
use crate::azure::services::sql_managed::{
    failover_groups_path, managed_section_lines, without_sas, ManagedContext, ManagedInstanceRow,
};
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The SQL Managed Instance arm of `section_lines_for`; `None` for
    /// another type.
    pub(crate) fn sql_managed_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let id = resource.id();
        let cx = ManagedContext {
            databases: self.lazy.mi_databases.get(id),
            failover_groups: self.lazy.mi_failover_groups.get(id),
            instances: self.section_list(JumpView::ManagedInstances),
        };
        managed_section_lines(resource, idx, &cx)
    }

    /// On-enter hook for an instance's Databases: one list per instance,
    /// each database's restore SAS token stripped before the store keeps it.
    pub fn trigger_mi_databases(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.mi_databases,
            event_tx,
            |c, id| {
                let fut = c.list_fetch(&format!("{}/databases", id.trim_end_matches('/')), SQL_API_VERSION);
                async move { fut.await.map(|items| items.iter().map(without_sas).collect()) }
            },
        );
    }

    /// On-enter hook for a pool's Instances: the Managed instances list.
    pub fn trigger_pool_instances(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::ManagedInstances, event_tx);
    }

    /// On-enter hook for an instance's Failover group: the failover groups
    /// of its group and region (no subscription-wide list exists), keyed
    /// by the instance.
    pub fn trigger_mi_failover_groups(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(path) = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<ManagedInstanceRow>())
            .and_then(failover_groups_path)
        else {
            return;
        };
        app.trigger_selected(|s| &mut s.mi_failover_groups, event_tx, move |c, _| c.list_fetch(&path, SQL_API_VERSION));
    }
}
