//! The glue for Azure Automation (#202, SERVICES.md rule 44): the section
//! dispatch and the lazy reads per account (runbooks, schedules and job
//! schedules, the window of jobs, worker groups with their workers, the
//! linked workspace). The rows and renderers are
//! `src/azure/services/automation.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::automation::{
    account_child_path, automation_section_lines, fetch_worker_groups, jobs_filter, without_secrets, AccountLazy,
    AUTOMATION_API_VERSION, MAX_JOBS,
};
use crate::azure::services::directory::now_unix;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The Automation account arm of `section_lines_for`; `None` for
    /// another type.
    pub(crate) fn automation_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let id = resource.id();
        let lazy = AccountLazy {
            runbooks: self.lazy.aa_runbooks.get(id),
            schedules: self.lazy.aa_schedules.get(id),
            job_schedules: self.lazy.aa_job_schedules.get(id),
            jobs: self.lazy.aa_jobs.get(id),
            workers: self.lazy.aa_workers.get(id),
            workspace: self.lazy.aa_linked_workspace.get(id),
        };
        automation_section_lines(resource, idx, lazy, now_unix())
    }

    /// On-enter hook for Runbooks: the runbooks, plus the job schedules
    /// and jobs their lines draw on.
    pub fn trigger_aa_runbooks(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.aa_runbooks, event_tx, |c, id| scrubbed_list(c, id, "runbooks"));
        Self::trigger_aa_job_schedules(app, event_tx);
        Self::trigger_aa_jobs(app, event_tx);
    }

    /// On-enter hook for Schedules: the schedules and the job schedules
    /// that tie them to runbooks.
    pub fn trigger_aa_schedules(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.aa_schedules, event_tx, |c, id| scrubbed_list(c, id, "schedules"));
        Self::trigger_aa_job_schedules(app, event_tx);
    }

    fn trigger_aa_job_schedules(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.aa_job_schedules, event_tx, |c, id| scrubbed_list(c, id, "jobSchedules"));
    }

    /// On-enter hook for Jobs: the jobs started in the window, capped.
    pub fn trigger_aa_jobs(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let filter = jobs_filter(now_unix());
        app.trigger_selected(
            |s| &mut s.aa_jobs,
            event_tx,
            |c, id| {
                let fetch = c.list_fetch_query_capped(
                    &account_child_path(id, "jobs"),
                    AUTOMATION_API_VERSION,
                    vec![("$filter".into(), filter)],
                    MAX_JOBS,
                );
                async move { fetch.await.map(|items| items.iter().map(without_secrets).collect()) }
            },
        );
    }

    /// On-enter hook for Hybrid workers: the groups, then each group's
    /// workers, in one read.
    pub fn trigger_aa_workers(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.aa_workers,
            event_tx,
            |c, id| fetch_worker_groups(c.arm_for_path(id), id.to_string()),
        );
    }

    /// On-enter hook for Related: the linked workspace and the workers'
    /// machines.
    pub fn trigger_aa_related(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.aa_linked_workspace,
            event_tx,
            |c, id| c.get_fetch(&account_child_path(id, "linkedWorkspace"), AUTOMATION_API_VERSION),
        );
        Self::trigger_aa_workers(app, event_tx);
    }
}

/// `GET {account}/{child}`, scrubbed before the store keeps it.
fn scrubbed_list(
    c: &crate::azure::client::AzureClients,
    id: &str,
    child: &str,
) -> impl std::future::Future<Output = Result<Vec<serde_json::Value>, String>> + Send + 'static {
    let fetch = c.list_fetch(&account_child_path(id, child), AUTOMATION_API_VERSION);
    async move { fetch.await.map(|items| items.iter().map(without_secrets).collect()) }
}
