//! The Backup tab's glue (#32): the lazy triggers (a vault's protected
//! items or backup instances, its policies, its jobs), the section
//! dispatch, and the reverse look-up every other type's Related reads
//! ("Backed up by {vault}", from what the vaults have already read). The
//! rows and renderers are `src/azure/services/backup.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::backup::{
    backup_vault_section_lines, child_api_version, failed_jobs_filter, is_backup_vault, protection_of, recovery_vault_section_lines,
    vault_child_path, with_protection, without_secrets, BackupLazy, BackupVaultDetailSection, BackupVaultRow,
    RecoveryVaultDetailSection, RecoveryVaultRow, BACKUP_VAULT_JOBS_MAX, DPP_API_VERSION, RSV_BACKUP_API_VERSION,
};
use crate::azure::services::directory::now_unix;
use crate::event::Event;
use tokio::sync::mpsc;

/// What a vault id is, for the hooks.
enum VaultKind {
    Recovery,
    Backup,
}

impl App {
    fn backup_lazy(&self) -> BackupLazy<'_> {
        BackupLazy {
            items: &self.lazy.backup_protected_items,
            instances: &self.lazy.backup_instances,
            policies: &self.lazy.backup_policies,
            jobs: &self.lazy.backup_jobs,
        }
    }

    /// The Backup-tab arm of `section_lines_for`; `None` for any other
    /// type.
    pub(crate) fn backup_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let any = resource.as_any();
        let lazy = self.backup_lazy();
        if let Some(r) = any.downcast_ref::<RecoveryVaultRow>() {
            return Some(recovery_vault_section_lines(r, RecoveryVaultDetailSection::from_index(idx), &lazy, now_unix()));
        }
        if let Some(r) = any.downcast_ref::<BackupVaultRow>() {
            return Some(backup_vault_section_lines(r, BackupVaultDetailSection::from_index(idx), &lazy, now_unix()));
        }
        None
    }

    /// Any type's Related body with "Backed up by {vault}" spliced in when
    /// a vault read this session protects it (no call).
    pub(crate) fn with_backup_protection(&self, id: &str, lines: Vec<(String, String)>) -> Vec<(String, String)> {
        let extra = protection_of(id, &self.backup_lazy(), now_unix());
        with_protection(lines, extra)
    }

    fn selected_vault(&self) -> Option<(String, VaultKind)> {
        let r = self.get_selected_resource()?;
        let any = r.as_any();
        if any.downcast_ref::<RecoveryVaultRow>().is_some() {
            Some((r.id().to_string(), VaultKind::Recovery))
        } else if any.downcast_ref::<BackupVaultRow>().is_some() {
            Some((r.id().to_string(), VaultKind::Backup))
        } else {
            None
        }
    }

    /// `GET {vault}/backupProtectedItems` once per Recovery Services vault.
    pub(crate) fn trigger_protected_items(&mut self, vault: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let fut = self
            .azure_clients
            .list_fetch(&vault_child_path(vault, "backupProtectedItems"), RSV_BACKUP_API_VERSION);
        self.trigger_lazy(|s| &mut s.backup_protected_items, vault.to_string(), event_tx, move || fut);
    }

    /// `GET {vault}/backupInstances` once per Backup vault, credentials
    /// stripped before the store keeps them.
    pub(crate) fn trigger_backup_instances(&mut self, vault: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let fut = self.azure_clients.list_fetch(&vault_child_path(vault, "backupInstances"), DPP_API_VERSION);
        self.trigger_lazy(|s| &mut s.backup_instances, vault.to_string(), event_tx, move || async move {
            fut.await.map(|items| items.iter().map(without_secrets).collect())
        });
    }

    /// `GET {vault}/backupPolicies` once per vault (either kind).
    fn trigger_vault_policies(&mut self, vault: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let fut = self
            .azure_clients
            .list_fetch(&vault_child_path(vault, "backupPolicies"), child_api_version(vault));
        self.trigger_lazy(|s| &mut s.backup_policies, vault.to_string(), event_tx, move || fut);
    }

    /// `GET {vault}/backupJobs` once per vault: a Recovery Services
    /// vault's failed jobs of the last week (`$filter`), a Backup vault's
    /// newest [`BACKUP_VAULT_JOBS_MAX`] (its list takes no filter).
    fn trigger_vault_jobs(&mut self, vault: &str, kind: &VaultKind, event_tx: &mpsc::UnboundedSender<Event>) {
        let path = vault_child_path(vault, "backupJobs");
        let fut = match kind {
            VaultKind::Recovery => self.azure_clients.list_fetch_query_capped(
                &path,
                RSV_BACKUP_API_VERSION,
                vec![("$filter".to_string(), failed_jobs_filter(now_unix()))],
                BACKUP_VAULT_JOBS_MAX,
            ),
            VaultKind::Backup => self.azure_clients.list_fetch_query_capped(&path, DPP_API_VERSION, Vec::new(), BACKUP_VAULT_JOBS_MAX),
        };
        self.trigger_lazy(|s| &mut s.backup_jobs, vault.to_string(), event_tx, move || fut);
    }

    /// What `r` in `@audit` reads for one vault: what the item checks
    /// need (the same maps the sections use, so nothing is read twice).
    pub(super) fn trigger_backup_audit_reads(&mut self, vault: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        if is_backup_vault(vault) {
            self.trigger_backup_instances(vault, event_tx);
            self.trigger_vault_jobs(vault, &VaultKind::Backup, event_tx);
        } else {
            self.trigger_protected_items(vault, event_tx);
            self.trigger_vault_policies(vault, event_tx);
        }
    }

    /// On-enter hook for Protected items / Backup instances. A Recovery
    /// Services vault also reads its policies (a weekly policy's items are
    /// judged stale on a week, not a day); a Backup vault its jobs (an
    /// instance's last backup is only in them) and policies (an
    /// operational-tier policy schedules no jobs).
    pub fn trigger_backup_items(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some((vault, kind)) = app.selected_vault() else {
            return;
        };
        match kind {
            VaultKind::Recovery => {
                app.trigger_protected_items(&vault, event_tx);
                app.trigger_vault_policies(&vault, event_tx);
            }
            VaultKind::Backup => {
                app.trigger_backup_instances(&vault, event_tx);
                app.trigger_vault_jobs(&vault, &kind, event_tx);
                app.trigger_vault_policies(&vault, event_tx);
            }
        }
    }

    /// On-enter hook for Policies.
    pub fn trigger_backup_policies(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        if let Some((vault, _)) = app.selected_vault() {
            app.trigger_vault_policies(&vault, event_tx);
        }
    }

    /// On-enter hook for (Failed) jobs.
    pub fn trigger_backup_jobs(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        if let Some((vault, kind)) = app.selected_vault() {
            app.trigger_vault_jobs(&vault, &kind, event_tx);
        }
    }
}
