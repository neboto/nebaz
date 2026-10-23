// ported from neboto-tui src/app.rs @ 03760c0 (PendingDeepExport,
// export_current, run_pending_deep_export, write_single_export,
// export_list_all, format_export_paths; neboto bcfb8d1): the walk fires
// nebaz's section descriptors instead of neboto's reset+cycle sweep
//! `X` and `Ctrl-X` on `App` (#40, #39). `X` exports one resource's every
//! detail section, lazy ones loaded: it **arms** a wait rather than writing
//! at once. Each pass (`export_tick`, once per main-loop iteration) fires
//! every section's on-enter hook for the armed rows (LazyMap-idempotent, so
//! a chained fetch such as Access's principal names follows its parent) and
//! writes once no captured section reads `Loading…`, immediately when all
//! are warm. After [`EXPORT_WAIT_LIMIT`] it writes what landed and says
//! which sections were still loading. `Esc` cancels; a subscription or
//! service switch cancels too. Sections behind a key with no on-enter hook
//! stay unfired. Progress goes in `deep_export_progress` (its own status
//! slot), not a toast, which would flood the `M` history.
//!
//! `X` over a list visual selection (`app/list_visual.rs`) arms the same
//! wait for every selected row and writes one combined
//! `nebaz-<label>-deep-<ts>` trio (`export::export_detail_multi`).
//!
//! The rows are held by ARM id (or `graph:/` id), not position: the wait
//! spans main-loop passes and a streamed page can reorder the list.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::ServiceType;
use crate::event::Event;
use crate::export::DetailSections;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How long an export waits on lazy sections before writing anyway.
pub(crate) const EXPORT_WAIT_LIMIT: Duration = Duration::from_secs(120);

/// An export armed by `X` and finished by [`App::export_tick`].
#[derive(Debug, Clone)]
pub struct PendingExport {
    /// The rows to export, by id, in display order at arm time.
    pub ids: Vec<String>,
    /// When `X` was pressed: the wait-limit clock.
    pub started: Instant,
    /// One resource's `X` (single-resource files and toast) rather than a
    /// selection's deep export (the combined `-deep-` trio).
    pub single: bool,
    /// The lazy store's epoch at arm time: a subscription switch replaces
    /// the store, and the export with it.
    epoch: u64,
    /// The service at arm time: switching away cancels.
    service: Option<ServiceType>,
}

/// `dir/nebaz-x-20261023-101500.{json, csv, md}`: the written files in one
/// line.
pub(crate) fn format_export_paths(paths: &[PathBuf]) -> String {
    let Some(first) = paths.first() else {
        return "nothing written".to_string();
    };
    let stem = first.with_extension("");
    let exts: Vec<&str> = paths.iter().filter_map(|p| p.extension().and_then(|e| e.to_str())).collect();
    format!("{}.{{{}}}", stem.display(), exts.join(", "))
}

impl App {
    /// `X`, from either pane: arm the export of the selected resource.
    /// A second press while one waits neither restarts nor stacks it.
    pub(crate) fn export_current(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.pending_export.is_some() {
            return;
        }
        let Some(id) = self.get_selected_resource_id() else {
            self.error_message = Some("Nothing to export".to_string());
            return;
        };
        self.arm_export(vec![id], true, event_tx);
    }

    pub(crate) fn arm_export(&mut self, ids: Vec<String>, single: bool, event_tx: &mpsc::UnboundedSender<Event>) {
        self.pending_export = Some(PendingExport {
            ids,
            started: Instant::now(),
            single,
            epoch: self.lazy.epoch(),
            service: self.current_service,
        });
        self.error_message = None;
        self.run_pending_export(event_tx);
    }

    /// Main-loop hook: advance an armed export. Cheap when none is armed.
    pub fn export_tick(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.pending_export.is_some() {
            self.run_pending_export(event_tx);
        }
    }

    /// `Esc` while an export waits, or anything that invalidates its rows.
    pub(crate) fn cancel_pending_export(&mut self) {
        if self.pending_export.take().is_some() {
            self.deep_export_progress = None;
            self.toast("Export cancelled");
        }
    }

    fn abandon_export(&mut self, why: &str) {
        self.pending_export = None;
        self.deep_export_progress = None;
        self.error_message = Some(format!("Export cancelled — {}", why));
    }

    /// The position of the row `id` names in the current list.
    fn position_of(&self, id: &str) -> Option<usize> {
        self.filtered_resources
            .iter()
            .position(|&i| self.resources.get(i).is_some_and(|r| r.id() == id))
    }

    /// Fire every section's on-enter hook for the row at `pos` and capture
    /// its sections. The hooks key off the selected row, so the selection
    /// moves there for the walk and is put back by the caller.
    fn fire_and_capture(&mut self, pos: usize, event_tx: &mpsc::UnboundedSender<Event>) -> DetailSections {
        self.selected_index = Some(pos);
        if let Some(desc) = self.selected_descriptor() {
            for i in 0..desc.len() {
                desc.enter(i, self, event_tx);
            }
        }
        self.detail_sections_snapshot()
    }

    /// One pass of the armed export: fire, capture, and write once nothing
    /// is loading or the wait limit has passed.
    fn run_pending_export(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(pending) = self.pending_export.as_ref() else {
            return;
        };
        if pending.epoch != self.lazy.epoch() {
            return self.abandon_export("the subscription changed");
        }
        if pending.service != self.current_service {
            return self.abandon_export("the view changed");
        }
        let started = pending.started;
        let single = pending.single;
        let ids = pending.ids.clone();
        let total = ids.len();

        let positions: Vec<usize> = ids.iter().filter_map(|id| self.position_of(id)).collect();
        if positions.is_empty() {
            // A load in flight is a gap, not a verdict.
            if self.loading || self.filtered_resources.is_empty() {
                return;
            }
            return self.abandon_export(if single {
                "the resource is no longer listed"
            } else {
                "the selected rows are no longer listed"
            });
        }

        let saved = self.selected_index;
        let snapshots: Vec<(usize, DetailSections)> =
            positions.into_iter().map(|pos| (pos, self.fire_and_capture(pos, event_tx))).collect();
        self.selected_index = saved;

        let waiting: Vec<String> = snapshots
            .iter()
            .flat_map(|(_, s)| crate::export::unloaded_sections(s))
            .collect();
        let rows_waiting = snapshots
            .iter()
            .filter(|(_, s)| !crate::export::unloaded_sections(s).is_empty())
            .count();
        if !waiting.is_empty() && started.elapsed() < EXPORT_WAIT_LIMIT {
            self.deep_export_progress = Some(if single {
                format!("Export: waiting on {} (Esc to cancel)", waiting.join(", "))
            } else {
                format!(
                    "Deep export: {}/{} ready — waiting on details (Esc to cancel)",
                    total - rows_waiting,
                    total
                )
            });
            return;
        }

        self.pending_export = None;
        self.deep_export_progress = None;
        if !single {
            self.write_deep_export(&snapshots);
            if rows_waiting > 0 {
                if let Some(msg) = self.success_message.take() {
                    self.success_message = Some(format!(
                        "{} ({} still loading after {}s — those sections are incomplete)",
                        msg,
                        rows_waiting,
                        EXPORT_WAIT_LIMIT.as_secs()
                    ));
                }
            }
            return;
        }
        if let Some((pos, sections)) = snapshots.first() {
            self.write_single_export(*pos, sections);
        }
        if !waiting.is_empty() {
            if let Some(msg) = self.success_message.take() {
                self.success_message = Some(format!(
                    "{} (still loading after {}s, exported as not loaded: {})",
                    msg,
                    EXPORT_WAIT_LIMIT.as_secs(),
                    waiting.join(", ")
                ));
            }
        }
    }

    /// Write a selection's combined deep export and report it.
    fn write_deep_export(&mut self, snapshots: &[(usize, DetailSections)]) {
        let items: Vec<(&dyn Resource, DetailSections)> = snapshots
            .iter()
            .filter_map(|(pos, sections)| {
                self.filtered_resources
                    .get(*pos)
                    .and_then(|&i| self.resources.get(i))
                    .map(|r| (r.as_ref(), sections.clone()))
            })
            .collect();
        let count = items.len();
        let label = self.export_label(items.iter().map(|(r, _)| r.resource_type()));
        let result = crate::export::export_detail_multi(&items, &label, &self.export_options);
        drop(items);
        self.clear_list_visual();
        self.report_list_export(count, &label, result);
    }

    /// Write one resource's files and report them.
    fn write_single_export(&mut self, pos: usize, sections: &DetailSections) {
        let result = self
            .filtered_resources
            .get(pos)
            .and_then(|&i| self.resources.get(i))
            .map(|r| {
                let name = r.name().to_string();
                (name.clone(), crate::export::export_detail(r.as_ref(), sections, &name, &self.export_options))
            });
        match result {
            Some((name, Ok(paths))) => {
                self.toast(format!("Exported {} → {}", name, format_export_paths(&paths)));
                self.last_export_paths = paths;
            }
            Some((_, Err(e))) => self.error_message = Some(format!("Export failed: {}", e)),
            None => self.error_message = Some("Nothing to export".to_string()),
        }
    }

    /// `Ctrl-X`: the whole filtered list, list-level fields only (no
    /// section is fetched, so it is never capped and never waits).
    pub(crate) fn export_list(&mut self) {
        let rows: Vec<&dyn Resource> = self
            .filtered_resources
            .iter()
            .filter_map(|&i| self.resources.get(i))
            .map(|r| r.as_ref())
            .collect();
        if rows.is_empty() {
            self.error_message = Some("Nothing to export".to_string());
            return;
        }
        let label = self
            .current_service
            .map(|s| s.short_name().to_string())
            .unwrap_or_else(|| "resources".into());
        let count = rows.len();
        let result = crate::export::export_list(&rows, &label, &self.export_options);
        drop(rows);
        self.report_list_export(count, &label, result);
    }

    pub(crate) fn report_list_export(&mut self, count: usize, label: &str, result: crate::error::Result<Vec<PathBuf>>) {
        match result {
            Ok(paths) => {
                self.toast(format!("Exported {} {} → {}", count, label, format_export_paths(&paths)));
                self.last_export_paths = paths;
            }
            Err(e) => self.error_message = Some(format!("Export failed: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_paths_read_as_one_stem_and_its_extensions() {
        let paths = vec![PathBuf::from("out/nebaz-vm-1-x.json"), PathBuf::from("out/nebaz-vm-1-x.md")];
        assert_eq!(format_export_paths(&paths), "out/nebaz-vm-1-x.{json, md}");
        assert_eq!(format_export_paths(&[]), "nothing written");
    }
}
