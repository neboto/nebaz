// ported from neboto-tui src/bookmarks.rs @ d483900
//! Persistent, user-curated bookmarks — saved navigation locations the user can
//! jump back to across sessions (unlike the ephemeral, auto-pruned nav history).
//! Stored as JSON next to the config file. A `NavLocation` already captures
//! everything needed to navigate back (service + sub-tab + selected id + label).

use crate::app::NavLocation;
use std::path::PathBuf;

/// Resolve the bookmarks file path. Honours `$NEBAZ_BOOKMARKS`, then
/// the config directory (`paths::config_dir`: `~/.config/nebaz` on Unix,
/// `%APPDATA%\nebaz` on Windows) plus `bookmarks.json`.
fn bookmarks_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("NEBAZ_BOOKMARKS") {
        return Some(PathBuf::from(p));
    }
    Some(crate::paths::config_dir()?.join("bookmarks.json"))
}

/// Load saved bookmarks. Returns empty on a missing file or a file that
/// isn't a JSON list — bookmarks are best-effort, never fatal. An entry this
/// build can't read (one saved by a newer nebaz, e.g. on a service or
/// sub-tab this build doesn't know) is skipped, not the whole file; `save`
/// keeps it. (neboto-tui#333)
pub fn load() -> Vec<NavLocation> {
    let Some(path) = bookmarks_path() else {
        return Vec::new();
    };
    let Ok(data) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    parse(&data).0
}

/// The entries this build reads, and the ones it can't, verbatim.
fn parse(data: &str) -> (Vec<NavLocation>, Vec<serde_json::Value>) {
    let entries: Vec<serde_json::Value> = serde_json::from_str(data).unwrap_or_default();
    let mut read = Vec::new();
    let mut unread = Vec::new();
    for entry in entries {
        match serde_json::from_value::<NavLocation>(entry.clone()) {
            Ok(loc) => read.push(loc),
            Err(_) => unread.push(entry),
        }
    }
    (read, unread)
}

/// Persist bookmarks (best-effort; creates the parent dir if needed). The
/// entries already on disk that this build can't read are written back
/// after them, so going back a version doesn't erase the newer one's
/// bookmarks.
pub fn save(bookmarks: &[NavLocation]) {
    let Some(path) = bookmarks_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
    if let Some(json) = merged(bookmarks, &on_disk) {
        let _ = std::fs::write(&path, json);
    }
}

/// `bookmarks`, then `on_disk`'s unreadable entries, as the file's JSON.
fn merged(bookmarks: &[NavLocation], on_disk: &str) -> Option<String> {
    let mut entries: Vec<serde_json::Value> = bookmarks.iter().filter_map(|b| serde_json::to_value(b).ok()).collect();
    entries.extend(parse(on_disk).1);
    serde_json::to_string_pretty(&entries).ok()
}

#[cfg(test)]
mod tests {
    use crate::app::NavLocation;
    use crate::azure::service::{JumpView, ServiceType};

    #[test]
    fn navlocation_roundtrips_through_json() {
        let loc = NavLocation {
            service: ServiceType::Aks,
            view: Some(JumpView::NodePools),
            subscription: Some("11111111-1111-1111-1111-111111111111".to_string()),
            query: String::new(),
            selected_id: Some("/subscriptions/0/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c".to_string()),
            label: "AKS · c".to_string(),
            details_focused: true,
            detail_section: Some("Node Pools".to_string()),
        };
        let json = serde_json::to_string(std::slice::from_ref(&loc)).unwrap();
        let back: Vec<NavLocation> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].service, ServiceType::Aks);
        assert_eq!(back[0].view, Some(JumpView::NodePools));
        assert_eq!(back[0].subscription.as_deref(), Some("11111111-1111-1111-1111-111111111111"));
        assert_eq!(back[0].label, "AKS · c");
        assert!(back[0].details_focused);
        assert_eq!(back[0].detail_section.as_deref(), Some("Node Pools"));
    }

    #[test]
    fn navlocation_without_detail_depth_fields_defaults() {
        // Bookmark files written before the fields existed must still load.
        let loc = NavLocation {
            service: ServiceType::Aks,
            view: None,
            subscription: None,
            query: String::new(),
            selected_id: None,
            label: "AKS".to_string(),
            details_focused: true,
            detail_section: Some("Tags".to_string()),
        };
        let mut value = serde_json::to_value(&loc).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("details_focused");
        obj.remove("detail_section");
        obj.remove("view");
        obj.remove("subscription");
        let back: NavLocation = serde_json::from_value(value).unwrap();
        assert!(!back.details_focused);
        assert!(back.detail_section.is_none());
        assert!(back.view.is_none(), "a bookmark without a sub-tab lands on the default one");
        assert!(back.subscription.is_none());
    }

    #[test]
    fn corrupt_json_loads_as_empty() {
        assert!(super::parse("not json").0.is_empty());
        assert!(super::parse(r#"{"not": "a list"}"#).0.is_empty());
    }

    fn bookmark(label: &str) -> NavLocation {
        NavLocation {
            service: ServiceType::Aks,
            view: Some(JumpView::NodePools),
            subscription: None,
            query: String::new(),
            selected_id: None,
            label: label.to_string(),
            details_focused: false,
            detail_section: None,
        }
    }

    /// A file a newer nebaz wrote: one entry this build reads, one on a
    /// sub-tab it has never heard of.
    fn file_with_a_newer_entry() -> String {
        let mut newer = serde_json::to_value(bookmark("newer")).unwrap();
        newer["view"] = serde_json::json!("QuantumCircuits");
        serde_json::to_string(&vec![serde_json::to_value(bookmark("web")).unwrap(), newer]).unwrap()
    }

    fn labels(read: &[NavLocation]) -> Vec<&str> {
        read.iter().map(|b| b.label.as_str()).collect()
    }

    #[test]
    fn an_unreadable_entry_skips_only_itself() {
        let (read, unread) = super::parse(&file_with_a_newer_entry());
        assert_eq!(labels(&read), ["web"]);
        assert_eq!(unread.len(), 1);
    }

    #[test]
    fn saving_keeps_the_entries_it_cannot_read() {
        let on_disk = file_with_a_newer_entry();
        let (mut read, _) = super::parse(&on_disk);
        read.push(bookmark("api"));
        let saved = super::merged(&read, &on_disk).unwrap();
        let (read, unread) = super::parse(&saved);
        assert_eq!(labels(&read), ["web", "api"]);
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0]["view"], serde_json::json!("QuantumCircuits"));
        assert_eq!(unread[0]["label"], "newer");
        // Deleting a readable bookmark leaves the unreadable one alone, and
        // a second save doesn't duplicate it.
        let saved = super::merged(&read[1..], &saved).unwrap();
        let (read, unread) = super::parse(&saved);
        assert_eq!(labels(&read), ["api"]);
        assert_eq!(unread.len(), 1);
    }
}
