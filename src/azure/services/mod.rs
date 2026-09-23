//! One provider per service. Each file follows the same shape: row
//! types implementing `Resource`, a `sections!` table per split-pane type,
//! the provider implementing `AzureService`, and `*_section_lines` bodies
//! the app dispatches to. The helpers here are the section-body shapes
//! every service shares.

pub mod stub;
pub mod subscriptions;

use std::collections::HashMap;

/// The one shape for a lazy-fetch failure in a section body.
pub fn error_rows(err: &str) -> Vec<(String, String)> {
    vec![
        (String::new(), String::new()),
        (String::new(), format!("⚠ {}", err)),
    ]
}

/// The Tags section body shared by every type: sorted, or "No tags".
pub fn tag_rows(tags: &HashMap<String, String>) -> Vec<(String, String)> {
    if tags.is_empty() {
        return vec![(String::new(), "No tags".into())];
    }
    let mut tags: Vec<_> = tags.iter().collect();
    tags.sort();
    tags.into_iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}
