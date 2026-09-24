//! One provider per service. Each file follows the same shape: row
//! types implementing `Resource` (an [`ArmBase`] plus the type's own
//! fields, parsed from the list body and kept raw for `e`), a `sections!`
//! table per split-pane type, the provider implementing `AzureService`
//! over a [`Scope`], and `*_section_lines` bodies the app dispatches to.
//! The helpers here are the pieces every service shares.

pub mod aks;
pub mod compute;
pub mod foundry;
pub mod keyvault;
pub mod network;
pub mod network_edge;
pub mod storage;
pub mod subscriptions;

use crate::azure::arm::ArmClient;
use crate::azure::auth::{AuthError, SubscriptionEntry};
use crate::azure::resource::Resource;
use crate::azure::service::ServiceType;
use crate::error::{Error, Result};
use crate::event::{Event, LoadProgress};
use crate::lazy::Lazy;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

// ── Section-body shapes ───────────────────────────────────────────────

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

/// The Overview body every type shares: `details()`, then the portal
/// link and the copied `az` command.
pub fn overview_rows(r: &dyn Resource) -> Vec<(String, String)> {
    let mut lines = r.details();
    lines.push((String::new(), String::new()));
    lines.push(("Portal".into(), r.portal_url().unwrap_or_default()));
    lines.push(("CLI".into(), r.cli_command().unwrap_or_default()));
    lines
}

/// The Related body: the row's labelled ARM ids, Enter jumps.
pub fn related_rows(r: &dyn Resource) -> Vec<(String, String)> {
    let mut lines = r.related();
    if lines.is_empty() {
        lines.push((String::new(), "No related resources".into()));
        return lines;
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "⏎ on a line jumps to it (y copies the id)".into()));
    lines
}

/// A lazy section whose payload is a list of ARM objects: the three arms,
/// with `render` turning the loaded list into lines.
pub fn lazy_list_rows(
    lazy: Option<&Lazy<Vec<Value>>>,
    what: &str,
    render: impl FnOnce(&[Value]) -> Vec<(String, String)>,
) -> Vec<(String, String)> {
    match lazy {
        None | Some(Lazy::Loading) => vec![(what.into(), "Loading…".into())],
        Some(Lazy::Error(e)) => error_rows(e),
        Some(Lazy::Loaded(items)) => render(items),
    }
}

// ── The fields every ARM row has ──────────────────────────────────────

/// The top-level envelope of every ARM resource: what the list body gives
/// for free before a type's own `properties`.
#[derive(Debug, Clone)]
pub struct ArmBase {
    pub id: String,
    pub name: String,
    pub location: String,
    pub tags: HashMap<String, String>,
    pub provisioning_state: Option<String>,
    pub tenant: Option<String>,
    pub raw: String,
}

impl ArmBase {
    /// Parse the envelope; `None` without an `id`.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ArmBase> {
        let id = json::str_at(v, "/id")?;
        let name = json::str_at(v, "/name")
            .unwrap_or_else(|| crate::azure::resource::name_of_id(&id).to_string());
        Some(ArmBase {
            name,
            location: json::str_at(v, "/location").unwrap_or_default().to_lowercase(),
            tags: json::tags_of(v),
            provisioning_state: json::str_at(v, "/properties/provisioningState"),
            tenant: tenant.map(str::to_string),
            raw: serde_json::to_string_pretty(v).unwrap_or_default(),
            id,
        })
    }
}

/// The `Resource` methods every `ArmBase`-carrying row answers the same
/// way. Used inside an `impl Resource for …` block.
macro_rules! arm_row {
    ($kind:expr) => {
        fn id(&self) -> &str {
            &self.base.id
        }
        fn name(&self) -> &str {
            &self.base.name
        }
        fn resource_type(&self) -> &str {
            $kind
        }
        fn tags(&self) -> &std::collections::HashMap<String, String> {
            &self.base.tags
        }
        fn location(&self) -> Option<&str> {
            Some(&self.base.location)
        }
        fn tenant_id(&self) -> Option<&str> {
            self.base.tenant.as_deref()
        }
        fn raw_content(&self) -> Option<String> {
            Some(self.base.raw.clone())
        }
        fn clone_box(&self) -> Box<dyn crate::azure::resource::Resource> {
            Box::new(self.clone())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    };
}
pub(crate) use arm_row;

// ── The provider's scope ──────────────────────────────────────────────

/// What a provider is pointed at: the current subscription's tenant
/// pipeline (or the auth condition that prevents one) and the
/// subscription entry itself.
pub struct Scope {
    arm: std::result::Result<Arc<ArmClient>, AuthError>,
    current: Option<SubscriptionEntry>,
}

impl Scope {
    pub fn new(arm: std::result::Result<Arc<ArmClient>, AuthError>, current: Option<SubscriptionEntry>) -> Self {
        Self { arm, current }
    }

    pub fn arm(&self) -> Result<&Arc<ArmClient>> {
        self.arm.as_ref().map_err(|e| Error::Auth(e.clone()))
    }

    pub fn current(&self) -> Result<&SubscriptionEntry> {
        self.current
            .as_ref()
            .ok_or_else(|| Error::Auth(self.arm.as_ref().err().cloned().unwrap_or(AuthError::NotLoggedIn)))
    }

    pub fn tenant(&self) -> Option<&str> {
        self.current.as_ref().map(|c| c.tenant_id.as_str())
    }

    /// `/subscriptions/{current}{suffix}`.
    pub fn path(&self, suffix: &str) -> Result<String> {
        Ok(format!("/subscriptions/{}{}", self.current()?.id, suffix))
    }

    /// One whole subscription-wide collection.
    pub async fn list(&self, suffix: &str, api_version: &str) -> Result<Vec<Value>> {
        self.arm()?.list(&self.path(suffix)?, api_version).await
    }

    /// One whole collection with extra query pairs (`statusOnly=true`).
    pub async fn list_query(&self, suffix: &str, api_version: &str, query: &[(&str, &str)]) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        self.arm()?
            .list_pages(&self.path(suffix)?, api_version, query, |page| all.extend(page))
            .await?;
        Ok(all)
    }

    /// One resource by ARM id.
    pub async fn get(&self, id: &str, api_version: &str) -> Result<Value> {
        self.arm()?.get(id, api_version).await
    }

    /// Stream a subscription-wide collection: every page becomes one
    /// `ResourcesPartiallyLoaded` of `rows(page)`. Returns how many rows
    /// landed; the caller decides how the stream ends ([`finish_stream`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn stream<F>(
        &self,
        suffix: &str,
        api_version: &str,
        query: &[(&str, &str)],
        service: ServiceType,
        message: &str,
        event_tx: &mpsc::UnboundedSender<Event>,
        mut rows: F,
    ) -> Result<usize>
    where
        F: FnMut(Vec<Value>) -> Vec<Box<dyn Resource>> + Send,
    {
        let path = self.path(suffix)?;
        let arm = self.arm()?;
        let mut loaded = 0usize;
        arm.list_pages(&path, api_version, query, |page| {
            let resources = rows(page);
            loaded += resources.len();
            let _ = event_tx.send(Event::ResourcesPartiallyLoaded {
                service,
                resources,
                progress: LoadProgress {
                    loaded_count: loaded,
                    total_count: None,
                    status_message: Some(message.to_string()),
                },
            });
        })
        .await?;
        Ok(loaded)
    }
}

/// End a streamed load: `ResourcesFullyLoaded` on success, one
/// `ResourceLoadError` (auth-classified) on failure.
pub fn finish_stream(
    service: ServiceType,
    result: Result<usize>,
    event_tx: &mpsc::UnboundedSender<Event>,
) -> Result<()> {
    match result {
        Ok(total) => {
            let _ = event_tx.send(Event::ResourcesFullyLoaded {
                service,
                total_count: total,
            });
            Ok(())
        }
        Err(e) => {
            let _ = event_tx.send(Event::ResourceLoadError {
                service,
                auth: e.auth_error(),
                error: e.to_string(),
            });
            Err(e)
        }
    }
}

// ── JSON helpers ──────────────────────────────────────────────────────

/// Small readers over `serde_json::Value` by JSON pointer, plus the
/// display conventions every section body uses (`-` for absent).
pub mod json {
    use serde_json::Value;
    use std::collections::HashMap;

    pub fn str_at(v: &Value, ptr: &str) -> Option<String> {
        match v.pointer(ptr)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// The string at `ptr`, or `-`.
    pub fn text(v: &Value, ptr: &str) -> String {
        str_at(v, ptr).unwrap_or_else(|| "-".into())
    }

    pub fn bool_at(v: &Value, ptr: &str) -> Option<bool> {
        v.pointer(ptr).and_then(|b| b.as_bool())
    }

    pub fn int_at(v: &Value, ptr: &str) -> Option<i64> {
        v.pointer(ptr).and_then(|n| n.as_i64())
    }

    pub fn arr(v: &Value, ptr: &str) -> Vec<Value> {
        v.pointer(ptr)
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default()
    }

    /// The `id` of the object at `ptr` (`{"subnet": {"id": "…"}}`).
    pub fn id_at(v: &Value, ptr: &str) -> Option<String> {
        str_at(v, &format!("{}/id", ptr))
    }

    /// The `id`s of the objects in the array at `ptr`.
    pub fn ids_at(v: &Value, ptr: &str) -> Vec<String> {
        arr(v, ptr)
            .iter()
            .filter_map(|o| str_at(o, "/id"))
            .collect()
    }

    /// The strings in the array at `ptr`.
    pub fn strings_at(v: &Value, ptr: &str) -> Vec<String> {
        arr(v, ptr)
            .iter()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect()
    }

    pub fn tags_of(v: &Value) -> HashMap<String, String> {
        v.get("tags")
            .and_then(|t| t.as_object())
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn opt(s: Option<String>) -> String {
        s.filter(|s| !s.is_empty()).unwrap_or_else(|| "-".into())
    }

    pub fn yes_no(b: Option<bool>) -> String {
        match b {
            Some(true) => "yes".into(),
            Some(false) => "no".into(),
            None => "-".into(),
        }
    }

    pub fn num(n: Option<i64>) -> String {
        n.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
    }

    /// `a, b, c` or `-`.
    pub fn join(items: &[String]) -> String {
        if items.is_empty() {
            "-".into()
        } else {
            items.join(", ")
        }
    }

    /// An ISO-8601 timestamp trimmed to the second: `2024-01-02 03:04:05`.
    pub fn time(s: Option<String>) -> String {
        match s {
            Some(s) if s.len() >= 19 => s[..19].replacen('T', " ", 1),
            Some(s) if !s.is_empty() => s,
            _ => "-".into(),
        }
    }

    /// A Key Vault attribute time: a Unix timestamp (the ARM shape) or an
    /// ISO string, rendered to the minute.
    pub fn unix_or_time(v: Option<&Value>) -> String {
        match v {
            Some(Value::Number(n)) => n.as_i64().map(unix_to_ymdhm).unwrap_or_else(|| "-".into()),
            Some(Value::String(s)) => time(Some(s.clone())),
            _ => "-".into(),
        }
    }

    /// Unix seconds → `YYYY-MM-DD HH:MM` (UTC), without a date crate.
    pub fn unix_to_ymdhm(secs: i64) -> String {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        // Howard Hinnant's civil-from-days.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, rem / 3600, (rem % 3600) / 60)
    }

    /// `Some(s)` only when the string is an ARM id under a subscription.
    pub fn arm_id(s: Option<String>) -> Option<String> {
        s.filter(|s| s.starts_with("/subscriptions/"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn unix_times_render_in_utc() {
            assert_eq!(unix_to_ymdhm(0), "1970-01-01 00:00");
            assert_eq!(unix_to_ymdhm(1_700_000_000), "2023-11-14 22:13");
            assert_eq!(time(Some("2024-01-02T03:04:05.1234567Z".into())), "2024-01-02 03:04:05");
            assert_eq!(unix_or_time(Some(&serde_json::json!(1_700_000_000))), "2023-11-14 22:13");
        }
    }
}
