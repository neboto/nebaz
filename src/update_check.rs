// ported from neboto-tui src/update_check.rs @ b92e140 (the cadence, the
// version rules, the state file); the request goes through the azure_core
// pipeline (`arm::anonymous_get`, ADR 0008) instead of ureq, and nothing is
// dismissed by a click yet
//! "A newer nebaz is out": a once-a-day check against the latest GitHub
//! Release, surfaced as a dim `↑ vX.Y.Z` chip on the service strip and on
//! the splash's tip line.
//!
//! **The only request nebaz makes that isn't to Azure** (ADR 0008): an
//! anonymous `GET` of [`LATEST_URL`] through `arm::anonymous_get`, the
//! same pipeline and `ReadOnlyPolicy` as every ARM call, minus the bearer
//! policy, so no token goes with it. The read-only guard allows the host in
//! this file only, and `anonymous_get` only from here.
//!
//! On by default, easy to turn off: config `update_check = false`,
//! `--no-update-check`, `NEBAZ_NO_UPDATE_CHECK=1`; never with `CI` set.
//! `main` spawns it from TUI startup only, so the headless subcommands and
//! the tests never reach it.
//!
//! Best-effort throughout, like `bookmarks.rs`: the state file lives in the
//! XDG cache dir, a missing or corrupt one just means "check again", and a
//! failed request (offline, proxy, rate limit) never reaches the status bar.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The releases endpoint. `/latest` never returns drafts or pre-releases, so
/// an `-rc` tag can't announce itself.
pub const LATEST_URL: &str = "https://api.github.com/repos/neboto/nebaz/releases/latest";

/// The upgrade command the splash names — the README's primary install
/// path. nebaz can't tell how it was installed, so binstall users get the
/// release page alongside it.
pub const UPGRADE_COMMAND: &str = "curl -fsSL https://raw.githubusercontent.com/neboto/nebaz/main/install.sh | sh";

/// How long a check's answer is trusted. Unauthenticated GitHub API calls
/// allow 60/hour per IP; one a day per machine is nowhere near that.
const CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// A slow network must not leave a task hanging for the whole session.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// The version this binary was built as.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// What the cache file holds.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateState {
    /// Unix seconds of the last successful check.
    pub checked_at: u64,
    /// The latest release's version, without the `v`.
    pub latest: Option<String>,
}

impl UpdateState {
    /// Whether the cached answer is too old to trust (or there isn't one).
    /// A clock that went backwards counts as stale.
    pub fn is_stale(&self, now: u64) -> bool {
        now < self.checked_at || now - self.checked_at >= CHECK_INTERVAL_SECS
    }

    /// The version to announce, if the cached latest is newer than `current`.
    pub fn announce(&self, current: &str) -> Option<String> {
        let latest = self.latest.as_deref()?;
        is_newer(latest, current).then(|| latest.to_string())
    }
}

/// Whether the check may run at all: `config` is `update_check` after the
/// CLI overlay (`None` = default on), the other two the environment.
pub fn enabled(config: Option<bool>) -> bool {
    off_reason(config).is_none()
}

/// Why the check is off, if it is (what `nebaz doctor` names).
pub fn off_reason(config: Option<bool>) -> Option<&'static str> {
    reason(config, std::env::var_os("NEBAZ_NO_UPDATE_CHECK"), std::env::var_os("CI"))
}

/// [`off_reason`] over explicit values.
fn reason(config: Option<bool>, no_update_check: Option<OsString>, ci: Option<OsString>) -> Option<&'static str> {
    if config == Some(false) {
        Some("turned off: update_check = false, --no-update-check or --demo")
    } else if !no_update_check.is_none_or(|v| v.is_empty() || v == "0") {
        Some("turned off: NEBAZ_NO_UPDATE_CHECK is set")
    } else if ci.is_some() {
        Some("turned off: CI is set")
    } else {
        None
    }
}

/// [`enabled`] over explicit values, for the tests.
#[cfg(test)]
fn allowed(config: Option<bool>, no_update_check: Option<OsString>, ci: Option<OsString>) -> bool {
    reason(config, no_update_check, ci).is_none()
}

/// `$NEBAZ_UPDATE_STATE`, then `$XDG_CACHE_HOME/nebaz/update-check.json`
/// (default `~/.cache/…`).
pub fn state_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("NEBAZ_UPDATE_STATE") {
        return Some(PathBuf::from(p));
    }
    let home = std::env::var("HOME").ok()?;
    let xdg = std::env::var("XDG_CACHE_HOME").unwrap_or_else(|_| format!("{}/.cache", home));
    Some(PathBuf::from(format!("{}/nebaz/update-check.json", xdg)))
}

pub fn load() -> UpdateState {
    state_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(state: &UpdateState) {
    let Some(path) = state_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = std::fs::write(&path, json);
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Ask GitHub for the latest release's version: the one non-Azure request.
pub async fn fetch_latest() -> Result<String, String> {
    let headers = [("accept", "application/vnd.github+json".to_string())];
    let body = crate::azure::arm::anonymous_get(LATEST_URL, &headers, REQUEST_TIMEOUT)
        .await
        .map_err(|e| e.to_string())?;
    version_of(&body)
}

/// The release body's `tag_name`, without the `v`, if it is a version.
fn version_of(body: &Value) -> Result<String, String> {
    let tag = body.get("tag_name").and_then(Value::as_str).ok_or("no tag_name")?;
    let version = tag.trim_start_matches('v').to_string();
    parse(&version).ok_or_else(|| format!("unrecognised release tag {}", tag))?;
    Ok(version)
}

/// `X.Y.Z[-pre][+build]` → `((X, Y, Z), has_pre)`. Anything else is `None`.
fn parse(v: &str) -> Option<((u64, u64, u64), bool)> {
    let v = v.trim().trim_start_matches('v');
    let v = v.split('+').next()?;
    let (core, pre) = match v.split_once('-') {
        Some((core, _)) => (core, true),
        None => (v, false),
    };
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let triple = (it.next()??, it.next()??, it.next()??);
    if it.next().is_some() {
        return None;
    }
    Some((triple, pre))
}

/// Whether `latest` is a release strictly newer than `current`. A pre-release
/// `latest` never counts (the endpoint shouldn't return one, but a manual
/// "latest" flag could), and a local build ahead of the release stays quiet.
pub fn is_newer(latest: &str, current: &str) -> bool {
    let (Some((l, l_pre)), Some((c, c_pre))) = (parse(latest), parse(current)) else {
        return false;
    };
    if l_pre {
        return false;
    }
    // 0.4.0 is newer than 0.4.0-rc.1.
    l > c || (l == c && c_pre)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn newer_compares_numerically() {
        assert!(is_newer("0.3.2", "0.3.1"));
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0.0", "0.99.0"));
        assert!(is_newer("v0.4.0", "0.3.1"));
        assert!(!is_newer("0.3.1", "0.3.1"));
        assert!(!is_newer("0.3.0", "0.3.1"));
    }

    #[test]
    fn prereleases_never_announce_but_release_beats_its_rc() {
        assert!(!is_newer("0.5.0-rc.1", "0.4.0"));
        assert!(is_newer("0.4.0", "0.4.0-rc.1"));
        assert!(!is_newer("0.4.0-rc.2", "0.4.0-rc.1"));
    }

    #[test]
    fn garbage_versions_never_announce() {
        assert!(!is_newer("latest", "0.3.1"));
        assert!(!is_newer("0.4", "0.3.1"));
        assert!(!is_newer("0.4.0.1", "0.3.1"));
        assert!(!is_newer("0.4.0", "dev"));
    }

    #[test]
    fn checks_at_most_once_a_day() {
        let s = UpdateState { checked_at: 1_000_000, ..Default::default() };
        assert!(!s.is_stale(1_000_000));
        assert!(!s.is_stale(1_000_000 + CHECK_INTERVAL_SECS - 1));
        assert!(s.is_stale(1_000_000 + CHECK_INTERVAL_SECS));
        // Clock moved backwards: don't trust the stamp.
        assert!(s.is_stale(999_999));
        assert!(UpdateState::default().is_stale(now_secs()));
    }

    #[test]
    fn announces_only_a_newer_cached_release() {
        let s = UpdateState { latest: Some("0.4.0".into()), ..Default::default() };
        assert_eq!(s.announce("0.3.1").as_deref(), Some("0.4.0"));
        assert_eq!(s.announce("0.4.0"), None);
        assert_eq!(s.announce("0.5.0"), None, "a local build ahead of the release");
        assert_eq!(UpdateState::default().announce("0.3.1"), None);
    }

    #[test]
    fn disabled_by_config_env_or_ci() {
        let os = |s: &str| Some(OsString::from(s));
        assert!(allowed(None, None, None), "on by default");
        assert!(allowed(Some(true), None, None));
        assert!(!allowed(Some(false), None, None), "update_check = false / --no-update-check");
        assert!(!allowed(None, os("1"), None), "NEBAZ_NO_UPDATE_CHECK=1");
        assert!(allowed(None, os("0"), None), "=0 means keep checking");
        assert!(allowed(None, os(""), None));
        assert!(!allowed(None, None, os("true")), "never in CI");
    }

    #[test]
    fn reads_the_release_tag() {
        assert_eq!(version_of(&json!({"tag_name": "v0.4.0"})).as_deref(), Ok("0.4.0"));
        assert!(version_of(&json!({"tag_name": "nightly"})).is_err());
        assert!(version_of(&json!({"message": "API rate limit exceeded"})).is_err());
    }

    /// Hits the real GitHub API — `cargo test live_fetch -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_fetch_returns_a_version() {
        let v = fetch_latest().await.expect("GitHub reachable and a release published");
        assert!(parse(&v).is_some(), "{v}");
    }

    #[test]
    fn corrupt_or_old_state_loads_as_default() {
        assert_eq!(serde_json::from_str::<UpdateState>("{}").unwrap(), UpdateState::default());
        let s: UpdateState = serde_json::from_str(r#"{"latest":"0.4.0","dismissed":"0.3.9"}"#).unwrap();
        assert_eq!(s.latest.as_deref(), Some("0.4.0"));
    }
}
