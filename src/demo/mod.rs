// adapted from neboto-tui src/demo/mod.rs @ b92e140 (the idea: answer every
// request from embedded fixtures at the HTTP layer; nebaz matches ARM and
// Graph paths instead of AWS operations)
//! Demo mode (`nebaz --demo`, #45): a canned, offline tenant with two
//! subscriptions, `contoso-prod` and `contoso-dev`, and problems planted in
//! them to find (`docs/DEMO.md` tells the story).
//!
//! Demo mode is a **credential source** (`auth = "demo"`, ADR 0003's
//! explicit source): `ArmClient::build` gives such a pipeline
//! [`DemoCredential`] (a fixed token, no `az`) and [`DemoTransport`] in
//! place of the network, and `AzureClients` reads [`subscriptions`] in
//! place of `az account list`. Nothing above the pipeline knows: list
//! loads, lazy sections, Graph reads, the lens, metrics and jumps all run
//! their real requests, so a feature gets demo coverage by adding a
//! fixture, not code. The transport still sits under `ReadOnlyPolicy`.
//!
//! Lookup is by **path** (ARM or Graph, `*` matching one segment, case
//! insensitive like ARM itself), optionally narrowed by substrings of the
//! decoded query (`when`), first match wins ([`fixtures`]). A few bodies
//! are computed per request instead ([`generate`]: metric series over the
//! asked-for timespan). A request with no fixture answers like Azure does
//! for "none": an empty `{"value": []}` for a collection, a `404
//! ResourceNotFound` for a single resource.
//!
//! `NEBAZ_DEMO_TRACE=<file>` appends one line per request, saying which
//! fixture (or `EMPTY` / `404`) answered it: the way to find what a new
//! screen asks for. `NEBAZ_DEMO_LATENCY=0` turns off the made-up network
//! delay (recordings want it; tests don't).

pub mod fixtures;
mod generate;
#[cfg(test)]
mod tests;

use crate::azure::auth::SubscriptionEntry;
use async_trait::async_trait;
use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::http::headers::Headers;
use azure_core::http::{AsyncRawResponse, HttpClient, Request, StatusCode};
use std::io::Write as _;
use std::sync::Mutex;
use std::time::Duration;

/// The demo tenant (`contoso.onmicrosoft.com`).
pub const TENANT: &str = "a1c3e5f7-2b4d-4f6a-8c0e-1d3f5a7b9c2e";
/// `contoso-prod`: where the story happens.
pub const PROD: &str = "8f4c2a1e-6b3d-4e7a-9c15-2d8e0f6a7b31";
/// `contoso-dev`: a second subscription, for `P` and `--subscriptions`.
pub const DEV: &str = "3b9e7d52-1a4f-4c8b-b2e6-7f0a9d1c5e48";
/// The signed-in user every picker and "who did it" line names.
pub const USER: &str = "alex.kim@contoso.com";

/// The `az account list` stand-in: prod is the default.
pub fn subscriptions() -> Vec<SubscriptionEntry> {
    let entry = |id: &str, name: &str, default: bool| SubscriptionEntry {
        id: id.to_string(),
        name: name.to_string(),
        tenant_id: TENANT.to_string(),
        state: "Enabled".to_string(),
        is_default: default,
        cloud_name: Some("AzureCloud".to_string()),
        user: Some(USER.to_string()),
    };
    vec![entry(PROD, "contoso-prod", true), entry(DEV, "contoso-dev", false)]
}

/// A fixed token: the bearer policy wants one, nothing ever checks it.
#[derive(Debug)]
pub struct DemoCredential;

#[async_trait]
impl TokenCredential for DemoCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let expires = azure_core::time::OffsetDateTime::now_utc() + azure_core::time::Duration::hours(1);
        Ok(AccessToken::new("nebaz-demo-token", expires))
    }
}

/// The pipeline's HTTP client in demo mode: answers from the fixtures and
/// never opens a socket.
#[derive(Debug)]
pub struct DemoTransport;

#[async_trait]
impl HttpClient for DemoTransport {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        let url = request.url();
        let query = decoded_query(url.query().unwrap_or(""));
        let reply = respond(url.path(), &query, now_secs());
        trace(&reply, url.path(), &query);
        if let Some(delay) = latency(url.path(), &reply) {
            tokio::time::sleep(delay).await;
        }
        let mut headers = Headers::new();
        headers.insert("content-type", "application/json; charset=utf-8");
        headers.insert("x-ms-request-id", "nebaz-demo");
        let status = StatusCode::from(reply.status);
        Ok(AsyncRawResponse::from_bytes(status, headers, reply.body.into_bytes()))
    }
}

/// Where a reply came from, for the trace and the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A stored fixture, by its file name.
    Fixture(&'static str),
    /// Computed for this request ([`generate`]).
    Generated(&'static str),
    /// No fixture; an empty collection.
    Empty,
    /// No fixture; a single resource that does not exist.
    NotFound,
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub source: Source,
}

/// Answer one `GET`: `path` as sent, `query` decoded (`key=value&…`),
/// `now` in Unix seconds for the relative timestamps.
pub fn respond(path: &str, query: &str, now: i64) -> Reply {
    respond_from(fixtures::AREAS, path, query, now)
}

pub(crate) fn respond_from(areas: &[&[fixtures::Fixture]], path: &str, query: &str, now: i64) -> Reply {
    if let Some((name, body)) = generate::respond(path, query, now) {
        return Reply {
            status: 200,
            body,
            source: Source::Generated(name),
        };
    }
    let query_lower = query.to_lowercase();
    if let Some(f) = areas
        .iter()
        .flat_map(|a| a.iter())
        .find(|f| path_matches(f.path, path) && f.when.iter().all(|w| query_lower.contains(&w.to_lowercase())))
    {
        return Reply {
            status: f.status,
            body: render(f.body, now),
            source: Source::Fixture(f.file),
        };
    }
    if is_collection(path) {
        Reply {
            status: 200,
            body: r#"{"value": []}"#.to_string(),
            source: Source::Empty,
        }
    } else {
        Reply {
            status: 404,
            body: r#"{"error": {"code": "ResourceNotFound", "message": "Not in the nebaz demo dataset."}}"#.to_string(),
            source: Source::NotFound,
        }
    }
}

/// Whether a fixture's path pattern (placeholders allowed, `*` = any one
/// segment) matches a request path. ARM paths are case-insensitive.
pub(crate) fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern = substitute_ids(pattern).to_lowercase();
    let path = path.to_lowercase();
    let mut want = pattern.trim_matches('/').split('/');
    let mut got = path.trim_matches('/').split('/');
    loop {
        match (want.next(), got.next()) {
            (None, None) => return true,
            (Some(w), Some(g)) if w == "*" || w == g => {}
            _ => return false,
        }
    }
}

/// Whether an unmatched path names a collection (answered `{"value": []}`)
/// or one resource (answered 404). ARM alternates type / name segments
/// after the last provider namespace, and before any (`subscriptions/x/
/// resourceGroups`); Graph alternates after the version.
pub(crate) fn is_collection(path: &str) -> bool {
    let segs: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    if segs.first().is_some_and(|s| s.starts_with("v1.0") || s.starts_with("beta")) {
        return (segs.len() - 1) % 2 == 1;
    }
    match segs.iter().rposition(|s| s.eq_ignore_ascii_case("providers")) {
        // `…/providers/{Namespace}/{type}/{name}/…`: an odd count after the
        // namespace ends on a type.
        Some(i) if i + 1 < segs.len() => (segs.len() - (i + 2)) % 2 == 1,
        // `/subscriptions/x/providers`: the provider list.
        Some(_) => true,
        None => segs.len() % 2 == 1,
    }
}

/// The demo ids: `{{prod}}`, `{{dev}}`, `{{tenant}}`.
fn substitute_ids(text: &str) -> String {
    text.replace("{{prod}}", PROD)
        .replace("{{dev}}", DEV)
        .replace("{{tenant}}", TENANT)
}

/// A fixture body with its placeholders filled: the ids, and
/// `{{iso:now-15m}}` / `{{iso:now+30d}}` (units `s m h d`) as UTC
/// timestamps relative to `now`, so the dataset never ages.
pub fn render(body: &str, now: i64) -> String {
    let body = substitute_ids(body);
    let mut out = String::with_capacity(body.len());
    let mut rest = body.as_str();
    while let Some(start) = rest.find("{{iso:") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 6..];
        match after.find("}}").and_then(|end| relative(&after[..end], now).map(|t| (end, t))) {
            Some((end, t)) => {
                out.push_str(&crate::azure::metrics::iso_utc(t));
                rest = &after[end + 2..];
            }
            None => {
                out.push_str("{{iso:");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `now`, `now-15m`, `now+30d` → Unix seconds.
fn relative(spec: &str, now: i64) -> Option<i64> {
    let spec = spec.trim();
    let offset = spec.strip_prefix("now")?;
    if offset.is_empty() {
        return Some(now);
    }
    let (sign, amount) = match offset.as_bytes()[0] {
        b'-' => (-1, &offset[1..]),
        b'+' => (1, &offset[1..]),
        _ => return None,
    };
    let unit = amount.chars().last()?;
    let n: i64 = amount[..amount.len() - unit.len_utf8()].parse().ok()?;
    let secs = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return None,
    };
    Some(now + sign * n * secs)
}

/// `a=b%20c&d=e` → `a=b c&d=e`: `when` matches what a reader would write.
fn decoded_query(raw: &str) -> String {
    azure_core::http::Url::parse(&format!("https://x/?{raw}"))
        .map(|u| {
            u.query_pairs()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&")
        })
        .unwrap_or_else(|_| raw.to_string())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A made-up network delay, steady per path so a recording replays the
/// same way: collections 0.2–0.7 s, single resources 0.08–0.3 s.
fn latency(path: &str, reply: &Reply) -> Option<Duration> {
    if cfg!(test) || std::env::var("NEBAZ_DEMO_LATENCY").is_ok_and(|v| v.trim() == "0") {
        return None;
    }
    let h = path.bytes().fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
    let ms = if is_collection(path) && reply.status == 200 {
        200 + h % 500
    } else {
        80 + h % 220
    };
    Some(Duration::from_millis(ms))
}

static TRACE: Mutex<()> = Mutex::new(());

/// `NEBAZ_DEMO_TRACE=<file>`: one line per request, what answered it.
fn trace(reply: &Reply, path: &str, query: &str) {
    let Ok(file) = std::env::var("NEBAZ_DEMO_TRACE") else {
        return;
    };
    let what = match &reply.source {
        Source::Fixture(f) => format!("fixture {f}"),
        Source::Generated(g) => format!("generated {g}"),
        Source::Empty => "EMPTY".to_string(),
        Source::NotFound => "404".to_string(),
    };
    let _one_writer = TRACE.lock();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(file) {
        let _ = writeln!(f, "{what}\tGET {path}?{query}");
    }
}
