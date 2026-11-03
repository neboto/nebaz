//! `nebaz doctor`: can this machine reach what nebaz needs, and if not,
//! why. Every check prints its whole error instead of swallowing it: the
//! TUI's update check is silent by design (ADR 0008), so a proxy or a
//! TLS-inspecting middlebox (Zscaler) that breaks it leaves no trace there.
//!
//! The requests are the ones nebaz makes anyway, through the same
//! pipelines: `az account list`, one ARM `GET …/locations`, one Graph
//! `GET /v1.0/applications?$top=1`, and the update check's
//! `GET` of the latest release, which is skipped when the check is off.

use super::{Failure, SCHEMA};
use crate::azure::client::AzureClients;
use crate::cli::{Cli, OutputFormat};
use crate::config::Config;
use crate::error::Error;
use crate::update_check as uc;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// A request that hasn't answered by now won't: a dead proxy, a dropped
/// packet. The pipeline's retries stay inside this.
const PROBE_LIMIT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Ok,
    Info,
    Warn,
    Fail,
    Skip,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Info => "info",
            Status::Warn => "warn",
            Status::Fail => "fail",
            Status::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    /// What to try next, when there is something.
    pub hint: Option<String>,
}

impl Check {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Check { name, status, detail: detail.into(), hint: None }
    }

    fn hint(mut self, hint: Option<String>) -> Self {
        self.hint = hint;
        self
    }
}

/// Run every check; exit 1 when one failed, else 0.
pub(crate) async fn doctor(cli: &Cli, format: OutputFormat) -> Result<(String, i32), Failure> {
    let mut config = Config::load();
    cli.apply_to(&mut config);
    let mut checks = vec![
        Check::new("nebaz", Status::Info, format!("v{} · {} {}", uc::current_version(), std::env::consts::OS, std::env::consts::ARCH)),
    ];
    if let Some(w) = config.load_warning.take() {
        checks.push(Check::new("config", Status::Warn, w));
    }
    checks.push(proxy_check(&env_pairs()));
    checks.push(certificate_check(&env_pairs()));
    let proxied = has_https_proxy(&env_pairs());

    let clients = match AzureClients::new(&config).await {
        Ok(c) => Some(c),
        Err(e) => {
            let detail = match e {
                Error::Auth(a) => super::auth_line(&a.status_line()),
                other => other.to_string(),
            };
            checks.push(Check::new("az login", Status::Fail, detail));
            checks.push(Check::new("arm", Status::Skip, "no login to call with"));
            checks.push(Check::new("graph", Status::Skip, "no login to call with"));
            None
        }
    };
    if let Some(clients) = &clients {
        checks.extend(azure_checks(clients, proxied).await);
    }
    checks.push(update_check(&config, proxied).await);

    let code = if checks.iter().any(|c| c.status == Status::Fail) { 1 } else { 0 };
    Ok((render(&checks, format), code))
}

/// The proxy and certificate variables, as the process sees them.
fn env_pairs() -> Vec<(String, String)> {
    const NAMES: &[&str] = &[
        "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
    ];
    NAMES
        .iter()
        .filter_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()).map(|v| (n.to_string(), v)))
        .collect()
}

fn get<'a>(env: &'a [(String, String)], names: &[&str]) -> Option<(&'a str, &'a str)> {
    names
        .iter()
        .find_map(|n| env.iter().find(|(k, _)| k == n).map(|(k, v)| (k.as_str(), v.as_str())))
}

/// Whether an https request goes through a proxy: HTTPS_PROXY, else
/// ALL_PROXY (HTTP_PROXY applies to plain-http URLs only).
fn has_https_proxy(env: &[(String, String)]) -> bool {
    get(env, &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]).is_some()
}

/// `http://user:secret@proxy:8080` → `http://***@proxy:8080`: a proxy
/// password never reaches the output.
fn redact(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").map(|(s, r)| (format!("{}://", s), r)).unwrap_or((String::new(), url));
    match rest.rsplit_once('@') {
        Some((_, host)) => format!("{}***@{}", scheme, host),
        None => url.to_string(),
    }
}

fn system_proxy_note() -> Option<String> {
    (cfg!(target_os = "macos") || cfg!(windows)).then(|| {
        "nebaz reads the proxy from these variables only, never the system proxy settings or a PAC file: set HTTPS_PROXY when the network needs one".to_string()
    })
}

fn proxy_check(env: &[(String, String)]) -> Check {
    let https = get(env, &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]);
    let http = get(env, &["HTTP_PROXY", "http_proxy"]);
    let no = get(env, &["NO_PROXY", "no_proxy"]);
    let mut parts: Vec<String> = https.iter().map(|(k, v)| format!("{}={}", k, redact(v))).collect();
    parts.extend(no.map(|(k, v)| format!("{}={}", k, v)));
    match (https, http) {
        (None, Some((k, v))) => Check::new("proxy", Status::Warn, format!("only {}={}", k, redact(v))).hint(Some(
            "every nebaz request is https, which uses HTTPS_PROXY or ALL_PROXY, not HTTP_PROXY: set HTTPS_PROXY to the same proxy".into(),
        )),
        (None, None) => Check::new("proxy", Status::Info, "none: HTTPS_PROXY and ALL_PROXY are not set").hint(system_proxy_note()),
        (Some(_), _) => Check::new("proxy", Status::Info, parts.join(" · ")),
    }
}

fn certificate_check(env: &[(String, String)]) -> Check {
    let store = if cfg!(target_os = "macos") {
        "the macOS Keychain (the system's trust settings, as Safari uses)"
    } else if cfg!(windows) {
        "the Windows certificate store"
    } else {
        "the system CA bundle (/etc/ssl/certs, or SSL_CERT_FILE / SSL_CERT_DIR)"
    };
    let mut detail = format!("verified against {}", store);
    if !cfg!(any(target_os = "macos", windows)) {
        for (k, v) in env.iter().filter(|(k, _)| k.starts_with("SSL_CERT_")) {
            detail.push_str(&format!(" · {}={}", k, v));
        }
    }
    let hint = (get(env, &["REQUESTS_CA_BUNDLE"]).is_some() && get(env, &["SSL_CERT_FILE"]).is_none()).then(|| {
        if cfg!(any(target_os = "macos", windows)) {
            "REQUESTS_CA_BUNDLE is set: that is the Azure CLI's own setting, nebaz trusts the OS store; add the CA there".to_string()
        } else {
            "REQUESTS_CA_BUNDLE is set: that is the Azure CLI's own setting; for nebaz, set SSL_CERT_FILE to the same bundle".to_string()
        }
    });
    Check::new("certificates", Status::Info, detail).hint(hint)
}

/// What to try after a failed request, read from its error text.
fn network_hint(err: &str, proxied: bool) -> Option<String> {
    let e = err.to_ascii_lowercase();
    if e.contains("certificate") || e.contains("unknownissuer") || e.contains("unknown issuer") {
        let fix = if cfg!(target_os = "macos") {
            "add it to the System keychain and mark it trusted"
        } else if cfg!(windows) {
            "add it to Trusted Root Certification Authorities"
        } else {
            "copy it to /usr/local/share/ca-certificates/ and run update-ca-certificates, or point SSL_CERT_FILE at a bundle with it (WSL does not see the Windows store)"
        };
        return Some(format!(
            "the server's certificate is not trusted: a TLS-inspecting proxy (Zscaler, Netskope…) signs with its own root CA; {}",
            fix
        ));
    }
    if e.contains("tunnel") || (proxied && e.contains("connect")) {
        return Some("the proxy in HTTPS_PROXY / ALL_PROXY refused or failed the connection: check its host, port and credentials".into());
    }
    if !proxied && (e.contains("connect") || e.contains("dns") || e.contains("no answer within")) {
        return Some(match system_proxy_note() {
            Some(note) => format!("no direct connection: if this network needs a proxy, {}", note.split_once(": ").map(|(_, t)| t).unwrap_or(&note)),
            None => "no direct connection: if this network needs a proxy, set HTTPS_PROXY".into(),
        });
    }
    None
}

async fn timed<T>(f: impl std::future::Future<Output = Result<T, String>>) -> (Result<T, String>, Duration) {
    let start = Instant::now();
    let r = match tokio::time::timeout(PROBE_LIMIT, f).await {
        Ok(r) => r,
        Err(_) => Err(format!("no answer within {}s", PROBE_LIMIT.as_secs())),
    };
    (r, start.elapsed())
}

async fn azure_checks(clients: &AzureClients, proxied: bool) -> Vec<Check> {
    let mut checks = Vec::new();
    let Some(sub) = clients.current_subscription().map(str::to_string) else {
        let detail = match clients.auth_error() {
            Some(a) => super::auth_line(&a.status_line()),
            None => "logged in, but `az account list` shows no enabled subscription".into(),
        };
        checks.push(Check::new("az login", Status::Fail, detail));
        checks.push(Check::new("arm", Status::Skip, "no subscription to call"));
        checks.push(Check::new("graph", Status::Skip, "no subscription to call"));
        return checks;
    };
    checks.push(Check::new(
        "az login",
        Status::Ok,
        format!(
            "{} subscriptions · current {} ({})",
            clients.subscriptions().len(),
            clients.current_subscription_name().unwrap_or("-"),
            sub
        ),
    ));

    let endpoint = if clients.is_demo() {
        "the demo tenant (answered offline)".to_string()
    } else {
        clients.endpoint().to_string()
    };
    let (r, took) = timed(clients.locations_fetch(&sub)).await;
    checks.push(match r {
        Ok(locs) => Check::new("arm", Status::Ok, format!("{} · {} locations · {} ms", endpoint, locs.len(), took.as_millis())),
        Err(e) => Check::new("arm", Status::Fail, format!("{} · {}", endpoint, e)).hint(network_hint(&e, proxied)),
    });

    let graph = clients.current_graph();
    let (r, took) = timed(async move {
        graph?
            .graph_get(crate::azure::graph::APPLICATIONS_PATH, &[("$top", "1")])
            .await
            .map_err(|e| e.to_string())
    })
    .await;
    checks.push(match r {
        Ok(_) => Check::new("graph", Status::Ok, format!("directory readable · {} ms", took.as_millis())),
        Err(e) if crate::azure::graph::is_denied(&e) => Check::new(
            "graph",
            Status::Warn,
            format!("{}: the Identity tab will be empty · {}", crate::azure::graph::DIRECTORY_READ_DENIED, e),
        ),
        Err(e) => Check::new("graph", Status::Fail, e.clone()).hint(network_hint(&e, proxied)),
    });
    checks
}

/// The release check, with its error, and what the TUI has cached. A
/// success is saved, as the TUI's check saves it.
async fn update_check(config: &Config, proxied: bool) -> Check {
    let cached = uc::load();
    let state = match (uc::state_path(), cached.checked_at) {
        (Some(p), 0) => format!("{}: never written", p.display()),
        (Some(p), at) => format!("{}: v{} at {}", p.display(), cached.latest.as_deref().unwrap_or("?"), crate::azure::services::json::time(Some(crate::azure::metrics::iso_utc(at as i64)))),
        (None, _) => "no state file (HOME is not set)".into(),
    };
    if let Some(why) = uc::off_reason(config.update_check) {
        return Check::new("update check", Status::Skip, format!("{} · {}", why, state));
    }
    let (r, took) = timed(uc::fetch_latest()).await;
    match r {
        Ok(latest) => {
            let fresh = uc::UpdateState { checked_at: uc::now_secs(), latest: Some(latest.clone()) };
            uc::save(&fresh);
            let verdict = match fresh.announce(uc::current_version()) {
                Some(v) => format!("v{} is out (this is v{})", v, uc::current_version()),
                None => "up to date".into(),
            };
            Check::new("update check", Status::Ok, format!("{} · latest v{} · {} ms", verdict, latest, took.as_millis()))
        }
        // The transport's error type is the Azure one; this host is GitHub.
        Err(e) => Check::new("update check", Status::Fail, format!("{} · {}", uc::LATEST_URL, e.trim_start_matches("Azure error: ")))
            .hint(network_hint(&e, proxied).or(Some(format!("the TUI's check fails silently the same way · {}", state)))),
    }
}

pub(crate) fn render(checks: &[Check], format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => {
            let items: Vec<Value> = checks
                .iter()
                .map(|c| json!({"name": c.name, "status": c.status.as_str(), "detail": c.detail, "hint": c.hint}))
                .collect();
            super::pretty(&json!({"schema": SCHEMA, "ok": !checks.iter().any(|c| c.status == Status::Fail), "checks": items}))
        }
        OutputFormat::Md => {
            let mut out = String::from("# nebaz doctor\n\n| Check | Status | Detail |\n| --- | --- | --- |\n");
            for c in checks {
                out.push_str(&format!("| {} | {} | {} |\n", c.name, c.status.as_str(), c.detail.replace('|', "\\|")));
            }
            let hints: Vec<&Check> = checks.iter().filter(|c| c.hint.is_some()).collect();
            if !hints.is_empty() {
                out.push('\n');
                for c in hints {
                    out.push_str(&format!("- **{}**: {}\n", c.name, c.hint.as_deref().unwrap_or_default()));
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn proxy_passwords_never_print() {
        assert_eq!(redact("http://alice:s3cret@proxy.corp:8080"), "http://***@proxy.corp:8080");
        assert_eq!(redact("http://proxy.corp:8080"), "http://proxy.corp:8080");
        let c = proxy_check(&env(&[("HTTPS_PROXY", "http://alice:s3cret@proxy.corp:8080"), ("NO_PROXY", "localhost")]));
        assert_eq!(c.status, Status::Info);
        assert!(!c.detail.contains("s3cret"), "{}", c.detail);
        assert!(c.detail.contains("NO_PROXY=localhost"));
    }

    #[test]
    fn http_proxy_alone_is_a_warning_since_every_request_is_https() {
        let c = proxy_check(&env(&[("http_proxy", "http://proxy.corp:8080")]));
        assert_eq!(c.status, Status::Warn);
        assert!(c.hint.unwrap().contains("HTTPS_PROXY"));
        assert!(!has_https_proxy(&env(&[("HTTP_PROXY", "http://p:1")])));
        assert!(has_https_proxy(&env(&[("all_proxy", "socks5://p:1")])));
    }

    #[test]
    fn hints_name_the_untrusted_root_and_the_proxy() {
        let tls = "connection failed: invalid peer certificate: UnknownIssuer";
        assert!(network_hint(tls, true).unwrap().contains("root CA"));
        let tunnel = "client error (Connect): tunnel error: failed to create underlying connection";
        assert!(network_hint(tunnel, true).unwrap().contains("HTTPS_PROXY"));
        assert!(network_hint("tcp connect error: Connection refused", false).unwrap().contains("proxy"));
        assert_eq!(network_hint("404 Not Found", false), None);
    }

    #[test]
    fn requests_ca_bundle_is_called_out_as_az_only() {
        let c = certificate_check(&env(&[("REQUESTS_CA_BUNDLE", "/etc/zscaler.pem")]));
        assert!(c.hint.unwrap().contains("Azure CLI's own setting"));
        assert!(certificate_check(&env(&[])).hint.is_none());
    }

    #[test]
    fn render_carries_ok_and_every_check() {
        let checks = vec![
            Check::new("proxy", Status::Info, "none"),
            Check::new("arm", Status::Fail, "a | b").hint(Some("try x".into())),
        ];
        let v: Value = serde_json::from_str(&render(&checks, OutputFormat::Json)).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["checks"][1]["status"], "fail");
        assert_eq!(v["checks"][1]["hint"], "try x");
        let md = render(&checks, OutputFormat::Md);
        assert!(md.contains("| arm | fail | a \\| b |"));
        assert!(md.contains("- **arm**: try x"));
    }
}
