//! Credentials (ADR 0003): the explicit credential source, the thin
//! `TokenCredential` wrapper around `azure_identity`'s `AzureCliCredential`
//! (a timeout, one `az` at a time, and the CLI's stderr classified into one
//! [`AuthError`]), and the `az account list` reader that feeds the `P`
//! picker and the subscription → tenant table.
//!
//! Nothing here caches tokens: the pipeline's `BearerTokenAuthorizationPolicy`
//! does, per tenant (see `arm.rs`).

use crate::error::{Error, Result};
use async_trait::async_trait;
use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::error::ErrorKind;
use azure_identity::{AzureCliCredential, AzureCliCredentialOptions};
use std::sync::Arc;
use std::time::Duration;

/// How long one `az` invocation may take before it counts as hung.
pub const AZ_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the Azure CLI's install instructions live — the one line printed
/// when `az` is missing.
pub const AZ_INSTALL_URL: &str = "https://aka.ms/azure-cli";

/// The minimum Azure CLI: `az account get-access-token` gained the
/// `expires_on` field the credential needs in 2.54.0.
pub const AZ_MIN_VERSION: &str = "2.54.0";

/// Where tokens come from. Chosen explicitly in config (`auth = "cli"`,
/// env `NEBAZ_AUTH`), never guessed from the environment. Only `cli`
/// exists in the first release; the others parse and fail with "not
/// supported yet" so the config key is stable from day one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    /// `az login` — the Azure CLI's account cache.
    Cli,
    /// Service-principal environment variables (later).
    Environment,
    /// Managed identity (later).
    ManagedIdentity,
}

impl CredentialSource {
    /// The config spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialSource::Cli => "cli",
            CredentialSource::Environment => "environment",
            CredentialSource::ManagedIdentity => "managed-identity",
        }
    }

    pub fn parse(s: &str) -> Option<CredentialSource> {
        match s.trim().to_lowercase().as_str() {
            "cli" | "azure-cli" | "az" => Some(CredentialSource::Cli),
            "environment" | "env" => Some(CredentialSource::Environment),
            "managed-identity" | "managedidentity" | "msi" => Some(CredentialSource::ManagedIdentity),
            _ => None,
        }
    }

    /// Resolve from the config value with `NEBAZ_AUTH` overriding it;
    /// default `cli`. An unknown spelling is a config error, not a fallback.
    pub fn resolve(config_value: Option<&str>) -> Result<CredentialSource> {
        let env = std::env::var("NEBAZ_AUTH").ok();
        let (value, origin) = match (env.as_deref(), config_value) {
            (Some(e), _) if !e.trim().is_empty() => (e, "NEBAZ_AUTH"),
            (_, Some(c)) => (c, "auth"),
            _ => return Ok(CredentialSource::Cli),
        };
        CredentialSource::parse(value).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "{} = {:?} is not a credential source (cli | environment | managed-identity)",
                origin, value
            ))
        })
    }
}

/// The single, app-wide condition that tokens cannot be obtained. Rendered
/// as one status-bar line with the fix; it replaces per-service load errors
/// while it holds and clears on the next successful token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// `az` is not on PATH — fatal before the TUI opens.
    CliMissing,
    /// `az` predates 2.54.0 and returns no `expires_on`.
    CliTooOld,
    /// No account in the CLI's cache.
    NotLoggedIn,
    /// The CLI's refresh token has expired (AADSTS700082 and friends).
    TokenExpired,
    /// `az` did not answer within [`AZ_TIMEOUT`].
    Timeout,
    /// A credential failure this build doesn't recognise; the raw text.
    Other(String),
}

impl AuthError {
    /// Classify an `az` stderr / credential error message, loosely: the
    /// CLI's exact wording drifts between versions, so this keys on the
    /// stable fragments. `None` when nothing auth-shaped is recognised.
    pub fn classify(msg: &str) -> Option<AuthError> {
        let m = msg.to_lowercase();
        if m.contains("not found on path")
            || m.contains("wasn't found on path")
            || m.contains("no such file or directory")
            || m.contains("is not recognized")
            || m.contains("command not found")
        {
            return Some(AuthError::CliMissing);
        }
        if m.contains("expires_on field not found") || m.contains(AZ_MIN_VERSION) {
            return Some(AuthError::CliTooOld);
        }
        if m.contains("timed out") {
            return Some(AuthError::Timeout);
        }
        // Expiry mentions `az login` too, so it is checked first.
        if m.contains("aadsts700082") || m.contains("aadsts70008") || m.contains("expired") {
            return Some(AuthError::TokenExpired);
        }
        if m.contains("az login") || m.contains("not logged in") || m.contains("no subscriptions found") {
            return Some(AuthError::NotLoggedIn);
        }
        None
    }

    /// Classify, or keep the raw text as [`AuthError::Other`].
    pub fn from_message(msg: &str) -> AuthError {
        Self::classify(msg).unwrap_or_else(|| AuthError::Other(msg.trim().to_string()))
    }

    /// The one status-bar line: what is wrong and the fix. Each line
    /// carries the fragment `classify` keys on, so an `AuthError` survives
    /// a round trip through an error string.
    pub fn status_line(&self) -> String {
        match self {
            AuthError::CliMissing => format!(
                "Azure CLI (az) not found on PATH — install it from {}",
                AZ_INSTALL_URL
            ),
            AuthError::CliTooOld => format!(
                "Azure CLI too old (need {} or newer) — run `az upgrade`, then press R to retry",
                AZ_MIN_VERSION
            ),
            AuthError::NotLoggedIn => {
                "Azure CLI not logged in. Run `az login`, then press R to retry".to_string()
            }
            AuthError::TokenExpired => {
                "Azure CLI login expired. Run `az login`, then press R to retry".to_string()
            }
            AuthError::Timeout => format!(
                "Azure CLI timed out after {} s — check `az account get-access-token`, then press R to retry",
                AZ_TIMEOUT.as_secs()
            ),
            AuthError::Other(msg) => format!("Azure CLI credential failed: {} — press R to retry", msg),
        }
    }

    /// Whether the TUI cannot usefully open: only a missing `az`.
    pub fn is_fatal_at_startup(&self) -> bool {
        matches!(self, AuthError::CliMissing)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.status_line())
    }
}

/// The CLI credential nebaz hands the pipeline: `AzureCliCredential` for
/// one tenant, plus a 30 s timeout, a mutex so six services' first fetches
/// share one `az` process instead of spawning six, and stderr classified
/// into an [`AuthError`] whose text the app can read back.
#[derive(Debug)]
pub struct CliCredential {
    inner: Arc<AzureCliCredential>,
    gate: tokio::sync::Mutex<()>,
}

impl CliCredential {
    pub fn new(tenant_id: &str) -> Result<Arc<Self>> {
        let options = AzureCliCredentialOptions {
            tenant_id: Some(tenant_id.to_string()),
            ..Default::default()
        };
        let inner = AzureCliCredential::new(Some(options))?;
        Ok(Arc::new(Self {
            inner,
            gate: tokio::sync::Mutex::new(()),
        }))
    }
}

#[async_trait]
impl TokenCredential for CliCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        // One `az` at a time: concurrent first-use fetches queue here and the
        // bearer policy's cache serves the later ones.
        let _one_at_a_time = self.gate.lock().await;
        match tokio::time::timeout(AZ_TIMEOUT, self.inner.get_token(scopes, options)).await {
            Ok(Ok(token)) => Ok(token),
            Ok(Err(e)) => Err(azure_core::Error::with_message(
                ErrorKind::Credential,
                AuthError::from_message(&e.to_string()).status_line(),
            )),
            Err(_elapsed) => Err(azure_core::Error::with_message(
                ErrorKind::Credential,
                AuthError::Timeout.status_line(),
            )),
        }
    }
}

/// One `az account list` entry: the picker row and the subscription →
/// tenant table. The CLI's local cache spans every tenant the user has
/// logged into, which ARM's `GET /subscriptions` (one tenant per token)
/// cannot see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionEntry {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
    /// `Enabled`, `Disabled`, `Warned`, `PastDue`, `Deleted`.
    pub state: String,
    pub is_default: bool,
    pub cloud_name: Option<String>,
    /// The signed-in account (`user.name`), when the CLI reports one.
    pub user: Option<String>,
}

impl SubscriptionEntry {
    pub fn is_enabled(&self) -> bool {
        self.state.eq_ignore_ascii_case("Enabled")
    }

    /// The ARM id of the subscription itself.
    pub fn arm_id(&self) -> String {
        format!("/subscriptions/{}", self.id)
    }

    /// Whether `s` names this entry — by id or display name, case-insensitive.
    pub fn matches(&self, s: &str) -> bool {
        let s = s.trim();
        self.id.eq_ignore_ascii_case(s) || self.name.eq_ignore_ascii_case(s)
    }

    /// The first 8 characters of a GUID, for narrow columns.
    pub fn short_id(&self) -> &str {
        short_guid(&self.id)
    }

    pub fn short_tenant(&self) -> &str {
        short_guid(&self.tenant_id)
    }

    /// Parse one element of `az account list -o json`.
    pub fn from_json(v: &serde_json::Value) -> Option<SubscriptionEntry> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        Some(SubscriptionEntry {
            id: s("id")?,
            name: s("name").unwrap_or_default(),
            tenant_id: s("tenantId").or_else(|| s("homeTenantId")).unwrap_or_default(),
            state: s("state").unwrap_or_else(|| "Unknown".into()),
            is_default: v.get("isDefault").and_then(|x| x.as_bool()).unwrap_or(false),
            cloud_name: s("cloudName"),
            user: v.pointer("/user/name").and_then(|x| x.as_str()).map(str::to_string),
        })
    }
}

/// The first 8 characters of a GUID, for narrow columns.
pub fn short_guid(id: &str) -> &str {
    let end = id.char_indices().nth(8).map(|(i, _)| i).unwrap_or(id.len());
    &id[..end]
}

/// Parse the whole `az account list -o json` output.
pub fn parse_account_list(json: &str) -> Result<Vec<SubscriptionEntry>> {
    let v: serde_json::Value = serde_json::from_str(json.trim())?;
    let entries = v
        .as_array()
        .ok_or_else(|| Error::Azure("az account list did not return a JSON array".into()))?;
    Ok(entries.iter().filter_map(SubscriptionEntry::from_json).collect())
}

/// Run `az account list -o json` once. A missing `az` is
/// `Error::Auth(CliMissing)`; a non-zero exit is classified from stderr;
/// an empty list is `NotLoggedIn` (the CLI prints its `az login` hint to
/// stderr and exits 0 in that case).
pub async fn az_account_list() -> Result<Vec<SubscriptionEntry>> {
    let mut cmd = az_command();
    cmd.args(["account", "list", "-o", "json", "--only-show-errors"]);
    cmd.stdin(std::process::Stdio::null());
    let output = match tokio::time::timeout(AZ_TIMEOUT, cmd.output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Auth(AuthError::CliMissing));
        }
        Ok(Err(e)) => return Err(Error::Auth(AuthError::from_message(&e.to_string()))),
        Err(_) => return Err(Error::Auth(AuthError::Timeout)),
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        if output.status.code() == Some(127) {
            return Err(Error::Auth(AuthError::CliMissing));
        }
        return Err(Error::Auth(AuthError::from_message(stderr.trim())));
    }
    let entries = parse_account_list(&String::from_utf8_lossy(&output.stdout))?;
    if entries.is_empty() {
        return Err(Error::Auth(AuthError::NotLoggedIn));
    }
    Ok(entries)
}

/// `az` on PATH (`az.cmd` on Windows, through `cmd /C` like azure_identity).
fn az_command() -> tokio::process::Command {
    #[cfg(windows)]
    {
        let mut c = tokio::process::Command::new("cmd");
        c.arg("/C").arg("az");
        c
    }
    #[cfg(not(windows))]
    {
        tokio::process::Command::new("az")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_source_parses_and_defaults_to_cli() {
        assert_eq!(CredentialSource::parse("cli"), Some(CredentialSource::Cli));
        assert_eq!(CredentialSource::parse("Managed-Identity"), Some(CredentialSource::ManagedIdentity));
        assert_eq!(CredentialSource::parse("magic"), None);
        // No env in tests: the config value wins, default is cli.
        assert_eq!(CredentialSource::resolve(None).unwrap(), CredentialSource::Cli);
        assert_eq!(
            CredentialSource::resolve(Some("environment")).unwrap(),
            CredentialSource::Environment
        );
        assert!(CredentialSource::resolve(Some("magic")).is_err());
    }

    #[test]
    fn classify_recognises_the_cli_wording() {
        assert_eq!(
            AuthError::classify("Please run 'az login' to setup account."),
            Some(AuthError::NotLoggedIn)
        );
        assert_eq!(
            AuthError::classify("AADSTS700082: The refresh token has expired due to inactivity. Please run 'az login'"),
            Some(AuthError::TokenExpired)
        );
        assert_eq!(AuthError::classify("\"/bin/sh\" wasn't found on PATH"), Some(AuthError::CliMissing));
        assert_eq!(AuthError::classify("az not found on PATH"), Some(AuthError::CliMissing));
        assert_eq!(
            AuthError::classify("expires_on field not found. Please use Azure CLI 2.54.0 or newer."),
            Some(AuthError::CliTooOld)
        );
        assert_eq!(AuthError::classify("something else entirely"), None);
        assert_eq!(
            AuthError::from_message(" odd "),
            AuthError::Other("odd".into())
        );
    }

    #[test]
    fn every_status_line_round_trips_through_classify() {
        for e in [
            AuthError::CliMissing,
            AuthError::CliTooOld,
            AuthError::NotLoggedIn,
            AuthError::TokenExpired,
            AuthError::Timeout,
        ] {
            assert_eq!(AuthError::classify(&e.status_line()), Some(e.clone()), "{:?}", e);
        }
    }

    #[test]
    fn account_list_parses_the_cli_shape() {
        let json = r#"[
          {"cloudName":"AzureCloud","homeTenantId":"t-1","id":"11111111-1111-1111-1111-111111111111",
           "isDefault":true,"name":"Prod","state":"Enabled","tenantId":"t-1","user":{"name":"me@example.com","type":"user"}},
          {"cloudName":"AzureCloud","id":"22222222-2222-2222-2222-222222222222","isDefault":false,
           "name":"Old","state":"Disabled","tenantId":"t-2","user":{"name":"me@example.com","type":"user"}},
          {"garbage": true}
        ]"#;
        let entries = parse_account_list(json).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "Prod");
        assert!(entries[0].is_default);
        assert!(entries[0].is_enabled());
        assert_eq!(entries[0].user.as_deref(), Some("me@example.com"));
        assert_eq!(entries[0].short_id(), "11111111");
        assert_eq!(entries[1].short_tenant(), "t-2");
        assert!(!entries[1].is_enabled());
        assert!(entries[0].matches("prod"));
        assert!(entries[0].matches("11111111-1111-1111-1111-111111111111"));
        assert!(!entries[0].matches("1111"));
        assert_eq!(entries[0].arm_id(), "/subscriptions/11111111-1111-1111-1111-111111111111");
        assert!(parse_account_list("{}").is_err());
    }
}
