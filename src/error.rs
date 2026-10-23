// ported from neboto-tui src/error.rs @ d483900
use crate::azure::auth::AuthError;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)] // `ChannelError` is neboto's name; kept for the ported table
pub enum Error {
    /// Anything the Azure side reports — an ARM error body, a transport
    /// failure. `From<azure_core::Error>` is the analog of neboto's
    /// `sdk_error_message` + `From<SdkError>`.
    #[error("Azure error: {0}")]
    Azure(String),

    /// Tokens cannot be obtained (ADR 0003) — the one app-wide condition,
    /// shown as one status-bar line instead of per-service errors.
    #[error("{0}")]
    Auth(AuthError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Service not found: {0:?}")]
    #[allow(dead_code)]
    ServiceNotFound(crate::azure::service::ServiceType),

    #[error("Resource not found: {0}")]
    #[allow(dead_code)]
    ResourceNotFound(String),

    #[error("Feature not implemented")]
    NotImplemented,

    #[error("Invalid configuration: {0}")]
    #[allow(dead_code)]
    InvalidConfig(String),

    #[error("Event channel error")]
    #[allow(dead_code)]
    ChannelError,

    #[error("Editor operation failed: {0}")]
    EditorFailed(String),

    #[error("Editor not found: {0}. Set $EDITOR environment variable.")]
    EditorNotFound(String),
}

impl Error {
    /// The auth condition behind this error, if it is one — a provider's
    /// load error carries it so the app can raise the app-wide line.
    pub fn auth_error(&self) -> Option<AuthError> {
        match self {
            Error::Auth(a) => Some(a.clone()),
            _ => None,
        }
    }
}

/// A credential failure becomes `Error::Auth` (classified from the
/// message the CLI credential wrapper wrote); an HTTP error keeps its
/// status and ARM error message; anything else is its message.
impl From<azure_core::Error> for Error {
    fn from(e: azure_core::Error) -> Self {
        use azure_core::error::ErrorKind;
        match e.kind() {
            ErrorKind::Credential => Error::Auth(AuthError::from_message(&e.to_string())),
            // ARM throttling: the retry policy already retried the 429
            // honouring `Retry-After`; say so in words, not a status dump.
            ErrorKind::HttpResponse { status, .. } if *status == azure_core::http::StatusCode::TooManyRequests => {
                Error::Azure(
                    "ARM is throttling this subscription (429 Too Many Requests); gave up after retries, press r to try again shortly"
                        .to_string(),
                )
            }
            ErrorKind::HttpResponse { status, error_code, raw_response } => {
                // The service's own words first: ARM and Graph both send
                // `{"error": {"code", "message"}}`, a few older resource
                // providers a bare `{"code", "message"}`, which the SDK
                // leaves as the raw body text.
                if let Some((code, message)) = raw_response.as_deref().and_then(|r| service_error(r.body())) {
                    return Error::Azure(format!("{} {}: {}", status, code, message));
                }
                let code = error_code.as_deref().unwrap_or("");
                let msg = e.to_string();
                if code.is_empty() || msg.contains(code) {
                    Error::Azure(format!("{} {}", status, msg))
                } else {
                    Error::Azure(format!("{} {}: {}", status, code, msg))
                }
            }
            ErrorKind::Connection => Error::Azure(format!("connection failed: {}", cause_chain(&e))),
            _ => Error::Azure(cause_chain(&e)),
        }
    }
}

/// The `code` and `message` of an ARM or Graph error body, under `error`
/// or at the top level; `None` when the body says neither (an HTML proxy
/// page, an empty 404), so the caller falls back to the SDK's text.
fn service_error(body: &[u8]) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let detail = v.get("error").filter(|e| e.is_object()).unwrap_or(&v);
    let text = |k: &str| detail.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty());
    let message = text("message")?;
    Some((text("code").unwrap_or("Error").to_string(), message.to_string()))
}

/// An error and every cause beneath it, outermost first: the retry policy
/// wraps the transport error as its `source()`, and the transport error
/// wraps the socket's, so `to_string()` alone says "retry policy expired"
/// and hides the DNS, TLS or proxy failure that actually happened.
pub fn cause_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts: Vec<String> = vec![e.to_string()];
    let mut cur = e.source();
    while let Some(c) = cur {
        let text = c.to_string();
        // Levels often repeat the text beneath them; keep each once.
        if !parts.iter().any(|p| p.contains(&text)) {
            parts.push(text);
        }
        cur = c.source();
    }
    parts.join(": ")
}

/// The innermost cause's text alone — what to lead a status line with,
/// since the bar truncates and the outer levels are policy noise.
pub fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur: &(dyn std::error::Error + 'static) = e;
    while let Some(c) = cur.source() {
        cur = c;
    }
    cur.to_string()
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_errors_carry_the_whole_cause_chain() {
        use azure_core::error::ErrorKind;
        let inner = azure_core::Error::with_message(ErrorKind::Connection, "dns error: no such host");
        let outer = inner.with_context("retry policy expired and the request will no longer be retried");
        let e: Error = outer.into();
        let text = e.to_string();
        assert!(text.contains("retry policy expired"), "{}", text);
        assert!(text.contains("no such host"), "the root cause must survive: {}", text);
        assert!(text.starts_with("Azure error: connection failed:"), "{}", text);
        let again = azure_core::Error::with_message(ErrorKind::Connection, "dns error: no such host")
            .with_context("retry policy expired");
        assert_eq!(root_cause(&again), "dns error: no such host");
    }

    #[test]
    fn throttling_reads_as_throttling() {
        use azure_core::error::ErrorKind;
        let throttled = azure_core::Error::with_message(
            ErrorKind::HttpResponse {
                status: azure_core::http::StatusCode::TooManyRequests,
                error_code: Some("TooManyRequests".to_string()),
                raw_response: None,
            },
            "Number of read requests exceeded the limit",
        );
        let e: Error = throttled.into();
        assert!(e.to_string().contains("throttling"), "{}", e);
        assert!(e.auth_error().is_none());
    }

    /// What the pipeline hands back for a non-2xx response with `body`:
    /// the SDK's own `check_success`, as `ArmClient::send_json` meets it.
    async fn http_error(status: azure_core::http::StatusCode, body: &'static str) -> Error {
        let response = azure_core::http::AsyncRawResponse::from_bytes(
            status,
            azure_core::http::headers::Headers::new(),
            azure_core::Bytes::from_static(body.as_bytes()),
        );
        azure_core::http::check_success(response, None).await.unwrap_err().into()
    }

    #[tokio::test]
    async fn a_4xx_carries_the_services_code_and_message() {
        use azure_core::http::StatusCode;
        // ARM: a list the identity may not read.
        let arm = http_error(
            StatusCode::Forbidden,
            r#"{"error":{"code":"AuthorizationFailed","message":"The client 'u@example.test' with object id '1' does not have authorization to perform action 'Microsoft.KeyVault/vaults/read' over scope '/subscriptions/0000'."}}"#,
        )
        .await;
        assert_eq!(
            arm.to_string(),
            "Azure error: 403 AuthorizationFailed: The client 'u@example.test' with object id '1' does not have authorization to perform action 'Microsoft.KeyVault/vaults/read' over scope '/subscriptions/0000'."
        );
        // Graph: same envelope, plus innerError the line leaves out.
        let graph = http_error(
            StatusCode::Forbidden,
            r#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation.","innerError":{"date":"2026-10-23T00:00:00","request-id":"r"}}}"#,
        )
        .await;
        assert_eq!(
            graph.to_string(),
            "Azure error: 403 Authorization_RequestDenied: Insufficient privileges to complete the operation."
        );
        // An older resource provider's bare envelope (Microsoft.Insights).
        let bare = http_error(
            StatusCode::BadRequest,
            r#"{"code":"BadRequest","message":"Failed to find metric configuration for provider: Microsoft.Web"}"#,
        )
        .await;
        assert_eq!(
            bare.to_string(),
            "Azure error: 400 BadRequest: Failed to find metric configuration for provider: Microsoft.Web"
        );
        // A not-found child resource.
        let missing = http_error(
            StatusCode::NotFound,
            r#"{"error":{"code":"ResourceNotFound","message":"The Resource 'Microsoft.Sql/servers/sql-1' under resource group 'rg' was not found."}}"#,
        )
        .await;
        assert!(missing.to_string().starts_with("Azure error: 404 ResourceNotFound: The Resource"), "{}", missing);
        // No JSON at all (a proxy's HTML page): still the status and text.
        let html = http_error(StatusCode::Forbidden, "<html>blocked by proxy</html>").await;
        assert!(html.to_string().contains("403") && html.to_string().contains("blocked by proxy"), "{}", html);
        for e in [arm, graph, bare, missing, html] {
            assert!(e.auth_error().is_none(), "a 4xx is the service's answer, not a login problem: {}", e);
        }
    }
}
