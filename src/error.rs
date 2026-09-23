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
            ErrorKind::HttpResponse { status, error_code, .. } => {
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
}
