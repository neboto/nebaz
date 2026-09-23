// ported from neboto-tui src/error.rs @ d483900
use crate::azure::auth::AuthError;
use thiserror::Error;

#[derive(Error, Debug)]
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
            ErrorKind::Connection => Error::Azure(format!("connection failed: {}", e)),
            _ => Error::Azure(e.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
