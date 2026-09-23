// ported from neboto-tui src/error.rs @ d483900
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Anything the Azure side reports — an ARM error body, a failed
    /// `az` token fetch, a transport failure. The `azure_core::Error` →
    /// `Error::Azure` conversion (the analog of neboto's `sdk_error_message`
    /// + `From<SdkError>`) lands with the auth ticket.
    #[error("Azure error: {0}")]
    Azure(String),

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

pub type Result<T> = std::result::Result<T, Error>;
