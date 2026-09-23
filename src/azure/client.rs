//! The async client factory — the analog of neboto's `AwsClients`
//! (`src/aws/client.rs`, 957 lines, **not** ported: it is entirely AWS SDK
//! config, STS assume-role and profile-file parsing).
//!
//! Skeleton shape only. Ticket 05 fills it in: one `AzureCliCredential`
//! (subscription + tenant chosen at construction), one `azure_core`
//! `Pipeline` carrying `BearerTokenAuthorizationPolicy` for token caching,
//! and per-service `Arc<dyn AzureService>` providers that share the
//! pipeline. Subscription discovery for the `P` picker comes from
//! `GET /subscriptions?api-version=2022-12-01` on the same pipeline.

use crate::azure::service::{AzureService, ServiceType};
use crate::azure::services::stub::StubService;
use crate::error::Result;
use std::sync::Arc;

pub struct AzureClients {
    subscription: Option<String>,
    endpoint: Option<String>,
}

impl AzureClients {
    pub async fn new(subscription: Option<String>, endpoint: Option<String>) -> Result<Self> {
        Ok(Self {
            subscription,
            endpoint,
        })
    }

    /// The active subscription id (the `P` slot). `None` until one is chosen
    /// or discovered.
    pub fn current_subscription(&self) -> Option<&str> {
        self.subscription.as_deref()
    }

    /// A custom ARM endpoint (an emulator, a sovereign cloud). The service
    /// tab strip shows it as a loud badge, like neboto's endpoint badge.
    pub fn current_endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// The provider for a service. Every service is the stub until its
    /// catalog ticket lands.
    pub fn service(&self, service: ServiceType) -> Arc<dyn AzureService> {
        Arc::new(StubService::new(
            service,
            self.subscription.clone().unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".into()),
        ))
    }
}

/// Subscriptions available to the `P` picker. neboto reads
/// `~/.aws/config`; here the list is what `az account list` (or the ARM
/// subscriptions endpoint) reports — ticket 05 decides which. Empty until
/// then.
pub fn list_subscriptions() -> Vec<String> {
    Vec::new()
}
