//! The client factory — the analog of neboto's `AwsClients`
//! (`src/aws/client.rs`, 957 lines, **not** ported: it is entirely AWS SDK
//! config, STS assume-role and profile-file parsing).
//!
//! Shape (ADR 0003): the subscription list comes from `az account list`
//! read once at startup (every tenant the user has logged into, with the
//! default marked); one [`ArmClient`] per **tenant**, built on demand and
//! held in a map keyed by tenant id; a subscription switch within a tenant
//! rebuilds nothing, crossing tenants builds that tenant's pipeline once.
//! There is no tenant picker: choosing a subscription chooses its tenant.

use crate::azure::arm::{ArmClient, DEFAULT_ENDPOINT};
use crate::azure::auth::{az_account_list, AuthError, CredentialSource, SubscriptionEntry};
use crate::azure::location::LocationInfo;
use crate::azure::service::{AzureService, ServiceType};
use crate::azure::resource::subscription_of;
use crate::azure::services::aks::AksService;
use crate::azure::services::compute::ComputeService;
use crate::azure::services::app_service::AppServiceService;
use crate::azure::services::foundry::FoundryService;
use crate::azure::services::sql::SqlService;
use crate::azure::services::identity::IdentityService;
use crate::azure::services::keyvault::KeyVaultService;
use crate::azure::services::network::NetworkService;
use crate::azure::services::storage::StorageService;
use crate::azure::services::subscriptions::{SubscriptionsService, SUBSCRIPTIONS_API_VERSION};
use crate::azure::services::Scope;
use crate::config::Config;
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

/// `GET /subscriptions/{id}/locations` api-version.
pub const LOCATIONS_API_VERSION: &str = "2022-12-01";

pub struct AzureClients {
    source: CredentialSource,
    /// ARM base URL without a trailing slash.
    endpoint: String,
    subscriptions: Vec<SubscriptionEntry>,
    /// Index into `subscriptions`; `None` until one is resolved.
    current: Option<usize>,
    /// One pipeline per tenant, built on first use.
    pipelines: Mutex<HashMap<String, Arc<ArmClient>>>,
    /// The auth condition met while reading the subscription list, if
    /// any — the TUI opens with it on the status bar and an empty picker.
    auth_error: Option<AuthError>,
}

impl AzureClients {
    /// Read the credential source and the subscription list, then resolve
    /// the startup subscription: `--subscription` / `default_subscription`
    /// (id or display name) > the CLI's default > the first enabled one.
    ///
    /// Errors here end the process before the TUI opens: a missing `az`,
    /// an unsupported credential source, an unknown subscription (listing
    /// the known ones). Not being logged in is **not** an error: the TUI
    /// opens with the auth line and the `P` picker.
    pub async fn new(config: &Config) -> Result<Self> {
        let source = CredentialSource::resolve(config.auth.as_deref())?;
        if source != CredentialSource::Cli {
            return Err(Error::InvalidConfig(format!(
                "auth = \"{}\" is not supported yet; only \"cli\" is implemented",
                source.as_str()
            )));
        }
        let endpoint = config
            .endpoint_url
            .as_deref()
            .map(|e| e.trim().trim_end_matches('/').to_string())
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        // Fail early on a malformed endpoint rather than at the first fetch.
        crate::azure::arm::parse_endpoint(&endpoint)?;

        let mut clients = Self {
            source,
            endpoint,
            subscriptions: Vec::new(),
            current: None,
            pipelines: Mutex::new(HashMap::new()),
            auth_error: None,
        };
        clients.load_subscriptions().await?;
        clients.resolve_startup(config.default_subscription.as_deref())?;
        Ok(clients)
    }

    /// (Re-)read `az account list`. A missing `az` is fatal; any other
    /// auth condition is recorded and the list left empty.
    async fn load_subscriptions(&mut self) -> Result<()> {
        match az_account_list().await {
            Ok(entries) => {
                self.subscriptions = entries;
                self.auth_error = None;
                Ok(())
            }
            Err(Error::Auth(e)) if e.is_fatal_at_startup() => Err(Error::Auth(e)),
            Err(Error::Auth(e)) => {
                self.subscriptions.clear();
                self.auth_error = Some(e);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn resolve_startup(&mut self, wanted: Option<&str>) -> Result<()> {
        if let Some(w) = wanted.map(str::trim).filter(|w| !w.is_empty()) {
            match self.subscriptions.iter().position(|s| s.matches(w)) {
                Some(i) => {
                    self.current = Some(i);
                    return Ok(());
                }
                None if self.subscriptions.is_empty() => {
                    // Not logged in: nothing to validate against; the picker
                    // opens with the auth line instead.
                    return Ok(());
                }
                None => {
                    let known: Vec<String> = self
                        .subscriptions
                        .iter()
                        .map(|s| format!("  {}  {}", s.id, s.name))
                        .collect();
                    return Err(Error::InvalidConfig(format!(
                        "unknown subscription {:?}. Known subscriptions (id  name):\n{}",
                        w,
                        known.join("\n")
                    )));
                }
            }
        }
        self.current = self.default_index();
        Ok(())
    }

    /// The CLI's default entry if it is enabled, else the first enabled one.
    fn default_index(&self) -> Option<usize> {
        self.subscriptions
            .iter()
            .position(|s| s.is_default && s.is_enabled())
            .or_else(|| self.subscriptions.iter().position(|s| s.is_enabled()))
    }

    /// `R` on the auth line: re-read the account list and, if the current
    /// subscription is gone, fall back to the default. Returns whether a
    /// subscription is now selected.
    pub async fn retry_auth(&mut self) -> Result<bool> {
        let keep = self.current_subscription().map(str::to_string);
        self.load_subscriptions().await?;
        self.current = keep
            .and_then(|id| self.subscriptions.iter().position(|s| s.id == id))
            .or_else(|| self.default_index());
        Ok(self.current.is_some())
    }

    /// The auth condition found while reading the subscription list.
    pub fn auth_error(&self) -> Option<&AuthError> {
        self.auth_error.as_ref()
    }

    /// Every subscription the CLI knows, all tenants, in CLI order.
    pub fn subscriptions(&self) -> &[SubscriptionEntry] {
        &self.subscriptions
    }

    pub fn current_entry(&self) -> Option<&SubscriptionEntry> {
        self.current.and_then(|i| self.subscriptions.get(i))
    }

    /// The active subscription id (the `P` slot). `None` until one is chosen
    /// or discovered.
    pub fn current_subscription(&self) -> Option<&str> {
        self.current_entry().map(|s| s.id.as_str())
    }

    pub fn current_subscription_name(&self) -> Option<&str> {
        self.current_entry().map(|s| s.name.as_str())
    }

    pub fn current_tenant(&self) -> Option<&str> {
        self.current_entry().map(|s| s.tenant_id.as_str())
    }

    /// The ARM base URL every request goes to.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// A non-default ARM endpoint (a sovereign cloud). The service tab
    /// strip shows it as a loud badge, like neboto's endpoint badge.
    pub fn current_endpoint(&self) -> Option<&str> {
        (self.endpoint != DEFAULT_ENDPOINT).then_some(self.endpoint.as_str())
    }

    /// Look a subscription up by id or display name (case-insensitive).
    pub fn resolve_subscription(&self, id_or_name: &str) -> Option<SubscriptionEntry> {
        self.subscriptions.iter().find(|s| s.matches(id_or_name)).cloned()
    }

    /// Point the client at another subscription — a value, not a rebuild.
    /// Its tenant's pipeline is built on the first request if needed.
    pub fn set_subscription(&mut self, id_or_name: &str) -> Result<()> {
        match self.subscriptions.iter().position(|s| s.matches(id_or_name)) {
            Some(i) => {
                self.current = Some(i);
                Ok(())
            }
            None => Err(Error::Azure(format!(
                "subscription {} is not in the picker's list",
                id_or_name
            ))),
        }
    }

    /// The pipeline for a tenant, built once.
    pub fn arm_for_tenant(&self, tenant_id: &str) -> Result<Arc<ArmClient>> {
        let mut map = self.pipelines.lock().expect("pipeline map poisoned");
        if let Some(c) = map.get(tenant_id) {
            return Ok(c.clone());
        }
        let client = Arc::new(ArmClient::new(self.source, tenant_id, &self.endpoint)?);
        map.insert(tenant_id.to_string(), client.clone());
        Ok(client)
    }

    /// The pipeline for the tenant a subscription belongs to.
    pub fn arm_for_subscription(&self, subscription_id: &str) -> Result<Arc<ArmClient>> {
        let entry = self
            .subscriptions
            .iter()
            .find(|s| s.id.eq_ignore_ascii_case(subscription_id))
            .ok_or_else(|| Error::Azure(format!("subscription {} is not in the picker's list", subscription_id)))?;
        self.arm_for_tenant(&entry.tenant_id)
    }

    /// The pipeline for the current subscription's tenant, or the auth
    /// condition that prevents one.
    pub fn current_arm(&self) -> Result<Arc<ArmClient>> {
        match self.current_entry() {
            Some(entry) => self.arm_for_tenant(&entry.tenant_id),
            None => Err(Error::Auth(
                self.auth_error.clone().unwrap_or(AuthError::NotLoggedIn),
            )),
        }
    }

    /// The provider for a service, holding the current subscription's ARM
    /// client (or the auth condition that prevents one, which the provider
    /// reports as its load error). Every other service is the stub until
    /// its catalog lands.
    /// What a provider is pointed at: the current subscription's tenant
    /// pipeline (or the auth condition that prevents one) and the entry.
    pub fn scope(&self) -> Scope {
        Scope::new(
            self.current_arm().map_err(|e| {
                e.auth_error()
                    .unwrap_or_else(|| AuthError::Other(e.to_string()))
            }),
            self.current_entry().cloned(),
        )
    }

    /// The provider for one service, over the current scope.
    pub fn service(&self, service: ServiceType) -> Arc<dyn AzureService> {
        let scope = self.scope();
        match service {
            ServiceType::Subscriptions => Arc::new(SubscriptionsService::new(scope, self.subscriptions.clone())),
            ServiceType::VirtualMachines => Arc::new(ComputeService::new(scope)),
            ServiceType::Storage => Arc::new(StorageService::new(scope)),
            ServiceType::Network => Arc::new(NetworkService::new(scope)),
            ServiceType::KeyVault => Arc::new(KeyVaultService::new(scope)),
            ServiceType::Identity => Arc::new(IdentityService::new(scope)),
            ServiceType::Aks => Arc::new(AksService::new(scope)),
            ServiceType::AppService => Arc::new(AppServiceService::new(scope)),
            ServiceType::Sql => Arc::new(SqlService::new(scope)),
            ServiceType::Foundry => Arc::new(FoundryService::new(scope)),
        }
    }

    /// The pipeline for the tenant an ARM path belongs to, resolved
    /// synchronously so an auth condition surfaces as the fetch's error.
    fn arm_for_path(&self, path: &str) -> std::result::Result<Arc<ArmClient>, String> {
        let sub = subscription_of(path).ok_or_else(|| format!("not an ARM path: {}", path))?;
        self.arm_for_subscription(sub).map_err(|e| e.to_string())
    }

    /// `GET {path}` as a future the lazy store can own (a VM's instance
    /// view).
    pub fn get_fetch(
        &self,
        path: &str,
        api_version: &'static str,
    ) -> impl Future<Output = std::result::Result<serde_json::Value, String>> + Send + 'static {
        let arm = self.arm_for_path(path);
        let path = path.to_string();
        async move {
            let arm = arm?;
            arm.get(&path, api_version).await.map_err(|e| e.to_string())
        }
    }

    /// `GET {path}` as a whole collection, for the lazy children
    /// (containers, secret and key names).
    pub fn list_fetch(
        &self,
        path: &str,
        api_version: &'static str,
    ) -> impl Future<Output = std::result::Result<Vec<serde_json::Value>, String>> + Send + 'static {
        let arm = self.arm_for_path(path);
        let path = path.to_string();
        async move {
            let arm = arm?;
            arm.list(&path, api_version).await.map_err(|e| e.to_string())
        }
    }

    /// `GET /subscriptions/{id}` for a subscription row's Details section.
    pub fn subscription_details_fetch(
        &self,
        subscription: &str,
    ) -> impl Future<Output = std::result::Result<serde_json::Value, String>> + Send + 'static {
        let arm = self.arm_for_subscription(subscription);
        let path = format!("/subscriptions/{}", subscription);
        async move {
            let arm = arm.map_err(|e| e.to_string())?;
            arm.get(&path, SUBSCRIPTIONS_API_VERSION)
                .await
                .map_err(|e| e.to_string())
        }
    }

    /// The locations list for a subscription
    /// (`GET /subscriptions/{id}/locations`), as a future the lazy store
    /// can own: the pipeline is resolved here, synchronously, so an auth
    /// condition surfaces as the fetch's error.
    pub fn locations_fetch(
        &self,
        subscription: &str,
    ) -> impl Future<Output = std::result::Result<Vec<LocationInfo>, String>> + Send + 'static {
        let arm = self.arm_for_subscription(subscription);
        let path = format!("/subscriptions/{}/locations", subscription);
        async move {
            let arm = arm.map_err(|e| e.to_string())?;
            let items = arm
                .list(&path, LOCATIONS_API_VERSION)
                .await
                .map_err(|e| e.to_string())?;
            let mut infos: Vec<LocationInfo> = items.iter().filter_map(LocationInfo::from_json).collect();
            infos.sort_by(|a, b| a.display_name.cmp(&b.display_name));
            Ok(infos)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, name: &str, tenant: &str, state: &str, default: bool) -> SubscriptionEntry {
        SubscriptionEntry {
            id: id.into(),
            name: name.into(),
            tenant_id: tenant.into(),
            state: state.into(),
            is_default: default,
            cloud_name: None,
            user: None,
        }
    }

    fn clients(subs: Vec<SubscriptionEntry>) -> AzureClients {
        AzureClients {
            source: CredentialSource::Cli,
            endpoint: DEFAULT_ENDPOINT.into(),
            subscriptions: subs,
            current: None,
            pipelines: Mutex::new(HashMap::new()),
            auth_error: None,
        }
    }

    #[test]
    fn startup_prefers_the_flag_then_the_enabled_default_then_the_first_enabled() {
        let subs = vec![
            entry("a", "Alpha", "t-1", "Disabled", true),
            entry("b", "Beta", "t-1", "Enabled", false),
            entry("c", "Gamma", "t-2", "Enabled", false),
        ];
        let mut c = clients(subs.clone());
        c.resolve_startup(Some("gamma")).unwrap();
        assert_eq!(c.current_subscription(), Some("c"));
        assert_eq!(c.current_tenant(), Some("t-2"));

        let mut c = clients(subs.clone());
        c.resolve_startup(None).unwrap();
        // The default is disabled: the first enabled one wins.
        assert_eq!(c.current_subscription(), Some("b"));

        let mut c = clients(subs.clone());
        let err = c.resolve_startup(Some("nope")).unwrap_err().to_string();
        assert!(err.contains("unknown subscription"), "{}", err);
        assert!(err.contains("Gamma"), "{}", err);

        // Not logged in: an unknown --subscription is not an error, the
        // picker opens with the auth line.
        let mut c = clients(Vec::new());
        c.resolve_startup(Some("nope")).unwrap();
        assert_eq!(c.current_subscription(), None);
    }

    #[test]
    fn set_subscription_matches_id_or_name_and_pipelines_are_per_tenant() {
        let mut c = clients(vec![
            entry("a", "Alpha", "t-1", "Enabled", true),
            entry("b", "Beta", "t-1", "Enabled", false),
            entry("c", "Gamma", "t-2", "Enabled", false),
        ]);
        c.resolve_startup(None).unwrap();
        let first = c.current_arm().unwrap();
        c.set_subscription("BETA").unwrap();
        // Same tenant: the same pipeline.
        assert!(Arc::ptr_eq(&first, &c.current_arm().unwrap()));
        c.set_subscription("c").unwrap();
        // Another tenant: a second pipeline, built once.
        let second = c.current_arm().unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.tenant_id(), "t-2");
        assert!(Arc::ptr_eq(&second, &c.arm_for_subscription("c").unwrap()));
        assert!(c.set_subscription("zeta").is_err());
        assert_eq!(c.current_subscription(), Some("c"));
        assert_eq!(c.current_endpoint(), None);
    }
}
