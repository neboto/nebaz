//! The ARM REST client: one `azure_core` pipeline per tenant (ADR 0003)
//! carrying a `BearerTokenAuthorizationPolicy` over the CLI credential, so
//! tokens are cached and refreshed per tenant, and direct `GET`s against the
//! management endpoint (ticket 01: no management-plane crate exists).
//!
//! **Read-only guarantee.** Every request this crate sends is built by
//! [`ArmClient::get_request`] — the one place `Method::Get` appears — so a
//! grep for `Method::` under `src/azure/` is the whole audit. Ticket 07
//! turns that into a CI check.

use crate::auth_scope;
use crate::azure::auth::{CliCredential, CredentialSource};
use crate::error::{Error, Result};
use azure_core::credentials::TokenCredential;
use azure_core::http::policies::auth::BearerTokenAuthorizationPolicy;
use azure_core::http::{
    ClientOptions, Context, ExponentialRetryOptions, Method, Pipeline, Request, RetryOptions, Url,
};
use azure_core::time::Duration;
use serde_json::Value;
use std::sync::Arc;

/// The public cloud's ARM base URL; `endpoint_url` overrides it for a
/// sovereign cloud.
pub const DEFAULT_ENDPOINT: &str = "https://management.azure.com";

/// One ARM connection: a pipeline whose bearer policy holds one tenant's
/// token.
#[derive(Debug)]
pub struct ArmClient {
    pipeline: Pipeline,
    endpoint: Url,
    tenant_id: String,
}

impl ArmClient {
    /// Build the pipeline for one tenant. Cheap and synchronous: the
    /// first token is minted on the first request.
    pub fn new(source: CredentialSource, tenant_id: &str, endpoint: &str) -> Result<ArmClient> {
        let credential: Arc<dyn TokenCredential> = match source {
            CredentialSource::Cli => CliCredential::new(tenant_id)?,
            other => {
                return Err(Error::InvalidConfig(format!(
                    "auth = \"{}\" is not supported yet; only \"cli\" is implemented",
                    other.as_str()
                )))
            }
        };
        let endpoint = parse_endpoint(endpoint)?;
        let scope = auth_scope!(endpoint.as_str().trim_end_matches('/'));
        let bearer = BearerTokenAuthorizationPolicy::new(credential, [scope]);
        // The SDK default is 8 exponential retries up to 30 s apart — over a
        // minute before a dead endpoint shows in the status bar. A TUI wants
        // a few short ones; ARM's 429 `Retry-After` is still honoured.
        let options = ClientOptions {
            retry: RetryOptions::exponential(ExponentialRetryOptions {
                initial_delay: Duration::milliseconds(500),
                max_retries: 3,
                max_total_elapsed: Duration::seconds(20),
                max_delay: Duration::seconds(4),
            }),
            ..Default::default()
        };
        let pipeline = Pipeline::new(
            Some("nebaz"),
            Some(env!("CARGO_PKG_VERSION")),
            options,
            vec![Arc::new(bearer)],
            Vec::new(),
            None,
        );
        Ok(ArmClient {
            pipeline,
            endpoint,
            tenant_id: tenant_id.to_string(),
        })
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// The single request constructor: an authorised `GET` of an ARM path
    /// (`/subscriptions/…`) at one `api-version`, plus extra query pairs.
    fn get_request(&self, path: &str, api_version: &str, query: &[(&str, &str)]) -> Result<Request> {
        let mut url = self
            .endpoint
            .join(path.trim_start_matches('/'))
            .map_err(|e| Error::Azure(format!("bad ARM path {:?}: {}", path, e)))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("api-version", api_version);
            for (k, v) in query {
                q.append_pair(k, v);
            }
        }
        Ok(Request::new(url, Method::Get))
    }

    /// A `GET` of an absolute continuation URL (`nextLink`), which already
    /// carries its api-version and skip token.
    fn get_link(&self, link: &str) -> Result<Request> {
        let url = Url::parse(link).map_err(|e| Error::Azure(format!("bad nextLink {:?}: {}", link, e)))?;
        if url.origin() != self.endpoint.origin() {
            return Err(Error::Azure(format!(
                "nextLink points outside the ARM endpoint: {}",
                link
            )));
        }
        Ok(Request::new(url, Method::Get))
    }

    async fn send_json(&self, mut request: Request) -> Result<Value> {
        let response = self.pipeline.send(&Context::new(), &mut request, None).await?;
        Ok(response.into_body().json::<Value>()?)
    }

    /// `GET` one resource (or any single-object endpoint).
    pub async fn get(&self, path: &str, api_version: &str) -> Result<Value> {
        self.get_query(path, api_version, &[]).await
    }

    /// `GET` one resource with extra query pairs (`$expand=instanceView`).
    pub async fn get_query(&self, path: &str, api_version: &str, query: &[(&str, &str)]) -> Result<Value> {
        self.send_json(self.get_request(path, api_version, query)?).await
    }

    /// `GET` a whole collection, following `nextLink` to the end.
    pub async fn list(&self, path: &str, api_version: &str) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        self.list_pages(path, api_version, &[], |page| all.extend(page)).await?;
        Ok(all)
    }

    /// `GET` a collection one page at a time, handing each page's `value`
    /// array to `on_page` as it lands (the streaming list load). Returns
    /// the number of pages.
    pub async fn list_pages<F>(
        &self,
        path: &str,
        api_version: &str,
        query: &[(&str, &str)],
        mut on_page: F,
    ) -> Result<usize>
    where
        F: FnMut(Vec<Value>) + Send,
    {
        let mut request = Some(self.get_request(path, api_version, query)?);
        let mut pages = 0usize;
        while let Some(req) = request.take() {
            let body = self.send_json(req).await?;
            pages += 1;
            let (value, next) = split_page(body);
            on_page(value);
            if let Some(link) = next {
                request = Some(self.get_link(&link)?);
            }
        }
        Ok(pages)
    }
}

/// Split an ARM list body into its `value` array and `nextLink`.
pub fn split_page(body: Value) -> (Vec<Value>, Option<String>) {
    let mut body = body;
    let next = body
        .get("nextLink")
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let value = match body.get_mut("value").map(Value::take) {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    };
    (value, next)
}

/// Normalise the configured endpoint: must be `https` (the bearer policy
/// refuses anything else) and ends with one slash so `Url::join` keeps the
/// host.
pub fn parse_endpoint(endpoint: &str) -> Result<Url> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let url = Url::parse(&format!("{}/", trimmed))
        .map_err(|e| Error::InvalidConfig(format!("endpoint_url {:?}: {}", endpoint, e)))?;
    if url.scheme() != "https" {
        return Err(Error::InvalidConfig(format!(
            "endpoint_url must be https (authorised requests refuse plain http): {}",
            endpoint
        )));
    }
    Ok(url)
}

/// The Entra v2 scope for an ARM endpoint: `{endpoint}//.default`. The
/// double slash is deliberate — ARM's resource identifier carries a
/// trailing slash — and was verified against `az account get-access-token`
/// (ticket 05).
#[macro_export]
macro_rules! auth_scope {
    ($endpoint:expr) => {
        format!("{}//.default", $endpoint)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_is_the_double_slash_form() {
        assert_eq!(
            auth_scope!(DEFAULT_ENDPOINT),
            "https://management.azure.com//.default"
        );
        assert_eq!(
            auth_scope!(parse_endpoint("https://management.usgovcloudapi.net/").unwrap().as_str().trim_end_matches('/')),
            "https://management.usgovcloudapi.net//.default"
        );
    }

    #[test]
    fn endpoint_must_be_https_and_is_normalised() {
        assert_eq!(parse_endpoint("https://management.azure.com").unwrap().as_str(), "https://management.azure.com/");
        assert_eq!(parse_endpoint(" https://management.azure.com// ").unwrap().as_str(), "https://management.azure.com/");
        assert!(parse_endpoint("http://localhost:10000").is_err());
        assert!(parse_endpoint("not a url").is_err());
    }

    #[test]
    fn get_request_is_a_get_with_api_version_and_query() {
        let client = ArmClient::new(CredentialSource::Cli, "t-1", DEFAULT_ENDPOINT).unwrap();
        let req = client
            .get_request("/subscriptions/0/resourcegroups", "2021-04-01", &[("$top", "10")])
            .unwrap();
        assert_eq!(req.method(), Method::Get);
        assert_eq!(
            req.url().as_str(),
            "https://management.azure.com/subscriptions/0/resourcegroups?api-version=2021-04-01&%24top=10"
        );
        let link = client
            .get_link("https://management.azure.com/subscriptions/0/resourcegroups?api-version=2021-04-01&%24skiptoken=abc")
            .unwrap();
        assert_eq!(link.method(), Method::Get);
        assert!(client.get_link("https://evil.example/x").is_err());
    }

    #[test]
    fn non_cli_sources_fail_with_not_supported_yet() {
        let err = ArmClient::new(CredentialSource::Environment, "t-1", DEFAULT_ENDPOINT).unwrap_err();
        assert!(err.to_string().contains("not supported yet"), "{}", err);
    }

    #[test]
    fn split_page_handles_both_shapes() {
        let (v, next) = split_page(serde_json::json!({"value": [1, 2], "nextLink": "https://x/y"}));
        assert_eq!(v.len(), 2);
        assert_eq!(next.as_deref(), Some("https://x/y"));
        let (v, next) = split_page(serde_json::json!({"value": [], "nextLink": ""}));
        assert!(v.is_empty());
        assert!(next.is_none());
        let (v, next) = split_page(serde_json::json!({"id": "single"}));
        assert!(v.is_empty());
        assert!(next.is_none());
    }
}
