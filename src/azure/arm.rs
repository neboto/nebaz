//! The ARM REST client: one `azure_core` pipeline per tenant (ADR 0003)
//! carrying a `BearerTokenAuthorizationPolicy` over the CLI credential, so
//! tokens are cached and refreshed per tenant, and direct `GET`s against the
//! management endpoint (ticket 01: no management-plane crate exists).
//!
//! **Read-only guarantee** (ticket 07, `PERMISSIONS.md`). Every request
//! this crate sends is built by [`ArmClient::get_request`],
//! [`ArmClient::get_link`] or [`anonymous_get`] (the update check's one
//! non-Azure `GET`, ADR 0008) — the only places `Method::` appears — and
//! every pipeline carries [`ReadOnlyPolicy`], which refuses any request whose
//! method is not `GET` before it leaves the process. `tests/readonly_guard.rs`
//! checks the source for both facts (and for `az` command verbs and
//! data-plane hosts) under `cargo test`.
//!
//! **Two flavours, one constructor** (ADR 0004). The same client, built
//! with [`ArmClient::new_graph`], talks to Microsoft Graph: the request
//! constructor then puts no `api-version` on the URL (Graph versions in
//! the path) and paging follows `@odata.nextLink`. The Graph paths and
//! hosts themselves live in `src/azure/graph.rs`.
//!
//! **Named in the user agent.** Every request on either flavour carries
//! `User-Agent: nebaz azsdk-rust-nebaz/<version> (…)` ([`APPLICATION_ID`]
//! and the crate's name and version, through `azure_core`'s
//! `UserAgentPolicy`), so its directory reads are named in the tenant's
//! Microsoft Graph activity logs and its ARM calls in anything that
//! records the caller's user agent (Microsoft support's request traces,
//! a proxy). ARM's own Activity Log records writes only, so nebaz should
//! appear there not at all.

use crate::auth_scope;
use crate::azure::auth::{CliCredential, CredentialSource};
use crate::error::{Error, Result};
use azure_core::credentials::TokenCredential;
use azure_core::http::policies::auth::BearerTokenAuthorizationPolicy;
use azure_core::http::policies::{Policy, PolicyResult};
use azure_core::http::{
    ClientOptions, Context, ExponentialRetryOptions, Method, Pipeline, Request, RetryOptions, Transport, Url,
    UserAgentOptions,
};
use azure_core::time::Duration;
use serde_json::Value;
use std::sync::Arc;

/// The public cloud's ARM base URL; `endpoint_url` overrides it for a
/// sovereign cloud.
pub const DEFAULT_ENDPOINT: &str = "https://management.azure.com";

/// The runtime half of the read-only guarantee: a per-call policy that
/// refuses every request whose method is not `GET`. Nothing in this crate
/// can build such a request, so this exists for the day something does.
#[derive(Debug)]
pub struct ReadOnlyPolicy;

#[async_trait::async_trait]
impl Policy for ReadOnlyPolicy {
    async fn send(&self, ctx: &Context, request: &mut Request, next: &[Arc<dyn Policy>]) -> PolicyResult {
        if request.method() != Method::Get {
            return Err(azure_core::Error::with_message(
                azure_core::error::ErrorKind::Other,
                format!(
                    "nebaz is read-only: refused a {} request to {}",
                    request.method(),
                    request.url()
                ),
            ));
        }
        next[0].send(ctx, request, &next[1..]).await
    }
}

/// Which REST surface a client speaks: the two differ only in where the
/// version goes and what the continuation link is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// Azure Resource Manager: `?api-version=` on every request, `nextLink`.
    Arm,
    /// Microsoft Graph: the version is the path's first segment (`/v1.0`),
    /// `@odata.nextLink`.
    Graph,
}

impl Api {
    /// The list body's continuation-link property.
    pub fn next_link_key(self) -> &'static str {
        match self {
            Api::Arm => "nextLink",
            Api::Graph => "@odata.nextLink",
        }
    }
}

/// An extra request header: a lowercase static name and its value
/// (`consistencylevel: eventual` for a Graph advanced query).
pub type Header = (&'static str, String);

/// One connection: a pipeline whose bearer policy holds one tenant's
/// token for one API (ARM, or Graph for directory reads).
#[derive(Debug)]
pub struct ArmClient {
    pipeline: Pipeline,
    endpoint: Url,
    tenant_id: String,
    api: Api,
}

impl ArmClient {
    /// Build the pipeline for one tenant. Cheap and synchronous: the
    /// first token is minted on the first request.
    pub fn new(source: CredentialSource, tenant_id: &str, endpoint: &str) -> Result<ArmClient> {
        let endpoint = parse_endpoint(endpoint)?;
        let scope = auth_scope!(endpoint.as_str().trim_end_matches('/'));
        Self::build(source, tenant_id, endpoint, scope, Api::Arm)
    }

    /// The Graph flavour for one tenant (ADR 0004): `graph_endpoint` is the
    /// cloud's Graph base URL (`src/azure/graph.rs` derives it) and the
    /// token scope is `{graph}/.default`: one slash, unlike ARM's.
    pub fn new_graph(source: CredentialSource, tenant_id: &str, graph_endpoint: &str) -> Result<ArmClient> {
        let endpoint = parse_endpoint(graph_endpoint)?;
        let scope = format!("{}/.default", endpoint.as_str().trim_end_matches('/'));
        Self::build(source, tenant_id, endpoint, scope, Api::Graph)
    }

    fn build(source: CredentialSource, tenant_id: &str, endpoint: Url, scope: String, api: Api) -> Result<ArmClient> {
        let credential: Arc<dyn TokenCredential> = match source {
            CredentialSource::Cli => CliCredential::new(tenant_id)?,
            // Demo mode (#45): a fixed token over a transport that answers
            // from the embedded fixtures; still behind `ReadOnlyPolicy`.
            CredentialSource::Demo => {
                let options = ClientOptions {
                    transport: Some(Transport::new(Arc::new(crate::demo::DemoTransport))),
                    retry: RetryOptions::none(),
                    ..client_options()
                };
                return Self::pipeline_with(options, Arc::new(crate::demo::DemoCredential), tenant_id, endpoint, scope, api);
            }
            other => {
                return Err(Error::InvalidConfig(format!(
                    "auth = \"{}\" is not supported yet; only \"cli\" is implemented",
                    other.as_str()
                )))
            }
        };
        Self::pipeline_over(credential, tenant_id, endpoint, scope, api)
    }

    /// The ARM pipeline over the wiring harness's offline credential
    /// (`src/harness_tests`), which never yields a token so nothing leaves
    /// the process. `new` and `new_graph` reach the same pipeline through
    /// `build`.
    #[cfg(test)]
    pub(crate) fn with_credential(
        credential: Arc<dyn TokenCredential>,
        tenant_id: &str,
        endpoint: &str,
    ) -> Result<ArmClient> {
        let endpoint = parse_endpoint(endpoint)?;
        let scope = auth_scope!(endpoint.as_str().trim_end_matches('/'));
        Self::pipeline_over(credential, tenant_id, endpoint, scope, Api::Arm)
    }

    /// [`with_credential`](Self::with_credential) for the Graph flavour:
    /// the harness's directory lists hang offline like its ARM ones.
    #[cfg(test)]
    pub(crate) fn graph_with_credential(
        credential: Arc<dyn TokenCredential>,
        tenant_id: &str,
        endpoint: &str,
    ) -> Result<ArmClient> {
        let endpoint = parse_endpoint(endpoint)?;
        let scope = format!("{}/.default", endpoint.as_str().trim_end_matches('/'));
        Self::pipeline_over(credential, tenant_id, endpoint, scope, Api::Graph)
    }

    /// The one pipeline both flavours share: `ReadOnlyPolicy` first, then
    /// the bearer policy for `scope`.
    fn pipeline_over(
        credential: Arc<dyn TokenCredential>,
        tenant_id: &str,
        endpoint: Url,
        scope: String,
        api: Api,
    ) -> Result<ArmClient> {
        Self::pipeline_with(client_options(), credential, tenant_id, endpoint, scope, api)
    }

    /// [`pipeline_over`](Self::pipeline_over) with its options given: the
    /// demo's carry its transport.
    fn pipeline_with(
        options: ClientOptions,
        credential: Arc<dyn TokenCredential>,
        tenant_id: &str,
        endpoint: Url,
        scope: String,
        api: Api,
    ) -> Result<ArmClient> {
        let bearer = BearerTokenAuthorizationPolicy::new(credential, [scope]);
        let pipeline = build_pipeline(options, vec![Arc::new(ReadOnlyPolicy), Arc::new(bearer)]);
        Ok(ArmClient {
            pipeline,
            endpoint,
            tenant_id: tenant_id.to_string(),
            api,
        })
    }

    pub fn api(&self) -> Api {
        self.api
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// The single request constructor: an authorised `GET` of a path
    /// (`/subscriptions/…`, or `/v1.0/…` on Graph), plus extra query pairs
    /// and headers. ARM requests carry an `api-version`; Graph requests
    /// must not (the version is in the path), and the flavour checks it.
    fn get_request(
        &self,
        path: &str,
        api_version: Option<&str>,
        query: &[(&str, &str)],
        headers: &[Header],
    ) -> Result<Request> {
        match (self.api, api_version) {
            (Api::Arm, None) => return Err(Error::Azure(format!("ARM request without an api-version: {}", path))),
            (Api::Graph, Some(_)) => return Err(Error::Azure(format!("Graph request with an api-version: {}", path))),
            _ => {}
        }
        let mut url = self
            .endpoint
            .join(path.trim_start_matches('/'))
            .map_err(|e| Error::Azure(format!("bad request path {:?}: {}", path, e)))?;
        if api_version.is_some() || !query.is_empty() {
            let mut q = url.query_pairs_mut();
            if let Some(v) = api_version {
                q.append_pair("api-version", v);
            }
            for (k, v) in query {
                q.append_pair(k, v);
            }
        }
        let mut request = Request::new(url, Method::Get);
        for (name, value) in headers {
            request.insert_header(*name, value.clone());
        }
        Ok(request)
    }

    /// A `GET` of an absolute continuation URL (`nextLink` /
    /// `@odata.nextLink`), which already carries its version and skip
    /// token; the first page's headers go with it.
    fn get_link(&self, link: &str, headers: &[Header]) -> Result<Request> {
        let url = Url::parse(link).map_err(|e| Error::Azure(format!("bad nextLink {:?}: {}", link, e)))?;
        if url.origin() != self.endpoint.origin() {
            return Err(Error::Azure(format!("nextLink points outside the endpoint: {}", link)));
        }
        let mut request = Request::new(url, Method::Get);
        for (name, value) in headers {
            request.insert_header(*name, value.clone());
        }
        Ok(request)
    }

    async fn send_json(&self, mut request: Request) -> Result<Value> {
        let response = match self.pipeline.send(&Context::new(), &mut request, None).await {
            Ok(r) => r,
            // Name the host we could not reach: a wrong `endpoint_url`, a
            // proxy or DNS problem all end here, and the status bar is the
            // only place the user sees it.
            Err(e) if matches!(e.kind(), azure_core::error::ErrorKind::Connection) => {
                let root = crate::error::root_cause(&e);
                let chain = crate::error::cause_chain(&e);
                let policy = if chain.contains("retry policy expired") { " (gave up after retries)" } else { "" };
                return Err(Error::Azure(format!(
                    "cannot reach {}: {}{}",
                    self.endpoint.host_str().unwrap_or("the endpoint"),
                    root,
                    policy
                )));
            }
            Err(e) => return Err(e.into()),
        };
        Ok(response.into_body().json::<Value>()?)
    }

    /// `GET` one resource (or any single-object endpoint).
    pub async fn get(&self, path: &str, api_version: &str) -> Result<Value> {
        self.get_query(path, api_version, &[]).await
    }

    /// `GET` one resource with extra query pairs (`$expand=instanceView`).
    pub async fn get_query(&self, path: &str, api_version: &str, query: &[(&str, &str)]) -> Result<Value> {
        self.send_json(self.get_request(path, Some(api_version), query, &[])?).await
    }

    /// `GET` one Graph object (`/v1.0/directoryObjects/{id}`).
    pub async fn graph_get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        self.send_json(self.get_request(path, None, query, &[])?).await
    }

    /// `GET` a Graph collection a page at a time, following
    /// `@odata.nextLink` while `on_page` returns `true`; `headers` go on
    /// every page (`ConsistencyLevel: eventual` for an advanced query).
    pub async fn graph_list_pages_while<F>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        headers: &[Header],
        on_page: F,
    ) -> Result<usize>
    where
        F: FnMut(Vec<Value>) -> bool + Send,
    {
        self.pages_while(path, None, query, headers, on_page).await
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
        self.list_pages_while(path, api_version, query, |page| {
            on_page(page);
            true
        })
        .await
    }

    /// [`list_pages`](Self::list_pages) that stops following `nextLink`
    /// once `on_page` returns `false` (a capped lazy list: the activity
    /// log).
    pub async fn list_pages_while<F>(
        &self,
        path: &str,
        api_version: &str,
        query: &[(&str, &str)],
        on_page: F,
    ) -> Result<usize>
    where
        F: FnMut(Vec<Value>) -> bool + Send,
    {
        self.pages_while(path, Some(api_version), query, &[], on_page).await
    }

    /// The one paging loop under both flavours.
    async fn pages_while<F>(
        &self,
        path: &str,
        api_version: Option<&str>,
        query: &[(&str, &str)],
        headers: &[Header],
        mut on_page: F,
    ) -> Result<usize>
    where
        F: FnMut(Vec<Value>) -> bool + Send,
    {
        let mut request = Some(self.get_request(path, api_version, query, headers)?);
        let mut pages = 0usize;
        while let Some(req) = request.take() {
            let body = self.send_json(req).await?;
            pages += 1;
            let (value, next) = split_page_at(body, self.api.next_link_key());
            if !on_page(value) {
                break;
            }
            if let Some(link) = next {
                request = Some(self.get_link(&link, headers)?);
            }
        }
        Ok(pages)
    }
}

/// The application id nebaz puts first in every request's `User-Agent`
/// (ARM and Graph alike), ahead of the SDK's
/// `azsdk-rust-nebaz/<version> (<rustc>; <os>; <arch>)` token: a tenant
/// admin finds nebaz's calls in the Activity Log and sign-in diagnostics
/// by it. An RFC 9110 token of at most 24 characters (the SDK panics
/// otherwise), so no `/`: the version is in the SDK token.
pub const APPLICATION_ID: &str = "nebaz";

/// The options every pipeline shares: the user agent's application id and
/// a TUI-sized retry policy. The SDK default is 8 exponential retries up
/// to 30 s apart — over a minute before a dead endpoint shows in the
/// status bar. A TUI wants a few short ones; ARM's 429 `Retry-After` is
/// still honoured.
fn client_options() -> ClientOptions {
    ClientOptions {
        retry: RetryOptions::exponential(ExponentialRetryOptions {
            initial_delay: Duration::milliseconds(500),
            max_retries: 3,
            max_total_elapsed: Duration::seconds(20),
            max_delay: Duration::seconds(4),
        }),
        user_agent: UserAgentOptions {
            application_id: Some(APPLICATION_ID.to_string()),
        },
        ..Default::default()
    }
}

/// The pipeline over `options`, with the crate's name and version for the
/// SDK's `User-Agent` token and `per_call` policies (read-only, bearer)
/// ahead of the SDK's own.
fn build_pipeline(options: ClientOptions, per_call: Vec<Arc<dyn Policy>>) -> Pipeline {
    Pipeline::new(
        Some(env!("CARGO_PKG_NAME")),
        Some(env!("CARGO_PKG_VERSION")),
        options,
        per_call,
        Vec::new(),
        None,
    )
}

/// Split an ARM list body into its `value` array and `nextLink`.
#[cfg(test)]
fn split_page(body: Value) -> (Vec<Value>, Option<String>) {
    split_page_at(body, Api::Arm.next_link_key())
}

/// Split a list body into its `value` array and the continuation link
/// named `next_key` (`nextLink` on ARM, `@odata.nextLink` on Graph).
pub fn split_page_at(body: Value, next_key: &str) -> (Vec<Value>, Option<String>) {
    let mut body = body;
    let next = body
        .get(next_key)
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let value = match body.get_mut("value").map(Value::take) {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    };
    (value, next)
}

/// The one request nebaz sends that is not to Azure (ADR 0008): the daily
/// update check's anonymous `GET` of the latest GitHub release
/// (`src/update_check.rs`, the only caller the read-only guard allows).
///
/// The same transport as every Azure call (`azure_core`'s pipeline, no new
/// HTTP crate), carrying [`ReadOnlyPolicy`] and the same `User-Agent`
/// (GitHub refuses a request without one), but **no bearer policy**: no
/// Azure token can reach another host. No retries, `timeout` overall, and
/// `https` only. A non-2xx status is an error (the pipeline's success
/// check), as on the ARM flavour.
pub async fn anonymous_get(url: &str, headers: &[Header], timeout: std::time::Duration) -> Result<Value> {
    let url = Url::parse(url).map_err(|e| Error::Azure(format!("bad URL {:?}: {}", url, e)))?;
    if url.scheme() != "https" {
        return Err(Error::Azure(format!("refused a plain-http request to {}", url)));
    }
    let options = ClientOptions {
        retry: RetryOptions::none(),
        ..client_options()
    };
    let pipeline = build_pipeline(options, vec![Arc::new(ReadOnlyPolicy)]);
    let mut request = Request::new(url, Method::Get);
    for (name, value) in headers {
        request.insert_header(*name, value.clone());
    }
    let send = async {
        let response = pipeline.send(&Context::new(), &mut request, None).await?;
        Ok::<Value, Error>(response.into_body().json::<Value>()?)
    };
    tokio::time::timeout(timeout, send)
        .await
        .map_err(|_| Error::Azure(format!("no answer within {}s", timeout.as_secs())))?
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
            .get_request("/subscriptions/0/resourcegroups", Some("2021-04-01"), &[("$top", "10")], &[])
            .unwrap();
        assert_eq!(req.method(), Method::Get);
        assert_eq!(
            req.url().as_str(),
            "https://management.azure.com/subscriptions/0/resourcegroups?api-version=2021-04-01&%24top=10"
        );
        let link = client
            .get_link("https://management.azure.com/subscriptions/0/resourcegroups?api-version=2021-04-01&%24skiptoken=abc", &[])
            .unwrap();
        assert_eq!(link.method(), Method::Get);
        assert!(client.get_link("https://evil.example/x", &[]).is_err());
        assert!(client.get_request("/subscriptions/0", None, &[], &[]).is_err(), "ARM needs an api-version");
    }

    #[test]
    fn the_graph_flavour_has_no_api_version_carries_headers_and_pages_on_odata_next_link() {
        let client = ArmClient::new_graph(CredentialSource::Cli, "t-1", "https://graph.example.test").unwrap();
        assert_eq!(client.api(), Api::Graph);
        let eventual: Vec<Header> = vec![("consistencylevel", "eventual".to_string())];
        let req = client
            .get_request(
                "/v1.0/servicePrincipals",
                None,
                &[("$filter", "servicePrincipalType eq 'ManagedIdentity'")],
                &eventual,
            )
            .unwrap();
        assert_eq!(req.method(), Method::Get);
        assert_eq!(
            req.url().as_str(),
            "https://graph.example.test/v1.0/servicePrincipals?%24filter=servicePrincipalType+eq+%27ManagedIdentity%27"
        );
        assert_eq!(req.headers().get_optional_str(&"consistencylevel".into()), Some("eventual"));
        let bare = client.get_request("/v1.0/directoryObjects/abc", None, &[], &[]).unwrap();
        assert_eq!(bare.url().as_str(), "https://graph.example.test/v1.0/directoryObjects/abc");
        assert!(client.get_request("/v1.0/x", Some("2021-04-01"), &[], &[]).is_err(), "Graph takes no api-version");
        let link = client
            .get_link("https://graph.example.test/v1.0/servicePrincipals?$skiptoken=x", &eventual)
            .unwrap();
        assert_eq!(link.headers().get_optional_str(&"consistencylevel".into()), Some("eventual"));
        assert!(client.get_link("https://management.azure.com/x", &[]).is_err());

        let (v, next) = split_page_at(
            serde_json::json!({"value": [1], "@odata.nextLink": "https://graph.example.test/v1.0/x?$skiptoken=y"}),
            Api::Graph.next_link_key(),
        );
        assert_eq!(v.len(), 1);
        assert_eq!(next.as_deref(), Some("https://graph.example.test/v1.0/x?$skiptoken=y"));
        let (_, next) = split_page(serde_json::json!({"value": [], "@odata.nextLink": "https://x/y"}));
        assert!(next.is_none(), "ARM paging never follows an OData link");
    }

    #[test]
    fn non_cli_sources_fail_with_not_supported_yet() {
        let err = ArmClient::new(CredentialSource::Environment, "t-1", DEFAULT_ENDPOINT).unwrap_err();
        assert!(err.to_string().contains("not supported yet"), "{}", err);
    }

    /// A stand-in for the transport: proves the policy let a `GET` through.
    #[derive(Debug)]
    struct Reached;

    #[async_trait::async_trait]
    impl Policy for Reached {
        async fn send(&self, _: &Context, _: &mut Request, _: &[Arc<dyn Policy>]) -> PolicyResult {
            Err(azure_core::Error::with_message(azure_core::error::ErrorKind::Other, "reached transport"))
        }
    }

    #[tokio::test]
    async fn the_read_only_policy_refuses_everything_but_get() {
        let url = Url::parse("https://management.azure.com/subscriptions/0?api-version=2022-12-01").unwrap();
        let next: Vec<Arc<dyn Policy>> = vec![Arc::new(Reached)];
        let mut get = Request::new(url.clone(), Method::Get);
        let err = ReadOnlyPolicy.send(&Context::new(), &mut get, &next).await.unwrap_err();
        assert!(err.to_string().contains("reached transport"), "{}", err);
        for method in [Method::Post, Method::Put, Method::Patch, Method::Delete] {
            let mut req = Request::new(url.clone(), method);
            let err = ReadOnlyPolicy.send(&Context::new(), &mut req, &next).await.unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("read-only") && msg.contains("refused"), "{}", msg);
            assert!(!msg.contains("reached transport"), "{}", msg);
        }
    }

    /// A canned transport: answers every request with `status` and `body`
    /// and keeps each request's `User-Agent`.
    #[derive(Debug)]
    struct Canned {
        status: azure_core::http::StatusCode,
        body: &'static str,
        user_agents: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl azure_core::http::HttpClient for Canned {
        async fn execute_request(&self, request: &Request) -> azure_core::Result<azure_core::http::AsyncRawResponse> {
            let ua = request.headers().get_optional_str(&azure_core::http::headers::USER_AGENT).unwrap_or("").to_string();
            self.user_agents.lock().unwrap().push(ua);
            Ok(azure_core::http::AsyncRawResponse::from_bytes(
                self.status,
                azure_core::http::headers::Headers::new(),
                azure_core::Bytes::from_static(self.body.as_bytes()),
            ))
        }
    }

    /// An `api` client whose pipeline is the production one (`client_options`,
    /// `build_pipeline`, `ReadOnlyPolicy`) over `transport`; no bearer
    /// policy, since nothing here may mint a token.
    fn canned_client(api: Api, endpoint: &str, transport: Arc<Canned>) -> ArmClient {
        let mut options = client_options();
        options.transport = Some(azure_core::http::Transport::new(transport));
        ArmClient {
            pipeline: build_pipeline(options, vec![Arc::new(ReadOnlyPolicy)]),
            endpoint: parse_endpoint(endpoint).unwrap(),
            tenant_id: "t-1".into(),
            api,
        }
    }

    fn canned(status: azure_core::http::StatusCode, body: &'static str) -> Arc<Canned> {
        Arc::new(Canned { status, body, user_agents: std::sync::Mutex::new(Vec::new()) })
    }

    #[tokio::test]
    async fn every_request_names_nebaz_in_its_user_agent() {
        let expected = format!("nebaz azsdk-rust-nebaz/{} (", env!("CARGO_PKG_VERSION"));
        let ok = canned(azure_core::http::StatusCode::Ok, r#"{"value": []}"#);
        let arm = canned_client(Api::Arm, DEFAULT_ENDPOINT, ok.clone());
        arm.get("/subscriptions/0", "2022-12-01").await.unwrap();
        arm.list("/subscriptions/0/resourcegroups", "2021-04-01").await.unwrap();
        let graph = canned_client(Api::Graph, "https://graph.example.test", ok.clone());
        graph.graph_get("/v1.0/directoryObjects/abc", &[]).await.unwrap();
        let seen = ok.user_agents.lock().unwrap().clone();
        assert_eq!(seen.len(), 3);
        for ua in seen {
            assert!(ua.starts_with(&expected), "{:?} does not start with {:?}", ua, expected);
        }
    }

    #[tokio::test]
    async fn a_denied_list_or_get_fails_with_the_services_words() {
        let body = r#"{"error":{"code":"AuthorizationFailed","message":"The client 'u' does not have authorization to perform action 'Microsoft.Web/sites/config/read'."}}"#;
        let denied = canned(azure_core::http::StatusCode::Forbidden, body);
        let arm = canned_client(Api::Arm, DEFAULT_ENDPOINT, denied.clone());
        let want = "Azure error: 403 AuthorizationFailed: The client 'u' does not have authorization to perform action 'Microsoft.Web/sites/config/read'.";
        // A list load (the streaming pages) and a lazy section's GET.
        let err = arm.list_pages("/subscriptions/0/providers/Microsoft.Web/sites", "2023-12-01", &[], |_| {}).await.unwrap_err();
        assert_eq!(err.to_string(), want);
        let err = arm.get("/subscriptions/0/x/config/web", "2023-12-01").await.unwrap_err();
        assert_eq!(err.to_string(), want);
        assert_eq!(denied.user_agents.lock().unwrap().len(), 2, "a 403 is not retried");
        let graph_body = r#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}"#;
        let graph = canned_client(Api::Graph, "https://graph.example.test", canned(azure_core::http::StatusCode::Forbidden, graph_body));
        let err = graph.graph_list_pages_while("/v1.0/applications", &[], &[], |_| true).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "Azure error: 403 Authorization_RequestDenied: Insufficient privileges to complete the operation."
        );
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
