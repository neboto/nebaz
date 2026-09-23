//! A provider that lists one hard-coded resource type for every service, so
//! the copied skeleton has rows to render, a split pane to open and a lazy
//! section to trigger. Replaced service by service as the catalog lands.

use crate::azure::resource::{Resource, ResourceState};
use crate::azure::service::{AzureService, ServiceType};
use crate::error::Result;
use crate::lazy::Lazy;
use async_trait::async_trait;
use std::collections::HashMap;

crate::sections! {
    pub enum StubDetailSection,
    pub static STUB_SECTIONS = [
        Overview "Overview",
        Details "Details" => crate::app::App::trigger_stub_details,
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct StubResource {
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    pub location: String,
    pub state: ResourceState,
    pub tags: HashMap<String, String>,
}

impl Resource for StubResource {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn resource_type(&self) -> &str {
        self.kind
    }
    fn state(&self) -> ResourceState {
        self.state.clone()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&STUB_SECTIONS)
    }
    fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }
    fn location(&self) -> Option<&str> {
        Some(&self.location)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Id".into(), self.id.clone()),
            ("Name".into(), self.name.clone()),
            ("Type".into(), self.kind.to_string()),
            ("Location".into(), self.location.clone()),
            (
                "Resource group".into(),
                self.resource_group().unwrap_or("-").to_string(),
            ),
        ]
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az resource show --ids {}", self.id))
    }
}

pub struct StubService {
    service: ServiceType,
    subscription: String,
}

impl StubService {
    pub fn new(service: ServiceType, subscription: String) -> Self {
        Self {
            service,
            subscription,
        }
    }

    fn row(&self, n: usize, location: &str, state: ResourceState) -> Box<dyn Resource> {
        let kind = match self.service {
            ServiceType::Subscriptions => "Resource Group",
            ServiceType::VirtualMachines => "Virtual Machine",
            ServiceType::Storage => "Storage Account",
            ServiceType::Network => "Virtual Network",
            ServiceType::KeyVault => "Key Vault",
            ServiceType::Aks => "Managed Cluster",
        };
        let slug = kind.to_lowercase().replace(' ', "-");
        let mut tags = HashMap::new();
        tags.insert("env".into(), if n.is_multiple_of(2) { "prod" } else { "dev" }.into());
        Box::new(StubResource {
            id: format!(
                "/subscriptions/{}/resourceGroups/rg-{}/providers/Microsoft.Stub/{}/{}-{}",
                self.subscription,
                n % 3,
                slug,
                slug,
                n
            ),
            name: format!("{}-{}", slug, n),
            kind,
            location: location.to_string(),
            state,
            tags,
        })
    }
}

#[async_trait]
impl AzureService for StubService {
    fn service_type(&self) -> ServiceType {
        self.service
    }

    fn name(&self) -> &str {
        self.service.name()
    }

    async fn list_resources(&self) -> Result<Vec<Box<dyn Resource>>> {
        // A short async gap so the loading path (spinner, streaming, the
        // list-load generation guard) is observable rather than instant.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        Ok(vec![
            self.row(1, "eastus", ResourceState::Running),
            self.row(2, "westeurope", ResourceState::Stopped),
            self.row(3, "eastus", ResourceState::stateless()),
            self.row(4, "northeurope", ResourceState::Available),
            self.row(5, "westeurope", ResourceState::Creating),
        ])
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        self.list_resources()
            .await?
            .into_iter()
            .find(|r| r.id() == id)
            .ok_or_else(|| crate::error::Error::ResourceNotFound(id.to_string()))
    }
}

/// Body lines for one section of the stub pane — the `*_section_lines`
/// shape every real service follows. Lazy sections take `Option<&Lazy<T>>`
/// and cover all three arms; failures render inline via `error_rows`.
pub fn stub_section_lines(
    r: &StubResource,
    section: StubDetailSection,
    details: Option<&Lazy<String>>,
) -> Vec<(String, String)> {
    match section {
        StubDetailSection::Overview => r.details(),
        StubDetailSection::Details => match details {
            None | Some(Lazy::Loading) => vec![("Details".into(), "Loading…".into())],
            Some(Lazy::Loaded(text)) => vec![
                ("Fetched".into(), text.clone()),
                (String::new(), String::new()),
                ("Portal".into(), r.portal_url().unwrap_or_default()),
                ("CLI".into(), r.cli_command().unwrap_or_default()),
            ],
            Some(Lazy::Error(e)) => error_rows(e),
        },
        StubDetailSection::Tags => {
            if r.tags.is_empty() {
                return vec![(String::new(), "No tags".into())];
            }
            let mut tags: Vec<_> = r.tags.iter().collect();
            tags.sort();
            tags.into_iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        }
    }
}

/// The one shape for a lazy-fetch failure in a section body.
pub fn error_rows(err: &str) -> Vec<(String, String)> {
    vec![
        (String::new(), String::new()),
        (String::new(), format!("⚠ {}", err)),
    ]
}
