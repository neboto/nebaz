//! Demo fixtures: the `identity` area (see `docs/DEMO.md` for who owns what):
//! managed identities, the directory (Microsoft Graph service principals,
//! app registrations and every principal the Access and Activity sections
//! name), Power Platform, Monitor and Foundry.
//!
//! A directory object's body is one file served on every path that reads
//! it: `servicePrincipals/{id}`, `servicePrincipals(appId='…')` and
//! `directoryObjects/{id}`, so the three can never disagree.

use super::{fx, Fixture};

pub static FIXTURES: &[Fixture] = &[
    // ── Managed identities ──
    fx!("identity", "/subscriptions/{{prod}}/providers/Microsoft.ManagedIdentity/userAssignedIdentities", "identities.json"),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-orders-api",
        "id-orders-api.json"
    ),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-orders-api/federatedIdentityCredentials",
        "id-orders-api-federated.json"
    ),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/MC_rg-platform-prod_aks-platform-prod_westeurope/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-platform-prod-agentpool",
        "id-aks-platform-prod-agentpool.json"
    ),
    // ── Service principals: the two lists `graph.rs` asks for ──
    fx!("identity", "/v1.0/servicePrincipals", when["servicePrincipalType eq 'ManagedIdentity'"], "sp-managed-identities.json"),
    fx!("identity", "/v1.0/servicePrincipals", when["appOwnerOrganizationId eq"], "sp-tenant-owned.json"),
    // ── Service principals by object id ──
    fx!("identity", "/v1.0/servicePrincipals/535edf48-335f-4761-b6ed-e0613ed690b3", "sp-id-orders-api.json"),
    fx!("identity", "/v1.0/servicePrincipals/37ec34fc-62c5-4180-a17f-0cccd5ed2e95", "sp-aks-agentpool.json"),
    fx!("identity", "/v1.0/servicePrincipals/51b687b3-bdb3-4408-b436-500e659cc8cb", "sp-ca-orders-worker.json"),
    fx!("identity", "/v1.0/servicePrincipals/1f342012-a634-4ddc-8970-f178395ab2e5", "sp-ai-contoso-prod.json"),
    fx!("identity", "/v1.0/servicePrincipals/2163cbd0-48ad-4c52-bb85-c34c6c4809cf", "sp-orders-assistant.json"),
    fx!("identity", "/v1.0/servicePrincipals/f5233913-f487-4d23-b621-98c7511347d1", "sp-github-actions-deploy.json"),
    fx!("identity", "/v1.0/servicePrincipals/47302d33-ba06-4194-bc89-bec920f2a564", "sp-orders-api-client.json"),
    fx!(
        "identity",
        "/v1.0/servicePrincipals/47302d33-ba06-4194-bc89-bec920f2a564/oauth2PermissionGrants",
        "sp-orders-api-client-grants.json"
    ),
    fx!("identity", "/v1.0/servicePrincipals/80303294-4904-46c2-87a0-d8cb283aa2a9", "sp-fabrikam-connector.json"),
    fx!(
        "identity",
        "/v1.0/servicePrincipals/80303294-4904-46c2-87a0-d8cb283aa2a9/appRoleAssignments",
        "sp-fabrikam-connector-roles.json"
    ),
    fx!("identity", "/v1.0/servicePrincipals/0fa66fc7-cbb8-497a-84a2-8c6dc97ef59a", "sp-microsoft-graph.json"),
    // ── Service principals by app id (API permissions, activity callers) ──
    fx!("identity", "/v1.0/servicePrincipals(appId='a486b752-7257-42ba-bc16-23a4e0381f56')", "sp-id-orders-api.json"),
    fx!("identity", "/v1.0/servicePrincipals(appId='e12c192b-685e-4570-b8f9-758cef84d4d0')", "sp-aks-agentpool.json"),
    fx!("identity", "/v1.0/servicePrincipals(appId='8587b0bc-6107-463b-a8d3-278472a07067')", "sp-ca-orders-worker.json"),
    fx!("identity", "/v1.0/servicePrincipals(appId='f7e9cf30-122a-4b27-a009-e51ffcb17c73')", "sp-ai-contoso-prod.json"),
    fx!("identity", "/v1.0/servicePrincipals(appId='05bac95b-e64c-4bd3-af4c-4b3baf097c09')", "sp-orders-assistant.json"),
    fx!("identity", "/v1.0/servicePrincipals(appId='edc89266-a363-4046-9c6e-e0629dfedbad')", "sp-github-actions-deploy.json"),
    fx!("identity", "/v1.0/servicePrincipals(appId='7b985643-85cc-4880-8e95-9dac694b9dfc')", "sp-orders-api-client.json"),
    fx!("identity", "/v1.0/servicePrincipals(appId='600d5263-b150-479c-ab05-60929b2edcbd')", "sp-fabrikam-connector.json"),
    fx!("identity", "/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')", "sp-microsoft-graph.json"),
    // ── App registrations ──
    fx!("identity", "/v1.0/applications", "applications.json"),
    fx!("identity", "/v1.0/applications/4087b8f1-0c36-436a-a23c-1868b3c7fb86", "app-github-actions-deploy.json"),
    fx!(
        "identity",
        "/v1.0/applications/4087b8f1-0c36-436a-a23c-1868b3c7fb86/federatedIdentityCredentials",
        "app-github-actions-deploy-federated.json"
    ),
    fx!("identity", "/v1.0/applications/4087b8f1-0c36-436a-a23c-1868b3c7fb86/owners", "app-github-actions-deploy-owners.json"),
    fx!("identity", "/v1.0/applications/65269b0d-f929-40b3-a28d-a281b6b6503b", "app-orders-api-client.json"),
    // `orders-api-client` has no owners: its `/owners` is the empty default.
    // ── Directory objects: every principal DEMO.md names ──
    fx!("identity", "/v1.0/directoryObjects/8851538f-3984-4858-a0fd-773a4f49a810", "user-alex-kim.json"),
    fx!("identity", "/v1.0/directoryObjects/e37ad877-49b0-4f5a-b333-31c5f278f12f", "user-j-ortiz-guest.json"),
    fx!("identity", "/v1.0/directoryObjects/e1a8fb8b-9024-4a39-abf4-cc2a5c73b98d", "group-platform-admins.json"),
    fx!("identity", "/v1.0/directoryObjects/4087b8f1-0c36-436a-a23c-1868b3c7fb86", "app-github-actions-deploy.json"),
    fx!("identity", "/v1.0/directoryObjects/65269b0d-f929-40b3-a28d-a281b6b6503b", "app-orders-api-client.json"),
    fx!("identity", "/v1.0/directoryObjects/f5233913-f487-4d23-b621-98c7511347d1", "sp-github-actions-deploy.json"),
    fx!("identity", "/v1.0/directoryObjects/47302d33-ba06-4194-bc89-bec920f2a564", "sp-orders-api-client.json"),
    fx!("identity", "/v1.0/directoryObjects/80303294-4904-46c2-87a0-d8cb283aa2a9", "sp-fabrikam-connector.json"),
    fx!("identity", "/v1.0/directoryObjects/535edf48-335f-4761-b6ed-e0613ed690b3", "sp-id-orders-api.json"),
    fx!("identity", "/v1.0/directoryObjects/51b687b3-bdb3-4408-b436-500e659cc8cb", "sp-ca-orders-worker.json"),
    fx!("identity", "/v1.0/directoryObjects/37ec34fc-62c5-4180-a17f-0cccd5ed2e95", "sp-aks-agentpool.json"),
    fx!("identity", "/v1.0/directoryObjects/1f342012-a634-4ddc-8970-f178395ab2e5", "sp-ai-contoso-prod.json"),
    fx!("identity", "/v1.0/directoryObjects/2163cbd0-48ad-4c52-bb85-c34c6c4809cf", "sp-orders-assistant.json"),
    fx!("identity", "/v1.0/directoryObjects/0fa66fc7-cbb8-497a-84a2-8c6dc97ef59a", "sp-microsoft-graph.json"),
    // ── Power Platform ──
    fx!("identity", "/subscriptions/{{prod}}/providers/Microsoft.PowerPlatform/enterprisePolicies", "pp-policies.json"),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.PowerPlatform/enterprisePolicies/ep-pp-network-injection",
        "pp-ep-pp-network-injection.json"
    ),
    // ── Monitor ──
    fx!("identity", "/subscriptions/{{prod}}/providers/Microsoft.OperationalInsights/workspaces", "law-workspaces.json"),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.OperationalInsights/workspaces/law-contoso-prod",
        "law-contoso-prod.json"
    ),
    fx!("identity", "/subscriptions/{{prod}}/providers/Microsoft.Insights/components", "appi-components.json"),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.Insights/components/appi-orders",
        "appi-orders.json"
    ),
    // ── Foundry ──
    fx!("identity", "/subscriptions/{{prod}}/providers/Microsoft.CognitiveServices/accounts", "foundry-accounts.json"),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/rg-ai-prod/providers/Microsoft.CognitiveServices/accounts/ai-contoso-prod",
        "foundry-ai-contoso-prod.json"
    ),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/rg-ai-prod/providers/Microsoft.CognitiveServices/accounts/ai-contoso-prod/deployments",
        "foundry-deployments.json"
    ),
    fx!(
        "identity",
        "/subscriptions/{{prod}}/resourceGroups/rg-ai-prod/providers/Microsoft.CognitiveServices/accounts/ai-contoso-prod/projects",
        "foundry-projects.json"
    ),
];
