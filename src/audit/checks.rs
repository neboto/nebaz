//! The built-in checks (#60). Each is a pure function over an
//! [`AuditInput`]: typed rows from the list cache (or their raw ARM JSON),
//! warm lazy sections, and a clock value passed in. None of them can
//! fetch (ADR 0007); a gap in its input is a note, never a pass.
//!
//! Severity rule of thumb: **critical** is reachable by anyone now (a
//! world-open admin port, a 0.0.0.0–255.255.255.255 firewall rule, a guest
//! Owner); **high** removes a whole layer (anonymous pull, plain HTTP, no
//! RBAC); **medium** widens the attack surface or weakens a control
//! (public network with no rules, local auth, shared keys); **low** is
//! hygiene; **info** is a configuration worth knowing about.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::{AuditFinding, AuditInput, Check, Severity, AUDIT_LAZY_MAX};
use crate::azure::graph;
use crate::azure::resource::{name_of_id, Resource};
use crate::azure::service::JumpView;
use crate::azure::services::aks::ClusterRow;
use crate::azure::services::app_service::SiteRow;
use crate::azure::services::container_apps::{ContainerAppRow, EnvironmentRow, JobRow, Workload};
use crate::azure::services::container_registry::RegistryRow;
use crate::azure::services::cosmos::CosmosAccountRow;
use crate::azure::services::directory::{AppRegistrationRow, DirectoryBase, Expiry, ServicePrincipalRow};
use crate::azure::services::json;
use crate::azure::services::keyvault::VaultRow;
use crate::azure::services::network::{NsgRow, SecurityRule, SubnetRow, VnetRow};
use crate::azure::services::power_platform::{EnterprisePolicyRow, POWER_PLATFORM_DELEGATION};
use crate::azure::services::redis::{ManagedRedisRow, RedisCacheRow};
use crate::azure::services::sql::SqlServerRow;
use crate::azure::services::storage::StorageAccountRow;
use crate::lazy::Lazy;

use JumpView as V;

const NSGS: &[V] = &[V::NetworkSecurityGroups];
const SUBNETS: &[V] = &[V::VirtualNetworks, V::Subnets];
const STORAGE: &[V] = &[V::StorageAccounts];
const VAULTS: &[V] = &[V::KeyVaults];
const SQL: &[V] = &[V::SqlServers];
const COSMOS: &[V] = &[V::CosmosAccounts];
const AKS: &[V] = &[V::Clusters];
const ACR: &[V] = &[V::Registries];
const SITES: &[V] = &[V::WebApps];
const ACA_APPS: &[V] = &[V::ContainerApps];
const ACA_ENVS: &[V] = &[V::ContainerAppEnvironments];
const PP: &[V] = &[V::EnterprisePolicies];
const APP_REGS: &[V] = &[V::AppRegistrations];
const SPS: &[V] = &[V::ServicePrincipals];
const REDIS: &[V] = &[V::RedisCaches];
const AMR: &[V] = &[V::ManagedRedis];

/// The checks, in display order (findings sort by severity anyway).
pub static CHECKS: [Check; 35] = [
    // ── Network ──
    Check {
        id: "nsg-open-internet",
        title: "NSG allows inbound from the internet",
        why: "An Allow rule whose source is *, Internet or 0.0.0.0/0 lets anyone reach whatever the NSG guards. SSH and RDP are scanned within minutes of exposure; database and cache ports next. 80/443 is normal for a public front end.",
        fix: "Narrow the rule's source to the address ranges that need it, or remove it. Reach VMs through Azure Bastion or a VPN, and databases through private endpoints. Press N on the NSG for the effective access across NIC and subnet NSGs.",
        sources: &[NSGS],
        run: nsg_open_internet,
    },
    Check {
        id: "subnet-pp-no-nsg",
        title: "Power Platform subnet has no NSG",
        why: "A subnet delegated to Microsoft.PowerPlatform/enterprisePolicies carries the outbound traffic of every Power Platform environment linked to the policy. With no NSG, nothing restricts where that traffic goes inside the VNet.",
        fix: "Associate an NSG with the subnet (Microsoft's guidance for Power Platform VNet support) and allow only the destinations the environments need.",
        sources: &[SUBNETS],
        run: subnet_pp_no_nsg,
    },
    // ── Storage ──
    Check {
        id: "storage-blob-public-access",
        title: "Storage account allows public blob access",
        why: "With allowBlobPublicAccess on, any container can be switched to anonymous read, and one mistaken setting publishes its blobs to the internet.",
        fix: "Set allowBlobPublicAccess to false on the account (Configuration → Allow Blob anonymous access: Disabled). Check the Containers section for containers already public first.",
        sources: &[STORAGE],
        run: storage_blob_public,
    },
    Check {
        id: "storage-shared-key",
        title: "Storage account allows shared key access",
        why: "Account keys grant full data access, never expire, and bypass Entra ID and RBAC entirely; SAS tokens signed with them inherit that. Unset means allowed.",
        fix: "Move clients to Entra ID (RBAC data roles), then set allowSharedKeyAccess to false (Configuration → Allow storage account key access: Disabled).",
        sources: &[STORAGE],
        run: storage_shared_key,
    },
    Check {
        id: "storage-min-tls",
        title: "Storage account accepts TLS below 1.2",
        why: "TLS 1.0 and 1.1 have known weaknesses and Azure is retiring them; a minimum below 1.2 lets a client negotiate down.",
        fix: "Set minimumTlsVersion to TLS1_2 (Configuration → Minimum TLS version).",
        sources: &[STORAGE],
        run: storage_min_tls,
    },
    Check {
        id: "storage-https-only",
        title: "Storage account allows plain HTTP",
        why: "With supportsHttpsTrafficOnly off, requests (and the SAS tokens or keys they carry) can travel unencrypted.",
        fix: "Set supportsHttpsTrafficOnly to true (Configuration → Secure transfer required: Enabled).",
        sources: &[STORAGE],
        run: storage_https_only,
    },
    Check {
        id: "storage-public-network",
        title: "Storage account open to all networks",
        why: "Public network access is enabled and the network rules' default action is Allow, so the account's endpoints accept requests from any IP; only the credential stands in the way.",
        fix: "Set the network default action to Deny and allow the VNets and IP ranges that need it, or disable public network access and use private endpoints.",
        sources: &[STORAGE],
        run: storage_public_network,
    },
    // ── Key Vault ──
    Check {
        id: "kv-purge-protection",
        title: "Key vault purge protection off",
        why: "Without purge protection, a deleted vault or secret can be purged before its retention ends: one compromised identity can destroy keys irrecoverably.",
        fix: "Enable purge protection (Properties → Purge protection). It cannot be turned off again, by design.",
        sources: &[VAULTS],
        run: kv_purge_protection,
    },
    Check {
        id: "kv-soft-delete",
        title: "Key vault soft delete off",
        why: "With soft delete off, a deleted secret, key or certificate is gone at once, with no recovery window.",
        fix: "Enable soft delete (it is mandatory on new vaults; an old vault keeps the setting until changed).",
        sources: &[VAULTS],
        run: kv_soft_delete,
    },
    Check {
        id: "kv-public-network",
        title: "Key vault open to all networks",
        why: "Public network access is enabled and the firewall's default action is Allow, so the vault answers from any IP; only the token stands in the way.",
        fix: "Set the firewall default action to Deny with the VNets and IPs that need it, or disable public access and use a private endpoint.",
        sources: &[VAULTS],
        run: kv_public_network,
    },
    // ── SQL ──
    Check {
        id: "sql-public-network",
        title: "SQL server public network access enabled",
        why: "The server's public endpoint accepts connections from any address its firewall rules admit. A private endpoint with public access disabled removes the endpoint altogether.",
        fix: "Disable public network access (Networking → Public access: Disable) and connect through private endpoints, or keep the firewall rules to known ranges.",
        sources: &[SQL],
        run: sql_public_network,
    },
    Check {
        id: "sql-firewall-open",
        title: "SQL firewall rule admits the whole internet",
        why: "A rule from 0.0.0.0 to 255.255.255.255 lets any IP reach the server's login; only the password stands in the way. 0.0.0.0–0.0.0.0 (Allow Azure services) admits every Azure tenant's traffic, not just yours.",
        fix: "Delete the rule and add ranges for the clients that need it, or move to a private endpoint. Prefer VNet rules or private endpoints over \"Allow Azure services\".",
        sources: &[SQL],
        run: sql_firewall_open,
    },
    Check {
        id: "sql-min-tls",
        title: "SQL server accepts TLS below 1.2",
        why: "A minimal TLS version below 1.2 (or None) lets clients connect with deprecated protocols.",
        fix: "Set the minimal TLS version to 1.2 (Networking → Connectivity → Minimum TLS version).",
        sources: &[SQL],
        run: sql_min_tls,
    },
    // ── Cosmos DB ──
    Check {
        id: "cosmos-public-network",
        title: "Cosmos DB public network access enabled",
        why: "The account's endpoint is reachable from the internet. With no IP or VNet rules it accepts any address; with rules, only those.",
        fix: "Add IP or VNet rules (Networking → Selected networks), or disable public network access and use private endpoints.",
        sources: &[COSMOS],
        run: cosmos_public_network,
    },
    Check {
        id: "cosmos-local-auth",
        title: "Cosmos DB key-based auth enabled",
        why: "With disableLocalAuth off, the primary and secondary keys grant full data access and bypass Entra ID and RBAC.",
        fix: "Move clients to Entra ID with Cosmos DB data-plane RBAC, then set disableLocalAuth to true on the account.",
        sources: &[COSMOS],
        run: cosmos_local_auth,
    },
    // ── AKS ──
    Check {
        id: "aks-public-api",
        title: "AKS API server open to the internet",
        why: "A public cluster with no authorized IP ranges exposes the Kubernetes API to any address: authentication still applies, but credential stuffing and any API server vulnerability reach it.",
        fix: "Set authorized IP ranges on the API server, or make the cluster private (or use API server VNet integration).",
        sources: &[AKS],
        run: aks_public_api,
    },
    Check {
        id: "aks-local-accounts",
        title: "AKS local accounts enabled",
        why: "Local accounts give a static cluster-admin kubeconfig that bypasses Entra ID, Conditional Access and audit by identity.",
        fix: "With Entra ID integration on, set disableLocalAccounts to true; admins then sign in through Entra ID.",
        sources: &[AKS],
        run: aks_local_accounts,
    },
    Check {
        id: "aks-rbac-disabled",
        title: "AKS Kubernetes RBAC disabled",
        why: "Without Kubernetes RBAC every authenticated user is effectively cluster-admin. It can only be set when the cluster is created.",
        fix: "Recreate the cluster with RBAC enabled (and Entra ID integration), then migrate workloads.",
        sources: &[AKS],
        run: aks_rbac_disabled,
    },
    // ── Container Registry ──
    Check {
        id: "acr-admin-user",
        title: "Container registry admin user enabled",
        why: "The admin user is one shared username and password with push and pull on every repository, not tied to any identity.",
        fix: "Give pullers and pushers RBAC roles (AcrPull / AcrPush) or tokens, then disable the admin user (Access keys → Admin user).",
        sources: &[ACR],
        run: acr_admin_user,
    },
    Check {
        id: "acr-anonymous-pull",
        title: "Container registry allows anonymous pull",
        why: "Anyone who can reach the registry can pull every image without credentials, with whatever is baked into them.",
        fix: "Turn anonymous pull access off and grant AcrPull to the identities that need it.",
        sources: &[ACR],
        run: acr_anonymous_pull,
    },
    // ── App Service ──
    Check {
        id: "app-https-only",
        title: "App Service app allows plain HTTP",
        why: "With httpsOnly off the app answers on HTTP, so cookies, tokens and form posts can travel unencrypted.",
        fix: "Set httpsOnly to true (Configuration → General settings → HTTPS Only: On).",
        sources: &[SITES],
        run: app_https_only,
    },
    Check {
        id: "app-min-tls",
        title: "App Service app accepts TLS below 1.2",
        why: "A minimum TLS version below 1.2 lets clients negotiate deprecated protocols.",
        fix: "Set minTlsVersion to 1.2 (Configuration → General settings → Minimum inbound TLS version).",
        sources: &[SITES],
        run: app_min_tls,
    },
    Check {
        id: "app-ftps",
        title: "App Service app allows plain FTP",
        why: "ftpsState AllAllowed accepts FTP without TLS, so deployment credentials and content cross the network in clear text.",
        fix: "Set ftpsState to FtpsOnly, or Disabled when nothing deploys over FTP (Configuration → General settings → FTP state).",
        sources: &[SITES],
        run: app_ftps,
    },
    // ── Container Apps ──
    Check {
        id: "aca-ingress-open",
        title: "Container app ingress external with no IP restrictions",
        why: "External ingress with no IP security restrictions accepts traffic from anywhere the environment is reachable: the internet for an external environment, the whole VNet (and anything peered or on-premises) for an internal one.",
        fix: "Add ipSecurityRestrictions allowing only the callers that need it, or set ingress to internal (environment-only) when nothing outside the environment calls the app.",
        sources: &[ACA_APPS],
        run: aca_ingress_open,
    },
    Check {
        id: "aca-allow-insecure",
        title: "Container app ingress allows plain HTTP",
        why: "allowInsecure lets clients call the app over HTTP instead of being redirected to HTTPS.",
        fix: "Set ingress allowInsecure to false.",
        sources: &[ACA_APPS],
        run: aca_allow_insecure,
    },
    Check {
        id: "aca-env-external-pp-vnet",
        title: "Container Apps environment external in a Power Platform VNet",
        why: "A Power Platform enterprise policy injects into this VNet, so Power Platform reaches the environment privately — but the environment is external, so its apps' ingress also faces the internet. A private path from Power Platform usually means an internal environment.",
        fix: "If only the VNet (and Power Platform) should reach the apps, use an internal environment (it is set at creation: create one with internal: true and move the apps). Otherwise restrict each app's ingress by IP.",
        sources: &[ACA_ENVS, PP],
        run: aca_env_external_pp_vnet,
    },
    Check {
        id: "aca-secrets-not-kv",
        title: "Container app secrets stored in the app, not Key Vault",
        why: "A secret held in the app's own configuration is readable by anyone with write (listSecrets) on the app and is rotated by redeploying. A Key Vault reference keeps it in one audited place, read by a managed identity.",
        fix: "Move the secret to Key Vault and set the app secret's keyVaultUrl and identity instead of a value.",
        sources: &[ACA_APPS],
        run: aca_secrets_not_kv,
    },
    // ── Redis ──
    Check {
        id: "redis-non-ssl-port",
        title: "Redis cache non-SSL port enabled",
        why: "Port 6379 carries the access key and every command in clear text: anyone on the path can read the data and replay the key. Every current client library speaks TLS on 6380.",
        fix: "Move clients to the SSL port (6380) with TLS, then turn off the non-SSL port (enableNonSslPort false).",
        sources: &[REDIS],
        run: redis_non_ssl_port,
    },
    Check {
        id: "redis-min-tls",
        title: "Redis cache allows TLS below 1.2",
        why: "TLS 1.0 and 1.1 have known weaknesses and are being retired across Azure; a minimum below 1.2 lets a client (or a downgrade) negotiate them.",
        fix: "Set the cache's minimum TLS version to 1.2 once the clients support it.",
        sources: &[REDIS],
        run: redis_min_tls,
    },
    Check {
        id: "redis-public-no-firewall",
        title: "Redis cache public with no firewall rules",
        why: "A cache with public network access, no VNet injection and no firewall rules accepts connections from every IP address; only the access key (or Entra token) stands between the internet and the data.",
        fix: "Turn off public network access and reach the cache through a private endpoint, or add firewall rules for the address ranges that need it. Prefer Entra authentication and turn off access keys.",
        sources: &[REDIS],
        run: redis_public_no_firewall,
    },
    Check {
        id: "amr-min-tls",
        title: "Managed Redis allows TLS below 1.2",
        why: "TLS 1.0 and 1.1 have known weaknesses and are being retired across Azure; a minimum below 1.2 lets a client negotiate them.",
        fix: "Set the cluster's minimum TLS version to 1.2.",
        sources: &[AMR],
        run: amr_min_tls,
    },
    // ── Power Platform ──
    Check {
        id: "pp-policy-unhealthy",
        title: "Power Platform enterprise policy not healthy",
        why: "A policy whose health is not Healthy may not be applying its network injection or encryption to the linked environments, which then fall back to the public path or lose the customer-managed key.",
        fix: "Open the policy in the Power Platform admin center and check the subnet delegation, its free addresses and the key vault access the policy's identity needs.",
        sources: &[PP],
        run: pp_policy_unhealthy,
    },
    // ── Directory (Microsoft Graph) ──
    Check {
        id: "appreg-credential-expiry",
        title: "App registration credential expired or expiring",
        why: "An expired secret or certificate breaks whatever signs in with it; one expiring soon is an outage on a date. Long-lived secrets are themselves a risk: federated credentials avoid them.",
        fix: "Add a new credential, roll it out to the client, then remove the old one; prefer a federated credential or a managed identity over a secret.",
        sources: &[APP_REGS],
        run: appreg_credential_expiry,
    },
    Check {
        id: "sp-credential-expiry",
        title: "Service principal credential expired or expiring",
        why: "A credential on the service principal itself (often a SAML signing certificate) that has expired breaks sign-in to the app; one expiring soon is an outage on a date.",
        fix: "Add a new certificate or secret before the old one ends, make it active, then remove the old one.",
        sources: &[SPS],
        run: sp_credential_expiry,
    },
    // ── Access ──
    Check {
        id: "sub-privileged-guest-or-sp",
        title: "Owner or User Access Administrator held by a guest or service principal",
        why: "Owner and User Access Administrator can grant any role on the subscription. Held by a guest, control sits with another tenant's account lifecycle; held by a service principal, with whoever holds its credential.",
        fix: "Replace the assignment with a narrower role (Contributor or a custom role), scoped to the resource group that needs it; use PIM for standing admin access.",
        sources: &[],
        run: sub_privileged_guest_or_sp,
    },
];

// ── Shared readers ────────────────────────────────────────────────────

fn eq(a: Option<&str>, b: &str) -> bool {
    a.is_some_and(|a| a.eq_ignore_ascii_case(b))
}

/// `publicNetworkAccess`: anything but Disabled (or a perimeter) is open;
/// absent means the service default, which is enabled.
fn public_enabled(pna: Option<&str>) -> bool {
    !(eq(pna, "Disabled") || eq(pna, "SecuredByPerimeter"))
}

/// A minimum TLS value below 1.2, whatever the RP's spelling: `TLS1_0`,
/// `1.1`, `Tls11`, `Tls` (Cosmos for 1.0), `None` (SQL: no minimum).
pub(crate) fn tls_below_1_2(v: &str) -> bool {
    let digits: String = v.chars().filter(char::is_ascii_digit).collect();
    matches!(digits.as_str(), "" | "1" | "10" | "11")
}

fn raw(r: &dyn Resource) -> Value {
    r.raw_content().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
}

/// Per-resource lazy data a check reads: the loaded payloads, and one
/// note for the resources whose data isn't there.
#[derive(Default)]
struct LazyGaps {
    total: usize,
    missing: usize,
    loading: usize,
    failed: Vec<String>,
}

impl LazyGaps {
    fn see<'x, T>(&mut self, name: &str, l: Option<&'x Lazy<T>>) -> Option<&'x T> {
        self.total += 1;
        match l {
            Some(Lazy::Loaded(v)) => Some(v),
            Some(Lazy::Loading) => {
                self.loading += 1;
                None
            }
            Some(Lazy::Error(e)) => {
                self.failed.push(format!("{}: {}", name, e));
                None
            }
            None => {
                self.missing += 1;
                None
            }
        }
    }

    fn note(self, check: &'static Check, what: &str, section: &str, out: &mut Vec<AuditFinding>) {
        let mut status = Vec::new();
        let mut reason = Vec::new();
        if self.missing > 0 {
            status.push(format!("{} of {} not checked — r fetches {}", self.missing, self.total, what));
            reason.push(format!(
                "{} isn't loaded for {} of {}, so they weren't checked. Press r here (it fetches up to {} each) or open each one's {} section.",
                what, self.missing, self.total, AUDIT_LAZY_MAX, section
            ));
        }
        if self.loading > 0 {
            status.push(format!("{} loading…", self.loading));
            reason.push(format!("{} of {} are loading; the check runs on each as it lands.", self.loading, self.total));
        }
        if !self.failed.is_empty() {
            status.push(format!("{} unreadable", self.failed.len()));
            reason.push(format!("Couldn't read {} for {}: {}", what, self.failed.len(), self.failed.join("; ")));
        }
        if !status.is_empty() {
            out.push(AuditFinding::note(check, status.join(" · "), reason.join(" ")));
        }
    }
}

// ── Network ───────────────────────────────────────────────────────────

/// Sources that mean "anyone".
fn is_world(prefix: &str) -> bool {
    matches!(
        prefix.trim().to_ascii_lowercase().as_str(),
        "*" | "internet" | "any" | "0.0.0.0/0" | "0.0.0.0" | "::/0"
    )
}

/// Remote administration: open to the world is critical.
const ADMIN_PORTS: &[u16] = &[22, 3389];
/// Databases, caches, file sharing and control planes: high.
const SENSITIVE_PORTS: &[u16] = &[
    20, 21, 23, 135, 139, 445, 1433, 1434, 1521, 2049, 2375, 2376, 2379, 3306, 5432, 5601, 5900, 5984, 5985, 5986,
    6379, 9200, 9300, 11211, 27017,
];

fn port_range(p: &str) -> Option<(u16, u16)> {
    let p = p.trim();
    if p == "*" || p.eq_ignore_ascii_case("any") {
        return Some((0, u16::MAX));
    }
    match p.split_once('-') {
        Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
        None => p.parse().ok().map(|n| (n, n)),
    }
}

pub(crate) fn rule_severity(rule: &SecurityRule) -> Severity {
    if rule.protocol.to_ascii_lowercase().starts_with("icmp") {
        return Severity::Low;
    }
    let ranges: Vec<(u16, u16)> = rule.destination_ports.iter().filter_map(|p| port_range(p)).collect();
    if ranges.is_empty() {
        return Severity::Medium;
    }
    ranges
        .iter()
        .map(|&(from, to)| {
            let hits = |ports: &[u16]| ports.iter().any(|p| (from..=to).contains(p));
            if (from == 0 && to == u16::MAX) || hits(ADMIN_PORTS) {
                Severity::Critical
            } else if hits(SENSITIVE_PORTS) {
                Severity::High
            } else if from == to && (from == 80 || from == 443) {
                Severity::Low
            } else {
                Severity::Medium
            }
        })
        .min()
        .unwrap_or(Severity::Medium)
}

fn nsg_open_internet(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for nsg in input.of::<NsgRow>(V::NetworkSecurityGroups) {
        let world: Vec<&SecurityRule> = nsg
            .rules
            .iter()
            .filter(|r| !r.is_default)
            .filter(|r| r.direction.eq_ignore_ascii_case("Inbound") && r.access.eq_ignore_ascii_case("Allow"))
            .filter(|r| {
                if r.source_prefixes.is_empty() {
                    is_world(&r.source)
                } else {
                    r.source_prefixes.iter().any(|p| is_world(p))
                }
            })
            .collect();
        let Some(severity) = world.iter().map(|r| rule_severity(r)).min() else {
            continue;
        };
        let mut what: Vec<String> = Vec::new();
        for r in &world {
            let w = format!("{} {}", r.protocol, r.destination_port);
            if !what.contains(&w) {
                what.push(w);
            }
        }
        let mut evidence: Vec<String> = world
            .iter()
            .map(|r| {
                let line = format!(
                    "{} {} · {} {} from {} ({})",
                    json::num(r.priority),
                    r.name,
                    r.protocol,
                    r.destination_port,
                    r.source,
                    rule_severity(r).label()
                );
                match &r.description {
                    Some(d) => format!("{line} — {d}"),
                    None => line,
                }
            })
            .collect();
        evidence.push(format!(
            "attached to {} NIC(s) and {} subnet(s)",
            nsg.nic_ids.len(),
            nsg.subnet_ids.len()
        ));
        out.push(
            AuditFinding::about(check, severity, nsg, format!("inbound from the internet on {}", what.join(", ")))
                .with_evidence(evidence),
        );
    }
}

/// Every cached subnet, from the VNets list and the Subnets list, once.
fn subnets<'a>(input: &AuditInput<'a>) -> Vec<&'a SubnetRow> {
    let mut seen = HashSet::new();
    input
        .of::<VnetRow>(V::VirtualNetworks)
        .flat_map(|v| v.subnets.iter())
        .chain(input.of::<SubnetRow>(V::Subnets))
        .filter(|s| seen.insert(s.id.to_lowercase()))
        .collect()
}

fn subnet_pp_no_nsg(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for s in subnets(input) {
        let delegated = s.delegations.iter().any(|d| d.eq_ignore_ascii_case(POWER_PLATFORM_DELEGATION));
        if delegated && s.nsg_id.is_none() {
            out.push(
                AuditFinding::about(check, Severity::Medium, s, "delegated to Power Platform, no NSG").with_evidence(vec![
                    format!("delegations: {}", s.delegations.join(", ")),
                    "networkSecurityGroup: none".into(),
                ]),
            );
        }
    }
}

// ── Storage ───────────────────────────────────────────────────────────

fn storage_blob_public(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<StorageAccountRow>(V::StorageAccounts) {
        if a.allow_blob_public_access == Some(true) {
            out.push(
                AuditFinding::about(check, Severity::High, a, "allowBlobPublicAccess is true")
                    .with_evidence(vec!["allowBlobPublicAccess: true".into()]),
            );
        }
    }
}

fn storage_shared_key(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<StorageAccountRow>(V::StorageAccounts) {
        let reason = match a.allow_shared_key_access {
            Some(false) => continue,
            Some(true) => "allowSharedKeyAccess is true",
            None => "allowSharedKeyAccess unset (allowed)",
        };
        out.push(
            AuditFinding::about(check, Severity::Medium, a, reason)
                .with_evidence(vec![format!("allowSharedKeyAccess: {}", json::yes_no(a.allow_shared_key_access))]),
        );
    }
}

fn storage_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<StorageAccountRow>(V::StorageAccounts) {
        if let Some(tls) = a.min_tls.as_deref().filter(|t| tls_below_1_2(t)) {
            out.push(
                AuditFinding::about(check, Severity::High, a, format!("minimumTlsVersion {}", tls))
                    .with_evidence(vec![format!("minimumTlsVersion: {}", tls)]),
            );
        }
    }
}

fn storage_https_only(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<StorageAccountRow>(V::StorageAccounts) {
        if a.https_only == Some(false) {
            out.push(
                AuditFinding::about(check, Severity::High, a, "supportsHttpsTrafficOnly is false")
                    .with_evidence(vec!["supportsHttpsTrafficOnly: false".into()]),
            );
        }
    }
}

fn storage_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<StorageAccountRow>(V::StorageAccounts) {
        if public_enabled(a.public_network_access.as_deref()) && !eq(a.network_default_action.as_deref(), "Deny") {
            out.push(
                AuditFinding::about(check, Severity::Medium, a, "public network access, default action Allow").with_evidence(
                    vec![
                        format!("publicNetworkAccess: {}", json::opt(a.public_network_access.clone())),
                        format!("networkAcls.defaultAction: {}", json::opt(a.network_default_action.clone())),
                    ],
                ),
            );
        }
    }
}

// ── Key Vault ─────────────────────────────────────────────────────────

fn kv_purge_protection(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for v in input.of::<VaultRow>(V::KeyVaults) {
        if v.purge_protection != Some(true) {
            out.push(
                AuditFinding::about(check, Severity::Medium, v, "purge protection off")
                    .with_evidence(vec![format!("enablePurgeProtection: {}", json::yes_no(v.purge_protection))]),
            );
        }
    }
}

fn kv_soft_delete(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for v in input.of::<VaultRow>(V::KeyVaults) {
        if v.soft_delete == Some(false) {
            out.push(
                AuditFinding::about(check, Severity::High, v, "soft delete off")
                    .with_evidence(vec!["enableSoftDelete: false".into()]),
            );
        }
    }
}

fn kv_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for v in input.of::<VaultRow>(V::KeyVaults) {
        if public_enabled(v.public_network_access.as_deref()) && !eq(v.acl_default_action.as_deref(), "Deny") {
            out.push(
                AuditFinding::about(check, Severity::Medium, v, "public network access, default action Allow").with_evidence(
                    vec![
                        format!("publicNetworkAccess: {}", json::opt(v.public_network_access.clone())),
                        format!("networkAcls.defaultAction: {}", json::opt(v.acl_default_action.clone())),
                        format!("private endpoints: {}", v.private_endpoint_ids.len()),
                    ],
                ),
            );
        }
    }
}

// ── SQL ───────────────────────────────────────────────────────────────

fn sql_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for s in input.of::<SqlServerRow>(V::SqlServers) {
        if public_enabled(s.public_network_access.as_deref()) {
            out.push(
                AuditFinding::about(check, Severity::Medium, s, "public network access enabled").with_evidence(vec![
                    format!("publicNetworkAccess: {}", json::opt(s.public_network_access.clone())),
                    format!("private endpoints: {}", s.private_endpoint_ids.len()),
                ]),
            );
        }
    }
}

fn sql_firewall_open(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let mut gaps = LazyGaps::default();
    for s in input.of::<SqlServerRow>(V::SqlServers) {
        let rules = gaps.see(&s.base.name, input.lazy().and_then(|l| l.sql_firewall_rules.get(&s.base.id)));
        let Some(rules) = rules else { continue };
        let mut worst: Option<Severity> = None;
        let mut evidence = Vec::new();
        for r in rules {
            let start = json::text(r, "/properties/startIpAddress");
            let end = json::text(r, "/properties/endIpAddress");
            let sev = match (start.as_str(), end.as_str()) {
                ("0.0.0.0", "255.255.255.255") => Severity::Critical,
                ("0.0.0.0", "0.0.0.0") => Severity::Low,
                _ => continue,
            };
            evidence.push(format!("{}: {} – {} ({})", json::text(r, "/name"), start, end, sev.label()));
            worst = Some(worst.map_or(sev, |w| w.min(sev)));
        }
        if let Some(sev) = worst {
            let reason = if sev == Severity::Critical {
                "firewall rule 0.0.0.0 – 255.255.255.255"
            } else {
                "firewall allows all Azure services (0.0.0.0)"
            };
            out.push(AuditFinding::about(check, sev, s, reason).with_evidence(evidence));
        }
    }
    gaps.note(check, "firewall rules", "Firewall", out);
}

fn sql_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for s in input.of::<SqlServerRow>(V::SqlServers) {
        if let Some(tls) = s.min_tls.as_deref().filter(|t| tls_below_1_2(t)) {
            out.push(
                AuditFinding::about(check, Severity::Medium, s, format!("minimalTlsVersion {}", tls))
                    .with_evidence(vec![format!("minimalTlsVersion: {}", tls)]),
            );
        }
    }
}

// ── Cosmos DB ─────────────────────────────────────────────────────────

fn cosmos_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<CosmosAccountRow>(V::CosmosAccounts) {
        if !public_enabled(a.public_network_access.as_deref()) {
            continue;
        }
        let vnet = a.vnet_filter == Some(true) && !a.subnet_ids.is_empty();
        let (sev, reason) = if a.ip_rules.is_empty() && !vnet {
            (Severity::Medium, "public network access, no IP or VNet rules".to_string())
        } else {
            (
                Severity::Low,
                format!("public network access limited to {} IP rule(s), {} VNet rule(s)", a.ip_rules.len(), a.subnet_ids.len()),
            )
        };
        out.push(AuditFinding::about(check, sev, a, reason).with_evidence(vec![
            format!("publicNetworkAccess: {}", json::opt(a.public_network_access.clone())),
            format!("ipRules: {}", json::join(&a.ip_rules)),
            format!("isVirtualNetworkFilterEnabled: {}", json::yes_no(a.vnet_filter)),
            format!("private endpoints: {}", a.private_endpoint_ids.len()),
        ]));
    }
}

fn cosmos_local_auth(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<CosmosAccountRow>(V::CosmosAccounts) {
        if a.local_auth_disabled != Some(true) {
            out.push(
                AuditFinding::about(check, Severity::Medium, a, "disableLocalAuth is false (keys work)")
                    .with_evidence(vec![format!("disableLocalAuth: {}", json::yes_no(a.local_auth_disabled))]),
            );
        }
    }
}

// ── AKS ───────────────────────────────────────────────────────────────

fn aks_public_api(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for c in input.of::<ClusterRow>(V::Clusters) {
        if c.private_cluster != Some(true) && c.authorized_ip_ranges.is_empty() {
            out.push(
                AuditFinding::about(check, Severity::High, c, "public API server, no authorized IP ranges").with_evidence(vec![
                    format!("enablePrivateCluster: {}", json::yes_no(c.private_cluster)),
                    "authorizedIPRanges: none".into(),
                    format!("fqdn: {}", json::opt(c.fqdn.clone())),
                ]),
            );
        }
    }
}

fn aks_local_accounts(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for c in input.of::<ClusterRow>(V::Clusters) {
        let disabled = json::bool_at(&raw(c), "/properties/disableLocalAccounts");
        if disabled != Some(true) {
            out.push(
                AuditFinding::about(check, Severity::Medium, c, "local accounts enabled")
                    .with_evidence(vec![format!("disableLocalAccounts: {}", json::yes_no(disabled))]),
            );
        }
    }
}

fn aks_rbac_disabled(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for c in input.of::<ClusterRow>(V::Clusters) {
        if c.enable_rbac == Some(false) {
            out.push(
                AuditFinding::about(check, Severity::High, c, "Kubernetes RBAC disabled")
                    .with_evidence(vec!["enableRBAC: false".into()]),
            );
        }
    }
}

// ── Container Registry ────────────────────────────────────────────────

fn acr_admin_user(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for r in input.of::<RegistryRow>(V::Registries) {
        if r.admin_user_enabled == Some(true) {
            out.push(
                AuditFinding::about(check, Severity::Medium, r, "admin user enabled")
                    .with_evidence(vec!["adminUserEnabled: true".into()]),
            );
        }
    }
}

fn acr_anonymous_pull(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for r in input.of::<RegistryRow>(V::Registries) {
        if r.anonymous_pull_enabled == Some(true) {
            out.push(
                AuditFinding::about(check, Severity::High, r, "anonymous pull enabled").with_evidence(vec![
                    "anonymousPullEnabled: true".into(),
                    format!("publicNetworkAccess: {}", json::opt(r.public_network_access.clone())),
                ]),
            );
        }
    }
}

// ── App Service ───────────────────────────────────────────────────────

fn app_https_only(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for s in input.of::<SiteRow>(V::WebApps) {
        if s.https_only == Some(false) {
            out.push(
                AuditFinding::about(check, Severity::High, s, "httpsOnly is false")
                    .with_evidence(vec!["httpsOnly: false".into()]),
            );
        }
    }
}

/// A site-config check: `test` reads `GET {site}/config/web` (the
/// Configuration section's lazy data) and says what it found.
fn site_config_check(
    check: &'static Check,
    input: &AuditInput,
    out: &mut Vec<AuditFinding>,
    test: fn(&Value) -> Option<(Severity, String, String)>,
) {
    let mut gaps = LazyGaps::default();
    for s in input.of::<SiteRow>(V::WebApps) {
        let config = gaps.see(&s.base.name, input.lazy().and_then(|l| l.site_configs.get(&s.base.id)));
        if let Some((sev, reason, evidence)) = config.and_then(test) {
            out.push(AuditFinding::about(check, sev, s, reason).with_evidence(vec![evidence]));
        }
    }
    gaps.note(check, "site configs", "Configuration", out);
}

fn app_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    site_config_check(check, input, out, |c| {
        let tls = json::str_at(c, "/properties/minTlsVersion")?;
        tls_below_1_2(&tls).then(|| (Severity::Medium, format!("minTlsVersion {}", tls), format!("minTlsVersion: {}", tls)))
    });
}

fn app_ftps(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    site_config_check(check, input, out, |c| {
        let ftps = json::str_at(c, "/properties/ftpsState")?;
        ftps.eq_ignore_ascii_case("AllAllowed")
            .then(|| (Severity::Medium, "plain FTP allowed (ftpsState AllAllowed)".into(), format!("ftpsState: {}", ftps)))
    });
}

// ── Redis ─────────────────────────────────────────────────────────────

fn redis_non_ssl_port(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for c in input.of::<RedisCacheRow>(V::RedisCaches) {
        if c.non_ssl_port == Some(true) {
            let port = c.port.map(|p| p.to_string()).unwrap_or_else(|| "6379".into());
            out.push(
                AuditFinding::about(check, Severity::High, c, format!("non-SSL port {} enabled", port))
                    .with_evidence(vec!["enableNonSslPort: true".into(), format!("port: {}", port)]),
            );
        }
    }
}

fn redis_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for c in input.of::<RedisCacheRow>(V::RedisCaches) {
        if let Some(tls) = c.min_tls.as_deref().filter(|t| tls_below_1_2(t)) {
            out.push(
                AuditFinding::about(check, Severity::Medium, c, format!("minimumTlsVersion {}", tls))
                    .with_evidence(vec![format!("minimumTlsVersion: {}", tls)]),
            );
        }
    }
}

/// Public, not VNet-injected (its subnet and NSG would decide), and the
/// warm Network section's firewall list is empty. A cache whose rules
/// aren't loaded is counted in the note, never passed.
fn redis_public_no_firewall(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let mut gaps = LazyGaps::default();
    for c in input.of::<RedisCacheRow>(V::RedisCaches) {
        if !public_enabled(c.public_network_access.as_deref()) || c.subnet_id.is_some() {
            continue;
        }
        let rules = gaps.see(&c.base.name, input.lazy().and_then(|l| l.redis_firewall_rules.get(&c.base.id)));
        if rules.is_some_and(|r| r.is_empty()) {
            out.push(
                AuditFinding::about(check, Severity::Medium, c, "public network access, no firewall rules").with_evidence(vec![
                    format!("publicNetworkAccess: {}", c.public_network_access.as_deref().unwrap_or("(default: Enabled)")),
                    "firewall rules: none".into(),
                    format!("private endpoints: {}", c.private_endpoints.len()),
                ]),
            );
        }
    }
    gaps.note(check, "firewall rules", "Network", out);
}

fn amr_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for c in input.of::<ManagedRedisRow>(V::ManagedRedis) {
        if let Some(tls) = c.min_tls.as_deref().filter(|t| tls_below_1_2(t)) {
            out.push(
                AuditFinding::about(check, Severity::Medium, c, format!("minimumTlsVersion {}", tls))
                    .with_evidence(vec![format!("minimumTlsVersion: {}", tls)]),
            );
        }
    }
}

// ── Container Apps ────────────────────────────────────────────────────

/// The cached environments by lowercase id.
fn environments<'a>(input: &AuditInput<'a>) -> HashMap<String, &'a EnvironmentRow> {
    input
        .of::<EnvironmentRow>(V::ContainerAppEnvironments)
        .map(|e| (e.base.id.to_lowercase(), e))
        .collect()
}

fn aca_ingress_open(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let envs = environments(input);
    for app in input.of::<ContainerAppRow>(V::ContainerApps) {
        let Some(ingress) = &app.ingress else { continue };
        if json::bool_at(ingress, "/external") != Some(true) {
            continue;
        }
        let restrictions = json::arr(ingress, "/ipSecurityRestrictions");
        if !restrictions.is_empty() {
            continue;
        }
        let env = app.workload.environment_id.as_deref().and_then(|id| envs.get(&id.to_lowercase()));
        let (sev, reach) = match env.and_then(|e| e.internal) {
            Some(true) => (Severity::Low, "reachable from the whole VNet (internal environment)"),
            Some(false) => (Severity::Medium, "reachable from the internet (external environment)"),
            None if env.is_some() => (Severity::Medium, "reachable from the internet (no VNet: public environment)"),
            None => (Severity::Medium, "reachable from wherever the environment is (load @aca Environments to tell)"),
        };
        out.push(
            AuditFinding::about(check, sev, app, "external ingress, no IP restrictions").with_evidence(vec![
                "ingress.external: true".into(),
                "ingress.ipSecurityRestrictions: none".into(),
                reach.into(),
            ]),
        );
    }
}

fn aca_allow_insecure(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for app in input.of::<ContainerAppRow>(V::ContainerApps) {
        let Some(ingress) = &app.ingress else { continue };
        if json::bool_at(ingress, "/allowInsecure") == Some(true) {
            out.push(
                AuditFinding::about(check, Severity::Medium, app, "ingress allowInsecure is true")
                    .with_evidence(vec!["ingress.allowInsecure: true".into()]),
            );
        }
    }
}

/// `…/virtualNetworks/{vnet}` of a subnet id, lowercased.
fn vnet_of_subnet(subnet_id: &str) -> Option<String> {
    let lower = subnet_id.to_lowercase();
    lower.find("/subnets/").map(|i| lower[..i].to_string())
}

fn aca_env_external_pp_vnet(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let policies: Vec<&EnterprisePolicyRow> = input.of::<EnterprisePolicyRow>(V::EnterprisePolicies).collect();
    for env in input.of::<EnvironmentRow>(V::ContainerAppEnvironments) {
        if env.internal == Some(true) {
            continue;
        }
        let Some(subnet) = env.infrastructure_subnet_id.as_deref() else { continue };
        let Some(vnet) = vnet_of_subnet(subnet) else { continue };
        let matching: Vec<&&EnterprisePolicyRow> = policies
            .iter()
            .filter(|p| p.networks.iter().any(|n| n.vnet_id.to_lowercase() == vnet))
            .collect();
        if matching.is_empty() {
            continue;
        }
        let mut evidence = vec![
            format!("vnetConfiguration.internal: {}", json::yes_no(env.internal)),
            format!("infrastructure subnet: {}", subnet),
        ];
        for p in &matching {
            evidence.push(format!("Power Platform policy {} injects into {}", p.base.name, name_of_id(&vnet)));
        }
        out.push(
            AuditFinding::about(check, Severity::Info, env, format!("external environment in Power Platform VNet {}", name_of_id(&vnet)))
                .with_evidence(evidence),
        );
    }
}

fn secrets_finding(check: &'static Check, r: &dyn Resource, w: &Workload) -> Option<AuditFinding> {
    let plain: Vec<String> = w
        .secrets
        .iter()
        .filter(|s| json::str_at(s, "/keyVaultUrl").filter(|u| !u.is_empty()).is_none())
        .map(|s| json::text(s, "/name"))
        .collect();
    if plain.is_empty() {
        return None;
    }
    let mut evidence: Vec<String> = plain.iter().map(|n| format!("secret {}: stored in the app (no keyVaultUrl)", n)).collect();
    evidence.push(format!("{} of {} secrets are Key Vault references", w.secrets.len() - plain.len(), w.secrets.len()));
    Some(
        AuditFinding::about(check, Severity::Low, r, format!("{} secret(s) not from Key Vault", plain.len()))
            .with_evidence(evidence),
    )
}

fn aca_secrets_not_kv(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for app in input.of::<ContainerAppRow>(V::ContainerApps) {
        out.extend(secrets_finding(check, app, &app.workload));
    }
    // Jobs carry the same secrets block; checked when their list is warm.
    for job in input.of::<JobRow>(V::ContainerAppJobs) {
        out.extend(secrets_finding(check, job, &job.workload));
    }
}

// ── Power Platform ────────────────────────────────────────────────────

fn pp_policy_unhealthy(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for p in input.of::<EnterprisePolicyRow>(V::EnterprisePolicies) {
        let Some(health) = p.health.as_deref() else { continue };
        if !health.eq_ignore_ascii_case("Healthy") {
            out.push(
                AuditFinding::about(check, Severity::Medium, p, format!("health {}", health))
                    .with_evidence(vec![format!("healthStatus: {}", health), format!("kind: {}", json::opt(p.kind.clone()))]),
            );
        }
    }
}

// ── Directory ─────────────────────────────────────────────────────────

/// The worst credential's finding, re-dated against the input's clock.
fn credential_finding(check: &'static Check, r: &dyn Resource, base: &DirectoryBase, now: i64) -> Option<AuditFinding> {
    let mut creds = json::arr(&base.json, "/passwordCredentials");
    let secrets = creds.len();
    creds.extend(json::arr(&base.json, "/keyCredentials"));
    let mut worst: Option<Severity> = None;
    let mut evidence = Vec::new();
    for (i, c) in creds.iter().enumerate() {
        let end = json::str_at(c, "/endDateTime");
        let e = Expiry::of(end.as_deref(), now);
        let sev = match e {
            Expiry::Expired => Severity::Medium,
            Expiry::Expiring(_) => Severity::Low,
            _ => continue,
        };
        let kind = if i < secrets { "secret" } else { "certificate" };
        let name = json::str_at(c, "/displayName").filter(|n| !n.is_empty()).unwrap_or_else(|| json::text(c, "/keyId"));
        evidence.push(format!("{} {}: ends {} ({})", kind, name, json::opt(end), e.describe()));
        worst = Some(worst.map_or(sev, |w| w.min(sev)));
    }
    let sev = worst?;
    let reason = if sev == Severity::Medium { "credential expired" } else { "credential expiring within 30 days" };
    Some(AuditFinding::about(check, sev, r, reason).with_evidence(evidence))
}

fn appreg_credential_expiry(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<AppRegistrationRow>(V::AppRegistrations) {
        out.extend(credential_finding(check, a, &a.base, input.now()));
    }
}

fn sp_credential_expiry(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    // A managed identity's credentials are Azure's to rotate.
    for sp in input.of::<ServicePrincipalRow>(V::ServicePrincipals).filter(|s| !s.is_managed_identity()) {
        out.extend(credential_finding(check, sp, &sp.base, input.now()));
    }
}

// ── Access ────────────────────────────────────────────────────────────

/// Built-in role definition GUIDs (the same in every tenant).
pub(crate) const OWNER_ROLE: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
pub(crate) const USER_ACCESS_ADMIN_ROLE: &str = "18d7d88d-4d8f-4c43-8eb6-b8f9ecb4e6ef";

/// The role an assignment grants, when it is Owner or User Access
/// Administrator.
pub(crate) fn privileged_role(a: &Value) -> Option<&'static str> {
    let def = json::str_at(a, "/properties/roleDefinitionId")?.to_lowercase();
    if def.ends_with(OWNER_ROLE) {
        Some("Owner")
    } else if def.ends_with(USER_ACCESS_ADMIN_ROLE) {
        Some("User Access Administrator")
    } else {
        None
    }
}

/// Whether a directory user object is a guest: `userType` when Graph
/// returned it, else the `#EXT#` marker in the UPN.
fn is_guest(v: &Value) -> bool {
    json::str_at(v, "/userType").is_some_and(|t| t.eq_ignore_ascii_case("Guest"))
        || json::str_at(v, "/userPrincipalName").is_some_and(|u| u.contains("#EXT#"))
}

fn sub_privileged_guest_or_sp(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let scope = input.subscription_scope();
    let lazy = input.lazy();
    let assignments = match lazy.and_then(|l| l.role_assignments.get(&scope)) {
        Some(Lazy::Loaded(items)) => items,
        Some(Lazy::Loading) => {
            out.push(AuditFinding::note(
                check,
                "loading…".into(),
                "The subscription's role assignments are loading; this check runs when they land.".into(),
            ));
            return;
        }
        Some(Lazy::Error(e)) => {
            out.push(AuditFinding::note(
                check,
                "not checked — role assignments unreadable".into(),
                format!("Reading the subscription's role assignments failed: {}", e),
            ));
            return;
        }
        None => {
            out.push(AuditFinding::note(
                check,
                "not checked — r fetches the subscription's role assignments".into(),
                "This check reads the subscription's Access list (role assignments at and above the subscription). Press r here, or open the subscription's Access section.".into(),
            ));
            return;
        }
    };
    let mut unresolved = 0usize;
    for a in assignments {
        let Some(role) = privileged_role(a) else { continue };
        let kind = json::str_at(a, "/properties/principalType").unwrap_or_default();
        let pid = json::text(a, "/properties/principalId").to_lowercase();
        let principal = lazy.and_then(|l| l.principals.get(&pid));
        let display = match principal {
            Some(Lazy::Loaded(v)) => graph::object_display(v),
            _ => pid.clone(),
        };
        let (sev, who) = if kind.eq_ignore_ascii_case("ServicePrincipal") {
            (Severity::High, "service principal")
        } else if kind.eq_ignore_ascii_case("User") {
            match principal {
                Some(Lazy::Loaded(v)) if is_guest(v) => (Severity::Critical, "guest user"),
                Some(Lazy::Loaded(_)) => continue,
                _ => {
                    unresolved += 1;
                    continue;
                }
            }
        } else {
            continue;
        };
        let at = json::text(a, "/properties/scope");
        out.push(
            AuditFinding::at(
                check,
                sev,
                &scope,
                &display,
                None,
                HashMap::new(),
                format!("{} on the subscription held by a {}", role, who),
            )
            .with_evidence(vec![
                format!("role: {}", role),
                format!("principal: {} ({}) · {}", display, kind, pid),
                format!("assigned at: {}", at),
                format!("assignment: {}", json::text(a, "/id")),
            ]),
        );
        // One row per assignment: the row id carries the principal.
        if let Some(last) = out.last_mut() {
            last.row_id = format!("audit:{}:{}:{}", check.id, pid, role);
        }
    }
    if unresolved > 0 {
        out.push(AuditFinding::note(
            check,
            format!("{} privileged user(s) not resolved — r looks them up", unresolved),
            format!(
                "{} Owner / User Access Administrator user(s) aren't resolved in Microsoft Graph yet, so whether they are guests is unknown. Press r here, or open the subscription's Access section.",
                unresolved
            ),
        ));
    }
}

/// The privileged User principals of a loaded Access list, lowercased: the
/// object ids `r` resolves through Graph for the guest test.
pub fn privileged_user_ids(items: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for a in items {
        if privileged_role(a).is_none() {
            continue;
        }
        if !json::str_at(a, "/properties/principalType").is_some_and(|k| k.eq_ignore_ascii_case("User")) {
            continue;
        }
        if let Some(id) = json::str_at(a, "/properties/principalId").map(|s| s.to_lowercase()) {
            if graph::is_object_id(&id) && !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
