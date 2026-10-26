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
//! hygiene; **info** is a configuration worth knowing about. Availability
//! and cost findings (a link down, a plan protecting nothing) use the same
//! scale by impact: **medium** when traffic stops, **low** when something
//! bills for nothing or rides on one zone, **info** for leftovers.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::{AuditFinding, AuditInput, Check, Severity, AUDIT_LAZY_MAX};
use crate::azure::graph;
use crate::azure::resource::{name_of_id, Resource};
use crate::azure::service::JumpView;
use crate::azure::services::aks::ClusterRow;
use crate::azure::services::app_service::SiteRow;
use crate::azure::services::backup::{self, BackupVaultRow, RecoveryVaultRow};
use crate::azure::services::compute::{DiskRow, NicRow};
use crate::azure::services::container_apps::{ContainerAppRow, EnvironmentRow, JobRow, Workload};
use crate::azure::services::container_registry::RegistryRow;
use crate::azure::services::cosmos::CosmosAccountRow;
use crate::azure::services::directory::{AppRegistrationRow, DirectoryBase, Expiry, ServicePrincipalRow};
use crate::azure::services::edge::{WafKind, WafPolicyRow};
use crate::azure::services::firewall::{AzureFirewallRow, CloudNgfwRow, FirewallPolicyRow};
use crate::azure::services::hybrid::{CircuitRow, ConnectionRow, GatewayRow};
use crate::azure::services::foundry::FoundryRow;
use crate::azure::services::json;
use crate::azure::services::keyvault::VaultRow;
use crate::azure::services::messaging::{EventHubsRow, Namespace, ServiceBusRow};
use crate::azure::services::network::{NsgRow, Peering, SecurityRule, SubnetRow, VnetRow};
use crate::azure::services::network_edge::{LoadBalancerRow, PublicIpRow};
use crate::azure::services::network_hub::DdosPlanRow;
use crate::azure::services::network_private::{PrivateEndpointRow, PrivateLinkConnection};
use crate::azure::services::postgres_mysql::{Engine, FlexibleServerRow};
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
const SERVICE_BUS: &[V] = &[V::ServiceBusNamespaces];
const EVENT_HUBS: &[V] = &[V::EventHubNamespaces];
const PG: &[V] = &[V::PostgresServers];
const MYSQL: &[V] = &[V::MysqlServers];
const FOUNDRY: &[V] = &[V::AiAccounts];
const WAFS: &[V] = &[V::WafPolicies];
const DISKS: &[V] = &[V::Disks];
const VNETS: &[V] = &[V::VirtualNetworks];
const PES: &[V] = &[V::PrivateEndpoints];
const PIPS: &[V] = &[V::PublicIps];
const NICS: &[V] = &[V::Nics];
const LBS: &[V] = &[V::LoadBalancers];
const DDOS: &[V] = &[V::DdosPlans];
const CIRCUITS: &[V] = &[V::ExpressRouteCircuits];
const GATEWAYS: &[V] = &[V::VnetGateways];
const CONNECTIONS: &[V] = &[V::GatewayConnections];
const AFWS: &[V] = &[V::AzureFirewalls];
const FWPS: &[V] = &[V::FirewallPolicies];
const NGFWS: &[V] = &[V::CloudNgfws];
const RSVS: &[V] = &[V::RecoveryVaults];
const BVS: &[V] = &[V::BackupVaults];

/// The checks, in display order (findings sort by severity anyway).
pub static CHECKS: [Check; 72] = [
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
    Check {
        id: "waf-not-blocking",
        title: "WAF policy in Detection mode or disabled",
        why: "In Detection mode the WAF logs a matched attack and lets it through; disabled, it does nothing. Either way the gateway or Front Door it is attached to is unprotected while the policy reads as present.",
        fix: "Review the WAF logs for false positives, add exclusions for them, then switch the policy to Prevention (Policy settings → Prevention mode) and make sure its state is Enabled.",
        sources: &[WAFS],
        run: waf_not_blocking,
    },
    Check {
        id: "subnet-no-nsg",
        title: "Subnet has no NSG",
        why: "With no NSG on the subnet, nothing filters traffic into or out of it at the subnet boundary: every VNet, peered network and on-premises range reaches whatever lands there, and a NIC without its own NSG is open. Subnets that cannot carry one (GatewaySubnet, AzureFirewallSubnet, AzureFirewallManagementSubnet, RouteServerSubnet) and private-endpoint-only subnets with network policies off are skipped; AzureBastionSubnet supports one and is checked. A Power Platform subnet is subnet-pp-no-nsg instead.",
        fix: "Associate an NSG with the subnet that allows only what its workloads need (for AzureBastionSubnet, Microsoft's required Bastion rules). Press N on the subnet for the effective access.",
        sources: &[SUBNETS],
        run: subnet_no_nsg,
    },
    Check {
        id: "peering-not-connected",
        title: "VNet peering not connected",
        why: "A peering that is not Connected carries no traffic: Initiated means the other side was never created, Disconnected that it was deleted. Whatever is reached through the peer (a hub's firewall, a shared service, a failover VNet) is unreachable.",
        fix: "Create the peering on the remote VNet; a Disconnected peering must be deleted and recreated on both sides.",
        sources: &[VNETS],
        run: peering_not_connected,
    },
    Check {
        id: "pe-not-approved",
        title: "Private endpoint connection not approved",
        why: "Until the target's owner approves the connection, the endpoint's private IP carries nothing: clients whose DNS resolves to it fail, or fall back to the public endpoint. Rejected and Disconnected never recover on their own.",
        fix: "Approve the connection on the target resource (Networking → Private endpoint connections), or delete the endpoint if it is no longer wanted and recreate it after a rejection.",
        sources: &[PES],
        run: pe_not_approved,
    },
    Check {
        id: "pip-unattached",
        title: "Public IP unattached",
        why: "A static public IP bills whether or not anything uses it, and an address left allocated is one a later mistake can attach to something that should not face the internet. Not a weakness on its own: info, below the default --fail-on. A Cloud NGFW's public IPs show no attachment; they are skipped when the Cloud NGFW list is warm.",
        fix: "Delete it if nothing needs the address, or attach it to the resource that should own it.",
        sources: &[PIPS],
        run: pip_unattached,
    },
    Check {
        id: "nic-orphaned",
        title: "Network interface attached to nothing",
        why: "A NIC with no VM (and no private endpoint or private link service owning it) is usually left over from a deleted VM: it holds a private IP in its subnet and keeps its NSG and load balancer memberships. Hygiene: info.",
        fix: "Delete it once nothing will reattach it.",
        sources: &[NICS],
        run: nic_orphaned,
    },
    Check {
        id: "lb-empty-pool",
        title: "Load balancer backend pool empty",
        why: "A backend pool with no NIC and no address receives nothing: a rule using it drops every connection, and a Standard load balancer still bills for its rules. Often a leftover, sometimes a scale set that lost its pool membership. Info.",
        fix: "Add the backends to the pool, or delete the empty pool (or the load balancer) if nothing uses it.",
        sources: &[LBS],
        run: lb_empty_pool,
    },
    Check {
        id: "ddos-plan-unused",
        title: "DDoS protection plan covers no VNet",
        why: "A DDoS Network Protection plan bills a fixed monthly fee (about USD 2,900) from creation, whether or not a VNet is linked to it. With none, it protects nothing.",
        fix: "Link the VNets with public endpoints to the plan (VNet → DDoS protection), or delete the plan; one plan can cover VNets across subscriptions in the tenant.",
        sources: &[DDOS],
        run: ddos_plan_unused,
    },
    // ── Hybrid ──
    Check {
        id: "er-connection-down",
        title: "ExpressRoute connection not connected",
        why: "A gateway connection to an ExpressRoute circuit that reads NotConnected carries no traffic: the private path to on-premises is down, and traffic falls back to a VPN if there is one, or fails.",
        fix: "Check the circuit's private peering and provider state, then the connection's authorization; the circuit's and gateway's Connections sections show both sides.",
        sources: &[CONNECTIONS],
        run: er_connection_down,
    },
    Check {
        id: "vpn-connection-down",
        title: "VPN connection not connected",
        why: "A site-to-site or VNet-to-VNet connection that reads NotConnected carries no traffic: the tunnel is down, so the site (or the backup path it provides) is unreachable.",
        fix: "Compare the shared key and the IKE / IPsec policy with the on-premises device, and the local network gateway's address and prefixes with the site; the gateway's VPN diagnostics run in the portal.",
        sources: &[CONNECTIONS],
        run: vpn_connection_down,
    },
    Check {
        id: "er-circuit-not-provisioned",
        title: "ExpressRoute circuit enabled but not provisioned by the provider",
        why: "A circuit bills from the moment it is created, but carries nothing until the connectivity provider provisions its side. NotProvisioned long after creation is usually an order never completed, or one cancelled with the circuit left behind.",
        fix: "Give the service key to the provider (or chase the order); delete the circuit if it is no longer wanted.",
        sources: &[CIRCUITS],
        run: er_circuit_not_provisioned,
    },
    Check {
        id: "gateway-not-zone-redundant",
        title: "Virtual network gateway not zone-redundant",
        why: "A non-AZ gateway SKU runs in one zone, so a zone outage takes the on-premises path down with it. ErGw*AZ, ErGwScale and VpnGw*AZ spread the instances across zones, and Microsoft is retiring the non-AZ VPN SKUs. Basic VPN gateways have no AZ variant and are skipped.",
        fix: "Migrate the gateway to the matching AZ SKU (ErGw1AZ…, VpnGw1AZ…), which also needs a Standard, zone-redundant public IP.",
        sources: &[GATEWAYS],
        run: gateway_not_zone_redundant,
    },
    // ── Firewall ──
    Check {
        id: "fw-threat-intel-off",
        title: "Azure Firewall threat intelligence off",
        why: "Threat intelligence filtering alerts on (or denies) traffic to and from known malicious IPs and domains from Microsoft's feed; Off drops that layer. A firewall with a policy uses the policy's mode (its own setting is ignored), so the attached policy is judged, and a policy with no mode of its own takes its base policy's.",
        fix: "Set threat intelligence to Alert, or Deny once the alerts are reviewed (the policy's Threat intelligence page, or the firewall's for classic rules).",
        sources: &[AFWS, FWPS],
        run: fw_threat_intel_off,
    },
    Check {
        id: "ngfw-marketplace-not-subscribed",
        title: "Cloud NGFW Marketplace subscription not active",
        why: "A Palo Alto Networks Cloud NGFW runs on its Azure Marketplace subscription: Suspended (often an expired or unpaid offer) or Unsubscribed stops the firewall, and every route that sends traffic through it black-holes. A subscription still being fulfilled is not yet passing traffic either.",
        fix: "Restore the Marketplace subscription (Azure portal → SaaS resources, or the Palo Alto Networks account), or move the routes off the firewall before removing it.",
        sources: &[NGFWS],
        run: ngfw_marketplace_not_subscribed,
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
    // ── Backup ──
    Check {
        id: "backup-soft-delete-off",
        title: "Backup vault has soft delete off",
        why: "With soft delete off, deleting a protected item's backup data (or the vault's last policy) removes the recovery points at once. Ransomware operators and a compromised admin delete backups first; soft delete keeps them recoverable for 14 days or more.",
        fix: "Turn soft delete on (Recovery Services vault → Properties → Security settings; Backup vault → Properties → Soft delete), ideally Always On so it cannot be turned off again.",
        sources: &[RSVS, BVS],
        run: backup_soft_delete_off,
    },
    Check {
        id: "backup-item-failing",
        title: "Protected item's last backup failed or is overdue",
        why: "A protected item whose last backup failed (or whose protection is in error) is only as recoverable as its last good recovery point, and the gap grows every day it goes unnoticed. Overdue means a Protected item with no backup for 36 hours (8 days on a weekly policy).",
        fix: "Open the vault's Protected items (or Failed jobs) for the error; fix the cause (the VM agent or extension, network egress to the backup service, a missing permission), then run an on-demand backup and watch the job.",
        sources: &[RSVS, BVS],
        run: backup_item_failing,
    },
    Check {
        id: "backup-vault-hardening",
        title: "Backup vault without immutability or multi-user authorization",
        why: "Immutability stops recovery points being deleted (or retention shortened) before they expire; multi-user authorization puts a resource guard, owned by someone else, in front of the critical operations (disabling soft delete, stopping protection). Without either, one compromised vault admin can destroy the backups.",
        fix: "Enable immutability (and lock it once settled) and protect the vault with a resource guard in another subscription (Properties → Multi-user authorization).",
        sources: &[RSVS, BVS],
        run: backup_vault_hardening,
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
    // ── Messaging ──
    Check {
        id: "sb-local-auth",
        title: "Service Bus namespace allows SAS key auth",
        why: "With local auth on, a shared access key (a connection string) grants send, listen or manage to whoever holds it, with no identity in the logs and no expiry until someone rotates it. Entra ID with RBAC names every caller.",
        fix: "Move clients to Entra ID (a managed identity with the Data Sender / Receiver role), then set disableLocalAuth to true on the namespace.",
        sources: &[SERVICE_BUS],
        run: sb_local_auth,
    },
    Check {
        id: "sb-min-tls",
        title: "Service Bus namespace allows TLS below 1.2",
        why: "TLS 1.0 and 1.1 have known weaknesses and are being retired across Azure; a minimum below 1.2 lets a client negotiate them.",
        fix: "Set the namespace's minimum TLS version to 1.2.",
        sources: &[SERVICE_BUS],
        run: sb_min_tls,
    },
    Check {
        id: "sb-public-network",
        title: "Service Bus namespace reachable from every network",
        why: "With public network access on and the firewall's default action Allow (or Deny with no rule, which Azure does not enforce), any address on the internet can connect; only the key or token stands in the way.",
        fix: "Turn off public network access and use private endpoints, or set the default action to Deny with IP or VNet rules for the callers that need it (Premium for Service Bus VNet rules).",
        sources: &[SERVICE_BUS],
        run: sb_public_network,
    },
    Check {
        id: "eh-local-auth",
        title: "Event Hubs namespace allows SAS key auth",
        why: "With local auth on, a shared access key (a connection string) grants send, listen or manage to whoever holds it, with no identity in the logs and no expiry until someone rotates it. Entra ID with RBAC names every caller.",
        fix: "Move clients to Entra ID (a managed identity with the Data Sender / Receiver role), then set disableLocalAuth to true on the namespace.",
        sources: &[EVENT_HUBS],
        run: eh_local_auth,
    },
    Check {
        id: "eh-min-tls",
        title: "Event Hubs namespace allows TLS below 1.2",
        why: "TLS 1.0 and 1.1 have known weaknesses and are being retired across Azure; a minimum below 1.2 lets a client negotiate them.",
        fix: "Set the namespace's minimum TLS version to 1.2.",
        sources: &[EVENT_HUBS],
        run: eh_min_tls,
    },
    Check {
        id: "eh-public-network",
        title: "Event Hubs namespace reachable from every network",
        why: "With public network access on and the firewall's default action Allow (or Deny with no rule, which Azure does not enforce), any address on the internet can connect; only the key or token stands in the way.",
        fix: "Turn off public network access and use private endpoints, or set the default action to Deny with IP or VNet rules for the callers that need it (Premium for Service Bus VNet rules).",
        sources: &[EVENT_HUBS],
        run: eh_public_network,
    },
    // ── PostgreSQL & MySQL ──
    Check {
        id: "pg-public-network",
        title: "PostgreSQL server public network access enabled",
        why: "With public access on, the server has an internet endpoint and its firewall rules are the only network control: one broad rule (or Allow Azure services) away from every address. A VNet-integrated server or a private endpoint takes it off the internet.",
        fix: "Reach the server through a private endpoint (or a VNet-integrated server) and set public network access to Disabled; until then keep the firewall rules to the exact addresses that need it.",
        sources: &[PG],
        run: pg_public_network,
    },
    Check {
        id: "pg-firewall-open",
        title: "PostgreSQL server firewall open to the internet or to all of Azure",
        why: "A 0.0.0.0–255.255.255.255 rule admits every address on the internet; the 0.0.0.0 rule (Allow Azure services) admits every Azure service, in any tenant. Either leaves only the password or token in the way.",
        fix: "Delete the rule and add rules for the addresses that need the server, or move callers to a private endpoint and turn off public access.",
        sources: &[PG],
        run: pg_firewall_open,
    },
    Check {
        id: "pg-insecure-transport",
        title: "PostgreSQL server accepts unencrypted connections",
        why: "require_secure_transport off lets a client connect without TLS, so credentials and every query cross the network in clear text.",
        fix: "Set the server parameter require_secure_transport to ON once every client connects with TLS (sslmode=require or stricter).",
        sources: &[PG],
        run: pg_insecure_transport,
    },
    Check {
        id: "pg-min-tls",
        title: "PostgreSQL server allows TLS below 1.2",
        why: "TLS 1.0 and 1.1 have known weaknesses and are being retired across Azure; a minimum below 1.2 lets a client negotiate them.",
        fix: "Set the server parameter ssl_min_protocol_version to TLSv1.2.",
        sources: &[PG],
        run: pg_min_tls,
    },
    Check {
        id: "pg-password-no-entra",
        title: "PostgreSQL server uses passwords with no Entra admin",
        why: "Password authentication with no Microsoft Entra admin means every login is a database password: no conditional access, no MFA, no managed identity, and rotation by hand.",
        fix: "Enable Microsoft Entra authentication, add an Entra admin (a group), move apps to managed identities, then consider turning password authentication off.",
        sources: &[PG],
        run: pg_password_no_entra,
    },
    Check {
        id: "mysql-public-network",
        title: "MySQL server public network access enabled",
        why: "With public access on, the server has an internet endpoint and its firewall rules are the only network control: one broad rule (or Allow Azure services) away from every address. A VNet-integrated server or a private endpoint takes it off the internet.",
        fix: "Reach the server through a private endpoint (or a VNet-integrated server) and set public network access to Disabled; until then keep the firewall rules to the exact addresses that need it.",
        sources: &[MYSQL],
        run: mysql_public_network,
    },
    Check {
        id: "mysql-firewall-open",
        title: "MySQL server firewall open to the internet or to all of Azure",
        why: "A 0.0.0.0–255.255.255.255 rule admits every address on the internet; the 0.0.0.0 rule (Allow Azure services) admits every Azure service, in any tenant. Either leaves only the password or token in the way.",
        fix: "Delete the rule and add rules for the addresses that need the server, or move callers to a private endpoint and turn off public access.",
        sources: &[MYSQL],
        run: mysql_firewall_open,
    },
    Check {
        id: "mysql-insecure-transport",
        title: "MySQL server accepts unencrypted connections",
        why: "require_secure_transport OFF lets a client connect without TLS, so credentials and every query cross the network in clear text.",
        fix: "Set the server parameter require_secure_transport to ON once every client connects with TLS (ssl-mode=REQUIRED or stricter).",
        sources: &[MYSQL],
        run: mysql_insecure_transport,
    },
    Check {
        id: "mysql-min-tls",
        title: "MySQL server allows TLS below 1.2",
        why: "TLS 1.0 and 1.1 have known weaknesses and are being retired across Azure; a tls_version that lists them lets a client negotiate them.",
        fix: "Set the server parameter tls_version to TLSv1.2 (and TLSv1.3 where supported).",
        sources: &[MYSQL],
        run: mysql_min_tls,
    },
    Check {
        id: "mysql-password-no-entra",
        title: "MySQL server uses passwords with no Entra admin",
        why: "With no Microsoft Entra admin every login is a database password: no conditional access, no MFA, no managed identity, and rotation by hand.",
        fix: "Add a Microsoft Entra admin (a group, with a user-assigned identity for the Graph lookups), move apps to managed identities, then consider aad_auth_only.",
        sources: &[MYSQL],
        run: mysql_password_no_entra,
    },
    // ── Foundry ──
    Check {
        id: "foundry-public-network",
        title: "Foundry / AI Services account open to all networks",
        why: "Public network access is enabled and the network ACL's default action is Allow, so the account's endpoint (models, agents, keys) answers from any IP; only the key or token stands in the way.",
        fix: "Set the network default action to Deny with the IP ranges and VNets that need it, or disable public network access and use a private endpoint (Networking → Firewalls and virtual networks).",
        sources: &[FOUNDRY],
        run: foundry_public_network,
    },
    Check {
        id: "foundry-local-auth",
        title: "Foundry / AI Services account allows key auth",
        why: "With disableLocalAuth off, the account's two API keys grant full use of every deployment, bypass Entra ID and RBAC, and leave no identity in the logs.",
        fix: "Move callers to Entra ID (a managed identity with Cognitive Services OpenAI User or Azure AI User), then set disableLocalAuth to true on the account.",
        sources: &[FOUNDRY],
        run: foundry_local_auth,
    },
    // ── Compute ──
    Check {
        id: "disk-unattached",
        title: "Managed disk unattached",
        why: "An unattached disk bills at its full provisioned size and still holds whatever the VM it came from wrote, outside any VM's controls. Not a weakness on its own: hygiene, so info, below the default --fail-on.",
        fix: "Snapshot it if the data may be needed, then delete it; or attach it to the VM that should own it.",
        sources: &[DISKS],
        run: disk_unattached,
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
    Check {
        id: "sub-contributor-guest-or-sp",
        title: "Contributor on the subscription held by a guest or service principal",
        why: "Contributor at subscription scope can change or delete every resource and read most of their keys and connection strings, though it cannot grant access. Held by a guest, that sits with another tenant's account lifecycle; held by a service principal, with whoever holds its credential.",
        fix: "Scope the assignment to the resource groups the principal works in, or replace it with the narrower built-in roles it needs; use PIM for standing access.",
        sources: &[],
        run: sub_contributor_guest_or_sp,
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

/// An attached WAF policy that does not block: Detection mode, or its
/// state off. An unattached policy protects nothing either way: skipped.
fn waf_not_blocking(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for w in input.of::<WafPolicyRow>(V::WafPolicies) {
        if w.associations.is_empty() {
            continue;
        }
        let reason = if w.enabled == Some(false) {
            "policy disabled".to_string()
        } else if eq(w.mode.as_deref(), "Detection") {
            "Detection mode (logs, does not block)".to_string()
        } else {
            continue;
        };
        let kind = match w.kind {
            WafKind::AppGateway => "App Gateway",
            WafKind::FrontDoor => "Front Door",
        };
        let mut evidence = vec![
            format!("kind: {}", kind),
            format!("policySettings.mode: {}", json::opt(w.mode.clone())),
            format!("policySettings state: {}", match w.enabled {
                Some(true) => "Enabled",
                Some(false) => "Disabled",
                None => "-",
            }),
        ];
        evidence.extend(w.associations.iter().map(|a| format!("attached to: {}", a)));
        out.push(AuditFinding::about(check, Severity::Medium, w, reason).with_evidence(evidence));
    }
}

/// Azure's own subnets that refuse (or must not have) an NSG.
const NO_NSG_SUBNETS: &[&str] = &["GatewaySubnet", "AzureFirewallSubnet", "AzureFirewallManagementSubnet", "RouteServerSubnet"];

/// Delegations whose subnets cannot take an NSG. Azure NetApp Files with
/// Basic network features is the one left (Standard supports NSGs, and the
/// subnet does not say which it is): skipped rather than guessed.
const NO_NSG_DELEGATIONS: &[&str] = &["Microsoft.Netapp/volumes"];

/// Every subnet with no NSG, except the ones Azure won't let carry one, a
/// private-endpoint-only subnet whose network policies are off (an NSG
/// would not apply to its endpoints) and a Power Platform subnet (its own,
/// higher check, `subnet-pp-no-nsg`).
fn subnet_no_nsg(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for s in subnets(input) {
        if s.nsg_id.is_some() || NO_NSG_SUBNETS.iter().any(|n| s.name.eq_ignore_ascii_case(n)) {
            continue;
        }
        let delegated = |names: &[&str]| s.delegations.iter().any(|d| names.iter().any(|n| d.eq_ignore_ascii_case(n)));
        if delegated(NO_NSG_DELEGATIONS) || delegated(&[POWER_PLATFORM_DELEGATION]) {
            continue;
        }
        let pe_policies_on = s
            .private_endpoint_policies
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case("Enabled") || p.to_ascii_lowercase().contains("networksecuritygroup"));
        if s.private_endpoint_count > 0 && s.ip_configuration_count <= s.private_endpoint_count && !pe_policies_on {
            continue;
        }
        let mut evidence = vec![
            "networkSecurityGroup: none".to_string(),
            format!("address prefixes: {}", json::join(&s.prefixes)),
            format!("IP configurations: {}", s.ip_configuration_count),
        ];
        if !s.delegations.is_empty() {
            evidence.push(format!("delegations: {}", s.delegations.join(", ")));
        }
        out.push(AuditFinding::about(check, Severity::Low, s, "no NSG on the subnet").with_evidence(evidence));
    }
}

fn peering_not_connected(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for v in input.of::<VnetRow>(V::VirtualNetworks) {
        let down: Vec<&Peering> = v
            .peerings
            .iter()
            .filter(|p| p.state.as_deref().is_some_and(|s| !s.eq_ignore_ascii_case("Connected")))
            .collect();
        if down.is_empty() {
            continue;
        }
        let what: Vec<String> = down
            .iter()
            .map(|p| format!("{} {}", p.name, p.state.as_deref().unwrap_or("-")))
            .collect();
        let evidence = down
            .iter()
            .map(|p| {
                format!(
                    "{}: peeringState {} → {}",
                    p.name,
                    p.state.as_deref().unwrap_or("-"),
                    p.remote_id.as_deref().unwrap_or("-")
                )
            })
            .collect();
        out.push(
            AuditFinding::about(check, Severity::Medium, v, format!("peering {}", what.join(", "))).with_evidence(evidence),
        );
    }
}

/// One finding per endpoint: Rejected or Disconnected (it will not come
/// back) is medium, Pending (waiting on the owner) low.
fn pe_not_approved(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for pe in input.of::<PrivateEndpointRow>(V::PrivateEndpoints) {
        let bad: Vec<&PrivateLinkConnection> = pe
            .connections
            .iter()
            .filter(|c| c.status.as_deref().is_some_and(|s| !s.eq_ignore_ascii_case("Approved")))
            .collect();
        if bad.is_empty() {
            continue;
        }
        let severity = if bad.iter().all(|c| eq(c.status.as_deref(), "Pending")) { Severity::Low } else { Severity::Medium };
        let statuses: Vec<String> = bad.iter().filter_map(|c| c.status.clone()).collect();
        let evidence = bad
            .iter()
            .map(|c| {
                let mut line = format!(
                    "{}: {} → {}{}",
                    c.name,
                    c.status.as_deref().unwrap_or("-"),
                    c.target_id.as_deref().map(name_of_id).unwrap_or("-"),
                    if c.manual { " (manual approval)" } else { "" }
                );
                if let Some(d) = c.description.as_deref().filter(|d| !d.is_empty()) {
                    line.push_str(&format!(" — {d}"));
                }
                line
            })
            .collect();
        out.push(
            AuditFinding::about(check, severity, pe, format!("connection {}", statuses.join(", "))).with_evidence(evidence),
        );
    }
}

/// The public IPs the warm Cloud NGFWs use (ids and addresses, lowercased):
/// ARM shows them attached to nothing.
fn ngfw_public_ips(input: &AuditInput) -> HashSet<String> {
    input
        .of::<CloudNgfwRow>(V::CloudNgfws)
        .flat_map(|n| n.public_ips.iter().chain(n.egress_nat_ips.iter()))
        .flat_map(|ip| [json::str_at(ip, "/resourceId"), json::str_at(ip, "/address")])
        .flatten()
        .map(|s| s.to_lowercase())
        .collect()
}

fn pip_unattached(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let ngfw_warm = input.has_slot(NGFWS);
    let ngfw_ips = ngfw_public_ips(input);
    for p in input.of::<PublicIpRow>(V::PublicIps) {
        if p.attached_to().is_some() {
            continue;
        }
        // A dynamic IP with no address holds nothing and bills nothing.
        if p.address.is_none() && eq(p.allocation.as_deref(), "Dynamic") {
            continue;
        }
        let used_by_ngfw = ngfw_ips.contains(&p.base.id.to_lowercase())
            || p.address.as_deref().is_some_and(|a| ngfw_ips.contains(&a.to_lowercase()));
        if used_by_ngfw {
            continue;
        }
        let mut evidence = vec![
            "ipConfiguration: none · natGateway: none".to_string(),
            format!(
                "address: {} · {} · sku {}",
                json::opt(p.address.clone()),
                json::opt(p.allocation.clone()),
                json::opt(p.sku.clone())
            ),
        ];
        if !ngfw_warm {
            evidence.push("the Cloud NGFW list isn't loaded: a Cloud NGFW's public IP also reads as attached to nothing (open @ngfw)".into());
        }
        let reason = match &p.address {
            Some(a) => format!("{} attached to nothing", a),
            None => "attached to nothing".to_string(),
        };
        out.push(AuditFinding::about(check, Severity::Info, p, reason).with_evidence(evidence));
    }
}

fn nic_orphaned(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for n in input.of::<NicRow>(V::Nics) {
        if n.vm_id.is_some() {
            continue;
        }
        let v = raw(n);
        let owned = ["/properties/privateEndpoint", "/properties/privateLinkService", "/properties/virtualMachine"]
            .iter()
            .any(|ptr| v.pointer(ptr).is_some_and(|o| !o.is_null()))
            || !json::arr(&v, "/properties/hostedWorkloads").is_empty();
        if owned {
            continue;
        }
        let ips: Vec<String> = n.ip_configs.iter().filter_map(|c| c.private_ip.clone()).collect();
        let subnets: Vec<String> = n
            .ip_configs
            .iter()
            .filter_map(|c| c.subnet_id.as_deref())
            .map(|s| {
                let vnet = vnet_of_subnet(s).map(|v| name_of_id(&v).to_string()).unwrap_or_default();
                format!("{}/{}", vnet, name_of_id(s))
            })
            .collect();
        let mut evidence = vec![
            "virtualMachine: none".to_string(),
            format!("private IPs: {}", json::join(&ips)),
            format!("subnets: {}", json::join(&subnets)),
        ];
        if let Some(nsg) = &n.nsg_id {
            evidence.push(format!("NSG: {}", name_of_id(nsg)));
        }
        out.push(
            AuditFinding::about(check, Severity::Info, n, format!("no VM, holds {}", json::join(&ips))).with_evidence(evidence),
        );
    }
}

fn lb_empty_pool(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for lb in input.of::<LoadBalancerRow>(V::LoadBalancers) {
        // A cross-region (Global) load balancer's pools hold regional
        // frontends, which the row does not read as addresses.
        if eq(lb.tier.as_deref(), "Global") {
            continue;
        }
        let empty: Vec<&str> = lb
            .pools
            .iter()
            .filter(|p| p.ip_config_ids.is_empty() && p.addresses.is_empty())
            .map(|p| p.name.as_str())
            .collect();
        let (reason, evidence) = if lb.pools.is_empty() {
            if !lb.nat_rules.is_empty() {
                continue;
            }
            ("no backend pool".to_string(), vec!["backendAddressPools: none · inboundNatRules: none".to_string()])
        } else if empty.is_empty() {
            continue;
        } else {
            (
                format!("empty backend pool{} {}", if empty.len() == 1 { "" } else { "s" }, empty.join(", ")),
                vec![
                    format!("empty: {} of {} pool(s)", empty.len(), lb.pools.len()),
                    format!("load-balancing rules: {}", lb.rules.len()),
                ],
            )
        };
        out.push(AuditFinding::about(check, Severity::Info, lb, reason).with_evidence(evidence));
    }
}

fn ddos_plan_unused(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for d in input.of::<DdosPlanRow>(V::DdosPlans) {
        if d.vnet_ids.is_empty() {
            out.push(
                AuditFinding::about(check, Severity::Low, d, "covers no VNet")
                    .with_evidence(vec!["virtualNetworks: none".into(), format!("public IPs: {}", d.public_ip_ids.len())]),
            );
        }
    }
}

// ── Hybrid ────────────────────────────────────────────────────────────

/// The NotConnected connections of one family: ExpressRoute, or the VPN
/// kinds (site-to-site, VNet-to-VNet).
fn connection_down(check: &'static Check, input: &AuditInput, kinds: &[&str], out: &mut Vec<AuditFinding>) {
    for c in input.of::<ConnectionRow>(V::GatewayConnections) {
        let kind = c.connection_type.as_deref().unwrap_or("");
        if !kinds.iter().any(|k| kind.eq_ignore_ascii_case(k)) || !eq(c.status.as_deref(), "NotConnected") {
            continue;
        }
        let other = c
            .circuit_id
            .as_deref()
            .or(c.local_gateway_id.as_deref())
            .or(c.peer_gateway_id.as_deref())
            .map(name_of_id)
            .unwrap_or("-");
        let gateway = c.gateway_id.as_deref().map(name_of_id).unwrap_or("-");
        out.push(
            AuditFinding::about(check, Severity::Medium, c, format!("NotConnected ({} ↔ {})", gateway, other)).with_evidence(vec![
                format!("connectionType: {} · connectionStatus: NotConnected", kind),
                format!("gateway: {} · other side: {}", gateway, other),
                format!(
                    "bytes in / out: {} / {}",
                    c.ingress_bytes.map(|b| b.to_string()).unwrap_or_else(|| "-".into()),
                    c.egress_bytes.map(|b| b.to_string()).unwrap_or_else(|| "-".into())
                ),
            ]),
        );
    }
}

fn er_connection_down(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    connection_down(check, input, &["ExpressRoute"], out);
}

fn vpn_connection_down(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    connection_down(check, input, &["IPsec", "Vnet2Vnet"], out);
}

/// Enabled on Azure's side, not Provisioned on the provider's. An
/// ExpressRoute Direct circuit has no provider: skipped.
fn er_circuit_not_provisioned(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for c in input.of::<CircuitRow>(V::ExpressRouteCircuits) {
        let Some(state) = c.provider_state.as_deref() else { continue };
        if !eq(c.circuit_state.as_deref(), "Enabled") || c.port_id.is_some() {
            continue;
        }
        if state.eq_ignore_ascii_case("Provisioned") || state.eq_ignore_ascii_case("Deprovisioning") {
            continue;
        }
        out.push(
            AuditFinding::about(check, Severity::Low, c, format!("provider state {}", state)).with_evidence(vec![
                format!("circuitProvisioningState: Enabled · serviceProviderProvisioningState: {}", state),
                format!(
                    "provider: {} · {} · {}",
                    json::opt(c.provider.clone()),
                    json::opt(c.peering_location.clone()),
                    json::opt(c.sku_name.clone())
                ),
            ]),
        );
    }
}

fn gateway_not_zone_redundant(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for g in input.of::<GatewayRow>(V::VnetGateways) {
        let kind = g.gateway_type.as_deref().unwrap_or("");
        if !(kind.eq_ignore_ascii_case("Vpn") || kind.eq_ignore_ascii_case("ExpressRoute")) {
            continue;
        }
        let Some(sku) = g.sku_name.as_deref() else { continue };
        if sku.to_ascii_uppercase().ends_with("AZ") || sku.eq_ignore_ascii_case("ErGwScale") || sku.eq_ignore_ascii_case("Basic") {
            continue;
        }
        out.push(
            AuditFinding::about(check, Severity::Low, g, format!("{} is not an AZ SKU", sku)).with_evidence(vec![
                format!("gatewayType: {} · sku: {}", kind, sku),
                format!("zone redundant: {}", g.zone_redundancy()),
            ]),
        );
    }
}

// ── Firewall ──────────────────────────────────────────────────────────

/// A policy's threat intelligence mode: its own, else its base policy's
/// (followed through the warm list), else Azure's default, Alert.
fn effective_threat_intel(p: &FirewallPolicyRow, policies: &HashMap<String, &FirewallPolicyRow>) -> (String, Option<String>) {
    let mut cur = p;
    let mut seen = HashSet::new();
    loop {
        if let Some(m) = &cur.threat_intel_mode {
            let from = (!std::ptr::eq(cur, p)).then(|| cur.base.name.clone());
            return (m.clone(), from);
        }
        let Some(base) = cur.base_policy_id.as_deref().map(str::to_lowercase) else { break };
        if !seen.insert(base.clone()) {
            break;
        }
        match policies.get(&base) {
            Some(b) => cur = b,
            None => break,
        }
    }
    ("Alert".into(), None)
}

/// Classic firewalls on their own mode, attached policies on theirs (with
/// inheritance). A firewall whose policy is in the warm list is judged by
/// it; one whose policy isn't (another subscription) is skipped. An
/// unattached policy protects nothing: skipped.
fn fw_threat_intel_off(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let policies: HashMap<String, &FirewallPolicyRow> = input
        .of::<FirewallPolicyRow>(V::FirewallPolicies)
        .map(|p| (p.base.id.to_lowercase(), p))
        .collect();
    for f in input.of::<AzureFirewallRow>(V::AzureFirewalls) {
        if f.policy_id.is_some() || !eq(f.threat_intel_mode.as_deref(), "Off") {
            continue;
        }
        out.push(
            AuditFinding::about(check, Severity::Medium, f, "threat intelligence Off (classic rules)")
                .with_evidence(vec!["threatIntelMode: Off".into(), "firewallPolicy: none".into()]),
        );
    }
    let firewalls: Vec<&AzureFirewallRow> = input.of::<AzureFirewallRow>(V::AzureFirewalls).collect();
    for p in policies.values() {
        // The firewalls using it: the policy's own list, or a warm
        // firewall that names it.
        let mut users: Vec<String> = p.firewall_ids.iter().map(|id| name_of_id(id).to_string()).collect();
        for f in &firewalls {
            if f.policy_id.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(&p.base.id)) && !users.contains(&f.base.name) {
                users.push(f.base.name.clone());
            }
        }
        if users.is_empty() {
            continue;
        }
        let (mode, inherited) = effective_threat_intel(p, &policies);
        if !mode.eq_ignore_ascii_case("Off") {
            continue;
        }
        let mut evidence = vec![match &inherited {
            Some(base) => format!("threatIntelMode: Off (inherited from base policy {})", base),
            None => "threatIntelMode: Off".to_string(),
        }];
        evidence.push(format!("used by: {}", users.join(", ")));
        out.push(AuditFinding::about(check, Severity::Medium, *p, "threat intelligence Off").with_evidence(evidence));
    }
}

fn ngfw_marketplace_not_subscribed(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for n in input.of::<CloudNgfwRow>(V::CloudNgfws) {
        let Some(status) = n.marketplace.as_ref().and_then(|m| json::str_at(m, "/marketplaceSubscriptionStatus")) else {
            continue;
        };
        if status.eq_ignore_ascii_case("Subscribed") {
            continue;
        }
        let stopped = status.eq_ignore_ascii_case("Suspended") || status.eq_ignore_ascii_case("Unsubscribed");
        let severity = if stopped { Severity::Medium } else { Severity::Low };
        let mut evidence = vec![format!("marketplaceSubscriptionStatus: {}", status)];
        if let Some(offer) = n.marketplace.as_ref().and_then(|m| json::str_at(m, "/offerId")) {
            evidence.push(format!("offer: {}", offer));
        }
        out.push(AuditFinding::about(check, severity, n, format!("Marketplace subscription {}", status)).with_evidence(evidence));
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

// ── Backup ────────────────────────────────────────────────────────────

fn backup_soft_delete_off(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for v in input.of::<RecoveryVaultRow>(V::RecoveryVaults).filter(|v| v.soft_delete_off()) {
        out.push(
            AuditFinding::about(check, Severity::Medium, v, "soft delete disabled")
                .with_evidence(vec![format!("softDeleteState: {}", json::opt(v.soft_delete.clone()))]),
        );
    }
    for v in input.of::<BackupVaultRow>(V::BackupVaults).filter(|v| v.soft_delete_off()) {
        out.push(
            AuditFinding::about(check, Severity::Medium, v, "soft delete off")
                .with_evidence(vec![format!("softDeleteSettings.state: {}", json::opt(v.soft_delete.clone()))]),
        );
    }
}

/// One finding per failing item, about its source resource (Enter opens
/// it; its Related then names the vault), else the vault.
fn item_finding(
    check: &'static Check,
    vault: &dyn Resource,
    source: Option<String>,
    name: &str,
    flags: &[backup::ItemFlag],
    out: &mut Vec<AuditFinding>,
) {
    let stale_only = flags.iter().all(|f| matches!(f, backup::ItemFlag::Stale(..) | backup::ItemFlag::Health(_)));
    let severity = if stale_only { Severity::Low } else { Severity::Medium };
    let id = source.unwrap_or_else(|| vault.id().to_string());
    let mut evidence: Vec<String> = flags.iter().map(|f| f.text()).collect();
    evidence.push(format!("vault: {}", vault.name()));
    out.push(
        AuditFinding::at(
            check,
            severity,
            &id,
            name,
            vault.location(),
            vault.tags().clone(),
            format!("{} in {}", flags[0].text(), vault.name()),
        )
        .with_evidence(evidence),
    );
}

fn backup_item_failing(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let mut gaps = LazyGaps::default();
    let lazy = input.lazy();
    for v in input.of::<RecoveryVaultRow>(V::RecoveryVaults) {
        let Some(items) = gaps.see(&v.base.name, lazy.and_then(|l| l.backup_protected_items.get(&v.base.id))) else {
            continue;
        };
        let policies = match lazy.and_then(|l| l.backup_policies.get(&v.base.id)) {
            Some(Lazy::Loaded(p)) => p.as_slice(),
            _ => &[],
        };
        for item in items {
            let policy_id = json::str_at(item, "/properties/policyId");
            let policy = policy_id
                .as_deref()
                .and_then(|pid| policies.iter().find(|p| json::str_at(p, "/id").is_some_and(|i| i.eq_ignore_ascii_case(pid))));
            let flags = backup::item_flags(item, input.now(), backup::stale_hours(policy));
            if !flags.is_empty() {
                let name = json::str_at(item, "/properties/friendlyName").unwrap_or_else(|| json::text(item, "/name"));
                item_finding(check, v, backup::item_source(item), &name, &flags, out);
            }
        }
    }
    for v in input.of::<BackupVaultRow>(V::BackupVaults) {
        let Some(instances) = gaps.see(&v.base.name, lazy.and_then(|l| l.backup_instances.get(&v.base.id))) else {
            continue;
        };
        let jobs = match lazy.and_then(|l| l.backup_jobs.get(&v.base.id)) {
            Some(Lazy::Loaded(j)) => j.as_slice(),
            _ => &[],
        };
        for i in instances {
            let last = backup::last_backup_job(jobs, &json::text(i, "/id"));
            let flags = backup::instance_flags(i, last);
            if !flags.is_empty() {
                let name = json::str_at(i, "/properties/friendlyName").unwrap_or_else(|| json::text(i, "/name"));
                item_finding(check, v, backup::instance_source(i), &name, &flags, out);
            }
        }
    }
    gaps.note(check, "protected items", "Protected items", out);
}

fn backup_vault_hardening(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    let mut push = |v: &dyn Resource, immutability: Option<&str>, mua: bool, mua_text: String| {
        let immutable = immutability.is_some_and(|i| i.eq_ignore_ascii_case("Locked") || i.eq_ignore_ascii_case("Unlocked"));
        let reason = match (immutable, mua) {
            (true, true) => return,
            (false, false) => "no immutability, no multi-user authorization",
            (false, true) => "immutability off",
            (true, false) => "no multi-user authorization",
        };
        out.push(AuditFinding::about(check, Severity::Info, v, reason).with_evidence(vec![
            format!("immutability: {}", immutability.unwrap_or("-")),
            format!("multi-user authorization: {}", mua_text),
        ]));
    };
    for v in input.of::<RecoveryVaultRow>(V::RecoveryVaults) {
        let mua = v.mua.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("Enabled"));
        push(v, v.immutability.as_deref(), mua, json::opt(v.mua.clone()));
    }
    for v in input.of::<BackupVaultRow>(V::BackupVaults) {
        push(v, v.immutability.as_deref(), v.mua_on(), json::yes_no(v.resource_guard));
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

// ── Messaging ───────────────────────────────────────────────────────

/// The namespaces of one kind: the row and its shared namespace fields.
fn namespaces<'a>(input: &AuditInput<'a>, view: V) -> Vec<(&'a dyn Resource, &'a Namespace)> {
    match view {
        V::ServiceBusNamespaces => input.of::<ServiceBusRow>(view).map(|r| (r as &dyn Resource, &r.ns)).collect(),
        _ => input.of::<EventHubsRow>(view).map(|r| (r as &dyn Resource, &r.ns)).collect(),
    }
}

fn ns_local_auth(check: &'static Check, input: &AuditInput, view: V, out: &mut Vec<AuditFinding>) {
    for (r, ns) in namespaces(input, view) {
        if ns.disable_local_auth != Some(true) {
            let v = ns.disable_local_auth.map(|b| b.to_string()).unwrap_or_else(|| "(unset: false)".into());
            out.push(
                AuditFinding::about(check, Severity::Medium, r, "SAS keys (local auth) enabled")
                    .with_evidence(vec![format!("disableLocalAuth: {}", v)]),
            );
        }
    }
}

fn ns_min_tls(check: &'static Check, input: &AuditInput, view: V, out: &mut Vec<AuditFinding>) {
    for (r, ns) in namespaces(input, view) {
        if let Some(tls) = ns.min_tls.as_deref().filter(|t| tls_below_1_2(t)) {
            out.push(
                AuditFinding::about(check, Severity::Medium, r, format!("minimumTlsVersion {}", tls))
                    .with_evidence(vec![format!("minimumTlsVersion: {}", tls)]),
            );
        }
    }
}

/// Public, and the warm Network section's rule set lets every network in:
/// default action Allow (or unset), or Deny with no IP or VNet rule, which
/// Azure does not enforce. A namespace whose rule set isn't loaded is
/// counted in the note, never passed.
fn ns_public_network(check: &'static Check, input: &AuditInput, view: V, out: &mut Vec<AuditFinding>) {
    let mut gaps = LazyGaps::default();
    for (r, ns) in namespaces(input, view) {
        if !public_enabled(ns.public_network_access.as_deref()) {
            continue;
        }
        let Some(set) = gaps.see(r.name(), input.lazy().and_then(|l| l.messaging_network_rules.get(r.id()))) else {
            continue;
        };
        let pna = json::str_at(set, "/properties/publicNetworkAccess").or_else(|| ns.public_network_access.clone());
        if !public_enabled(pna.as_deref()) {
            continue;
        }
        let action = json::str_at(set, "/properties/defaultAction");
        let ip = json::arr(set, "/properties/ipRules").len();
        let vnet = json::arr(set, "/properties/virtualNetworkRules").len();
        let open = match action.as_deref() {
            Some(a) if a.eq_ignore_ascii_case("deny") => ip == 0 && vnet == 0,
            _ => true,
        };
        if open {
            let reason = if eq(action.as_deref(), "deny") {
                "default action Deny with no rules (not enforced)"
            } else {
                "public network access, default action Allow"
            };
            out.push(AuditFinding::about(check, Severity::Medium, r, reason).with_evidence(vec![
                format!("publicNetworkAccess: {}", pna.as_deref().unwrap_or("(default: Enabled)")),
                format!("defaultAction: {}", action.as_deref().unwrap_or("(unset)")),
                format!("IP rules: {} · VNet rules: {}", ip, vnet),
                format!("private endpoints: {}", ns.private_endpoints.len()),
            ]));
        }
    }
    gaps.note(check, "network rule sets", "Network", out);
}

fn sb_local_auth(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    ns_local_auth(check, input, V::ServiceBusNamespaces, out)
}

fn sb_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    ns_min_tls(check, input, V::ServiceBusNamespaces, out)
}

fn sb_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    ns_public_network(check, input, V::ServiceBusNamespaces, out)
}

fn eh_local_auth(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    ns_local_auth(check, input, V::EventHubNamespaces, out)
}

fn eh_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    ns_min_tls(check, input, V::EventHubNamespaces, out)
}

fn eh_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    ns_public_network(check, input, V::EventHubNamespaces, out)
}

// ── PostgreSQL & MySQL ────────────────────────────────────────────────

/// The cached flexible servers of one engine's list.
fn flexible_servers<'a>(input: &AuditInput<'a>, view: V) -> impl Iterator<Item = &'a FlexibleServerRow> + 'a {
    let rows: Vec<&'a FlexibleServerRow> = input.of::<FlexibleServerRow>(view).collect();
    rows.into_iter()
}

/// Whether a server takes connections from the internet at all: public
/// access on and not VNet-integrated (a VNet-integrated server has no
/// public endpoint; its subnet's NSG decides).
fn flex_public(s: &FlexibleServerRow) -> bool {
    s.delegated_subnet_id.is_none() && public_enabled(s.public_network_access.as_deref())
}

/// A server parameter's value from the warm Parameters section
/// (`GET {server}/configurations`).
fn flex_param(params: &[Value], name: &str) -> Option<String> {
    params
        .iter()
        .find(|p| json::str_at(p, "/name").is_some_and(|n| n.eq_ignore_ascii_case(name)))
        .and_then(|p| json::str_at(p, "/properties/value"))
}

fn flex_public_network(check: &'static Check, input: &AuditInput, view: V, out: &mut Vec<AuditFinding>) {
    for s in flexible_servers(input, view) {
        if !flex_public(s) {
            continue;
        }
        let mut evidence = vec![
            format!("publicNetworkAccess: {}", s.public_network_access.as_deref().unwrap_or("(default: Enabled)")),
            "delegated subnet: none".into(),
            format!("private endpoints: {}", s.private_endpoints.len()),
        ];
        if let Some(Lazy::Loaded(rules)) = input.lazy().and_then(|l| l.flex_firewall_rules.get(&s.base.id)) {
            evidence.push(format!("firewall rules: {}", rules.len()));
        }
        out.push(AuditFinding::about(check, Severity::Medium, s, "public network access enabled").with_evidence(evidence));
    }
}

/// The SQL rule, on the warm Firewall section. A VNet-integrated server
/// or one with public access off has rules that admit nothing: skipped,
/// not counted as unchecked.
fn flex_firewall_open(check: &'static Check, input: &AuditInput, view: V, out: &mut Vec<AuditFinding>) {
    let mut gaps = LazyGaps::default();
    for s in flexible_servers(input, view) {
        if !flex_public(s) {
            continue;
        }
        let rules = gaps.see(&s.base.name, input.lazy().and_then(|l| l.flex_firewall_rules.get(&s.base.id)));
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

/// `require_secure_transport` OFF, from the warm Parameters section; a
/// server whose parameters aren't loaded is counted in the note.
fn flex_insecure_transport(check: &'static Check, input: &AuditInput, view: V, out: &mut Vec<AuditFinding>) {
    let mut gaps = LazyGaps::default();
    for s in flexible_servers(input, view) {
        let params = gaps.see(&s.base.name, input.lazy().and_then(|l| l.flex_parameters.get(&s.base.id)));
        let Some(params) = params else { continue };
        if let Some(v) = flex_param(params, "require_secure_transport").filter(|v| v.eq_ignore_ascii_case("off")) {
            out.push(
                AuditFinding::about(check, Severity::High, s, "require_secure_transport off")
                    .with_evidence(vec![format!("require_secure_transport: {}", v)]),
            );
        }
    }
    gaps.note(check, "server parameters", "Parameters", out);
}

/// The TLS floor, from the warm Parameters section: PostgreSQL's
/// `ssl_min_protocol_version`, MySQL's `tls_version` (a list: any entry
/// below 1.2 counts).
fn flex_min_tls(check: &'static Check, input: &AuditInput, view: V, out: &mut Vec<AuditFinding>) {
    let mut gaps = LazyGaps::default();
    for s in flexible_servers(input, view) {
        let params = gaps.see(&s.base.name, input.lazy().and_then(|l| l.flex_parameters.get(&s.base.id)));
        let Some(params) = params else { continue };
        let name = match s.engine {
            Engine::Postgres => "ssl_min_protocol_version",
            Engine::Mysql => "tls_version",
        };
        let Some(v) = flex_param(params, name) else { continue };
        if v.split(',').map(str::trim).filter(|t| !t.is_empty()).any(tls_below_1_2) {
            out.push(
                AuditFinding::about(check, Severity::Medium, s, format!("{} {}", name, v))
                    .with_evidence(vec![format!("{}: {}", name, v)]),
            );
        }
    }
    gaps.note(check, "server parameters", "Parameters", out);
}

/// Password logins with no Entra admin. PostgreSQL says both modes on the
/// row (Entra off needs no lazy read); otherwise the warm Security
/// section's admin list decides.
fn flex_password_no_entra(check: &'static Check, input: &AuditInput, view: V, out: &mut Vec<AuditFinding>) {
    let mut gaps = LazyGaps::default();
    for s in flexible_servers(input, view) {
        let password_on = s.password_auth.as_deref().is_none_or(|p| p.eq_ignore_ascii_case("enabled"));
        if !password_on {
            continue;
        }
        let entra_off = s.engine == Engine::Postgres && !eq(s.entra_auth.as_deref(), "enabled");
        let no_admin = entra_off || {
            let admins = gaps.see(&s.base.name, input.lazy().and_then(|l| l.flex_admins.get(&s.base.id)));
            admins.is_some_and(|a| a.is_empty())
        };
        if no_admin {
            let mut evidence = vec![format!("admin login: {}", s.admin_login.as_deref().unwrap_or("-"))];
            if s.engine == Engine::Postgres {
                evidence.push(format!("passwordAuth: {}", s.password_auth.as_deref().unwrap_or("(default: Enabled)")));
                evidence.push(format!("activeDirectoryAuth: {}", s.entra_auth.as_deref().unwrap_or("Disabled")));
            }
            if !entra_off {
                evidence.push("Entra admins: none".into());
            }
            out.push(AuditFinding::about(check, Severity::Low, s, "password auth, no Entra admin").with_evidence(evidence));
        }
    }
    gaps.note(check, "Entra admins", "Security", out);
}

fn pg_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_public_network(check, input, V::PostgresServers, out)
}
fn pg_firewall_open(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_firewall_open(check, input, V::PostgresServers, out)
}
fn pg_insecure_transport(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_insecure_transport(check, input, V::PostgresServers, out)
}
fn pg_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_min_tls(check, input, V::PostgresServers, out)
}
fn pg_password_no_entra(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_password_no_entra(check, input, V::PostgresServers, out)
}
fn mysql_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_public_network(check, input, V::MysqlServers, out)
}
fn mysql_firewall_open(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_firewall_open(check, input, V::MysqlServers, out)
}
fn mysql_insecure_transport(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_insecure_transport(check, input, V::MysqlServers, out)
}
fn mysql_min_tls(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_min_tls(check, input, V::MysqlServers, out)
}
fn mysql_password_no_entra(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    flex_password_no_entra(check, input, V::MysqlServers, out)
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

// ── Foundry ───────────────────────────────────────────────────────────

fn foundry_public_network(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<FoundryRow>(V::AiAccounts) {
        if public_enabled(a.public_network_access.as_deref()) && !eq(a.acl_default_action.as_deref(), "Deny") {
            out.push(
                AuditFinding::about(check, Severity::Medium, a, "public network access, default action Allow").with_evidence(
                    vec![
                        format!("publicNetworkAccess: {}", a.public_network_access.as_deref().unwrap_or("(default: Enabled)")),
                        format!("networkAcls.defaultAction: {}", json::opt(a.acl_default_action.clone())),
                        format!("private endpoints: {}", a.private_endpoint_ids.len()),
                    ],
                ),
            );
        }
    }
}

fn foundry_local_auth(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for a in input.of::<FoundryRow>(V::AiAccounts) {
        if a.disable_local_auth != Some(true) {
            let v = a.disable_local_auth.map(|b| b.to_string()).unwrap_or_else(|| "(unset: false)".into());
            out.push(
                AuditFinding::about(check, Severity::Medium, a, "API keys (local auth) enabled")
                    .with_evidence(vec![format!("disableLocalAuth: {}", v)]),
            );
        }
    }
}

// ── Compute ───────────────────────────────────────────────────────────

fn disk_unattached(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    for d in input.of::<DiskRow>(V::Disks) {
        if !eq(d.disk_state.as_deref(), "Unattached") {
            continue;
        }
        let size = d.size_gb.map(|g| format!("{} GiB", g)).unwrap_or_else(|| "-".into());
        let mut evidence = vec![
            "diskState: Unattached".into(),
            format!("size: {} · sku: {}", size, json::opt(d.sku.clone())),
        ];
        if let Some(t) = json::str_at(&raw(d), "/properties/LastOwnershipUpdateTime") {
            evidence.push(format!("last owner change: {}", json::time(Some(t))));
        }
        out.push(AuditFinding::about(check, Severity::Info, d, format!("unattached, {}", size)).with_evidence(evidence));
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
pub(crate) const USER_ACCESS_ADMIN_ROLE: &str = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";
pub(crate) const CONTRIBUTOR_ROLE: &str = "b24988ac-6180-42a0-ab88-20f7382dd24c";

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

/// The role an assignment grants, when it is Contributor: write on
/// everything, no access management.
pub(crate) fn broad_write_role(a: &Value) -> Option<&'static str> {
    let def = json::str_at(a, "/properties/roleDefinitionId")?.to_lowercase();
    def.ends_with(CONTRIBUTOR_ROLE).then_some("Contributor")
}

/// Whether an assignment applies to the whole subscription: made at it or
/// above it (a management group, the root). An assignment on a resource
/// group or resource is narrower, and one on another subscription is not
/// this one's.
fn at_or_above(a: &Value, subscription_scope: &str) -> bool {
    let at = json::text(a, "/properties/scope");
    let at = at.trim_end_matches('/');
    at.eq_ignore_ascii_case(subscription_scope) || !at.to_lowercase().starts_with("/subscriptions/")
}

/// Whether a directory user object is a guest: `userType` when Graph
/// returned it, else the `#EXT#` marker in the UPN.
fn is_guest(v: &Value) -> bool {
    json::str_at(v, "/userType").is_some_and(|t| t.eq_ignore_ascii_case("Guest"))
        || json::str_at(v, "/userPrincipalName").is_some_and(|u| u.contains("#EXT#"))
}

/// A subscription Access check: the roles `role` names, at or above the
/// subscription, held by a guest user (`guest`) or a service principal
/// (`sp`). `what` names the roles in the unresolved-users note.
fn subscription_role_check(
    check: &'static Check,
    input: &AuditInput,
    out: &mut Vec<AuditFinding>,
    role_of: fn(&Value) -> Option<&'static str>,
    (guest, sp): (Severity, Severity),
    what: &str,
) {
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
        let Some(role) = role_of(a) else { continue };
        if !at_or_above(a, &scope) {
            continue;
        }
        let kind = json::str_at(a, "/properties/principalType").unwrap_or_default();
        let pid = json::text(a, "/properties/principalId").to_lowercase();
        let principal = lazy.and_then(|l| l.principals.get(&pid));
        // The name Graph resolved, else a loaded service principal row's,
        // else the object id.
        let display = match principal {
            Some(Lazy::Loaded(v)) => graph::object_display(v),
            _ => input
                .of::<ServicePrincipalRow>(V::ServicePrincipals)
                .find(|s| s.base.object_id.eq_ignore_ascii_case(&pid))
                .map(|s| s.base.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| pid.clone()),
        };
        let (sev, who) = if kind.eq_ignore_ascii_case("ServicePrincipal") {
            (sp, "service principal")
        } else if kind.eq_ignore_ascii_case("User") {
            match principal {
                Some(Lazy::Loaded(v)) if is_guest(v) => (guest, "guest user"),
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
            format!("{} {} user(s) not resolved — r looks them up", unresolved, what),
            format!(
                "{} user(s) holding {} aren't resolved in Microsoft Graph yet, so whether they are guests is unknown. Press r here, or open the subscription's Access section.",
                unresolved, what
            ),
        ));
    }
}

fn sub_privileged_guest_or_sp(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    subscription_role_check(
        check,
        input,
        out,
        privileged_role,
        (Severity::Critical, Severity::High),
        "privileged",
    );
}

/// Contributor is a notch below Owner / User Access Administrator: it
/// cannot grant access, so it is its own check one severity lower.
fn sub_contributor_guest_or_sp(check: &'static Check, input: &AuditInput, out: &mut Vec<AuditFinding>) {
    subscription_role_check(
        check,
        input,
        out,
        broad_write_role,
        (Severity::High, Severity::Medium),
        "Contributor",
    );
}

/// The User principals of a loaded Access list holding a role an Access
/// check grades (Owner, User Access Administrator, Contributor),
/// lowercased: the object ids `r` resolves through Graph for the guest
/// test.
pub fn privileged_user_ids(items: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for a in items {
        if privileged_role(a).or_else(|| broad_write_role(a)).is_none() {
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
