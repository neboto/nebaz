//! Info cards (`i`): a short page per sub-tab on what the service is, its
//! key ideas, what nebaz shows of it and where Microsoft Learn explains
//! the rest. The text is Markdown in `docs/cards/` (its README is the
//! format), built into the binary; this module maps sub-tabs to cards and
//! parses the small Markdown subset into [`Block`]s. The popup is
//! `src/ui/widgets/info_card.rs`. A card is text only: its links are
//! copied, never fetched.

use crate::azure::service::JumpView;

pub struct Card {
    /// The sub-tabs the card is about (several when they are one idea).
    pub views: &'static [JumpView],
    pub source: &'static str,
}

pub static CARDS: &[Card] = &[
    Card { views: &[JumpView::VirtualNetworks, JumpView::Subnets], source: include_str!("../docs/cards/vnets.md") },
    Card { views: &[JumpView::StorageAccounts], source: include_str!("../docs/cards/storage-accounts.md") },
    Card { views: &[JumpView::RecoveryVaults, JumpView::BackupVaults], source: include_str!("../docs/cards/backup.md") },
    Card { views: &[JumpView::SqlServers], source: include_str!("../docs/cards/sql-servers.md") },
    Card {
        views: &[JumpView::ManagedInstances, JumpView::InstancePools],
        source: include_str!("../docs/cards/sql-managed-instances.md"),
    },
    Card { views: &[JumpView::CosmosAccounts], source: include_str!("../docs/cards/cosmos.md") },
    Card { views: &[JumpView::PostgresServers], source: include_str!("../docs/cards/postgres.md") },
    Card { views: &[JumpView::MysqlServers], source: include_str!("../docs/cards/mysql.md") },
    Card { views: &[JumpView::RedisCaches], source: include_str!("../docs/cards/redis-caches.md") },
    Card { views: &[JumpView::ManagedRedis], source: include_str!("../docs/cards/managed-redis.md") },
    Card { views: &[JumpView::ArcMachines], source: include_str!("../docs/cards/arc-servers.md") },
    Card { views: &[JumpView::AutomationAccounts], source: include_str!("../docs/cards/automation-accounts.md") },
    Card {
        views: &[JumpView::GroupDeployments, JumpView::SubscriptionDeployments],
        source: include_str!("../docs/cards/deployments.md"),
    },
    Card { views: &[JumpView::VirtualMachines], source: include_str!("../docs/cards/vms.md") },
    Card { views: &[JumpView::Disks], source: include_str!("../docs/cards/disks.md") },
    Card { views: &[JumpView::Nics], source: include_str!("../docs/cards/nics.md") },
    Card { views: &[JumpView::ScaleSets], source: include_str!("../docs/cards/scale-sets.md") },
    Card { views: &[JumpView::ApplicationSecurityGroups], source: include_str!("../docs/cards/asgs.md") },
    Card { views: &[JumpView::Galleries], source: include_str!("../docs/cards/galleries.md") },
    Card { views: &[JumpView::ArcClusters], source: include_str!("../docs/cards/arc-kubernetes.md") },
    Card { views: &[JumpView::ArcPrivateLinkScopes], source: include_str!("../docs/cards/arc-private-link-scopes.md") },
    Card {
        views: &[JumpView::HostPools, JumpView::AvdApplicationGroups, JumpView::AvdWorkspaces, JumpView::ScalingPlans],
        source: include_str!("../docs/cards/virtual-desktop.md"),
    },
    Card { views: &[JumpView::Clusters, JumpView::NodePools], source: include_str!("../docs/cards/aks.md") },
    Card { views: &[JumpView::Registries], source: include_str!("../docs/cards/registries.md") },
    Card {
        views: &[JumpView::ContainerApps, JumpView::ContainerAppEnvironments, JumpView::ContainerAppJobs],
        source: include_str!("../docs/cards/container-apps.md"),
    },
    Card { views: &[JumpView::ContainerGroups], source: include_str!("../docs/cards/container-groups.md") },
    Card { views: &[JumpView::NetworkSecurityGroups], source: include_str!("../docs/cards/nsgs.md") },
    Card { views: &[JumpView::PublicIps], source: include_str!("../docs/cards/public-ips.md") },
    Card { views: &[JumpView::LoadBalancers], source: include_str!("../docs/cards/load-balancers.md") },
    Card { views: &[JumpView::RouteTables], source: include_str!("../docs/cards/route-tables.md") },
    Card { views: &[JumpView::NatGateways], source: include_str!("../docs/cards/nat-gateways.md") },
    Card { views: &[JumpView::PrivateEndpoints], source: include_str!("../docs/cards/private-endpoints.md") },
    Card { views: &[JumpView::BastionHosts], source: include_str!("../docs/cards/bastion-hosts.md") },
    Card { views: &[JumpView::DdosPlans], source: include_str!("../docs/cards/ddos-plans.md") },
    Card { views: &[JumpView::PrivateDnsZones], source: include_str!("../docs/cards/private-dns-zones.md") },
    Card { views: &[JumpView::DnsZones], source: include_str!("../docs/cards/dns-zones.md") },
    Card {
        views: &[JumpView::DnsResolvers, JumpView::DnsForwardingRulesets],
        source: include_str!("../docs/cards/dns-resolvers.md"),
    },
    Card { views: &[JumpView::DnsResolverPolicies], source: include_str!("../docs/cards/dns-security-policies.md") },
    Card { views: &[JumpView::TrafficManagerProfiles], source: include_str!("../docs/cards/traffic-manager.md") },
    Card { views: &[JumpView::AppGateways], source: include_str!("../docs/cards/app-gateways.md") },
    Card { views: &[JumpView::FrontDoorProfiles], source: include_str!("../docs/cards/front-door.md") },
    Card { views: &[JumpView::WafPolicies], source: include_str!("../docs/cards/waf-policies.md") },
    Card { views: &[JumpView::PrivateLinkServices], source: include_str!("../docs/cards/private-link-services.md") },
    Card { views: &[JumpView::ExpressRouteCircuits], source: include_str!("../docs/cards/expressroute-circuits.md") },
    Card {
        views: &[JumpView::VnetGateways, JumpView::GatewayConnections, JumpView::LocalGateways],
        source: include_str!("../docs/cards/vnet-gateways.md"),
    },
    Card {
        views: &[JumpView::VirtualWans, JumpView::VirtualHubs],
        source: include_str!("../docs/cards/virtual-wan.md"),
    },
    Card {
        views: &[JumpView::VwanVpnGateways, JumpView::VwanErGateways, JumpView::P2sGateways, JumpView::VpnSites],
        source: include_str!("../docs/cards/vwan-gateways.md"),
    },
    Card {
        views: &[JumpView::AzureFirewalls, JumpView::FirewallPolicies, JumpView::IpGroups],
        source: include_str!("../docs/cards/azure-firewall.md"),
    },
    Card {
        views: &[JumpView::CloudNgfws, JumpView::NgfwRulestacks],
        source: include_str!("../docs/cards/cloud-ngfw.md"),
    },
    Card { views: &[JumpView::KeyVaults], source: include_str!("../docs/cards/key-vaults.md") },
    Card { views: &[JumpView::Identities], source: include_str!("../docs/cards/managed-identities.md") },
    Card {
        views: &[JumpView::AppRegistrations, JumpView::ServicePrincipals],
        source: include_str!("../docs/cards/entra-apps.md"),
    },
    Card {
        views: &[JumpView::WebApps, JumpView::AppServicePlans],
        source: include_str!("../docs/cards/app-service.md"),
    },
    Card { views: &[JumpView::FunctionApps], source: include_str!("../docs/cards/function-apps.md") },
    Card { views: &[JumpView::StaticSites], source: include_str!("../docs/cards/static-web-apps.md") },
    Card { views: &[JumpView::AiAccounts], source: include_str!("../docs/cards/foundry.md") },
    Card { views: &[JumpView::SearchServices], source: include_str!("../docs/cards/ai-search.md") },
    Card { views: &[JumpView::ServiceBusNamespaces], source: include_str!("../docs/cards/service-bus.md") },
    Card { views: &[JumpView::EventHubNamespaces], source: include_str!("../docs/cards/event-hubs.md") },
    Card {
        views: &[JumpView::Subscriptions, JumpView::ResourceGroups],
        source: include_str!("../docs/cards/subscriptions.md"),
    },
    Card { views: &[JumpView::AllResources], source: include_str!("../docs/cards/all-resources.md") },
    Card { views: &[JumpView::LogWorkspaces], source: include_str!("../docs/cards/log-analytics.md") },
    Card { views: &[JumpView::AppInsights], source: include_str!("../docs/cards/app-insights.md") },
    Card {
        views: &[JumpView::MetricAlerts, JumpView::LogAlerts, JumpView::ActivityLogAlerts, JumpView::ActionGroups, JumpView::AlertProcessingRules, JumpView::FiredAlerts],
        source: include_str!("../docs/cards/monitor-alerts.md"),
    },
    Card { views: &[JumpView::EnterprisePolicies], source: include_str!("../docs/cards/power-platform.md") },
    Card {
        views: &[JumpView::PolicyAssignments, JumpView::PolicyExemptions, JumpView::PolicyDefinitions],
        source: include_str!("../docs/cards/azure-policy.md"),
    },
    Card { views: &[JumpView::ResourceLocks], source: include_str!("../docs/cards/resource-locks.md") },
    Card { views: &[JumpView::ManagementGroups], source: include_str!("../docs/cards/management-groups.md") },
    Card { views: &[JumpView::Budgets], source: include_str!("../docs/cards/budgets.md") },
    Card {
        views: &[JumpView::DefenderRecommendations, JumpView::DefenderAlerts, JumpView::SecureScore, JumpView::DefenderPlans],
        source: include_str!("../docs/cards/defender.md"),
    },
    Card {
        views: &[JumpView::AdvisorRecommendations, JumpView::AdvisorScore, JumpView::AdvisorSuppressions],
        source: include_str!("../docs/cards/advisor.md"),
    },
    Card {
        views: &[JumpView::ChangesAll, JumpView::ChangesActivity, JumpView::ChangesDeployments, JumpView::ChangesHealth],
        source: include_str!("../docs/cards/changes.md"),
    },
    Card { views: &[JumpView::Audit], source: include_str!("../docs/cards/audit.md") },
];

/// The card for a sub-tab, if one is written.
pub fn for_view(view: JumpView) -> Option<&'static Card> {
    CARDS.iter().find(|c| c.views.contains(&view))
}

/// One piece of a card, in reading order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Title(String),
    Heading(String),
    Paragraph(String),
    Bullet(String),
    /// A `- Label: https://…` line, numbered in the card's order.
    Link { n: usize, label: String, url: String },
}

impl Card {
    /// The card as blocks. A paragraph's lines join with spaces; a bullet
    /// whose text is `Label: https://…` is a link.
    pub fn blocks(&self) -> Vec<Block> {
        let mut out = Vec::new();
        let mut para: Vec<&str> = Vec::new();
        let mut links = 0;
        let flush = |para: &mut Vec<&str>, out: &mut Vec<Block>| {
            if !para.is_empty() {
                out.push(Block::Paragraph(para.join(" ")));
                para.clear();
            }
        };
        for line in self.source.lines().map(str::trim_end) {
            if line.trim().is_empty() {
                flush(&mut para, &mut out);
            } else if let Some(t) = line.strip_prefix("## ") {
                flush(&mut para, &mut out);
                out.push(Block::Heading(t.trim().to_string()));
            } else if let Some(t) = line.strip_prefix("# ") {
                flush(&mut para, &mut out);
                out.push(Block::Title(t.trim().to_string()));
            } else if let Some(t) = line.strip_prefix("- ") {
                flush(&mut para, &mut out);
                match t.split_once(": https://") {
                    Some((label, rest)) => {
                        links += 1;
                        out.push(Block::Link { n: links, label: label.trim().to_string(), url: format!("https://{}", rest.trim()) });
                    }
                    None => out.push(Block::Bullet(t.trim().to_string())),
                }
            } else {
                para.push(line.trim());
            }
        }
        flush(&mut para, &mut out);
        out
    }

    /// Blocks `lo..=hi` as plain text for the clipboard: the card's own
    /// Markdown minus the `**`, a blank line before each heading and
    /// paragraph, so a pasted range reads as it does on screen.
    pub fn text_of(&self, lo: usize, hi: usize) -> String {
        let mut out = String::new();
        for (i, b) in self.blocks().iter().enumerate().skip(lo).take(hi.saturating_sub(lo) + 1) {
            let (gap, line) = match b {
                Block::Title(t) => (false, t.clone()),
                Block::Heading(h) => (true, h.clone()),
                Block::Paragraph(p) => (true, p.replace("**", "")),
                Block::Bullet(t) => (false, format!("- {}", t.replace("**", ""))),
                Block::Link { label, url, .. } => (false, format!("- {}: {}", label, url)),
            };
            if i > lo {
                out.push_str(if gap { "\n\n" } else { "\n" });
            }
            out.push_str(&line);
        }
        out
    }

    /// The URL of link `n` (1-based).
    pub fn link(&self, n: usize) -> Option<String> {
        self.blocks().into_iter().find_map(|b| match b {
            Block::Link { n: k, url, .. } if k == n => Some(url),
            _ => None,
        })
    }
}

/// `text` as words, each a run of `(bold, piece)` segments: `**` toggles
/// emphasis without breaking a word, so `**Peering**:` stays one word.
pub fn styled_words(text: &str) -> Vec<Vec<(bool, String)>> {
    let mut words = Vec::new();
    let mut word: Vec<(bool, String)> = Vec::new();
    let mut bold = false;
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if let Some(after) = rest.strip_prefix("**") {
            bold = !bold;
            rest = after;
            continue;
        }
        rest = &rest[c.len_utf8()..];
        if c.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        match word.last_mut() {
            Some((b, piece)) if *b == bold => piece.push(c),
            _ => word.push((bold, c.to_string())),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::service::ServiceType;

    #[test]
    fn every_card_has_a_title_the_three_parts_and_learn_links() {
        for card in CARDS {
            let blocks = card.blocks();
            assert!(matches!(blocks.first(), Some(Block::Title(_))), "{:?}: starts with a # title", card.views);
            let headings: Vec<&str> = blocks
                .iter()
                .filter_map(|b| match b {
                    Block::Heading(h) => Some(h.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(headings, ["Key ideas", "In nebaz", "Learn more"], "{:?}", card.views);
            let links: Vec<&str> = blocks
                .iter()
                .filter_map(|b| match b {
                    Block::Link { url, .. } => Some(url.as_str()),
                    _ => None,
                })
                .collect();
            assert!(!links.is_empty() && links.len() <= 9, "{:?}: 1 to 9 links (keys 1–9 copy them)", card.views);
            assert!(
                links.iter().all(|u| u.starts_with("https://learn.microsoft.com/")),
                "{:?}: links go to Microsoft Learn",
                card.views
            );
        }
    }

    #[test]
    fn no_sub_tab_has_two_cards() {
        let mut seen = Vec::new();
        for view in CARDS.iter().flat_map(|c| c.views) {
            assert!(!seen.contains(view), "{view:?} has two cards");
            seen.push(*view);
        }
    }

    #[test]
    fn every_sub_tab_has_a_card() {
        let missing: Vec<&str> = ServiceType::all()
            .iter()
            .flat_map(|s| s.views().iter())
            .filter(|v| for_view(**v).is_none())
            .map(|v| v.as_str())
            .collect();
        assert!(missing.is_empty(), "sub-tabs without a card in docs/cards: {}", missing.join(", "));
    }

    #[test]
    fn a_card_parses_into_blocks_and_numbers_its_links() {
        let card = Card {
            views: &[],
            source: "# T\n\nOne line\nand the next.\n\n## Key ideas\n\n- **A**: b\n\n## Learn more\n\n- Overview: https://learn.microsoft.com/x\n- More: https://learn.microsoft.com/y\n",
        };
        assert_eq!(
            card.blocks(),
            [
                Block::Title("T".into()),
                Block::Paragraph("One line and the next.".into()),
                Block::Heading("Key ideas".into()),
                Block::Bullet("**A**: b".into()),
                Block::Heading("Learn more".into()),
                Block::Link { n: 1, label: "Overview".into(), url: "https://learn.microsoft.com/x".into() },
                Block::Link { n: 2, label: "More".into(), url: "https://learn.microsoft.com/y".into() },
            ]
        );
        assert_eq!(card.link(2).as_deref(), Some("https://learn.microsoft.com/y"));
        assert_eq!(card.link(3), None);
        assert_eq!(card.text_of(2, 3), "Key ideas\n- A: b");
        assert_eq!(card.text_of(0, 1), "T\n\nOne line and the next.");
        assert_eq!(card.text_of(5, 5), "- Overview: https://learn.microsoft.com/x");
        assert_eq!(
            styled_words("**Peering**: joins"),
            [vec![(true, "Peering".to_string()), (false, ":".to_string())], vec![(false, "joins".to_string())]]
        );
    }
}
