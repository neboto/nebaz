# Azure Firewall

Azure Firewall is a managed, stateful network firewall for a virtual network or a Virtual WAN hub. Traffic is sent to it with user-defined routes (its private IP is the next hop), and its rules decide what may pass, by IP and port or by FQDN. Its rules usually live in a firewall policy.

## Key ideas

- **Tiers**: Basic, Standard and Premium. Premium adds TLS inspection, IDPS signatures and URL filtering.
- **AzureFirewallSubnet**: a dedicated subnet, /26; forced tunnelling needs a second one for management.
- **Firewall policy**: rule collection groups, holding collections of DNAT, network and application rules, processed in that order and by priority. A policy can inherit from a base policy.
- **Threat intelligence**: alerts on or denies traffic to and from known malicious IPs and domains.
- **DNS proxy**: lets FQDNs in network rules resolve the same way as clients do.
- **IP groups**: named lists of addresses and ranges that rules can share.

## In nebaz

- Firewalls: Network leads with the UDR next hop (the private IP) and lists the loaded route tables that route here. Policy shows the policy's tier, threat intel, IDPS, TLS inspection and DNS proxy, a tier mismatch flagged. Rules is a lazy read of the rule collection groups.
- Policies: Settings, the rule collection groups (lazy) and Hierarchy (the base, the child policies and the firewalls using it).
- IP groups: the addresses, and the firewalls and policies using them.
- @audit: fw-threat-intel-off.

## Learn more

- Overview: https://learn.microsoft.com/azure/firewall/overview
- Features by tier: https://learn.microsoft.com/azure/firewall/choose-firewall-sku
- Rule processing: https://learn.microsoft.com/azure/firewall/rule-processing
- Firewall policy: https://learn.microsoft.com/azure/firewall/policy-rule-sets
- Threat intelligence: https://learn.microsoft.com/azure/firewall/threat-intel
- IP groups: https://learn.microsoft.com/azure/firewall/ip-groups
