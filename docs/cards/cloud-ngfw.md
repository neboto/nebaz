# Cloud NGFW by Palo Alto Networks

Cloud NGFW is Palo Alto Networks' next-generation firewall offered as an Azure native service: you deploy it like an Azure resource and buy it through the Azure Marketplace, and Palo Alto runs it. Its rules come from a local rulestack in Azure, or from Panorama or Strata Cloud Manager.

## Key ideas

- **Marketplace subscription**: the firewall is billed through a SaaS subscription in the Marketplace; it can't run if that subscription is not active.
- **Network**: in a VNet, with a trust subnet (towards your workloads) and an untrust subnet (towards the internet), or in a Virtual WAN hub. Routes send traffic to the trust subnet's IP.
- **Local rulestack**: rules, prefix lists, FQDN lists and security profiles kept in Azure. Panorama or Strata Cloud Manager manage the rules centrally instead.
- **App-ID and security services**: rules match applications, not just ports, with threat prevention, URL filtering and DNS security.
- **Destination NAT**: inbound rules from a public IP and port to a private backend.

## In nebaz

- Cloud NGFW: Network leads with the UDR next hop, the trust and untrust subnets and the loaded route tables that route here; Front end lists the DNAT rules; Management shows the rulestack or Panorama and the Marketplace status; Rules and Status are lazy.
- Rulestacks: Rules (lazy, by priority), Objects (prefix and FQDN lists), the security services and the firewalls using it.
- @audit: ngfw-marketplace-not-subscribed.

## Learn more

- Overview: https://learn.microsoft.com/azure/partner-solutions/palo-alto/overview
- Create a firewall: https://learn.microsoft.com/azure/partner-solutions/palo-alto/create
