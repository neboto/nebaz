# Azure DNS Private Resolver

DNS Private Resolver connects Azure DNS with DNS elsewhere, without running your own DNS servers in VMs. Inbound endpoints let on-premises networks resolve Azure private DNS zones; outbound endpoints with forwarding rulesets send Azure's queries for your own domains to your DNS servers.

## Key ideas

- **Resolver**: lives in one virtual network and region; its endpoints each need a subnet of their own, delegated to it.
- **Inbound endpoint**: a private IP that on-premises DNS servers forward to, to reach private DNS zones and privatelink records.
- **Outbound endpoint**: where queries leave for the targets in a ruleset.
- **Forwarding ruleset**: rules mapping a domain (corp.contoso.com.) to target DNS servers. A ruleset is linked to VNets; queries from them follow its rules.
- **Hub and spoke**: one resolver in the hub, its ruleset linked to the spokes.

## In nebaz

- Resolvers: Endpoints is a lazy read (inbound with its private IP and subnet; outbound with its subnet), and Rulesets lists the rulesets that forward through its outbound endpoints.
- Rulesets (its own sub-tab): Rules (domain, target servers and ports, enabled) and VNet links, each a jump.
- A VNet's Related lists the resolvers in it and the rulesets linked to it.

## Learn more

- Overview: https://learn.microsoft.com/azure/dns/dns-private-resolver-overview
- Endpoints and rulesets: https://learn.microsoft.com/azure/dns/private-resolver-endpoints-rulesets
- Architecture: https://learn.microsoft.com/azure/dns/private-resolver-architecture
