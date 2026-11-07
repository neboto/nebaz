# Azure Private DNS zones

A private DNS zone answers DNS queries only inside the virtual networks linked to it: names such as db.internal.contoso.com, or the privatelink zones that make a service's public name resolve to its private endpoint. Azure's resolver at 168.63.129.16 answers for the linked zones.

## Key ideas

- **Virtual network links**: a zone answers for a VNet only when it is linked to it. Peering does not carry the link.
- **Auto-registration**: a link can register the VMs in the VNet automatically. A VNet can auto-register in one zone only.
- **privatelink zones**: zones such as privatelink.vaults.azure.net hold the records for private endpoints; one zone per service, shared by everything that should reach it privately.
- **Global**: zones are not in a region; the records reach every linked VNet.
- **On-premises**: networks outside Azure reach the zones through a DNS Private Resolver inbound endpoint or a forwarder in Azure.

## In nebaz

- Records is a lazy read: name, type, TTL and values, with auto-registered records flagged. VNet links is a lazy read, each linked VNet a jump, with auto-registration and state.
- A VNet's Related lists the private DNS zones linked to it.

## Learn more

- Overview: https://learn.microsoft.com/azure/dns/private-dns-overview
- VNet links: https://learn.microsoft.com/azure/dns/private-dns-virtual-network-links
- Auto-registration: https://learn.microsoft.com/azure/dns/private-dns-autoregistration
- Private endpoint DNS: https://learn.microsoft.com/azure/private-link/private-endpoint-dns
