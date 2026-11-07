# Azure DNS zones

An Azure DNS zone hosts the public DNS records for a domain on Microsoft's name servers. You buy the domain from a registrar and delegate it to Azure by setting the zone's name servers there; Azure then answers queries for it from anywhere.

## Key ideas

- **Delegation**: the registrar (or the parent zone) points to the zone's four name servers. Until it does, the zone answers no one.
- **Record sets**: the records of one name and type (A, AAAA, CNAME, MX, TXT, …) with one TTL.
- **Alias records**: a record that points at an Azure resource (a public IP, Traffic Manager, Front Door) and follows it when its address changes; one can sit at the zone apex, which a CNAME cannot.
- **Child zones**: a subdomain delegated to its own zone, for separate ownership.
- **DNSSEC**: signs the zone so resolvers can check the answers.

## In nebaz

- Records is a lazy read of the first 1,000 record sets: name, type, TTL and values. An alias record's target is its own line and a jump.
- Delegation shows the name servers as text; nebaz never resolves them.

## Learn more

- Overview: https://learn.microsoft.com/azure/dns/dns-overview
- Delegate a domain: https://learn.microsoft.com/azure/dns/dns-delegate-domain-azure-dns
- Alias records: https://learn.microsoft.com/azure/dns/dns-alias
- DNSSEC: https://learn.microsoft.com/azure/dns/dnssec
