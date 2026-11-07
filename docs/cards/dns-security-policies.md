# DNS security policies

A DNS security policy filters the DNS queries from the virtual networks it is linked to: queries for domains on a list can be blocked, allowed or just logged. It is a way to stop resolution of known-bad domains and to see what names your workloads look up.

## Key ideas

- **Domain lists**: the domains a rule matches, in a list of their own that rules can share.
- **Security rules**: by priority, each with domain lists and an action: allow, block (answered with a refusal) or alert.
- **VNet links**: a policy applies to the VNets linked to it; a VNet has at most one policy.
- **Logs**: query logs go to Log Analytics, storage or Event Hubs through diagnostic settings.

## In nebaz

- Rules is a lazy read of the security rules by priority: action, state and each domain list (a jump to All resources).
- VNet links is a lazy read; a VNet's Related lists the policy linked to it.

## Learn more

- Overview: https://learn.microsoft.com/azure/dns/dns-security-policy
