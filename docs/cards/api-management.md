# Azure API Management

API Management is a gateway in front of your APIs: clients call one hostname, and the gateway routes each call to a backend (an App Service, a function, a container app, anything with a URL), applying policies on the way in and out (authentication, rate limits, transformation, caching). It also runs a developer portal where consumers find the APIs and get keys.

## Key ideas

- **APIs**: each API has a path on the gateway, a backend URL and operations; versions and revisions let it change without breaking callers.
- **Products**: bundles of APIs that consumers subscribe to. A product that requires no subscription is open to anyone who can reach the gateway.
- **Subscriptions and keys**: a subscription to a product (or an API) carries the keys callers send in the Ocp-Apim-Subscription-Key header.
- **Backends**: named targets with their URL, credentials, TLS checks, and for v2 tiers, load-balanced pools and circuit breakers.
- **Named values**: settings policies read; a secret one can be a Key Vault reference, refreshed by the instance's managed identity.
- **Tiers and platform**: Consumption, the classic Developer, Basic, Standard, Premium and Isolated tiers, and the v2 tiers. Classic instances run on the stv2 compute platform; stv1 was retired on 31 August 2024.
- **Networking**: no VNet, External (in a subnet with a public gateway) or Internal (in a subnet, private only), plus private endpoints.

## In nebaz

- Overview and Network show the tier and units, the platform (stv1 ⚠), the VNet mode and subnet, the IP addresses and each extra region.
- Hostnames shows each custom domain's certificate, ⚠ when it expires within 30 days; Security shows the TLS and cipher switches (old protocols on ⚠) and the minimum API version.
- APIs, Products, Backends and Named values are lazy reads: plain-http APIs ⚠, open products ⚠, backends' TLS checks and credential kinds, Key Vault refresh failures ⚠.
- Never read: subscription keys, a named value's value (secret or not), a backend's credential values, policies.

## Learn more

- Overview: https://learn.microsoft.com/azure/api-management/api-management-key-concepts
- Tiers: https://learn.microsoft.com/azure/api-management/api-management-features
- stv1 retirement: https://learn.microsoft.com/azure/api-management/breaking-changes/stv1-platform-retirement-august-2024
- Virtual networks: https://learn.microsoft.com/azure/api-management/virtual-network-concepts
- Named values: https://learn.microsoft.com/azure/api-management/api-management-howto-properties
- Backends: https://learn.microsoft.com/azure/api-management/backends
