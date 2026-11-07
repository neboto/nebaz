# Azure Key Vault

Key Vault stores secrets (passwords, connection strings), cryptographic keys and certificates, so applications read them at runtime instead of keeping them in code or configuration. Access is controlled by Entra ID, every operation can be logged, and keys can be kept in hardware security modules.

## Key ideas

- **Secrets, keys and certificates**: three kinds of object, each with versions. A certificate is stored with its key and a secret holding both.
- **Access model**: Azure RBAC (roles such as Key Vault Secrets User, the recommended model) or the older vault access policies.
- **Soft delete and purge protection**: deleted vaults and objects are kept for 7 to 90 days. Purge protection forbids deleting them for good during that time, and can't be turned off once on.
- **Network access**: public, restricted to IPs and VNets with trusted Microsoft services let through, or private endpoints only.
- **Managed identities**: the usual way an app or VM signs in to read from a vault, with no credential to store.
- **SKUs**: Standard, and Premium for HSM-protected keys; Managed HSM is a separate single-tenant service.

## In nebaz

- Access model says policies or Azure RBAC; Network shows the default action, bypass, IP and VNet rules and private endpoints.
- Secrets and Keys are lazy reads of the names only, through ARM, which never returns a value. Certificates aren't listed: ARM has no list for them, and nebaz never calls the vault itself.
- @audit: kv-soft-delete, kv-purge-protection, kv-public-network.

## Learn more

- Overview: https://learn.microsoft.com/azure/key-vault/general/overview
- Azure RBAC: https://learn.microsoft.com/azure/key-vault/general/rbac-guide
- Soft delete: https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview
- Network security: https://learn.microsoft.com/azure/key-vault/general/network-security
- Securing a vault: https://learn.microsoft.com/azure/key-vault/general/secure-key-vault
