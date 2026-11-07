# Managed identities

A managed identity gives an Azure resource its own identity in Microsoft Entra ID, so code running on it can get tokens for Key Vault, storage, SQL or any Entra-protected API without a password or certificate to store. Azure creates and rotates the credential itself.

## Key ideas

- **System-assigned**: part of one resource and deleted with it.
- **User-assigned**: a resource of its own (this sub-tab), shared by any number of resources and kept when they go.
- **Client id and principal id**: the client id is what code asks for a token with; the principal (object) id is what role assignments name.
- **Role assignments**: an identity can do nothing until it holds roles, such as Storage Blob Data Reader on an account.
- **Federated credentials**: let an outside workload (GitHub Actions, Kubernetes pods with workload identity, another cloud) swap its own token for one of this identity's, with no secret.

## In nebaz

- Overview shows the client id, the principal id and the tenant; both ids are searchable.
- Can do is a lazy read of every role the identity holds, each scope a jump. Federated credentials is a lazy read of issuer, subject and audiences.
- Related links to its service principal in the directory; resources that use the identity list it in their own Related.

## Learn more

- Overview: https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview
- Best practices: https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations
- Workload identity federation: https://learn.microsoft.com/entra/workload-id/workload-identity-federation
