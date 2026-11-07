# Azure Storage accounts

A storage account is the container for Azure's core storage services: blobs (objects), files (SMB and NFS shares), queues and tables. It sets the name in every endpoint (myaccount.blob.core.windows.net), the redundancy, the performance tier and who may reach the data and how.

## Key ideas

- **Kind and tier**: general-purpose v2 for most uses; premium accounts for block blobs, file shares or page blobs with low latency. Blob access tiers (hot, cool, cold, archive) trade storage price against access price.
- **Redundancy**: LRS (three copies in one datacentre), ZRS (across zones), GRS and GZRS (also copied to the paired region), with RA- for read access to the copy.
- **Authorisation**: Entra ID with data roles (such as Storage Blob Data Reader), shared access signatures, or the two account keys. Turning off shared key access forces Entra ID.
- **Anonymous blob access**: lets a container be read by anyone with the URL. Off at the account level, no container can be public.
- **Network access**: all networks, selected networks and IPs, or private endpoints only, with trusted Azure services let through.
- **Data Lake Storage**: the hierarchical namespace (HNS) gives blobs real directories and ACLs, for analytics.

## In nebaz

- Security shows public blob access, shared key, minimum TLS, HTTPS only, public network access and the encryption key source. The state is the primary region's status.
- Containers is one lazy read of the container names, through ARM.
- Never read: the account keys or SAS tokens (POST calls), or any blob, file, queue or table data (the data plane is never called).
- @audit: storage-blob-public-access, storage-shared-key, storage-min-tls, storage-https-only, storage-public-network.

## Learn more

- Overview: https://learn.microsoft.com/azure/storage/common/storage-account-overview
- Redundancy: https://learn.microsoft.com/azure/storage/common/storage-redundancy
- Authorise data access: https://learn.microsoft.com/azure/storage/common/authorize-data-access
- Anonymous read access: https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent
- Shared key: https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent
- Network security: https://learn.microsoft.com/azure/storage/common/storage-network-security
