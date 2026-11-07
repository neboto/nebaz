# Azure Compute Gallery

A Compute Gallery stores VM images you build yourself and replicates them to the regions where you deploy, so every VM and scale set starts from a known, versioned image. A gallery can be private to your subscriptions or shared with other tenants or the community.

## Key ideas

- **Image definition**: the image's identity and its fixed properties: the OS, Generation 1 or 2, the architecture, the security type (such as Trusted Launch) and publisher:offer:sku.
- **Image version**: one build of a definition (1.0.0, 1.0.1, …). VMs deploy from a version or from the latest one.
- **Replicas**: copies of each version in each target region; more replicas allow more VMs to be created at once.
- **Exclude from latest and end of life**: a version that is excluded is never chosen as the latest; end-of-life dates say when to stop using a version.
- **Sharing**: Azure RBAC within your tenant, shared directly with other subscriptions or tenants, or as a community gallery under a public name.

## In nebaz

- Images is one lazy read: each definition, and its versions newest first with the regions and replica counts, end of life and "excluded from latest".
- Sharing shows how the gallery is shared, soft delete and its identity.
- Related lists the loaded VMs and scale sets built from the gallery's images.

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-machines/azure-compute-gallery
- Image definitions and versions: https://learn.microsoft.com/azure/virtual-machines/image-version
- Sharing: https://learn.microsoft.com/azure/virtual-machines/share-gallery
