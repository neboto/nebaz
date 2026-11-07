# Azure managed disks

A managed disk is a block storage volume that Azure keeps for a virtual machine: you pick a type and a size, and Azure handles the storage behind it, with three copies inside the region. A disk is its own resource, so it outlives the VM it was attached to unless you delete it too.

## Key ideas

- **Disk types**: Standard HDD, Standard SSD, Premium SSD, Premium SSD v2 and Ultra Disk, in rising order of performance and price.
- **Size and performance**: on most types the size tier sets the IOPS and throughput; Premium SSD v2 and Ultra let you set them separately.
- **Disk state**: Attached, Reserved (attached to a deallocated VM), Unattached, or ActiveSAS while a download or upload link is open.
- **Redundancy**: locally redundant (LRS) by default; zone-redundant (ZRS) copies across availability zones for SSDs.
- **Snapshots**: point-in-time copies of a disk, billed for the space they use.
- **Encryption**: always on at rest, with platform-managed keys or your own keys through a disk encryption set.

## In nebaz

- The state is the disk's own (Attached, Reserved, Unattached); Related jumps to the VM that holds it.
- Never sent: a SAS export (it would give a download link to the disk's data).
- @audit: disk-unattached, at info level. An unattached disk is still billed and still holds its data. Reserved, a deallocated VM's disk, does not count.

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-machines/managed-disks-overview
- Disk types: https://learn.microsoft.com/azure/virtual-machines/disks-types
- Redundancy: https://learn.microsoft.com/azure/virtual-machines/disks-redundancy
- Find unattached disks: https://learn.microsoft.com/azure/virtual-machines/disks-find-unattached-portal
