# Azure Backup

Azure Backup keeps copies of your data in vaults that live apart from the resources they protect, by a policy that says when to back up and how long to keep each copy. There are two kinds of vault: Recovery Services vaults (VMs, SQL Server and SAP HANA in VMs, Azure Files, on-premises machines) and Backup vaults (managed disks, blobs, PostgreSQL, AKS and newer workloads).

## Key ideas

- **Protected item / backup instance**: one resource being backed up, with its policy, its last backup and its recovery points.
- **Policy**: the schedule (daily, weekly, hourly for some workloads) and the retention (daily, weekly, monthly and yearly points). Enhanced policies allow several backups a day.
- **Soft delete**: deleted backup data is kept, 14 days by default, so a deleted backup can be brought back. Always-on soft delete cannot be turned off again.
- **Immutability and multi-user authorisation**: an immutable vault refuses operations that would shorten retention; MUA asks for approval from a resource guard in another tenant or subscription before a critical change.
- **Redundancy and cross-region restore**: the vault's storage is LRS, ZRS or GRS, set before the first backup; with GRS, cross-region restore restores in the paired region.

## In nebaz

- Security shows soft delete (⚠ when off), immutability, MUA, encryption, public access and private endpoints, redundancy and cross-region restore.
- Protected items (or Backup instances), Policies and Failed jobs (last 7 days) are lazy reads. An item is ⚠ for a failed last backup, an overdue one (36 hours, or 8 days on a weekly policy), a protection error or ActionRequired health.
- Never sent: a backup, a restore, stopping protection.
- @audit: backup-soft-delete-off, backup-item-failing, backup-vault-hardening.

## Learn more

- Overview: https://learn.microsoft.com/azure/backup/backup-overview
- Recovery Services vaults: https://learn.microsoft.com/azure/backup/backup-azure-recovery-services-vault-overview
- Backup vaults: https://learn.microsoft.com/azure/backup/backup-vault-overview
- Soft delete: https://learn.microsoft.com/azure/backup/secure-by-default
- Immutable vaults: https://learn.microsoft.com/azure/backup/backup-azure-immutable-vault-concept
- Multi-user authorisation: https://learn.microsoft.com/azure/backup/multi-user-authorization-concept
