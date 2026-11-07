# @audit findings

@audit is nebaz's own security and hygiene review: a set of checks run over the lists you have already loaded, each finding a misconfiguration (an NSG open to the internet, a registry's admin user, a key vault without purge protection, an expiring credential). It isn't an Azure service; its checks follow Microsoft's security guidance and benchmark.

## Key ideas

- **Checks are pure**: they read only what nebaz already has in memory. Opening @audit makes no call.
- **Severity**: critical, high, medium, low or info, as the row's state, so F filters and z sorts critical first.
- **Coverage**: a check whose list isn't loaded shows as "not checked", never as passing; one whose lazy data is missing for some resources says how many.
- **Defender and Advisor**: Microsoft's own findings live in their tabs; @audit never repeats them.

## In nebaz

- Enter on a finding jumps to its resource; l reads the evidence, why it matters and how to fix it, as text (no command is run).
- r loads every list the checks need that isn't loaded yet, and the lazy reads they use, then audits again as each lands.
- nebaz audit runs the same checks headlessly, exiting 3 at or above --fail-on.
- Each tab's card names its checks; docs/SERVICES.md lists them all.

## Learn more

- Microsoft cloud security benchmark: https://learn.microsoft.com/security/benchmark/azure/overview
- Security best practices: https://learn.microsoft.com/azure/security/fundamentals/best-practices-and-patterns
- Well-Architected security: https://learn.microsoft.com/azure/well-architected/security/
