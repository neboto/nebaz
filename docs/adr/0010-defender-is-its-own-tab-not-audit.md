---
status: accepted
date: 2026-10-28
---

# Defender for Cloud is its own tab, never `@audit` rows

Issue #156 adds Microsoft Defender for Cloud: recommendations (the
assessments), security alerts, the secure score and which Defender plans
are on. All four are GETs under `Microsoft.Security`, readable with
`Reader` at subscription scope. Three things needed deciding: whether
Defender's findings join `@audit`, how a recommendation gets its severity,
and what an alert may show.

## Decision

**1. Defender's findings stay in the Defender tab.** `@audit` (ADR 0007)
is nebaz's own checks: pure functions over the warm lists, each with a
why and a fix nebaz wrote. Defender's recommendations overlap them heavily
(public network access, a key vault's purge protection, an admin user on a
registry). Folding them into `@audit` would show the same problem twice,
with two severities and two wordings, and deduplicating them would need a
mapping between two vocabularies that neither side maintains. So the
Defender tab shows what Defender says, and `@audit` shows what nebaz
checks. Neither reads the other.

**2. A recommendation's severity comes from a client-side join.** The
assessments list (`2025-05-04`, the newest stable) cannot `$expand` the
metadata, and the metadata is where the severity, description and
remediation live. The Recommendations load first reads the metadata, which
is the tenant's built-in metadata
(`GET /providers/Microsoft.Security/assessmentMetadata`, readable by
anyone) plus the subscription's custom metadata. It then streams the
assessments, joining each one by its name, which is the metadata's name.
If the metadata read fails, that costs only the severities: the load warns
and the rows list without them. It is never the list's error.
The built-in metadata is the same for every subscription and changes over
days, while a session lasts hours. So it is read **once per tenant per
session** and kept in memory: loads that miss together (the `P` fan-out)
wait on one read, a failed read is not kept, and `r` does not re-read it.
There is no TTL and no disk cache. The custom metadata is small and
differs per subscription, so it is read on every load.
Healthy and not-applicable assessments far outnumber unhealthy ones, so
they are noise (`a`). The unhealthy subset is normally non-empty, which is
the condition `is_noise` requires.

**3. An alert keeps names and addresses, nothing that can carry a
secret.** An alert's `extendedProperties` are free-form and often hold a
process's command line. Its `supportingEvidence` is raw telemetry. Its
`entities` include processes (with a `commandLine`) and URLs (which can
hold a SAS token). Before `ArmBase` keeps the raw JSON, `sanitize_alert`
removes the first two and reduces each entity to an allowlist of fields
(host, account, address, file, domain, resource names and ids). An entity
left with only its type is dropped. So the detail pane, `e` and every
export see the sanitized body, the same rule that keeps App Insights'
connection string out (`CLAUDE.md`). The alert's portal link is shown for
the full evidence.

## Considered options

- **Defender recommendations as `@audit` findings, deduplicated against
  nebaz's checks.** Rejected: decision 1.
- **Defender recommendations in `@audit` as a separate source, not
  deduplicated.** Rejected: the same issue reported twice is noise, and
  `@audit`'s severities are nebaz's scale (`src/audit/checks.rs`), not
  Defender's.
- **`2021-06-01` assessments with a per-assessment `$expand=metadata` GET.**
  Rejected: one call per row, thousands of rows.
- **Showing alert extended properties behind a denylist of key names**
  (`command`, `password`, …). Rejected: the keys are free text that
  Defender's detections choose, so a denylist would always be behind.

## Consequences

- `PERMISSIONS.md` gains `Microsoft.Security/assessments/read`,
  `assessmentMetadata/read`, `alerts/read`, `secureScores/read`,
  `secureScoreControls/read` and `pricings/read`. All are in `Reader`.
- A Defender row has no RBAC and no tags of its own, so its tail is
  Activity and Related, like a governance row's (`is_defender_id`).
- An empty Alerts list says alerts come from the plans that are on. That
  is the usual answer on the Free tier, not a failure.
- A per-resource "Defender" section on every type (its unhealthy
  recommendations) is deferred. When it comes, it is computed from the
  warm Recommendations list by resource id and makes no per-resource call,
  like the governance section ADR 0009 defers.
