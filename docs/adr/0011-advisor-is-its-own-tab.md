---
status: accepted
date: 2026-11-05
---

# Advisor is its own tab, beside Defender and `@audit`

Issue #157 adds Azure Advisor: recommendations by category and impact.
They are GETs under `Microsoft.Advisor`, readable with `Reader` at
subscription scope. The issue left three things open: where the rows
live, what to do about Advisor's Security category (which overlaps
Defender), and how to deal with the list being whatever Advisor last
computed.

## Decision

**1. Advisor is its own tab, with three sub-tabs.** Recommendations
(`@advisor`), the Advisor score (`@advscore`) and the suppressions
(`@snooze`). The tab sits in the Management group beside Governance.
For the reasons ADR 0010 gives for Defender, it is not `@audit`
rows and not a Governance sub-tab. `@audit` is nebaz's own pure checks.
Advisor's reliability and cost advice is a third voice with its own
impact scale, and mixing the two would show one issue twice with two
wordings. Governance is about policy, and Advisor's advice isn't policy.

**2. Security recommendations are Defender's, so they are noise and link
there.** Advisor's Security category relays Defender for Cloud's
assessments: the row's `resourceMetadata.source` is the assessment's id.
Showing them unfiltered would repeat the Defender tab with less detail
(no severity, no remediation). So they are noise (`a` shows them). Their
Related section names the Defender recommendation, and ⏎ opens it there.
The non-noise subset (cost, reliability, operational excellence,
performance) is normally non-empty, which is what `is_noise` requires.
The overall score's Recommendations section leaves them out for the same
reason.

**3. The list is what Advisor last computed, and every row says how old
it is.** `generateRecommendations` is a POST, so it is never sent, even
though the portal's refresh and `az advisor recommendation list --refresh`
call it. Advisor refreshes on its own, roughly daily for most
recommendation types. Each recommendation's Recommendation section shows
`lastUpdated` with its age and says nebaz never asks Advisor to re-run.
The score row shows when it was computed.

**4. Suppressions are a sub-tab, not a join.** A snoozed or dismissed
recommendation is not in the recommendations list while it is
suppressed, so a "snoozed until" line on the recommendation would almost
never have a row to sit on. The suppressions list is one cheap GET. Its
rows name the recommendation (the id's parent) and the resource. A TTL of
`-1` means dismissed for good.

**5. API version `2025-01-01` for all three lists.** `2026-10-01` was two
weeks old when this was written. It adds a recommendation's status and the
review it belongs to, and nebaz shows neither.

## Considered options

- **Advisor as a Governance sub-tab.** Rejected: decision 1.
- **Advisor recommendations as `@audit` findings.** Rejected for the
  reasons in ADR 0010 decision 1.
- **Filtering Security out in the request.** The filter has no `ne`, but
  `Category eq 'Cost' or …` over the other four would do it. Rejected:
  it would hide the Security rows entirely and silently drop any category
  Advisor adds later. Noise keeps them one key away, along with their
  link to Defender.
- **A "Suppressed" line on each recommendation from the warm
  suppressions list.** Rejected: decision 4.

## Consequences

- `PERMISSIONS.md` gains `Microsoft.Advisor/recommendations/read`,
  `advisorScore/read` and `suppressions/read`. All are in `Reader`.
- An Advisor row has no RBAC and no tags of its own, so its tail is
  Activity and Related, like Defender's (`is_advisor_id`).
- A recommendation's and a suppression's portal link is the resource's
  page (its Advisor blade), because their own ids are no portal page. The
  score's link is the subscription's page.
- The score's `score` is read as a percentage from 0 to 100. The REST
  example's values don't settle the scale, so this needs checking against
  a live tenant.
