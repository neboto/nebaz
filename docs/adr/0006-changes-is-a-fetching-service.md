---
status: accepted
date: 2026-10-24
---

# `@changes` is a regular service that fetches, not a view over caches

`@changes` (#61) answers "what changed just before this started?" for the
whole subscription. The `W` timeline (#52) answers it for one resource.
`@*` (#38) is a view over warm caches, but `@changes` is **not**. It is an
ordinary `ServiceType` with its own provider (`src/azure/services/changes.rs`),
registered in `AzureClients::service`. Its list load queries the change
sources directly over a `[`/`]` window (15m, 1h, 6h, 24h, 7d), and the
result is cached per window like any other list. This mirrors neboto's ADR
0007, adapted to Azure.

## Considered options

- **A regular service that fetches (chosen).**
  - None of the sources has a list nebaz already holds. The Activity Log,
    deployment history and Resource Health statuses aren't rows in any
    other service's cache.
  - As a normal service it gets the existing machinery for free: streaming
    batches, load warnings, the list cache, the noise toggle, headless
    `ls` (and `nebaz changes --since`), and the read-only guard, which
    audits every literal in a service file.
- **A virtual service over warm caches, like `@*`.** This would cost
  nothing, but it would almost always be empty. The question comes up
  mid-incident, when you haven't visited the sources, and the Activity Log
  has no warm list to read. Rejected.
- **Resource Graph `resourcechanges`.** This is the ideal source: property-level
  diffs for every resource, 14 days back, in one query. But it is a `POST`.
  The runtime `ReadOnlyPolicy`, the guard and ADR 0003's GET-only client
  rule it out. Rejected for as long as nebaz is GET-only.
- **Extend `W` to "every resource".** `W` filters its sources to one
  resource. Subscription-wide, those filters disappear and the cost becomes
  unbounded, so the result needs its own caps and its own view.

## Consequences

- **The window is the list's identity.** The cache variant is the window
  (`changes-1h`), not the sub-tab. The sub-tabs (All / Activity /
  Deployments / Health) filter one list client-side, so switching them
  costs nothing, and `[`/`]` back to a window loaded earlier is
  instant.
- **Every expensive source is capped, and a cap hit is a warning.** The
  Activity Log is paged newest first, at most 10 pages. When the cap is
  hit, the load warns how far back it got ("back to 2026-10-24 09:12 UTC; [
  narrows the window"), so a truncated feed never looks complete. Resource
  Health's subscription list stops at 20 pages. Deployment histories are
  read for at most 20 resource groups, 200 deployments each, and only for
  groups the Activity Log saw a deployment operation in. A subscription has
  no deployment list across its groups, and listing every group's history
  would cost one call per group.
- **A failing source is a warning, never the load.** Activity (then
  deployments, which need its groups) and health run concurrently and
  stream when done. Only when both the Activity Log and Resource Health fail
  is the load an error.
- **Noise is classification, not a filter.** Activity rows whose caller is
  not a person are `is_noise()`: shown when `a` is off, hidden when it is
  on. A caller is a UPN (a person), an id or a service name. A service
  name, or no caller at all, is the platform. An id is looked up in
  Microsoft Graph (ADR 0004), as an object id, then as an app id, with at
  most 50 lookups. A managed identity is noise, and so is an app whose
  owner is a Microsoft tenant. The tenant's own apps aren't: a CI
  pipeline's deployment is a change someone made. Without directory read,
  ids stay unclassified (not noise) and a warning says so. Deployments and
  health transitions are never noise.
- **Rows are events, not resources.** A row's id is `change:…`, never an
  ARM id. Its pane is Overview (named fields only, never a `properties`
  bag, a deployment's parameters or outputs, or the caller's claims) and
  Related (what it happened to, which `⏎` jumps to). It has no Access,
  Activity or Tags. `W` on a row opens the timeline of its resource.
- **Opening it costs real API calls.** Each load or `r` makes up to 10
  Activity Log calls, up to 20 health calls, up to 50 Graph calls and one
  deployment-history call per group. The list cache's TTL keeps casual
  revisits free.
- **New sources are new fetches in `changes.rs`.** Don't route them through
  another service's cache. A source whose events already appear as
  Activity Log writes waits until it adds something the log doesn't have,
  as deployments do: the log says a deployment ran, while the deployment
  says what it deployed and why it failed. Fired alerts (`W`'s fourth
  source) are a candidate.
