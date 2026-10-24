---
status: accepted
date: 2026-10-23
---

# Audit checks are pure functions over fetched data, and can't fetch

Mirrors neboto's ADR 0006 (copied, not shared: ADR 0001).

`@audit` (#60) is a virtual service whose rows are security findings. Every
check is a pure function: it takes what nebaz has **already fetched** (the
list cache's rows, as typed rows or their raw ARM JSON, and warm lazy
sections such as SQL and Redis firewall rules, a site's `config/web` and the
subscription's role assignments) plus a clock value passed in, and returns
findings. A check never calls ARM or Graph. The code is `src/audit.rs`
(the machinery and the finding row), `src/audit/checks.rs` (the checks,
unit-tested over fixtures) and `src/app/audit.rs` (the app glue).

The TUI audits the **warm caches** of the current subscription. A check
whose list isn't cached produces a "not checked — load @x" row, never
silence; a check whose lazy data isn't loaded for some resources says how
many and how to get it. `r` in `@audit` loads the missing source lists in
the background: the same streaming list load visiting the tab does, run
to completion off-screen and cached under the tab's own key, so visiting
the tab afterwards is a cache hit with identical rows. It then fetches the
per-resource lazy reads the checks use through the same `LazyMap`s the
detail sections use (each SQL server's and Redis cache's firewall rules,
each messaging namespace's network rule set, each site's config,
the subscription's role assignments, and its Owner / User Access
Administrator users' directory objects), capped at `AUDIT_LAZY_MAX` per
kind. Each result re-audits as it lands, through the apply-closure event,
so the lazy epoch drops anything from before a subscription switch.

## Considered options

- **Pure checks over fetched data (chosen).**
  - Every check is a unit test over fixtures parsed through the row
    types' real `from_json`.
  - The read-only guard covers the audit with no extra work: the audit adds
    no request, and the loads `r` starts are the lists' and sections' own.
  - It keeps the door open for rule packs: a pack rule would be a check
    whose logic comes from a file.
- **Checks that fetch what they need** (Prowler-style). Each check would
  become its own API client with its own paging, throttling and permission
  errors, and the guard would have to audit check code, not just the
  service files. Rejected. When a check needs data no list carries (SQL
  firewall rules, a site's TLS setting), the fetch belongs in a lazy
  section, where it is visible, capped and shared with the panes.
- **A full background sweep on open.** Opening `@audit` would fire a list
  call per source and the Storage resource provider's 100-calls-per-5-min
  budget would pay for a glance. Loading is an explicit `r`, limited to the
  lists the checks read. A denied load is one status error and its checks
  stay "not checked".

## Consequences

- **Checks can't fetch.** An `AuditInput` holds borrowed rows and a borrowed
  `LazyStore`; there is no client in reach. A future rule-pack evaluator
  gets the same input and never a "call this API" primitive, so the worst a
  pack can do is produce wrong findings.
- **Coverage is part of the result.** "Not checked" rows sit in the list
  beside the findings. A permission gap or an unvisited tab never reads as
  a clean audit; "no findings" names how many checks ran clean.
- **`@audit` is never cached and has no list.** `ServiceType::is_virtual()`
  marks it: `load_service_resources` computes the rows instead of loading,
  the mock and registration tests skip it, and its provider slot in
  `AzureClients::service` is a stub that lists nothing.
- **Severity is the state**, through the state ladder: critical →
  Unavailable, high → Stopped, medium → Pending, low → Creating, info
  stateless, with the severity word as the label. `F` filters by it and
  `z` sorts critical first, with no audit-specific keys.
- **Remediation is text.** Each check carries why it matters and what to
  change, as prose: never a command nebaz runs, and never an `az` write
  verb (the guard forbids one in `src/`).
- **The headless form** (`nebaz audit --fail-on`) is `@audit` with `r`
  pressed on a terminal-less `App`: the same source loads and capped lazy
  reads, pumped until nothing is in flight, then `audit::run` over the
  caches. Exit 3 means it ran and found something at or above
  `--fail-on`; a check that couldn't run is `not_checked`, never a pass
  and never a finding.
