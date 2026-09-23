---
status: accepted
date: 2026-09-23
---

# Lists are subscription-scoped; location is a client-side filter; the ARM id is the key

Azure's ARM list endpoints are subscription-wide and offer no server-side
location filter (verified for all first-release types), whereas every AWS
list neboto makes is region-scoped. So nebaz inverts neboto's scoping: the
**subscription** takes the `P` slot and is what every list is fetched for;
the **location** takes the `R` slot but is a pure filter over rows already
held, with "all locations" as the default; the **resource group** is a
search-query token (`rg:<name>`), not a slot at all. The **ARM resource id**
is the universal key — row identity, portal link, cache and lazy key, and
the argument of every copied `az` command.

Two stores follow from this:

- The **list cache** is keyed by `(service, subscription, sub-tab)` and
  survives a subscription switch, so switching back is instant. Location
  changes never touch it. Tenant-scoped lists (only the subscription list)
  are keyed under a fixed pseudo-subscription.
- The **LazyStore** holds everything fetched per resource (blob containers,
  secret/key names, VM instance view) keyed by ARM id, and is replaced
  wholesale on a subscription switch (epoch bump), exactly as in neboto.

A **sub-tab exists only when its rows come from one subscription-wide list
or are embedded in one** (subnets in virtual networks, node pools in
clusters). Anything that needs a call per parent (containers, secret names)
is a lazy section on the parent, never a sub-tab. This is what keeps the
Storage resource provider's budget of 100 list calls per 5 minutes intact.

`Location` is a string, not a compiled enum: the picker is fed from
`GET /subscriptions/{id}/locations` (fetched once per subscription) merged
with the distinct locations of the current list and their row counts. A
compiled table would go stale the day Azure adds a region.

## Considered options

- **Location as a scope with a per-location cache key (neboto's model)** —
  rejected: would refetch the whole subscription on every `R` change and
  burn the Storage RP budget for nothing.
- **Resource group as a first-class slot** — rejected: a third axis to reset
  on every switch, when the group is already in the ARM id and a query token
  composes with search, macros and bookmarks for free.
- **Containers / secret names as sub-tabs** — rejected: N calls per view,
  throttled.

## Consequences

- A subscription switch keeps the client and the list cache, replaces the
  LazyStore, and bumps the load generation. A tenant change is a credential
  concern: see ADR 0003.
- Navigation history and bookmarks carry the subscription, so a jump into
  another subscription switches it first.
- Copied `az` commands use `--ids <ARM id>` and never append
  `--subscription`; only commands without `--ids` carry it themselves.
- Portal links use the tenant-qualified form `#@{tenant}/resource{id}` once
  the tenant is known.
