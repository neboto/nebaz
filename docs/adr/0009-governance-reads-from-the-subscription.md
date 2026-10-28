---
status: accepted
date: 2026-10-28
---

# Governance is read from the subscription; management groups are what the caller can see

Issue #155 adds a Governance tab: policy assignments, exemptions, custom
definitions and initiatives, resource locks, and management groups. In a
CAF landing zone most of these do not live on the subscription. The policy
is assigned at the intermediate-root and landing-zone management groups,
the custom definitions are stored there too, and the subscription only
inherits them. ADR 0002 says every list is subscription-wide and keyed by
the ARM id. This ADR decides how rows that live *above* the subscription
fit that rule, given that the one role nebaz asks for is `Reader` at
subscription scope (`PERMISSIONS.md`).

## Decision

**1. Every governance list is the subscription's view, with what it
inherits.** The assignment and exemption lists are fetched at subscription
scope **unfiltered**, which returns what was made on the subscription, on
its resource groups and resources, and on every management group above
it. (`$filter=atScope()` drops the ones made on the groups and resources
inside it; the spec's description of each list says so.) Subscription `Reader` can read all of that,
because it is what applies to the subscription. The definition and
initiative lists are fetched at subscription scope as well (custom only,
`$filter=policyType eq 'Custom'`; the built-ins are thousands of rows). So
the tab holds one subscription-wide list per sub-tab and is cached under
`(service, subscription, sub-tab)` like everything else. A row inherited
from a management group appears in each subscription's cache that inherits
it, and that duplication is fine: each cache is that subscription's view.

**2. A definition is resolved from the subscription's own lists, never by
its id at management-group scope.** An assignment names its definition by
id, and for a CAF policy that id is under
`/providers/Microsoft.Management/managementGroups/{mg}/…`. A direct GET of
that path needs read at the management group, which a subscription
`Reader` may not have. The assignment's Definition line therefore looks
the id up in the warm definition and initiative lists. A built-in
(`/providers/Microsoft.Authorization/policyDefinitions/{guid}`, readable by
anyone) resolves with one lazy GET by id. Anything else that isn't in the
lists shows as the id and a note that it wasn't found, never as an error.

**3. The Management groups sub-tab lists the groups the caller can read,
and an empty list is not an error.**
`GET /providers/Microsoft.Management/managementGroups` returns only the
groups the caller has access to. A subscription `Reader` with nothing at
management-group scope gets an empty list, which the tab shows as one
line: "no management groups readable with this account; the assignments
they make are still listed under Policy assignments". It never shows a
`⚠`, because nothing failed. A group's detail fetches its children lazily
(`GET …/managementGroups/{mg}?$expand=children`). The list is cached per
**subscription**, like Service principals (see `JumpView::ServicePrincipals`
in `src/azure/service.rs`), not under the tenant pseudo-key, because that
key is shared by every tenant (`src/azure/cache.rs`). One extra call per
subscription is cheap, and making the pseudo-key per tenant is a separate
change that nothing else needs yet.

**4. Ids that aren't under a subscription are still the key.** A
management group, and an assignment or definition made at one, has an
ARM id that starts at `/providers/…`, so `subscription_of` returns `None`.
Such a row keys, caches, jumps and copies on its ARM id like any other.
A jump to it stays in the current subscription, since it was found
through that subscription's list. Its portal link takes the
tenant-qualified form (`#@{tenant}/resource{id}`), which already works
for any id. Its Related section has no Subscription line, only the scope
it was made at.

**5. Extension resources route on their last `/providers/` segment.** A
lock or an assignment made on a single resource has an id like
`…/storageAccounts/a/providers/Microsoft.Authorization/locks/l`. Today
`arm_type_chain` reads the first `/providers/` segment and would call it a
storage account. It changes to read the **last** one, which gives the
row's own type, and the part before that segment becomes the row's
**scope**: a Related line labelled "Locks" or "Applies to" that jumps to
the scoped resource. Every id nebaz routes today has only one
`/providers/`, so nothing that already works changes. A test pins that
down.

**6. Compliance is out.** Per-resource compliance (`Microsoft.PolicyInsights`
`policyStates/…/queryResults`, `summarize`) is POST only. The runtime
policy and the guard keep "nebaz only sends GETs" a mechanical fact, so
nebaz does not show compliance state. It shows what is *assigned* and
what is *exempted*, and the `C` picker carries the
`az policy state summarize` / `list` commands for the user to run. #33
already recorded this.

**7. Location never filters governance rows.** Assignments carry a
`location` only when they have a managed identity, and that location is
where the identity lives, not where the assignment applies. Every
governance row is location-less for the `R` filter, so
`Location::admits` passes it. That is the same rule subscriptions and
resource groups follow.

## Considered options

- **The tenant's hierarchy as the primary view** (start at the tenant root
  group and expand it). Rejected: it needs `Reader` at the root group,
  which most operators don't have, and a tab that is empty for most users
  is the wrong default. Decision 3 shows it to the users who can read it.
- **Deriving the subscription's ancestry from the scopes of assignment and
  role-assignment ids.** Rejected for now: the scopes give the names of
  the groups but not their order, so the result would be a set presented
  as a path. If the live check shows that subscription `Reader` can read
  `…/managementGroups/{mg}/subscriptions/{sub}` (its `parent`), the
  ancestry becomes a line on the Subscription detail. That is a follow-up,
  not this ADR.
- **Fetching definitions by id at management-group scope.** Rejected:
  decision 2. With subscription `Reader` it would 403 on exactly the
  definitions a CAF tenant cares about.
- **A per-tenant pseudo-key in the list cache** (so management groups are
  fetched once per tenant). Deferred: it is correct and cheap, but only
  the Management groups sub-tab would use it, and caching per subscription
  is already correct.
- **A Governance section on every resource type** (the locks and
  assignments that apply at its scope, the way Access shows inherited
  role assignments). Deferred to after the tab ships. When it comes, it
  is computed from the warm governance lists by ARM-id prefix (pure, like
  an `@audit` check, ADR 0007) and never makes a per-resource call.

## Consequences

- `PERMISSIONS.md` gains `Microsoft.Authorization/policyAssignments/read`,
  `policyExemptions/read`, `policyDefinitions/read`,
  `policySetDefinitions/read`, `locks/read` and
  `Microsoft.Management/managementGroups/read`. All are in `Reader`, so
  the requirement doesn't change. The last one only takes effect where
  the role is assigned at a management group.
- `arm_type_chain` reads the last `/providers/` segment (decision 5), and
  `for_arm_id` gains the governance arms. The Access section's
  `inherited_from` already names management-group scopes. The Governance
  rows reuse it for their Scope column, so "management group corp" reads
  the same in both places.
- `@audit` gains pure checks over the new lists (an assignment in
  `DoNotEnforce`, an exemption that has expired or expires soon) without
  any change to ADR 0007.
- To verify on a live CAF tenant before the PR that adds the lists
  merges (this dev machine has no `az`):
  - that the unfiltered list on the subscription returns assignments
    made at management groups;
  - that the subscription's definition list includes custom definitions
    stored at management groups;
  - what `GET …/managementGroups` returns for an account that is
    `Reader` at subscription scope only.

  If the second one fails, decision 2 still holds, but such definitions
  show as unresolved ids, and this ADR gets a note.
