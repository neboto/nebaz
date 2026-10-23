---
status: accepted
date: 2026-10-23
---

# Read Microsoft Graph with the same credential, GET only, one module

nebaz talks to Microsoft Graph as well as ARM, for directory reads only:
principal names in Access, and (issue #78) service principals and app
registrations. Graph is a second host behind the **same** machinery as ARM
(ADR 0003), not a second client:

- **Credential**: the same `AzureCliCredential` wrapper, minting a token
  for the Graph scope `{graph}/.default` (single slash: Graph's resource
  identifier has no trailing slash, unlike ARM's `{endpoint}//.default`).
  The Graph base URL is derived from `endpoint_url`, the way the ARM scope
  is: `management.azure.com` → `graph.microsoft.com`,
  `management.usgovcloudapi.net` → `graph.microsoft.us`,
  `management.chinacloudapi.cn` → `microsoftgraph.chinacloudapi.cn`. Any
  other endpoint has no Graph: every Graph section says so and the rest of
  the app is unchanged.
- **Pipeline**: one Graph pipeline per tenant, built on demand by
  `AzureClients` next to the ARM one, carrying the same `ReadOnlyPolicy`.
  It is an `ArmClient` built for the Graph flavour: the one GET constructor
  in `src/azure/arm.rs` skips `api-version` (Graph versions in the path,
  `/v1.0`) and follows `@odata.nextLink` instead of `nextLink`. The
  constructor can carry request headers, so an advanced query sends
  `ConsistencyLevel: eventual` with `$count=true`. No new HTTP crate.
- **One module**: every Graph path, query and host lives in
  `src/azure/graph.rs`. The read-only guard allows the Graph hosts there
  and nowhere else; every other data-plane host stays forbidden
  everywhere.
- **GET only**: `directoryObjects/getByIds` is a `POST`, so it is out.
  A principal id resolves with one `GET /v1.0/directoryObjects/{id}`
  (which returns the typed object with its `@odata.type`), cached in a
  `LazyMap` keyed by object id and bounded per section. The guard forbids
  `getByIds` as a literal.
- **No secret material**: a Graph `GET` never returns a secret value
  (`secretText` only comes back from the `addPassword` `POST`), and a
  certificate's public `key` only when `keyCredentials` is `$select`ed.
  nebaz never uses `$select` on Graph (the guard forbids it, and a `key`
  field, in the Graph module's literals), so `key` stays null; it shows a
  credential's display name, key id, start, end and an expiry state, never
  the `hint`.
- **Permission**: the signed-in user's own directory read. Members can read
  users, groups, service principals and applications by default; guests
  and tenants that restrict directory access get a `403`. A 403 is a
  section-level warning ("directory read not allowed for this account"),
  never the app-wide auth line and never a fatal list error.

## Considered options

- **`directoryObjects/getByIds`** (one call for every principal on screen)
  — rejected: it is a `POST`, and the runtime policy and the guard exist to
  make "nebaz only sends GETs" a mechanical fact. One GET per id, cached
  and bounded, costs a few more requests on a busy Access section.
- **A separate `GraphClient` with its own constructor** — rejected: a
  second place that builds requests is a second place the guard has to
  trust. The flavour is a field on the one client.
- **Leaving Graph on the forbidden-host list** (the v0.1 position) —
  superseded: Access showing GUIDs, and no way to see an app
  registration's expiring secrets, were the most-asked gaps.
- **`az ad` shell-outs** — rejected: nebaz runs `az` only for the account
  list and tokens (ADR 0003); the copied `az ad sp show` / `az ad app show`
  commands stay the user's to run.

## Consequences

- `PERMISSIONS.md` names a second requirement beside `Reader`: directory
  read in the tenant (the default for members). Nothing else changes for a
  user who never opens an Access section or the Graph sub-tabs.
- A subscription switch that crosses tenants builds a Graph pipeline for
  that tenant the first time a Graph section is entered; the
  `LazyStore` reset on a switch drops every resolved name with it.
- Rows from Graph have no ARM id. They key on a synthetic id
  (`graph:/servicePrincipals/{id}`); see issue #78's second half for the
  sub-tabs that need it.
