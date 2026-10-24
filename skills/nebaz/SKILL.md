---
name: nebaz
description: Read-only Azure lookups with the nebaz CLI — list a subscription's resources (VMs, networks, NSGs, Key Vaults, AKS, App Service, SQL, Cosmos, Container Apps, managed identities, service principals, …), fetch one resource's full detail (overview, networking, RBAC access, activity log, related resources) and run a security audit (world-open NSGs, public storage, weak TLS, expiring credentials, …) as JSON or Markdown. Use when answering what exists in an Azure subscription, how something is configured, or what is exposed. It cannot change anything, so prefer it over the az CLI for looking.
---

# nebaz: read-only Azure lookups

`nebaz` is a terminal Azure browser whose subcommands print instead of
opening the UI. It only ever sends `GET`s to Azure Resource Manager and
Microsoft Graph (checked in its tests, and refused at runtime), so nothing
you run through it can create, change or delete a resource. It signs in
through the Azure CLI: the user must have run `az login`.

## The loop

1. **Find the prefix** (once): `nebaz services`
2. **Find the resource**: `nebaz ls <prefix>` with filters, to get its ARM id
3. **Read its detail**: `nebaz get <ARM id>`, ideally with `--section`

```sh
nebaz services -o json
nebaz ls vm -o json
nebaz ls nsg -f 'rg:prod' -o json
nebaz ls vnet/subnets -r westeurope -o json
nebaz ls kv -f 'tag:env=prod' --limit 20 -o json
nebaz ls vm --subscriptions Prod,Dev -o json
nebaz get /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1 -o json
nebaz get vm-1 --in vm --section networking --section access -o json
nebaz get graph:/servicePrincipals/00000000-0000-0000-0000-000000000000 -o md
nebaz changes --since 6h --hide-noise -o json
nebaz audit --fail-on high -o json
```

## `services` — the catalogue

Every service with its prefix, name, category and sub-tabs. Each sub-tab
has its own prefix (`vm`, `disk`, `nic`; `vnet`, `subnet`, `nsg`, `pip`,
…), and `ls` takes any of them, or `service/sub-tab` (`vnet/subnets`,
`aca/jobs`, `id/service-principals`).

## `ls` — one subscription-wide list

| Flag | Meaning |
|---|---|
| `-f QUERY` | The TUI's search: fuzzy text plus exact `rg:NAME` and `tag:key=value` terms: `-f 'web rg:prod tag:env=prod'` |
| `-r LOCATION` | Only this location (`westeurope`); `global` rows always pass. An unknown location fails |
| `--state STATE` | Only this state, as the row shows it (`running`, `succeeded`, …), any case |
| `--hide-noise` | Drop noise rows (subscriptions that are not Enabled; changes made by managed identities and Azure itself) |
| `--limit N` | At most N rows (across every subscription with `--subscriptions`) |
| `--subscriptions LIST` | Several subscriptions at once, ids or names, comma-separated (see below) |
| `--all-configured` | Every subscription in the user's config `subscriptions` |

Every list is the whole subscription; location is a filter over it, and
a resource group is the `rg:` term.

**Several subscriptions.** `ls vm --subscriptions Prod,Dev` lists the
sub-tab in each, in the order given, filters applied per subscription;
`--all-configured` uses the user's config `subscriptions` (a usage error,
saying how to set it, if they have none). The JSON swaps `"subscription"`
for `"subscriptions": [{"subscription", "name", "status", "count",
"message"}]` (`status` is `ok`, `denied` — a 403, the identity can't read
that subscription — `disabled`, or `error`), and every row carries
`"subscription"` and `"subscription_name"`; `-o md` adds a leading
Subscription column. Exit 0 if any subscription listed: check
`subscriptions[].status` for the rest. Lists that are the tenant's
(`sub`, `id/service-principals`, `id/app-registrations`) and `changes`
refuse it. One list call per subscription, four at a time.

## `changes` — what changed recently

`changes --since WINDOW` lists the subscription's recent changes, newest
first: Activity Log writes, deletes and actions that finished, ARM
deployments, and Resource Health transitions. It is `ls changes` over a
window: `15m`, `1h` (the default), `6h`, `24h` or `7d`. `--source
activity|deployments|health` keeps one source; `-f`, `--hide-noise`
(managed identities and Azure itself) and `--limit` work as in `ls`. Each
row's `id` is `change:…`, not an ARM id; the resource it happened to is in
its Related. A source that cannot be read, or the Activity Log stopping
after 10 pages (it says how far back it got), is a warning on stderr.

## `audit` — security findings

`audit` loads the lists its checks read (NSGs, VNets, storage, Key Vault,
SQL, Cosmos, AKS, ACR, App Service, Container Apps, Redis, Service Bus,
Event Hubs, PostgreSQL and MySQL flexible servers, Power Platform, app registrations, service principals), the
capped per-resource reads a few need (SQL and Redis firewall rules, a
flexible server's firewall rules, parameters and Entra admins,
messaging network rule sets, site configs, the subscription's
role assignments; at most 50 each), and prints the **findings**, worst
first: severity, check, resource id, reason, evidence and remediation as
text. Checks are pure over what was fetched; nothing is changed.
`not_checked` lists each check that could not run (a list that failed to
load, firewall rules not read for some servers) — **a check in
`not_checked` did not pass**, say so rather than reporting the
subscription clean. `-r` keeps the findings in one location.
`--fail-on SEVERITY` (`critical`, `high`, `medium`, `low` (default),
`info`, `never`) sets which findings exit `3`.

## `get` — full detail

`get <ID>...` returns every section the resource's detail pane has,
including the ones that need extra calls (a VM's instance view, the RBAC
role assignments in **Access**, the last week's **Activity** log, a
vault's secret *names*, …). Up to 50 ids per call, all in one subscription.

- An **ARM id** (`/subscriptions/…`) or a **directory id**
  (`graph:/servicePrincipals/…`, `graph:/applications/…`) routes itself
  to the list that holds it; the ids in `ls` output are exactly these.
  The id's subscription is used, so `-p` is not needed.
- A **name** needs `--in PREFIX` (`get vm-1 --in vm`): exact name only, no
  partial matches. A name that matches several rows fails and lists their
  ids.
- `--section NAME` (repeatable, any case) returns only those sections **and
  skips the other sections' calls**. Prefer it. An unknown name fails and
  lists the real ones, so a first `get` without `--section` tells you what
  exists. Every resource has `Overview` first and `Access`, `Activity`,
  `Related`, `Tags` last.
- `--wait SECS` (default 60): a section still loading after that comes
  back as `null`, with a note on stderr.
- **Related** lists the ARM ids of connected resources (a VM's NICs and
  disks, a subnet's NSG): `get` them next to follow the graph.
- To compare two resources, diff two `get`s:
  `diff <(nebaz get ID1 -o md) <(nebaz get ID2 -o md)`.

## Output

Pass `-o json` (the default) or `-o md` for text to reason over.

- `services`: `{"schema": "nebaz/v1", "count", "services": [{"prefix", "name", "category", "subtabs": [{"subtab", "label", "prefix"}]}]}`
- `ls`: `{"schema", "service", "subtab", "subscription", "location", "count", "resources": [{"type", "id", "name", "state", …, "location", "resource_group", "tags"}]}`
  — each row also carries its type's list-level fields; `get` has the rest.
- `get`, one id: `{"schema", "subscription", "service", "subtab", "resource": {"type", "id", "name", "state", "location", "resource_group"}, "sections": {…}, "tags": {…}}`
- `get`, several ids: `{"schema", "subscription", "count", "resources": [ <the one-id shape without schema/subscription> ]}`
- `audit`: `{"schema", "subscription", "location", "count", "findings": [{"severity", "check", "title", "resource_id", "resource_name", "location", "reason", "evidence", "remediation"}], "not_checked": [{"check", "title", "status", "reason"}]}`

Section values mirror the UI: human-readable labels and formatted values,
not raw ARM fields. A group heading becomes a nested object, verbatim text
(rule tables) a `"content"` array of lines, a repeated key gets a ` (2)`
suffix, and a section that is `null` didn't load.

**What's stable.** The envelopes above, the core keys, section names, type
names, prefixes, flags and exit codes only change with a new schema
version (`src/headless/contract.json` pins them). What's *inside* a
section follows the TUI and can change in any release: read it to answer
a question, but a script someone will keep should select on the stable
keys.

stdout carries only the result; warnings (a partial load) go to stderr.

## Exit codes

- `0` — success, including an empty list.
- `1` — Azure error (a denied call, throttling, network). The message is
  Azure's.
- `2` — the request is wrong: unknown prefix / sub-tab / section /
  subscription / location, a resource that isn't there or is ambiguous, or
  bad flags. **The message says what to pass instead**: read it and retry.
- `3` — `audit` only: it ran and found something at or above `--fail-on`
  (the output is printed as usual). Not a failure: report the findings.
- `4` — not signed in: `az` is missing, not logged in, or the login
  expired. Ask the user to run `az login`; don't retry.

## Subscription and location

- `-p SUBSCRIPTION` (id or display name) picks the subscription for `ls`, `changes` and `audit`;
  without it, the Azure CLI's default. An unknown subscription **fails**
  and lists the known ones, so an answer is never from a subscription you
  didn't ask for.
- `get` uses the subscription in the ids; a `-p` that disagrees fails.
- `ls --subscriptions` names the subscriptions itself; every one must be
  known to `az account list`, or it fails listing the known ones.


## Rules

- **Secret values are never available.** Key Vault shows secret and key
  *names*; Container Apps shows secret and env var *names*; App Insights
  never shows its instrumentation key or connection string; storage,
  Cosmos and AI keys are never fetched. Don't try to get values another
  way; if the user needs one, they use the portal or their own tooling.
- **Cost of a call:** `get` loads the list the id routes to, then reads
  the sections. Batch ids from one list into one `get` rather than one
  `get` per resource.
- The output is a snapshot; nothing is cached between runs.
