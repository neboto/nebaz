---
status: accepted
date: 2026-09-23
---

# Authenticate through the Azure CLI, one credential and pipeline per tenant

nebaz signs ARM requests with `azure_identity`'s `AzureCliCredential`
(shelling out to `az account get-access-token`, Azure CLI ≥ 2.54), wrapped in
`azure_core`'s `BearerTokenAuthorizationPolicy` for caching and refresh. An
ARM token is minted for one tenant, so the app keeps **one credential and one
pipeline per tenant**, built on demand and held in a map keyed by tenant id.
The subscription-to-tenant table comes from `az account list -o json` read
once at startup — the CLI's local account cache, which spans every tenant the
user has logged into and marks the default — not from ARM's subscriptions
endpoint, which sees one tenant per token. A subscription switch therefore
rebuilds nothing inside a tenant and builds one pipeline the first time a
tenant is crossed; there is no tenant picker, the subscription picker shows a
tenant column and the switch is implicit.

The credential source is an explicit config key (`auth = "cli"`, env
`NEBAZ_AUTH`), never auto-detected; only `cli` exists in the first release.
When a non-CLI source arrives, its subscription list must come from ARM per
tenant, because there is no `az` cache to read.

The ARM base URL is `endpoint_url` (default `https://management.azure.com`),
and the token scope is derived from it as `{endpoint}//.default` — the double
slash is what Entra documents for ARM's trailing-slash resource identifier.
Both spellings were checked against `az account get-access-token` and both
return a token; the documented one is used.

## Considered options

- **One credential per subscription** (let `az --subscription` resolve the
  tenant) — rejected: a fresh `az` process and pipeline on every switch, for
  no gain over the tenant map.
- **ARM `GET /subscriptions` as the picker source** — rejected for the CLI
  case: it cannot see other tenants without a token for each, which is
  exactly what the picker is trying to discover.
- **An auto-detecting chain in the style of `DefaultAzureCredential`** —
  rejected: silent source selection is the wrong surprise in a tool whose
  status bar names the identity it acts as.

## Consequences

- A thin `TokenCredential` wrapper around the CLI credential adds a 30 s
  timeout, classifies the CLI's stderr into one `AuthError` (CLI missing,
  CLI too old, not logged in, token expired), and serialises concurrent
  first-use fetches so six services don't spawn six `az` processes.
- Auth failure is one status-bar line, never a per-service error: a missing
  `az` exits before the TUI opens; not-logged-in or expired keeps the TUI
  open with "run `az login`, then press R"; an unknown `--subscription`
  exits listing the known ones.
- The first release depends on the Azure CLI being installed; the install
  docs say so.
