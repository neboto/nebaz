# 05 — Auth and the credential chain

Type: grilling
Status: open
Blocked by: 01
Map: ../map.md

## Question

How does nebaz authenticate on day one with the Azure CLI credential, and how
is the chain shaped so service-principal env vars / managed identity are a
later config addition?

Decide:
- Credential construction and token refresh inside the async client factory
  (the neboto `AwsClients` analog); what "profile" means when there is none —
  is the `P` picker fed by `az account list`?
- Tenant handling: single tenant in the first release, with tenant switching
  left in the fog.
- Failure surface: an expired `az login` should read as one clear status-bar
  message with the fix, not a per-service error.
- What the CLI flags are (`-s/--subscription`, `-l/--location`?) and how
  config (`~/.nebaz.toml`) mirrors neboto's.

## Inputs from ticket 01

`DefaultAzureCredential` no longer exists; build `AzureCliCredential`
directly (options `subscription`, `tenant_id`, `executor`; `tokio` feature).
It does not cache tokens — rely on `azure_core`'s
`BearerTokenAuthorizationPolicy` (refresh 5 min before expiry, https only);
Azure CLI ≥ 2.54.0 required. Open: whether the ARM scope must be
`https://management.azure.com//.default` (double slash) — verify in the
prototype, not by reading.

## Comments

**2026-09-23 — input from ticket 04.** Decided there: a subscription switch
keeps `AzureClients` (subscription is a value on the provider, not a client
to rebuild), keeps the list cache and replaces the LazyStore. So this ticket
owns the one case where that is not enough: a subscription in **another
tenant**, where the token must be minted for that tenant. Also decided:
`NavLocation` carries a subscription and a jump may switch it — which needs
the subscription list this ticket sources (`az account list` vs the ARM
subscriptions endpoint) to be available for validation. The `R` picker is
fed from `GET /subscriptions/{id}/locations`, one extra call per
subscription on the same pipeline.
