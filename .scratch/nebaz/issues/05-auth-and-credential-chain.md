# 05 — Auth and the credential chain

Type: grilling
Status: resolved
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

## Answer

**Resolved 2026-09-23** in a grill; every recommendation accepted. Recorded
as [ADR 0003](../../../docs/adr/0003-azure-cli-credential-per-tenant.md) and
three glossary entries in [`CONTEXT.md`](../../../CONTEXT.md) (tenant,
credential source, auth error). No code changed on this map.

### Decisions

1. **Picker source**: `az account list -o json` read once at startup (local
   cache, all tenants, `isDefault`, display names, `tenantId`, `state`,
   `cloudName`). ARM's `GET /subscriptions` is the source only for non-CLI
   credential sources, per tenant.
2. **Credential shape**: one `AzureCliCredential(tenant_id)` + one
   `azure_core` `Pipeline` with `BearerTokenAuthorizationPolicy` **per
   tenant**, built on demand, held in `AzureClients` as a map keyed by tenant
   id. Subscription → tenant from (1). A subscription switch within a tenant
   rebuilds nothing; crossing tenants builds that tenant's pipeline once.
   No tenant picker; the `P` picker gets a tenant column.
3. **Scope**: `{endpoint_url}//.default`, default
   `https://management.azure.com//.default`. **Verified 2026-09-23** on the
   Azure machine: `az account get-access-token --scope` returns a token for
   both the double-slash and the single-slash spelling. The double slash is
   the one Entra documents, so it is the one used; nothing left to check.
4. **Failure surface**:
   - `az` not on PATH → exit non-zero before the TUI, one stderr line with
     the install link.
   - not logged in / refresh token expired (startup or mid-session) → TUI
     opens/stays open; `App.auth_error: Option<AuthError>` renders one
     status-bar line ("Azure CLI not logged in. Run `az login`, then press R
     to retry") and suppresses per-service load errors; cleared by the next
     successful token.
   - unknown `--subscription` / `default_subscription` → exit non-zero
     listing the known subscriptions (name and id).
   - `az` hang → a thin `TokenCredential` wrapper around the CLI credential:
     30 s `tokio::time::timeout`, stderr → `AuthError::{CliMissing,
     CliTooOld, NotLoggedIn, TokenExpired}`, and a mutex so concurrent
     first-use fetches share one `az` invocation. `Error::Auth(AuthError)`
     joins `error.rs`.
5. **CLI flags**: keep `-s/--service`, `-r/--location`, `-p/--subscription`
   (flag letter = picker key, neboto parity). `--subscription` and
   `default_subscription` accept an id **or** a display name,
   case-insensitive.
6. **Credential source config**: `auth = "cli" | "environment" |
   "managed-identity"` (env `NEBAZ_AUTH` overrides), default `cli`, no
   auto-detection. Day one only `cli` is implemented; the others parse and
   fail with "not supported yet". Internally a `CredentialSource` enum →
   `Arc<dyn TokenCredential>` factory; the subscription-list source follows
   the auth kind.
7. **Endpoint**: `endpoint_url` becomes live as the ARM base URL (default
   public cloud); sovereign clouds work by setting it by hand. Auto-detection
   via `az cloud show` stays in the fog with the emulator question.
8. **Startup resolution**: `--subscription` > `default_subscription` >
   the `isDefault` entry > (if that entry is not `Enabled`, the first
   `Enabled` one) > open the `P` picker with the auth message.
   `SubscriptionInfoLoaded` is filled from the list entry — no ARM call.

### Routine calls made without asking

- Picker row: `⦿ display name · id (short) · tenant (short) · state`; the
  current one marked; disabled subscriptions listed but dimmed.
- No `az account list --refresh` action in the first release.
- `az` binary discovery is `azure_identity`'s (`az` / `az.cmd` on PATH).
- The CLI's exact stderr strings for "not logged in" and "expired" are
  matched loosely (`az login`, `AADSTS700082`, `expired`) — confirm on the
  Azure machine while checking the scope.

### Skeleton deltas for the build session

- `Cargo.toml`: `azure_core = "1"`, `azure_identity = { version = "1",
  features = ["tokio"] }`.
- `src/azure/client.rs`: `AzureClients { pipelines: HashMap<tenant,
  Arc<ArmClient>>, subscriptions: Vec<SubscriptionEntry>, current }`;
  `list_subscriptions()` returns the parsed `az account list` entries;
  `service()` hands the provider the current subscription's `Arc<ArmClient>`.
- `src/azure/auth.rs` (new): `CredentialSource`, the classifying/timeout
  `TokenCredential` wrapper, `AuthError`, `az account list` parsing.
- `src/error.rs`: `Error::Auth(AuthError)`; `From<azure_core::Error>`.
- `src/config.rs` / `src/cli.rs`: `auth` key, `NEBAZ_AUTH`, name matching
  for the subscription.
- `src/app.rs`: `auth_error`; `spawn_subscription_info_fetch` reads the
  list entry; `R` retries when `auth_error` is set.
- `src/ui/widgets/subscription_selector.rs`: tenant + state columns.

### Inputs to later tickets

- **Read-only guarantee mechanism**: the per-tenant pipeline is the single
  choke point for a GET-only per-call policy.
- **Release and install pipeline**: document Azure CLI ≥ 2.54 as a runtime
  dependency; the install script does not install `az`.
- **First-release spec**: the failure-surface wording above is the spec's
  auth section.
