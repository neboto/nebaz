# 07 — Read-only guarantee mechanism

Type: grilling
Status: resolved
Blocked by: 01, 04
Map: ../map.md

## Question

How does nebaz enforce and document its read-only promise, the way neboto
does with `scripts/check-readonly.py` + PERMISSIONS.md?

Decide:
- The CI check: allowlist of SDK operations / HTTP verbs (depends on whether
  the SDK research shows verbs are visible at the crate level, or whether
  direct ARM REST makes the check trivially a GET-only client);
- The permissions doc: the minimal RBAC role(s) — `Reader` per subscription
  plus Key Vault's separate reader roles — listed per service;
- Where the "never resolve a secret value" line is enforced for Key Vault
  (no `getSecret` call exists in the codebase, checked by the same script).

## Inputs from ticket 01

With direct ARM REST the verb guard is one request constructor that only
emits `Method::Get` — the CI script greps for any other method. RBAC `Reader`
(`*/read`) per subscription is the server-side backstop; Key Vault secret
*values* are never returned by the ARM list, and no data-plane vault call
should exist in the codebase.

## Comments

**2026-09-23 — input from ticket 04.** Every `cli_command()` is an `az`
**read** command using `--ids <ARM id>`; the app never appends
`--subscription`. The guarantee this ticket designs should cover the copied
command table as well as the HTTP layer (GET-only pipeline policy is the
obvious backstop): Key Vault maps to `secret list`, never `secret show`.

**2026-09-23 — input from ticket 05.** Every ARM request goes through one
`azure_core` pipeline per tenant (ADR 0003). That pipeline is the single
choke point: a per-call policy that rejects any method but `GET` is the
cheapest runtime backstop, on top of the CI check.

**2026-09-23 — input from ticket 06.** The catalog's "API calls per view"
table is the allowlist: 15 `GET` paths (plus `nextLink` continuations) at
seven api-versions, every one built by `ArmClient::get_request`. The copied
command table is `show --ids` for every ARM row except the five whose
`show` takes no `--ids` (`az account show`, `az group show`,
`az keyvault show`, `az aks show`, `az aks nodepool show`), which carry
`--subscription` by name; lazy children (containers,
secret and key names) are section lines with no command, and the vault's
sections name `az keyvault secret list` / `key list` as the read commands.
Key Vault values are never fetched: the ARM `secrets` / `keys` lists cannot
return them, and no data-plane vault scope exists in the app.

## Answer

**Resolved 2026-09-23 (grilled, one round, all recommendations accepted).**

The guarantee is **three layers**, one more than neboto, because direct ARM
REST makes a runtime layer cheap:

1. **Runtime**: every request is built by the single constructor in
   `src/azure/arm.rs` (`Method::Get` only), and the per-tenant pipeline
   carries a `ReadOnlyPolicy` per-call policy that refuses any request whose
   method is not `GET` before it leaves the process. A future helper or bug
   cannot send a write.
2. **Guard test**: `tests/readonly_guard.rs`, a Rust integration test under
   `cargo test` (no Python step, runs for every contributor). Four rules:
   - `Method::`, `Pipeline::new` and `BearerTokenAuthorizationPolicy` occur
     only in `arm.rs`, and `Method::` only as `Method::Get`;
   - no data-plane host anywhere in `src/` (`vault.azure.net`,
     `blob.core.windows.net`, `dfs.core.windows.net`,
     `file.core.windows.net`, `queue.core.windows.net`,
     `table.core.windows.net`, `vault.usgovcloudapi.net`,
     `vault.azure.cn`), so no secret value or blob body is ever fetchable;
   - every `az …` literal in `src/` uses a read verb (`show`, `list`,
     `get-access-token`) or is on a written allowlist (`az login` as advice
     text); `keyvault secret show`, `keyvault key show` and `keyvault
     certificate` are named forbidden;
   - every action in `PERMISSIONS.md` ends in `/read`.
   No API-path allowlist in the test: the path list is documentation in
   `PERMISSIONS.md`, kept in sync by the PR-template checkbox.
3. **RBAC**: `PERMISSIONS.md` at the repo root, neboto-style: assign the
   built-in **`Reader`** role at subscription scope, then per service the
   exact ARM actions used so a least-privilege custom role can be built. No
   custom-role JSON shipped. Key Vault secret and key *names* are the
   control-plane actions `Microsoft.KeyVault/vaults/secrets/read` and
   `vaults/keys/read`, which `Reader` includes and which never return
   values, so **no data-plane role and no vault access policy is needed**.
   The doc also lists the two local commands the app runs (`az account
   list`, `az account get-access-token` via azure_identity).

No ADR: the mechanism is self-describing once the test and doc exist. The
promise is written for users in a README "Why read-only" section.

**Built off-map right after resolution** (same pattern as ticket 06):
`ReadOnlyPolicy`, `tests/readonly_guard.rs`, `PERMISSIONS.md`, the README
section, and `.github/workflows/ci.yml` (test + clippy, copied from
neboto, the guard runs inside `cargo test`) plus neboto's PR template.
Ticket 08 stays a pure release ticket.
