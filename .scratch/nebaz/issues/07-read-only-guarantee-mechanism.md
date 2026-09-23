# 07 — Read-only guarantee mechanism

Type: grilling
Status: open
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
command table is `show --ids` for every ARM row, `az account show` /
`az group show` for the two without `--ids`; lazy children (containers,
secret and key names) are section lines with no command, and the vault's
sections name `az keyvault secret list` / `key list` as the read commands.
Key Vault values are never fetched: the ARM `secrets` / `keys` lists cannot
return them, and no data-plane vault scope exists in the app.
