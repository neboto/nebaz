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
