---
status: accepted
date: 2026-10-23
---

# `C` may copy commands that change Azure, from one file, never run

`C` used to copy one `az … show` command. Issue #47 (neboto `343ef65`)
turns it into a picker of commands for the selected row in three tiers:
**Inspect** (reads), **Connect** (`ssh vm`, `aks get-credentials`,
`containerapp exec`, `acr login`) and **Change** (`vm start`,
`webapp restart`, `aks nodepool scale`). The Connect and Change commands
are not reads, and the read-only guard (layer 2 in `PERMISSIONS.md`)
refused every `az` literal without a read verb. This records how they are
let in without weakening the promise.

## Decision

- **nebaz never runs a copied command.** The picker puts the text on the
  clipboard and nowhere else. nebaz still runs exactly two `az` commands
  (`account list`, and `account get-access-token` through
  `azure_identity`). Every request nebaz itself sends is still a `GET`
  (layer 1), and `Reader` is still the whole RBAC footprint (layer 3): a
  pasted Change command runs in the user's shell, under the user's own
  `az login` and its own permissions, like a command typed from the docs.
- **One file.** Every Connect and Change command lives in
  `src/azure/cli_actions.rs`, the catalogue. The guard admits a short,
  named list of Connect verbs (`ssh`, `rdp`, `connect`, `get-credentials`,
  `exec`, `login`, `tail`) and Change verbs (`start`, `stop`, `restart`,
  `deallocate`, `scale`) in that file and nowhere else; anywhere else they
  fail as before. Verbs are judged as whole words of the command chain
  (the words before the first flag), so a verb hidden behind a `{}`
  placeholder reads as no verb and fails.
- **Refused everywhere, the catalogue included**: destructive or
  code-running verbs (`delete`, `purge`, `remove`, `reset`, `regenerate`,
  `invoke`, `run-command`, `reimage`, `create`, `update`, `set`, …),
  every chain on the secret list (`keyvault secret show`, `acr
  credential`, `storage account keys`, connection strings, SAS,
  publishing profiles, …), and the flags that print a credential
  (`--admin`, `--expose-token`, `--show-values`, `--show-secrets`).
- **Only copied, mechanically**: the guard checks that the catalogue
  spawns nothing (no `process::`, `Command::new`, `spawn`), that only the
  picker's glue (`src/app/command_picker.rs`, which hands a command to
  `copy_to_clipboard`) and widget name it, that neither of those spawns a
  process, and that a bare `"az"` literal (the start of a command built
  by concatenation) appears only in `auth.rs` and the catalogue.
- **Visibly marked**: Change rows sit under a `⚠ changes Azure` heading in
  the warning colour, the picker shows the exact text before it is copied,
  its header says nebaz never runs these, and the toast says
  "changes Azure; not run".
- **Neboto's catalogue rules carry over**: nothing destructive; never a
  command that reveals a secret; a value-taking command is prefilled with
  the current value, so a blind paste is a no-op (`aks nodepool scale
  --node-count <current>`); the read command is the first entry, so `C`
  `⏎` copies what `C` always copied. `--ids` or the name form exactly as
  `cli_command()` does (`SERVICES.md` rule 9), each checked against the
  CLI's parameter table (`id_part`).

## Considered

- **Keep `C` read-only** (copy `show`, the user edits the verb). Safe, but
  it gives up the Connect commands, which change nothing in Azure and are
  most of the value (`aks get-credentials`, `ssh vm`).
- **An allowlist of whole commands in the guard.** Exact, but every new
  catalogue entry would need a guard edit, and the guard would duplicate
  the catalogue. A verb list per tier is short, reviewable, and still
  refuses anything outside it.
- **Exempt the file entirely.** Rejected: the denylist must still hold in
  the one file that is allowed to spell a change.

## Consequences

- A new Change verb is a deliberate edit to `tests/readonly_guard.rs`
  (`AZ_CHANGE_VERBS`) and should come with a reason; a new destructive or
  secret-revealing command cannot be added at all.
- `PERMISSIONS.md` is unchanged in substance: nebaz's own requests are
  `GET`s under `Reader`. What a pasted command needs is the user's own
  role (a Change command needs more than `Reader`; the picker's notes say
  where it matters, as for the NIC effective-rules reads, which Azure
  serves as `POST` actions).
- neboto gates Change rows while an org role is assumed; nebaz has no
  assumed role (a subscription carries its tenant, ADR 0003), so there is
  no gate. A non-public `endpoint_url` shows a caution in the picker
  (`az cloud show` must name the same cloud).
- Batching a list visual selection (#39) into one `--ids a b c` command
  (neboto's batch mode) is left for later; `C` acts on the cursor row.
- The headless CLI (`nebaz get`, #44) does not print the catalogue yet.
  Wiring it there means adding its module to the guard's
  `CLI_CATALOGUE_USERS` deliberately, with the same rule: the commands
  are printed, never run.
