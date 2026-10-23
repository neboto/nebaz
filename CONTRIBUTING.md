# Contributing to nebaz

Thanks for helping. nebaz is a **read-only** Azure browser; that single
promise shapes every rule below.

## The one rule that never bends

nebaz only sends HTTP `GET`s, to Azure Resource Manager and to Microsoft
Graph for directory objects. A pull request that adds a write — a `PUT`,
`PATCH`, `DELETE` or `POST`, a data-plane call (a vault's secrets, a blob,
a database, a model endpoint), or running an `az` command — will not be
merged, however useful the feature. Three layers hold it
([`PERMISSIONS.md`](PERMISSIONS.md)), and CI checks the first two:

1. **Runtime.** Only `src/azure/arm.rs` builds requests, only `GET`s, and
   the pipeline's `ReadOnlyPolicy` refuses any other method before it
   leaves the process.
2. **The guard.** `tests/readonly_guard.rs` runs under `cargo test` and
   fails on a `Method::` outside `arm.rs`, an HTTP client crate, a
   data-plane host literal in non-test code (`vault.azure.net`,
   `blob.core.windows.net`, …), a Graph host outside
   `src/azure/graph.rs`, an `az` literal without a read verb, or a
   non-`/read` action in `PERMISSIONS.md`. If the guard trips on something
   you believe is read-only (some ARM reads are `POST`s, and nebaz does not
   make them), say so in the PR description; don't loosen the guard in the
   same PR without a reason written next to the change.
3. **RBAC.** `Reader` at subscription scope is the whole requirement. A
   new call that needs more than `Reader` is a design conversation, not a
   PR.

A credential the ARM `GET` itself returns (App Insights' instrumentation
key and connection string) is stripped before the row keeps its JSON, so
no pane, export or `e` view can show it. A new service that returns one
does the same.

## Before you open a PR

```bash
cargo test                                  # unit tests, the offline wiring harness, the read-only guard
cargo clippy --all-targets -- -D warnings   # CI fails on any warning
scripts/smoke.sh                            # offline pty run with a fake az (needs python3)
```

Then walk the checklist in the PR template:

- **New or changed ARM / Graph calls?** Add the action to `PERMISSIONS.md`
  and the path + api-version to the call table in `docs/SERVICES.md`. The
  guard fails on a non-read action.
- **New service or sub-tab?** Read `CLAUDE.md` ("Adding a service or
  sub-tab") and `docs/SERVICES.md` first: decide whether it is a
  subscription-wide list, an embedded child or a lazy child, then follow
  the steps (the `ServiceType` / `JumpView` arms, the row via `ArmBase` +
  `arm_row!`, the `*_SECTIONS` descriptor, registration in
  `AzureClients::service()`, the `section_lines_for` arm). The service's
  entry in `docs/SERVICES.md` — its state rule, its links, the quirks you
  hit — is the part nobody can recover from your code.
- **A lazy section?** A failed fetch renders as a `⚠` line with the
  service's message, never as "No …". Empty and denied must look
  different.
- **Colors** go through `src/ui/theme.rs` accessors, never `Color::`
  literals, or the light preset breaks.
- **No `eprintln!`** anywhere in the TUI path; it draws over the raw
  terminal.
- **Docs**: if behaviour changed, `README.md` and the relevant `docs/` file
  (and `CONTEXT.md` for new vocabulary) change in the same PR.

## What a good PR looks like

- One concern per PR. A new service and an unrelated refactor are two PRs.
- The description says what you tested against: a live tenant (which
  services), the fake-`az` smoke run, or unit tests only. All are fine;
  pretending is not.
- Screenshots or a short recording for anything visual.
- One label from the `area:*` set (or `bug` / `documentation`); release
  notes are grouped by it (`.github/release.yml`).
- Commit history doesn't matter; PRs are squash-merged and you keep
  authorship on the squash commit.

## AI-assisted contributions

Welcome, with the same bar as any other PR. The things a tool won't know
are exactly the things reviewers look for: the `docs/SERVICES.md` entry,
the `PERMISSIONS.md` action, and whether every call is actually a
control-plane `GET`. A PR that adds a service without those will be sent
back for them, not reviewed around them.

## Where work is tracked

Open work lives in [GitHub Issues](https://github.com/neboto/nebaz/issues),
labelled by area (`area:platform`, `area:new-service`,
`area:service-depth`, `area:ux`, `area:security`, `area:testing`,
`area:release`). `docs/` is for knowledge only. The test for where
something goes: if someone could close it, it's an issue. If it stays true
after the work ships, or explains why something will never be built, it
goes in `docs/`:

- per-service behaviour and "this looks like a gap but isn't" go in
  `docs/SERVICES.md`;
- settled decisions go in `docs/adr/`.

Rejected ideas also get a closed `wontfix` issue linking the ADR, so a
search of the issues finds the answer.

nebaz is the Azure sibling of [neboto](https://github.com/neboto/neboto-tui)
and copies its provider-neutral modules rather than depending on them
(ADR 0001). A fix in a ported file may belong in neboto too;
`docs/PORTED-FROM-NEBOTO.md` says which files came from where.

## Security

Please don't open a public issue for a vulnerability — see
[`SECURITY.md`](SECURITY.md).

## License

By contributing you agree your contribution is licensed under the MIT
license in `LICENSE`.
