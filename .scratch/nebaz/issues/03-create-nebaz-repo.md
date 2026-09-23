# 03 — Create the neboto/nebaz repo

Type: task
Status: resolved
Blocked by: 02
Map: ../map.md

## Question

Nothing to decide: publish `~/work/nebaz` (already the local repo holding
this map and, after ticket 02, the skeleton) as `neboto/nebaz`.

Checklist (agent-driven via `gh` where possible; the human confirms the org
push):
- `gh repo create neboto/nebaz --public --source ~/work/nebaz --push` — MIT,
  description "Read-only Azure terminal UI, sibling of neboto"; the local
  history (map + skeleton initial commit) is the whole history.
- Decide whether `.scratch/` is committed or gitignored before the push (the
  map is useful to future sessions; recommend committing it).
- Squash-only merges and tag-push releases, matching neboto-tui's settings.

Answer records: repo URL, initial commit hash, settings applied.

## Answer

Resolved 2026-09-23.

- **Repo**: https://github.com/neboto/nebaz — public, MIT, description
  "Read-only Azure terminal UI, sibling of neboto", homepage
  https://neboto.dev/azure, topics `azure devops ratatui read-only rust
  terminal tui`.
- **History pushed**: `46070db` (skeleton, the initial commit) and
  `e7b494b` (MIT LICENSE + this map). Local `main` tracks `origin/main`.
- **`.scratch/` is committed**, not ignored: the map, tickets and SDK
  research travel with the repo so a session on any machine sees the same
  route. Consequence: pull before a wayfinder session and push after it.
- **Settings applied** (mirroring neboto-tui): squash merges only (merge
  commits and rebase merges off), squash title = commit-or-PR title,
  squash body = commit messages, delete branch on merge, wiki off, issues
  and projects on. neboto-tui has no branch protection on `main`, so none
  was added here either.
- Tag-push releases are the workflow's job: unblocked
  [Release and install pipeline](08-release-and-install-pipeline.md).
- To test on another machine: `git clone https://github.com/neboto/nebaz
  && cd nebaz && cargo build && ./target/debug/nebaz -s vm` (stub provider
  only until the auth ticket lands).
