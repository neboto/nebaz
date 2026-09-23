# 03 — Create the neboto/nebaz repo

Type: task
Status: claimed
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
