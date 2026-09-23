---
status: accepted
date: 2026-09-23
---

# Build nebaz by copying neboto's files, never by depending on them

nebaz is the Azure sibling of neboto (`neboto/neboto-tui`), and roughly
7K of its lines are neboto's provider-neutral core. We copy those files into
this repo (each with a `// ported from neboto-tui <path> @ <commit>` header
and a row in `docs/PORTED-FROM-NEBOTO.md`) instead of extracting a shared
crate or a Cargo workspace, because neboto is stable and shipped: it must not
be refactored, re-released or made to carry abstractions it doesn't need in
order to serve a second product. There is no expectation of sync; when a fix
in neboto matters here it is ported deliberately, by hand, using the table.

## Considered options

- **Shared crate / workspace** — rejected: forces neboto to move, and the
  "neutral" list turned out to be neutral at the module level only (thirteen
  of nineteen copied files needed structural cuts), so the shared surface
  would have been small and awkward.
- **Clone-and-strip** — rejected: carries 30K lines of AWS `App` and 42K of
  per-type detail renderers that would be deleted, plus a history that is
  about a different product.

## Consequences

Divergence is expected and unmanaged. A reader must not "fix" nebaz by
pointing it at neboto, nor "fix" neboto to make it reusable.
