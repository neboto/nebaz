# 08 — Release and install pipeline

Type: task
Status: open
Blocked by: 03
Map: ../map.md

## Question

Nothing to decide: port neboto-tui's `.github/workflows/release.yml`,
`install.sh`, the `[package.metadata.binstall]` table and `docs/RELEASING.md`
to nebaz, renamed, so a tag push cuts a release the same way.

Answer records what was ported, the archive-name triple that must stay in
sync, and any Azure-specific build deps (e.g. OpenSSL vs. rustls choice).
