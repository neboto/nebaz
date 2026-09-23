# 08 — Release and install pipeline

Type: task
Status: claimed
Blocked by: 03
Map: ../map.md

## Question

Nothing to decide: port neboto-tui's `.github/workflows/release.yml`,
`install.sh`, the `[package.metadata.binstall]` table and `docs/RELEASING.md`
to nebaz, renamed, so a tag push cuts a release the same way.

Answer records what was ported, the archive-name triple that must stay in
sync, and any Azure-specific build deps (e.g. OpenSSL vs. rustls choice).

## Comments

**2026-09-23 — input from ticket 05.** Runtime dependency to document in
the README and the install script's post-install note: Azure CLI ≥ 2.54.0,
logged in (`az login`). The script does not install `az`.

**2026-09-23 — input from ticket 07.** `.github/workflows/ci.yml` (test +
clippy on Linux, copied from neboto) and the PR template already exist; the
read-only guard runs inside `cargo test`, so `release.yml` needs no extra
step. This ticket ports only `release.yml`, `install.sh`, the binstall
table and `docs/RELEASING.md`.
