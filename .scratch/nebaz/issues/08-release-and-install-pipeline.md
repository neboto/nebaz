# 08 — Release and install pipeline

Type: task
Status: resolved
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

## Answer

**Resolved 2026-09-23 (task, AFK).** Ported and pushed in commit
`117bf4c`; verified by a `workflow_dispatch` dry run
(https://github.com/neboto/nebaz/actions/runs/35858121936): all four
targets built, archives downloaded, the x86_64 macOS binary runs
(`nebaz 0.0.1`), the arm64 one is a Mach-O arm64, checksums verify, and
`gh attestation verify … --repo neboto/nebaz` passes on a dry-run archive,
so the provenance plumbing works before any tag relies on it.

**What was ported** (all from neboto-tui, renamed):
- `.github/workflows/release.yml` — draft release → four-target build
  matrix → attestation → publish. The private-repo knobs (`RELEASE_ON_CI`,
  `BUILD_MACOS`) and `scripts/release-local.sh` are **not** ported: nebaz
  is public, Actions are free, releases are always cut by the workflow.
- `install.sh` — `REPO=neboto/nebaz`, `BIN=nebaz`, env `NEBAZ_VERSION`,
  `NEBAZ_INSTALL_DIR`, `NEBAZ_NO_ATTEST`; `UNATTESTED_VERSIONS` is empty
  (every release is attested from the first tag) and must stay so; the
  closing line names the Azure CLI ≥ 2.54.0 + `az login` runtime
  dependency, which the script does not install.
- `[package.metadata.binstall]` — already in `Cargo.toml` from the
  prototype; unchanged.
- `docs/RELEASING.md` — runbook, supply-chain rules, advisories, the
  measured build table, a **repo hardening checklist** (rulesets, private
  vulnerability reporting, secret scanning, fork-PR approval, immutable
  releases, tag protection, Dependabot security fixes, SHA-pinned
  actions), and the not-done list.
- `.github/dependabot.yml`, `.github/rulesets/protect-main.json`,
  `protect-release-tags.json` — copied; **nothing applied to the repo**,
  because the branch ruleset makes a direct push to `main` wait for CI,
  and direct pushes are how this map is worked. Applying is the operator's
  call (checklist in the runbook).
- `config.example.toml` — new, with the Azure keys (`auth`, `endpoint_url`,
  `default_subscription`, `default_location`) and shipped in the archive.
  A unit test parses it with every key uncommented; the tables sit last
  because a `[table]` header claims every key below it (neboto's example
  has that trap: `cache_ttl` follows `[theme_colors]`).
- README gained an Install section (installer, binstall, verify, source)
  and a pointer to the example config.

**The archive-name triple that must stay in sync**: `bin: nebaz` in
`release.yml` (`nebaz-<target>.tar.gz` + `.sha256`), `BIN="nebaz"` in
`install.sh`, and the binstall `pkg-url` template
`{ name }-{ target }{ archive-suffix }` in `Cargo.toml`. Archive contents:
`nebaz`, `README.md`, `LICENSE`, `PERMISSIONS.md`, `config.example.toml`.

**Azure-specific build deps**: none beyond neboto's. TLS is rustls with
`aws-lc-sys` (reqwest under `azure_core`), so the aarch64 Linux leg needs
the C compiler `cross` provides, exactly as neboto's did; no OpenSSL.

**Measured**: cold dry run 4 min end to end (2.8–4.1 min per target),
archives 3.5–3.9 MB.

**Not done**: no tag cut (`0.0.1`; the first release is ticket 09's call),
no Homebrew tap, no crates.io publish, no macOS signing, no Windows target.
