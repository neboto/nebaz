# Releasing

How a version of nebaz gets built and published, and how people install it.
The mechanics live in `.github/workflows/release.yml`; this is the runbook.
Ported from neboto-tui's `docs/RELEASING.md` (ticket 08) with the
private-repo material removed: nebaz is public, so Actions minutes are free
and releases are always cut by the workflow.

## What a release is

A git tag `vX.Y.Z` on `main` that matches `version` in `Cargo.toml`. Pushing
the tag runs the Release workflow, which:

1. creates a **draft** GitHub Release with auto-generated notes (the merged
   PRs / commits since the previous tag);
2. builds `nebaz` in release mode for every target in the matrix and uploads
   `nebaz-<target>.tar.gz` + `nebaz-<target>.sha256` (sha256sum format,
   one line per asset) into the draft;
3. flips the draft to published (and marks it *latest*) only once every
   target succeeded.

Targets today: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`aarch64-apple-darwin`, `x86_64-apple-darwin`. Linux builds run on
`ubuntu-22.04` so the binaries need glibc ≥ 2.35; arm64 Linux is
cross-compiled with `cross` (the image carries the C compiler that
`aws-lc-sys`, rustls' crypto backend behind `azure_core`'s reqwest, needs),
Intel macOS is cross-compiled from Apple Silicon. No OpenSSL anywhere:
`reqwest` is built with rustls, so the binaries carry no system TLS
dependency.

The tarball layout is flat — `nebaz`, `README.md`, `LICENSE`,
`PERMISSIONS.md`, `config.example.toml` — and the archive name is
load-bearing: `install.sh` and the `[package.metadata.binstall]` table in
`Cargo.toml` both derive it from `<bin>-<target>.tar.gz`. Change all three
together.

**Runtime dependency**: the binary needs the Azure CLI (≥ 2.54.0), logged in
(`az login`). Neither the workflow nor `install.sh` installs it; the
installer's last line says so.

## Supply-chain rules for the workflows

- Every `uses:` is pinned to a **full commit SHA**, with the human-readable
  version in a trailing comment (`# v4.4.0`). Tags and branches are mutable
  and have been retargeted in real attacks (tj-actions, March 2025); a SHA
  cannot be. Turn on the repo setting *Require actions to be pinned to a
  full-length commit SHA* so an unpinned `uses:` fails the run.
- `.github/dependabot.yml` bumps the pins weekly in one grouped PR and
  refreshes `Cargo.lock` monthly. Review the diff of the action itself when
  a bump lands — the pin only helps if the new SHA gets a look.
- The moving refs those actions rely on (`dtolnay/rust-toolchain@stable`,
  `taiki-e/install-action@cross`) are expressed as inputs instead
  (`toolchain: stable`, `tool: cross`) so the action code stays pinned while
  the toolchain / tool selection still works.
- Builds run `--locked`, so Rust dependencies come from `Cargo.lock` exactly.
- Every archive gets a **build provenance attestation**
  (`actions/attest-build-provenance`, right after the build step): a
  Sigstore-signed statement that this exact file was built by this
  workflow, from this commit, on a GitHub-hosted runner, recorded in the
  public transparency log and stored on GitHub. The build job carries
  `id-token: write` + `attestations: write` for it. Verify with
  `gh attestation verify <archive> --repo neboto/nebaz` (add
  `--format json` for the full provenance). It covers a swapped asset (the
  `.sha256` is uploaded by the same token, so a checksum alone can't), not a
  compromised build step — the SHA pins are what cover that — and it is not
  macOS code signing. Dry runs attest too, so a `workflow_dispatch`
  exercises the plumbing before a real tag relies on it. `install.sh` runs
  the same verification when the GitHub CLI is present and logged in, and
  refuses to install on a failure. Every nebaz release is attested from the
  first tag, so its `UNATTESTED_VERSIONS` list is empty and must stay so.
- Still unpinned, by design or for now: the `cross` docker image (pulled by
  tag; pin it by digest in a `Cross.toml` if this matters), the Rust
  `stable` toolchain itself, and the GitHub-hosted runner images.

## Dependency advisories

Run an advisory scan before tagging (`cargo install cargo-audit && cargo
audit`, or the OSV batch API against `Cargo.lock`). A targeted
`cargo update -p <crate>` fixes anything with a semver-compatible patch.
The dependency tree is small (azure_core + azure_identity + reqwest/rustls,
ratatui, tokio), so a full `cargo update` is usually safe here — check it
builds and that `cargo test` still passes before committing the lock.

Known leftovers and why they're accepted:

- `lru 0.12` / `paste` (unmaintained): via `ratatui 0.26`. Neither is
  reachable from the TUI's usage; goes away with a ratatui upgrade.

## Cutting a release

```bash
# 1. bump the version (Cargo.toml + Cargo.lock)
cargo set-version 0.2.0        # from cargo-edit; or edit Cargo.toml and run `cargo check`
git commit -am "Release v0.2.0"

# 2. tag + push — the tag push is the trigger
git tag v0.2.0
git push origin main v0.2.0

# 3. watch it
gh run watch
gh release view v0.2.0
```

The workflow refuses a tag whose version doesn't match `Cargo.toml`, so a
forgotten bump fails in the first job rather than shipping mislabelled
binaries. A tag with a pre-release suffix (`v0.2.0-rc.1`) is published as a
GitHub *pre-release* and never becomes *latest*.

**Something failed mid-way?** The draft stays a draft with whichever assets
made it. Fix the problem on `main`, then delete the draft and the tag and
re-tag:

```bash
gh release delete v0.2.0 --yes
git tag -d v0.2.0 && git push origin :refs/tags/v0.2.0
git tag v0.2.0 && git push origin v0.2.0
```

(Once the release-tag ruleset below is applied, deleting a `v*` tag needs
a bypass; fix forward with a patch tag instead.)

**Trying a toolchain / target change without a tag:** run the workflow by
hand (`gh workflow run release.yml`, or the *Run workflow* button). A manual
run is a dry run — it builds every target and keeps the archives as workflow
artifacts, but creates no release and uploads nothing.

## Build time

Measured on the first dry run (2026-09-23, cold cache, run 35858121936):

| Target | Runner | Wall time | Archive |
|---|---|---|---|
| x86_64-unknown-linux-gnu | ubuntu-22.04 | 2.9 min | 3.9 MB |
| aarch64-unknown-linux-gnu (cross) | ubuntu-22.04 | 3.1 min | 3.6 MB |
| aarch64-apple-darwin | macos-15 | 4.1 min | 3.5 MB |
| x86_64-apple-darwin | macos-15 | 2.8 min | 3.7 MB |

Four minutes end to end, in parallel. nebaz's dependency tree is a fraction
of neboto's (no 80 SDK crates), which is the whole difference.
`[profile.release] strip = true` is on. Actions are free on the public
repo, so there is no cost table and no local-release script.

## Repo hardening — checklist

The repo is public, so all of these are available. Apply step 1 only once
direct pushes to `main` are no longer the working shape, because it makes
a fresh push to `main` wait for CI to pass on it (branch → PR → CI →
squash merge; the merge settings in step 5 are already on). Each command
is one line; paste them one at a time.

1. Branch ruleset (no force push, no deletion, CI must pass):
   `gh api -X POST repos/neboto/nebaz/rulesets --input .github/rulesets/protect-main.json`
2. Private vulnerability reporting:
   `gh api -X PUT repos/neboto/nebaz/private-vulnerability-reporting`
3. Secret scanning + push protection:
   `gh api -X PATCH repos/neboto/nebaz --input - <<< '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}'`
4. Require approval for workflows from **all** outside contributors:
   `gh api -X PUT repos/neboto/nebaz/actions/permissions/fork-pr-contributor-approval --input - <<< '{"approval_policy":"all_external_contributors"}'`
   Never `pull_request_target`, never a self-hosted runner on the public repo.
5. Merge settings (squash only, delete branches on merge) — already set at
   repo creation (ticket 03).
6. Immutable releases — once published, a release's assets and tag can't be
   changed, which is what `install.sh` and binstall implicitly trust:
   `gh api -X PUT repos/neboto/nebaz/immutable-releases`
7. Protect the release tags too (the branch ruleset says nothing about tags):
   `gh api -X POST repos/neboto/nebaz/rulesets --input .github/rulesets/protect-release-tags.json`
8. Dependabot **security** updates:
   `gh api -X PUT repos/neboto/nebaz/automated-security-fixes`
9. Actions must be SHA-pinned, matching the supply-chain rule above (the
   field sits on the general Actions permissions endpoint):
   `gh api -X PUT repos/neboto/nebaz/actions/permissions -F enabled=true -f allowed_actions=all -F sha_pinning_required=true`

Applied 2026-09-24: 1 is deliberately not; 2, 4, 6, 7, 8 are on; 3 and 9
were re-run after a paste mangled the `<<<` forms (see the spec).

## How users install

| Method | Command |
|---|---|
| Installer script | `curl -fsSL https://raw.githubusercontent.com/neboto/nebaz/main/install.sh \| sh` |
| cargo-binstall | `cargo binstall --git https://github.com/neboto/nebaz nebaz` (plain `cargo binstall nebaz` once published to crates.io) |
| Manual | download `nebaz-<target>.tar.gz` + `nebaz-<target>.sha256` from the Releases page, `shasum -a 256 -c` the latter, put `nebaz` on `PATH` |
| From source | `cargo install --git https://github.com/neboto/nebaz` |

`install.sh` honours `NEBAZ_VERSION` (pin a tag), `NEBAZ_INSTALL_DIR`
(default `~/.local/bin`), `NEBAZ_NO_ATTEST=1` and `GITHUB_TOKEN`.

## Not done yet (in rough priority order)

- **First tag**: nothing is released; `Cargo.toml` is at `0.0.1`. The first
  release is ticket 09's call (the first-release spec).
- **Homebrew tap** (`brew install neboto/tap/nebaz`): needs a
  `neboto/homebrew-tap` repo and a job that rewrites the formula's URLs +
  SHAs on each release.
- **crates.io publish**: `cargo publish` makes `cargo install nebaz` and
  plain `cargo binstall nebaz` work.
- **macOS signing / notarization**: the binaries are unsigned. Installing
  through the script or `gh` is fine (no quarantine attribute), but a tarball
  downloaded in a browser will trip Gatekeeper; users can
  `xattr -d com.apple.quarantine nebaz`.
- **Windows**: the CLI credential already runs `az.cmd` through `cmd /C`
  (as azure_identity does) and `crossterm` supports it, but `$EDITOR` and
  the browser opener are Unix-shaped. Untested, not in the matrix.
- **musl Linux builds** for old-glibc distros / Alpine — `aws-lc-sys` needs a
  musl C toolchain, so it's a `cross` job like the arm64 one.
- **CHANGELOG.md**: release notes are GitHub's auto-generated PR list today.
