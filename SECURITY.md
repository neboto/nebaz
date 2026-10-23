# Security policy

nebaz is a read-only Azure browser. The kinds of report we care most about:

- a code path that sends anything but a `GET`, to ARM or Microsoft Graph,
  or an action in `PERMISSIONS.md` that isn't a `*/read`;
- a request to a data-plane host (a vault, a storage account, a database)
  or a credential reaching a log, an export, the clipboard or the `e` view
  (App Insights' instrumentation key and connection string are stripped
  before the row keeps its JSON; a regression there counts);
- nebaz running anything but `az account list` and the credential's
  `az account get-access-token`, or a copied `az` command being run;
- anything in the release pipeline or `install.sh` that could let a
  tampered binary reach users;
- a dependency advisory we haven't picked up (Dependabot watches, but tell
  us).

## Reporting

Use GitHub's private vulnerability reporting:
<https://github.com/neboto/nebaz/security/advisories/new>. If that isn't
available to you, email <stojan@neboto.dev>. Please don't open a public
issue.

You'll get an acknowledgement within a few days. Fixes ship as a patch
release with the advisory published once users have had a chance to update.

## Supported versions

The latest release only. Pre-1.0, every release may change behaviour.

## What we do on our side

- Read-only in three layers (`PERMISSIONS.md`): the one request constructor
  in `src/azure/arm.rs` builds only `GET`s and the pipeline's
  `ReadOnlyPolicy` refuses anything else; `tests/readonly_guard.rs` fails
  CI on another request builder, an HTTP client crate, a data-plane host, a
  mutating `az` verb or a non-read action; and `Reader` is the whole RBAC
  requirement.
- Every request names the app at the front of its `User-Agent`
  (`nebaz azsdk-rust-nebaz/<version>`), so a tenant admin can find nebaz's
  directory reads in the Microsoft Graph activity logs (README, "Why
  read-only").
- Every GitHub Action is pinned to a commit SHA and the repo rejects
  unpinned ones; Dependabot bumps the pins. CodeQL scans the Rust code and
  the workflows on every pull request and weekly.
- Builds run `--locked`; the lockfile is scanned against advisories before a
  release (`docs/RELEASING.md`).
- Release tarballs ship with a `nebaz-<target>.sha256` and a build
  provenance attestation; `install.sh` checks the checksum before
  installing, and the attestation too when `gh` is installed.
