---
status: accepted
date: 2026-10-24
---

# The update check is the one non-Azure request, through the same pipeline

Issue #53 asks for neboto's "a newer release is out" chip: once a day, read
the latest GitHub release and show `↑ vX.Y.Z` when it is newer than the
running build. Until now every request nebaz sent went to ARM or Microsoft
Graph (ADR 0004), and `tests/readonly_guard.rs` forbids HTTP client crates
and any request builder outside `src/azure/arm.rs`. neboto sends this
request with `ureq`, a second HTTP stack, which nebaz's guard refuses by
name.

nebaz sends it through what it already has:

- **Transport**: `arm::anonymous_get`, next to the ARM client's GET
  constructor in `src/azure/arm.rs`: an `azure_core` pipeline (reqwest
  underneath, already in `Cargo.lock` through `azure_core`; no new crate)
  carrying `ReadOnlyPolicy` and the same `User-Agent` (`nebaz
  azsdk-rust-nebaz/<version> …`; GitHub refuses a request without one),
  and **no bearer policy**, so no Azure token can reach another host. No
  retries, a 3 s overall timeout, `https` only.
- **One caller, one URL**: `src/update_check.rs` is the only file that may
  name `api.github.com` or call `anonymous_get`, and its one URL is
  `https://api.github.com/repos/neboto/nebaz/releases/latest` (public
  release metadata; `/latest` never returns a draft or a pre-release).
  The guard names this allowance with its reason (`NON_AZURE_HOSTS`),
  checks the callers and the URL, and checks that `anonymous_get` carries
  `ReadOnlyPolicy` and names no credential.
- **Cadence and state**: at most once a day per machine; the answer is
  cached in `$XDG_CACHE_HOME/nebaz/update-check.json` (`~/.cache/…`,
  `$NEBAZ_UPDATE_STATE` overrides), and a fresh answer is shown at once
  from the cache. GitHub's unauthenticated limit (60 an hour per IP) is
  nowhere near.
- **Never in the way**: spawned as a task from the TUI's startup in
  `main` only, after the first load is armed; the result arrives as one
  event (`UpdateAvailable`). The headless subcommands and the tests never
  reach it. Offline, a proxy, a rate limit, an unparsable tag: silent.
  Pre-releases and a local build ahead of the release never announce.
- **Opt-out**: config `update_check = false`, `--no-update-check`,
  `NEBAZ_NO_UPDATE_CHECK=1`; never with `CI` set. `scripts/smoke.sh` sets
  the variable, so the offline smoke run stays offline.

## Considered options

- **Port neboto's `ureq` call** — rejected: a second HTTP stack is what the
  guard's crate list exists to keep out, and it would sit outside
  `ReadOnlyPolicy`.
- **A third `ArmClient` flavour** (as Graph is, ADR 0004) — rejected: the
  flavours share a bearer policy by construction, and this request must
  carry no token. A free function beside the constructor keeps the one
  request-building file and makes "no credential" checkable in a few lines.
- **Shell out to `gh release view`** — rejected: nebaz runs `az` only for
  the account list and tokens (ADR 0003), `gh` is not installed for most
  users, and it would send the user's GitHub token.
- **No update check** — the issue's alternative. The chip is the cheapest
  way to get fixes to people who installed from the release tarballs; an
  opt-out that is documented beside the read-only promise keeps the trust
  story honest.

## Consequences

- "Every request nebaz sends goes to Azure" becomes "every request is a
  `GET`; all but one go to Azure". README and `PERMISSIONS.md` name the
  exception as the only non-Azure request, with how to turn it off.
- A machine that may not talk to GitHub (an air-gapped jump box) sets
  `update_check = false` or the variable; a failing request there costs
  one silent 3 s task a day.
- Not ported from neboto (yet): clicking the chip to copy the upgrade
  command and dismiss that version. nebaz's mouse only replays keys, and
  there is no key for it; the splash names the upgrade command instead.

## Amendment (2026-10-30): `nebaz doctor` makes it on request

Behind a proxy or a TLS-inspecting middlebox (Zscaler) the silent check
leaves nothing to go on. `nebaz doctor` (`src/headless/doctor.rs`) calls
`update_check::fetch_latest` once and prints its error in full, beside the
proxy and certificate settings, the `az` login, and one ARM and one Graph
read. It is the one headless path that reaches the check; it honours every
opt-out (a turned-off check reads `skip`, with the reason), and `--demo`
turns it off as in the TUI. `anonymous_get` still has one caller,
`src/update_check.rs`.
