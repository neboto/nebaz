#!/bin/sh
# Offline smoke run: drives the built binary in a pseudo-terminal with a fake
# `az` on PATH and a dead ARM endpoint, and polls the screen for the expected
# text. No Azure, no network. It is a manual check, not a CI gate (needs
# python3; `pyte` makes the screen dump exact, without it the raw stream is
# stripped).
#
#   scripts/smoke.sh                    # builds debug, runs every scenario
#   scripts/smoke.sh -v                 # also prints each last screen
#   SMOKE_TIMEOUT=120 scripts/smoke.sh  # seconds per wait (default 60)
#
# No fixed sleeps: a key list waits on text ({"wait": "Partner Dev"}) before
# keys that need a loaded list, and each expected text is polled for until
# it appears or SMOKE_TIMEOUT runs out, when the last screen is printed. A
# passing scenario ends as soon as everything has been seen.
#
# Scenarios:
#   logged-in   fake az with three subscriptions across two tenants →
#               subscription rows render (no ARM call), `C` copies a command
#   arm-unreachable   same, on Resource Groups (an ARM list) with ARM at a
#               closed port → the connection error names the host and the
#               root cause after the short retry policy gives up
#   flat-and-select   focus the pane, `\` for the flat view, `V J J y` →
#               section headers on screen and "Copied 3 lines"
#   not-logged-in   fake az that says "Please run 'az login'" → the single
#               app-wide auth line, no crash
#
# `python3 -m pip install --user pyte` makes the screen dump exact; without
# it the raw byte stream is stripped of escapes and matched ignoring
# whitespace (cursor moves stand in for some spaces), which is enough.
set -eu
cd "$(dirname "$0")/.."
verbose=0; [ "${1:-}" = "-v" ] && verbose=1

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
cargo build --quiet
bin="$PWD/target/debug/nebaz"
here="$PWD/scripts/smoke"
dead="https://127.0.0.1:9"
timeout="${SMOKE_TIMEOUT:-60}"
fail=0
# No network at all: the daily update check (api.github.com, ADR 0008) stays off.
export NEBAZ_NO_UPDATE_CHECK=1

run() { # name fake-az-dir service keys-json expected...
  name="$1"; fake="$2"; svc="$3"; keys="$4"; shift 4
  v=false; [ "$verbose" = 1 ] && v=true
  spec="$(printf '{"name":"%s","cmd":["%s","-s","%s","--endpoint-url","%s"],"keys":%s,"timeout":%s,"verbose":%s,"env":{"PATH":"%s:%s","NEBAZ_CONFIG":"/dev/null","HOME":"%s"}}' \
    "$name" "$bin" "$svc" "$dead" "$keys" "$timeout" "$v" "$here/fake-az/$fake" "$PATH" "$PWD/target/smoke-home")"
  mkdir -p target/smoke-home
  # Polls for every expected text up to $timeout; prints ok / FAIL lines
  # and, on a timeout, the last screen.
  python3 "$here/ptyrun.py" "$spec" "$@" || fail=1
}

run logged-in ok sub '[{"wait": "Partner Dev"}, "j", "C", "\r"]' \
  "Production" "Partner Dev" \
  'Copied `account show`'

run arm-unreachable ok rg '[]' \
  "cannot reach 127.0.0.1" \
  "Connection refused"

# Focus the pane, flat view, select three lines from the top, copy.
run flat-and-select ok sub '[{"wait": "Partner Dev"}, "\r", "\\", "V", "J", "J", "y"]' \
  "━━ Overview" "━━ Access" \
  "3 lines"

# Ctrl-N moves down in a picker (it used to type `n` into the filter).
# The picker lists services by category (`ServiceType::CATEGORIES`), then
# in `ServiceType::all()` order: Subscriptions → Power Platform →
# Governance (all Management) → Virtual Machines → Storage, then Enter. A
# new service in Management or Compute needs one more press here.
run picker-ctrl-n ok sub '[{"wait": "Partner Dev"}, "S", "\u000e", "\u000e", "\u000e", "\u000e", "\r"]' \
  "Loading Storage…"

# A seventh tab still fits, and the Foundry list goes to ARM like the rest.
run foundry-tab ok foundry '[]' \
  "Foundry" \
  "cannot reach 127.0.0.1"

# A routing prefix lands on a Network edge sub-tab, which lists through ARM.
run network-edge-lb ok lb '[]' \
  "5 LBs" \
  "cannot reach 127.0.0.1"

# The Identity tab loads and lists through ARM.
run identity-tab ok id '[]' \
  "Managed identities" \
  "cannot reach 127.0.0.1"

# Private DNS is the DNS tab's first chip (it moved from Network in #37),
# and the zone list goes to ARM on the private DNS api-version.
run private-dns-tab ok pdns '[]' \
  "1 Private DNS" \
  "cannot reach 127.0.0.1"

# The DNS tab's resolver chip has a digit key, and the resolver list goes
# to ARM on the resolver api-version.
run dns-resolver-tab ok dnsr '[]' \
  "3 Resolvers" \
  "cannot reach 127.0.0.1"

# A routing prefix lands on App Service's filtered Functions sub-tab.
run app-service-func ok func '[]' \
  "2 Functions" \
  "cannot reach 127.0.0.1"

# The SQL tab loads and lists servers through ARM.
run sql-tab ok sql '[]' \
  "SQL servers & databases" \
  "cannot reach 127.0.0.1"

# The Container Registry tab loads and lists registries through ARM.
run acr-tab ok acr '[]' \
  "Container registries" \
  "cannot reach 127.0.0.1"

# The Cosmos DB tab loads and lists accounts through ARM.
run cosmos-tab ok cosmos '[]' \
  "Cosmos DB accounts" \
  "cannot reach 127.0.0.1"

# The Redis tab loads through its routing prefix for Managed Redis, with
# the Caches chip on the sub-tab row.
run redis-amr ok amr '[6.0]' \
  "Azure Cache for Redis & Managed Redis" \
  "1 Caches" \
  "cannot reach 127.0.0.1"

# The PostgreSQL & MySQL tab loads through a routing prefix (MySQL).
run mysql-tab ok mysql '[]' \
  "PostgreSQL & MySQL flexible servers" \
  "cannot reach 127.0.0.1"

# The Container Apps tab loads through a routing prefix (environments).
run aca-env ok acaenv '[]' \
  "Container apps, environments & jobs" \
  "cannot reach 127.0.0.1"

# The Messaging tab loads through a routing prefix (Event Hubs).
run messaging-eh ok eh '[6.0]' \
  "Service Bus & Event Hubs namespaces" \
  "cannot reach 127.0.0.1"

# The Edge tab loads through a routing prefix (WAF policies: two lists,
# both failing is the one error).
run edge-waf ok waf '[]' \
  "App gateways, Front Door, WAF & Private Link" \
  "3 WAF policies" \
  "cannot reach 127.0.0.1"

# Private Link services are the Edge tab's fourth chip (#143).
run edge-pls ok pls '[]' \
  "4 Private Link" \
  "cannot reach 127.0.0.1"

# Traffic Manager is the DNS tab's sixth chip, on its own api-version.
run dns-traffic-manager ok tm '[]' \
  "6 Traffic Manager" \
  "cannot reach 127.0.0.1"

# The Firewall tab loads through a routing prefix (Cloud NGFW).
run firewall-ngfw ok ngfw '[]' \
  "Azure Firewall, policies, IP groups & Cloud NGFW" \
  "4 Cloud NGFW" \
  "cannot reach 127.0.0.1"

# VM scale sets load through a routing prefix (the VMs tab's fourth chip).
run vm-scale-sets ok vmss '[]' \
  "Virtual Machines, Disks, NICs & Scale Sets" \
  "4 Scale sets" \
  "cannot reach 127.0.0.1"

# The Backup tab loads through a routing prefix (Backup vaults).
run backup-bvault ok bvault '[]' \
  "Recovery Services & Backup vaults" \
  "2 Backup vaults" \
  "cannot reach 127.0.0.1"

# The Governance tab loads through a routing prefix (Locks).
run governance-locks ok lock '[]' \
  "Policy, locks & management groups" \
  "4 Locks" \
  "cannot reach 127.0.0.1"

# Management groups are read above the subscription; the dead endpoint
# still names the host, so the list call went out.
run governance-mgs ok mg '[]' \
  "5 Management groups" \
  "cannot reach 127.0.0.1"

# Defender reads Microsoft.Security under the subscription; the dead
# endpoint names the host, so the list call went out.
run defender-plans ok pricing '[]' \
  "Recommendations, alerts, score & plans" \
  "4 Plans" \
  "cannot reach 127.0.0.1"

# The Monitor tab loads through a routing prefix (the sub-tab it picks
# is covered by the from_prefix unit tests).
run monitor-appi ok appi '[]' \
  "Log Analytics & App Insights" \
  "cannot reach 127.0.0.1"

# Access on a subscription row fetches role assignments from ARM; the
# Subscriptions list itself makes no ARM call, so the error proves the
# section fired.
run access-section ok sub '[{"wait": "Partner Dev"}, "\r", "4"]' \
  "Access" \
  "cannot reach 127.0.0.1"

# @all lands on the All resources sub-tab, whose list goes to ARM (the
# Subscriptions sub-tab itself makes no ARM call).
run all-resources ok all '[]' \
  "All resources" \
  "cannot reach 127.0.0.1"

# Activity on a subscription row reads the activity log from ARM; like
# Access, the error proves the section fired.
run activity-section ok sub '[{"wait": "Partner Dev"}, "\r", "5"]' \
  "Activity" \
  "cannot reach 127.0.0.1"

# @audit opens with coverage notes and no call; `r` loads its sources in
# the background, and against the dead endpoint they fail as one status
# error while the checks stay "not checked".
run audit ok audit '[{"wait": "not checked"}, "r"]' \
  "Security findings from what's loaded" \
  "not checked" \
  "Audit: some checks couldn't run"

run not-logged-in nologin sub '[]' \
  "az login"

# Headless (#44): no pty. Each run checks the exit code and greps stdout
# plus stderr.
headless() { # name fake-az-dir want-exit expected... -- args...
  name="$1"; fake="$2"; want="$3"; shift 3
  expects=""
  while [ "$1" != "--" ]; do expects="$expects
$1"; shift; done
  shift
  set +e
  out="$(PATH="$here/fake-az/$fake:$PATH" NEBAZ_CONFIG=/dev/null HOME="$PWD/target/smoke-home" \
    "$bin" --endpoint-url "$dead" "$@" 2>&1)"
  code=$?
  set -e
  [ "$verbose" = 1 ] && { echo "=== $name (exit $code) ==="; echo "$out"; }
  if [ "$code" = "$want" ]; then echo "ok   $name: exit $code"; else
    echo "FAIL $name: exit $code, expected $want" >&2; echo "$out" >&2; fail=1; fi
  echo "$expects" | while IFS= read -r e; do
    [ -z "$e" ] && continue
    if echo "$out" | grep -qF -- "$e"; then echo "ok   $name: $e"; else
      echo "FAIL $name: expected \"$e\"" >&2; echo "$out" >&2; exit 1; fi
  done || fail=1
}

headless headless-services ok 0 '"schema": "nebaz/v1"' '"prefix": "vm"' -- services
headless headless-ls-subs ok 0 '"subtab": "subscriptions"' 'Partner Dev' -- ls sub
headless headless-ls-md ok 0 '# Subscriptions · Subscriptions' -- ls sub -o md
headless headless-ls-arm ok 1 'cannot reach 127.0.0.1' -- ls rg
headless headless-ls-fanout ok 1 'Partner Dev: ' 'no subscription could be listed' 'Old Sandbox disabled' \
  -- ls rg --subscriptions 'Production,Partner Dev,Old Sandbox'
headless headless-ls-unconfigured ok 2 'subscriptions = [' -- ls rg --all-configured
headless headless-usage ok 2 'pass --in PREFIX' -- get vm-1
headless headless-unknown ok 2 'unknown service' -- ls nope
headless headless-auth nologin 4 'az login' -- ls vm
# Every audit source fails against the dead endpoint: a stderr warning,
# every check under not_checked, and no finding, so exit 0.
headless headless-audit ok 0 '"not_checked"' "Audit: some checks couldn't run" -- audit
headless headless-audit-fail-on ok 2 'one of critical, high' -- audit --fail-on severe
headless headless-ls-audit ok 2 'run `nebaz audit`' -- ls audit

[ "$fail" = 0 ] && echo "smoke: all scenarios passed"
exit "$fail"
