#!/bin/sh
# Offline smoke run: drives the built binary in a pseudo-terminal with a fake
# `az` on PATH and a dead ARM endpoint, and greps the final screen. No Azure,
# no network. It is a manual check, not a CI gate (needs python3; `pyte`
# makes the screen dump exact, without it the raw stream is stripped).
#
#   scripts/smoke.sh            # builds debug, runs every scenario
#   scripts/smoke.sh -v         # also prints each final screen
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
# it the raw byte stream is stripped of escapes, which is enough to grep.
set -eu
cd "$(dirname "$0")/.."
verbose=0; [ "${1:-}" = "-v" ] && verbose=1

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
cargo build --quiet
bin="$PWD/target/debug/nebaz"
here="$PWD/scripts/smoke"
dead="https://127.0.0.1:9"
fail=0

run() { # name fake-az-dir service keys-json expected...
  name="$1"; fake="$2"; svc="$3"; keys="$4"; shift 4
  spec="$(printf '{"cmd":["%s","-s","%s","--endpoint-url","%s"],"keys":%s,"env":{"PATH":"%s:%s","NEBAZ_CONFIG":"/dev/null","HOME":"%s"}}' \
    "$bin" "$svc" "$dead" "$keys" "$here/fake-az/$fake" "$PATH" "$PWD/target/smoke-home")"
  mkdir -p target/smoke-home
  screen="$(python3 "$here/ptyrun.py" "$spec")"
  [ "$verbose" = 1 ] && { echo "=== $name ==="; echo "$screen"; }
  for want in "$@"; do
    if echo "$screen" | grep -qF -- "$want"; then
      echo "ok   $name: $want"
    else
      echo "FAIL $name: expected \"$want\"" >&2
      [ "$verbose" = 1 ] || echo "$screen" >&2
      fail=1
    fi
  done
}

run logged-in ok sub '[2.0, "j", "C", 1.0]' \
  "Production" "Partner Dev" \
  "Copied az command"

run arm-unreachable ok rg '[8.0]' \
  "cannot reach 127.0.0.1" \
  "Connection refused"

# Focus the pane, flat view, select three lines from the top, copy.
run flat-and-select ok sub '[2.0, "\r", 0.3, "\\", 0.5, "V", "J", "J", "y", 1.0]' \
  "━━ Overview" "━━ Related" \
  "3 lines"

# Ctrl-N moves down in a picker (it used to type `n` into the filter):
# Subscriptions → Virtual Machines → Storage, then Enter.
run picker-ctrl-n ok sub '[2.0, "S", 0.3, "\u000e", "\u000e", 0.3, "\r", 3.0]' \
  "Loading Storage…"

# A seventh tab still fits, and the Foundry list goes to ARM like the rest.
run foundry-tab ok foundry '[8.0]' \
  "Foundry" \
  "cannot reach 127.0.0.1"

# A routing prefix lands on a Network edge sub-tab, which lists through ARM.
run network-edge-lb ok lb '[6.0]' \
  "5 LBs" \
  "cannot reach 127.0.0.1"

run not-logged-in nologin sub '[2.0]' \
  "az login"

[ "$fail" = 0 ] && echo "smoke: all scenarios passed"
exit "$fail"
