# nebaz hero — VHS tape (https://github.com/charmbracelet/vhs)
#
# The loop at the top of README.md: the Power Platform outage from
# docs/DEMO.md, from "the orders API went quiet" to "here's the rule that
# did it" in about 40s, then @audit for everything else that's wrong.
# ca-orders-worker's failed rollout is the red herring; @changes finds alex's
# DenyAllOutbound on nsg-pp-injection; W puts it next to the alert; Enter
# follows the NSG to its subnet; N shows the deny shadowing
# AllowVnetOutBound; @audit loads its sources and lists the findings.
#
# Run from the repo root:
#   cargo build --release             # the tape runs ./target/release/nebaz
#   brew install ttyd ffmpeg          # vhs drives ttyd; ffmpeg encodes
#   go install github.com/charmbracelet/vhs@latest   # v0.11.0 and v0.12.1 work
#     (v0.12.0 prints "Creating …" and writes nothing — charmbracelet/vhs#787)
#   vhs demo/nebaz.tape               # writes demo/nebaz.gif + demo/poster.png
#   # then squeeze the hero under 3 MB (64 colours is lossless for this palette):
#   ffmpeg -i demo/nebaz.gif -vf "split[a][b];[a]palettegen=max_colors=64:stats_mode=full[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" /tmp/n.gif && mv /tmp/n.gif demo/nebaz.gif
#
# Keys: `--show-keys` puts each key, and what it did, in a corner box — the
# clip is silent, so that box is how a viewer knows one key did each step.
#
# Data: `nebaz --demo`, the made-up contoso-prod tenant in src/demo/ — no
# Azure, no `az`, the same data every take, timestamps relative to now.
# The shorter clips for single workflows live in demo/scenes/.
#
# Cursor arithmetic:
#   - Container Apps: ca-orders-api, ca-orders-worker → j; 5 Revisions
#   - @changes at 6h, newest first: the security rule is row 5 → jjjjj
#   - NSG sections: 3 Outbound, 4 Used by (one line: the subnet)
#   - Enter moves the keys to the detail pane, where / filters the section;
#     h hands them back to the list before each @service search.
#
# Sizing: 1200×700 px at 14px — the split pane needs ≥ 110 cols to render list
# + detail side by side without truncating the section bar. A Nerd Font is
# required for the ⛓ ⇄ glyphs.

Output demo/nebaz.gif

Set Shell "zsh"
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 12
Set Framerate 12
Set TypingSpeed 70ms
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set BorderRadius 8

# demo/nebaz.toml pins theme and banner so the machine's real config can't
# leak into a take; --demo pins tenant, subscription and data. The XDG dirs
# point nowhere so bookmarks and macros can't leak in either. Nothing here
# presses `e`, but EDITOR is harmless in case a take ever does.
Env NEBAZ_CONFIG "demo/nebaz.toml"
Env XDG_CONFIG_HOME "demo/.no-config"
Env XDG_CACHE_HOME "demo/.no-config"
Env EDITOR "true"

# ── Boot off-camera ───────────────────────────────────────────────────────────
Hide
Type "./target/release/nebaz --demo --show-keys -s aca"
Enter
Sleep 3s
Show

# The first frame doubles as a poster.
Screenshot demo/poster.png
Sleep 1s

# ── 1. The red herring: ca-orders-worker's rollout failed ─────────────────────
Type "j"
Sleep 600ms
Enter
Sleep 800ms
Type "5"
Sleep 2.5s

# ── 2. What changed? alex added a security rule 2h ago ───────────────────────
Type "h"
Sleep 300ms
Type "/@changes"
Enter
Sleep 1.2s
Type "]"
Sleep 1.2s
Type "jjjjj"
Sleep 500ms
Enter
Sleep 2.7s

# ── 3. The rule: DenyAllOutbound at 4000; W shows the alert it set off ────────
Type "h"
Sleep 300ms
Type "/@nsg pp-inj"
Enter
Sleep 1.2s
Enter
Sleep 500ms
Type "3"
Sleep 2.2s
Type "W"
Sleep 1s
Type "Z"
Sleep 2.8s
Escape
Sleep 500ms

# ── 4. Follow it to the subnet; N: the deny shadows AllowVnetOutBound ─────────
Type "4"
Sleep 800ms
Enter
Sleep 1.5s
Type "N"
Sleep 800ms
Type "Z"
Sleep 3.7s
Escape
Sleep 500ms

# ── 5. @audit: everything else that's wrong, worst first ──────────────────────
Type "h"
Sleep 300ms
Type "/@audit"
Enter
Sleep 800ms
Type "r"
Sleep 1.5s
Type "Z"
Sleep 3.8s

# Leave the app before the recording ends so ttyd doesn't hold the tty.
Hide
Type "q"
Sleep 300ms
