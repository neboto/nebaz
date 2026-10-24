# Scene: the Power Platform outage. Fabrikam's connector, injected into
# snet-pp-injection, stopped reaching the orders API two hours ago.
# @changes finds alex's DenyAllOutbound on nsg-pp-injection; W puts the rule
# next to the alert it set off; N from the subnet shows the deny shadowing
# the default AllowVnetOutBound. The story: docs/DEMO.md, "The story".
#
# Rows counted:
#   - @changes at 6h, newest first: 0 Degraded ca-orders-worker, 1 Create
#     Deployment, 2 Deployment failed, 3 Create or Update Container App,
#     4 Restart Container App Revision, 5 Create or Update Security Rule
#     → jjjjj
#   - NSG sections: 3 Outbound, 4 Used by (one line: the subnet) → 4 ⏎

Output demo/scenes/power-platform-outage.gif

Set Shell "zsh"
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 12
Set Framerate 12
Set TypingSpeed 80ms
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set BorderRadius 8

# demo/nebaz.toml pins theme and banner; --demo pins tenant and data. The
# XDG dirs point nowhere so bookmarks and macros can't leak in either.
Env NEBAZ_CONFIG "demo/nebaz.toml"
Env XDG_CONFIG_HOME "demo/.no-config"
Env XDG_CACHE_HOME "demo/.no-config"
Env EDITOR "true"

# ── Boot off-camera ──────────────────────────────────────────────────────────
Hide
Type "./target/release/nebaz --demo --show-keys -s changes"
Enter
Sleep 3s
Show
Sleep 1.5s

# What changed? The last hour is only the worker's failed rollout; ] widens
# the window to 6h and the security rule appears.
Type "]"
Sleep 2s
Type "jjjjj"
Sleep 1s
Enter
Sleep 3s

# The NSG behind the rule: DenyAllOutbound at 4000, ahead of every default.
# h hands the keys back to the list, where / is the search box.
Type "h"
Sleep 400ms
Type "/@nsg pp-inj"
Sleep 300ms
Enter
Sleep 1.5s
Enter
Sleep 800ms
Type "3"
Sleep 2.5s

# W: the rule change, and the alert that fired a minute later. Z gives the
# timeline the full width; closing it goes back to the split.
Type "W"
Sleep 1.5s
Type "Z"
Sleep 4s
Escape
Sleep 600ms

# Used by: the Power Platform subnet. Enter follows it.
Type "4"
Sleep 1.2s
Enter
Sleep 1.8s

# N: the subnet's effective access. Outbound, 4000 deny shadows everything
# below it, AllowVnetOutBound included. Z again: the full width.
Type "N"
Sleep 1.5s
Type "Z"
Sleep 5.5s

# Leave the app before the recording ends so ttyd does not hold the tty.
Hide
Type "q"
Sleep 300ms
