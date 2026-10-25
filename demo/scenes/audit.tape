# Scene: @audit. r loads every list the checks read (in the demo, offline)
# and the findings land worst first; Enter on one opens the resource it is
# about. The top finding is nsg-jump-prod's SSH-from-anywhere rule, and W
# on the NSG says who added it: the Fabrikam guest, three days ago.
#
# Rows counted:
#   - Findings, worst first: 0 nsg-jump-prod (critical) → ⏎ jumps to it
#   - NSG sections: 2 Inbound (AllowSSHInbound 100 is the first line)

Output demo/.raw/audit.gif

Set Shell "zsh"
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 14
Set Width 1296
Set Height 796
Set Padding 12
Set Framerate 12
Set TypingSpeed 80ms
# Dracula with the background as a key colour: demo/render.sh swaps
# it (and the margin) for the backdrop.
Set Theme { "name": "DraculaKeyed", "black": "#21222c", "red": "#ff5555", "green": "#50fa7b", "yellow": "#f1fa8c", "blue": "#bd93f9", "magenta": "#ff79c6", "cyan": "#8be9fd", "white": "#f8f8f2", "brightBlack": "#6272a4", "brightRed": "#ff6e6e", "brightGreen": "#69ff94", "brightYellow": "#ffffa5", "brightBlue": "#d6acff", "brightMagenta": "#ff92df", "brightCyan": "#a4ffff", "brightWhite": "#ffffff", "background": "#010203", "foreground": "#f8f8f2", "selection": "#44475a", "cursor": "#f8f8f2" }
Set WindowBar Colorful
Set BorderRadius 10
Set Margin 48
Set MarginFill "#010203"

# demo/nebaz.toml pins theme and banner; --demo pins tenant and data. The
# XDG dirs point nowhere so bookmarks and macros can't leak in either.
Env NEBAZ_CONFIG "demo/nebaz.toml"
Env XDG_CONFIG_HOME "demo/.no-config"
Env XDG_CACHE_HOME "demo/.no-config"
Env EDITOR "true"

# ── Boot off-camera ──────────────────────────────────────────────────────────
Hide
Type "./target/release/nebaz --demo --show-keys -s audit"
Enter
Sleep 3s
Show
# Before r: every check says what it would need loaded.
Sleep 2s

# r loads the sources; the findings arrive as each list lands.
Type "r"
Sleep 3s
# Z: the findings at full width, with their severities.
Type "Z"
Sleep 4.3s
Type "Z"
Sleep 1s

# l reads the top finding: evidence, why it matters, the fix.
Type "l"
Sleep 3.8s
Type "h"
Sleep 600ms

# Enter opens the NSG itself; 2 Inbound shows the rule.
Enter
Sleep 1.5s
Type "2"
Sleep 2.8s

# W: who added it, and when.
Type "W"
Sleep 1.2s
Type "Z"
Sleep 5s

# Leave the app before the recording ends so ttyd does not hold the tty.
Hide
Type "q"
Sleep 300ms
