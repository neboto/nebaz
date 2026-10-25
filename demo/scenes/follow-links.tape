# Scene: follow the links. The app gateway's backend pool → the container
# app it matched → its environment → the environment's subnet, then N: what
# can reach that subnet (443 from the Power Platform and app gateway
# subnets). Each hop is / to filter the section to one line, then Enter.
#
# Rows counted: none. The detail filter (/) leaves the one line to follow
# under the cursor, so each hop survives a section's layout changing.
#   - App gateway sections: 5 Backends
#   - Container app sections: 2 Ingress (names the environment)
#   - Environment sections: 2 Network (names the infrastructure subnet)

Output demo/.raw/follow-links.gif

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
# Load Container Apps first: the gateway matches its backends against the
# lists already loaded, then switch to Edge.
Type "./target/release/nebaz --demo --show-keys -s aca"
Enter
Sleep 3s
Type "/@agw"
Enter
Sleep 2.5s
# --show-keys: let the boot's keys fade before the camera rolls.
Sleep 1s
Show
Sleep 1s

# agw-contoso-prod. Backends: pool orders-api, matched to ca-orders-api.
Enter
Sleep 1s
Type "5"
Sleep 2.8s
Type "/ca-orders"
Sleep 300ms
Enter
Sleep 1.2s
Enter
Sleep 2s

# ca-orders-api. Ingress names its environment.
Type "2"
Sleep 2.3s
Type "/cae-"
Sleep 300ms
Enter
Sleep 1s
Enter
Sleep 2s

# cae-orders-prod: internal, static IP 10.10.0.62. Network names the subnet.
Type "2"
Sleep 2.3s
Type "/snet"
Sleep 300ms
Enter
Sleep 1s
Enter
Sleep 2s

# snet-aca. N: who can reach it.
Type "N"
Sleep 1.2s
Type "Z"
Sleep 5s

# Leave the app before the recording ends so ttyd does not hold the tty.
Hide
Type "q"
Sleep 300ms
