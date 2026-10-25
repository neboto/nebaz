# Scene: identities. App registrations and service principals come from
# Microsoft Graph (directory reads only). orders-api-client has one secret
# that expired last month and one that expires in 6 days; the deploy
# pipeline's service principal holds Contributor and User Access
# Administrator on the subscription, and the subscription's Access section
# shows it next to everyone else who can change it.
#
# Rows counted:
#   - App registrations: 0 github-actions-deploy, 1 orders-api-client → j ⏎
#   - Service principal sections: 6 Azure roles, first line Contributor ·
#     subscription → 6 ⏎ jumps to the subscription
#   - Subscription sections: 4 Access

Output demo/.raw/identities.gif

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
Type "./target/release/nebaz --demo --show-keys -s appreg"
Enter
Sleep 3s
Show
Sleep 1.5s

# orders-api-client is red on the list: a credential problem.
Type "j"
Sleep 800ms
Enter
Sleep 1.5s
Type "2"
Sleep 4.3s

# The service principals tab: managed identities and this tenant's apps.
Type "h"
Sleep 400ms
Type "H"
Sleep 2.3s
Type "/github"
Sleep 300ms
Enter
Sleep 800ms
Enter
Sleep 1.2s

# Azure roles: what the deploy pipeline can do, at subscription scope.
Type "6"
Sleep 3.8s

# Enter follows the scope to the subscription; its Access section lists
# every assignment there, principals named through Graph.
Enter
Sleep 1.8s
Type "4"
Sleep 5.5s

# Leave the app before the recording ends so ttyd does not hold the tty.
Hide
Type "q"
Sleep 300ms
