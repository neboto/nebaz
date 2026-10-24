# Scene: private DNS topology. privatelink.blob.core.windows.net holds the
# storage private endpoint's A record but is linked to no VNet, so nothing
# resolves it and the blob endpoint resolves publicly. The Container Apps
# environment's zone is linked to vnet-hub-prod only (not Power Platform's
# failover VNet); Enter follows the link to the VNet, whose Related section
# lists the resolver, ruleset, DNS policy and every zone linked to it.
#
# Rows counted:
#   - Private DNS: 0 privatelink.azurecr.io, 1 privatelink.blob…, 2 database,
#     3 vaultcore, 4 psql-orders-prod…, 5 wonderfulsea-… → j, then jjjj
#   - Zone sections: 2 Records, 3 VNet links
#   - VNet sections: 6 Related

Output demo/scenes/dns.gif

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
Type "./target/release/nebaz --demo --show-keys -s dns"
Enter
Sleep 3s
Show
Sleep 1s

# Z: the zones at full width, record and link counts side by side. The blob
# zone has records and no links.
Type "Z"
Sleep 3.8s
Type "Z"
Sleep 600ms

# The blob zone: the private endpoint's A record...
Type "j"
Sleep 600ms
Enter
Sleep 1s
Type "2"
Sleep 2.8s
# ...and no VNet links: nothing resolves it.
Type "3"
Sleep 3.3s

# The Container Apps environment's zone: linked to vnet-hub-prod only.
Type "h"
Sleep 400ms
Type "jjjj"
Sleep 600ms
Enter
Sleep 1s
Type "3"
Sleep 2.8s

# Follow the link to the VNet: its Related section is its DNS topology.
Type "/vnet-hub"
Sleep 300ms
Enter
Sleep 600ms
Enter
Sleep 1.8s
Type "6"
Sleep 1s
Type "Z"
Sleep 7.5s

# Leave the app before the recording ends so ttyd does not hold the tty.
Hide
Type "q"
Sleep 300ms
