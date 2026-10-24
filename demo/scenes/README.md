# Showcase scenes

One short clip per story, recorded against `nebaz --demo`: no Azure, no
`az`, and the same data every take. Everything on screen is the made-up
Contoso tenant from `src/demo/`, described in
[`docs/DEMO.md`](../../docs/DEMO.md) (the story, the planted findings, the
ids).

The outage is also the hero loop, `demo/nebaz.tape`, which writes
`demo/nebaz.gif` and the poster frame `demo/poster.png`.

| Scene | Shows |
|---|---|
| `power-platform-outage.tape` | `@changes` finds alex's `DenyAllOutbound` on `nsg-pp-injection`; `W` puts it next to the alert; Enter follows the NSG to `snet-pp-injection`; `N` shows the deny shadowing `AllowVnetOutBound` |
| `audit.tape` | `@audit`: `r` loads the sources, the findings land worst first; Enter opens `nsg-jump-prod` and `W` shows the Fabrikam guest added the SSH rule |
| `identities.tape` | App registrations and service principals from Graph: `orders-api-client`'s expired and expiring secrets, `github-actions-deploy`'s Azure roles, then the subscription's Access section |
| `dns.tape` | Private DNS: `privatelink.blob.core.windows.net` has the PE's record and no VNet link; the Container Apps zone links to `vnet-hub-prod` only, whose Related section is its DNS topology |
| `follow-links.tape` | Enter follows links: app gateway → container app → environment → subnet, then `N` on the subnet |

## Re-recording

From the repo root, with `vhs` (v0.11.0 or v0.12.1; v0.12.0 writes
nothing, charmbracelet/vhs#787), `ttyd`, `ffmpeg` and a Nerd Font
(JetBrainsMono Nerd Font):

```bash
cargo build --release                             # the tapes run ./target/release/nebaz
vhs demo/nebaz.tape                               # the hero
for t in demo/scenes/*.tape; do vhs "$t"; done   # writes demo/scenes/<name>.gif
```

The hero comes out near 4 MB; one ffmpeg pass (the command is in
`demo/nebaz.tape`'s header) re-palettes it to 64 colours and under 3 MB
with no visible change. The scenes are 2 MB or less as recorded.

To record a binary somewhere else (an installed release, say), change the
`Type "./target/release/nebaz …"` line in the tape's hidden boot.

Every tape:

- runs with `--show-keys`, so a corner box names each key and what it did;
- pins its config with `NEBAZ_CONFIG=demo/nebaz.toml` (theme, no banner,
  no update check) and points `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` at a
  directory that doesn't exist, so the recording machine's config,
  bookmarks and macros never leak into a take;
- sets `EDITOR=true` and never presses `e`;
- boots off-camera (`Hide` / `Show`) and quits off-camera, so ttyd doesn't
  hold the tty.

Timestamps in the demo are relative to now, so a take never looks stale.

## Things that trip a take

- `/` means two things. In the list pane it is the search box (and
  `@service` switches service); in the detail pane it filters the section.
  Enter on a row moves the keys to the detail pane, so the tapes press `h`
  before each `/@service`. A jump clears the list search; nothing else
  does, so a second `/` appends to what is there.
- Closing `W` or `N` puts the layout back to the split; `Z` inside them
  widens only while they are open.
- Cursor arithmetic: each tape's header lists the rows it counts. The
  detail cursor is a plain row index (blank rows count) and resets to row 0
  on a section switch. Where a hop would need counting, the tapes filter
  the section to one line with `/` instead (`follow-links.tape`).
- To check a take frame by frame, add `Screenshot shots/x.png` lines (a
  relative path not starting with a digit), run the tape, and look at the
  PNGs. VHS writes a screenshot a beat late, so leave a `Sleep` after it
  before the next key.
