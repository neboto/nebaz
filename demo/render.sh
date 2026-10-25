#!/usr/bin/env bash
# Record the demo tapes and put each over the backdrop.
#
#   demo/render.sh                      # the hero and every scene
#   demo/render.sh demo/scenes/dns.tape # just one
#
# Each tape records to demo/.raw/ with the terminal's background and the
# window margin painted one key colour (#010203). This keys that colour out
# and lays the recording over demo/backdrop.png dimmed to $DIM percent, so
# the backdrop shows through the terminal; everything nebaz draws keeps its
# own colour. demo/x.tape writes demo/x.gif; the hero also writes
# demo/poster.png from its first frame.
#
# Needs vhs, ttyd, ffmpeg and ImageMagick (`magick`), and a release build:
# the tapes run ./target/release/nebaz.
set -euo pipefail
cd "$(dirname "$0")/.."

DIM=35
FPS=12

if [ $# -eq 0 ]; then
  set -- demo/nebaz.tape demo/scenes/*.tape
fi

mkdir -p demo/.raw
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
magick demo/backdrop.png -modulate "$DIM" "$work/bg.png"

for tape in "$@"; do
  raw=$(sed -n 's/^Output "\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$tape")
  out="${tape%.tape}.gif"
  case "$raw" in
    demo/.raw/*.gif) ;;
    *) echo "$tape: Output must be demo/.raw/<name>.gif, got '$raw'" >&2; exit 1 ;;
  esac

  echo "── $tape"
  vhs "$tape"

  # The hero is the README's first download: 64 colours, undithered, keeps
  # it under 3 MB with no visible banding. The scenes keep 256.
  palette="max_colors=256:stats_mode=full[p];[b][p]paletteuse=dither=sierra2_4a"
  if [ "$tape" = demo/nebaz.tape ]; then
    palette="max_colors=64:stats_mode=full[p];[b][p]paletteuse=dither=none:diff_mode=rectangle"
  fi

  # The key as the GIF encoder left it (its palette can shift it a step):
  # the top-left pixel is margin, so it is always the key.
  key=$(magick "${raw}[0]" -format '%[hex:p{0,0}]' info: | cut -c1-6)

  ffmpeg -y -loglevel error -loop 1 -framerate "$FPS" -i "$work/bg.png" -i "$raw" -filter_complex \
    "[1:v]format=rgba,colorkey=0x${key}:similarity=0.015:blend=0[fg];\
[0:v][fg]overlay=shortest=1,format=rgb24,split[a][b];\
[a]palettegen=${palette}" \
    -r "$FPS" "$out"

  if [ "$tape" = demo/nebaz.tape ]; then
    magick "${out}[0]" demo/poster.png
  fi
  echo "   $out $(( $(wc -c < "$out") / 1024 )) KB"
done
