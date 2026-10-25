# /// script
# dependencies = ["numpy", "pillow"]
# ///
"""The backdrop behind every demo recording: Azure glows over a navy sky,
a glowing horizon and a perspective grid. Generated, so it carries no
licence. demo/render.sh dims it and shows it through the terminal.

    uv run demo/backdrop.py demo/backdrop.png

The size is the tapes' Width × Height (the terminal plus a 48 px margin).
"""
import sys

import numpy as np
from PIL import Image, ImageFilter

W, H = 1296, 796
out = sys.argv[1]
y, x = np.mgrid[0:H, 0:W].astype(np.float32)


def hexc(h):
    return np.array([int(h[i:i + 2], 16) for i in (1, 3, 5)], np.float32) / 255


def glow(cx, cy, r, color, strength):
    d = ((x - cx) ** 2 + (y - cy) ** 2) / (r * r)
    return np.exp(-d)[..., None] * hexc(color) * strength


# Base: deep navy, slightly lighter towards the horizon.
t = (y / H)[..., None]
img = hexc("#030814") * (1 - t) + hexc("#06132b") * t

# Glows: Azure blue top-left, cyan right, a touch of violet top-right.
img += glow(180, 120, 520, "#0078d4", 0.32)
img += glow(1150, 420, 420, "#50e6ff", 0.12)
img += glow(1050, 60, 380, "#5b3fd1", 0.20)

# Perspective grid below the horizon.
hz = H * 0.62
grid = np.zeros((H, W), np.float32)
below = y > hz
depth = (y - hz) / (H - hz)  # 0 at horizon, 1 at bottom
with np.errstate(divide="ignore", invalid="ignore"):
    z = 1.0 / np.maximum(depth, 1e-3)  # distance into the scene
    # horizontal lines, evenly spaced in z
    hl = np.abs(((z * 1.6) % 1.0) - 0.5)
    hline = np.clip(1 - hl / (0.03 * z + 0.02), 0, 1)
    # vertical lines converge on the vanishing point
    u = (x - W / 2) / np.maximum(depth, 1e-3) / 90
    vl = np.abs((u % 1.0) - 0.5)
    vline = np.clip(1 - vl / (0.02 / np.maximum(depth, 0.05) + 0.015), 0, 1)
grid[below] = np.maximum(hline, vline)[below] * np.clip(depth[below] * 1.6, 0, 1) ** 1.8
gimg = Image.fromarray((grid * 255).astype(np.uint8))
soft = np.asarray(gimg.filter(ImageFilter.GaussianBlur(3)), np.float32) / 255
img += grid[..., None] * hexc("#3aa0ff") * 0.55 + soft[..., None] * hexc("#0078d4") * 0.6

# Horizon light.
hzd = np.exp(-((y - hz) ** 2) / (2 * 6 ** 2)) * np.exp(-((x - W / 2) ** 2) / (2 * 420 ** 2))
img += hzd[..., None] * hexc("#7fd8ff") * 0.9
img += glow(W / 2, hz, 300, "#0078d4", 0.25) * np.clip((hz + 70 - y) / 50, 0, 1)[..., None]

# Dot matrix in the sky, fading out towards the horizon.
dots = ((x % 22 < 1.5) & (y % 22 < 1.5) & (y < hz - 20)).astype(np.float32)
img += dots[..., None] * hexc("#8ab8ff") * 0.10 * (1 - y / hz)[..., None]

img = np.clip(img, 0, 1)
Image.fromarray((img * 255).astype(np.uint8)).save(out)
