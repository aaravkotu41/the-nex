#!/usr/bin/env python3
"""Generate app icons with the standard library only (no Pillow).

Writes <crate>/icons/{icon.png, 32x32.png, 128x128.png, icon.ico, icon.icns}. The Nex's mark
(default) is the gyro bot from the in-app assistant (ui/bot.js): a thin white outer ring with
two gimbal rings crossing at +/-35 deg inside it (not touching it) and a mint (#7CEB8E) hub,
on a near-black tile with a slight top-to-bottom gradient. From 64 px up the tile follows the
macOS icon grid (824 of 1024, so it sits level with other apps in the Dock); smaller sizes
keep a thin margin and thicker strokes so 16 px stays legible. The .icns carries every size up
to 1024 px. The default run also writes tray-template.png (44x44, black glyph on transparent,
for macOS template images). With --variant aegismesh it writes the AegisMesh shield on a matte
#0A0B0D tile, unchanged. Edges are anti-aliased with exact horizontal coverage per scanline;
shapes of one colour are unioned (max coverage) and colours are painted in order.
"""

import argparse
import math
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BACKGROUND = (10, 11, 13)
FOREGROUND = (255, 255, 255)
MINT = (124, 235, 142)
INK = (14, 15, 14)
WHITE = (255, 255, 255)
TILE_TOP = (38, 42, 38)  # the bot's ink, lifted a little at the top so the tile has depth
TILE_BOTTOM = (9, 10, 9)
MAC_GRID_INSET = 100 / 1024  # Apple's icon grid: an 824 px body centred in 1024
SMALL_INSET = 0.04
ICNS_TYPES = {16: b"icp4", 32: b"icp5", 64: b"icp6", 128: b"ic07", 256: b"ic08", 512: b"ic09", 1024: b"ic10"}
CORNER_RADIUS = 0.22
VERTICAL_SAMPLES = 4
CURVE_POINTS = 128
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
# Shield outline with a beacon at its centre (even-odd fill: outline minus hole plus core).
SHIELD = [
    [(16, 3.5), (26.5, 7), (26, 16.5), (22.5, 23), (16, 28.5), (9.5, 23), (6, 16.5), (5.5, 7)],
    [(16, 7.4), (22.8, 9.7), (22.4, 16.1), (19.8, 20.9), (16, 24.3), (12.2, 20.9), (9.6, 16.1), (9.2, 9.7)],
    [(16, 11.2), (19.3, 15.4), (16, 19.6), (12.7, 15.4)],
]


def ellipse(rx, ry, angle=0.0, cx=16.0, cy=16.0):
    c, s = math.cos(math.radians(angle)), math.sin(math.radians(angle))
    pts = []
    for i in range(CURVE_POINTS):
        t = 2 * math.pi * i / CURVE_POINTS
        x, y = rx * math.cos(t), ry * math.sin(t)
        pts.append((cx + x * c - y * s, cy + x * s + y * c))
    return pts


def ring(rx, ry, stroke, angle=0.0):
    return [ellipse(rx + stroke / 2, ry + stroke / 2, angle), ellipse(rx - stroke / 2, ry - stroke / 2, angle)]


def thenex_inset(size):
    return MAC_GRID_INSET if size >= 64 else SMALL_INSET


THENEX_GLYPH_SCALE = 0.84  # share of the tile the 32-unit grid spans


def gyro_bot(size):
    """Colour groups [(layers, colour)] of the gyro bot on a 32-unit grid, tuned for `size` px."""
    px = size * (1 - 2 * thenex_inset(size)) * THENEX_GLYPH_SCALE / 32  # pixels per grid unit
    line = max(1.4, 1.35 / px)  # outer ring: fine at large sizes, never under 1.35 px
    thin = max(1.15, 1.2 / px)
    if size < 24:  # 16/20 px: one tilted gimbal inside the ring
        return [([ring(12.6, 12.6, line), ring(9.4, 4.8, thin, -35)], WHITE), ([[ellipse(3.4, 3.4)]], MINT)]
    ry = 4.5 if size >= 48 else 5.2  # rounder gimbals keep the gaps open at 24-40 px
    lines = [ring(13, 13, line), ring(11.0, ry, thin, 35), ring(11.0, ry, thin, -35)]
    return [(lines, WHITE), ([[ellipse(2.7, 2.7)]], MINT)]


def gyroscope_tray():
    stroke = 2.4  # outer edge 13.8 of 16 units; gimbals stop short of the ring, like the bot
    return [ring(12.6, 12.6, stroke), ring(10.2, 4.4, stroke * 0.9, 35), ring(10.2, 4.4, stroke * 0.9, -35), [ellipse(2.9, 2.9)]]


SHIELD_GROUPS = [([SHIELD], FOREGROUND)]
# name -> (output dir, colour groups for size, tile colour or (top, bottom), sizes, tile inset for size)
VARIANTS = {
    "thenex": (
        ROOT / "crates" / "the-nex-gui" / "icons",
        gyro_bot,
        (TILE_TOP, TILE_BOTTOM),
        ICO_SIZES + (512, 1024),
        thenex_inset,
    ),
    "aegismesh": (
        ROOT / "crates" / "aegismesh-gui" / "icons",
        lambda size: SHIELD_GROUPS,
        BACKGROUND,
        ICO_SIZES,
        lambda size: 0.0,
    ),
}
GLYPH_SCALE = {"thenex": THENEX_GLYPH_SCALE, "aegismesh": 1.0}


def polygon_spans(polygons, y):
    """Even-odd interior intervals of the polygons on horizontal line y."""
    xs = []
    for points in polygons:
        count = len(points)
        for i in range(count):
            x1, y1 = points[i]
            x2, y2 = points[(i + 1) % count]
            if (y1 <= y < y2) or (y2 <= y < y1):
                xs.append(x1 + (y - y1) * (x2 - x1) / (y2 - y1))
    xs.sort()
    return [(xs[i], xs[i + 1]) for i in range(0, len(xs) - 1, 2)]


def rounded_rect_span(size, radius, y):
    if y < 0 or y > size:
        return []
    if y < radius:
        dy = radius - y
    elif y > size - radius:
        dy = y - (size - radius)
    else:
        dy = 0.0
    if dy > radius:
        return []
    dx = radius - math.sqrt(max(radius * radius - dy * dy, 0.0))
    return [(dx, size - dx)]


def accumulate(coverage, spans, width, weight):
    for start, end in spans:
        start = max(start, 0.0)
        end = min(end, float(width))
        if end <= start:
            continue
        first = int(math.floor(start))
        last = int(math.ceil(end))
        for px in range(first, last):
            overlap = min(end, px + 1) - max(start, px)
            if overlap > 0:
                coverage[px] += overlap * weight


def render(size, groups, tile=BACKGROUND, tray=False, inset=0.0, glyph_scale=1.0):
    """Rows of RGBA. `groups` is [(layers, colour)], painted in order; `tile` is one colour or a
    (top, bottom) pair; `inset` is the tile's margin as a share of the canvas.
    tray=True: black glyph on transparent (macOS template), no tile."""
    body = size * (1 - 2 * inset)
    origin = size * inset
    scale = body / 32.0 * glyph_scale
    shift = origin + body * (1 - glyph_scale) / 2
    # One even-odd layer per original layer, so overlapping rings of one colour union cleanly.
    scaled = [
        ([[[(x * scale + shift, y * scale + shift) for x, y in shape] for shape in layer] for layer in layers], colour)
        for layers, colour in groups
    ]
    top, bottom = tile if isinstance(tile[0], tuple) else (tile, tile)
    radius = CORNER_RADIUS * body
    weight = 1.0 / VERTICAL_SAMPLES
    rows = []
    for py in range(size):
        background = [0.0] * size
        covers = [[[0.0] * size for _ in layers] for layers, _ in scaled]
        for j in range(VERTICAL_SAMPLES):
            y = py + (j + 0.5) / VERTICAL_SAMPLES
            spans = [(a + origin, b + origin) for a, b in rounded_rect_span(body, radius, y - origin)]
            accumulate(background, spans, size, weight)
            for (layers, _), group_cover in zip(scaled, covers):
                for layer, cover in zip(layers, group_cover):
                    accumulate(cover, polygon_spans(layer, y), size, weight)
        glyphs = [[max(col) for col in zip(*group_cover)] for group_cover in covers]  # union per colour
        blend = min(max((py + 0.5 - origin) / body, 0.0), 1.0)
        base = [t + (b - t) * blend for t, b in zip(top, bottom)]
        row = bytearray()
        for px in range(size):
            if tray:
                row += b"\x00\x00\x00" + bytes([round(min(max(g[px] for g in glyphs), 1.0) * 255)])
                continue
            alpha = min(background[px], 1.0)
            if alpha <= 0.0:
                row += b"\x00\x00\x00\x00"
                continue
            pixel = list(base)
            for glyph, (_, colour) in zip(glyphs, scaled):
                mix = min(glyph[px], alpha) / alpha
                pixel = [p + (c - p) * mix for p, c in zip(pixel, colour)]
            row += bytes(round(p) for p in pixel) + bytes([round(alpha * 255)])
        rows.append(bytes(row))
    return rows


def png_bytes(size, groups, tile=BACKGROUND, tray=False, inset=0.0, glyph_scale=1.0):
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + row for row in render(size, groups, tile, tray, inset, glyph_scale))
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA, as tauri-codegen requires
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def ico_bytes(images):
    directory = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    payload = b""
    for size, data in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        payload += data
        offset += len(data)
    return directory + entries + payload


def icns_bytes(images):
    body = b"".join(ICNS_TYPES[size] + struct.pack(">I", len(data) + 8) + data for size, data in images)
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def validate_png(data, size):
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "bad PNG signature"
    width, height, depth, color = struct.unpack(">IIBB", data[16:26])
    assert (width, height, depth, color) == (size, size, 8, 6), "PNG is not 8-bit RGBA"


def main():
    parser = argparse.ArgumentParser(description="Generate app icons.")
    parser.add_argument("--variant", choices=sorted(VARIANTS), default="thenex")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    default_out, groups_for, tile, sizes, inset_for = VARIANTS[args.variant]
    out = args.out or default_out
    out.mkdir(parents=True, exist_ok=True)

    glyph_scale = GLYPH_SCALE[args.variant]
    pngs = {size: png_bytes(size, groups_for(size), tile, inset=inset_for(size), glyph_scale=glyph_scale) for size in sizes}
    for size, data in pngs.items():
        validate_png(data, size)

    outputs = {
        "icon.png": pngs[max(s for s in sizes if s <= 512)],
        "32x32.png": pngs[32],
        "128x128.png": pngs[128],
        "icon.ico": ico_bytes([(size, pngs[size]) for size in ICO_SIZES]),
        "icon.icns": icns_bytes([(size, pngs[size]) for size in sorted(ICNS_TYPES) if size in pngs]),
    }
    if args.variant == "thenex":
        # Tray glyph fills most of the canvas, thicker strokes for 22 pt.
        tray = png_bytes(44, [(gyroscope_tray(), INK)], tray=True)
        validate_png(tray, 44)
        outputs["tray-template.png"] = tray
    for name, data in outputs.items():
        target = out / name
        target.write_bytes(data)
        print(f"{target}  {len(data):,} B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
