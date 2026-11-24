#!/usr/bin/env python3
"""Generate app icons with the standard library only (no Pillow).

Writes <crate>/icons/{icon.png, 32x32.png, 128x128.png, icon.ico, icon.icns}. The Nex's mark
(default) is a gyroscope: an ink (#0E0F0E) outer ring, two gimbal rings crossing at +/-35 deg
and a solid hub, on a mint (#7CEB8E) rounded square. Strokes thicken
as the icon shrinks and the outer ring is dropped below 24 px so the 16 px tray size stays
legible. The default run also writes tray-template.png (44x44, black glyph on transparent,
for macOS template images). With --variant aegismesh it writes the AegisMesh shield on a matte
#0A0B0D tile, unchanged. Edges are anti-aliased with exact horizontal coverage per scanline;
each ring/shape is its own even-odd layer and layers are combined by union (max coverage).
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


def gyroscope(size, radius=11.5):
    """Layers (each even-odd, unioned) of the gyroscope on a 32-unit grid, tuned for `size` px."""
    stroke = max(1.9, 1.7 * 32 / size)  # >= 1.7 px at every size
    if size < 24:  # 16/20 px: a single tilted gimbal inside the ring, small hub
        return [ring(radius, radius, stroke), ring(radius, radius * 0.45, stroke, -40), [ellipse(2.4, 2.4)]]
    ratio = 0.4 if size >= 32 else 0.5  # rounder gimbals keep the gaps open at 24 px
    layers = [ring(radius, radius * ratio, stroke, 35), ring(radius, radius * ratio, stroke, -35)]
    layers += [[ellipse(1.6 + stroke * 0.5, 1.6 + stroke * 0.5)], ring(radius, radius, stroke)]
    return layers


def gyroscope_tray():
    stroke, r = 2.6, 11.5  # outer edge 12.8 of 16 units = 80% of the canvas
    return [ring(r, r * 0.4, stroke, 35), ring(r, r * 0.4, stroke, -35), ring(r, r, stroke), [ellipse(3.0, 3.0)]]


SHIELD_LAYERS = [SHIELD]
# name -> (output dir, layers for size, tile colour, glyph colour)
VARIANTS = {
    "thenex": (ROOT / "crates" / "the-nex-gui" / "icons", gyroscope, MINT, INK),
    "aegismesh": (ROOT / "crates" / "aegismesh-gui" / "icons", lambda size: SHIELD_LAYERS, BACKGROUND, FOREGROUND),
}


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


def render(size, layers, tile=BACKGROUND, glyph_color=FOREGROUND, tray=False):
    """Rows of RGBA. tray=True: black glyph on transparent (macOS template), no tile."""
    scale = size / 32.0
    scaled = [[[(x * scale, y * scale) for x, y in shape] for shape in layer] for layer in layers]
    radius = CORNER_RADIUS * size
    weight = 1.0 / VERTICAL_SAMPLES
    rows = []
    for py in range(size):
        background = [0.0] * size
        covers = [[0.0] * size for _ in scaled]
        for j in range(VERTICAL_SAMPLES):
            y = py + (j + 0.5) / VERTICAL_SAMPLES
            accumulate(background, rounded_rect_span(size, radius, y), size, weight)
            for layer, cover in zip(scaled, covers):
                accumulate(cover, polygon_spans(layer, y), size, weight)
        glyph = [max(col) for col in zip(*covers)]  # union of layers
        row = bytearray()
        for px in range(size):
            if tray:
                row += b"\x00\x00\x00" + bytes([round(min(glyph[px], 1.0) * 255)])
                continue
            alpha = min(background[px], 1.0)
            ink = min(glyph[px], alpha)
            if alpha <= 0.0:
                row += b"\x00\x00\x00\x00"
                continue
            mix = ink / alpha
            pixel = [round(b + (f - b) * mix) for b, f in zip(tile, glyph_color)]
            row += bytes(pixel) + bytes([round(alpha * 255)])
        rows.append(bytes(row))
    return rows


def png_bytes(size, layers, tile=BACKGROUND, glyph_color=FOREGROUND, tray=False):
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + row for row in render(size, layers, tile, glyph_color, tray))
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
    types = {128: b"ic07", 256: b"ic08"}
    body = b"".join(types[size] + struct.pack(">I", len(data) + 8) + data for size, data in images)
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
    default_out, layers_for, tile, glyph_color = VARIANTS[args.variant]
    out = args.out or default_out
    out.mkdir(parents=True, exist_ok=True)

    pngs = {size: png_bytes(size, layers_for(size), tile, glyph_color) for size in ICO_SIZES}
    for size, data in pngs.items():
        validate_png(data, size)

    outputs = {
        "icon.png": pngs[256],
        "32x32.png": pngs[32],
        "128x128.png": pngs[128],
        "icon.ico": ico_bytes([(size, pngs[size]) for size in ICO_SIZES]),
        "icon.icns": icns_bytes([(128, pngs[128]), (256, pngs[256])]),
    }
    if args.variant == "thenex":
        # Tray glyph fills ~80% of the canvas, thicker strokes for 22 pt.
        tray = png_bytes(44, gyroscope_tray(), tray=True)
        validate_png(tray, 44)
        outputs["tray-template.png"] = tray
    for name, data in outputs.items():
        target = out / name
        target.write_bytes(data)
        print(f"{target}  {len(data):,} B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
