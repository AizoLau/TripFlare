#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate tripflare.ico (32x32 + 16x16, 32bpp BGRA) with pure stdlib.

Design: flat, geometric, tool-like - dark blue-gray (#1F2937) rounded
square with a plain near-white letter "T" (TripFlare wordmark) and one
small orange accent dot. No gradients, no starbursts, no sparks: it must
stay recognizable at 16x16.
"""
import os
import struct

SIZES = (32, 16)

BG = (31, 41, 55, 255)        # #1F2937 dark blue-gray background (RGBA)
LETTER = (242, 244, 248, 255)  # near-white letter T
DOT = (255, 150, 40, 255)      # single orange accent dot
TRANSPARENT = (0, 0, 0, 0)


def inside_rounded_rect(x, y, w, h, r):
    """True when (x, y) is inside a rounded rect covering [0,w) x [0,h)."""
    if not (0 <= x < w and 0 <= y < h):
        return False
    cx = min(max(x, r), w - r - 1)
    cy = min(max(y, r), h - r - 1)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def paint(size):
    """Return top-down RGBA pixel rows for one icon size."""
    px = [[TRANSPARENT] * size for _ in range(size)]
    s = size / 32.0
    radius = max(2, int(round(6 * s)))
    for y in range(size):
        for x in range(size):
            if inside_rounded_rect(x, y, size, size, radius):
                px[y][x] = BG
    # Letter T: horizontal bar on top, vertical stem below, both 2-4 px.
    th = max(2, int(round(4 * s)))
    top = int(round(9 * s))
    x0, x1 = int(round(9 * s)), int(round(23 * s))
    for y in range(top, top + th):
        for x in range(x0, x1):
            px[y][x] = LETTER
    cx = int(round(16 * s))
    for y in range(top, int(round(24 * s))):
        for x in range(cx - th // 2, cx - th // 2 + th):
            px[y][x] = LETTER
    # One small orange accent dot, bottom-right of the T.
    dx, dy = int(round(24 * s)), int(round(24 * s))
    dot_r = max(1.5, 2 * s)
    for y in range(size):
        for x in range(size):
            if (x - dx) ** 2 + (y - dy) ** 2 <= dot_r * dot_r:
                px[y][x] = DOT
    return px


def dib_bytes(size):
    """BITMAPINFOHEADER + bottom-up BGRA pixels + zero AND mask."""
    pixels = paint(size)
    mask_row = ((size + 31) // 32) * 4
    image_size = size * size * 4 + mask_row * size
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                         image_size, 0, 0, 0, 0)
    body = bytearray()
    for row in reversed(pixels):  # DIB is bottom-up
        for (r, g, b, a) in row:
            body += bytes((b, g, r, a))  # stored as BGRA
    body += b"\x00" * (mask_row * size)  # AND mask: opaque, alpha rules
    return header + bytes(body)


def build_ico(path):
    images = [dib_bytes(size) for size in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    entries = bytearray()
    offset = 6 + 16 * len(images)
    for size, data in zip(SIZES, images):
        entries += struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32,
                               len(data), offset)
        offset += len(data)
    with open(path, "wb") as fh:
        fh.write(header)
        fh.write(entries)
        for data in images:
            fh.write(data)
    return path


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = build_ico(os.path.join(root, "tripflare.ico"))
    print("wrote %s (%d bytes)" % (out, os.path.getsize(out)))
