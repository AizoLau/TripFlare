#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate tripflare.ico (32x32 + 16x16, 32bpp BGRA) with pure stdlib.

Design: dark rounded-square background with an orange/yellow flare spark
(vertical + horizontal rays, bright core, two small sparks). No imaging
libraries: the ICO container and the DIB payloads are written byte by byte.
"""
import os
import struct

SIZES = (32, 16)

BG = (34, 40, 54, 255)        # dark slate background (R, G, B, A)
RAY = (255, 150, 40, 255)     # orange flare rays
CORE = (255, 224, 138, 255)   # bright yellow core
SPARK = (255, 190, 80, 255)   # small sparks
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
    cx, cy = int(round(16 * s)), int(round(15 * s))
    # Rays: a 4-point star around the centre, tapering with distance.
    v_len, h_len = int(round(9 * s)), int(round(6 * s))
    for dy in range(-v_len, v_len + 1):
        half = max(0, int(round(1.6 * s)) - abs(dy) // max(1, int(4 * s)))
        for dx in range(-half, half + 1):
            if 0 <= cx + dx < size and 0 <= cy + dy < size:
                px[cy + dy][cx + dx] = RAY
    for dx in range(-h_len, h_len + 1):
        half = max(0, int(round(1.2 * s)) - abs(dx) // max(1, int(4 * s)))
        for dy in range(-half, half + 1):
            if 0 <= cx + dx < size and 0 <= cy + dy < size:
                px[cy + dy][cx + dx] = RAY
    # Bright core circle.
    core_r = max(1.5, 3 * s)
    for y in range(size):
        for x in range(size):
            if (x - cx) ** 2 + (y - cy) ** 2 <= core_r * core_r:
                px[y][x] = CORE
    # Two tiny sparks.
    for sx, sy in ((10, 9), (23, 20)):
        sx, sy = int(round(sx * s)), int(round(sy * s))
        if 0 <= sx < size and 0 <= sy < size:
            px[sy][sx] = SPARK
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
