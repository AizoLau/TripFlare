#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate TripFlare brand tripflare.ico (256..16 px, 32bpp RGBA) with pure stdlib.

Direction A design ("Laser Tripwire + Signal Flare"):
- Deep midnight squircle badge (#0B1120 -> #172033) with a subtle slate rim (#334155).
- Taut cyan-to-orange diagonal laser tripwire anchored across the perimeter.
- Vibrant orange-white 4-point signal flare starburst + halo at trigger node (0.582, 0.461).
- Encodes 256x256 as PNG-compressed RGBA (per Windows ICO spec) and
  128, 64, 48, 32, 24, 16 as 32bpp BGRA DIBs with proper 1-bit AND masks.
"""
import math
import os
import struct
import zlib

SIZES = (256, 128, 64, 48, 32, 24, 16)

TX, TY = 0.582, 0.461
AX, AY = 0.188, 0.672
BX, BY = 0.816, 0.336


def _clamp01(v):
    return 0.0 if v < 0.0 else (1.0 if v > 1.0 else v)


def _lerp(a, b, t):
    return a + (b - a) * t


def _mix_rgb(c1, c2, t):
    t = _clamp01(t)
    return (_lerp(c1[0], c2[0], t),
            _lerp(c1[1], c2[1], t),
            _lerp(c1[2], c2[2], t))


def _over(dst_rgba, src_rgb, alpha):
    a = _clamp01(alpha)
    if a <= 0.0:
        return dst_rgba
    dr, dg, db, da = dst_rgba
    sr, sg, sb = src_rgb
    nr = sr * a + dr * (1.0 - a)
    ng = sg * a + dg * (1.0 - a)
    nb = sb * a + db * (1.0 - a)
    na = a + da * (1.0 - a)
    return (nr, ng, nb, na)


def _sd_rounded_box(px, py, cx, cy, hw, hh, r):
    dx = abs(px - cx) - hw + r
    dy = abs(py - cy) - hh + r
    out = math.hypot(max(dx, 0.0), max(dy, 0.0))
    inside = min(max(dx, dy), 0.0)
    return out + inside - r


def _seg_dist_and_t(px, py, x1, y1, x2, y2):
    vx, vy = x2 - x1, y2 - y1
    wx, wy = px - x1, py - y1
    c2 = vx * vx + vy * vy
    t = _clamp01((wx * vx + wy * vy) / c2) if c2 > 0.0 else 0.0
    qx = x1 + t * vx
    qy = y1 + t * vy
    return math.hypot(px - qx, py - qy), t


def _star4_val(dx, dy, radius, waist):
    """Concave 4-point starburst implicit metric <= 1.0 inside star."""
    ax, ay = abs(dx), abs(dy)
    if ax > radius or ay > radius:
        return 2.0
    # Normalized concave star equation: (ax/R)^p + (ay/R)^p with pinch toward axes
    u = ax / radius
    v = ay / radius
    # Concave curve controlled by waist ratio w = waist / radius
    w = waist / radius
    if u + v <= 0.0:
        return 0.0
    # Radial profile interpolating diamond waist smoothly
    diag = (u * v) / max(w * w, 1e-6)
    return u + v + 0.55 * diag - 0.55 * (u * u * v * v)


def _sample_pixel(u, v, size):
    """Evaluate normalized point (u, v) in [0, 1]^2 at icon resolution `size`."""
    small = size <= 24
    margin = 0.025 if small else 0.047
    half = 0.5 - margin
    radius = 0.21 if not small else 0.23
    aa = 1.15 / size

    sd_outer = _sd_rounded_box(u, v, 0.5, 0.5, half, half, radius)
    cov = _clamp01(0.5 - sd_outer / aa)
    if cov <= 0.0:
        return (0.0, 0.0, 0.0, 0.0)

    # Diagonal background gradient #0B1120 -> #172033
    bg_t = _clamp01(0.5 * u + 0.5 * v)
    bg = _mix_rgb((11.0, 17.0, 32.0), (23.0, 32.0, 51.0), bg_t)
    rgba = (bg[0], bg[1], bg[2], 1.0)

    # Outer rim border for light/dark theme contrast
    rim_w = 0.028 if small else 0.015
    if -rim_w - aa < sd_outer <= 0.0:
        rim_alpha = _clamp01((sd_outer + rim_w) / aa)
        rim_rgb = _mix_rgb((71.0, 85.0, 105.0), (30.0, 41.0, 59.0), bg_t)
        rgba = _over(rgba, rim_rgb, rim_alpha * 0.95)

    # Subtle inner security frame & shockwave ring on >= 48px icons
    if size >= 48:
        sd_inner = _sd_rounded_box(u, v, 0.5, 0.5, 0.35, 0.35, 0.08)
        frame_hw = 0.0035 if size >= 128 else 0.006
        frame_a = _clamp01(1.0 - abs(sd_inner) / (frame_hw + aa))
        rgba = _over(rgba, (45, 62, 90), frame_a * 0.65)

        dist_t = math.hypot(u - TX, v - TY)
        ring_hw = 0.0028 if size >= 128 else 0.0045
        ring_a = _clamp01(1.0 - abs(dist_t - 0.16) / (ring_hw + aa))
        ang = math.atan2(v - TY, u - TX)
        if math.sin(ang * 8.0) > -0.25:
            rgba = _over(rgba, (251.0, 146.0, 60.0), ring_a * 0.45)

    # Soft flare radial halo around trigger point
    dist_t = math.hypot(u - TX, v - TY)
    halo_r = 0.34 if small else 0.28
    if dist_t < halo_r:
        ht = 1.0 - dist_t / halo_r
        halo_rgb = _mix_rgb((239.0, 68.0, 68.0), (255.0, 224.0, 178.0), ht * ht)
        rgba = _over(rgba, halo_rgb, (ht ** 1.7) * (0.72 if small else 0.62))

    # Taut diagonal laser tripwire (cyan -> orange -> crimson)
    line_r = 0.040 if small else (0.025 if size <= 32 else 0.015)
    d_wire, t_wire = _seg_dist_and_t(u, v, AX, AY, BX, BY)
    # Soft wire glow
    glow_r = line_r * 2.8
    if d_wire < glow_r:
        gt = (1.0 - d_wire / glow_r) ** 2
        glow_c = ((56.0, 189.0, 248.0) if t_wire < 0.62
                  else (249.0, 115.0, 22.0))
        rgba = _over(rgba, glow_c, gt * 0.35)
    if d_wire < line_r + aa:
        wire_a = _clamp01((line_r - d_wire) / aa + 0.5)
        if t_wire <= 0.62:
            wire_rgb = _mix_rgb((56.0, 189.0, 248.0), (251.0, 146.0, 60.0),
                                t_wire / 0.62)
        else:
            wire_rgb = _mix_rgb((253.0, 186.0, 116.0), (239.0, 68.0, 68.0),
                                (t_wire - 0.62) / 0.38)
        rgba = _over(rgba, wire_rgb, wire_a)

    # Perimeter anchor dots
    node_r = 0.050 if small else 0.028
    da = math.hypot(u - AX, v - AY)
    if da < node_r + aa:
        na = _clamp01((node_r - da) / aa + 0.5)
        rgba = _over(rgba, (56.0, 189.0, 248.0), na)
        if da < node_r * 0.45:
            rgba = _over(rgba, (224.0, 242.0, 254.0), na)
    db = math.hypot(u - BX, v - BY)
    if db < node_r + aa:
        nb = _clamp01((node_r - db) / aa + 0.5)
        rgba = _over(rgba, (239.0, 68.0, 68.0), nb)
        if db < node_r * 0.45:
            rgba = _over(rgba, (254.0, 226.0, 226.0), nb)

    # Secondary 45-degree red-orange spikes behind main starburst
    dx = u - TX
    dy = v - TY
    rx = 0.70710678 * (dx - dy)
    ry = 0.70710678 * (dx + dy)
    diag_r = 0.14 if small else 0.12
    diag_val = _star4_val(rx, ry, diag_r, diag_r * 0.24)
    if diag_val < 1.15:
        d_a = _clamp01((1.0 - diag_val) / (aa * 8.0) + 0.5)
        rgba = _over(rgba, (239.0, 68.0, 68.0), d_a * 0.75)

    # Primary 4-point concave orange-to-white flare starburst
    star_r = 0.31 if small else 0.265
    star_w = 0.070 if small else 0.048
    sv = _star4_val(dx, dy, star_r, star_w)
    if sv < 1.18:
        sa = _clamp01((1.0 - sv) / (aa * 5.0) + 0.5)
        kt = _clamp01(dist_t / star_r)
        sc = _mix_rgb((255.0, 250.0, 240.0), (249.0, 115.0, 22.0), kt ** 0.7)
        rgba = _over(rgba, sc, sa)

    # Incandescent white-hot inner flare core
    core_r = 0.12 if small else 0.095
    cv = _star4_val(dx, dy, core_r, core_r * 0.32)
    if cv < 1.15:
        ca = _clamp01((1.0 - cv) / (aa * 10.0) + 0.5)
        rgba = _over(rgba, (255.0, 247.0, 237.0), ca)
    center_r = 0.042 if small else 0.028
    if dist_t < center_r + aa:
        ca2 = _clamp01((center_r - dist_t) / aa + 0.5)
        rgba = _over(rgba, (255.0, 255.0, 255.0), ca2)

    return (rgba[0], rgba[1], rgba[2], cov)


def render_rgba(size):
    """Render size x size premultiplied/straight RGBA byte matrix."""
    ss = 4 if size <= 64 else 2
    inv_ss2 = 1.0 / (ss * ss)
    rows = []
    for y in range(size):
        row = []
        for x in range(size):
            ar = ag = ab = aa = 0.0
            for sy in range(ss):
                v = (y + (sy + 0.5) / ss) / size
                for sx in range(ss):
                    u = (x + (sx + 0.5) / ss) / size
                    pr, pg, pb, pa = _sample_pixel(u, v, size)
                    ar += pr * pa
                    ag += pg * pa
                    ab += pb * pa
                    aa += pa
            aa *= inv_ss2
            if aa > 1e-4:
                r = int(round(_clamp01((ar * inv_ss2 / aa) / 255.0) * 255))
                g = int(round(_clamp01((ag * inv_ss2 / aa) / 255.0) * 255))
                b = int(round(_clamp01((ab * inv_ss2 / aa) / 255.0) * 255))
                a = int(round(_clamp01(aa) * 255))
            else:
                r = g = b = a = 0
            row.append((r, g, b, a))
        rows.append(row)
    return rows


def _png_chunk(tag, payload):
    crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)


def encode_png(size, rows):
    """Encode size x size RGBA matrix into PNG bytes using pure stdlib."""
    raw = bytearray()
    for row in rows:
        raw.append(0)  # filter type 0 (None)
        for r, g, b, a in row:
            raw.extend((r, g, b, a))
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 9)
    return (b"\x89PNG\r\n\x1a\n"
            + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", idat)
            + _png_chunk(b"IEND", b""))


def encode_dib(size, rows):
    """Encode size x size RGBA matrix into 32bpp BGRA BITMAPINFOHEADER + 1-bit AND mask."""
    mask_stride = ((size + 31) // 32) * 4
    image_size = size * size * 4 + mask_stride * size
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                         image_size, 0, 0, 0, 0)
    xor_buf = bytearray()
    and_buf = bytearray()
    for row in reversed(rows):
        mask_row = bytearray(mask_stride)
        for x, (r, g, b, a) in enumerate(row):
            xor_buf.extend((b, g, r, a))
            if a == 0:
                mask_row[x >> 3] |= (0x80 >> (x & 7))
        and_buf.extend(mask_row)
    return header + bytes(xor_buf) + bytes(and_buf)


def build_ico(path):
    entries = []
    blobs = []
    for size in SIZES:
        rows = render_rgba(size)
        data = encode_png(size, rows) if size >= 256 else encode_dib(size, rows)
        entries.append((size, data))
        blobs.append(data)

    header = struct.pack("<HHH", 0, 1, len(entries))
    dir_bytes = bytearray()
    offset = 6 + 16 * len(entries)
    for size, data in entries:
        w_byte = 0 if size >= 256 else size
        h_byte = 0 if size >= 256 else size
        dir_bytes += struct.pack("<BBBBHHII", w_byte, h_byte, 0, 0, 1, 32,
                                 len(data), offset)
        offset += len(data)
    with open(path, "wb") as fh:
        fh.write(header)
        fh.write(dir_bytes)
        for data in blobs:
            fh.write(data)
    return path


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = build_ico(os.path.join(root, "tripflare.ico"))
    print("wrote %s (%d bytes, %d sizes: %s)" % (
        out, os.path.getsize(out), len(SIZES), ",".join(str(s) for s in SIZES)))
