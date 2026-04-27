#!/usr/bin/env python3
"""visualize_shadow_v2 — render a v2 shadow's per-slot sprites + T10 grid.

The v2 visual pipeline:

  1. Per-slot ECIES-decrypt c2 into a 39-Field plaintext (or load it
     directly from a solve fixture's `plaintexts.json`).
  2. Decode plaintext via `decode_plaintext_v2` into
     (pose, w, h, palette_indices[w*h]).
  3. Map each 4-bit palette index to RGB via a palette table. v2 does
     not store palettes on chain (only `paletteCommit`); we use a
     default 16-color palette so the output is reproducible from
     fixtures alone.
  4. Compose 16 slots into a 48x48 RGB canvas using the revealed
     z-permutation (post-solve; pre-solve the z-order is opaque).
  5. Compute T10 byte-equal via sponge_18 over (shadowId, zCommit,
     liveStateHash[16]) and split into 256 bits = 4 quartets,
     reproducing what `shadow_t10` v2 commits to.

Modes:

  from-solve-fixture   : decode `plaintexts.json` from a solve_shadow_v2
                         fixture (e.g. solve_demo); compose using the
                         revealed z-perm; render PNG.
                         No live chain required.

  from-transfer-fixture: decode the rotated-c2 from an atomic_transfer
                         fixture using the recipient's owner_sk; render PNG.

Usage:

  python3 visualize_shadow_v2.py from-solve-fixture \\
      --fixture-dir contracts/test/fixtures/solve_shadow_v2/solve_demo \\
      --out runs/solve_demo.png

  python3 visualize_shadow_v2.py palette
      # dump the default palette as a PNG strip for reference

The renderer produces a PIL.Image you can save anywhere; the CLI just
wraps it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS, CANVAS_W, CANVAS_H,
    decode_plaintext_v2,
)

# sponge_18 + split_128 live in tools/build_atomic_*_fixture.py modules; reuse.
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("PIL/Pillow required: pip install Pillow", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# Default 16-color palette. v2 paletteCommits commit to per-carrier
# palettes which are owner-private; for fixture-driven visualization we
# use a deterministic default so renders are reproducible.
# Selected for visual diversity + decent contrast on white background.
# --------------------------------------------------------------------------
DEFAULT_PALETTE: list[tuple[int, int, int]] = [
    (255, 255, 255),  # 0  white
    (  0,   0,   0),  # 1  black
    (220,  20,  60),  # 2  crimson
    (255, 140,   0),  # 3  dark orange
    (255, 215,   0),  # 4  gold
    ( 50, 205,  50),  # 5  lime green
    (  0, 191, 255),  # 6  deep sky blue
    ( 75,   0, 130),  # 7  indigo
    (199,  21, 133),  # 8  medium violet red
    (139,  69,  19),  # 9  saddle brown
    (255, 192, 203),  # 10 pink
    (128, 128, 128),  # 11 grey
    ( 64, 224, 208),  # 12 turquoise
    (255, 105, 180),  # 13 hot pink
    (124, 252,   0),  # 14 lawn green
    (188, 143, 143),  # 15 rosy brown
]
assert len(DEFAULT_PALETTE) == 16


def decode_pose(pose_packed: int) -> tuple[int, int, int, int, int]:
    """Inverse of v2_circuit_helpers.pack_pose. Returns (x, y, scale_q88,
    cos_q15, sin_q15)."""
    x = pose_packed & 0x3F
    y = (pose_packed >> 6) & 0x3F
    scale_q88 = (pose_packed >> 12) & 0xFFFF
    cos_q15 = (pose_packed >> 28) & 0xFFFF
    sin_q15 = (pose_packed >> 44) & 0xFFFF
    return x, y, scale_q88, cos_q15, sin_q15


def render_slot_sprite(
    plaintext_fields: list[int],
    palette: list[tuple[int, int, int]] | None = None,
) -> tuple[Optional[Image.Image], dict]:
    """Decode a single slot's 39-Field plaintext and render its sprite.

    Returns (sprite_image, metadata). For empty slots (all-zero plaintext)
    returns (None, {"empty": True}).
    """
    if palette is None:
        palette = DEFAULT_PALETTE
    if all(f == 0 for f in plaintext_fields):
        return None, {"empty": True}
    pose, w, h, indices = decode_plaintext_v2(plaintext_fields)
    px, py, scale_q88, cos_q15, sin_q15 = decode_pose(pose)
    sprite = Image.new("RGB", (w, h), color=palette[0])
    pixels = sprite.load()
    for j in range(h):
        for i in range(w):
            idx = indices[j * w + i] & 0xF
            pixels[i, j] = palette[idx]
    return sprite, {
        "empty": False,
        "x": px, "y": py,
        "w": w, "h": h,
        "scale_q88": scale_q88,
        "cos_q15": cos_q15,
        "sin_q15": sin_q15,
        "indices": indices,
    }


def compose_canvas(
    slots: list[tuple[Optional[Image.Image], dict]],
    z_perm: list[int],
    palette: list[tuple[int, int, int]] | None = None,
    canvas_size: int = 48,
) -> Image.Image:
    """Compose 16 slot sprites onto a (canvas_size x canvas_size) canvas.

    z_perm[i] = which slot index renders i-th in z-order (i=0 is bottom).
    Slots outside the canvas are clipped. Empty slots are skipped.
    """
    if palette is None:
        palette = DEFAULT_PALETTE
    canvas = Image.new("RGB", (canvas_size, canvas_size), color=palette[0])
    for z in range(16):
        slot_idx = z_perm[z]
        sprite, meta = slots[slot_idx]
        if sprite is None or meta.get("empty"):
            continue
        canvas.paste(sprite, (meta["x"], meta["y"]))
    return canvas


def upscale(img: Image.Image, factor: int = 8) -> Image.Image:
    return img.resize((img.width * factor, img.height * factor), Image.NEAREST)


def render_palette_strip(
    palette: list[tuple[int, int, int]] | None = None,
    cell: int = 32,
) -> Image.Image:
    if palette is None:
        palette = DEFAULT_PALETTE
    img = Image.new("RGB", (cell * 16, cell), color=(255, 255, 255))
    for i, c in enumerate(palette):
        for x in range(cell):
            for y in range(cell):
                img.putpixel((i * cell + x, y), c)
    return img


def render_t10_grid(
    shadow_id: int,
    z_index_commit: int,
    live_state_hash: list[int],
    cell: int = 32,
) -> tuple[Image.Image, tuple[int, int]]:
    """Reproduce the public T10 hash and render its 16x16 bit grid.

    T10 is two 128-bit halves of `sponge_18(shadow_id, zCommit, lsh[16])`.
    Render as a 4x4 grid of 8x8 quartets where each cell is the
    bit-pattern of one byte.
    """
    if len(live_state_hash) != 16:
        raise ValueError("live_state_hash must be 16 entries")
    buf = [shadow_id % P, z_index_commit % P] + [v % P for v in live_state_hash]
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    # 256 bits = 32 bytes laid out as a 16x16 grid.
    grid = Image.new("RGB", (cell * 16, cell * 16), color=(255, 255, 255))
    bits = (lo.to_bytes(16, "little") + hi.to_bytes(16, "little"))
    assert len(bits) == 32
    for byte_idx in range(32):
        byte = bits[byte_idx]
        for bit in range(8):
            on = (byte >> bit) & 1
            row = byte_idx // 2
            col = (byte_idx % 2) * 8 + bit
            color = (0, 0, 0) if on else (240, 240, 240)
            for x in range(cell):
                for y in range(cell):
                    grid.putpixel((col * cell + x, row * cell + y), color)
    return grid, (hi, lo)


# --------------------------------------------------------------------------
# CLI modes
# --------------------------------------------------------------------------

def cmd_from_solve_fixture(args) -> None:
    fix_dir = Path(args.fixture_dir).resolve()
    plaintexts_path = fix_dir / "plaintexts.json"
    meta_path = fix_dir / "meta.json"
    if not plaintexts_path.exists():
        sys.exit(f"missing {plaintexts_path}")
    if not meta_path.exists():
        sys.exit(f"missing {meta_path}")

    pdata = json.loads(plaintexts_path.read_text())
    meta = json.loads(meta_path.read_text())

    plaintexts: list[list[int]] = []
    for slot_arr in pdata["plaintexts"]:
        fields = [int(s, 16) for s in slot_arr]
        plaintexts.append(fields)
    assert len(plaintexts) == 16

    z_perm = meta["z_perm"]
    shadow_id = int(meta["shadow_id"], 16)
    z_index_commit = int(meta["z_index_commit"], 16)
    prev_lsh = [int(s, 16) for s in meta["prev_lsh"]]
    occupied = meta["occupied_idxs"]

    # Render per-slot sprites.
    slots = [render_slot_sprite(p) for p in plaintexts]

    # Compose final canvas using revealed z-perm.
    composite = compose_canvas(slots, z_perm)
    composite_up = upscale(composite, factor=args.upscale)

    # T10 grid.
    t10, (hi, lo) = render_t10_grid(shadow_id, z_index_commit, prev_lsh, cell=12)

    # Per-slot strip showing each non-empty sprite individually.
    sprites = [(i, s, m) for i, (s, m) in enumerate(slots) if not m.get("empty")]
    if sprites:
        max_w = max(m["w"] for _, _, m in sprites) * args.upscale
        max_h = max(m["h"] for _, _, m in sprites) * args.upscale
        strip = Image.new("RGB", (max_w * len(sprites) + 4 * (len(sprites) - 1), max_h),
                          color=(255, 255, 255))
        x_off = 0
        for slot_idx, sprite, m in sprites:
            sup = upscale(sprite, factor=args.upscale)
            strip.paste(sup, (x_off, 0))
            x_off += sup.width + 4
    else:
        strip = Image.new("RGB", (1, 1), color=(255, 255, 255))

    # Combined output: composite, strip, T10 vertically.
    pad = 16
    total_w = max(composite_up.width, strip.width, t10.width)
    total_h = composite_up.height + strip.height + t10.height + pad * 4
    out = Image.new("RGB", (total_w + pad * 2, total_h + pad), color=(255, 255, 255))
    out.paste(composite_up, (pad, pad))
    out.paste(strip, (pad, pad + composite_up.height + pad))
    out.paste(t10, (pad, pad + composite_up.height + pad + strip.height + pad))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    out.save(args.out)
    print(f"[wrote] {args.out}")
    print(f"  composite : 48x48 -> {composite_up.width}x{composite_up.height}")
    print(f"  occupied  : {occupied}")
    print(f"  z_perm    : {z_perm}")
    print(f"  T10 hi    : 0x{hi:032x}")
    print(f"  T10 lo    : 0x{lo:032x}")


def cmd_palette(args) -> None:
    img = render_palette_strip()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    img.save(args.out)
    print(f"[wrote] {args.out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)

    f = sp.add_parser("from-solve-fixture")
    f.add_argument("--fixture-dir", required=True,
                   help="Path to a solve_shadow_v2 fixture dir (containing meta.json + plaintexts.json)")
    f.add_argument("--out", required=True, help="Output PNG path")
    f.add_argument("--upscale", type=int, default=8, help="Pixel-art upscale factor")
    f.set_defaults(func=cmd_from_solve_fixture)

    g = sp.add_parser("palette")
    g.add_argument("--out", required=True)
    g.set_defaults(func=cmd_palette)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
