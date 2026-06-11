#!/usr/bin/env python3
"""Build pure-Python reference renders for the dashboard palette debug grid.

The dashboard's left/middle/right comparison is intentionally split:
  1. source 48px input image path,
  2. browser render from localhost chain ciphertext + active viewer decrypt key,
  3. this Python reference render from fixture plaintexts + canonical palettes.

The reference output does not use browser rendering code. It decodes the fixture's
39-field plaintexts, applies the same Q8.8 scale/quarter-turn pose rules, and
writes SVG rectangles for a 48x48 expected feature composite. That makes palette
or transform discrepancies visible in the dashboard without relying on a JS
self-check.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(TOOLS / "landmark"))

from palette_quantizer import PALETTES, PALETTE_RANK  # type: ignore  # noqa: E402
from v2_circuit_helpers import decode_plaintext_v2  # type: ignore  # noqa: E402

CANVAS_SIZE = 48
DEFAULT_FIXTURE = REPO / "contracts" / "test" / "fixtures" / "atomic_mint" / "atomic_mint_demo"
DEFAULT_OUT = REPO / ".local" / "palette_debug_reference.json"
DEFAULT_FACE_SOURCES = [
    "../examples/faces/alice0.png",
    "../examples/faces/synthetic/grid_48/s100_smile_+3.png",
    "../examples/faces/synthetic/grid_48/s101_neutral.png",
    "../examples/faces/synthetic/grid_48/s102_neutral.png",
    "../examples/faces/synthetic/grid_48/s103_neutral.png",
    "../examples/faces/synthetic/grid_48/s104_neutral.png",
    "../examples/faces/synthetic/grid_48/s105_neutral.png",
    "../examples/faces/synthetic/grid_48/s106_neutral.png",
    "../examples/faces/synthetic/grid_48/s107_neutral.png",
    "../examples/faces/synthetic/grid_48/s108_neutral.png",
    "../examples/faces/synthetic/grid_48/s109_neutral.png",
    "../examples/faces/synthetic/grid_48/s110_neutral.png",
    "../examples/faces/synthetic/grid_48/s111_neutral.png",
    "../examples/faces/synthetic/grid_48/s112_neutral.png",
    "../examples/faces/synthetic/grid_48/s113_neutral.png",
    "../examples/faces/synthetic/grid_48/s114_neutral.png",
    "../examples/faces/synthetic/grid_48/s115_neutral.png",
    "../examples/faces/synthetic/grid_48/s116_neutral.png",
    "../examples/faces/synthetic/grid_48/s117_neutral.png",
    "../examples/faces/synthetic/grid_48/s118_neutral.png",
    "../examples/faces/synthetic/grid_48/s119_neutral.png",
    "../examples/faces/synthetic/random_48/rand_0000.png",
    "../examples/faces/synthetic/random_48/rand_0001.png",
    "../examples/faces/synthetic/random_48/rand_0002.png",
    "../examples/faces/synthetic/random_48/rand_0003.png",
    "../examples/faces/synthetic/random_48/rand_0004.png",
    "../examples/faces/synthetic/random_48/rand_0005.png",
    "../examples/faces/synthetic/random_48/rand_0006.png",
    "../examples/faces/synthetic/random_48/rand_0007.png",
    "../examples/faces/synthetic/random_48/rand_0008.png",
    "../examples/faces/synthetic/random_48/rand_0009.png",
    "../examples/faces/synthetic/random_48/rand_0010.png",
    "../examples/faces/synthetic/random_48/rand_0011.png",
    "../examples/faces/synthetic/random_48/rand_0012.png",
    "../examples/faces/synthetic/random_48/rand_0013.png",
    "../examples/faces/synthetic/random_48/rand_0014.png",
    "../examples/faces/synthetic/random_48/rand_0015.png",
    "../examples/faces/synthetic/random_48/rand_0016.png",
    "../examples/faces/synthetic/random_48/rand_0017.png",
    "../examples/faces/synthetic/random_48/rand_0018.png",
    "../examples/faces/synthetic/random_48/rand_0019.png",
    "../examples/faces/synthetic/random_48/rand_0020.png",
    "../examples/faces/synthetic/random_48/rand_0021.png",
    "../examples/faces/synthetic/random_48/rand_0022.png",
    "../examples/faces/synthetic/random_48/rand_0023.png",
    "../examples/faces/synthetic/random_48/rand_0024.png",
    "../examples/faces/alice0.png",
    "../examples/faces/synthetic/grid_48/s101_neutral.png",
    "../examples/faces/synthetic/random_48/rand_0000.png",
    "../examples/faces/synthetic/grid_48/s119_neutral.png",
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--cases", type=int, default=50)
    args = ap.parse_args()

    fixture = args.fixture.resolve()
    plaintexts = load_plaintexts(fixture)
    decoded_slots = decode_slots(plaintexts)
    cases = []
    for case_idx in range(args.cases):
        varied = []
        for slot_idx, decoded in decoded_slots:
            palette_name = PALETTE_RANK[(case_idx + slot_idx) % len(PALETTE_RANK)]
            varied.append({"slotIdx": slot_idx, "decoded": decoded, "paletteName": palette_name})
        cases.append({
            "case": case_idx + 1,
            "src": DEFAULT_FACE_SOURCES[case_idx % len(DEFAULT_FACE_SOURCES)],
            "paletteOffset": case_idx % len(PALETTE_RANK),
            "paletteNames": sorted({slot["paletteName"] for slot in varied}),
            "svg": compose_svg(varied),
        })

    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "source": "tools/build_palette_debug_reference.py",
        "fixture": str(fixture.relative_to(REPO)),
        "paletteRank": PALETTE_RANK,
        "cases": cases,
    }, indent=2) + "\n")
    print(f"wrote {out}")
    return 0


def load_plaintexts(fixture: Path) -> list[list[int]]:
    data = json.loads((fixture / "plaintexts.json").read_text())
    plaintexts = [[int(field, 16) for field in slot] for slot in data["plaintexts"]]
    if len(plaintexts) != 16:
        raise ValueError(f"expected 16 plaintext slots, got {len(plaintexts)}")
    return plaintexts


def decode_slots(plaintexts: list[list[int]]) -> list[tuple[int, dict[str, Any]]]:
    out: list[tuple[int, dict[str, Any]]] = []
    for slot_idx, fields in enumerate(plaintexts):
        if all(v == 0 for v in fields):
            continue
        pose, w, h, indices = decode_plaintext_v2(fields)
        out.append((slot_idx, {
            "x": pose & 0x3F,
            "y": (pose >> 6) & 0x3F,
            "scaleQ88": (pose >> 12) & 0xFFFF,
            "quarterTurns": (pose >> 28) & 0x03,
            "w": w,
            "h": h,
            "indices": indices,
        }))
    return out


def compose_svg(slots: list[dict[str, Any]]) -> str:
    canvas: list[tuple[int, int, int] | None] = [None] * (CANVAS_SIZE * CANVAS_SIZE)
    for slot in sorted(slots, key=lambda s: s["slotIdx"]):
        draw_slot(canvas, slot["decoded"], PALETTES[slot["paletteName"]])
    rects = []
    for y in range(CANVAS_SIZE):
        for x in range(CANVAS_SIZE):
            rgb = canvas[y * CANVAS_SIZE + x]
            if rgb is None:
                continue
            rects.append(f'<rect x="{x}" y="{y}" width="1" height="1" fill="#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}" />')
    return f'<svg class="debugPythonOutput" viewBox="0 0 {CANVAS_SIZE} {CANVAS_SIZE}" role="img" aria-label="pure Python expected feature output">{"".join(rects)}</svg>'


def draw_slot(canvas: list[tuple[int, int, int] | None], decoded: dict[str, Any], palette: list[tuple[int, int, int]]) -> None:
    scale = int(decoded["scaleQ88"])
    w = int(decoded["w"])
    h = int(decoded["h"])
    if scale <= 0 or w <= 0 or h <= 0:
        return
    scaled_w = max(1, (w * scale + 255) >> 8)
    scaled_h = max(1, (h * scale + 255) >> 8)
    turns = int(decoded["quarterTurns"]) & 3
    rot_w = scaled_w if turns % 2 == 0 else scaled_h
    rot_h = scaled_h if turns % 2 == 0 else scaled_w
    x0 = (2 * int(decoded["x"]) + scaled_w - rot_w) // 2
    y0 = (2 * int(decoded["y"]) + scaled_h - rot_h) // 2
    indices = decoded["indices"]
    for ry in range(rot_h):
        for rx in range(rot_w):
            sx_scaled, sy_scaled = unrotate_point(rx, ry, scaled_w, scaled_h, turns)
            sx = min(w - 1, (sx_scaled * 256) // scale)
            sy = min(h - 1, (sy_scaled * 256) // scale)
            idx = int(indices[sy * w + sx])
            if idx < 0 or idx >= len(palette):
                raise ValueError(f"slot palette index {idx} outside palette length {len(palette)}")
            dx = x0 + rx
            dy = y0 + ry
            if 0 <= dx < CANVAS_SIZE and 0 <= dy < CANVAS_SIZE:
                canvas[dy * CANVAS_SIZE + dx] = palette[idx]


def unrotate_point(rx: int, ry: int, scaled_w: int, scaled_h: int, turns: int) -> tuple[int, int]:
    if turns == 1:
        return ry, scaled_h - 1 - rx
    if turns == 2:
        return scaled_w - 1 - rx, scaled_h - 1 - ry
    if turns == 3:
        return scaled_w - 1 - ry, rx
    return rx, ry


if __name__ == "__main__":
    raise SystemExit(main())
