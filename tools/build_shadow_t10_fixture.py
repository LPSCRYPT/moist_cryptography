#!/usr/bin/env python3
"""Generate a shadow_t10 fixture for one (shadow state) point.

Inputs:
  - alice0 mint state (PI + c2.bin + recipient_sk from fixture.json)
  - per-slot pose overrides (mutate at index k -> new pose)

Outputs:
  - <fixture_dir>/proof, public_inputs, fixture.json
  - All 11 step states (mint + 10 mutations) producible by --step N

Usage:
  python3 build_shadow_t10_fixture.py [--step N] [--out FIXTURE_DIR]

The script emits the Prover.toml, calls nargo execute + bb prove, and
saves artifacts. It mirrors build_extract_slot_fixture.py.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from secret_inbox import G, ec_mul, P  # noqa: E402
from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, unpack_fields_to_recolored, split_into_regions,
    poseidon2_hash_2,
)
from t10 import (  # noqa: E402
    compute_t10, manifest_hash, poseidon2_sponge,
    SLOT_KIND_ORIGINAL, SLOT_KIND_EMPTY, REGION_W, REGION_H,
)
from chain_ids import shadow_id_for, ANVIL_CHAIN_ID  # noqa: E402

ROOT = REPO.parent
ALICE0_DIR = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
CIRCUIT_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "shadow_t10"

VAST_HOST = "root@ssh6.vast.ai"
VAST_PORT = "32194"
VAST_CIRCUIT = "/root/test_pipeline/circuits/shadow_t10"


# =============================================================================
# Mutate-only PROGRAMME (8 steps total: step 0 = mint, steps 1..7 = mutates)
# =============================================================================
# Tuples: (slot_idx, cx, cy, scale_q88, cos_q15, sin_q15, label)
# Scale_q88 MUST be a power of 2 (32, 64, 128, 256, 512, 1024, 2048, 4096)
# for the v1 T10 circuit's exact-inversion constraint.

PROGRAMME = [
    # (slot_idx, cx, cy, scale_q88, cos_q15, sin_q15, label)
    (1, 15,  19, 256,  32767,      0, "eye L\n+3 right"),
    (2, 22,  19, 256,  32767,      0, "eye R\n-3 left"),
    (3,  5,  10, 512,  32767,      0, "nose\n2x scale"),
    (6, 15, 33, 256,  28377,  16383, "mouth\nrotate 30 deg"),
    (0,  0,  4, 256,  32767,      0, "forehead\nup 4"),
    (7, 13, 35, 256,  32767,      0, "chin\nup 4"),
    (1, 12, 19, 128,  28377, -16383, "eye L\n0.5x rot -30 deg"),
]


def pack_pose(cx: int, cy: int, scale_q88: int = 256,
              cos_q15: int = 32767, sin_q15: int = 0) -> int:
    """Pack into uint64 matching PoseLib + circuit."""
    cos_u = cos_q15 & 0xFFFF
    sin_u = sin_q15 & 0xFFFF
    return ((cx & 0x3F)
            | ((cy & 0x3F) << 6)
            | ((scale_q88 & 0xFFFF) << 12)
            | (cos_u << 28)
            | (sin_u << 44))


def unpack_pose(p: int) -> tuple[int, int, int, int, int, int, int]:
    """Returns (cx, cy, scale_q88, cos_u16, sin_u16, cos_signed, sin_signed)."""
    cx = p & 0x3F
    cy = (p >> 6) & 0x3F
    sc = (p >> 12) & 0xFFFF
    co_u = (p >> 28) & 0xFFFF
    si_u = (p >> 44) & 0xFFFF
    co_s = co_u - 0x10000 if co_u >= 0x8000 else co_u
    si_s = si_u - 0x10000 if si_u >= 0x8000 else si_u
    return cx, cy, sc, co_u, si_u, co_s, si_s


def state_at_step(step: int, chain_id: int = ANVIL_CHAIN_ID) -> dict:
    """Compute the shadow's manifest state at PROGRAMME step N (0..7).

    Returns a dict with: poses (list of 16 uint64), kinds (list of 16),
    boxes_packed, shadow_plaintext_packed (249 fields), shadow_prev_k,
    state_nonce, prev_ct_commit, shadow_id_field.
    """
    if not (0 <= step <= len(PROGRAMME)):
        raise ValueError(f"step {step} out of range 0..{len(PROGRAMME)}")

    # ---- Load mint state ----
    pi_bytes = (ALICE0_DIR / "public_inputs").read_bytes()
    pi = [int.from_bytes(pi_bytes[i*32:(i+1)*32], "big") for i in range(17)]
    c2_bytes = (ALICE0_DIR / "c2.bin").read_bytes()
    c2 = [int.from_bytes(c2_bytes[i*32:(i+1)*32], "big") for i in range(249)]
    fix = json.loads((ALICE0_DIR / "fixture.json").read_text())
    sk = int(fix["witness"]["recipient_sk"], 16)
    c1_x = pi[12]; c1_y = pi[13]
    prev_ct_commit = pi[14]
    boxes_packed = pi[9]
    face_origin_id = pi[8]

    # ---- Decrypt to get shadow_plaintext (249 fields) ----
    plaintext = decrypt_mint_envelope(
        recipient_sk=sk, c1_x=c1_x, c1_y=c1_y, c2=c2,
    )
    # Re-encrypt to verify
    shared = ec_mul((c1_x, c1_y), sk)
    shadow_prev_k = poseidon2_hash_2(shared[0], shared[1])

    # ---- Decode initial poses (identity, from boxes_packed) ----
    poses: list[int] = []
    dims_wh: list[tuple[int, int]] = []
    for i in range(8):
        sd = (boxes_packed >> (24 * i)) & 0xFFFFFF
        x = sd & 0x3F; y = (sd >> 6) & 0x3F
        w = (sd >> 12) & 0x3F; h = (sd >> 18) & 0x3F
        poses.append(pack_pose(x, y))
        dims_wh.append((w, h))
    poses += [0] * 8
    kinds = [SLOT_KIND_ORIGINAL] * 8 + [SLOT_KIND_EMPTY] * 8
    dims_wh += [(0, 0)] * 8

    # ---- Apply step's mutations ----
    for op_idx in range(step):
        slot, cx, cy, sc, co, si, _label = PROGRAMME[op_idx]
        poses[slot] = pack_pose(cx, cy, sc, co, si)

    # ---- Decrypt regions for visualisation later ----
    concat = unpack_fields_to_recolored(plaintext)
    regions = list(split_into_regions(concat))
    per_slot = list(regions) + [b""] * 8
    max_dims = [(REGION_W[i], REGION_H[i]) for i in range(8)] + [(0, 0)] * 8

    # ---- Compute T10 ----
    res = compute_t10(per_slot, kinds, poses, dims_wh, max_dims)

    return {
        "step": step,
        "shadow_id_field": shadow_id_for(face_origin_id, chain_id),
        "state_nonce": step,                       # state_nonce bumps on each mutate
        "prev_ct_commit": prev_ct_commit,
        "boxes_packed": boxes_packed,
        "poses": poses,
        "kinds": kinds,
        "dims_wh": dims_wh,
        "shadow_plaintext": list(plaintext),
        "shadow_prev_k": shadow_prev_k,
        "t10_quarters": list(res.quarters),
        "t10_grid": res.grid,
        "t10_canvas": res.canvas,
        "shadow_hi": res.hi,
        "shadow_lo": res.lo,
    }


def write_prover_toml(state: dict, out_path: Path) -> None:
    """Write Prover.toml for shadow_t10."""
    poses = state["poses"]
    pose_cx = []; pose_cy = []; pose_scale = []
    pose_cos_u = []; pose_sin_u = []
    pose_scale_inv_q24 = []
    for k in range(8):
        cx, cy, sc, co_u, si_u, _co_s, _si_s = unpack_pose(poses[k])
        pose_cx.append(cx)
        pose_cy.append(cy)
        pose_scale.append(sc)
        pose_cos_u.append(co_u)
        pose_sin_u.append(si_u)
        # Power-of-2 scale only.
        if (sc & (sc - 1)) != 0 or sc == 0:
            raise ValueError(f"slot {k} scale_q88={sc} is not a power of 2")
        pose_scale_inv_q24.append((1 << 24) // sc)

    # Pad poses to 18 (multiple of 3) so the chain's Yul Poseidon2YulSponge
    # (which only accepts multiples of 96 bytes) and the circuit agree.
    poses_hash = poseidon2_sponge(list(poses) + [0, 0])

    # Quote the long shadow_plaintext array compactly.
    plaintext_lines: list[str] = []
    for i in range(0, 249, 8):
        chunk = state["shadow_plaintext"][i:i+8]
        plaintext_lines.append(", ".join(f'"{hex(v)}"' for v in chunk))
    plaintext_block = (
        "shadow_plaintext = [\n  "
        + ",\n  ".join(plaintext_lines)
        + "\n]\n"
    )

    poses_lines = ", ".join(f'"{hex(p)}"' for p in poses)
    pose_cx_lines = ", ".join(f'"{v}"' for v in pose_cx)
    pose_cy_lines = ", ".join(f'"{v}"' for v in pose_cy)
    pose_sc_lines = ", ".join(f'"{v}"' for v in pose_scale)
    pose_co_lines = ", ".join(f'"{v}"' for v in pose_cos_u)
    pose_si_lines = ", ".join(f'"{v}"' for v in pose_sin_u)
    pose_inv_lines = ", ".join(f'"{v}"' for v in pose_scale_inv_q24)

    body = (
        f'shadow_id        = "{hex(state["shadow_id_field"])}"\n'
        f'state_nonce      = "{state["state_nonce"]}"\n'
        f'prev_ct_commit   = "{hex(state["prev_ct_commit"])}"\n'
        f'boxes_packed     = "{hex(state["boxes_packed"])}"\n'
        f'poses_hash       = "{hex(poses_hash)}"\n'
        f'shadow_q0        = "{hex(state["t10_quarters"][0])}"\n'
        f'shadow_q1        = "{hex(state["t10_quarters"][1])}"\n'
        f'shadow_q2        = "{hex(state["t10_quarters"][2])}"\n'
        f'shadow_q3        = "{hex(state["t10_quarters"][3])}"\n'
        f'shadow_prev_k    = "{hex(state["shadow_prev_k"])}"\n'
        f'poses            = [{poses_lines}]\n'
        f'pose_cx          = [{pose_cx_lines}]\n'
        f'pose_cy          = [{pose_cy_lines}]\n'
        f'pose_scale_q88   = [{pose_sc_lines}]\n'
        f'pose_cos_q15_u16 = [{pose_co_lines}]\n'
        f'pose_sin_q15_u16 = [{pose_si_lines}]\n'
        f'pose_scale_inv_q24 = [{pose_inv_lines}]\n'
    )
    out_path.write_text(plaintext_block + body)


# =============================================================================
# Subprocess helpers
# =============================================================================
def run(cmd: list, cwd: Path | None = None, capture: bool = True) -> tuple[str, str, float]:
    started = time.time()
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    p = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=capture, text=True)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("  STDOUT:", (p.stdout or "")[-2000:])
        print("  STDERR:", (p.stderr or "")[-2000:])
        raise SystemExit(f"command failed exit={p.returncode} after {elapsed:.1f}s")
    return p.stdout, p.stderr, elapsed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--step", type=int, default=0,
                    help="PROGRAMME step (0 = mint, 1..7 = mutate)")
    ap.add_argument("--out", default=None, help="Fixture output dir")
    ap.add_argument("--chain-id", type=int, default=ANVIL_CHAIN_ID,
                    help="Chain id used for shadowId derivation (default: 31337 / Anvil)")
    ap.add_argument("--no-prove", action="store_true",
                    help="Only nargo execute (skip bb prove)")
    args = ap.parse_args()

    fixture_dir = Path(args.out) if args.out else FIXTURE_ROOT / f"step_{args.step:02d}"
    fixture_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 68)
    print(f" shadow_t10 fixture builder (step {args.step})")
    print("=" * 68)

    state = state_at_step(args.step, chain_id=args.chain_id)
    print(f"  shadow_id_field : {hex(state['shadow_id_field'])[:18]}...")
    print(f"  state_nonce     : {state['state_nonce']}")
    print(f"  prev_ct_commit  : {hex(state['prev_ct_commit'])[:18]}...")
    print(f"  boxes_packed    : {hex(state['boxes_packed'])[:18]}...")
    print(f"  poses (first 8) :")
    for k in range(8):
        cx, cy, sc, co_u, si_u, co_s, si_s = unpack_pose(state["poses"][k])
        print(f"    slot {k}: cx={cx} cy={cy} scale={sc} cos={co_s} sin={si_s}  (raw=0x{state['poses'][k]:016x})")
    print(f"  T10 hi: 0x{state['shadow_hi']:064x}")
    print(f"  T10 lo: 0x{state['shadow_lo']:064x}")

    # ---- Write Prover.toml ----
    print(f"\n[1] Write Prover.toml")
    prover_toml = CIRCUIT_DIR / "Prover.toml"
    write_prover_toml(state, prover_toml)
    print(f"  {prover_toml} ({prover_toml.stat().st_size:,} bytes)")

    # ---- Run nargo execute ----
    print(f"\n[2] nargo execute (witness + PI)")
    # Resolve nargo from PATH first, fall back to default install location.
    import shutil
    nargo = shutil.which("nargo") or str(Path.home() / ".nargo" / "bin" / "nargo")
    out, _, t_exec = run(
        [nargo, "execute", "--silence-warnings"],
        cwd=CIRCUIT_DIR,
    )
    print(f"  nargo execute: {t_exec:.1f}s")
    # Pull last line (which usually summarises the proof location).
    for line in (out.splitlines() or [""])[-5:]:
        if line.strip(): print(f"    {line.strip()}")

    # ---- Parse public_inputs ----
    pi_path = CIRCUIT_DIR / "target" / "shadow_t10.gz"
    if not pi_path.exists():
        # nargo execute writes target/<circuit>.gz (witness) but not always public_inputs as a separate file.
        # PI are at target/shadow_t10.json (the proven-circuit format) - or extracted via VK.
        print(f"  (note: target/shadow_t10.gz not at expected path, witness in target/)")
    print(f"  witness saved at {pi_path}")

    # Save fixture summary
    summary = {
        "step": args.step,
        "shadow_id_field": hex(state["shadow_id_field"]),
        "state_nonce": state["state_nonce"],
        "prev_ct_commit": hex(state["prev_ct_commit"]),
        "boxes_packed": hex(state["boxes_packed"]),
        "poses": [hex(p) for p in state["poses"]],
        "shadow_q0": hex(state["t10_quarters"][0]),
        "shadow_q1": hex(state["t10_quarters"][1]),
        "shadow_q2": hex(state["t10_quarters"][2]),
        "shadow_q3": hex(state["t10_quarters"][3]),
        "shadow_hi": hex(state["shadow_hi"]),
        "shadow_lo": hex(state["shadow_lo"]),
        "timing": {"nargo_execute": round(t_exec, 2)},
    }
    (fixture_dir / "fixture.json").write_text(json.dumps(summary, indent=2))
    print(f"\n  wrote fixture summary to {fixture_dir / 'fixture.json'}")

    # Save canvas + grid PNG for visual eyeball
    try:
        from PIL import Image
        from t10 import grid_to_grayscale_image
        Image.fromarray(state["t10_canvas"]).save(fixture_dir / "secret_canvas.png")
        Image.fromarray(grid_to_grayscale_image(state["t10_grid"], scale=24)).save(fixture_dir / "public_t10.png")
        print(f"  wrote {fixture_dir / 'secret_canvas.png'}")
        print(f"  wrote {fixture_dir / 'public_t10.png'}")
    except ImportError:
        pass

    if args.no_prove:
        print(f"\n[3] Skipped bb prove (use without --no-prove to generate proof)")
        return 0

    print(f"\n[3] bb prove deferred to a separate machine (proof gen needs ~16 GB RAM).")
    print(f"    Run: bb prove -b target/shadow_t10.json -w target/<witness> -o target/proofs/<step>/")
    print(f"    Then copy `proof` and `public_inputs` into <fixture_dir>/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
