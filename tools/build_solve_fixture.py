#!/usr/bin/env python3
# **STALE — v1 fixture builder.** v2 solve_shadow circuit pending (Phase 9).
"""Generate a solve_shadow fixture: alice0's shadow's full plaintext revealed.

The solve circuit is a one-way reveal: the prover publishes ALL 252 packed
plaintext Fields as PI (no secret remains in the shadow). The chain checks
PI[i] == feature.stateCommit (where stateCommit is sponge_11 over the per-
feature state) and emits the revealed_pixels bytes for permanent on-chain
public reveal.

Pipeline:
  1. Load alice0 mint PI + decrypt c2 -> 249 contiguous Fields -> 7716 bytes.
  2. Split per region (REGION_BYTES = (1296, 792, 792, 792, 798, 798, 1296, 1152)).
  3. For each region, pack into K_i Fields (per-feature canonical packing).
  4. Concatenate 8 * K_i = 252 Fields = revealed_pixels[252].
  5. Compute per-feature stateCommit via state_commit() helper.
  6. Write Prover.toml + nargo execute + bb prove + bb write_solidity_verifier.

Usage:
    python3 build_solve_fixture.py [--seed alice0]
"""
from __future__ import annotations

import argparse
import json
import sys
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, unpack_fields_to_recolored, split_into_regions,
    P, REGION_BYTES,
)
from mint_pipeline import compute_face_state, REGION_W, REGION_H, REGION_NAMES, PACKED_COUNTS  # noqa: E402
from relay_geom import (  # noqa: E402
    pack_feature_to_fields, pixel_commit_for_type, state_commit,
)

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "solve_shadow"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
ALICE0_DIR = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "solve_shadow"
ALICE_FACE = ROOT / "examples" / "faces" / "alice0.png"

NARGO = Path.home() / ".nargo" / "bin" / "nargo"
BB = Path.home() / ".bb" / "bb"

# Cumulative offsets within revealed_pixels[252].
_OFFSETS = []
_acc = 0
for _k in PACKED_COUNTS:
    _OFFSETS.append(_acc)
    _acc += _k
assert _acc == 252


def parse_pi_file(path):
    raw = path.read_bytes()
    return [int.from_bytes(raw[i*32:(i+1)*32], "big") for i in range(len(raw) // 32)]


def hex_field(v): return f'"{hex(v)}"'


def render_array(name, vs):
    return f"{name} = [{', '.join(hex_field(v) for v in vs)}]"


def run(cmd, cwd, timeout=600):
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s")
    return p.stdout, elapsed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="alice0")
    ap.add_argument("--out", default=None)
    ap.add_argument("--skip-prove", action="store_true")
    args = ap.parse_args()

    fixture_dir = Path(args.out) if args.out else FIXTURE_ROOT / args.seed
    fixture_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 68)
    print(f"solve_shadow fixture generator (seed={args.seed})")
    print("=" * 68)

    print("[1] Load alice0 mint state + compute_face_state")
    alice_pi = parse_pi_file(ALICE0_DIR / "public_inputs")
    color = int(alice_pi[10])
    state = compute_face_state(ALICE_FACE, color)
    face_origin_id = alice_pi[8]
    print(f"    color = {color}, faceOriginId = {hex(face_origin_id)[:18]}...")

    # Build per-feature state from compute_face_state regions.
    color_w     = []
    cur_x_w     = []
    cur_y_w     = []
    cur_w_w     = []
    cur_h_w     = []
    scale_q88_w = []
    cos_q15_w   = []
    sin_q15_w   = []
    revealed_pixels = [0] * 252
    state_commits = []

    DEFAULT_SCALE_Q88 = 256
    DEFAULT_COS_Q15 = 32767
    DEFAULT_SIN_Q15 = 0

    print("[2] Per-region: pack + state_commit")
    for i, region in enumerate(state.regions):
        K = PACKED_COUNTS[i]
        max_w = REGION_W[i]
        max_h = REGION_H[i]
        w = region.w
        h = region.h
        x1 = region.x1
        y1 = region.y1

        # Per-feature packed[K] = canonical packing per-region (NOT contiguous shadow packing).
        # state.regions[i].packed already gives this, length K.
        fields = list(region.packed)
        assert len(fields) == K, f"region {i}: expected K={K} fields, got {len(fields)}"

        pixel_commit = pixel_commit_for_type(i, fields)
        # Note: state_commit takes orig (cur_w/cur_h are the per-face box dims at mint).
        # mint_pipeline computes (w, h) for actual face, not max.
        sc = state_commit(
            face_origin_id, i, color,
            x1, y1, w, h,
            DEFAULT_SCALE_Q88, DEFAULT_COS_Q15, DEFAULT_SIN_Q15,
            pixel_commit,
        )

        color_w.append(color)
        cur_x_w.append(x1)
        cur_y_w.append(y1)
        cur_w_w.append(w)
        cur_h_w.append(h)
        scale_q88_w.append(DEFAULT_SCALE_Q88)
        cos_q15_w.append(DEFAULT_COS_Q15)
        sin_q15_w.append(DEFAULT_SIN_Q15)

        off = _OFFSETS[i]
        for j in range(K):
            revealed_pixels[off + j] = fields[j]
        state_commits.append(sc)
        print(f"    region {i} ({REGION_NAMES[i]:12s}): @ ({x1},{y1}) {w}x{h} -> stateCommit={hex(sc)[:18]}...")

    # Sanity check: stateCommits MUST match alice0's mint PI[0..7].
    print("\n[3] Verify stateCommits match alice0.PI[0..7]")
    for i in range(8):
        if state_commits[i] != alice_pi[i]:
            print(f"   FAIL slot {i}: phase2 sc={hex(state_commits[i])} vs mint PI[{i}]={hex(alice_pi[i])}")
            sys.exit("stateCommit mismatch -- mint pipeline divergence")
    print("    OK: all 8 stateCommits match alice0 mint")

    presence = 0xff  # all 8 slots bound

    print("[4] Write Prover.toml")
    lines = []
    for i, c in enumerate(state_commits):
        lines.append(f'state_commit_{i} = "{hex(c)}"')
    lines.append(f'presence = "{hex(presence)}"')
    arr_pix = ",\n  ".join(", ".join(f'"{hex(v)}"' for v in revealed_pixels[i:i + 12])
                           for i in range(0, 252, 12))
    lines.append(f"revealed_pixels = [\n  {arr_pix}\n]")
    lines.append(f'face_origin_id = "{hex(face_origin_id)}"')

    def _emit(name, vals):
        lines.append(f"{name} = [{', '.join(hex_field(v) for v in vals)}]")

    _emit("color", color_w)
    _emit("cur_x", cur_x_w)
    _emit("cur_y", cur_y_w)
    _emit("cur_w", cur_w_w)
    _emit("cur_h", cur_h_w)
    _emit("scale_q88", scale_q88_w)
    _emit("cos_q15", cos_q15_w)
    _emit("sin_q15", sin_q15_w)

    PROVER_TOML.write_text("\n".join(lines) + "\n")
    print(f"    {PROVER_TOML} ({PROVER_TOML.stat().st_size:,} bytes)")

    print("\n[5] nargo execute")
    out, t_exec = run([NARGO, "execute", "--silence-warnings"], CIRCUIT_DIR, timeout=600)
    print(f"    {t_exec:.1f}s")

    if args.skip_prove:
        return 0

    print("\n[6] bb write_vk + prove")
    out, t_vk = run([BB, "write_vk", "-b", "target/solve_shadow.json", "-o", "target", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
    proof_dir = CIRCUIT_DIR / "target" / "proof"
    if proof_dir.exists():
        for f in proof_dir.iterdir(): f.unlink()
    out, t_prove = run([BB, "prove", "-b", "target/solve_shadow.json", "-w", "target/solve_shadow.gz", "-o", "target/proof", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=900)
    out, t_ver = run([BB, "verify", "-k", "target/vk", "-p", "target/proof/proof", "-i", "target/proof/public_inputs", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
    print(f"    write_vk: {t_vk:.1f}s, prove: {t_prove:.1f}s, verify: {t_ver:.1f}s")

    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes    = (proof_dir / "public_inputs").read_bytes()
    n_pi = len(pi_bytes) // 32

    (fixture_dir / "proof").write_bytes(proof_bytes)
    (fixture_dir / "public_inputs").write_bytes(pi_bytes)

    fixture_meta = {
        "version": 1,
        "seed": args.seed,
        "face_origin_id": hex(face_origin_id),
        "color": color,
        "presence": hex(presence),
        "n_pi": n_pi,
    }
    (fixture_dir / "fixture.json").write_text(json.dumps(fixture_meta, indent=2))
    print(f"\n    saved fixture to {fixture_dir}/  (n_pi={n_pi})")

    print("\n[7] bb write_solidity_verifier")
    verifier_out = CIRCUIT_DIR / "target" / "SolveShadowVerifier.sol"
    run([BB, "write_solidity_verifier", "-k", "target/vk", "-o", str(verifier_out)], CIRCUIT_DIR, timeout=300)
    forge_src = ROOT / "contracts" / "src" / "SolveShadowVerifier.sol"
    text = verifier_out.read_text().replace("contract HonkVerifier", "contract SolveShadowVerifier")
    forge_src.write_text(text)
    print(f"    wrote {forge_src}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
