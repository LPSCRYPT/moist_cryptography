#!/usr/bin/env python3
"""Anvil end-to-end for Screen 1 / T10 public-shadow circuit.

Deploys the full phase-2 stack on a local anvil node, mints alice0, then walks
the 8-step PROGRAMME (post-mint state + 7 mutations). After each state change,
calls setShadowT10 with a fresh proof and renders BOTH:

  * PUBLIC PNG  -- decoded from on-chain shadowT10[hi, lo] (16x16 4-level grey)
  * SECRET PNG  -- composited from c2 (read from ShadowCiphertext event +
                   decrypted with alice's sk) under the step's poses

so visual outputs are demonstrably chain-derived (no Python-only renders).

Pre-requisites:
  - anvil running on --rpc (default http://127.0.0.1:8545)
  - 8 step fixtures in contracts/test/fixtures/shadow_t10/step_NN/{proof,public_inputs}
  - Mint fixture in contracts/test/fixtures/mint_shadow/alice0/{proof,public_inputs,c2.bin,fixture.json}

Outputs all artefacts (per-step PNGs, addresses.json, run.log) under
runs/anvil_t10_<timestamp>/.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from chain_ids import shadow_id_for, ANVIL_CHAIN_ID  # noqa: E402
from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, unpack_fields_to_recolored, split_into_regions,
)
from t10 import (  # noqa: E402
    composite_canvas, grid_to_grayscale_image,
    SLOT_KIND_ORIGINAL, SLOT_KIND_EMPTY, REGION_W, REGION_H,
)
from build_shadow_t10_fixture import PROGRAMME, unpack_pose, pack_pose  # noqa: E402

ROOT = REPO.parent
FORGE_DIR = ROOT / "contracts"
FIX_MINT = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
FIX_T10  = ROOT / "contracts" / "test" / "fixtures" / "shadow_t10"

DEFAULT_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; D = "\033[90m"; X = "\033[0m"


def cast(args: list[str], rpc: str, env: dict | None = None,
         timeout: int = 60, retries: int = 5) -> str:
    """Run a cast command. Retries transient nonce/network errors."""
    full = ["cast"] + args + ["--rpc-url", rpc]
    last_err = ""
    for attempt in range(retries):
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout, env=env)
        if p.returncode == 0:
            txt = p.stdout.strip()
            # Detect on-chain revert (status 0) on receipts.
            if "status               0 (failed)" in txt:
                # Mining-time revert -- different from nonce errors. Surface immediately.
                # Pull revertReason if present.
                reason = next((l.split(':', 1)[1].strip() for l in txt.split("\n")
                              if l.startswith("revertReason")), "")
                print(" ".join(full))
                print(f"  on-chain revert: {reason or '<no data>'}")
                sys.exit("tx mined but reverted")
            return txt
        last_err = (p.stderr or p.stdout).strip()
        # Retry on transient RPC errors (Base Sepolia is flaky under load).
        if any(s in last_err for s in ("nonce too low", "replacement transaction underpriced",
                                        "connection", "timed out", "rate limit", "504", "503")):
            backoff = 2 + attempt * 3
            print(f"  {Y}retry{X} ({attempt+1}/{retries}) after {backoff}s -- {last_err[:120]}")
            time.sleep(backoff)
            continue
        # Non-transient: fail.
        print(" ".join(full))
        print("STDOUT:", p.stdout)
        print("STDERR:", p.stderr)
        sys.exit(f"cast failed (exit {p.returncode})")
    sys.exit(f"cast still failing after {retries} retries: {last_err[:200]}")


def parse_pi_file(path: Path) -> list[int]:
    raw = path.read_bytes()
    return [int.from_bytes(raw[i*32:(i+1)*32], "big") for i in range(len(raw) // 32)]


def hex_array(items: list[int]) -> str:
    return "[" + ",".join(f"0x{v:064x}" for v in items) + "]"


def quarters_to_grid(q0: int, q1: int, q2: int, q3: int) -> np.ndarray:
    """Decode 4 quartet Fields into a 16x16 array of values 0..3."""
    quarters = [q0, q1, q2, q3]
    grid = np.zeros((16, 16), dtype=np.uint8)
    for by in range(16):
        for bx in range(16):
            cell_idx = by * 16 + bx
            q = cell_idx // 64
            bit_in_q = (cell_idx % 64) * 2
            grid[by, bx] = (quarters[q] >> bit_in_q) & 0x3
    return grid


def hi_lo_to_quarters(hi: int, lo: int) -> tuple[int, int, int, int]:
    """hi = q0 | (q1 << 128); lo = q2 | (q3 << 128)."""
    mask = (1 << 128) - 1
    return (hi & mask, (hi >> 128) & mask, lo & mask, (lo >> 128) & mask)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY,
                    help="Sender EOA sk. For Sepolia, pass PRIVATE_KEY from <repo>/.env.")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--chain-id", type=int, default=ANVIL_CHAIN_ID)
    ap.add_argument("--fixture-root", default=str(FIX_T10),
                    help="Root dir of T10 step_NN/ fixtures (default: shadow_t10/)")
    ap.add_argument("--label", default="anvil",
                    help="Tag used in default --out-dir name (anvil, sepolia, ...)")
    args = ap.parse_args()

    fix_root = Path(args.fixture_root)
    out_dir = Path(args.out_dir) if args.out_dir else \
        ROOT / "runs" / f"{args.label}_t10_{int(time.time())}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"  rpc          : {args.rpc}")
    print(f"  out_dir      : {out_dir}")
    print(f"  chain_id     : {args.chain_id}")
    print(f"  fixture_root : {fix_root}")

    # ---- Verify all 8 t10 fixtures exist ----
    for s in range(8):
        fix = fix_root / f"step_{s:02d}"
        for needed in ("proof", "public_inputs", "fixture.json"):
            if not (fix / needed).exists():
                sys.exit(f"missing {fix / needed}; run build_shadow_t10_fixture.py --step {s} first")

    # ---- 1. Deploy ----------------------------------------------------------
    print(f"\n{Y}[1/4]{X} Deploy")
    env = os.environ.copy()
    env["PRIVATE_KEY"] = args.private_key
    p = subprocess.run([
        "forge", "script", "script/DeployShadowPipeline.s.sol",
        "--rpc-url", args.rpc, "--private-key", args.private_key,
        "--broadcast", "--skip-simulation",
    ], cwd=str(FORGE_DIR), capture_output=True, text=True, timeout=600, env=env)
    (out_dir / "deploy.log").write_text(p.stdout + "\n=== STDERR ===\n" + p.stderr)
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        sys.exit(f"deploy failed (exit {p.returncode})")
    addresses = {}
    for needle in ["Poseidon2YulSponge:", "ShadowToken:", "FeatureNFT:",
                   "MintShadowVerifier:", "T10ShadowVerifier:",
                   "FaceDiscVerifier:"]:
        for line in p.stdout.split("\n"):
            if needle in line:
                addr = line.split(needle, 1)[1].strip().split()[0]
                if addr.startswith("0x"):
                    addresses[needle.rstrip(":")] = addr
                    break
    (out_dir / "addresses.json").write_text(json.dumps(addresses, indent=2))
    print(f"  ShadowToken      : {addresses.get('ShadowToken')}")
    print(f"  T10ShadowVerifier: {addresses.get('T10ShadowVerifier')}")
    shadow_token = addresses["ShadowToken"]

    # ---- 2. Mint alice0 -----------------------------------------------------
    print(f"\n{Y}[2/4]{X} mintShadow alice0")
    mint_pi = parse_pi_file(FIX_MINT / "public_inputs")
    mint_proof = (FIX_MINT / "proof").read_bytes()
    c2 = (FIX_MINT / "c2.bin").read_bytes()
    # face_disc proof binds to mint PI[17] (image_commit) -- contract enforces.
    FIX_DISC = ROOT / "contracts" / "test" / "fixtures" / "face_disc" / "alice0"
    disc_proof = (FIX_DISC / "proof").read_bytes()
    out = cast([
        "send", shadow_token, "mintShadow(bytes,bytes32[],bytes,bytes)",
        "0x" + mint_proof.hex(), hex_array(mint_pi), "0x" + c2.hex(),
        "0x" + disc_proof.hex(),
        "--gas-limit", "15000000", "--private-key", args.private_key,
    ], args.rpc, env=env, timeout=300)
    (out_dir / "mint_receipt.txt").write_text(out)
    face_origin = mint_pi[8]
    shadow_id = shadow_id_for(face_origin, args.chain_id)
    print(f"  shadow_id: {hex(shadow_id)}")

    # Decrypt c2 once -- needed for SECRET row rendering on every step.
    fix_meta = json.loads((FIX_MINT / "fixture.json").read_text())
    sk = int(fix_meta["witness"]["recipient_sk"], 16)
    c1_x = mint_pi[12]; c1_y = mint_pi[13]
    c2_fields = [int.from_bytes(c2[i*32:(i+1)*32], "big") for i in range(249)]
    plaintext = decrypt_mint_envelope(recipient_sk=sk, c1_x=c1_x, c1_y=c1_y, c2=c2_fields)
    concat = unpack_fields_to_recolored(plaintext)
    per_slot = list(split_into_regions(concat)) + [b""] * 8
    max_dims = [(REGION_W[i], REGION_H[i]) for i in range(8)] + [(0, 0)] * 8
    boxes_packed = mint_pi[9]
    dims_wh = []
    for i in range(8):
        sd = (boxes_packed >> (24 * i)) & 0xFFFFFF
        w = (sd >> 12) & 0x3F; h = (sd >> 18) & 0x3F
        dims_wh.append((w, h))
    dims_wh += [(0, 0)] * 8

    # Decode the initial (post-mint) poses from boxes_packed.
    initial_poses: list[int] = []
    for i in range(8):
        sd = (boxes_packed >> (24 * i)) & 0xFFFFFF
        x = sd & 0x3F; y = (sd >> 6) & 0x3F
        initial_poses.append(pack_pose(x, y))
    initial_poses += [0] * 8
    kinds = [SLOT_KIND_ORIGINAL] * 8 + [SLOT_KIND_EMPTY] * 8

    # ---- 3. Walk the PROGRAMME, alternating mutate + setShadowT10 ----------
    print(f"\n{Y}[3/4]{X} 8 steps: {len(PROGRAMME)} mutate + 8 setShadowT10")

    # Build the per-step pose list off-chain (matches build_shadow_t10_fixture.py).
    per_step_poses: list[list[int]] = [list(initial_poses)]
    for step in range(1, 8):
        ps = list(per_step_poses[-1])
        slot, cx, cy, sc, co, si, _label = PROGRAMME[step - 1]
        ps[slot] = pack_pose(cx, cy, sc, co, si)
        per_step_poses.append(ps)

    PROGRAMME_LABELS = ["mint state"] + [t[6] for t in PROGRAMME]

    # Verify each fixture's PI matches the chain's view of state.
    for step in range(8):
        fix = fix_root / f"step_{step:02d}"
        pi = parse_pi_file(fix / "public_inputs")
        meta = json.loads((fix / "fixture.json").read_text())
        # Sanity: shadow_id, ct_commit, boxes_packed
        assert pi[0] == shadow_id, f"step {step} PI[0] mismatch"
        assert int(meta["state_nonce"]) == step, f"step {step} state_nonce mismatch"

    # Walk through each step.
    for step in range(8):
        label = PROGRAMME_LABELS[step]
        print(f"\n  {Y}-- step {step}{X}  {label}")

        # Mutation tx (skip for step 0 -- post-mint state).
        if step > 0:
            slot, cx, cy, sc, co, si, _ = PROGRAMME[step - 1]
            new_pose = pack_pose(cx, cy, sc, co, si)
            print(f"    mutateSlot slot={slot} pose=0x{new_pose:016x}")
            out = cast([
                "send", shadow_token, "mutateSlot(uint256,uint8,uint64)",
                str(shadow_id), str(slot), str(new_pose),
                "--gas-limit", "200000", "--private-key", args.private_key,
            ], args.rpc, env=env, timeout=120)
            (out_dir / f"step_{step:02d}_mutate.txt").write_text(out)

        # setShadowT10 tx
        fix = fix_root / f"step_{step:02d}"
        t10_proof = (fix / "proof").read_bytes()
        t10_pi = parse_pi_file(fix / "public_inputs")
        out = cast([
            "send", shadow_token, "setShadowT10(uint256,bytes,bytes32[])",
            str(shadow_id), "0x" + t10_proof.hex(), hex_array(t10_pi),
            "--gas-limit", "8000000", "--private-key", args.private_key,
        ], args.rpc, env=env, timeout=300)
        (out_dir / f"step_{step:02d}_setT10.txt").write_text(out)
        gas_used = next((l.split()[1] for l in out.split("\n") if l.startswith("gasUsed")), "?")
        print(f"    setShadowT10 gas_used={gas_used}")

        # Read shadowT10 from chain (single source of truth for PUBLIC).
        # Read shadowT10 from chain. Retry on staleness (Base Sepolia RPC
        # load-balances and a fresh node may serve a slightly older state).
        meta = json.loads((fix / "fixture.json").read_text())
        ref_hi = int(meta["shadow_hi"], 16); ref_lo = int(meta["shadow_lo"], 16)
        for read_attempt in range(8):
            hi = int(cast(["call", shadow_token, "shadowT10(uint256,uint256)(bytes32)",
                           str(shadow_id), "0"], args.rpc).strip(), 16)
            lo = int(cast(["call", shadow_token, "shadowT10(uint256,uint256)(bytes32)",
                           str(shadow_id), "1"], args.rpc).strip(), 16)
            if hi == ref_hi and lo == ref_lo:
                break
            time.sleep(2 + read_attempt)
        q0, q1, q2, q3 = hi_lo_to_quarters(hi, lo)
        print(f"    chain hi: 0x{hi:064x}")
        print(f"    chain lo: 0x{lo:064x}")
        if hi != ref_hi or lo != ref_lo:
            sys.exit(f"step {step}: chain T10 != python ref\n  chain: hi={hex(hi)} lo={hex(lo)}\n  ref:   hi={hex(ref_hi)} lo={hex(ref_lo)}")
        print(f"    {G}OK{X} chain T10 == python ref (byte-equal)")

        # Render PUBLIC PNG from chain bytes.
        grid = quarters_to_grid(q0, q1, q2, q3)
        public_img = grid_to_grayscale_image(grid, scale=24)
        public_path = out_dir / f"step_{step:02d}_public.png"
        from PIL import Image  # type: ignore
        Image.fromarray(public_img).save(public_path)
        print(f"    wrote {public_path.name} (PUBLIC, from chain)")

        # Render SECRET PNG: c2 was read on mint; current poses come from chain.
        # Read all 16 manifest poses from chain.
        chain_poses: list[int] = []
        for i in range(16):
            tup = cast([
                "call", shadow_token,
                "slotOf(uint256,uint8)((uint8,uint8,uint256,uint64))",
                str(shadow_id), str(i),
            ], args.rpc).strip()
            # tup looks like: "(0, 0, 0, 8795825636044 [8.795e12])".
            # cast pretty-prints big numbers with " [...e12]" annotation; strip it.
            parts = tup.strip("()").split(",")
            pose_str = parts[-1].strip().split()[0]
            chain_poses.append(int(pose_str, 16) if pose_str.startswith("0x") else int(pose_str))
        # Sanity: chain poses match the off-chain computed ones.
        assert chain_poses == per_step_poses[step], f"step {step}: chain poses mismatch"

        canvas = composite_canvas(per_slot, kinds, chain_poses, dims_wh, max_dims)
        secret_path = out_dir / f"step_{step:02d}_secret.png"
        Image.fromarray(canvas).save(secret_path)
        print(f"    wrote {secret_path.name} (SECRET, from chain poses)")

    # ---- 4. Summary --------------------------------------------------------
    print(f"\n{Y}[4/4]{X} Done. Outputs in {out_dir}/")
    print(f"  16 PNGs: 8 PUBLIC + 8 SECRET, all chain-derived.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
