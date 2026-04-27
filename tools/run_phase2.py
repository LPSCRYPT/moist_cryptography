#!/usr/bin/env python3
# **STALE — v1 phase-2 runner.** v2 has no equivalent runner; forge tests
# drive the full v2 surface.
"""End-to-end Phase 2 driver: deploy contracts on anvil + run alice0 fixture
through mint -> mutate -> insert -> remove on a real chain.

Skips operations that require additional fixtures (e.g. solve_shadow needs
its own fixture which isn't built yet).

Usage:
    # Start anvil first:
    pkill -9 anvil; sleep 1
    nohup anvil --port 8545 > /tmp/anvil.log 2>&1 &
    sleep 4

    # Then:
    python3 run_phase2.py --rpc http://127.0.0.1:8545
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
ROOT = REPO.parent
FIX_MINT     = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
FIX_TRANSFER = ROOT / "contracts" / "test" / "fixtures" / "transfer_shadow" / "alice0_to_bob"
FIX_EXTRACT  = ROOT / "contracts" / "test" / "fixtures" / "extract_slot" / "alice0_slot3_to_carol"
FORGE_DIR    = ROOT / "contracts"

DEFAULT_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def cast(args: list[str], rpc: str, env: dict | None = None, timeout: int = 60) -> str:
    """Run a `cast` command, return stdout (raises on nonzero)."""
    full = ["cast"] + args + ["--rpc-url", rpc]
    p = subprocess.run(full, capture_output=True, text=True, timeout=timeout, env=env)
    if p.returncode != 0:
        print(" ".join(full))
        print("STDOUT:", p.stdout)
        print("STDERR:", p.stderr)
        sys.exit(f"cast failed (exit {p.returncode})")
    return p.stdout.strip()


def parse_pi_file(path: Path) -> list[int]:
    raw = path.read_bytes()
    return [int.from_bytes(raw[i*32:(i+1)*32], "big") for i in range(len(raw) // 32)]


def hex_array(items: list[int]) -> str:
    """Format a list of uint256 as cast-array literal: '[0x...,0x...]'"""
    return "[" + ",".join(f"0x{v:064x}" for v in items) + "]"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY,
                    help="Sender EOA secret key (anvil's first account by default)")
    ap.add_argument("--out-dir", default=str(ROOT / "runs" / "anvil_phase2"))
    args = ap.parse_args()

    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / "run.log"
    print(f"  rpc      : {args.rpc}")
    print(f"  out_dir  : {out_dir}")
    print(f"  log      : {log}")

    # --- 1. Deploy ---------------------------------------------------------
    print("\n[1/4] Deploy")
    deploy_log_path = out_dir / "deploy.log"
    env = os.environ.copy()
    env["PRIVATE_KEY"] = args.private_key
    env["FOUNDRY_OFFLINE"] = "false"
    cmd = [
        "forge", "script",
        "script/DeployShadowPipeline.s.sol",
        "--rpc-url", args.rpc,
        "--private-key", args.private_key,
        "--broadcast",
        "-vvv",
    ]
    p = subprocess.run(cmd, cwd=str(FORGE_DIR), capture_output=True, text=True, timeout=600, env=env)
    deploy_log_path.write_text(p.stdout + "\n=== STDERR ===\n" + p.stderr)
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"deploy failed (exit {p.returncode})")
    log_text = p.stdout

    # Parse addresses from the deploy log.
    addresses = {}
    for needle in ["Poseidon2YulSponge:", "KeyRegistry:", "ShadowToken:", "FeatureNFT:",
                   "MintShadowVerifier:", "TransferShadowVerifier:",
                   "ExtractSlotVerifier:", "TransferFeatureVerifier:",
                   "SolveShadowVerifier:"]:
        for line in log_text.split("\n"):
            if needle in line:
                addr = line.split(needle, 1)[1].strip()
                if addr.startswith("0x"):
                    addresses[needle.rstrip(":")] = addr.split()[0]
                    break

    print("  Deployed addresses:")
    for k, v in addresses.items():
        print(f"    {k:30s} {v}")
    (out_dir / "addresses.json").write_text(json.dumps(addresses, indent=2))

    shadow_token = addresses.get("ShadowToken")
    feature_nft  = addresses.get("FeatureNFT")
    if not shadow_token or not feature_nft:
        sys.exit("missing core contract addresses in deploy log")

    # --- 2. Mint alice0's shadow ------------------------------------------
    print("\n[2/4] mintShadow alice0")
    pi = parse_pi_file(FIX_MINT / "public_inputs")
    proof = (FIX_MINT / "proof").read_bytes()
    c2 = (FIX_MINT / "c2.bin").read_bytes()

    mint_call = [
        "send", shadow_token,
        "mintShadow(bytes,bytes32[],bytes)",
        "0x" + proof.hex(),
        hex_array(pi),
        "0x" + c2.hex(),
        "--gas-limit", "13000000",
        "--private-key", args.private_key,
    ]
    out = cast(mint_call, args.rpc, env=env, timeout=300)
    (out_dir / "mint_receipt.txt").write_text(out)
    # Pull tx hash + gas used
    tx_hash = next((l.split()[1] for l in out.split("\n") if l.startswith("transactionHash")), None)
    gas_used = next((l.split()[1] for l in out.split("\n") if l.startswith("gasUsed")), None)
    print(f"  tx       : {tx_hash}")
    print(f"  gas_used : {gas_used}")

    # Compute shadowId = keccak256(abi.encode(DOMAIN_SHADOW, chainid, faceOriginId)) % FR_MOD
    from chain_ids import shadow_id_for, ANVIL_CHAIN_ID
    face_origin = pi[8]
    shadow_id = shadow_id_for(face_origin, ANVIL_CHAIN_ID)
    print(f"  shadow_id: {hex(shadow_id)[:18]}...")

    # Verify on-chain owner
    owner_addr = cast(["call", shadow_token, "ownerOf(uint256)(address)", str(shadow_id)], args.rpc).strip()
    print(f"  owner    : {owner_addr}")

    # --- 3. mutateSlot ---------------------------------------------------
    print("\n[3/4] mutateSlot slot 1 (left_eye) translate +1px")
    # origPose for slot 1: read from chain, then bump curX by 1.
    orig_pose_hex = cast(["call", shadow_token, "origPoseOf(uint256,uint8)(uint64)", str(shadow_id), "1"], args.rpc).strip()
    orig_pose = int(orig_pose_hex.split()[0])
    cx = orig_pose & 0x3F; cy = (orig_pose >> 6) & 0x3F
    new_cx = cx + 1
    new_pose = (new_cx & 0x3F) | ((cy & 0x3F) << 6) | (256 << 12) | (32767 << 28)
    print(f"  orig curX={cx} curY={cy} -> new curX={new_cx} curY={cy}")

    mutate_call = [
        "send", shadow_token,
        "mutateSlot(uint256,uint8,uint64)",
        str(shadow_id), "1", str(new_pose),
        "--gas-limit", "200000",
        "--private-key", args.private_key,
    ]
    out = cast(mutate_call, args.rpc, env=env, timeout=120)
    (out_dir / "mutate_receipt.txt").write_text(out)
    gas_used = next((l.split()[1] for l in out.split("\n") if l.startswith("gasUsed")), None)
    print(f"  gas_used : {gas_used}")

    # --- 4. transferShadow alice -> bob -----------------------------------
    print("\n[4/4] transferShadow alice -> bob (using fixture)")
    if not FIX_TRANSFER.exists():
        print("  skip: transfer fixture missing")
        return 0

    bob_fix = json.loads((FIX_TRANSFER / "fixture.json").read_text())
    bob_addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # anvil account #1
    xfer_pi = parse_pi_file(FIX_TRANSFER / "public_inputs")
    xfer_proof = (FIX_TRANSFER / "proof").read_bytes()
    xfer_c2 = (FIX_TRANSFER / "new_c2.bin").read_bytes()

    xfer_call = [
        "send", shadow_token,
        "transferShadow(uint256,address,bytes,bytes32[],bytes)",
        str(shadow_id), bob_addr,
        "0x" + xfer_proof.hex(),
        hex_array(xfer_pi),
        "0x" + xfer_c2.hex(),
        "--gas-limit", "12000000",
        "--private-key", args.private_key,
    ]
    out = cast(xfer_call, args.rpc, env=env, timeout=300)
    (out_dir / "transfer_receipt.txt").write_text(out)
    gas_used = next((l.split()[1] for l in out.split("\n") if l.startswith("gasUsed")), None)
    print(f"  gas_used : {gas_used}")

    # Confirm new owner
    new_owner_addr = cast(["call", shadow_token, "ownerOf(uint256)(address)", str(shadow_id)], args.rpc).strip()
    print(f"  new owner: {new_owner_addr}")

    print("\n" + "=" * 68)
    print(" Phase 2 anvil run complete")
    print("=" * 68)
    print(f" Logs in {out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
