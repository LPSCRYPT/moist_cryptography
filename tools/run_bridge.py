#!/usr/bin/env python3
# **STALE — v1 bridge runner.** Pending v2 redeploy (Phase 11).
"""End-to-end Base Sepolia <-> Eth Sepolia bridge runner.

Phases:
  0. Connectivity check (both chains)
  1. Deploy ShadowMirrorL1 on Ethereum Sepolia
  2. Deploy ShadowBridgeL2 on Base Sepolia (pointing at an existing ShadowToken)
  3. Wire setL1Mirror + setL2Bridge
  4. Fund the L2 shadow owner with gas (if a fresh-key recipient owns it)
  5. Owner: approve bridge for the shadowId, then bridgeShadow
  6. Verify L2 lock + sendMessage event
  7. Document the withdrawal-finalization step (7-day wait on L1)

Run AFTER running `sepolia_e2e.py --scenario solve` (which produces a solved
shadow on L2). The script reads the solve run's addresses.json + the test
keys to find the shadow and its owner.

Usage:
    python3 run_bridge.py [--solve-run-dir DIR] [--out-dir DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
ROOT = REPO.parent
FORGE_DIR = ROOT / "contracts"
ENV_PATH = ROOT / ".env"

L2_RPC = "https://sepolia.base.org"
L1_RPC = "https://sepolia.drpc.org"

FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; D = "\033[90m"; X = "\033[0m"


def load_env_pk() -> str:
    text = ENV_PATH.read_text()
    m = re.search(r"^PRIVATE_KEY\s*=\s*(.+?)\s*$", text, re.MULTILINE)
    if not m:
        sys.exit("PRIVATE_KEY missing in .env")
    pk = m.group(1).strip().strip('"').strip("'")
    return pk if pk.startswith("0x") else "0x" + pk


def cast_call(args, rpc, retries=5, timeout=90):
    cmd = ["cast", "call"] + args + ["--rpc-url", rpc]
    last_err = ""
    for attempt in range(retries):
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if p.returncode == 0:
            return p.stdout.strip()
        last_err = (p.stderr + " " + p.stdout)[-300:]
        if attempt < retries - 1:
            time.sleep(2 ** attempt)
    sys.exit(f"cast call failed: {last_err}")


def cast_call_until(args, rpc, predicate, timeout=120, interval=3.0):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        last = cast_call(args, rpc)
        if predicate(last):
            return last, True
        time.sleep(interval)
    return last, False


def cast_send(args, rpc, pk, gas_limit, timeout=600, value=None):
    cmd = ["cast", "send"] + args + ["--rpc-url", rpc, "--private-key", pk,
                                       "--gas-limit", str(gas_limit), "--json"]
    if value:
        cmd.extend(["--value", value])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        print(f"{R}STDOUT:{X}", p.stdout[-1500:])
        print(f"{R}STDERR:{X}", p.stderr[-1500:])
        sys.exit(f"cast send failed (exit {p.returncode})")
    return json.loads(p.stdout)


def deploy_l1(rpc: str, pk: str, out_dir: Path) -> str:
    print(f"{Y}[1] Deploy ShadowMirrorL1 on Ethereum Sepolia{X}")
    cmd = [
        "forge", "script",
        "script/DeployShadowMirrorL1.s.sol",
        "--rpc-url", rpc,
        "--private-key", pk,
        "--broadcast",
        "--slow",
        "-vvv",
    ]
    p = subprocess.run(cmd, cwd=str(FORGE_DIR), capture_output=True, text=True, timeout=300)
    (out_dir / "deploy_l1.log").write_text(p.stdout + "\n=== STDERR ===\n" + p.stderr)
    if p.returncode != 0:
        sys.exit(f"L1 deploy failed: {p.stderr[-1500:]}")
    for line in p.stdout.split("\n"):
        if "ShadowMirrorL1:" in line:
            addr = line.split("ShadowMirrorL1:")[1].strip().split()[0]
            print(f"  ShadowMirrorL1 @ {addr}")
            return addr
    sys.exit("could not parse L1 mirror address")


def deploy_l2_bridge(rpc: str, pk: str, shadow_token: str, out_dir: Path) -> str:
    print(f"{Y}[2] Deploy ShadowBridgeL2 on Base Sepolia{X}")
    env = dict(os.environ)
    env["SHADOW_TOKEN"] = shadow_token
    cmd = [
        "forge", "script",
        "script/DeployShadowBridgeL2.s.sol",
        "--rpc-url", rpc,
        "--private-key", pk,
        "--broadcast",
        "--slow",
        "-vvv",
    ]
    p = subprocess.run(cmd, cwd=str(FORGE_DIR), capture_output=True, text=True,
                       timeout=300, env=env)
    (out_dir / "deploy_l2_bridge.log").write_text(p.stdout + "\n=== STDERR ===\n" + p.stderr)
    if p.returncode != 0:
        sys.exit(f"L2 bridge deploy failed: {p.stderr[-1500:]}")
    for line in p.stdout.split("\n"):
        if "ShadowBridgeL2:" in line:
            addr = line.split("ShadowBridgeL2:")[1].strip().split()[0]
            print(f"  ShadowBridgeL2 @ {addr}")
            return addr
    sys.exit("could not parse L2 bridge address")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--solve-run-dir", default=None,
                    help="Path to a phase2 solve-scenario run with addresses.json. "
                         "Default: latest sepolia_solve_*")
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    pk = load_env_pk()
    deployer = subprocess.check_output(
        ["cast", "wallet", "address", "--private-key", pk], text=True).strip()

    ts = int(time.time())
    out_dir = Path(args.out_dir) if args.out_dir else ROOT / "runs" / f"bridge_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"{D}====================================================================={X}")
    print(f" Phase 2 cross-chain bridge runner")
    print(f"{D}====================================================================={X}")
    print(f"  deployer  : {deployer}")
    print(f"  out_dir   : {out_dir}")

    # Resolve solve run dir
    if args.solve_run_dir:
        solve_dir = Path(args.solve_run_dir)
    else:
        candidates = sorted((ROOT / "runs").glob("sepolia_solve_*"), reverse=True)
        candidates = [c for c in candidates if (c / "addresses.json").exists()]
        if not candidates:
            sys.exit("no sepolia_solve_* directory found; run sepolia_e2e.py --scenario solve first")
        solve_dir = candidates[0]
    print(f"  solve_dir : {solve_dir}")
    addrs = json.loads((solve_dir / "addresses.json").read_text())
    SHADOW = addrs["ShadowToken"]

    # Find the solved shadow + its owner
    pi_mint = (ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0" / "public_inputs").read_bytes()
    face_origin_id = int.from_bytes(pi_mint[8*32:9*32], "big")
    from chain_ids import shadow_id_for, BASE_SEPOLIA_CHAIN_ID
    sid = shadow_id_for(face_origin_id, BASE_SEPOLIA_CHAIN_ID)
    print(f"  sid       : 0x{sid:064x}")

    # Verify it's solved + find owner
    is_solved = cast_call([SHADOW, "solved(uint256)(bool)", str(sid)], L2_RPC).split()[0]
    print(f"  is_solved : {is_solved}")
    if "true" not in is_solved.lower():
        sys.exit("shadow not solved; run sepolia_e2e.py --scenario solve first")
    owner = cast_call([SHADOW, "ownerOf(uint256)(address)", str(sid)], L2_RPC).split()[0]
    print(f"  l2_owner  : {owner}")

    # Determine which test key matches the owner (for signing the bridge tx)
    keys = json.loads((REPO / "test_keys.json").read_text())["roles"]
    owner_role, owner_sk = None, None
    for role, info in keys.items():
        if info["address"].lower() == owner.lower():
            owner_role = role
            owner_sk = info["secp_sk"]
            break
    if not owner_role:
        if owner.lower() == deployer.lower():
            owner_role = "deployer"
            owner_sk = pk
        else:
            sys.exit(f"shadow owner {owner} not in test_keys.json or deployer")
    print(f"  owner_role: {owner_role}")

    # ---- 0. Connectivity ----------------------------------------------------
    print(f"\n{Y}[0] Connectivity{X}")
    bal_l2 = int(cast_call(["balance", deployer], L2_RPC).split()[0]) if False else int(
        subprocess.check_output(["cast", "balance", deployer, "--rpc-url", L2_RPC], text=True).strip())
    bal_l1 = int(subprocess.check_output(["cast", "balance", deployer, "--rpc-url", L1_RPC], text=True).strip())
    print(f"  L2 balance: {bal_l2 / 1e18:.4f} ETH")
    print(f"  L1 balance: {bal_l1 / 1e18:.4f} ETH")
    assert bal_l2 > 1e16 and bal_l1 > 1e16, "deployer needs ETH on both chains"

    # ---- 1. Deploy L1 mirror ------------------------------------------------
    mirror_addr = deploy_l1(L1_RPC, pk, out_dir)

    # ---- 2. Deploy L2 bridge ------------------------------------------------
    bridge_addr = deploy_l2_bridge(L2_RPC, pk, SHADOW, out_dir)

    # ---- 3. Wire ------------------------------------------------------------
    print(f"\n{Y}[3] Wire setL1Mirror + setL2Bridge{X}")
    rcpt1 = cast_send([bridge_addr, "setL1Mirror(address)", mirror_addr], L2_RPC, pk, gas_limit=120_000)
    print(f"  L2: setL1Mirror tx={rcpt1.get('transactionHash')}")
    rcpt2 = cast_send([mirror_addr, "setL2Bridge(address)", bridge_addr], L1_RPC, pk, gas_limit=120_000)
    print(f"  L1: setL2Bridge tx={rcpt2.get('transactionHash')}")

    # ---- 4. Fund owner if not deployer --------------------------------------
    if owner_role != "deployer":
        print(f"\n{Y}[4] Fund {owner_role} ({owner}) for L2 gas{X}")
        # bridgeShadow + approve gas: ~250k * 0.011 gwei = 0.000003 ETH; send 0.001 to be safe
        bal = int(subprocess.check_output(["cast", "balance", owner, "--rpc-url", L2_RPC], text=True).strip())
        print(f"  current bal: {bal / 1e18:.6f} ETH")
        if bal < int(0.0005 * 1e18):
            fund_rcpt = cast_send([owner], L2_RPC, pk, gas_limit=100_000, value="0.001ether")
            print(f"  fund tx: {fund_rcpt.get('transactionHash')}")
            # Wait for balance
            # Poll balance directly via cast balance (not cast call).
            for _ in range(30):
                bal = int(subprocess.check_output(
                    ["cast", "balance", owner, "--rpc-url", L2_RPC],
                    text=True, timeout=20).strip())
                if bal > int(0.0005 * 1e18):
                    break
                time.sleep(3)
            else:
                sys.exit("fund didn't reflect")

    # ---- 5. Approve + bridge ------------------------------------------------
    print(f"\n{Y}[5] {owner_role}: approve bridge + bridgeShadow{X}")
    appr_rcpt = cast_send(
        [SHADOW, "setApprovalForAll(address,bool)", bridge_addr, "true"],
        L2_RPC, owner_sk, gas_limit=100_000,
    )
    print(f"  setApprovalForAll tx: {appr_rcpt.get('transactionHash')}")

    # Read the solve PI bytes from the local fixture
    revealed_pi_bytes = (ROOT / "contracts" / "test" / "fixtures" / "solve_shadow" / "alice0" / "public_inputs").read_bytes()
    assert len(revealed_pi_bytes) == 261 * 32, f"expected 261*32 bytes, got {len(revealed_pi_bytes)}"

    bridge_rcpt = cast_send(
        [bridge_addr, "bridgeShadow(uint256,address,bytes)",
         str(sid), owner, "0x" + revealed_pi_bytes.hex()],
        L2_RPC, owner_sk, gas_limit=2_000_000,
    )
    bridge_tx = bridge_rcpt.get("transactionHash")
    bridge_gas = int(bridge_rcpt.get("gasUsed", "0x0"), 16)
    print(f"  bridgeShadow tx: {bridge_tx}")
    print(f"  bridgeShadow gas: {bridge_gas:,d}")

    # ---- 6. Verify L2 state -------------------------------------------------
    print(f"\n{Y}[6] Verify L2 state{X}")
    state_raw, ok = cast_call_until(
        [bridge_addr, "bridged(uint256)(uint8)", str(sid)],
        L2_RPC, lambda s: s.strip().split()[0] == "1",
        timeout=120, interval=3,
    )
    print(f"  bridged[sid] = {state_raw.strip()}  (1 = OWNED_ON_L1)")
    assert ok, f"bridge state didn't reach OWNED_ON_L1: got {state_raw}"

    new_l2_owner = cast_call([SHADOW, "ownerOf(uint256)(address)", str(sid)], L2_RPC).split()[0]
    print(f"  L2 ownerOf(sid) = {new_l2_owner}")
    assert new_l2_owner.lower() == bridge_addr.lower(), f"shadow not locked in bridge"

    # ---- 7. Manifest --------------------------------------------------------
    manifest = {
        "ts": ts,
        "l1_rpc": L1_RPC,
        "l2_rpc": L2_RPC,
        "deployer": deployer,
        "shadow_token": SHADOW,
        "shadow_id": hex(sid),
        "l1_mirror": mirror_addr,
        "l2_bridge": bridge_addr,
        "owner_role": owner_role,
        "bridge_tx": bridge_tx,
        "bridge_gas": bridge_gas,
        "wire_l2_setL1Mirror_tx": rcpt1.get("transactionHash"),
        "wire_l1_setL2Bridge_tx": rcpt2.get("transactionHash"),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(f"\n{D}====================================================================={X}")
    print(f" {G}L2 leg complete{X}")
    print(f" L1 mirror NFT will be minted automatically once the OP withdrawal")
    print(f" is proved + finalized (~7 days on Base Sepolia).")
    print(f"   1. Anyone calls OptimismPortal.proveWithdrawalTransaction(...)")
    print(f"      after the L2 output root is published (~30 mins after tx).")
    print(f"   2. After 7-day challenge: OptimismPortal.finalizeWithdrawalTransaction(...)")
    print(f"   3. The L1CrossDomainMessenger relays mintFromBridge() to ShadowMirrorL1.")
    print(f" Tx hash to track: {bridge_tx}")
    print(f" out_dir: {out_dir}")
    print(f"{D}====================================================================={X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
