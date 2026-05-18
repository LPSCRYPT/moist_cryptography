#!/usr/bin/env python3
# **STALE — v1 Sepolia e2e harness.** Pending v2 redeploy (Phase 11) and
# rewrite to v2 events / function surface.
"""Comprehensive Phase 2 testing on Base Sepolia.

Runs an end-to-end suite that exercises every contract entry point through
multiple combinations + load patterns + transformation proofs, with sanity
checks on every output (including luminance-equality on the recovered face
render to validate the "greyscale output" of the shadow token).

Suite phases:
  0. Verify deployer balance + RPC reachable.
  1. Deploy: 9 contracts + wire + setKeyRegistry (registry stays in permissive
     mode for the test sender to keep proof PI compatible with the alice0
     fixtures, which use a deterministic recipient pk that doesn't match a
     registered EOA).
  2. Mint alice0's shadow.
  3. Read-back sanity: shadowOf, manifestOf, origPoseOf, all 16 manifest entries.
  4. Mutate every ORIGINAL slot (0..7) at least once with various op kinds
     (translate, scale, rotate, combined) -- assert each pose recoverable.
  5. Mutate-revert sanity: bad scale, off-frame, non-unit rotation.
  6. ExtractSlot 3 -> carol's FeatureNFT; verify on-chain metadata.
  7. InsertFeature: bob (post-transfer) tries to insert into slot 8 -- skipped
     because we keep alice as owner for simplicity; instead, validate that
     calling extract twice on the same slot reverts.
  8. TransferShadow alice -> bob; assert ecdh rotation + c2 update.
  9. TransferFeature carol -> dave; assert ownership rotation.
 10. Solve alice's shadow (requires ownership; bob holds it post-step-8, so we
     transfer it back to alice before solving).
 11. Pixel-equality validator runs against the LIVE chain state:
       - decrypt mintCiphertext event with alice's sk
       - decrypt transferShadow event with bob's sk
       - decrypt feature ciphertext with carol's sk
       - assert byte-equality vs Python compute_face_state
 12. Greyscale luminance check: render decrypted RGB bytes -> luminance image
     -> compare against Python simulation luminance image. Pixel-by-pixel
     |diff| <= 1 (rounding tolerance).
 13. Load tests:
       - 5 rapid-fire mutateSlot calls (no proof, ~42k gas each)
       - 1 retry of mintShadow with same faceOriginId (must revert AlreadyMinted)
       - 1 retry of extractSlot on already-extracted slot (must revert SlotNotOriginal)

All gas + tx hashes captured in `phase2/logs/sepolia_<timestamp>/manifest.json`.

Usage:
    python3 sepolia_e2e.py [--rpc URL] [--out-dir DIR] [--private-key HEX]

Default RPC: https://sepolia.base.org
Default key: PRIVATE_KEY from <repo-root>/.env
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
sys.path.insert(0, str(REPO))

from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, unpack_fields_to_recolored, split_into_regions,
    poseidon2_keystream_249, poseidon2_hash_2, P,
)
from build_extract_slot_fixture import poseidon2_keystream_42  # noqa: E402
from mint_pipeline import compute_face_state, REGION_W, REGION_H, REGION_NAMES  # noqa: E402
from secret_inbox import ec_mul  # noqa: E402

ROOT = REPO.parent
FORGE_DIR = ROOT / "contracts"

FIX_MINT     = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
FIX_TRANSFER = ROOT / "contracts" / "test" / "fixtures" / "transfer_shadow" / "alice0_to_bob"
FIX_EXTRACT  = ROOT / "contracts" / "test" / "fixtures" / "extract_slot" / "alice0_slot3_to_carol"
FIX_TFEAT    = ROOT / "contracts" / "test" / "fixtures" / "transfer_feature" / "carol_to_dave"
FIX_SOLVE    = ROOT / "contracts" / "test" / "fixtures" / "solve_shadow" / "alice0"
FIX_DISC     = ROOT / "contracts" / "test" / "fixtures" / "face_disc" / "alice0"

ENV_PATH = ROOT / ".env"
ALICE_FACE = ROOT / "examples" / "faces" / "alice0.png"

DEFAULT_RPC = "https://sepolia.base.org"
FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Recipient addresses come from test_keys.json (fresh, never-broadcast EOAs).
# These match the Grumpkin sk used for the proof's recipient_pk binding,
# AND the secp256k1 sk that lets the recipient sign EVM txs (e.g. for
# transferFeature where the carol-side caller must own the FeatureNFT).
_keys_path = Path(__file__).resolve().parent / "test_keys.json"
if not _keys_path.exists():
    sys.exit(f"missing {_keys_path} -- run gen_test_keys.py first")
_KEYS = json.loads(_keys_path.read_text())["roles"]
BOB_ADDR   = _KEYS["bob"]["address"]
CAROL_ADDR = _KEYS["carol"]["address"]
DAVE_ADDR  = _KEYS["dave"]["address"]
BOB_SECP_SK   = _KEYS["bob"]["secp_sk"]
CAROL_SECP_SK = _KEYS["carol"]["secp_sk"]
DAVE_SECP_SK  = _KEYS["dave"]["secp_sk"]

# ANSI colors
G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; D = "\033[90m"; X = "\033[0m"


def load_env_pk() -> str:
    if not ENV_PATH.exists():
        sys.exit(f"missing {ENV_PATH}")
    text = ENV_PATH.read_text()
    m = re.search(r"^PRIVATE_KEY\s*=\s*(.+?)\s*$", text, re.MULTILINE)
    if not m:
        sys.exit("PRIVATE_KEY not found in .env")
    pk = m.group(1).strip().strip('"').strip("'")
    return pk if pk.startswith("0x") else "0x" + pk


def parse_pi_file(path: Path) -> list[int]:
    raw = path.read_bytes()
    return [int.from_bytes(raw[i*32:(i+1)*32], "big") for i in range(len(raw) // 32)]


def hex_array(items: list[int]) -> str:
    return "[" + ",".join(f"0x{v:064x}" for v in items) + "]"


def cast_send(args: list[str], rpc: str, pk: str, gas_limit: int, timeout: int = 600) -> dict:
    """cast send + parse receipt into dict."""
    cmd = ["cast", "send"] + args + ["--rpc-url", rpc, "--private-key", pk,
                                      "--gas-limit", str(gas_limit), "--json"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        print(f"{R}STDOUT:{X}", p.stdout[-2000:])
        print(f"{R}STDERR:{X}", p.stderr[-2000:])
        sys.exit(f"cast send failed (exit {p.returncode})")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        # Fall back to plain receipt parsing
        out = {"raw": p.stdout}
        for line in p.stdout.split("\n"):
            if line.startswith("transactionHash"):
                out["transactionHash"] = line.split()[1]
            elif line.startswith("gasUsed"):
                out["gasUsed"] = line.split()[1]
            elif line.startswith("status"):
                out["status"] = line.split()[1]
        return out


def cast_send_expect_revert(args: list[str], rpc: str, pk: str, gas_limit: int) -> bool:
    """cast send that we EXPECT to revert. Returns True if reverted."""
    cmd = ["cast", "send"] + args + ["--rpc-url", rpc, "--private-key", pk,
                                      "--gas-limit", str(gas_limit), "--json"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    # cast may return 0 with status=0 (revert), or non-zero exit.
    if p.returncode != 0:
        return True
    try:
        receipt = json.loads(p.stdout)
        status = receipt.get("status", "0x0")
        return status in ("0x0", "0", 0)
    except json.JSONDecodeError:
        return False


def cast_call(args: list[str], rpc: str, timeout: int = 90, retries: int = 5) -> str:
    """cast call with exponential-backoff retry on RPC errors."""
    cmd = ["cast", "call"] + args + ["--rpc-url", rpc]
    last_err = ""
    for attempt in range(retries):
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if p.returncode == 0:
            return p.stdout.strip()
        last_err = p.stderr[-500:] + " || " + p.stdout[-500:]
        if attempt < retries - 1:
            wait = 2 ** attempt  # 1, 2, 4, 8, 16 seconds
            print(f"      {Y}cast call retry {attempt+1}/{retries} after {wait}s ({last_err[:100]}){X}")
            time.sleep(wait)
    sys.exit(f"cast call failed after {retries} retries: {last_err}")


def cast_call_until(args: list[str], rpc: str, predicate, timeout: int = 90,
                    interval: float = 2.0) -> tuple[str, bool]:
    """Polls cast_call until predicate(value) is True, or timeout. Use after a
    state-changing tx to handle Sepolia public-RPC stale-replica reads (the
    public load-balancer can route reads to nodes lagging by a block)."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        last = cast_call(args, rpc)
        if predicate(last):
            return last, True
        time.sleep(interval)
    return last, False


def parse_addresses_from_deploy(log_text: str) -> dict:
    out = {}
    for needle in ["Poseidon2YulSponge:", "KeyRegistry:", "ShadowToken:", "FeatureNFT:",
                   "MintShadowVerifier:", "TransferShadowVerifier:",
                   "ExtractSlotVerifier:", "TransferFeatureVerifier:",
                   "SolveShadowVerifier:", "T10ShadowVerifier:",
                   "FaceDiscVerifier:"]:
        for line in log_text.split("\n"):
            if needle in line:
                addr = line.split(needle, 1)[1].strip().split()[0]
                if addr.startswith("0x"):
                    out[needle.rstrip(":")] = addr
                    break
    return out


def deploy(rpc: str, pk: str, out_dir: Path) -> dict:
    print(f"{Y}[1] Deploy phase 2 stack to Sepolia{X}")
    cmd = [
        "forge", "script",
        "script/DeployShadowPipeline.s.sol",
        "--rpc-url", rpc,
        "--private-key", pk,
        "--broadcast",
        "--slow",
        "-vvv",
    ]
    p = subprocess.run(cmd, cwd=str(FORGE_DIR), capture_output=True, text=True, timeout=900)
    deploy_log = out_dir / "deploy.log"
    deploy_log.write_text(p.stdout + "\n=== STDERR ===\n" + p.stderr)
    if p.returncode != 0:
        print(f"{R}DEPLOY FAILED -- see {deploy_log}{X}")
        print(p.stdout[-3000:])
        sys.exit(1)
    addrs = parse_addresses_from_deploy(p.stdout)
    print(f"  deployed {len(addrs)} contracts:")
    for k, v in addrs.items():
        print(f"    {k:30s} {v}")
    return addrs


def slot(addrs: dict, key: str) -> str:
    if key not in addrs:
        sys.exit(f"missing deployed addr: {key}")
    return addrs[key]


from chain_ids import shadow_id_for as _shadow_id_for, feature_nft_id_for as _fid_for, BASE_SEPOLIA_CHAIN_ID  # noqa: E402


def shadow_id_for_face(face_origin_id: int, chain_id: int = BASE_SEPOLIA_CHAIN_ID) -> int:
    """Match ShadowToken.shadowIdOf for the target chain (default Base Sepolia)."""
    return _shadow_id_for(face_origin_id, chain_id)


def feature_nft_id_for(shadow_id_field: int, slot_idx: int,
                        mint_counter: int = 1, chain_id: int = BASE_SEPOLIA_CHAIN_ID) -> int:
    return _fid_for(shadow_id_field, slot_idx, mint_counter, chain_id)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=DEFAULT_RPC)
    ap.add_argument("--private-key", default=None)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--skip-deploy", action="store_true",
                    help="Skip deploy + read addresses from existing manifest.json")
    ap.add_argument("--scenario", choices=["transfer", "solve"], default="transfer",
                    help="transfer: mint+extract+transferShadow alice->bob (default)\n"
                         "solve:    mint+extract+solve+post-solve transferFrom")
    args = ap.parse_args()

    pk = args.private_key or load_env_pk()
    ts = int(time.time())
    out_dir = Path(args.out_dir) if args.out_dir else ROOT / "runs" / f"sepolia_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"{D}====================================================================={X}")
    print(f" Phase 2 comprehensive Sepolia test suite")
    print(f"{D}====================================================================={X}")
    print(f"  rpc      : {args.rpc}")
    print(f"  out_dir  : {out_dir}")

    manifest = {
        "rpc": args.rpc,
        "started_at": ts,
        "gas_used": {},
        "tx_hashes": {},
        "checks": [],
    }

    def check(label: str, ok: bool, detail: str = "") -> bool:
        status = f"{G}OK{X}" if ok else f"{R}FAIL{X}"
        print(f"    {status} {label}{(' [' + detail + ']') if detail else ''}")
        manifest["checks"].append({"label": label, "ok": ok, "detail": detail})
        return ok

    # ---- 0. Connectivity + balance --------------------------------------
    print(f"\n{Y}[0] Connectivity{X}")
    deployer = subprocess.run(["cast", "wallet", "address", "--private-key", pk],
                              capture_output=True, text=True, check=True).stdout.strip()
    print(f"  deployer : {deployer}")
    bal_wei = int(subprocess.run(["cast", "balance", deployer, "--rpc-url", args.rpc],
                                 capture_output=True, text=True, check=True).stdout.strip())
    bal_eth = bal_wei / 1e18
    print(f"  balance  : {bal_eth:.6f} ETH")
    check("balance >= 0.05 ETH", bal_eth >= 0.05, f"{bal_eth:.4f}")

    # ---- 1. Deploy ------------------------------------------------------
    addrs_path = out_dir / "addresses.json"
    if args.skip_deploy and addrs_path.exists():
        addrs = json.loads(addrs_path.read_text())
        print(f"\n{Y}[1] Reusing addresses from {addrs_path}{X}")
    else:
        addrs = deploy(args.rpc, pk, out_dir)
    addrs_path.write_text(json.dumps(addrs, indent=2))

    SHADOW = slot(addrs, "ShadowToken")
    FEAT   = slot(addrs, "FeatureNFT")

    # ---- 2. Mint alice0 -------------------------------------------------
    print(f"\n{Y}[2] mintShadow alice0{X}")
    pi_mint   = parse_pi_file(FIX_MINT / "public_inputs")
    proof_mint = (FIX_MINT / "proof").read_bytes()
    c2_mint    = (FIX_MINT / "c2.bin").read_bytes()

    sid = shadow_id_for_face(pi_mint[8])

    # If shadow already exists (resume after deploy succeeded but later step
    # failed), skip the mint to avoid AlreadyMinted revert.
    existing_owner_raw = subprocess.run(
        ["cast", "call", SHADOW, "ownerOf(uint256)(address)", str(sid),
         "--rpc-url", args.rpc],
        capture_output=True, text=True, timeout=60,
    )
    if existing_owner_raw.returncode == 0 and existing_owner_raw.stdout.strip().startswith("0x") and \
       existing_owner_raw.stdout.strip().split()[0].lower() != "0x0000000000000000000000000000000000000000":
        print(f"    {Y}skip: shadow already exists, owner={existing_owner_raw.stdout.strip().split()[0]}{X}")
    else:
        proof_disc = (FIX_DISC / "proof").read_bytes()
        rcpt = cast_send([
            SHADOW, "mintShadow(bytes,bytes32[],bytes,bytes)",
            "0x" + proof_mint.hex(), hex_array(pi_mint), "0x" + c2_mint.hex(),
            "0x" + proof_disc.hex(),
        ], args.rpc, pk, gas_limit=15_000_000, timeout=900)
        manifest["gas_used"]["mintShadow"]  = rcpt.get("gasUsed")
        manifest["tx_hashes"]["mintShadow"] = rcpt.get("transactionHash")
        print(f"    tx={rcpt.get('transactionHash')}  gas={rcpt.get('gasUsed')}")
    print(f"    shadowId={hex(sid)[:18]}...")

    # ---- 3. Read-back sanity --------------------------------------------
    print(f"\n{Y}[3] Read-back sanity{X}")
    owner_raw = cast_call([SHADOW, "ownerOf(uint256)(address)", str(sid)], args.rpc).split()[0]
    check("ownerOf == deployer", owner_raw.lower() == deployer.lower(),
          f"got {owner_raw}")

    color_raw = cast_call([SHADOW, "shadowOf(uint256)((bytes32,uint8,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,bytes32))", str(sid)],
                           args.rpc)
    # Just confirm the call returns SOMETHING (parsing tuples is messy; check non-empty)
    check("shadowOf returns non-empty", len(color_raw) > 100, f"len={len(color_raw)}")

    for i in range(8):
        op_raw = cast_call([SHADOW, "origPoseOf(uint256,uint8)(uint64)", str(sid), str(i)], args.rpc).split()[0]
        op = int(op_raw)
        cx = op & 0x3F; cy = (op >> 6) & 0x3F
        boxes = pi_mint[9]
        slot_data = (boxes >> (24 * i)) & 0xFFFFFF
        ex = slot_data & 0x3F; ey = (slot_data >> 6) & 0x3F
        check(f"origPose[{i}] curX={cx},curY={cy}", cx == ex and cy == ey,
              f"expected ({ex},{ey})")

    # ---- 4. Mutate slots with various op kinds --------------------------
    print(f"\n{Y}[4] Mutate ORIGINAL slots (translate / scale / rotate){X}")
    # On-frame check uses REGION_W/H (max bounds), so chosen targets must
    # satisfy curX + REGION_W <= 48 AND curY + REGION_H <= 48.
    # REGION_W = [48, 33, 33, 24, 14, 14, 48, 48]
    # REGION_H = [9, 8, 8, 11, 19, 19, 9, 8]
    # Valid (curX, curY) ranges:
    #   slot 0 forehead: x=[0..0],   y=[0..39]
    #   slot 1 eye:      x=[0..15],  y=[0..40]
    #   slot 2 eye:      x=[0..15],  y=[0..40]
    #   slot 3 nose:     x=[0..24],  y=[0..37]
    #   slot 4 cheek:    x=[0..34],  y=[0..29]
    #   slot 5 cheek:    x=[0..34],  y=[0..29]
    #   slot 6 mouth:    x=[0..0],   y=[0..39]
    #   slot 7 chin:     x=[0..0],   y=[0..40]
    poses_to_try = [
        # (slot, label, target_curX, target_curY, scaleQ88, cosQ15, sinQ15)
        (1, "translate to (15, 20)",  15, 20, 256, 32767, 0),
        (2, "translate to (10, 25)",  10, 25, 256, 32767, 0),
        (3, "scale 0.5x at (5, 10)",   5, 10, 128, 32767, 0),
        (4, "scale 1.5x at (20, 10)", 20, 10, 384, 32767, 0),
        (5, "rotate 45deg at (10, 5)", 10,  5, 256, 23170, 23170),
        (3, "translate to (0, 0)",     0,  0, 256, 32767, 0),
        (1, "rotate -45deg at (5, 10)", 5, 10, 256, 23170, -23170 & 0xFFFF),
    ]
    for slot_i, label, target_x, target_y, sc, co, si in poses_to_try:
        new_pose = (target_x | (target_y << 6) | (sc << 12) | (co << 28) | (si << 44)) & ((1 << 60) - 1)
        rcpt = cast_send([
            SHADOW, "mutateSlot(uint256,uint8,uint64)",
            str(sid), str(slot_i), str(new_pose),
        ], args.rpc, pk, gas_limit=200_000, timeout=300)
        # Poll until the chain reflects the new pose (handles RPC stale reads).
        def _pose_matches(out: str) -> bool:
            try:
                fields = out.strip().strip("()").split(",")
                p = int(fields[-1].strip().split()[0])
                return p == new_pose
            except (ValueError, IndexError):
                return False
        out, ok = cast_call_until(
            [SHADOW, "slotOf(uint256,uint8)((uint8,uint8,uint256,uint64))",
             str(sid), str(slot_i)],
            args.rpc, _pose_matches, timeout=60, interval=2.0,
        )
        actual_pose = int(out.strip().strip("()").split(",")[-1].strip().split()[0])
        check(f"slot {slot_i} {label}: pose={hex(new_pose)[:14]}",
              ok and actual_pose == new_pose,
              f"chain={hex(actual_pose)[:14]}, gas={rcpt.get('gasUsed')}")
        manifest["gas_used"][f"mutate_slot_{slot_i}"] = rcpt.get("gasUsed")

    # ---- 5. Mutate revert paths -----------------------------------------
    print(f"\n{Y}[5] Mutate revert paths{X}")
    # Bad scale (0)
    bad_pose = 5 | (5 << 6) | (0 << 12) | (32767 << 28)  # scale=0
    reverted = cast_send_expect_revert([
        SHADOW, "mutateSlot(uint256,uint8,uint64)", str(sid), "1", str(bad_pose),
    ], args.rpc, pk, gas_limit=200_000)
    check("mutate slot 1 with scale=0 reverts", reverted)

    # Off-frame (slot 1 = eye 33x8; curX=20+33=53 > 48)
    off_pose = 20 | (10 << 6) | (256 << 12) | (32767 << 28)
    reverted = cast_send_expect_revert([
        SHADOW, "mutateSlot(uint256,uint8,uint64)", str(sid), "1", str(off_pose),
    ], args.rpc, pk, gas_limit=200_000)
    check("mutate slot 1 off-frame (curX=20 + W=33 > 48) reverts", reverted)

    # Slot out of range (16)
    reverted = cast_send_expect_revert([
        SHADOW, "mutateSlot(uint256,uint8,uint64)", str(sid), "16", str(0),
    ], args.rpc, pk, gas_limit=200_000)
    check("mutate slot 16 (out of range) reverts", reverted)

    # ---- 6. ExtractSlot 3 -> CAROL_ADDR ---------------------------------
    print(f"\n{Y}[6] extractSlot 3 (nose) -> carol{X}")
    pi_extract = parse_pi_file(FIX_EXTRACT / "public_inputs")
    proof_extract = (FIX_EXTRACT / "proof").read_bytes()
    feature_c2 = (FIX_EXTRACT / "feature_c2.bin").read_bytes()

    rcpt = cast_send([
        SHADOW, "extractSlot(uint256,uint8,address,bytes,bytes32[],bytes)",
        str(sid), "3", CAROL_ADDR,
        "0x" + proof_extract.hex(), hex_array(pi_extract), "0x" + feature_c2.hex(),
    ], args.rpc, pk, gas_limit=8_000_000, timeout=600)
    manifest["gas_used"]["extractSlot"]  = rcpt.get("gasUsed")
    manifest["tx_hashes"]["extractSlot"] = rcpt.get("transactionHash")
    print(f"    tx={rcpt.get('transactionHash')}  gas={rcpt.get('gasUsed')}")

    fid = feature_nft_id_for(sid, 3, mint_counter=1)
    out, ok = cast_call_until(
        [FEAT, "ownerOfFeature(uint256)(address)", str(fid)],
        args.rpc, lambda s: s.strip().split()[0].lower() == CAROL_ADDR.lower(),
        timeout=60, interval=2.0,
    )
    fid_owner = out.strip().split()[0]
    check("FeatureNFT minted to carol", ok and fid_owner.lower() == CAROL_ADDR.lower(),
          f"owner={fid_owner}")

    # Slot 3 should be EMPTY now
    raw = cast_call([SHADOW, "slotOf(uint256,uint8)((uint8,uint8,uint256,uint64))",
                     str(sid), "3"], args.rpc)
    # First field (kind) should be 0 (EMPTY)
    kind_str = raw.strip().strip("()").split(",")[0].strip()
    check("slot 3 -> EMPTY post-extract", kind_str == "0", f"kind={kind_str}")

    # ---- 7. Re-extract should revert (slot now EMPTY, not ORIGINAL) -----
    print(f"\n{Y}[7] re-extract slot 3 (EMPTY) should revert{X}")
    reverted = cast_send_expect_revert([
        SHADOW, "extractSlot(uint256,uint8,address,bytes,bytes32[],bytes)",
        str(sid), "3", CAROL_ADDR,
        "0x" + proof_extract.hex(), hex_array(pi_extract), "0x" + feature_c2.hex(),
    ], args.rpc, pk, gas_limit=8_000_000)
    check("re-extract slot 3 reverts", reverted)

    # ---- 7.5 transferFeature carol -> dave -----------------------------
    # carol now owns the FeatureNFT minted in step 6. Test that she can
    # transfer it to dave on chain. Carol's address is a fresh EOA (no
    # EIP-7702 hijacking), so we can fund her with a tiny amount of ETH
    # and have her sign the transferFeature tx.
    print(f"\n{Y}[7.5] transferFeature carol -> dave{X}")
    pi_tfeat = parse_pi_file(FIX_TFEAT / "public_inputs")
    proof_tfeat = (FIX_TFEAT / "proof").read_bytes()
    c2_tfeat = (FIX_TFEAT / "new_c2.bin").read_bytes()

    # Fund carol with 0.0005 ETH (~80x the gas cost at 0.011 gwei)
    print(f"    funding carol ({CAROL_ADDR}) with 0.0005 ETH")
    fund_rcpt = subprocess.run(
        ["cast", "send", CAROL_ADDR, "--value", "0.0005ether",
         "--rpc-url", args.rpc, "--private-key", pk,
         "--gas-limit", "80000", "--json"],
        capture_output=True, text=True, timeout=300,
    )
    if fund_rcpt.returncode != 0:
        print(f"      {R}fund failed:{X} {fund_rcpt.stderr[-200:]}")
        check("fund carol succeeds", False)
    else:
        # Wait until carol's balance is visible (RPC stale-replica guard)
        deadline = time.time() + 60
        carol_bal = 0
        while time.time() < deadline:
            r = subprocess.run(["cast", "balance", CAROL_ADDR, "--rpc-url", args.rpc],
                                capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and int(r.stdout.strip() or "0") > 0:
                carol_bal = int(r.stdout.strip())
                break
            time.sleep(2)
        check("fund carol: balance > 0", carol_bal > 0, f"bal={carol_bal} wei")

        # carol calls transferFeature(featureNftId, dave, proof, pi, newC1X, newC1Y, c2)
        fid = feature_nft_id_for(sid, 3, mint_counter=1)
        rcpt = cast_send([
            FEAT, "transferFeature(uint256,address,bytes,bytes32[],bytes32,bytes32,bytes)",
            str(fid), DAVE_ADDR,
            "0x" + proof_tfeat.hex(), hex_array(pi_tfeat), pi_tfeat[9], pi_tfeat[10], "0x" + c2_tfeat.hex(),
        ], args.rpc, CAROL_SECP_SK, gas_limit=12_000_000, timeout=900)
        manifest["gas_used"]["transferFeature"]  = rcpt.get("gasUsed")
        manifest["tx_hashes"]["transferFeature"] = rcpt.get("transactionHash")
        print(f"    tx={rcpt.get('transactionHash')}  gas={rcpt.get('gasUsed')}")
        out, ok = cast_call_until(
            [FEAT, "ownerOfFeature(uint256)(address)", str(fid)],
            args.rpc, lambda s: s.strip().split()[0].lower() == DAVE_ADDR.lower(),
            timeout=120, interval=3.0,
        )
        feat_owner = out.strip().split()[0]
        check("FeatureNFT owner == dave post-transferFeature",
              ok and feat_owner.lower() == DAVE_ADDR.lower(), f"owner={feat_owner}")
    if args.scenario == "transfer":
        # ---- 8. transferShadow alice -> bob -----------------------------
        print(f"\n{Y}[8] transferShadow alice -> bob (scenario=transfer){X}")
        pi_xfer = parse_pi_file(FIX_TRANSFER / "public_inputs")
        proof_xfer = (FIX_TRANSFER / "proof").read_bytes()
        c2_new = (FIX_TRANSFER / "new_c2.bin").read_bytes()

        rcpt = cast_send([
            SHADOW, "transferShadow(uint256,address,bytes,bytes32[],bytes)",
            str(sid), BOB_ADDR,
            "0x" + proof_xfer.hex(), hex_array(pi_xfer), "0x" + c2_new.hex(),
        ], args.rpc, pk, gas_limit=12_000_000, timeout=900)
        manifest["gas_used"]["transferShadow"]  = rcpt.get("gasUsed")
        manifest["tx_hashes"]["transferShadow"] = rcpt.get("transactionHash")
        print(f"    tx={rcpt.get('transactionHash')}  gas={rcpt.get('gasUsed')}")

        out, ok = cast_call_until(
            [SHADOW, "ownerOf(uint256)(address)", str(sid)],
            args.rpc, lambda s: s.strip().split()[0].lower() == BOB_ADDR.lower(),
            timeout=120, interval=3.0,
        )
        new_owner = out.strip().split()[0]
        check("shadow owner == bob post-transfer", ok and new_owner.lower() == BOB_ADDR.lower(),
              f"owner={new_owner}")
    else:  # scenario == "solve"
        # ---- 8s. solve as deployer (still owns) --------------------------
        print(f"\n{Y}[8s] solve as deployer (scenario=solve){X}")
        pi_solve = parse_pi_file(FIX_SOLVE / "public_inputs")
        proof_solve = (FIX_SOLVE / "proof").read_bytes()
        rcpt = cast_send([
            SHADOW, "solve(uint256,bytes,bytes32[])",
            str(sid), "0x" + proof_solve.hex(), hex_array(pi_solve),
        ], args.rpc, pk, gas_limit=14_000_000, timeout=900)
        manifest["gas_used"]["solve"]  = rcpt.get("gasUsed")
        manifest["tx_hashes"]["solve"] = rcpt.get("transactionHash")
        print(f"    tx={rcpt.get('transactionHash')}  gas={rcpt.get('gasUsed')}")

        # Verify solved=true on chain
        out, ok = cast_call_until(
            [SHADOW, "solved(uint256)(bool)", str(sid)],
            args.rpc, lambda s: "true" in s.lower(),
            timeout=60, interval=2.0,
        )
        check("shadow solved == true", ok, f"isSolved={out.strip()}")

        # Post-solve: transferShadow / mutateSlot / extractSlot must revert (AlreadySolved)
        print(f"\n{Y}[8s.b] post-solve gating reverts{X}")
        # Re-mint same shadow (already minted) -- different revert path, skip here
        # mutate revert
        any_pose = (12 | (12 << 6) | (256 << 12) | (32767 << 28))
        reverted = cast_send_expect_revert([
            SHADOW, "mutateSlot(uint256,uint8,uint64)", str(sid), "0", str(any_pose),
        ], args.rpc, pk, gas_limit=200_000)
        check("post-solve: mutateSlot reverts (AlreadySolved)", reverted)

        # transferShadow revert
        pi_xfer = parse_pi_file(FIX_TRANSFER / "public_inputs")
        proof_xfer = (FIX_TRANSFER / "proof").read_bytes()
        c2_new = (FIX_TRANSFER / "new_c2.bin").read_bytes()
        reverted = cast_send_expect_revert([
            SHADOW, "transferShadow(uint256,address,bytes,bytes32[],bytes)",
            str(sid), BOB_ADDR,
            "0x" + proof_xfer.hex(), hex_array(pi_xfer), "0x" + c2_new.hex(),
        ], args.rpc, pk, gas_limit=12_000_000)
        check("post-solve: transferShadow reverts (AlreadySolved)", reverted)

        # ---- 8s.c plain transferFrom alice -> bob (allowed post-solve) ---
        print(f"\n{Y}[8s.c] post-solve transferFrom alice -> bob{X}")
        rcpt = cast_send([
            SHADOW, "transferFrom(address,address,uint256)",
            "0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F", BOB_ADDR, str(sid),
        ], args.rpc, pk, gas_limit=200_000, timeout=300)
        manifest["gas_used"]["transferFrom_post_solve"]  = rcpt.get("gasUsed")
        manifest["tx_hashes"]["transferFrom_post_solve"] = rcpt.get("transactionHash")
        print(f"    tx={rcpt.get('transactionHash')}  gas={rcpt.get('gasUsed')}")
        out, ok = cast_call_until(
            [SHADOW, "ownerOf(uint256)(address)", str(sid)],
            args.rpc, lambda s: s.strip().split()[0].lower() == BOB_ADDR.lower(),
            timeout=120, interval=3.0,
        )
        new_owner = out.strip().split()[0]
        check("post-solve: shadow owner == bob via plain transferFrom",
              ok and new_owner.lower() == BOB_ADDR.lower(), f"owner={new_owner}")

    # ---- 9. Mint a 2nd shadow attempt (same faceOriginId) MUST revert ---
    print(f"\n{Y}[9] re-mint alice0 (must revert AlreadyMinted){X}")
    proof_disc = (FIX_DISC / "proof").read_bytes()
    reverted = cast_send_expect_revert([
        SHADOW, "mintShadow(bytes,bytes32[],bytes,bytes)",
        "0x" + proof_mint.hex(), hex_array(pi_mint), "0x" + c2_mint.hex(),
        "0x" + proof_disc.hex(),
    ], args.rpc, pk, gas_limit=15_000_000)
    check("re-mint same faceOriginId reverts", reverted)

    # ---- 10. Pixel-equality validation against LIVE chain ---------------
    print(f"\n{Y}[10] Pixel-equality: chain bytes vs Python simulation{X}")
    alice_fix = json.loads((FIX_MINT / "fixture.json").read_text())
    alice_sk = int(alice_fix["witness"]["recipient_sk"], 16)

    # Recompute canonical bytes from Python sim
    color = int(pi_mint[10])
    state = compute_face_state(ALICE_FACE, color)
    canonical_per_region = [bytes(r.recolored) for r in state.regions]
    canonical_concat = b"".join(canonical_per_region)

    # Decrypt the chain-bound mint c2 (which we still have locally as c2_mint;
    # the chain emitted it identically in the ShadowCiphertext event)
    alice_c2 = [int.from_bytes(c2_mint[i*32:(i+1)*32], "big") for i in range(249)]
    plaintext_packed = decrypt_mint_envelope(
        recipient_sk=alice_sk, c1_x=pi_mint[12], c1_y=pi_mint[13], c2=alice_c2,
    )
    recovered_concat = unpack_fields_to_recolored(plaintext_packed)

    check("alice mint: canonical == recovered concat (7716 B)",
          canonical_concat == recovered_concat, f"len={len(recovered_concat)}")

    if args.scenario == "transfer":
        # Decrypt bob's c2 (transfer envelope; uses transfer convention with c2_scalar)
        bob_fix = json.loads((FIX_TRANSFER / "fixture.json").read_text())
        bob_sk = int(bob_fix["bob_sk"], 16)
        bob_c2 = [int.from_bytes(c2_new[i*32:(i+1)*32], "big") for i in range(249)]
        bob_shared = ec_mul((int(bob_fix["c1_new_x"], 16), int(bob_fix["c1_new_y"], 16)), bob_sk)
        bob_k_mask = poseidon2_hash_2(bob_shared[0], bob_shared[1])
        bob_new_k = (int(bob_fix["c2_scalar"], 16) - bob_k_mask) % P
        bob_ks = poseidon2_keystream_249(bob_new_k)
        bob_recovered_packed = [(bob_c2[i] - bob_ks[i]) % P for i in range(249)]
        bob_recovered_concat = unpack_fields_to_recolored(bob_recovered_packed)
        check("bob transfer: canonical == bob's decrypt (byte-equal)",
              canonical_concat == bob_recovered_concat,
              f"diff at {next((i for i in range(7716) if canonical_concat[i] != bob_recovered_concat[i]), -1)}")

    # Decrypt carol's feature c2
    extract_fix = json.loads((FIX_EXTRACT / "fixture.json").read_text())
    carol_sk = int(extract_fix["carol_sk"], 16)
    feature_c2_arr = [int.from_bytes(feature_c2[i*32:(i+1)*32], "big") for i in range(42)]
    carol_shared = ec_mul((int(extract_fix["c1_new_x"], 16), int(extract_fix["c1_new_y"], 16)), carol_sk)
    carol_k_mask = poseidon2_hash_2(carol_shared[0], carol_shared[1])
    carol_feat_k = (int(extract_fix["c2_scalar"], 16) - carol_k_mask) % P
    carol_ks = poseidon2_keystream_42(carol_feat_k)
    carol_payload = [(feature_c2_arr[i] - carol_ks[i]) % P for i in range(42)]
    canonical_payload = list(state.regions[3].packed_padded)
    check("carol extract: canonical packed == carol's decrypt (slot 3 = nose)",
          canonical_payload == carol_payload)

    # ---- 11. Greyscale luminance check ----------------------------------
    print(f"\n{Y}[11] Greyscale luminance check{X}")
    try:
        from PIL import Image
        import numpy as np
        # Render canonical face from Python sim
        canonical_canvas = np.zeros((48, 48, 3), dtype=np.uint8)
        for ftype, region in enumerate(state.regions):
            arr = np.frombuffer(region.recolored, dtype=np.uint8).reshape(region.max_h, region.max_w, 3)
            canonical_canvas[region.y1:region.y1 + region.h, region.x1:region.x1 + region.w, :] = (
                arr[:region.h, :region.w, :]
            )

        # Render recovered face from chain bytes
        recovered_per_region = split_into_regions(recovered_concat)
        recovered_canvas = np.zeros((48, 48, 3), dtype=np.uint8)
        for ftype, (b, region) in enumerate(zip(recovered_per_region, state.regions)):
            arr = np.frombuffer(b, dtype=np.uint8).reshape(region.max_h, region.max_w, 3)
            recovered_canvas[region.y1:region.y1 + region.h, region.x1:region.x1 + region.w, :] = (
                arr[:region.h, :region.w, :]
            )

        # Compare RGB
        rgb_equal = bool(np.array_equal(canonical_canvas, recovered_canvas))
        check("RGB renders byte-equal (canonical vs chain)", rgb_equal)

        # Compute luminance per BT.601: Y = 0.299*R + 0.587*G + 0.114*B
        def luminance(arr):
            R = arr[:, :, 0].astype(np.float32)
            G = arr[:, :, 1].astype(np.float32)
            B = arr[:, :, 2].astype(np.float32)
            return np.clip(0.299 * R + 0.587 * G + 0.114 * B, 0, 255).astype(np.uint8)

        canon_y = luminance(canonical_canvas)
        rec_y   = luminance(recovered_canvas)
        max_diff = int(np.abs(canon_y.astype(int) - rec_y.astype(int)).max())
        check(f"luminance |diff| <= 1 (rounding tolerance)", max_diff <= 1,
              f"max_diff={max_diff}")
        n_diff_pixels = int((np.abs(canon_y.astype(int) - rec_y.astype(int)) > 0).sum())
        check(f"luminance pixel-diff count == 0", n_diff_pixels == 0,
              f"diff_pixels={n_diff_pixels}")

        # Save renders
        Image.fromarray(canonical_canvas).save(out_dir / "canonical_rgb.png")
        Image.fromarray(recovered_canvas).save(out_dir / "recovered_rgb.png")
        Image.fromarray(canon_y).save(out_dir / "canonical_grayscale.png")
        Image.fromarray(rec_y).save(out_dir / "recovered_grayscale.png")
        print(f"    saved 4 PNGs to {out_dir}/")
    except ImportError:
        print(f"    {Y}skip: PIL or numpy not available{X}")

    # ---- 12. Post-state revert checks (deployer no longer owns) ---------
    print(f"\n{Y}[12] Post-state: deployer no longer owns (mutate revert){X}")
    reverted = cast_send_expect_revert([
        SHADOW, "mutateSlot(uint256,uint8,uint64)", str(sid), "5", str(0),
    ], args.rpc, pk, gas_limit=200_000)
    if args.scenario == "transfer":
        check("post-transfer: deployer cannot mutate (NotShadowOwner)", reverted)
    else:
        # post-solve, deployer still owned BEFORE transferFrom; after transferFrom bob owns.
        # Whichever revert reason: must revert.
        check("post-solve+transferFrom: deployer cannot mutate", reverted)

    if args.scenario == "transfer":
        # ---- 13. Solve attempt: bob owns; we can't solve as deployer ----
        print(f"\n{Y}[13] Solve attempt as deployer (bob owns) -> revert{X}")
        pi_solve = parse_pi_file(FIX_SOLVE / "public_inputs")
        proof_solve = (FIX_SOLVE / "proof").read_bytes()
        reverted = cast_send_expect_revert([
            SHADOW, "solve(uint256,bytes,bytes32[])",
            str(sid), "0x" + proof_solve.hex(), hex_array(pi_solve),
        ], args.rpc, pk, gas_limit=8_000_000)
        check("solve as non-owner reverts", reverted)
    else:
        # solve scenario already executed solve. Try again -> AlreadySolved.
        print(f"\n{Y}[13] Re-solve attempt -> revert (AlreadySolved){X}")
        pi_solve = parse_pi_file(FIX_SOLVE / "public_inputs")
        proof_solve = (FIX_SOLVE / "proof").read_bytes()
        reverted = cast_send_expect_revert([
            SHADOW, "solve(uint256,bytes,bytes32[])",
            str(sid), "0x" + proof_solve.hex(), hex_array(pi_solve),
        ], args.rpc, pk, gas_limit=8_000_000)
        check("re-solve reverts", reverted)

    # ---- Final summary --------------------------------------------------
    print(f"\n{D}====================================================================={X}")
    n_pass = sum(1 for c in manifest["checks"] if c["ok"])
    n_fail = sum(1 for c in manifest["checks"] if not c["ok"])
    if n_fail == 0:
        print(f" {G}ALL {n_pass} CHECKS PASS{X}")
    else:
        print(f" {R}{n_fail} FAILED, {n_pass} passed{X}")
    print(f" gas summary:")
    for op, gas in manifest["gas_used"].items():
        if gas:
            try:
                print(f"   {op:25s} {int(gas):>12,d} gas")
            except (TypeError, ValueError):
                print(f"   {op:25s} {gas}")
    print(f" tx hashes:")
    for op, tx in manifest["tx_hashes"].items():
        print(f"   {op:25s} {tx}")
    print(f" out dir: {out_dir}")
    print(f"{D}====================================================================={X}")

    manifest["finished_at"] = int(time.time())
    manifest["addresses"] = addrs
    manifest["n_pass"] = n_pass
    manifest["n_fail"] = n_fail
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
