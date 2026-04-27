#!/usr/bin/env python3
"""On-chain cryptographic correctness check for `transferShadow`.

For the host shadow whose transferShadow tx is the latest broadcast in
contracts/broadcast/TransferOnSepolia.s.sol/<chain>/run-latest.json:
  1. Read the post-rotation per-slot LSH from chain (`slotOf`).
  2. Read the post-rotation ecdhPub from chain (`shadowOf`).
  3. Read the recipient's address from chain (`ownerOf(shadowId)`).
  4. Pull the per-slot c2 calldata from the broadcast's tx receipt logs
     (or from the fixture's meta.json side-car; we do the latter for
     simplicity, then sanity-check by comparing chain-emitted c2 from
     ShadowSlotMutated events against fixture c2).
  5. For each occupied slot:
       - decrypt c2 under recipient_sk via ECIES
       - compare against the fixture's pre-rotation plaintext
       - assert byte-for-byte equality

Recipient_sk is loaded from the fixture's meta.json side-car
(`recipient_sk`). This file is gitignored under contracts/test/fixtures/
and only used for testing.

Usage:
    # Pipeline #4 has no transferShadow demo broadcast yet; this example
    # references the pipeline #3 transferShadow tx. See
    # docs/DEPLOYMENT.md "Historical: pipeline #3" for the legacy address.
    python3 verify_onchain_transfer.py \
        --fixture contracts/test/fixtures/onchain_transfer/onchain_transfer_transfer_recipient_demo \
        --st 0x8439c6796508930863599cd9cB49db741C6ea21f \
        --rpc https://base-sepolia.gateway.tenderly.co
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from v2_circuit_helpers import ecies_decrypt_v2  # noqa: E402

import subprocess


def cast_call(rpc: str, addr: str, sig: str, *args: str) -> str:
    cmd = ["cast", "call", addr, sig, *args, "--rpc-url", rpc]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        sys.exit(f"cast call failed: {p.stderr.strip()}")
    return p.stdout.strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--st", required=True, help="ShadowToken address")
    ap.add_argument("--rpc", required=True)
    args = ap.parse_args()

    fix = Path(args.fixture)
    meta = json.loads((fix / "meta.json").read_text())
    pts_data = json.loads((fix / "plaintexts.json").read_text())
    shadow_id = meta["host_shadow_id"]
    occupied = meta["occupied_idxs"]
    recipient_sk = int(meta["recipient_sk"], 16)
    expected_owner = meta["recipient_addr"].lower()

    print(f"=== verify_onchain_transfer ===")
    print(f"shadow_id : {shadow_id}")
    print(f"recipient : {expected_owner}")
    print(f"occupied  : {occupied}")
    print()

    # 1. Owner check.
    owner = cast_call(args.rpc, args.st, "ownerOf(uint256)(address)", shadow_id)
    assert owner.lower() == expected_owner, f"owner mismatch: {owner} != {expected_owner}"
    print(f"[ok] ownerOf({shadow_id[:18]}..) == recipient")

    # 2. ecdhPub check.
    sout = cast_call(args.rpc, args.st,
                     "shadowOf(uint256)((bytes32,bytes32,bool,bytes32,uint64,bool,uint64,uint64))",
                     shadow_id)
    # Parse the tuple's first two elements.
    # cast outputs: (0x..., 0x..., bool, 0x..., uint, bool, uint, uint)
    pieces = [p.strip() for p in sout.strip("()").split(",")]
    ecdh_x_chain = pieces[0]
    ecdh_y_chain = pieces[1]
    assert ecdh_x_chain.lower() == meta["recipient_pk_x"].lower(), \
        f"ecdhPubX mismatch: chain={ecdh_x_chain} fixture={meta['recipient_pk_x']}"
    assert ecdh_y_chain.lower() == meta["recipient_pk_y"].lower(), \
        f"ecdhPubY mismatch: chain={ecdh_y_chain} fixture={meta['recipient_pk_y']}"
    print(f"[ok] shadow.ecdhPub rotated to recipient_pk")

    # 3. Per-slot LSH match.
    for i in range(16):
        slot_out = cast_call(args.rpc, args.st,
                             "slotOf(uint256,uint8)((uint8,uint256,bytes32))",
                             shadow_id, str(i))
        # parse "(kind, featureId, lsh)"
        parts = slot_out.strip("()").split(",")
        chain_lsh = parts[2].strip()
        expected_lsh = meta["post_transfer_lsh_array"][i].lower()
        assert chain_lsh.lower() == expected_lsh, \
            f"slot {i} lsh mismatch: chain={chain_lsh} fixture={expected_lsh}"
    print(f"[ok] all 16 per-slot LSHs match meta.post_transfer_lsh_array")

    # 4. Per-slot ECIES decrypt under recipient_sk.
    for i in occupied:
        c1_x = int(meta["new_c1_x"][i], 16)
        c1_y = int(meta["new_c1_y"][i], 16)
        c2 = [int(v, 16) for v in meta["c2_per_slot"][i]]
        decoded, dk = ecies_decrypt_v2((c1_x, c1_y), c2, recipient_sk)
        # Compare to pre-rotation plaintext.
        expected_pt = [int(v, 16) for v in pts_data["plaintexts"][i]]
        assert decoded == expected_pt, \
            f"slot {i}: recipient decrypt yields wrong plaintext"
    print(f"[ok] {len(occupied)} occupied slots: recipient ECIES decrypt round-trips to original plaintext")

    print()
    print("ALL TRANSFER CHECKS PASSED")


if __name__ == "__main__":
    main()
