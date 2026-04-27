#!/usr/bin/env python3
"""Recipient extractSlot fixture for shadow B post-mutateBatch.

extractSlot is proofless at the per-slot level. The contract only
requires a fresh T10 proof against the post-extract manifest. So this
builder is a thin wrapper that:

  1. Loads the current chain-state lsh_array for B (post-mutateBatch).
  2. Zeros the target slot.
  3. Computes new T10 = sponge_18([shadow_id, z_commit, *lsh_array]).
  4. Generates a shadow_t10 proof bound to the post-extract values.

Usage:
    python3 tools/build_extract_onchain_b.py --slot 2
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from v2_circuit_helpers import P, fhex, bx32  # noqa: E402
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402
from build_atomic_zindex_fixture import prove  # noqa: E402
from recipient_b_state import load_post_transfer_b_state  # noqa: E402

ROOT = REPO.parent
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_extract_b"


def parse_hex(s: str) -> int:
    s = s.lower()
    return int(s[2:] if s.startswith("0x") else s, 16)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slot", type=int, default=2,
                    help="slot of B to extract (default 2)")
    ap.add_argument("--mutate-batch-fixture",
                    default="onchain_mutate_batch/onchain_mutate_batch_b",
                    help="post-mutateBatch fixture providing the post-batch "
                         "lsh_array; use empty string to start from "
                         "post-transfer state directly.")
    ap.add_argument("--out-seed", default="onchain_extract_b_slot2")
    ap.add_argument("--z-commit", default=None,
                    help="override the z_index_commit (hex). Default: read "
                         "from chain-state via the prior fixtures (0 unless "
                         "setZIndex has run).")
    args = ap.parse_args()

    # Start from the recipient's current view of B, then overlay any
    # mutateBatch state if provided.
    state = load_post_transfer_b_state()
    lsh_array = list(state["lsh_array"])

    if args.mutate_batch_fixture:
        mb_path = ROOT / "contracts" / "test" / "fixtures" / args.mutate_batch_fixture / "meta.json"
        if not mb_path.exists():
            sys.exit(f"mutateBatch fixture not found: {mb_path}")
        mb = json.loads(mb_path.read_text())
        lsh_array = [parse_hex(v) for v in mb["post_batch_lsh_array"]]

    if state["slot_state"][args.slot] is None and lsh_array[args.slot] == 0:
        sys.exit(f"slot {args.slot} is EMPTY; nothing to extract")

    # Post-extract: zero the target slot.
    lsh_array[args.slot] = 0

    z_commit = state["z_index_commit"]
    if args.z_commit is not None:
        z_commit = parse_hex(args.z_commit)

    shadow_id = state["shadow_id"]

    print(f"[onchain_extract_b] slot={args.slot} z_commit={hex(z_commit)[:18]}...")
    print(f"  shadow_id   = {hex(shadow_id)[:18]}...")
    for i, v in enumerate(lsh_array):
        marker = " <- extracted (zero)" if i == args.slot else ""
        print(f"  lsh[{i:2d}] = {hex(v)[:18]}...{marker}")

    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"  post-extract t10 hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    proof_t10, pi_t10 = prove(T10_DIR, "shadow_t10.json")

    fix_dir = FIXTURE_ROOT / args.out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)
    (fix_dir / "meta.json").write_text(json.dumps({
        "kind": "onchain_extract_b",
        "shadow_id": bx32(shadow_id),
        "slot_extracted": args.slot,
        "z_commit": bx32(z_commit),
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "post_extract_lsh_array": [bx32(v) for v in lsh_array],
    }, indent=2))
    print(f"[wrote] {fix_dir}/")


if __name__ == "__main__":
    main()
