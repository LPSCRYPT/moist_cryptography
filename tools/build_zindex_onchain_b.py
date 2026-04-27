#!/usr/bin/env python3
"""Recipient setZIndexCommit fixture for shadow B post-mutateBatch + post-extract.

setZIndexCommit takes one zindex_commit proof + one T10 refresh. The
proof is chain-state-INDEPENDENT (binds only shadowId + newCommit; no
lsh array). The T10 binds the post-zindex manifest; lsh_array does not
change at zindex, only z_index_commit changes.

Usage:
    python3 tools/build_zindex_onchain_b.py
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
from build_atomic_zindex_fixture import (  # noqa: E402
    sponge_16, deterministic_perm, prove,
)
from recipient_b_state import load_post_transfer_b_state  # noqa: E402

ROOT = REPO.parent
ZIDX_DIR = ROOT / "circuits" / "zindex_commit"
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_zindex_b"


def parse_hex(s: str) -> int:
    s = s.lower()
    return int(s[2:] if s.startswith("0x") else s, 16)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="zidx_recipient_b_demo",
                    help="seed for the deterministic permutation")
    ap.add_argument("--mutate-batch-fixture",
                    default="onchain_mutate_batch/onchain_mutate_batch_b")
    ap.add_argument("--extract-fixture",
                    default="onchain_extract_b/onchain_extract_b_slot2")
    ap.add_argument("--out-seed", default=None)
    args = ap.parse_args()

    # Build current lsh array: post-transfer + post-batch + post-extract.
    state = load_post_transfer_b_state()
    lsh_array = list(state["lsh_array"])

    mb_path = ROOT / "contracts" / "test" / "fixtures" / args.mutate_batch_fixture / "meta.json"
    if mb_path.exists():
        mb = json.loads(mb_path.read_text())
        lsh_array = [parse_hex(v) for v in mb["post_batch_lsh_array"]]

    ex_path = ROOT / "contracts" / "test" / "fixtures" / args.extract_fixture / "meta.json"
    if ex_path.exists():
        ex = json.loads(ex_path.read_text())
        lsh_array = [parse_hex(v) for v in ex["post_extract_lsh_array"]]

    shadow_id = state["shadow_id"]
    print(f"[onchain_zindex_b] seed={args.seed!r}")
    print(f"  shadow_id = {hex(shadow_id)[:18]}...")
    for i, v in enumerate(lsh_array):
        if v == 0:
            continue
        print(f"  lsh[{i:2d}]  = {hex(v)[:18]}...")

    # ---- z-commit proof ----
    perm = deterministic_perm(args.seed.encode())
    z_commit = sponge_16(perm)
    print(f"[1/2] perm     = {perm}")
    print(f"      z_commit = {hex(z_commit)[:18]}...")
    (ZIDX_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"new_z_commit = {fhex(z_commit)}\n"
        f"perm = [{', '.join(fhex(v) for v in perm)}]\n"
    )
    proof_z, pi_z = prove(ZIDX_DIR, "zindex_commit.json")

    # ---- T10 with new z_commit, lsh_array unchanged ----
    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[2/2] post-zindex t10 hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")
    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    proof_t10, pi_t10 = prove(T10_DIR, "shadow_t10.json")

    out_seed = args.out_seed or f"onchain_zindex_b_{args.seed}"
    fix_dir = FIXTURE_ROOT / out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_z.bin").write_bytes(proof_z)
    (fix_dir / "public_inputs_z.bin").write_bytes(pi_z)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)
    (fix_dir / "meta.json").write_text(json.dumps({
        "kind":      "onchain_zindex_b",
        "seed":      args.seed,
        "shadow_id": bx32(shadow_id),
        "z_commit":  bx32(z_commit),
        "perm":      perm,
        "t10_hi":    bx32(hi),
        "t10_lo":    bx32(lo),
        "lsh_array": [bx32(v) for v in lsh_array],
    }, indent=2))
    print(f"[wrote] {fix_dir}/")


if __name__ == "__main__":
    main()
