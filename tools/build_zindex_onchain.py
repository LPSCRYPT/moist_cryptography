#!/usr/bin/env python3
"""Generate a chained setZIndexCommit + shadow_t10 fixture against
the live state of shadow A on Base Sepolia.

Differences from build_atomic_zindex_fixture.py:
  - Builds the post-zindex T10 against the FULL on-chain manifest array
    (slot 0 has the post-mutate lsh, slots 1..7 retain mint lsh_inits,
    slots 8..15 are zero) -- not the synthetic single-slot array the
    standalone builder uses.
  - shadow_id, mint state derive from the atomic_mint fixture.

Inputs:
    --mint-fixture     atomic_mint fixture dir (provides image_commit,
                       lsh_inits[0..7])
    --slot0-new-lsh    REQUIRED if slot 0 has been mutated; this is the
                       post-mutate liveStateHash to bind T10 against.
                       Provide hex (with or without 0x).
    --seed             seed for picking the deterministic permutation
                       (default zidx_onchain_demo)
    --out-seed         output dir name

Output:
    contracts/test/fixtures/onchain_zindex/<out_seed>/
        proof_z.bin
        public_inputs_z.bin
        proof_t10.bin
        public_inputs_t10.bin
        meta.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from secret_inbox import poseidon2_state  # noqa: E402
from v2_circuit_helpers import P, fhex, bx32  # noqa: E402
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402
from build_atomic_zindex_fixture import (  # noqa: E402
    sponge_16, deterministic_perm, prove,
)

ROOT = REPO.parent
ZIDX_DIR = ROOT / "circuits" / "zindex_commit"
T10_DIR  = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_zindex"


def parse_hex(s: str) -> int:
    s = s.lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mint-fixture", required=True,
                    help="atomic_mint fixture (provides image_commit + shadow_id)")
    ap.add_argument("--slot0-new-lsh", default=None,
                    help="DEPRECATED legacy flag for slot-0 mutate; use --lsh-array instead")
    ap.add_argument("--lsh-array", default=None,
                    help="JSON list of 16 hex strings; the FULL post-state lsh array "
                         "(empty slots = '0x0'). Overrides --slot0-new-lsh entirely.")
    ap.add_argument("--seed", default="zidx_onchain_demo")
    ap.add_argument("--out-seed", default=None)
    args = ap.parse_args()

    mint_fix = Path(args.mint_fixture)
    with open(mint_fix / "meta.json") as f:
        mint_meta = json.load(f)
    image_commit = int(mint_meta["image_commit"], 16)
    shadow_id = image_commit % P

    # Build current lsh array.
    if args.lsh_array is not None:
        lsh_in = json.loads(args.lsh_array)
        if not (isinstance(lsh_in, list) and len(lsh_in) == 16):
            sys.exit("--lsh-array must be a 16-element JSON list of hex strings")
        lsh_array = [parse_hex(s) if isinstance(s, str) else int(s) for s in lsh_in]
        print(f"[onchain_zindex] seed={args.seed!r}  (lsh-array supplied)")
    else:
        mint_lsh_inits = [int(x, 16) for x in mint_meta["lsh_inits"]]
        assert len(mint_lsh_inits) == 8
        lsh_array = list(mint_lsh_inits) + [0] * 8
        if args.slot0_new_lsh is not None:
            lsh_array[0] = parse_hex(args.slot0_new_lsh)
        print(f"[onchain_zindex] seed={args.seed!r}  (mint-state baseline)")
    print(f"  shadow_id     = {hex(shadow_id)[:18]}...")
    for i, v in enumerate(lsh_array):
        if v != 0:
            print(f"  lsh[{i:2d}]       = {hex(v)[:18]}...")
    # ---- z-commit proof ----
    seed_bytes = args.seed.encode()
    perm = deterministic_perm(seed_bytes)
    z_commit = sponge_16(perm)
    print(f"[1/2] perm  = {perm}")
    print(f"      z_commit = {hex(z_commit)[:18]}...")
    (ZIDX_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"new_z_commit = {fhex(z_commit)}\n"
        f"perm = [{', '.join(fhex(v) for v in perm)}]\n"
    )
    proof_z, pi_z = prove(ZIDX_DIR, "zindex_commit.json")

    # ---- T10 against post-zindex manifest (lsh_array unchanged, z_commit changed) ----
    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[2/2] post-zindex t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")
    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    proof_t10, pi_t10 = prove(T10_DIR, "shadow_t10.json")

    # ---- write fixture ----
    out_seed = args.out_seed or f"onchain_zindex_{args.seed}"
    fix_dir = FIXTURE_ROOT / out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_z.bin").write_bytes(proof_z)
    (fix_dir / "public_inputs_z.bin").write_bytes(pi_z)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)
    (fix_dir / "meta.json").write_text(json.dumps({
        "kind": "onchain_zindex",
        "seed": args.seed,
        "shadow_id": bx32(shadow_id),
        "z_commit": bx32(z_commit),
        "perm": perm,
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "lsh_array": [bx32(v) for v in lsh_array],
    }, indent=2))
    print(f"[wrote] {fix_dir}/")


if __name__ == "__main__":
    main()
