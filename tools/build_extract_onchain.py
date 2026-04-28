#!/usr/bin/env python3
"""Generate a chained extractSlot T10 proof against the live state of
any shadow.

extractSlot is structurally proofless at the per-slot level (no
mutate-style proof; carrier custody return is enforced by ownership +
single-host invariants). The contract only requires a fresh T10 proof
that covers the POST-EXTRACT manifest. This builder is a T10-only
proof builder bound to the post-extract lsh_array (mint state + any
pre-mutated overrides + the target slot zeroed).

Generic across pipelines: pass any number of `--pre-mutated-fixture`
paths to splice in single-slot or batch mutate updates onto the
otherwise mint-state lsh_array.

Inputs:
    --mint-fixture
    --slot                  slot to extract
    --z-commit              current chain-stored zIndexCommit
                            (hex; default 0 = setZIndex hasn't run)
    --pre-mutated-fixture   path to a single-slot mutate fixture
                            (slot_idx + new_lsh) OR a mutate_batch
                            fixture (slot_a + slot_b new_lshs).
                            Pass multiple times.
    --out-seed
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

ROOT = REPO.parent
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_extract"


def parse_hex(s: str) -> int:
    s = s.lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)


def overrides_from_fixture(fix: Path) -> dict[int, int]:
    """Extract {slot: new_lsh} from either a single-slot or batch fixture."""
    meta = json.loads((fix / "meta.json").read_text())
    out: dict[int, int] = {}
    kind = meta.get("kind", "")
    if kind == "onchain_mutate":
        slot = meta["slot_idx"]
        out[slot] = parse_hex(meta["new_lsh"])
    elif kind in ("onchain_mutate_batch", "onchain_mutate_batch_b"):
        for key in ("slot_a", "slot_b"):
            entry = meta[key]
            out[entry["slot_idx"]] = parse_hex(entry["new_lsh"])
    else:
        sys.exit(f"unsupported fixture kind {kind!r} at {fix}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mint-fixture", required=True)
    ap.add_argument("--slot", type=int, required=True,
                    help="slot to extract")
    ap.add_argument("--z-commit", default="0",
                    help="current chain-stored zIndexCommit (hex)")
    ap.add_argument("--pre-mutated-fixture", action="append", default=[],
                    help="Single-slot or batch mutate fixture whose new_lsh "
                         "overrides should be spliced into the pre-extract "
                         "lsh_array. Pass multiple times.")
    ap.add_argument("--out-seed", required=True)
    args = ap.parse_args()

    mint_fix = Path(args.mint_fixture)
    mint_meta = json.loads((mint_fix / "meta.json").read_text())
    image_commit = int(mint_meta["image_commit"], 16)
    shadow_id = image_commit % P
    mint_lsh_inits = [int(x, 16) for x in mint_meta["lsh_inits"]]

    # Build PRE-extract lsh_array: mint state + pre-mutated overrides.
    lsh_array = list(mint_lsh_inits) + [0] * 8

    for fix_path in args.pre_mutated_fixture:
        ov = overrides_from_fixture(Path(fix_path))
        for slot, new_lsh in ov.items():
            lsh_array[slot] = new_lsh
            print(f"  pre-mutated override: slot {slot} lsh = {hex(new_lsh)[:18]}...")

    # POST-extract: zero out the target slot.
    pre_extract_lsh = lsh_array[args.slot]
    lsh_array[args.slot] = 0

    z_commit = parse_hex(args.z_commit)

    print(f"[onchain_extract] slot={args.slot} z_commit={hex(z_commit)[:18]}...")
    print(f"  shadow_id   = {hex(shadow_id)[:18]}...")
    for i, v in enumerate(lsh_array):
        marker = " <- extracted (zero)" if i == args.slot else ""
        print(f"  lsh[{i:2d}] = {hex(v)[:18]}...{marker}")

    # ---- T10 proof against post-extract manifest ----
    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"  post-extract t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

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
        "kind": "onchain_extract",
        "shadow_id": bx32(shadow_id),
        "slot_extracted": args.slot,
        "pre_extract_slot_lsh": bx32(pre_extract_lsh),
        "z_commit": bx32(z_commit),
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "post_extract_lsh_array": [bx32(v) for v in lsh_array],
        "pre_mutated_fixtures": args.pre_mutated_fixture,
    }, indent=2))
    print(f"[wrote] {fix_dir}/")


if __name__ == "__main__":
    main()
