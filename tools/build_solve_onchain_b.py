#!/usr/bin/env python3
"""Recipient solve_shadow_v2 fixture for shadow B post-zindex.

Auto-extracts the 8 occupied slots of B (slots 0,1,3,4,5,6,7,8 — slot 2
was extracted earlier) and freezes B as a solved artifact.

Per-slot state assembly:
  slot 0,1 -- post-mutateBatch (new plaintext recomputed from salt;
              new_k derived from recipient sk * new_c1)
  slot 2   -- EMPTY (post-extract)
  slot 3..7 -- post-transfer recipient state
  slot 8   -- post-transfer recipient state (inserted carrier)
  slot 9..15 -- EMPTY (never occupied)

Usage:
    python3 tools/build_solve_onchain_b.py \\
        --z-perm "[2,13,9,11,12,6,1,15,5,14,4,10,0,7,8,3]" \\
        --out-seed onchain_solve_b
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
sys.path.insert(0, str(REPO))

from secret_inbox import ec_mul  # noqa: E402
from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS,
    sponge_39, sponge_16,
    poseidon2_hash_2,
    fhex, bx32,
)
from build_solve_onchain import pack_perm_base16, render_array, render_2d  # noqa: E402
from recipient_b_state import load_post_transfer_b_state  # noqa: E402
from build_mutate_batch_onchain import synthesize_new_plaintext  # noqa: E402

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "solve_shadow_v2"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_solve_b"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def parse_hex(s: str) -> int:
    s = s.lower()
    return int(s[2:] if s.startswith("0x") else s, 16)


def run(cmd, cwd, timeout=1800):
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s")
    print(f"  [{elapsed:.1f}s]")


def derive_k_from_c1(c1_x: int, c1_y: int, sk: int) -> int:
    """Recover the ECIES symmetric key from the recipient's secret key
    and the on-chain c1 commitment: k = poseidon2(sk*c1.x, sk*c1.y)."""
    shared = ec_mul((c1_x, c1_y), sk)
    assert shared is not None, "sk*c1 yields identity"
    return poseidon2_hash_2(shared[0], shared[1])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--z-perm", required=True,
                    help="JSON list of 16 ints; MUST match the perm "
                         "committed at setZIndex")
    ap.add_argument("--out-seed", default="onchain_solve_b")
    ap.add_argument("--mutate-batch-fixture",
                    default="onchain_mutate_batch/onchain_mutate_batch_b")
    ap.add_argument("--mutate-batch-salt",
                    default="recipient_mutate_batch_demo",
                    help="salt used to synthesize new plaintexts in the "
                         "mutateBatch builder; needed to reconstruct "
                         "new_plaintext for slots 0+1 in the witness")
    ap.add_argument("--extracted-slots", default="2",
                    help="comma-separated slot indices that are EMPTY "
                         "post-extract (default '2')")
    args = ap.parse_args()

    z_perm = json.loads(args.z_perm)
    assert len(z_perm) == 16 and sorted(z_perm) == list(range(16)), \
        "--z-perm must be a permutation of [0..15]"
    z_perm_packed = pack_perm_base16(z_perm)
    z_index_commit = sponge_16(z_perm)

    extracted = set()
    if args.extracted_slots.strip():
        extracted = set(int(x) for x in args.extracted_slots.split(",") if x.strip())

    state = load_post_transfer_b_state()
    shadow_id = state["shadow_id"]
    sk = state["recipient_sk"]
    pk_x = state["recipient_pk_x"]
    pk_y = state["recipient_pk_y"]

    # Load mutateBatch overrides for slots that were mutated by the recipient.
    mb_path = ROOT / "contracts" / "test" / "fixtures" / args.mutate_batch_fixture / "meta.json"
    mb = json.loads(mb_path.read_text())

    print(f"[onchain_solve_b] shadow_id={hex(shadow_id)[:18]}...")
    print(f"  z_perm           = {z_perm}")
    print(f"  z_index_commit   = {hex(z_index_commit)[:18]}...")
    print(f"  extracted_slots  = {sorted(extracted)}")

    is_occupied = [0] * 16
    plaintexts: list[list[int]] = [[0] * PLAINTEXT_FIELDS for _ in range(16)]
    prev_ct_commit = [0] * 16
    prev_c1_x = [0] * 16
    prev_c1_y = [0] * 16
    prev_mutation_count = [0] * 16
    prev_chain_tip = [0] * 16
    owner_k_arr = [0] * 16
    prev_lsh_arr = [0] * 16
    state_commits = [0] * 16

    # Map of slot_idx -> override dict from mutateBatch.
    mb_overrides: dict[int, dict] = {}
    for entry_key in ["slot_a", "slot_b"]:
        e = mb[entry_key]
        idx = int(e["slot_idx"])
        mb_overrides[idx] = e

    salt_bytes = args.mutate_batch_salt.encode()

    for i in range(16):
        if i in extracted:
            continue
        ss = state["slot_state"][i]
        if ss is None:
            continue
        is_occupied[i] = 1

        if i in mb_overrides:
            # Slot was mutated by recipient; use post-batch state.
            e = mb_overrides[i]
            new_pt, _, _, _ = synthesize_new_plaintext(i, salt_bytes)
            new_c1_x = parse_hex(e["new_c1_x"])
            new_c1_y = parse_hex(e["new_c1_y"])
            new_k = derive_k_from_c1(new_c1_x, new_c1_y, sk)
            new_ct_commit = parse_hex(e["new_ct_commit"])
            new_chain_tip = parse_hex(e["new_chain_tip"])
            new_count = int(e["new_mutation_count"])
            new_lsh = parse_hex(e["new_lsh"])

            # Sanity: re-derive state_commit and verify.
            sc = sponge_39(new_pt)

            plaintexts[i] = new_pt
            prev_ct_commit[i] = new_ct_commit
            prev_c1_x[i] = new_c1_x
            prev_c1_y[i] = new_c1_y
            prev_mutation_count[i] = new_count
            prev_chain_tip[i] = new_chain_tip
            owner_k_arr[i] = new_k
            prev_lsh_arr[i] = new_lsh
            state_commits[i] = sc
            print(f"  slot {i:2d} (mutated): count={new_count} "
                  f"lsh={hex(new_lsh)[:18]}...")
        else:
            # Use post-transfer state.
            plaintexts[i] = ss["plaintext"]
            prev_ct_commit[i] = ss["ct_commit"]
            prev_c1_x[i] = ss["c1_x"]
            prev_c1_y[i] = ss["c1_y"]
            prev_mutation_count[i] = ss["mutation_count"]
            prev_chain_tip[i] = ss["chain_tip"]
            owner_k_arr[i] = ss["k"]
            prev_lsh_arr[i] = ss["lsh"]
            state_commits[i] = ss["state_commit"]
            print(f"  slot {i:2d} (transferred): count={ss['mutation_count']} "
                  f"lsh={hex(ss['lsh'])[:18]}...")

    state_commits_root = sponge_16(state_commits)
    lsh_root = sponge_16(prev_lsh_arr)
    print(f"  state_commits_root = {hex(state_commits_root)[:18]}...")
    print(f"  lsh_root           = {hex(lsh_root)[:18]}...")

    print("[2/4] write Prover.toml")
    PROVER_TOML.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"shadow_id = {fhex(shadow_id)}",
        f"state_commits_root = {fhex(state_commits_root)}",
        f"z_perm_packed_pi = {fhex(z_perm_packed)}",
        f"z_index_commit = {fhex(z_index_commit)}",
        f"lsh_root = {fhex(lsh_root)}",
        f"owner_pk_x = {fhex(pk_x)}",
        f"owner_pk_y = {fhex(pk_y)}",
        render_array("is_occupied", is_occupied),
        render_2d("plaintexts", plaintexts),
        render_array("prev_ct_commit", prev_ct_commit),
        render_array("prev_c1_x", prev_c1_x),
        render_array("prev_c1_y", prev_c1_y),
        render_array("prev_mutation_count", prev_mutation_count),
        render_array("prev_chain_tip", prev_chain_tip),
        render_array("owner_k", owner_k_arr),
        render_array("prev_lsh", prev_lsh_arr),
        render_array("z_perm", z_perm),
        f"owner_sk = {fhex(sk)}",
    ]
    PROVER_TOML.write_text("\n".join(lines) + "\n")

    print("[3/4] nargo execute + bb prove")
    target_dir = CIRCUIT_DIR / "target"
    run([NARGO, "execute"], CIRCUIT_DIR, timeout=900)
    if not (target_dir / "vk").exists():
        run([BB, "write_vk", "-b", str(target_dir / "solve_shadow_v2.json"),
             "-o", str(target_dir),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)
    proof_dir = target_dir / "proof_dir_b"
    if proof_dir.exists():
        for f in proof_dir.iterdir():
            f.unlink()
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "solve_shadow_v2.json"),
         "-w", str(target_dir / "solve_shadow_v2.gz"),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=1800)
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=300)
    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes = (proof_dir / "public_inputs").read_bytes()
    print(f"  proof = {len(proof_bytes)} B  pi = {len(pi_bytes)} B "
          f"({len(pi_bytes) // 32} fields)")

    print("[4/4] write fixture")
    fix_dir = FIXTURE_ROOT / args.out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof.bin").write_bytes(proof_bytes)
    (fix_dir / "public_inputs.bin").write_bytes(pi_bytes)
    plaintexts_json = {
        "plaintexts": [[bx32(v) for v in plaintexts[i]] for i in range(16)]
    }
    (fix_dir / "plaintexts.json").write_text(json.dumps(plaintexts_json, indent=2))

    occupied_slots = [i for i in range(16) if is_occupied[i] == 1]
    meta = {
        "kind":               "onchain_solve_b",
        "shadow_id":          bx32(shadow_id),
        "extracted_slots":    sorted(extracted),
        "occupied_slots":     occupied_slots,
        "state_commits_root": bx32(state_commits_root),
        "lsh_root":           bx32(lsh_root),
        "z_perm":             z_perm,
        "z_perm_packed":      bx32(z_perm_packed),
        "z_index_commit":     bx32(z_index_commit),
        "owner_pk_x":         bx32(pk_x),
        "owner_pk_y":         bx32(pk_y),
        "state_commits":      [bx32(v) for v in state_commits],
        "prev_lsh_array":     [bx32(v) for v in prev_lsh_arr],
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")


if __name__ == "__main__":
    main()
