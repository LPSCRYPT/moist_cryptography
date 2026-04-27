#!/usr/bin/env python3
"""Generate a *linked* mutateBatch fixture: 2 mutate_slot proofs +
1 shadow_t10 proof against the post-batch manifest.

Tests the v2 ShadowToken.mutateBatch path. Two slots of the same shadow
are mutated in one tx; the T10 proof binds the manifest AFTER both
writes have landed, mirroring what _refreshT10Atomically constructs
from chain state at end of batch.

Each mutate_slot proof is independent: PI[6] (old_lsh) for slot A is
the chain's slot[A].liveStateHash before the batch starts, and PI[7]
is the new_lsh for slot A. Same for slot B. The proofs do not interact
in-circuit; they're verified sequentially by the contract loop, which
applies each write before reading the next slot's old_lsh.

Output:
    contracts/test/fixtures/atomic_mutate_batch/<seed>/
        proof_mut_a.bin, public_inputs_mut_a.bin   (slot 3 mutate)
        proof_mut_b.bin, public_inputs_mut_b.bin   (slot 5 mutate)
        proof_t10.bin, public_inputs_t10.bin        (post-batch T10)
        c2_a.bin, c2_b.bin                          (per-slot c2 calldata)
        meta.json                                   (everything the test reads)

Usage:
    python3 build_atomic_mutate_batch_fixture.py [--seed atomic_mutate_batch_demo]
                                                  [--slot-a 3] [--slot-b 5]
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

from build_mutate_slot_fixture import (  # noqa: E402
    build_witness as build_mutate_witness,
    write_prover_toml as write_mut_toml,
)
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402
from v2_circuit_helpers import P, fhex, bx32  # noqa: E402

ROOT = REPO.parent
MUT_DIR = ROOT / "circuits" / "mutate_slot"
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "atomic_mutate_batch"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def run(cmd: list, cwd: Path, timeout: int = 600) -> str:
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {time.time()-started:.1f}s")
    return p.stdout


def prove_mutate(seed: bytes, slot_idx: int, label: bytes) -> tuple[bytes, bytes, dict]:
    """Run mutate_slot for one slot. Returns (proof_bytes, pi_bytes, witness_dict)."""
    print(f"[mutate slot={slot_idx} label={label!r}] build witness")
    w = build_mutate_witness(seed, slot_idx=slot_idx, witness_label=label)
    write_mut_toml(w)
    print(f"[mutate slot={slot_idx}] nargo execute + bb prove")
    run([NARGO, "execute"], MUT_DIR, timeout=600)
    target = MUT_DIR / "target"
    # vk + prove (re-derive vk per call because Prover.toml changes the witness file)
    # vk is constant for the same circuit, so we only need one write_vk run total.
    if not (target / "vk").exists():
        run([BB, "write_vk", "-b", str(target / "mutate_slot.json"),
             "-o", str(target),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=900)
    proof_dir = target / f"proof_dir_{slot_idx}"
    if proof_dir.exists():
        # Clean stale proof dir to avoid bb conflicts.
        for f in proof_dir.iterdir():
            f.unlink()
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target / "mutate_slot.json"),
         "-w", str(target / "mutate_slot.gz"),
         "-o", str(proof_dir),
         "-k", str(target / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=1800)
    run([BB, "verify",
         "-k", str(target / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=300)
    proof = (proof_dir / "proof").read_bytes()
    pi    = (proof_dir / "public_inputs").read_bytes()
    return proof, pi, w


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="atomic_mutate_batch_demo")
    ap.add_argument("--slot-a", type=int, default=3)
    ap.add_argument("--slot-b", type=int, default=5)
    args = ap.parse_args()
    if args.slot_a == args.slot_b:
        sys.exit("slot-a and slot-b must differ for mutateBatch")

    seed = args.seed.encode()
    print(f"[atomic_mutate_batch fixture] seed={args.seed!r} slots=[{args.slot_a}, {args.slot_b}]")

    # ---- 1. mutate proof for slot A ----
    proof_a, pi_a, w_a = prove_mutate(seed, args.slot_a, b":slot_a")
    # ---- 2. mutate proof for slot B (same shadow, different slot) ----
    proof_b, pi_b, w_b = prove_mutate(seed, args.slot_b, b":slot_b")

    # Sanity: both proofs share the same shadow_id (ensures shadow-level
    # binding in PI[0] is consistent so the contract test seeds one
    # shadow + 2 slots).
    assert w_a["shadow_id"] == w_b["shadow_id"], "fixtures generated different shadow_ids"
    assert w_a["owner_pk_x"] == w_b["owner_pk_x"], "owner pk diverged across slots"

    shadow_id = w_a["shadow_id"]
    z_commit = 0

    # ---- 3. shadow_t10 against post-batch manifest ----
    # Slots in the test setup: slot_a + slot_b OCCUPIED with their
    # witnessed prev_lsh values; rest EMPTY (lsh = 0). After the batch:
    # slot_a -> w_a["new_lsh"], slot_b -> w_b["new_lsh"].
    lsh_array = [0] * 16
    lsh_array[args.slot_a] = w_a["new_lsh"]
    lsh_array[args.slot_b] = w_b["new_lsh"]

    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[T10] post-batch hi=0x{hi:032x} lo=0x{lo:032x}")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    run([NARGO, "execute"], T10_DIR, timeout=300)
    target_t10 = T10_DIR / "target"
    if not (target_t10 / "vk").exists():
        run([BB, "write_vk", "-b", str(target_t10 / "shadow_t10.json"),
             "-o", str(target_t10),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    proof_dir_t10 = target_t10 / "proof_dir"
    if proof_dir_t10.exists():
        for f in proof_dir_t10.iterdir():
            f.unlink()
    proof_dir_t10.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_t10 / "shadow_t10.json"),
         "-w", str(target_t10 / "shadow_t10.gz"),
         "-o", str(proof_dir_t10),
         "-k", str(target_t10 / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    run([BB, "verify",
         "-k", str(target_t10 / "vk"),
         "-p", str(proof_dir_t10 / "proof"),
         "-i", str(proof_dir_t10 / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=300)
    proof_t10 = (proof_dir_t10 / "proof").read_bytes()
    pi_t10    = (proof_dir_t10 / "public_inputs").read_bytes()

    # ---- 4. write fixture ----
    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_mut_a.bin").write_bytes(proof_a)
    (fix_dir / "public_inputs_mut_a.bin").write_bytes(pi_a)
    (fix_dir / "proof_mut_b.bin").write_bytes(proof_b)
    (fix_dir / "public_inputs_mut_b.bin").write_bytes(pi_b)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)

    c2_a_bytes = b"".join(c.to_bytes(32, "big") for c in w_a["new_c2"])
    c2_b_bytes = b"".join(c.to_bytes(32, "big") for c in w_b["new_c2"])
    (fix_dir / "c2_a.bin").write_bytes(c2_a_bytes)
    (fix_dir / "c2_b.bin").write_bytes(c2_b_bytes)

    def w_meta(w: dict) -> dict:
        return {
            "slot_idx": w["slot_idx"],
            "feature_id": bx32(w["feature_id"]),
            "type_idx": w["type_idx"],
            "origin_face_id": bx32(w["origin_face_id"]),
            "palette_commit": bx32(w["palette_commit"]),
            "old_lsh": bx32(w["old_lsh"]),
            "new_lsh": bx32(w["new_lsh"]),
            "new_ct_commit": bx32(w["new_ct_commit"]),
            "new_c1_x": bx32(w["new_c1_x"]),
            "new_c1_y": bx32(w["new_c1_y"]),
            "prev_chain_tip": bx32(w["old_chain_tip"]),
            "new_chain_tip": bx32(w["new_chain_tip"]),
            "prev_mutation_count": w["prev_mutation_count"],
            "new_mutation_count": w["new_mutation_count"],
            "c2_field_count": w["c2_field_count"],
        }

    meta = {
        "seed": args.seed,
        "shadow_id": bx32(shadow_id),
        "owner_pk_x": bx32(w_a["owner_pk_x"]),
        "owner_pk_y": bx32(w_a["owner_pk_y"]),
        "owner_sk":   bx32(w_a["owner_sk"]),
        "z_index_commit": "0x0",
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "post_batch_lsh": [bx32(v) for v in lsh_array],
        "slot_a": w_meta(w_a),
        "slot_b": w_meta(w_b),
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof_mut_a.bin ({len(proof_a)} B)")
    print(f"        proof_mut_b.bin ({len(proof_b)} B)")
    print(f"        proof_t10.bin    ({len(proof_t10)} B)")


if __name__ == "__main__":
    main()
