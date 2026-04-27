#!/usr/bin/env python3
"""Generate a *chained* mutate_slot fixture: 2 mutate proofs on the SAME
slot in sequence, each binding the chain state advanced by the prior
mutation, plus 2 shadow_t10 proofs (one after each mutation).

Tests the v2 ShadowToken's chain-advance invariant: a follow-on mutation
on the same slot uses the prior mutation's `new_*` outputs as its `old_*`
inputs. Specifically:

    Step 0 (M1):     pre-state = mint-time defaults (count=0).
                      Produces new_count=1, new_chain_tip_1, new_lsh_1.
    Step 1 (M2):     pre-state = M1's post-state.
                      Old: count=1, chain_tip=new_chain_tip_1, lsh=new_lsh_1.
                      Produces new_count=2, new_chain_tip_2, new_lsh_2.

This complements ReplayProtection.t.sol (which proves a stale proof
fails) with the positive case: a freshly-built proof bound to the
current chain state succeeds, and the chain advances byte-equal to the
prover's witness.

Output:
    contracts/test/fixtures/chained_mutate/<seed>/
        proof_m1.bin, public_inputs_m1.bin       (step 0 mutate proof)
        proof_m2.bin, public_inputs_m2.bin       (step 1 mutate proof)
        proof_t10_after_m1.bin,
            public_inputs_t10_after_m1.bin       (T10 bound to post-M1 manifest)
        proof_t10_after_m2.bin,
            public_inputs_t10_after_m2.bin       (T10 bound to post-M2 manifest)
        c2_m1.bin, c2_m2.bin                     (per-step c2 calldata)
        meta.json                                (everything the test reads)

Usage:
    python3 build_chained_mutate_fixture.py [--seed chained_mutate_demo]
                                            [--slot 3]

Run-time on M3: ~3-4 minutes wall-clock (4 honk proofs).
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
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "chained_mutate"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def run(cmd: list, cwd: Path, timeout: int = 1800) -> str:
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {time.time()-started:.1f}s")
    return p.stdout


def prove_mutate(w: dict, label: str) -> tuple[bytes, bytes]:
    """Write Prover.toml from witness dict, run nargo + bb, return
    (proof_bytes, public_inputs_bytes). Reuses the mutate_slot circuit's
    target dir; assumes write_vk has been run at least once."""
    write_mut_toml(w)
    print(f"[{label}] nargo execute")
    run([NARGO, "execute"], MUT_DIR, timeout=600)
    target = MUT_DIR / "target"
    if not (target / "vk").exists():
        print(f"[{label}] bb write_vk")
        run([BB, "write_vk", "-b", str(target / "mutate_slot.json"),
             "-o", str(target),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=900)
    proof_dir = target / f"proof_dir_{label}"
    if proof_dir.exists():
        for f in proof_dir.iterdir():
            f.unlink()
    proof_dir.mkdir(exist_ok=True)
    print(f"[{label}] bb prove")
    run([BB, "prove", "-b", str(target / "mutate_slot.json"),
         "-w", str(target / "mutate_slot.gz"),
         "-o", str(proof_dir),
         "-k", str(target / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=1800)
    print(f"[{label}] bb verify")
    run([BB, "verify",
         "-k", str(target / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=300)
    proof = (proof_dir / "proof").read_bytes()
    pi = (proof_dir / "public_inputs").read_bytes()
    return proof, pi


def prove_t10(shadow_id: int, lsh_array: list[int], label: str) -> tuple[bytes, bytes, int, int]:
    """Build a shadow_t10 proof bound to the given LSH array (16 entries).
    z_index_commit = 0 (default identity)."""
    z_commit = 0
    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[{label}] t10 hi=0x{hi:032x} lo=0x{lo:032x}")
    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    print(f"[{label}] nargo execute")
    run([NARGO, "execute"], T10_DIR, timeout=300)
    target = T10_DIR / "target"
    if not (target / "vk").exists():
        run([BB, "write_vk", "-b", str(target / "shadow_t10.json"),
             "-o", str(target),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    proof_dir = target / f"proof_dir_{label}"
    if proof_dir.exists():
        for f in proof_dir.iterdir():
            f.unlink()
    proof_dir.mkdir(exist_ok=True)
    print(f"[{label}] bb prove")
    run([BB, "prove", "-b", str(target / "shadow_t10.json"),
         "-w", str(target / "shadow_t10.gz"),
         "-o", str(proof_dir),
         "-k", str(target / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    print(f"[{label}] bb verify")
    run([BB, "verify",
         "-k", str(target / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=300)
    proof = (proof_dir / "proof").read_bytes()
    pi = (proof_dir / "public_inputs").read_bytes()
    return proof, pi, hi, lo


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="chained_mutate_demo")
    ap.add_argument("--slot", type=int, default=3)
    args = ap.parse_args()

    seed = args.seed.encode()
    slot_idx = args.slot
    print(f"[chained_mutate fixture] seed={args.seed!r} slot={slot_idx}")

    # ---- Step 0: M1 = mint-time -> state_A ----
    print("\n========== Step 0: M1 (count 0 -> 1) ==========")
    w1 = build_mutate_witness(seed, slot_idx=slot_idx, witness_label=b":chained")
    proof_m1, pi_m1 = prove_mutate(w1, "m1")

    # ---- Step 1: M2 = state_A -> state_B (chained) ----
    print("\n========== Step 1: M2 (count 1 -> 2) ==========")
    w2 = build_mutate_witness(
        seed,
        slot_idx=slot_idx,
        witness_label=b":chained",
        prev_state=w1,
        step_index=1,
    )
    # Sanity: the chained witness's old_* must match step 0's new_*.
    assert w2["prev_mutation_count"] == 1, "chain count desync"
    assert w2["prev_chain_tip"] == w1["new_chain_tip"], "chain_tip desync"
    assert w2["old_lsh"] == w1["new_lsh"], "old_lsh != prev new_lsh"
    proof_m2, pi_m2 = prove_mutate(w2, "m2")

    shadow_id = w1["shadow_id"]
    assert w2["shadow_id"] == shadow_id, "shadow_id diverged across steps"
    assert w2["feature_id"] == w1["feature_id"], "feature_id diverged"
    assert w2["origin_face_id"] == w1["origin_face_id"], "origin_face_id diverged"

    # ---- T10 #1: post-M1 manifest (slot has w1["new_lsh"]) ----
    print("\n========== T10 after M1 ==========")
    lsh_arr_after_m1 = [0] * 16
    lsh_arr_after_m1[slot_idx] = w1["new_lsh"]
    proof_t10_a, pi_t10_a, hi_a, lo_a = prove_t10(shadow_id, lsh_arr_after_m1, "t10_a")

    # ---- T10 #2: post-M2 manifest (slot has w2["new_lsh"]) ----
    print("\n========== T10 after M2 ==========")
    lsh_arr_after_m2 = [0] * 16
    lsh_arr_after_m2[slot_idx] = w2["new_lsh"]
    proof_t10_b, pi_t10_b, hi_b, lo_b = prove_t10(shadow_id, lsh_arr_after_m2, "t10_b")

    # ---- Write fixture ----
    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_m1.bin").write_bytes(proof_m1)
    (fix_dir / "public_inputs_m1.bin").write_bytes(pi_m1)
    (fix_dir / "proof_m2.bin").write_bytes(proof_m2)
    (fix_dir / "public_inputs_m2.bin").write_bytes(pi_m2)
    (fix_dir / "proof_t10_after_m1.bin").write_bytes(proof_t10_a)
    (fix_dir / "public_inputs_t10_after_m1.bin").write_bytes(pi_t10_a)
    (fix_dir / "proof_t10_after_m2.bin").write_bytes(proof_t10_b)
    (fix_dir / "public_inputs_t10_after_m2.bin").write_bytes(pi_t10_b)

    c2_m1 = b"".join(c.to_bytes(32, "big") for c in w1["new_c2"])
    c2_m2 = b"".join(c.to_bytes(32, "big") for c in w2["new_c2"])
    (fix_dir / "c2_m1.bin").write_bytes(c2_m1)
    (fix_dir / "c2_m2.bin").write_bytes(c2_m2)

    def step_meta(w: dict) -> dict:
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
            "prev_chain_tip": bx32(w["prev_chain_tip"]),
            "new_chain_tip": bx32(w["new_chain_tip"]),
            "prev_mutation_count": w["prev_mutation_count"],
            "new_mutation_count": w["new_mutation_count"],
            "c2_field_count": w["c2_field_count"],
        }

    meta = {
        "seed": args.seed,
        "shadow_id": bx32(shadow_id),
        "slot_idx": slot_idx,
        "owner_pk_x": bx32(w1["owner_pk_x"]),
        "owner_pk_y": bx32(w1["owner_pk_y"]),
        "z_index_commit": "0x0",
        "step_0_m1": step_meta(w1),
        "step_1_m2": step_meta(w2),
        "t10_after_m1": {"hi": bx32(hi_a), "lo": bx32(lo_a)},
        "t10_after_m2": {"hi": bx32(hi_b), "lo": bx32(lo_b)},
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"\n[wrote] {fix_dir}/")
    print(f"        proof_m1.bin           ({len(proof_m1)} B)")
    print(f"        proof_m2.bin           ({len(proof_m2)} B)")
    print(f"        proof_t10_after_m1.bin ({len(proof_t10_a)} B)")
    print(f"        proof_t10_after_m2.bin ({len(proof_t10_b)} B)")


if __name__ == "__main__":
    main()
