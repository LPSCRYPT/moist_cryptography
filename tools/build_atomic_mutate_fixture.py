#!/usr/bin/env python3
"""Generate a *linked* mutate_slot + shadow_t10 fixture.

The shadow_t10 proof is built against the LSH array that the chain will
hold *after* the mutateSlot write completes. This is the input the
v2 ShadowToken._refreshT10Atomically constructs from chain state.

For the test, we assume the pre-mutate state is:
    manifest[i].liveStateHash = 0  for i != slot
    manifest[slot].liveStateHash = old_lsh  (== piMut[6])
    z_index_commit = 0

After mutateSlot writes:
    manifest[slot].liveStateHash = new_lsh  (== piMut[7])

Hence the T10 PI is:
    PI[0]  = shadow_id  (== piMut[0])
    PI[1]  = z_index_commit (= 0)
    PI[2]  = t10_hi  (computed)
    PI[3]  = t10_lo  (computed)
    PI[4 + i] = post-mutate manifest[i].liveStateHash for i in 0..15

Output:
    contracts/test/fixtures/atomic_mutate/<seed>/proof_mut.bin
    contracts/test/fixtures/atomic_mutate/<seed>/public_inputs_mut.bin
    contracts/test/fixtures/atomic_mutate/<seed>/proof_t10.bin
    contracts/test/fixtures/atomic_mutate/<seed>/public_inputs_t10.bin
    contracts/test/fixtures/atomic_mutate/<seed>/c2.bin   (38-field new c2 ciphertext as 39 packed Fields, last is zero pad)
    contracts/test/fixtures/atomic_mutate/<seed>/meta.json

Usage:
    python3 build_atomic_mutate_fixture.py [--seed atomic_demo]
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

from build_mutate_slot_fixture import build_witness as build_mutate_witness, write_prover_toml as write_mut_toml  # noqa: E402
from v2_circuit_helpers import P, fhex, bx32, sponge_6  # noqa: E402
from secret_inbox import poseidon2_state  # noqa: E402

ROOT = REPO.parent
MUT_DIR = ROOT / "circuits" / "mutate_slot"
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "atomic_mutate"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def sponge_18(elems: list[int]) -> int:
    """Mirrors circuits/shadow_t10/src/main.nr's sponge_18."""
    if len(elems) != 18:
        raise ValueError("sponge_18 needs 18 elems")
    s0, s1, s2, s3 = 0, 0, 0, 0
    for b in range(6):
        s0 = (s0 + elems[b * 3]) % P
        s1 = (s1 + elems[b * 3 + 1]) % P
        s2 = (s2 + elems[b * 3 + 2]) % P
        s0, s1, s2, s3 = poseidon2_state(s0, s1, s2, s3)
    s0 = (s0 + 1) % P
    s0, s1, s2, s3 = poseidon2_state(s0, s1, s2, s3)
    return s0


def split_128(v: int) -> tuple[int, int]:
    bytes32 = (v % P).to_bytes(32, "little")
    lo = int.from_bytes(bytes32[:16], "little")
    hi = int.from_bytes(bytes32[16:], "little")
    return hi, lo


def run(cmd: list, cwd: Path, timeout: int = 600) -> str:
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {time.time()-started:.1f}s")
    return p.stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="atomic_demo")
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[atomic_mutate fixture] seed={args.seed!r}")

    # Step 1: build the mutate witness.
    w = build_mutate_witness(seed)
    write_mut_toml(w)

    print("[1/2] mutate_slot: nargo execute + bb prove")
    run([NARGO, "execute"], MUT_DIR)
    run([BB, "write_vk", "-b", str(MUT_DIR / "target/mutate_slot.json"),
         "-o", str(MUT_DIR / "target"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR)
    proof_dir_mut = MUT_DIR / "target" / "proof_dir"
    proof_dir_mut.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(MUT_DIR / "target/mutate_slot.json"),
         "-w", str(MUT_DIR / "target/mutate_slot.gz"),
         "-o", str(proof_dir_mut),
         "-k", str(MUT_DIR / "target/vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR)
    run([BB, "verify",
         "-k", str(MUT_DIR / "target/vk"),
         "-p", str(proof_dir_mut / "proof"),
         "-i", str(proof_dir_mut / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR)

    proof_mut_bytes = (proof_dir_mut / "proof").read_bytes()
    pi_mut_bytes = (proof_dir_mut / "public_inputs").read_bytes()

    # Step 2: build the shadow_t10 proof keyed to post-mutate LSH array.
    shadow_id = w["shadow_id"]
    slot_idx = w["slot_idx"]
    new_lsh = w["new_lsh"]
    z_commit = 0  # default identity permutation
    lsh_array = [0] * 16
    lsh_array[slot_idx] = new_lsh

    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[2/2] shadow_t10: post-mutate t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )

    run([NARGO, "execute"], T10_DIR)
    run([BB, "write_vk", "-b", str(T10_DIR / "target/shadow_t10.json"),
         "-o", str(T10_DIR / "target"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR)
    proof_dir_t10 = T10_DIR / "target" / "proof_dir"
    proof_dir_t10.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(T10_DIR / "target/shadow_t10.json"),
         "-w", str(T10_DIR / "target/shadow_t10.gz"),
         "-o", str(proof_dir_t10),
         "-k", str(T10_DIR / "target/vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR)
    run([BB, "verify",
         "-k", str(T10_DIR / "target/vk"),
         "-p", str(proof_dir_t10 / "proof"),
         "-i", str(proof_dir_t10 / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR)

    proof_t10_bytes = (proof_dir_t10 / "proof").read_bytes()
    pi_t10_bytes = (proof_dir_t10 / "public_inputs").read_bytes()

    # Step 3: write the linked fixture out.
    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_mut.bin").write_bytes(proof_mut_bytes)
    (fix_dir / "public_inputs_mut.bin").write_bytes(pi_mut_bytes)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10_bytes)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10_bytes)
    # new c2 calldata: 39 fields packed big-endian (matches contract sponge in)
    new_c2 = w["new_c2"]
    c2_bytes = b"".join(c.to_bytes(32, "big") for c in new_c2)
    (fix_dir / "c2.bin").write_bytes(c2_bytes)

    meta = {
        "seed": args.seed,
        "shadow_id": bx32(shadow_id),
        "slot_idx": slot_idx,
        "feature_id": bx32(w["feature_id"]),
        "type_idx": w["type_idx"],
        "origin_face_id": bx32(w["origin_face_id"]),
        "palette_commit": bx32(w["palette_commit"]),
        "owner_pk_x": bx32(w["owner_pk_x"]),
        "owner_pk_y": bx32(w["owner_pk_y"]),
        "owner_sk": bx32(w["owner_sk"]),
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
        "z_index_commit": "0x0",
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "post_mutate_lsh": [hex(v) for v in lsh_array],
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof_mut.bin ({len(proof_mut_bytes)} B)")
    print(f"        proof_t10.bin ({len(proof_t10_bytes)} B)")


if __name__ == "__main__":
    main()
