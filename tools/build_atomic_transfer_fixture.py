#!/usr/bin/env python3
"""Generate a *linked* transfer_shadow_v2 + shadow_t10 fixture.

The shadow_t10 proof is built against the LSH array that the chain will
hold *after* transferShadow writes the new manifest. This mirrors what
the v2 ShadowToken._refreshT10Atomically constructs from chain state.

For the test we assume pre-transfer state is the witness's prev_lsh
array (some slots OCCUPIED, rest EMPTY) and z_index_commit = 0; after
transferShadow rotates encryption, the manifest's per-slot LSH is the
witness's new_lsh array.

Usage:
    python3 build_atomic_transfer_fixture.py [--seed atomic_transfer_demo] [--n-occupied 4]
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

from build_transfer_shadow_v2_fixture import build_witness as build_transfer_witness, write_prover_toml as write_transfer_toml  # noqa: E402
from v2_circuit_helpers import P, fhex, bx32  # noqa: E402
from secret_inbox import poseidon2_state  # noqa: E402

ROOT = REPO.parent
TRANSFER_DIR = ROOT / "circuits" / "transfer_shadow_v2"
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "atomic_transfer"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def sponge_18(elems: list[int]) -> int:
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


def run(cmd: list, cwd: Path, timeout: int = 1800) -> str:
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s")
    print(f"  [{elapsed:.1f}s]")
    return p.stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="atomic_transfer_demo")
    ap.add_argument("--n-occupied", type=int, default=4)
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[atomic_transfer fixture] seed={args.seed!r} n_occupied={args.n_occupied}")

    print("[1/2] transfer_shadow_v2: build witness + nargo execute + bb prove")
    w = build_transfer_witness(seed, args.n_occupied)
    write_transfer_toml(w)
    run([NARGO, "execute"], TRANSFER_DIR, timeout=600)
    target_dir = TRANSFER_DIR / "target"
    run([BB, "write_vk", "-b", str(target_dir / "transfer_shadow_v2.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], TRANSFER_DIR, timeout=900)
    proof_dir_t = target_dir / "proof_dir"
    proof_dir_t.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "transfer_shadow_v2.json"),
         "-w", str(target_dir / "transfer_shadow_v2.gz"),
         "-o", str(proof_dir_t),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], TRANSFER_DIR, timeout=1800)
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir_t / "proof"),
         "-i", str(proof_dir_t / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], TRANSFER_DIR, timeout=300)

    proof_t_bytes = (proof_dir_t / "proof").read_bytes()
    pi_t_bytes = (proof_dir_t / "public_inputs").read_bytes()

    # Step 2: shadow_t10 proof against post-transfer LSH array.
    print("[2/2] shadow_t10: build T10 proof against post-transfer LSH array")
    shadow_id = w["shadow_id"]
    z_commit = 0  # default identity / unchanged on transfer
    lsh_array = list(w["new_lsh"])  # already 16 entries
    assert len(lsh_array) == 16

    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"  post-transfer t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    run([NARGO, "execute"], T10_DIR, timeout=300)
    run([BB, "write_vk", "-b", str(T10_DIR / "target/shadow_t10.json"),
         "-o", str(T10_DIR / "target"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    proof_dir_t10 = T10_DIR / "target" / "proof_dir"
    proof_dir_t10.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(T10_DIR / "target/shadow_t10.json"),
         "-w", str(T10_DIR / "target/shadow_t10.gz"),
         "-o", str(proof_dir_t10),
         "-k", str(T10_DIR / "target/vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    run([BB, "verify",
         "-k", str(T10_DIR / "target/vk"),
         "-p", str(proof_dir_t10 / "proof"),
         "-i", str(proof_dir_t10 / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=300)

    proof_t10_bytes = (proof_dir_t10 / "proof").read_bytes()
    pi_t10_bytes = (proof_dir_t10 / "public_inputs").read_bytes()

    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_transfer.bin").write_bytes(proof_t_bytes)
    (fix_dir / "public_inputs_transfer.bin").write_bytes(pi_t_bytes)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10_bytes)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10_bytes)

    # Per-slot c2 calldata for occupied slots (so the contract test can
    # replay them exactly as the proof witnessed them).
    c2_per_slot: dict[str, list[str]] = {}
    for i in w["occupied_idxs"]:
        c2_per_slot[str(i)] = [bx32(v) for v in w["new_c2"][i]]

    meta = {
        "seed": args.seed,
        "n_occupied": args.n_occupied,
        "occupied_idxs": w["occupied_idxs"],
        "shadow_id": bx32(w["shadow_id"]),
        "recipient_pk_x": bx32(w["recipient_pk_x"]),
        "recipient_pk_y": bx32(w["recipient_pk_y"]),
        "prev_lsh_root": bx32(w["prev_lsh_root"]),
        "new_lsh_root": bx32(w["new_lsh_root"]),
        "prev_owner_pk_x": bx32(w["prev_owner_pk_x"]),
        "prev_owner_pk_y": bx32(w["prev_owner_pk_y"]),
        "new_chain_tips_root": bx32(w["new_chain_tips_root"]),

        "prev_lsh": [bx32(v) for v in w["prev_lsh"]],
        "prev_state_commit": [bx32(v) for v in w["prev_state_commit"]],
        "prev_ct_commit": [bx32(v) for v in w["prev_ct_commit"]],
        "prev_c1_x": [bx32(v) for v in w["prev_c1_x"]],
        "prev_c1_y": [bx32(v) for v in w["prev_c1_y"]],
        "prev_mutation_count": w["prev_mutation_count"],
        "prev_chain_tip": [bx32(v) for v in w["prev_chain_tip"]],

        "new_lsh": [bx32(v) for v in w["new_lsh"]],
        "new_c1_x": [bx32(v) for v in w["new_c1_x"]],
        "new_c1_y": [bx32(v) for v in w["new_c1_y"]],
        "new_ct_commit": [bx32(v) for v in w["new_ct_commit"]],
        "new_chain_tip": [bx32(v) for v in w["new_chain_tip"]],
        "new_mutation_count": w["new_mutation_count"],

        "c2_per_slot": c2_per_slot,

        "z_index_commit": "0x0",
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),

        # Visualizer-friendly compatibility fields. Identity z_perm so
        # `visualize_shadow_v2 from-solve-fixture` renders post-transfer
        # state (pre-solve, no z_perm is revealed).
        "z_perm": list(range(16)),
        "occupied_idxs": w["occupied_idxs"],
    }
    # Per-slot plaintexts as bytes32 arrays (16 slots; empty slots = zeros).
    plaintexts_per_slot = [
        [bx32(v) for v in w["plaintexts"][i]] for i in range(16)
    ]
    (fix_dir / "plaintexts.json").write_text(
        json.dumps({"plaintexts": plaintexts_per_slot}, indent=2)
    )
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof_transfer.bin ({len(proof_t_bytes)} B)")
    print(f"        proof_t10.bin ({len(proof_t10_bytes)} B)")


if __name__ == "__main__":
    main()
