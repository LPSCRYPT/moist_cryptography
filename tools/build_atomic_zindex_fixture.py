#!/usr/bin/env python3
"""Generate a *linked* setZIndexCommit + T10 fixture.

setZIndexCommit verifies (zindex_commit, T10) atomically:
    proof_z:    zindex_commit proof on (shadow_id, new_z_commit) where
                new_z_commit = sponge_16(perm) of a permutation of [0..15].
    proof_t10:  shadow_t10 proof bound to shadow_id, NEW z_commit, AND
                the chain's CURRENT LSH array (slot[slot_idx] = lsh_held;
                rest = 0). T10 changes because z_commit changed even
                though the LSH array did not.

Output:
    contracts/test/fixtures/atomic_zindex/<seed>/proof_z.bin
    contracts/test/fixtures/atomic_zindex/<seed>/public_inputs_z.bin
    contracts/test/fixtures/atomic_zindex/<seed>/proof_t10.bin
    contracts/test/fixtures/atomic_zindex/<seed>/public_inputs_t10.bin
    contracts/test/fixtures/atomic_zindex/<seed>/meta.json

Run-time on M3: ~3 seconds.
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

ROOT = REPO.parent
ZIDX_DIR = ROOT / "circuits" / "zindex_commit"
T10_DIR  = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "atomic_zindex"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    return int.from_bytes(hashlib.sha256(b"OMP_ZIDX:" + label + b":" + seed).digest(), "big") % mod


def deterministic_perm(seed: bytes) -> list[int]:
    perm = list(range(16))
    for i in range(15, 0, -1):
        h = hashlib.sha256(b"OMP_ZIDX_PERM:" + seed + b":" + i.to_bytes(2, "big")).digest()
        j = int.from_bytes(h, "big") % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def sponge_16(elems: list[int]) -> int:
    if len(elems) != 16:
        raise ValueError("sponge_16 needs 16 elems")
    s0, s1, s2, s3 = 0, 0, 0, 0
    for b in range(5):
        s0 = (s0 + elems[b * 3]) % P
        s1 = (s1 + elems[b * 3 + 1]) % P
        s2 = (s2 + elems[b * 3 + 2]) % P
        s0, s1, s2, s3 = poseidon2_state(s0, s1, s2, s3)
    s0 = (s0 + elems[15]) % P
    s0, s1, s2, s3 = poseidon2_state(s0, s1, s2, s3)
    s0 = (s0 + 1) % P
    s0, s1, s2, s3 = poseidon2_state(s0, s1, s2, s3)
    return s0


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


def run(cmd: list, cwd: Path, timeout: int = 600) -> str:
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {time.time()-started:.1f}s")
    return p.stdout


def prove(circuit_dir: Path, json_name: str) -> tuple[bytes, bytes]:
    target_dir = circuit_dir / "target"
    run([NARGO, "execute"], circuit_dir)
    run([BB, "write_vk", "-b", str(target_dir / json_name),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], circuit_dir)
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    gz = json_name.replace(".json", ".gz")
    run([BB, "prove", "-b", str(target_dir / json_name),
         "-w", str(target_dir / gz),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], circuit_dir)
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], circuit_dir)
    return (proof_dir / "proof").read_bytes(), (proof_dir / "public_inputs").read_bytes()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="zidx_atomic_demo")
    ap.add_argument("--slot", type=int, default=3, help="OCCUPIED slot (rest zero)")
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[atomic_zindex fixture] seed={args.seed!r}")

    # ---- chain state (post-event LSH array == pre-event since z-commit", "    #      doesn't change LSH) ----
    shadow_id = deterministic_int(seed, b"shadow_id", P)
    lsh_held  = deterministic_int(seed, b"lsh", P)
    lsh_array = [0] * 16
    lsh_array[args.slot] = lsh_held

    # ---- z-commit proof ----
    perm = deterministic_perm(seed)
    z_commit = sponge_16(perm)
    print(f"[1/2] perm={perm}, z_commit={hex(z_commit)[:18]}...")
    (ZIDX_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"new_z_commit = {fhex(z_commit)}\n"
        f"perm = [{', '.join(fhex(v) for v in perm)}]\n"
    )
    proof_z, pi_z = prove(ZIDX_DIR, "zindex_commit.json")

    # ---- T10 proof: bind to NEW z_commit + unchanged LSH array ----
    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[2/2] post-zidx t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")
    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    proof_t10, pi_t10 = prove(T10_DIR, "shadow_t10.json")

    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_z.bin").write_bytes(proof_z)
    (fix_dir / "public_inputs_z.bin").write_bytes(pi_z)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)
    (fix_dir / "meta.json").write_text(json.dumps({
        "seed": args.seed,
        "shadow_id": bx32(shadow_id),
        "slot_idx": args.slot,
        "lsh_held": bx32(lsh_held),
        "z_commit": bx32(z_commit),
        "perm": perm,
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "lsh_array": [hex(v) for v in lsh_array],
    }, indent=2))
    print(f"[wrote] {fix_dir}/")


if __name__ == "__main__":
    main()
