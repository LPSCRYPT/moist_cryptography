#!/usr/bin/env python3
"""Generate a *linked* extract+T10 fixture.

extractSlot is proofless on the body itself; the only proof we need is
the bundled shadow_t10 covering the post-extract LSH array. We assume:
    pre-extract:  manifest[slot].liveStateHash = lsh_pre
    post-extract: manifest[slot].liveStateHash = 0
    other slots stay at zero (a fresh shadow with one OCCUPIED slot)

The fixture provides:
    proof_t10.bin / public_inputs_t10.bin: shadow_t10 proof bound to the
        post-extract LSH array (all zeros) plus shadow_id + zIndexCommit=0.
    meta.json: shadow_id, slot_idx, lsh_pre (so the test can seed the
        chain to that exact state), t10_hi/lo.

Run-time on M3: ~1 second.
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
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "atomic_extract"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    return int.from_bytes(hashlib.sha256(b"OMP_EXTRACT:" + label + b":" + seed).digest(), "big") % mod


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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="extract_demo")
    ap.add_argument("--slot", type=int, default=3)
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[atomic_extract fixture] seed={args.seed!r}")

    shadow_id = deterministic_int(seed, b"shadow_id", P)
    feature_id = deterministic_int(seed, b"feature_id", P)
    type_idx = 4
    origin_face_id = deterministic_int(seed, b"origin", P)
    palette_commit = deterministic_int(seed, b"palette", P)
    lsh_pre = deterministic_int(seed, b"lsh", P)
    z_commit = 0

    # Post-extract LSH array: target slot becomes 0; rest remain zero.
    post_lsh = [0] * 16

    buf = [shadow_id, z_commit] + post_lsh
    acc = sponge_18(buf)
    hi, lo = split_128(acc)

    print(f"[1/2] post-extract t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in post_lsh)}]\n"
    )

    print("[2/2] nargo execute + bb prove")
    run([NARGO, "execute"], T10_DIR)
    target_dir = T10_DIR / "target"
    run([BB, "write_vk", "-b", str(target_dir / "shadow_t10.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR)
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "shadow_t10.json"),
         "-w", str(target_dir / "shadow_t10.gz"),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR)
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR)

    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_t10.bin").write_bytes((proof_dir / "proof").read_bytes())
    (fix_dir / "public_inputs_t10.bin").write_bytes((proof_dir / "public_inputs").read_bytes())
    (fix_dir / "meta.json").write_text(json.dumps({
        "seed": args.seed,
        "shadow_id": bx32(shadow_id),
        "slot_idx": args.slot,
        "feature_id": bx32(feature_id),
        "type_idx": type_idx,
        "origin_face_id": bx32(origin_face_id),
        "palette_commit": bx32(palette_commit),
        "lsh_pre": bx32(lsh_pre),
        "z_index_commit": bx32(z_commit),
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "post_extract_lsh": [hex(v) for v in post_lsh],
    }, indent=2))
    print(f"[wrote] {fix_dir}/")


if __name__ == "__main__":
    main()
