#!/usr/bin/env python3
"""Generate a zindex_commit fixture: a permutation of [0..16) + its sponge_16.

Usage:
    python3 build_zindex_commit_fixture.py [--seed zidx_demo] [--rebuild-verifier]

Run-time on M3: ~10 seconds (poseidon perms + bb prove are both small).
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
from v2_circuit_helpers import P, fhex  # noqa: E402

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "zindex_commit"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
FIXTURE_DIR = ROOT / "contracts" / "test" / "fixtures" / "zindex_commit"
VERIFIER_DST = ROOT / "contracts" / "src" / "ZIndexCommitVerifier.sol"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_perm(seed: bytes) -> list[int]:
    """Fisher-Yates shuffle of [0..15] seeded from `seed`."""
    perm = list(range(16))
    for i in range(15, 0, -1):
        h = hashlib.sha256(b"OMP_ZIDX:" + seed + b":" + i.to_bytes(2, "big")).digest()
        j = int.from_bytes(h, "big") % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def sponge_16(elems: list[int]) -> int:
    """Mirrors circuits/zindex_commit/src/main.nr's `sponge_16`.

    Layout: 5 full absorb blocks (e[0..15]) then partial 6th block
    (e[15], pad, pad) then sentinel pad.
    """
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
    ap.add_argument("--seed", default="zidx_demo")
    ap.add_argument("--rebuild-verifier", action="store_true")
    ap.add_argument("--no-prove", action="store_true")
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[zindex_commit fixture] seed={args.seed!r}")

    perm = deterministic_perm(seed)
    print(f"[1/4] perm = {perm}")

    z_commit = sponge_16(perm)
    print(f"[2/4] z_commit = {hex(z_commit)}")

    shadow_id = int.from_bytes(hashlib.sha256(b"shadow:" + seed).digest(), "big") % P
    PROVER_TOML.write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"new_z_commit = {fhex(z_commit)}\n"
        f"perm = [{', '.join(fhex(v) for v in perm)}]\n"
    )
    print(f"[wrote] {PROVER_TOML}")

    print("[3/4] nargo execute + bb prove + verify")
    run([NARGO, "execute"], CIRCUIT_DIR)
    target_dir = CIRCUIT_DIR / "target"
    run([BB, "write_vk", "-b", str(target_dir / "zindex_commit.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR)
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "zindex_commit.json"),
         "-w", str(target_dir / "zindex_commit.gz"),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR)
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR)
    print("[ok] proof verified")

    if args.no_prove:
        return

    if args.rebuild_verifier or not VERIFIER_DST.exists():
        print("[4/4] bb write_solidity_verifier")
        verifier_path = target_dir / "Verifier.sol"
        run([BB, "write_solidity_verifier",
             "-k", str(target_dir / "vk"),
             "-o", str(verifier_path),
             "--verifier_target", "evm"], CIRCUIT_DIR)
        text = verifier_path.read_text().replace(
            "contract HonkVerifier", "contract ZIndexCommitVerifier")
        VERIFIER_DST.write_text(text)
        print(f"[wrote] {VERIFIER_DST}")

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    fix_dir = FIXTURE_DIR / args.seed
    fix_dir.mkdir(exist_ok=True)
    (fix_dir / "proof.bin").write_bytes((proof_dir / "proof").read_bytes())
    (fix_dir / "public_inputs.bin").write_bytes((proof_dir / "public_inputs").read_bytes())
    (FIXTURE_DIR / f"{args.seed}.json").write_text(json.dumps({
        "circuit": "zindex_commit",
        "shadow_id": hex(shadow_id),
        "z_commit": hex(z_commit),
        "perm": perm,
    }, indent=2))
    print(f"[wrote] {FIXTURE_DIR}/{args.seed}.json + proof.bin + public_inputs.bin")


if __name__ == "__main__":
    main()
