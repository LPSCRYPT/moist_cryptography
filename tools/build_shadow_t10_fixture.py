#!/usr/bin/env python3
"""Generate a shadow_t10 v2 fixture: sponge over (shadow_id, z_commit, 16 LSH).

Usage:
    python3 build_shadow_t10_fixture.py [--seed t10_demo] [--rebuild-verifier]

Run-time on M3: ~5 seconds.
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
CIRCUIT_DIR = ROOT / "circuits" / "shadow_t10"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
FIXTURE_DIR = ROOT / "contracts" / "test" / "fixtures" / "shadow_t10"
VERIFIER_DST = ROOT / "contracts" / "src" / "T10ShadowVerifier.sol"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    return int.from_bytes(hashlib.sha256(b"OMP_T10:" + label + b":" + seed).digest(), "big") % mod


def sponge_18(elems: list[int]) -> int:
    """Mirrors circuits/shadow_t10/src/main.nr's `sponge_18`.

    18 = 6 full rate-3 blocks, no tail. Sentinel pad after the final block.
    """
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
    """Match circuit `split_128`: hi*2^128 + lo == v, with both < 2^128.

    The circuit constrains via `to_le_bytes` (32 bytes), so v MUST fit in
    256 bits. Field elements are 254 bits in bn254, so v fits.
    """
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
    ap.add_argument("--seed", default="t10_demo")
    ap.add_argument("--rebuild-verifier", action="store_true")
    ap.add_argument("--no-prove", action="store_true")
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[shadow_t10 v2 fixture] seed={args.seed!r}")

    shadow_id = deterministic_int(seed, b"shadow_id", P)
    z_commit  = deterministic_int(seed, b"z_commit", P)
    lsh = [deterministic_int(seed, f"lsh_{i}".encode(), P) for i in range(16)]

    buf = [shadow_id, z_commit] + lsh
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[1/4] computed t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    PROVER_TOML.write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh)}]\n"
    )
    print(f"[wrote] {PROVER_TOML}")

    print("[2/4] nargo execute")
    run([NARGO, "execute"], CIRCUIT_DIR)
    target_dir = CIRCUIT_DIR / "target"

    print("[3/4] bb write_vk + prove + verify")
    run([BB, "write_vk", "-b", str(target_dir / "shadow_t10.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR)
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "shadow_t10.json"),
         "-w", str(target_dir / "shadow_t10.gz"),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR)
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR)
    print("[ok] verified")

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
            "contract HonkVerifier", "contract T10ShadowVerifier")
        VERIFIER_DST.write_text(text)
        print(f"[wrote] {VERIFIER_DST}")

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    fix_dir = FIXTURE_DIR / args.seed
    fix_dir.mkdir(exist_ok=True)
    (fix_dir / "proof.bin").write_bytes((proof_dir / "proof").read_bytes())
    (fix_dir / "public_inputs.bin").write_bytes((proof_dir / "public_inputs").read_bytes())
    (FIXTURE_DIR / f"{args.seed}.json").write_text(json.dumps({
        "circuit": "shadow_t10",
        "shadow_id": hex(shadow_id),
        "z_commit": hex(z_commit),
        "t10_hi": hex(hi), "t10_lo": hex(lo),
        "lsh": [hex(v) for v in lsh],
    }, indent=2))
    print(f"[wrote] {FIXTURE_DIR}/{args.seed}.json + proof + PI")


if __name__ == "__main__":
    main()
