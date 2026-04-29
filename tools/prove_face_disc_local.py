#!/usr/bin/env python3
"""Locally prove face_disc for a given image and save fixture.

Usage: python3 tools/prove_face_disc_local.py <image_path> <seed_name>

Writes:
  contracts/test/fixtures/face_disc/<seed_name>/proof
  contracts/test/fixtures/face_disc/<seed_name>/public_inputs

Times each step. Reuses target/vk if present.
"""
from __future__ import annotations
import sys, time, subprocess, shutil, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tools" / "landmark"))

import numpy as np
from build_landmark_mint_fixture import load_face

NARGO = Path.home() / ".nargo" / "bin" / "nargo"
BB    = Path.home() / ".bb" / "bb"
CIRCUIT_DIR = ROOT / "circuits" / "face_disc"
TARGET = CIRCUIT_DIR / "target"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
FIX_BASE = ROOT / "contracts" / "test" / "fixtures" / "face_disc"


def write_prover_toml(rgb: np.ndarray) -> None:
    chw = rgb.transpose(2, 0, 1).flatten().astype(np.int64)
    assert chw.size == 6912, f"expected 6912 values, got {chw.size}"
    lines = []
    for i in range(0, 6912, 48):
        lines.append(", ".join(f'"{int(v)}"' for v in chw[i:i+48]))
    PROVER_TOML.write_text(
        "image = [\n  " + ",\n  ".join(lines) + "\n]\n"
    )


def run(cmd: list[str], cwd: Path | None = None) -> float:
    t0 = time.time()
    r = subprocess.run(cmd, cwd=cwd, check=False, capture_output=True, text=True)
    dt = time.time() - t0
    if r.returncode != 0:
        print(f"FAIL {' '.join(cmd)}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}", file=sys.stderr)
        sys.exit(r.returncode)
    return dt


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    img_path = Path(sys.argv[1])
    seed = sys.argv[2]

    if not img_path.exists():
        print(f"missing image: {img_path}", file=sys.stderr); sys.exit(2)

    out_dir = FIX_BASE / seed
    if out_dir.exists() and (out_dir / "proof").exists():
        print(f"[skip] {out_dir} already has a proof", file=sys.stderr); sys.exit(0)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1] load image: {img_path}")
    rgb = load_face(img_path)
    assert rgb.shape == (48, 48, 3), rgb.shape

    print(f"[2] write Prover.toml")
    write_prover_toml(rgb)

    print(f"[3] nargo execute")
    dt = run([str(NARGO), "execute", "--silence-warnings"], cwd=CIRCUIT_DIR)
    print(f"    -> {dt:.1f}s")

    vk_path = TARGET / "vk" / "vk"
    if not vk_path.exists():
        print(f"[4] bb write_vk (no existing vk)")
        dt = run([str(BB), "write_vk",
                  "-b", "target/face_disc.json", "-o", "target/vk",
                  "--scheme", "ultra_honk", "--oracle_hash", "keccak"],
                 cwd=CIRCUIT_DIR)
        print(f"    -> {dt:.1f}s")
    else:
        print(f"[4] bb write_vk: skip (vk exists at {vk_path})")

    # Always purge old proof to avoid confusion
    proof_dir = TARGET / "proof"
    if proof_dir.exists():
        shutil.rmtree(proof_dir)

    print(f"[5] bb prove")
    dt = run([str(BB), "prove",
              "-b", "target/face_disc.json", "-w", "target/face_disc.gz",
              "-o", "target/proof", "-k", "target/vk/vk",
              "--scheme", "ultra_honk", "--oracle_hash", "keccak"],
             cwd=CIRCUIT_DIR)
    print(f"    -> {dt:.1f}s")

    print(f"[6] bb verify")
    dt = run([str(BB), "verify",
              "-k", "target/vk/vk",
              "-p", "target/proof/proof",
              "-i", "target/proof/public_inputs",
              "--scheme", "ultra_honk", "--oracle_hash", "keccak"],
             cwd=CIRCUIT_DIR)
    print(f"    -> {dt:.1f}s")

    print(f"[7] copy fixture -> {out_dir}")
    shutil.copy(proof_dir / "proof", out_dir / "proof")
    shutil.copy(proof_dir / "public_inputs", out_dir / "public_inputs")

    pi = (out_dir / "public_inputs").read_bytes()
    print(f"    image_commit = 0x{pi[:32].hex()}")
    print(f"    public_inputs size = {len(pi)} bytes")


if __name__ == "__main__":
    main()
