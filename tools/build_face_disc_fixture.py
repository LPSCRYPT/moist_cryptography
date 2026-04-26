#!/usr/bin/env python3
"""Generate face_disc proof for an image.

Companion to build_landmark_mint_fixture.py. The two fixtures together form
a complete mint: the contract verifies BOTH proofs, asserting they share
image_commit (landmark.PI[17] == disc.PI[0]).

Steps:
  1. Load 48x48x3 RGB face image.
  2. Optional: run Python disc inference for a sanity score print.
  3. Write Prover.toml for circuits/face_disc/.
  4. Sync to vast, run nargo execute + bb prove.
  5. SCP proof + public_inputs back; save under
     contracts/test/fixtures/face_disc/<seed>/.

Note: the disc proof's PI[0] (image_commit) MUST match what
landmark_regions emits at PI[17] when fed the SAME image. The circuits
both compute poseidon2_sponge_6912(image), so this holds by construction
provided the byte order matches (CHW flattened, same as the mint builder).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import cv2
import numpy as np

REPO = Path(__file__).resolve().parent
ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "face_disc"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"

VAST_HOST = "root@ssh6.vast.ai"
VAST_PORT = "32194"
VAST_CIRCUIT = "/root/test_pipeline/circuits/face_disc"

DEFAULT_FACE = ROOT / "examples" / "faces" / "alice0.png"
FIXTURES_ROOT = ROOT / "contracts" / "test" / "fixtures" / "face_disc"

sys.path.insert(0, str(REPO / "landmark"))
from discriminator import run_discriminator  # noqa: E402

# Reuse helpers from the mint fixture builder.
sys.path.insert(0, str(REPO))
from build_landmark_mint_fixture import (  # noqa: E402
    load_face,
    run,
    ssh,
    scp_to,
    scp_from,
    parse_public_inputs,
)


def write_prover_toml(rgb_48: np.ndarray) -> None:
    """face_disc only takes the 6912-pixel image as private witness."""
    chw = rgb_48.transpose(2, 0, 1).flatten().astype(np.int64)
    assert chw.size == 6912
    image_lines = []
    for i in range(0, 6912, 48):
        chunk = chw[i : i + 48]
        image_lines.append(", ".join(f'"{int(v)}"' for v in chunk))
    image_block = "image = [\n  " + ",\n  ".join(image_lines) + "\n]\n"
    PROVER_TOML.write_text(image_block)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--face", default=str(DEFAULT_FACE), type=Path)
    ap.add_argument("--seed", default="alice0", help="Fixture subdir under face_disc/")
    ap.add_argument("--out", default=None)
    ap.add_argument("--check-only", action="store_true",
                    help="Just run Python disc inference, no prove")
    args = ap.parse_args()

    fixture_dir = (
        Path(args.out) if args.out is not None else FIXTURES_ROOT / args.seed
    )

    print("=" * 68)
    print("face_disc fixture generator")
    print("=" * 68)
    print(f"  face        : {args.face}")
    print(f"  seed        : {args.seed}")
    print(f"  fixture dir : {fixture_dir}")
    print()

    print("[1] Load face")
    rgb = load_face(args.face)
    print(f"    image: {rgb.shape}, dtype={rgb.dtype}")

    print("\n[2] Python disc inference (sanity check)")
    score = run_discriminator(rgb)
    print(f"    disc score = {score:.4f}  (face if > 0)")
    if score <= 0:
        print(f"    WARNING: image classified as NOT face (score <= 0).")
        print(f"    The circuit will reject this image at proof time.")
        if not args.check_only:
            raise SystemExit(2)

    if args.check_only:
        print("\n--check-only: stopping after Python inference.")
        return 0

    fixture_dir.mkdir(parents=True, exist_ok=True)

    print("\n[3] Write Prover.toml")
    write_prover_toml(rgb)
    sz = PROVER_TOML.stat().st_size
    print(f"    {PROVER_TOML} ({sz:,} bytes)")

    print("\n[4] Sync to vast")
    ssh(f"mkdir -p {VAST_CIRCUIT}/src {VAST_CIRCUIT}/target")
    scp_to(CIRCUIT_DIR / "Nargo.toml", f"{VAST_CIRCUIT}/Nargo.toml")
    scp_to(CIRCUIT_DIR / "src" / "main.nr", f"{VAST_CIRCUIT}/src/main.nr")
    scp_to(CIRCUIT_DIR / "src" / "weights_disc.nr", f"{VAST_CIRCUIT}/src/weights_disc.nr")
    scp_to(PROVER_TOML, f"{VAST_CIRCUIT}/Prover.toml")
    # If circuit ACIR not pre-built on vast, compile it remotely.
    ssh(f"cd {VAST_CIRCUIT} && ls target/face_disc.json 2>/dev/null || "
        f"/root/.nargo/bin/nargo compile --silence-warnings")
    ssh(f"cd {VAST_CIRCUIT} && ls target/vk/vk 2>/dev/null || "
        f"/root/.bb/bb write_vk -b target/face_disc.json -o target/vk --verifier_target evm")

    print("\n[5] nargo execute on vast (witness + PI)")
    out, _, t_exec = ssh(
        f"cd {VAST_CIRCUIT} && time /root/.nargo/bin/nargo execute --silence-warnings 2>&1 | tail -10"
    )
    print(f"    nargo execute: {t_exec:.1f}s")

    print("\n[6] bb prove on vast")
    out, _, t_prove = ssh(
        f"cd {VAST_CIRCUIT} && rm -rf target/proof && "
        f"time /root/.bb/bb prove "
        f"-b target/face_disc.json "
        f"-w target/face_disc.gz "
        f"-o target/proof "
        f"--verifier_target evm 2>&1 | tail -8"
    )
    print(f"    bb prove: {t_prove:.1f}s")

    print("\n[7] bb verify on vast")
    out, _, t_ver = ssh(
        f"cd {VAST_CIRCUIT} && /root/.bb/bb verify "
        f"-k target/vk "
        f"-p target/proof/proof "
        f"-i target/proof/public_inputs "
        f"--verifier_target evm 2>&1 | tail -5"
    )
    print(f"    bb verify: {t_ver:.1f}s")

    print("\n[8] Pull artifacts back")
    proof_path = fixture_dir / "proof"
    pi_path = fixture_dir / "public_inputs"
    scp_from(f"{VAST_CIRCUIT}/target/proof/proof", proof_path)
    scp_from(f"{VAST_CIRCUIT}/target/proof/public_inputs", pi_path)

    proof_bytes = proof_path.read_bytes()
    pi_bytes = pi_path.read_bytes()
    pi_fields = parse_public_inputs(pi_bytes)
    print(f"    proof: {len(proof_bytes):,} bytes")
    print(f"    PI   : {len(pi_bytes):,} bytes ({len(pi_bytes) // 32} fields)")
    print(f"    image_commit (PI[0]): {hex(pi_fields[0])[:18]}...")

    fixture = {
        "version": 1,
        "seed": args.seed,
        "face_path": str(args.face),
        "python_disc_score": float(score),
        "image_commit": hex(pi_fields[0]),
        "n_pi_user": 1,
        "n_pi_total": len(pi_fields),
        "proof_size_bytes": len(proof_bytes),
        "timings_seconds": {
            "nargo_execute": round(t_exec, 2),
            "bb_prove": round(t_prove, 2),
            "bb_verify": round(t_ver, 2),
        },
    }
    fixture_json = fixture_dir / "fixture.json"
    fixture_json.write_text(json.dumps(fixture, indent=2))
    print(f"\n    wrote {fixture_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
