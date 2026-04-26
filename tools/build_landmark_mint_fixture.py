#!/usr/bin/env python3
"""Generate a single landmark-mint fixture: image -> proof + 17-field PI.

Runs the v2 mint `landmark_regions` circuit (v5 IOD/EMD-proportional
geometry) end-to-end on one face image, produces a proof + the public
inputs, and lays the artifacts out under
`forge/test/fixtures/landmark_mint/<seed>/` for the forge tests to consume.

This mode does NOT emit the 249-field c2 ciphertext - the recipient-side
decrypt flow is a follow-up (will require a bit-exact Python Poseidon2
port). On-chain we currently only commit to ct_commit (PI[14]).
Steps:
  1. Load a 48x48x3 RGB face image.
  2. Pick a caller_nonce (deterministic from --seed).
  3. Pick a recipient Grumpkin keypair (deterministic from --seed).
  4. Write Prover.toml to circuits/landmark_regions/.
  5. Sync circuit dir to vast (for proving).
  6. nargo execute on vast -> witness + 17-field PI.
  7. bb prove on vast -> proof.
  8. bb verify on vast -> sanity check.
  9. scp proof + PI back, deserialize, save fixture JSON.

Usage:
  python3 build_landmark_mint_fixture.py [--face PATH] [--seed STRING]
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

import cv2
import numpy as np

REPO = Path(__file__).resolve().parent
ROOT = REPO.parent  
CIRCUIT_DIR = ROOT / "circuits" / "landmark_regions"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"

# Vast paths
VAST_HOST = "root@ssh6.vast.ai"
VAST_PORT = "32194"
VAST_CIRCUIT = "/root/test_pipeline/circuits/landmark_regions"

DEFAULT_FACE = (
    ROOT / "examples" / "faces" / "alice0.png"
)

FIXTURES_ROOT = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow"

# Bring in Grumpkin primitives
sys.path.insert(0, str(REPO))
from secret_inbox import G, GRUMPKIN_ORDER, P, ec_mul, is_on_curve  # noqa: E402

# 18 PI field names, in order, for fixture introspection.
# image_commit added at PI[17] to bind face_disc proof against same image.
PI_NAMES = [
    "stateCommit_0", "stateCommit_1", "stateCommit_2", "stateCommit_3",
    "stateCommit_4", "stateCommit_5", "stateCommit_6", "stateCommit_7",
    "faceOriginId", "boxes_packed", "color", "caller_nonce_commit",
    "c1_x", "c1_y", "ct_commit", "recipient_pk_x", "recipient_pk_y",
    "image_commit",
]
assert len(PI_NAMES) == 18


def load_face(path: Path) -> np.ndarray:
    bgr = cv2.imread(str(path))
    if bgr is None:
        raise SystemExit(f"could not read {path}")
    if bgr.shape[:2] != (48, 48):
        bgr = cv2.resize(bgr, (48, 48), interpolation=cv2.INTER_AREA)
    return cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)


def deterministic_seed(seed: bytes, label: bytes) -> int:
    """Domain-separated SHA-256 -> Field-sized integer (mod GRUMPKIN_ORDER - 1, +1)."""
    h = hashlib.sha256(b"OMP_LM_MINT_FIXTURE_v1:" + label + b":" + seed).digest()
    return (int.from_bytes(h, "big") % (GRUMPKIN_ORDER - 1)) + 1


def write_prover_toml(
    rgb_48: np.ndarray,
    caller_nonce: int,
    recipient_pk: tuple[int, int],
) -> None:
    """Write Prover.toml with image (CHW 6912), nonce, and recipient pubkey."""
    chw = rgb_48.transpose(2, 0, 1).flatten().astype(np.int64)
    assert chw.size == 6912
    # Format the long image list compactly.
    image_lines = []
    for i in range(0, 6912, 48):
        chunk = chw[i : i + 48]
        image_lines.append(", ".join(f'"{int(v)}"' for v in chunk))
    image_block = "image = [\n  " + ",\n  ".join(image_lines) + "\n]\n"
    PROVER_TOML.write_text(
        image_block
        + f'caller_nonce    = "{hex(caller_nonce)}"\n'
        + f'recipient_pk_x  = "{hex(recipient_pk[0])}"\n'
        + f'recipient_pk_y  = "{hex(recipient_pk[1])}"\n'
    )


def run(cmd, cwd=None, capture=True, check=True):
    started = time.time()
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    p = subprocess.run(
        [str(c) for c in cmd],
        cwd=cwd,
        capture_output=capture,
        text=True,
    )
    elapsed = time.time() - started
    if check and p.returncode != 0:
        print("  STDOUT:", p.stdout[-2000:] if capture else "(captured)")
        print("  STDERR:", p.stderr[-2000:] if capture else "(captured)")
        raise SystemExit(
            f"command failed (exit {p.returncode}) after {elapsed:.1f}s"
        )
    return p.stdout, p.stderr, elapsed


def ssh(remote_cmd: str, capture: bool = True, check: bool = True):
    return run(
        ["ssh", "-p", VAST_PORT, "-o", "ConnectTimeout=15", VAST_HOST, remote_cmd],
        capture=capture,
        check=check,
    )


def scp_to(local: Path, remote: str):
    return run(["scp", "-P", VAST_PORT, str(local), f"{VAST_HOST}:{remote}"])


def scp_from(remote: str, local: Path):
    return run(["scp", "-P", VAST_PORT, f"{VAST_HOST}:{remote}", str(local)])


def parse_public_inputs(pi_bytes: bytes) -> list[int]:
    """bb writes PI as 32-byte big-endian Field elements concatenated."""
    assert len(pi_bytes) % 32 == 0, f"bad PI length {len(pi_bytes)}"
    return [
        int.from_bytes(pi_bytes[i : i + 32], "big")
        for i in range(0, len(pi_bytes), 32)
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--face", default=str(DEFAULT_FACE), type=Path)
    ap.add_argument("--seed", default="alice0", help="Deterministic seed label")
    ap.add_argument("--out", default=None, help="Fixture output directory")
    ap.add_argument("--color", type=int, default=None,
                    help="Override palette color id 0..22 (default: deterministic from seed)")
    ap.add_argument("--recipient-sk", default=None,
                    help="Hex Grumpkin sk (overrides deterministic derivation)")
    args = ap.parse_args()

    seed_bytes = args.seed.encode()
    fixture_dir = (
        Path(args.out) if args.out is not None else FIXTURES_ROOT / args.seed
    )
    fixture_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 68)
    print("Landmark Mint fixture generator")
    print("=" * 68)
    print(f"  face        : {args.face}")
    print(f"  seed        : {args.seed}")
    print(f"  fixture dir : {fixture_dir}")
    print()

    # ---- 1. Load face -----------------------------------------------------
    print("[1] Load face")
    rgb = load_face(args.face)
    print(f"    image: {rgb.shape}, dtype={rgb.dtype}")

    # ---- 2. Derive deterministic witness ----------------------------------
    print("\n[2] Derive deterministic witness from seed")
    caller_nonce = deterministic_seed(seed_bytes, b"caller_nonce")
    if args.recipient_sk:
        recipient_sk = int(args.recipient_sk, 16)
    else:
        recipient_sk = deterministic_seed(seed_bytes, b"recipient_sk")
    recipient_pk = ec_mul(G, recipient_sk)
    assert recipient_pk is not None
    assert is_on_curve(*recipient_pk)
    print(f"    caller_nonce   = {hex(caller_nonce)[:18]}...")
    print(f"    recipient_sk   = {hex(recipient_sk)[:18]}... (kept private)")
    print(f"    recipient_pk.x = {hex(recipient_pk[0])[:18]}...")
    print(f"    recipient_pk.y = {hex(recipient_pk[1])[:18]}...")

    # ---- 3. Write Prover.toml ---------------------------------------------
    print("\n[3] Write Prover.toml")
    write_prover_toml(rgb, caller_nonce, recipient_pk)
    sz = PROVER_TOML.stat().st_size
    print(f"    {PROVER_TOML} ({sz:,} bytes)")

    # ---- 4. Sync to vast --------------------------------------------------
    print("\n[4] Sync circuit directory to vast")
    # We assume target/landmark_regions.json + target/vk are already on vast
    # from the build step. Just push Prover.toml.
    scp_to(PROVER_TOML, f"{VAST_CIRCUIT}/Prover.toml")
    ssh(f"cd {VAST_CIRCUIT} && find . -name '._*' -delete && ls -la Prover.toml")

    # ---- 5. nargo execute on vast -----------------------------------------
    print("\n[5] nargo execute on vast (witness + PI)")
    out, _, t_exec = ssh(
        f"cd {VAST_CIRCUIT} && time /root/.nargo/bin/nargo execute --silence-warnings 2>&1 | tail -10"
    )
    print(f"    nargo execute: {t_exec:.1f}s")
    print(f"    {out.strip()[-400:]}")

    # ---- 6. bb prove on vast ----------------------------------------------
    print("\n[6] bb prove on vast")
    out, _, t_prove = ssh(
        f"cd {VAST_CIRCUIT} && rm -rf target/proof && "
        f"time /root/.bb/bb prove "
        f"-b target/landmark_regions.json "
        f"-w target/landmark_regions.gz "
        f"-o target/proof "
        f"--verifier_target evm 2>&1 | tail -8"
    )
    print(f"    bb prove: {t_prove:.1f}s")
    print(f"    {out.strip()[-400:]}")

    # ---- 7. bb verify on vast ---------------------------------------------
    print("\n[7] bb verify on vast")
    out, _, t_ver = ssh(
        f"cd {VAST_CIRCUIT} && /root/.bb/bb verify "
        f"-k target/vk "
        f"-p target/proof/proof "
        f"-i target/proof/public_inputs "
        f"--verifier_target evm 2>&1 | tail -5"
    )
    print(f"    bb verify: {t_ver:.1f}s")
    print(f"    {out.strip()[-300:]}")

    # ---- 8. Pull artifacts back -------------------------------------------
    print("\n[8] Pull proof + public inputs back")
    proof_path = fixture_dir / "proof"
    pi_path = fixture_dir / "public_inputs"
    scp_from(f"{VAST_CIRCUIT}/target/proof/proof", proof_path)
    scp_from(f"{VAST_CIRCUIT}/target/proof/public_inputs", pi_path)
    proof_bytes = proof_path.read_bytes()
    pi_bytes = pi_path.read_bytes()
    print(f"    proof: {len(proof_bytes):,} bytes")
    print(f"    PI   : {len(pi_bytes):,} bytes ({len(pi_bytes) // 32} fields)")

    # ---- 9. Decode and save fixture JSON ----------------------------------
    print("\n[9] Decode 17-field PI")
    pi_fields = parse_public_inputs(pi_bytes)
    if len(pi_fields) < 17:
        raise SystemExit(f"expected >=17 PI fields, got {len(pi_fields)}")
    pi_dict = dict(zip(PI_NAMES, pi_fields[:17]))
    for name in PI_NAMES:
        v = pi_dict[name]
        if name in ("color",):
            print(f"    {name:22s} = {v}")
        elif name == "boxes_packed":
            # Decompose into 8 (x, y, w, h) tuples at 6 bits each (24 bits/slot).
            quads = []
            for i in range(8):
                slot = (v >> (24 * i)) & 0xFFFFFF
                x = slot & 0x3F
                y = (slot >> 6) & 0x3F
                w = (slot >> 12) & 0x3F
                h = (slot >> 18) & 0x3F
                quads.append((int(x), int(y), int(w), int(h)))
            print(f"    {name:22s} = {hex(v)[:18]}... -> {quads}")
        else:
            print(f"    {name:22s} = {hex(v)[:18]}...")

    # Sanity: recipient_pk in PI must match what we supplied
    assert pi_dict["recipient_pk_x"] == recipient_pk[0], (
        "recipient_pk_x mismatch: PI says "
        f"{hex(pi_dict['recipient_pk_x'])} vs witness {hex(recipient_pk[0])}"
    )
    assert pi_dict["recipient_pk_y"] == recipient_pk[1]
    print("    OK: recipient_pk in PI matches witness")

    # ---- 10. Write fixture JSON -------------------------------------------
    fixture = {
        "version": 1,
        "seed": args.seed,
        "face_path": str(args.face),
        "image_chw_sha256": hashlib.sha256(
            rgb.transpose(2, 0, 1).flatten().tobytes()
        ).hexdigest(),
        "witness": {
            "caller_nonce": hex(caller_nonce),
            "recipient_sk": hex(recipient_sk),
            "recipient_pk_x": hex(recipient_pk[0]),
            "recipient_pk_y": hex(recipient_pk[1]),
        },
        "public_inputs": [hex(v) for v in pi_fields[:17]],
        "public_inputs_padded": [hex(v) for v in pi_fields],
        "n_pi_total": len(pi_fields),
        "n_pi_user": 17,
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
    print()
    print("=" * 68)
    print("DONE: fixture ready for forge test consumption")
    print("=" * 68)
    print(f"  proof          : {proof_path}")
    print(f"  public_inputs  : {pi_path}")
    print(f"  fixture.json   : {fixture_json}")


if __name__ == "__main__":
    main()
