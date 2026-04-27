#!/usr/bin/env python3
"""Generate a palette_reveal_v2 fixture: Noir witness + bb proof + bb verify.

Two modes:

(a) Synthetic (default): generate a deterministic palette + salt from a seed,
    pick an arbitrary featureId, write the witness, prove. Consumed by the
    forge unit test PaletteReveal.t.sol which seeds a Feature with the same
    featureId + paletteCommit before calling revealPalette.

(b) From-mint (--from-fixture <path>): consume an atomic_mint fixture's
    meta.json (which carries `palettes[i]` and `palette_salts[i]` per slot)
    and an explicit slot index. The fixture's featureId must match what the
    on-chain mint produced; pass via --feature-id <hex>.

Output (regardless of mode):
   contracts/test/fixtures/onchain_palette_reveal/<seed>/proof.bin
   contracts/test/fixtures/onchain_palette_reveal/<seed>/public_inputs.bin
   contracts/test/fixtures/onchain_palette_reveal/<seed>/meta.json
       { feature_id, palette_commit, palette_packed[8],
         palette[16], palette_salt }
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

from v2_circuit_helpers import (  # noqa: E402
    P, sponge_palette_salt, encode_palette_packed, fhex, bx32,
)

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "palette_reveal_v2"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_palette_reveal"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_PALETTE_REVEAL_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


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


def build_witness_synthetic(seed: bytes, feature_id: int | None
                            ) -> dict:
    palette = []
    for i in range(16):
        d = hashlib.sha256(seed + f":color:{i}".encode()).digest()
        palette.append(int.from_bytes(d[:3], "big") & 0xFFFFFF)
    palette_salt = deterministic_int(seed, b"salt", P)
    if feature_id is None:
        feature_id = deterministic_int(seed, b"fid", P)

    commit = sponge_palette_salt(palette, palette_salt)
    packed = encode_palette_packed(palette)
    return {
        "feature_id": feature_id,
        "palette_commit": commit,
        "palette_packed": packed,
        "palette": palette,
        "palette_salt": palette_salt,
    }


def build_witness_from_mint(meta_path: Path, slot: int, feature_id: int) -> dict:
    meta = json.loads(meta_path.read_text())
    palette_hex = meta["palettes"][slot]
    salt_hex    = meta["palette_salts"][slot]
    palette = [int(v, 16) for v in palette_hex]
    palette_salt = int(salt_hex, 16)
    commit = sponge_palette_salt(palette, palette_salt)
    # Sanity: must match the per-slot commit the mint already wrote on chain.
    expected = int(meta["palette_commits"][slot], 16)
    if commit != expected:
        sys.exit(
            f"palette_commit recompute mismatch at slot {slot}: "
            f"got {hex(commit)}, expected {hex(expected)} (fixture meta.json)"
        )
    packed = encode_palette_packed(palette)
    return {
        "feature_id": feature_id,
        "palette_commit": commit,
        "palette_packed": packed,
        "palette": palette,
        "palette_salt": palette_salt,
    }


def write_prover_toml(w: dict) -> None:
    prover_path = CIRCUIT_DIR / "Prover.toml"
    lines = [
        f"feature_id = {fhex(w['feature_id'])}",
        f"palette_commit = {fhex(w['palette_commit'])}",
        f"palette_packed = [{', '.join(fhex(v) for v in w['palette_packed'])}]",
        f"palette = [{', '.join(fhex(v) for v in w['palette'])}]",
        f"palette_salt = {fhex(w['palette_salt'])}",
    ]
    prover_path.write_text("\n".join(lines) + "\n")
    print(f"[wrote] {prover_path}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="palette_reveal_demo",
                    help="Fixture seed; also the output dir name.")
    ap.add_argument("--feature-id", default=None,
                    help="Hex featureId override (synthetic mode default; required in from-mint).")
    ap.add_argument("--from-fixture", type=Path, default=None,
                    help="Path to an atomic_mint meta.json to source palette + salt.")
    ap.add_argument("--slot", type=int, default=0,
                    help="Slot index (0..7) when reading from a mint fixture.")
    ap.add_argument("--no-prove", action="store_true")
    args = ap.parse_args()

    seed = args.seed.encode()
    fid_override = int(args.feature_id, 16) if args.feature_id else None

    if args.from_fixture:
        if fid_override is None:
            sys.exit("--feature-id is required with --from-fixture")
        w = build_witness_from_mint(args.from_fixture, args.slot, fid_override)
    else:
        w = build_witness_synthetic(seed, fid_override)

    print(f"[witness] feature_id    = {hex(w['feature_id'])[:18]}...")
    print(f"          palette_commit = {hex(w['palette_commit'])[:18]}...")

    write_prover_toml(w)

    print("[1/4] nargo execute")
    run([NARGO, "execute"], CIRCUIT_DIR, timeout=300)

    if args.no_prove:
        return

    target = CIRCUIT_DIR / "target"
    print("[2/4] bb write_vk")
    run([BB, "write_vk", "-b", str(target / "palette_reveal_v2.json"),
         "-o", str(target),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=600)

    proof_dir = target / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    print("[3/4] bb prove")
    run([BB, "prove", "-b", str(target / "palette_reveal_v2.json"),
         "-w", str(target / "palette_reveal_v2.gz"),
         "-o", str(proof_dir),
         "-k", str(target / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)

    print("[4/4] bb verify (sanity)")
    run([BB, "verify",
         "-k", str(target / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=300)
    print("[ok] proof verified")

    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes = (proof_dir / "public_inputs").read_bytes()

    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof.bin").write_bytes(proof_bytes)
    (fix_dir / "public_inputs.bin").write_bytes(pi_bytes)

    meta = {
        "seed": args.seed,
        "feature_id":     bx32(w["feature_id"]),
        "palette_commit": bx32(w["palette_commit"]),
        "palette_packed": [bx32(v) for v in w["palette_packed"]],
        "palette":        [bx32(v) for v in w["palette"]],
        "palette_salt":   bx32(w["palette_salt"]),
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof.bin ({len(proof_bytes)} B)")
    print(f"        public_inputs.bin ({len(pi_bytes)} B)")


if __name__ == "__main__":
    main()
