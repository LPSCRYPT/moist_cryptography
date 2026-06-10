#!/usr/bin/env python3
"""Generate an incremental solve_shadow_v2 reveal-slot fixture.

The current solve_shadow_v2 circuit proves one hidden occupied slot opens to a
public plaintext/stateCommit and the current owner key. It no longer proves a
full-shadow solve or z-permutation reveal.

Usage:
    python3 tools/build_solve_shadow_v2_fixture.py --seed reveal_demo
    python3 tools/build_solve_shadow_v2_fixture.py --seed reveal_demo --rebuild-verifier
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

from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # noqa: E402
from v2_circuit_helpers import (  # noqa: E402
    P,
    sponge_39,
    sponge_6,
    sponge_palette_salt,
    encode_plaintext_v2,
    pack_pose,
    ecies_encrypt_v2,
    chain_step,
    fhex,
)
from build_shadow_t10_fixture import sponge_18, split_128  # noqa: E402

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "solve_shadow_v2"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
T10_DIR = ROOT / "circuits" / "shadow_t10"
T10_PROVER_TOML = T10_DIR / "Prover.toml"
FIXTURE_DIR = ROOT / "contracts" / "test" / "fixtures" / "solve_shadow_v2"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_INCREMENTAL_REVEAL_V1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def render_array(name: str, vals: list[int]) -> str:
    return f"{name} = [{', '.join(fhex(v) for v in vals)}]"


def run(cmd: list[Path | str], cwd: Path, timeout: int = 1800) -> str:
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s")
    print(f"  [{elapsed:.1f}s]")
    return p.stdout


def build_witness(seed: bytes) -> dict:
    owner_sk = deterministic_int(seed, b"owner_sk", GRUMPKIN_ORDER - 1) + 1
    owner_pk = ec_mul(G, owner_sk)
    assert owner_pk is not None

    shadow_id = deterministic_int(seed, b"shadow_id", P)
    slot_idx = deterministic_int(seed, b"slot_idx", 16)
    feature_id = 10_000 + deterministic_int(seed, b"feature_id", 1_000_000)
    palette = [deterministic_int(seed, f"palette_{j}".encode(), 0x1000000) for j in range(16)]
    palette_salt = deterministic_int(seed, b"palette_salt", P)
    palette_commit = sponge_palette_salt(palette, palette_salt)
    revealed_rank = deterministic_int(seed, b"revealed_rank", 16)
    pose = pack_pose(x=2 + slot_idx, y=4 + (slot_idx % 8))
    w_dim = 6 + (slot_idx % 4)
    h_dim = 6 + ((slot_idx + 1) % 4)
    indices = [(j * 7 + slot_idx + 3) & 0xF for j in range(w_dim * h_dim)]
    plaintext = encode_plaintext_v2(pose, w_dim, h_dim, indices)
    state_commit = sponge_39(plaintext)

    r_i = deterministic_int(seed, b"slot_r", GRUMPKIN_ORDER - 1) + 1
    c1, c2, owner_k = ecies_encrypt_v2(plaintext, owner_pk, r_i)
    prev_ct_commit = sponge_39(c2)
    prev_mutation_count = deterministic_int(seed, b"mutation_count", 100)
    origin_face_id = deterministic_int(seed, b"origin_face_id", P)
    prev_chain_tip = chain_step(0, state_commit, prev_ct_commit, prev_mutation_count, origin_face_id, slot_idx)
    live_state_hash = sponge_6(state_commit, prev_ct_commit, c1[0], c1[1], prev_mutation_count, prev_chain_tip)

    return {
        "shadow_id": shadow_id,
        "slot_idx": slot_idx,
        "feature_id": feature_id,
        "live_state_hash": live_state_hash,
        "state_commit": state_commit,
        "palette_commit": palette_commit,
        "owner_pk_x": owner_pk[0],
        "owner_pk_y": owner_pk[1],
        "revealed_rank": revealed_rank,
        "palette": palette,
        "palette_salt": palette_salt,
        "plaintext": plaintext,
        "prev_ct_commit": prev_ct_commit,
        "prev_c1_x": c1[0],
        "prev_c1_y": c1[1],
        "prev_mutation_count": prev_mutation_count,
        "prev_chain_tip": prev_chain_tip,
        "owner_k": owner_k,
        "owner_sk": owner_sk,
        "c2": c2,
        "origin_face_id": origin_face_id,
    }


def write_prover_toml(w: dict) -> None:
    lines = []
    for name in [
        "shadow_id",
        "slot_idx",
        "feature_id",
        "live_state_hash",
        "state_commit",
        "palette_commit",
        "owner_pk_x",
        "owner_pk_y",
        "revealed_rank",
    ]:
        lines.append(f"{name} = {fhex(w[name])}")
    lines.append(render_array("plaintext", w["plaintext"]))
    for name in [
        "prev_ct_commit",
        "prev_c1_x",
        "prev_c1_y",
        "prev_mutation_count",
        "prev_chain_tip",
        "owner_k",
        "owner_sk",
    ]:
        lines.append(f"{name} = {fhex(w[name])}")
    PROVER_TOML.write_text("\n".join(lines) + "\n")
    os.chmod(PROVER_TOML, 0o600)
    print(f"[wrote transient 0600] {PROVER_TOML}")


def save_fixture(seed: str, w: dict) -> None:
    out = FIXTURE_DIR / seed
    out.mkdir(parents=True, exist_ok=True)
    target = CIRCUIT_DIR / "target" / "proof_dir"
    (out / "proof.bin").write_bytes((target / "proof").read_bytes())
    (out / "public_inputs.bin").write_bytes((target / "public_inputs").read_bytes())
    (out / "plaintext.bin").write_bytes(b"".join(int(x).to_bytes(32, "big") for x in w["plaintext"]))
    meta = {k: (hex(v) if isinstance(v, int) else [hex(x) for x in v]) for k, v in w.items() if k != "owner_sk"}
    (out / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    print(f"[wrote fixture] {out}")


def write_t10_prover_toml(w: dict) -> tuple[int, int]:
    # After this one-slot fixture is revealed, no hidden OCCUPIED slots remain.
    # ShadowToken's hidden BW/T10 manifest therefore hashes sixteen zero LSHs.
    lsh = [0] * 16
    z_commit = 0
    acc = sponge_18([w["shadow_id"], z_commit] + lsh)
    hi, lo = split_128(acc)
    T10_PROVER_TOML.write_text(
        f"shadow_id = {fhex(w['shadow_id'])}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh)}]\n"
    )
    os.chmod(T10_PROVER_TOML, 0o600)
    print(f"[wrote transient 0600] {T10_PROVER_TOML}")
    return hi, lo


def save_t10_fixture(seed: str, hi: int, lo: int) -> None:
    out = FIXTURE_DIR / seed
    proof_dir = T10_DIR / "target" / "proof_dir"
    (out / "proof_t10.bin").write_bytes((proof_dir / "proof").read_bytes())
    (out / "public_inputs_t10.bin").write_bytes((proof_dir / "public_inputs").read_bytes())
    t10_meta = {
        "z_index_commit": "0x0",
        "t10_hi": hex(hi),
        "t10_lo": hex(lo),
        "hidden_live_state_hashes_after_reveal": ["0x0"] * 16,
    }
    (out / "t10_meta.json").write_text(json.dumps(t10_meta, indent=2, sort_keys=True) + "\n")
    print(f"[wrote t10 fixture] {out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="reveal_demo")
    ap.add_argument("--no-prove", action="store_true")
    ap.add_argument("--rebuild-verifier", action="store_true", help="Regenerate contracts/src/SolveShadowVerifier.sol")
    args = ap.parse_args()

    print(f"[solve_shadow_v2 incremental fixture] seed={args.seed!r}")
    w = build_witness(args.seed.encode())
    write_prover_toml(w)
    try:
        print("[1/5] nargo execute")
        run([NARGO, "execute"], CIRCUIT_DIR, timeout=600)
        if args.no_prove:
            return

        target_dir = CIRCUIT_DIR / "target"
        print("[2/5] bb write_vk")
        run([BB, "write_vk", "-b", target_dir / "solve_shadow_v2.json", "-o", target_dir,
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)

        print("[3/5] bb prove")
        proof_dir = target_dir / "proof_dir"
        proof_dir.mkdir(exist_ok=True)
        run([BB, "prove", "-b", target_dir / "solve_shadow_v2.json", "-w", target_dir / "solve_shadow_v2.gz",
             "-o", proof_dir, "-k", target_dir / "vk", "--scheme", "ultra_honk", "--oracle_hash", "keccak"],
            CIRCUIT_DIR, timeout=1800)

        print("[4/5] bb verify")
        run([BB, "verify", "-k", target_dir / "vk", "-p", proof_dir / "proof", "-i", proof_dir / "public_inputs",
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=300)

        if args.rebuild_verifier:
            print("[4b/5] bb write_solidity_verifier")
            verifier_dst = ROOT / "contracts" / "src" / "SolveShadowVerifier.sol"
            run([BB, "write_solidity_verifier", "-k", target_dir / "vk", "-o", verifier_dst, "--verifier_target", "evm"],
                CIRCUIT_DIR, timeout=300)
            text = verifier_dst.read_text().replace("contract HonkVerifier", "contract SolveShadowVerifier")
            verifier_dst.write_text(text)
            print(f"[wrote] {verifier_dst}")

        print("[5/6] save reveal fixture")
        save_fixture(args.seed, w)

        print("[6/6] build real T10 refresh fixture")
        hi, lo = write_t10_prover_toml(w)
        t10_target = T10_DIR / "target"
        run([NARGO, "execute"], T10_DIR, timeout=600)
        run([BB, "write_vk", "-b", t10_target / "shadow_t10.json", "-o", t10_target,
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
        t10_proof_dir = t10_target / "proof_dir"
        t10_proof_dir.mkdir(exist_ok=True)
        run([BB, "prove", "-b", t10_target / "shadow_t10.json", "-w", t10_target / "shadow_t10.gz",
             "-o", t10_proof_dir, "-k", t10_target / "vk", "--scheme", "ultra_honk", "--oracle_hash", "keccak"],
            T10_DIR, timeout=1800)
        run([BB, "verify", "-k", t10_target / "vk", "-p", t10_proof_dir / "proof", "-i", t10_proof_dir / "public_inputs",
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=300)
        save_t10_fixture(args.seed, hi, lo)
    finally:
        if PROVER_TOML.exists():
            PROVER_TOML.unlink()
            print(f"[removed transient] {PROVER_TOML}")
        if T10_PROVER_TOML.exists():
            T10_PROVER_TOML.unlink()
            print(f"[removed transient] {T10_PROVER_TOML}")


if __name__ == "__main__":
    main()
