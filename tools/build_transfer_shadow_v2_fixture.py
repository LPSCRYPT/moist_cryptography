#!/usr/bin/env python3
"""Generate a transfer_shadow_v2 fixture: rotate all 16 slots' encryption
to a new owner.

Synthesises a shadow with N occupied slots (default 4) and 16-N empty
slots, then proves the transfer of the entire shadow to a fresh
recipient. Writes Prover.toml, runs nargo execute + bb prove, dumps
proof + public_inputs + meta.json into contracts/test/fixtures/.

Usage:
    python3 build_transfer_shadow_v2_fixture.py [--seed transfer_demo] [--n-occupied 4]

Run-time on M3: ~3-5 minutes (16-slot ECIES + sponge_16 hash-roots).
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
    P, PLAINTEXT_FIELDS,
    sponge_39, sponge_6, sponge_16, keystream_39, poseidon2_hash_2,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2, ecies_decrypt_v2,
    live_state_hash, chain_step, transfer_chain_step,
    fhex, bx32,
    TRANSFER_TAG,
)

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "transfer_shadow_v2"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
FIXTURE_DIR = ROOT / "contracts" / "test" / "fixtures" / "transfer_shadow_v2"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_TRANSFER_SHADOW_V2_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def render_array(name: str, vals: list[int]) -> str:
    return f"{name} = [{', '.join(fhex(v) for v in vals)}]"


def render_2d(name: str, rows: list[list[int]]) -> str:
    inner = []
    for r in rows:
        inner.append(f"  [{', '.join(fhex(v) for v in r)}]")
    return f"{name} = [\n" + ",\n".join(inner) + "\n]"


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


def build_witness(seed: bytes, n_occupied: int) -> dict:
    print("[1/9] keygen: prev_owner + recipient")
    prev_owner_sk = deterministic_int(seed, b"prev_owner_sk", GRUMPKIN_ORDER - 1) + 1
    prev_owner_pk = ec_mul(G, prev_owner_sk)
    assert prev_owner_pk is not None
    recipient_sk = deterministic_int(seed, b"recipient_sk", GRUMPKIN_ORDER - 1) + 1
    recipient_pk = ec_mul(G, recipient_sk)
    assert recipient_pk is not None

    shadow_id = deterministic_int(seed, b"shadow_id", P)
    print(f"  shadow_id = {hex(shadow_id)[:18]}...")

    # Per-slot witness arrays (always 16 entries; empty slots padded with zeros).
    is_occupied = [0] * 16
    plaintexts: list[list[int]] = [[0] * PLAINTEXT_FIELDS for _ in range(16)]
    prev_state_commit = [0] * 16
    prev_ct_commit = [0] * 16
    prev_c1_x = [0] * 16
    prev_c1_y = [0] * 16
    prev_mutation_count = [0] * 16
    prev_chain_tip = [0] * 16
    prev_k_arr = [0] * 16
    new_k_arr = [0] * 16
    # M-06: every slot's new_r must be nonzero (the circuit asserts
    # `new_r[i] != 0` unconditionally, even for empty slots whose ECIES
    # output is masked by occ=0). 1 is a cheap nonzero placeholder.
    new_r_arr = [1] * 16
    prev_lsh_arr = [0] * 16

    # Per-slot post-rotation values (chain-side, contract reconstructs).
    new_lsh_arr = [0] * 16
    new_c1_x_arr = [0] * 16
    new_c1_y_arr = [0] * 16
    new_ct_commit_arr = [0] * 16
    new_chain_tip_arr = [0] * 16
    new_mutation_count_arr = [0] * 16
    new_c2_arr: list[list[int]] = [[0] * PLAINTEXT_FIELDS for _ in range(16)]

    # Pick which slots are occupied. Use a deterministic spread.
    occupied_idxs = sorted(set(deterministic_int(seed, f"slot_pick_{i}".encode(), 16) for i in range(n_occupied * 3)))[:n_occupied]
    if len(occupied_idxs) < n_occupied:
        # fallback: just take first n_occupied
        occupied_idxs = list(range(n_occupied))
    print(f"[2/9] occupied slots = {occupied_idxs}")

    for i in occupied_idxs:
        is_occupied[i] = 1
        # Build a synthetic plaintext for slot i.
        pose = pack_pose(x=2 + i, y=4 + (i % 8))
        w_dim = 6 + (i % 4)
        h_dim = 6 + ((i + 1) % 4)
        indices = [(j * 7 + i + 3) & 0xF for j in range(w_dim * h_dim)]
        plaintext = encode_plaintext_v2(pose, w_dim, h_dim, indices)
        plaintexts[i] = plaintext

        # Encrypt under prev_owner.
        prev_r = deterministic_int(seed, f"prev_r_{i}".encode(), GRUMPKIN_ORDER - 1) + 1
        prev_c1, prev_c2, prev_k = ecies_encrypt_v2(plaintext, prev_owner_pk, prev_r)
        prev_state_commit[i] = sponge_39(plaintext)
        prev_ct_commit[i] = sponge_39(prev_c2)
        prev_c1_x[i] = prev_c1[0]
        prev_c1_y[i] = prev_c1[1]
        prev_mutation_count[i] = 0
        # Mint-time chain tip (count=0 baseline, like mutate_slot fixture).
        origin_face_id_i = deterministic_int(seed, f"originFaceId_{i}".encode(), P)
        prev_chain_tip[i] = chain_step(0, prev_state_commit[i], prev_ct_commit[i],
                                        0, origin_face_id_i, i)
        prev_k_arr[i] = prev_k
        prev_lsh_arr[i] = live_state_hash(prev_state_commit[i], prev_ct_commit[i],
                                           prev_c1_x[i], prev_c1_y[i],
                                           prev_mutation_count[i], prev_chain_tip[i])

        # Rotate ECIES under recipient_pk.
        new_r = deterministic_int(seed, f"new_r_{i}".encode(), GRUMPKIN_ORDER - 1) + 1
        new_c1, new_c2, new_k = ecies_encrypt_v2(plaintext, recipient_pk, new_r)
        new_k_arr[i] = new_k
        new_r_arr[i] = new_r
        new_c1_x_arr[i] = new_c1[0]
        new_c1_y_arr[i] = new_c1[1]
        new_ct_commit_arr[i] = sponge_39(new_c2)
        new_c2_arr[i] = new_c2

        # New chain tip extends prev with TRANSFER event.
        new_count = prev_mutation_count[i] + 1
        new_mutation_count_arr[i] = new_count
        new_chain_tip_arr[i] = transfer_chain_step(
            prev_chain_tip[i], recipient_pk[0], recipient_pk[1], new_count, i,
        )

        # New lsh: state_commit unchanged (re-encryption preserves plaintext);
        # ct_commit + c1 + count + chain_tip rotated.
        new_lsh_arr[i] = live_state_hash(
            prev_state_commit[i],     # unchanged
            new_ct_commit_arr[i],
            new_c1_x_arr[i],
            new_c1_y_arr[i],
            new_count,
            new_chain_tip_arr[i],
        )

    print("[3/9] sanity: decrypt rotation round-trip on each occupied slot")
    for i in occupied_idxs:
        # Recipient must be able to decrypt new ciphertext.
        decoded, dk = ecies_decrypt_v2(
            (new_c1_x_arr[i], new_c1_y_arr[i]), new_c2_arr[i], recipient_sk,
        )
        assert decoded == plaintexts[i], f"recipient decrypt mismatch on slot {i}"
        assert dk == new_k_arr[i], f"recipient k mismatch on slot {i}"

    print("[4/9] sponge_16 hash-roots")
    prev_lsh_root = sponge_16(prev_lsh_arr)
    new_lsh_root = sponge_16(new_lsh_arr)
    new_chain_tips_root = sponge_16(new_chain_tip_arr)
    new_ct_commits_root = sponge_16(new_ct_commit_arr)

    return {
        # PI
        "shadow_id": shadow_id,
        "recipient_pk_x": recipient_pk[0],
        "recipient_pk_y": recipient_pk[1],
        "prev_lsh_root": prev_lsh_root,
        "new_lsh_root": new_lsh_root,
        "prev_owner_pk_x": prev_owner_pk[0],
        "prev_owner_pk_y": prev_owner_pk[1],
        "new_chain_tips_root": new_chain_tips_root,
        "new_ct_commits_root": new_ct_commits_root,

        # witness arrays
        "prev_lsh": prev_lsh_arr,
        "is_occupied": is_occupied,
        "plaintexts": plaintexts,
        "prev_state_commit": prev_state_commit,
        "prev_ct_commit": prev_ct_commit,
        "prev_c1_x": prev_c1_x,
        "prev_c1_y": prev_c1_y,
        "prev_mutation_count": prev_mutation_count,
        "prev_chain_tip": prev_chain_tip,
        "prev_k": prev_k_arr,
        "new_k": new_k_arr,
        "new_r": new_r_arr,
        "prev_owner_sk": prev_owner_sk,

        # chain-side post-rotation values
        "occupied_idxs": occupied_idxs,
        "new_lsh": new_lsh_arr,
        "new_c1_x": new_c1_x_arr,
        "new_c1_y": new_c1_y_arr,
        "new_ct_commit": new_ct_commit_arr,
        "new_chain_tip": new_chain_tip_arr,
        "new_mutation_count": new_mutation_count_arr,
        "new_c2": new_c2_arr,
        "recipient_sk": recipient_sk,
    }


def write_prover_toml(w: dict) -> None:
    PROVER_TOML.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"shadow_id = {fhex(w['shadow_id'])}",
        f"recipient_pk_x = {fhex(w['recipient_pk_x'])}",
        f"recipient_pk_y = {fhex(w['recipient_pk_y'])}",
        f"prev_lsh_root = {fhex(w['prev_lsh_root'])}",
        f"new_lsh_root = {fhex(w['new_lsh_root'])}",
        f"prev_owner_pk_x = {fhex(w['prev_owner_pk_x'])}",
        f"prev_owner_pk_y = {fhex(w['prev_owner_pk_y'])}",
        f"new_chain_tips_root = {fhex(w['new_chain_tips_root'])}",
        f"new_ct_commits_root = {fhex(w['new_ct_commits_root'])}",

        render_array("prev_lsh", w["prev_lsh"]),
        render_array("is_occupied", w["is_occupied"]),
        render_2d("plaintexts", w["plaintexts"]),
        render_array("prev_state_commit", w["prev_state_commit"]),
        render_array("prev_ct_commit", w["prev_ct_commit"]),
        render_array("prev_c1_x", w["prev_c1_x"]),
        render_array("prev_c1_y", w["prev_c1_y"]),
        render_array("prev_mutation_count", w["prev_mutation_count"]),
        render_array("prev_chain_tip", w["prev_chain_tip"]),
        render_array("prev_k", w["prev_k"]),
        render_array("new_k", w["new_k"]),
        render_array("new_r", w["new_r"]),
        f"prev_owner_sk = {fhex(w['prev_owner_sk'])}",
    ]
    PROVER_TOML.write_text("\n".join(lines) + "\n")
    print(f"[wrote] {PROVER_TOML}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="transfer_demo")
    ap.add_argument("--n-occupied", type=int, default=4)
    ap.add_argument("--rebuild-verifier", action="store_true",
                    help="after prove+verify, regenerate contracts/src/TransferShadowVerifier.sol")
    ap.add_argument("--no-prove", action="store_true")
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[transfer_shadow_v2 fixture] seed={args.seed!r} n_occupied={args.n_occupied}")

    w = build_witness(seed, args.n_occupied)
    write_prover_toml(w)

    print("[5/9] nargo execute")
    run([NARGO, "execute"], CIRCUIT_DIR, timeout=600)
    witness = CIRCUIT_DIR / "target" / "transfer_shadow_v2.gz"
    print(f"[ok] witness at {witness}")

    if args.no_prove:
        return

    target_dir = CIRCUIT_DIR / "target"
    print("[6/9] bb write_vk")
    run([BB, "write_vk", "-b", str(target_dir / "transfer_shadow_v2.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)

    print("[7/9] bb prove")
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "transfer_shadow_v2.json"),
         "-w", str(witness),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=1800)

    print("[8/9] bb verify (sanity)")
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=300)
    print("[ok] proof verified")

    if args.rebuild_verifier:
        print("[8b/9] bb write_solidity_verifier")
        verifier_tmp = target_dir / "TransferShadowVerifier.tmp.sol"
        run([BB, "write_solidity_verifier",
             "-k", str(target_dir / "vk"),
             "-o", str(verifier_tmp),
             "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
        verifier_dst = ROOT / "contracts" / "src" / "TransferShadowVerifier.sol"
        text = verifier_tmp.read_text().replace(
            "contract HonkVerifier", "contract TransferShadowVerifier")
        verifier_dst.write_text(text)
        verifier_tmp.unlink()
        print(f"  wrote {verifier_dst}")

    # Save fixture for forge tests.
    fix_dir = FIXTURE_DIR / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes = (proof_dir / "public_inputs").read_bytes()
    (fix_dir / "proof.bin").write_bytes(proof_bytes)
    (fix_dir / "public_inputs.bin").write_bytes(pi_bytes)

    # Also dump per-slot c2 for occupied slots so the contract can replay them.
    c2_per_slot: dict[int, list[str]] = {}
    for i in w["occupied_idxs"]:
        c2_per_slot[i] = [bx32(v) for v in w["new_c2"][i]]

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
        "new_ct_commits_root": bx32(w["new_ct_commits_root"]),

        # per-slot pre-rotation chain state (contract seeds these for the test)
        "prev_lsh": [bx32(v) for v in w["prev_lsh"]],
        "prev_c1_x": [bx32(v) for v in w["prev_c1_x"]],
        "prev_c1_y": [bx32(v) for v in w["prev_c1_y"]],
        "prev_mutation_count": w["prev_mutation_count"],
        "prev_chain_tip": [bx32(v) for v in w["prev_chain_tip"]],
        "prev_state_commit": [bx32(v) for v in w["prev_state_commit"]],
        "prev_ct_commit": [bx32(v) for v in w["prev_ct_commit"]],

        # per-slot post-rotation chain state (contract writes these)
        "new_lsh": [bx32(v) for v in w["new_lsh"]],
        "new_c1_x": [bx32(v) for v in w["new_c1_x"]],
        "new_c1_y": [bx32(v) for v in w["new_c1_y"]],
        "new_ct_commit": [bx32(v) for v in w["new_ct_commit"]],
        "new_chain_tip": [bx32(v) for v in w["new_chain_tip"]],
        "new_mutation_count": w["new_mutation_count"],

        "c2_per_slot": c2_per_slot,
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof.bin ({len(proof_bytes)} B)")
    print(f"        public_inputs.bin ({len(pi_bytes)} B)")


if __name__ == "__main__":
    main()
