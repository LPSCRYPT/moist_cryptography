#!/usr/bin/env python3
"""Generate a solve_shadow_v2 fixture: reveal full per-slot plaintext +
the z-permutation for a shadow.

Synthesises a shadow with N occupied slots + 16-N empty slots + a known
z-permutation. The owner knows owner_k for each occupied slot
(deterministically derived from owner_sk + per-slot c1). Solve reveals
state_commits_root + z_perm_packed + binds chain's lsh_root.

Usage:
    python3 build_solve_shadow_v2_fixture.py [--seed solve_demo] [--n-occupied 4]
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
    live_state_hash, chain_step,
    fhex, bx32,
)

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "solve_shadow_v2"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
FIXTURE_DIR = ROOT / "contracts" / "test" / "fixtures" / "solve_shadow_v2"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_SOLVE_SHADOW_V2_FIXTURE_v1:" + label + b":" + seed).digest()
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


def deterministic_perm(seed: bytes) -> list[int]:
    """Fisher-Yates shuffle of [0..15] seeded from `seed`."""
    perm = list(range(16))
    for i in range(15, 0, -1):
        h = hashlib.sha256(b"OMP_SOLVE_PERM:" + seed + b":" + i.to_bytes(2, "big")).digest()
        j = int.from_bytes(h, "big") % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def pack_perm_base16(perm: list[int]) -> int:
    """Mirror the circuit's z_perm_packed: base-16 little-endian over 16 nibbles."""
    acc = 0
    mul = 1
    for v in perm:
        acc += v * mul
        mul *= 16
    return acc


def build_witness(seed: bytes, n_occupied: int) -> dict:
    print("[1/9] keygen: owner")
    owner_sk = deterministic_int(seed, b"owner_sk", GRUMPKIN_ORDER - 1) + 1
    owner_pk = ec_mul(G, owner_sk)
    assert owner_pk is not None

    shadow_id = deterministic_int(seed, b"shadow_id", P)
    print(f"  shadow_id = {hex(shadow_id)[:18]}...")

    is_occupied = [0] * 16
    plaintexts: list[list[int]] = [[0] * PLAINTEXT_FIELDS for _ in range(16)]
    prev_ct_commit = [0] * 16
    # M-05/M-06: empty slots must seed prev_c1 with an on-curve point so
    # Noir's multi_scalar_mul blackbox accepts the input. G is the cheapest
    # valid placeholder; the per-slot key-binding constraint
    # `occ * (owner_k[i] - kdf(sk*c1)) == 0` is gated by occ=0 so the
    # resulting MSM output is irrelevant in empty slots.
    prev_c1_x = [G[0]] * 16
    prev_c1_y = [G[1]] * 16
    prev_mutation_count = [0] * 16
    prev_chain_tip = [0] * 16
    owner_k_arr = [0] * 16
    prev_lsh_arr = [0] * 16

    occupied_idxs = sorted(set(deterministic_int(seed, f"slot_pick_{i}".encode(), 16) for i in range(n_occupied * 3)))[:n_occupied]
    if len(occupied_idxs) < n_occupied:
        occupied_idxs = list(range(n_occupied))
    print(f"[2/9] occupied slots = {occupied_idxs}")

    for i in occupied_idxs:
        is_occupied[i] = 1
        pose = pack_pose(x=2 + i, y=4 + (i % 8))
        w_dim = 6 + (i % 4)
        h_dim = 6 + ((i + 1) % 4)
        indices = [(j * 7 + i + 3) & 0xF for j in range(w_dim * h_dim)]
        plaintext = encode_plaintext_v2(pose, w_dim, h_dim, indices)
        plaintexts[i] = plaintext

        r_i = deterministic_int(seed, f"r_{i}".encode(), GRUMPKIN_ORDER - 1) + 1
        c1, c2, k = ecies_encrypt_v2(plaintext, owner_pk, r_i)
        owner_k_arr[i] = k
        prev_c1_x[i] = c1[0]
        prev_c1_y[i] = c1[1]
        prev_ct_commit[i] = sponge_39(c2)
        prev_mutation_count[i] = 0
        origin_face_id_i = deterministic_int(seed, f"originFaceId_{i}".encode(), P)
        prev_chain_tip[i] = chain_step(0, sponge_39(plaintext), prev_ct_commit[i], 0, origin_face_id_i, i)
        prev_lsh_arr[i] = live_state_hash(
            sponge_39(plaintext), prev_ct_commit[i],
            prev_c1_x[i], prev_c1_y[i],
            prev_mutation_count[i], prev_chain_tip[i],
        )

    # z-perm: deterministic Fisher-Yates over 0..15.
    z_perm = deterministic_perm(seed)
    z_perm_packed = pack_perm_base16(z_perm)
    z_index_commit = sponge_16(z_perm)

    print(f"[3/9] z_perm = {z_perm}")
    print(f"  packed = {hex(z_perm_packed)[:18]}...")
    print(f"  z_commit = {hex(z_index_commit)[:18]}...")

    state_commits = [0] * 16
    for i in occupied_idxs:
        state_commits[i] = sponge_39(plaintexts[i])
    state_commits_root = sponge_16(state_commits)
    lsh_root = sponge_16(prev_lsh_arr)

    print("[4/9] hash-roots computed")

    return {
        # PI
        "shadow_id": shadow_id,
        "state_commits_root": state_commits_root,
        "z_perm_packed": z_perm_packed,
        "z_index_commit": z_index_commit,
        "lsh_root": lsh_root,
        "owner_pk_x": owner_pk[0],
        "owner_pk_y": owner_pk[1],

        # witness arrays
        "is_occupied": is_occupied,
        "plaintexts": plaintexts,
        "prev_ct_commit": prev_ct_commit,
        "prev_c1_x": prev_c1_x,
        "prev_c1_y": prev_c1_y,
        "prev_mutation_count": prev_mutation_count,
        "prev_chain_tip": prev_chain_tip,
        "owner_k": owner_k_arr,
        "prev_lsh": prev_lsh_arr,
        "z_perm": z_perm,
        "owner_sk": owner_sk,

        # for chain seeding
        "occupied_idxs": occupied_idxs,
        "state_commits": state_commits,
    }


def write_prover_toml(w: dict) -> None:
    PROVER_TOML.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"shadow_id = {fhex(w['shadow_id'])}",
        f"state_commits_root = {fhex(w['state_commits_root'])}",
        f"z_perm_packed_pi = {fhex(w['z_perm_packed'])}",
        f"z_index_commit = {fhex(w['z_index_commit'])}",
        f"lsh_root = {fhex(w['lsh_root'])}",
        f"owner_pk_x = {fhex(w['owner_pk_x'])}",
        f"owner_pk_y = {fhex(w['owner_pk_y'])}",

        render_array("is_occupied", w["is_occupied"]),
        render_2d("plaintexts", w["plaintexts"]),
        render_array("prev_ct_commit", w["prev_ct_commit"]),
        render_array("prev_c1_x", w["prev_c1_x"]),
        render_array("prev_c1_y", w["prev_c1_y"]),
        render_array("prev_mutation_count", w["prev_mutation_count"]),
        render_array("prev_chain_tip", w["prev_chain_tip"]),
        render_array("owner_k", w["owner_k"]),
        render_array("prev_lsh", w["prev_lsh"]),

        render_array("z_perm", w["z_perm"]),
        f"owner_sk = {fhex(w['owner_sk'])}",
    ]
    PROVER_TOML.write_text("\n".join(lines) + "\n")
    print(f"[wrote] {PROVER_TOML}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="solve_demo")
    ap.add_argument("--n-occupied", type=int, default=4)
    ap.add_argument("--no-prove", action="store_true")
    ap.add_argument("--rebuild-verifier", action="store_true",
                    help="After proving, regenerate contracts/src/SolveShadowVerifier.sol")
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[solve_shadow_v2 fixture] seed={args.seed!r} n_occupied={args.n_occupied}")

    w = build_witness(seed, args.n_occupied)
    write_prover_toml(w)

    print("[5/9] nargo execute")
    run([NARGO, "execute"], CIRCUIT_DIR, timeout=600)

    if args.no_prove:
        return

    target_dir = CIRCUIT_DIR / "target"
    print("[6/9] bb write_vk")
    run([BB, "write_vk", "-b", str(target_dir / "solve_shadow_v2.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)

    print("[7/9] bb prove")
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "solve_shadow_v2.json"),
         "-w", str(target_dir / "solve_shadow_v2.gz"),
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
        verifier_tmp = target_dir / "SolveShadowVerifier.tmp.sol"
        run([BB, "write_solidity_verifier",
             "-k", str(target_dir / "vk"),
             "-o", str(verifier_tmp),
             "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
        verifier_dst = ROOT / "contracts" / "src" / "SolveShadowVerifier.sol"
        text = verifier_tmp.read_text().replace(
            "contract HonkVerifier", "contract SolveShadowVerifier")
        verifier_dst.write_text(text)
        verifier_tmp.unlink()
        print(f"[wrote] {verifier_dst}")

    fix_dir = FIXTURE_DIR / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes = (proof_dir / "public_inputs").read_bytes()
    (fix_dir / "proof.bin").write_bytes(proof_bytes)
    (fix_dir / "public_inputs.bin").write_bytes(pi_bytes)

    meta = {
        "seed": args.seed,
        "n_occupied": args.n_occupied,
        "occupied_idxs": w["occupied_idxs"],
        "shadow_id": bx32(w["shadow_id"]),
        "state_commits_root": bx32(w["state_commits_root"]),
        "z_perm_packed": bx32(w["z_perm_packed"]),
        "z_index_commit": bx32(w["z_index_commit"]),
        "lsh_root": bx32(w["lsh_root"]),
        "owner_pk_x": bx32(w["owner_pk_x"]),
        "owner_pk_y": bx32(w["owner_pk_y"]),

        # chain seeding
        "prev_lsh": [bx32(v) for v in w["prev_lsh"]],
        "prev_ct_commit": [bx32(v) for v in w["prev_ct_commit"]],
        "prev_c1_x": [bx32(v) for v in w["prev_c1_x"]],
        "prev_c1_y": [bx32(v) for v in w["prev_c1_y"]],
        "prev_mutation_count": w["prev_mutation_count"],
        "prev_chain_tip": [bx32(v) for v in w["prev_chain_tip"]],
        "state_commits": [bx32(v) for v in w["state_commits"]],

        "z_perm": w["z_perm"],
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    # Per-slot plaintexts as bytes32 arrays for forge consumption.
    plaintexts_json = {
        "plaintexts": [
            [bx32(v) for v in w["plaintexts"][i]]
            for i in range(16)
        ],
    }
    (fix_dir / "plaintexts.json").write_text(json.dumps(plaintexts_json, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof.bin ({len(proof_bytes)} B)")
    print(f"        public_inputs.bin ({len(pi_bytes)} B)")


if __name__ == "__main__":
    main()
