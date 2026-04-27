#!/usr/bin/env python3
"""Generate a mutate_slot fixture from a synthetic owner + synthetic state.

Pipeline:
  1. Roll a Grumpkin keypair for `owner` from a deterministic seed.
  2. Synthesise an OLD slot state: pose, w, h, palette indices.
  3. ECIES-encrypt OLD plaintext to owner -> (old_c1, old_c2, old_k).
  4. Compute old_state_commit, old_ct_commit, old_chain_tip,
     old_live_state_hash.
  5. Synthesise a NEW slot state (different pose/dims/indices, still
     canvas-contained).
  6. Roll new_r; ECIES-encrypt NEW plaintext to owner -> (new_c1, new_c2, new_k).
  7. Compute new_state_commit, new_ct_commit, new_chain_tip,
     new_live_state_hash.
  8. Write Prover.toml with all witness fields.
  9. nargo execute -> witness; bb prove -> proof; bb write_solidity_verifier
     -> MutateSlotVerifier.sol.
 10. Save fixture JSON for Forge tests.

Usage:
    python3 build_mutate_slot_fixture.py [--seed mutate_demo] [--rebuild-verifier]

Run-time on M3: ~1 minute end-to-end (Poseidon perms + nargo execute + bb prove).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # noqa: E402
from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS, CANVAS_W, CANVAS_H,
    sponge_39, sponge_6, keystream_39, poseidon2_hash_2,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2, ecies_decrypt_v2,
    live_state_hash, chain_step, fhex,
)

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "mutate_slot"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
FIXTURE_DIR = ROOT / "contracts" / "test" / "fixtures" / "mutate_slot"
VERIFIER_DST = ROOT / "contracts" / "src" / "MutateSlotVerifier.sol"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_MUTATE_SLOT_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def run(cmd: list, cwd: Path, timeout: int = 600) -> str:
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s")
    return p.stdout


def render_array(name: str, vals: list[int]) -> str:
    return f"{name} = [{', '.join(fhex(v) for v in vals)}]"


def build_witness(seed: bytes) -> dict:
    """Compute every PI + witness field for a synthetic mutation."""
    print("[1/9] keygen")
    owner_sk = deterministic_int(seed, b"owner_sk", GRUMPKIN_ORDER - 1) + 1
    owner_pk = ec_mul(G, owner_sk)
    assert owner_pk is not None

    # Synthetic public binding values (transcript-only in the circuit).
    print("[2/9] PI binding stubs")
    shadow_id = deterministic_int(seed, b"shadow_id", P)
    slot_idx = 3
    feature_id = deterministic_int(seed, b"feature_id", P)
    type_idx = 5
    origin_face_id = deterministic_int(seed, b"origin_face_id", P)
    palette_commit = deterministic_int(seed, b"palette_commit", P)

    # ---- OLD slot state ----
    print("[3/9] old plaintext")
    old_pose = pack_pose(x=4, y=8)             # identity rot/scale, anchor (4, 8)
    old_w, old_h = 12, 10
    old_indices = [(i * 7 + 3) & 0xF for i in range(old_w * old_h)]
    old_plaintext = encode_plaintext_v2(old_pose, old_w, old_h, old_indices)
    assert len(old_plaintext) == PLAINTEXT_FIELDS

    print("[4/9] encrypt old plaintext")
    old_r = deterministic_int(seed, b"old_r", GRUMPKIN_ORDER - 1) + 1
    old_c1, old_c2, old_k = ecies_encrypt_v2(old_plaintext, owner_pk, old_r)
    old_state_commit = sponge_39(old_plaintext)
    old_ct_commit = sponge_39(old_c2)

    # Sanity: decryption recovers same plaintext.
    decoded, dk = ecies_decrypt_v2(old_c1, old_c2, owner_sk)
    assert decoded == old_plaintext
    assert dk == old_k

    # Mint-time chain tip is sponge_6(0, state, ct, 0, origin_face_id, slot).
    # Mutation count starts at 0; first user mutation produces count = 1.
    old_count = 0
    old_chain_tip = chain_step(0, old_state_commit, old_ct_commit, 0, origin_face_id, slot_idx)
    old_lsh = live_state_hash(old_state_commit, old_ct_commit, old_c1[0], old_c1[1],
                              old_count, old_chain_tip)

    # ---- NEW slot state ----
    print("[5/9] new plaintext")
    new_pose = pack_pose(x=10, y=20)           # repositioned, still axis-aligned
    new_w, new_h = 16, 14
    new_indices = [(i * 11 + 5) & 0xF for i in range(new_w * new_h)]
    new_plaintext = encode_plaintext_v2(new_pose, new_w, new_h, new_indices)

    print("[6/9] encrypt new plaintext (deterministic k via owner_pk binding)")
    new_r = deterministic_int(seed, b"new_r", GRUMPKIN_ORDER - 1) + 1
    new_c1, new_c2, new_k = ecies_encrypt_v2(new_plaintext, owner_pk, new_r)
    new_state_commit = sponge_39(new_plaintext)
    new_ct_commit = sponge_39(new_c2)

    new_count = old_count + 1
    new_chain_tip = chain_step(old_chain_tip, new_state_commit, new_ct_commit,
                               new_count, origin_face_id, slot_idx)
    new_lsh = live_state_hash(new_state_commit, new_ct_commit, new_c1[0], new_c1[1],
                              new_count, new_chain_tip)

    c2_field_count = PLAINTEXT_FIELDS  # always 39 in v2 (13 sponge blocks; on-chain Yul-friendly) (constant per-slot capacity)

    return {
        "shadow_id": shadow_id,
        "slot_idx": slot_idx,
        "feature_id": feature_id,
        "type_idx": type_idx,
        "origin_face_id": origin_face_id,
        "palette_commit": palette_commit,
        "old_lsh": old_lsh,
        "new_lsh": new_lsh,
        "new_ct_commit": new_ct_commit,
        "c2_field_count": c2_field_count,
        "owner_pk_x": owner_pk[0],
        "owner_pk_y": owner_pk[1],
        "prev_chain_tip": old_chain_tip,
        "new_chain_tip": new_chain_tip,
        "prev_mutation_count": old_count,
        "new_mutation_count": new_count,

        # witness
        "old_plaintext": old_plaintext,
        "new_plaintext": new_plaintext,
        "old_state_commit": old_state_commit,
        "old_ct_commit": old_ct_commit,
        "old_c1_x": old_c1[0],
        "old_c1_y": old_c1[1],
        "old_count": old_count,
        "old_chain_tip": old_chain_tip,
        "old_k": old_k,
        "new_k": new_k,
        "new_r": new_r,
        "owner_sk": owner_sk,
        "w_new": new_w,
        "h_new": new_h,
        "c2_field_count_w": c2_field_count,

        # for the chain side (events / contract calldata)
        "old_c2": old_c2,
        "new_c2": new_c2,
        "new_c1_x": new_c1[0],
        "new_c1_y": new_c1[1],
    }


def write_prover_toml(w: dict) -> None:
    PROVER_TOML.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"shadow_id = {fhex(w['shadow_id'])}",
        f"slot_idx = {fhex(w['slot_idx'])}",
        f"feature_id = {fhex(w['feature_id'])}",
        f"type_idx = {fhex(w['type_idx'])}",
        f"origin_face_id = {fhex(w['origin_face_id'])}",
        f"palette_commit = {fhex(w['palette_commit'])}",
        f"old_live_state_hash = {fhex(w['old_lsh'])}",
        f"new_live_state_hash = {fhex(w['new_lsh'])}",
        f"new_ct_commit = {fhex(w['new_ct_commit'])}",
        f"c2_field_count = {fhex(w['c2_field_count'])}",
        f"owner_pk_x = {fhex(w['owner_pk_x'])}",
        f"owner_pk_y = {fhex(w['owner_pk_y'])}",
        f"prev_chain_tip = {fhex(w['prev_chain_tip'])}",
        f"new_chain_tip_pi = {fhex(w['new_chain_tip'])}",
        f"prev_mutation_count = {fhex(w['prev_mutation_count'])}",
        f"new_mutation_count_pi = {fhex(w['new_mutation_count'])}",

        render_array("old_plaintext", w["old_plaintext"]),
        render_array("new_plaintext", w["new_plaintext"]),

        f"old_state_commit = {fhex(w['old_state_commit'])}",
        f"old_ct_commit = {fhex(w['old_ct_commit'])}",
        f"old_c1_x = {fhex(w['old_c1_x'])}",
        f"old_c1_y = {fhex(w['old_c1_y'])}",
        f"old_mutation_count = {fhex(w['old_count'])}",
        f"old_chain_tip = {fhex(w['old_chain_tip'])}",
        f"old_k = {fhex(w['old_k'])}",
        f"new_k = {fhex(w['new_k'])}",
        f"new_r = {fhex(w['new_r'])}",
        f"owner_sk = {fhex(w['owner_sk'])}",
        f"w_new = {fhex(w['w_new'])}",
        f"h_new = {fhex(w['h_new'])}",
        f"c2_field_count_w = {fhex(w['c2_field_count_w'])}",
    ]
    PROVER_TOML.write_text("\n".join(lines) + "\n")
    print(f"[wrote] {PROVER_TOML}")


def write_fixture_json(w: dict, fixture_path: Path) -> None:
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    pi = [
        w["shadow_id"], w["slot_idx"], w["feature_id"], w["type_idx"],
        w["origin_face_id"], w["palette_commit"], w["old_lsh"], w["new_lsh"],
        w["new_ct_commit"], w["c2_field_count"], w["owner_pk_x"], w["owner_pk_y"],
        w["prev_chain_tip"], w["new_chain_tip"], w["prev_mutation_count"], w["new_mutation_count"],
    ]
    out = {
        "circuit": "mutate_slot",
        "pi": [hex(v) for v in pi],
        "old_c2": [hex(v) for v in w["old_c2"]],
        "new_c2": [hex(v) for v in w["new_c2"]],
        "new_c1": {"x": hex(w["new_c1_x"]), "y": hex(w["new_c1_y"])},
        "old_c1": {"x": hex(w["old_c1_x"]), "y": hex(w["old_c1_y"])},
    }
    fixture_path.write_text(json.dumps(out, indent=2))
    print(f"[wrote] {fixture_path}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="mutate_demo_v2")
    ap.add_argument("--rebuild-verifier", action="store_true",
                    help="Always regenerate MutateSlotVerifier.sol via bb")
    ap.add_argument("--no-prove", action="store_true",
                    help="Stop after nargo execute (skip bb prove + verifier gen)")
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[mutate_slot fixture] seed={args.seed!r}")

    w = build_witness(seed)
    write_prover_toml(w)

    print("[7/9] nargo execute")
    run([NARGO, "execute"], CIRCUIT_DIR)
    witness = CIRCUIT_DIR / "target" / "mutate_slot.gz"
    print(f"[ok] witness at {witness}")

    if args.no_prove:
        write_fixture_json(w, FIXTURE_DIR / f"{args.seed}.json")
        return

    print("[8a/9] bb write_vk")
    target_dir = CIRCUIT_DIR / "target"
    run([BB, "write_vk",
         "-b", str(target_dir / "mutate_slot.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk",
         "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)

    print("[8b/9] bb prove")
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove",
         "-b", str(target_dir / "mutate_slot.json"),
         "-w", str(witness),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk",
         "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)
    proof_path = proof_dir / "proof"
    pi_path = proof_dir / "public_inputs"
    print(f"[ok] proof at {proof_path}; PI at {pi_path}")

    print("[8c/9] bb verify (sanity)")
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_path),
         "-i", str(pi_path),
         "--scheme", "ultra_honk",
         "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=300)

    if args.rebuild_verifier or not VERIFIER_DST.exists():
        print("[9/9] bb write_solidity_verifier")
        verifier_path = target_dir / "Verifier.sol"
        run([BB, "write_solidity_verifier",
             "-k", str(target_dir / "vk"),
             "-o", str(verifier_path),
             "--verifier_target", "evm"], CIRCUIT_DIR, timeout=900)
        gen = verifier_path
        if not gen.exists():
            sys.exit(f"verifier not generated at {gen}")
        VERIFIER_DST.parent.mkdir(parents=True, exist_ok=True)
        # Rename the generated `HonkVerifier` contract to `MutateSlotVerifier`.
        text = gen.read_text()
        text = text.replace("contract HonkVerifier", "contract MutateSlotVerifier")
        VERIFIER_DST.write_text(text)
        print(f"[wrote] {VERIFIER_DST}")
    else:
        print("[skip] MutateSlotVerifier.sol already present")

    write_fixture_json(w, FIXTURE_DIR / f"{args.seed}.json")
    # Also store proof + PI bytes alongside the fixture for Forge to load.
    fix_dir = FIXTURE_DIR / args.seed
    fix_dir.mkdir(exist_ok=True)
    (fix_dir / "proof.bin").write_bytes(proof_path.read_bytes())
    (fix_dir / "public_inputs.bin").write_bytes(pi_path.read_bytes())
    print(f"[wrote] {fix_dir}/proof.bin and public_inputs.bin")


if __name__ == "__main__":
    main()
