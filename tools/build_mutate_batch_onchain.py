#!/usr/bin/env python3
"""Build a chained mutateBatch fixture for the RECIPIENT operating on
the live state of shadow B post-transfer.

Two mutate_slot proofs (slots a, b) + one shadow_t10 proof against the
post-batch B manifest. All ECIES re-encrypts under recipient_pk; signing
key on chain is PRIVATE_KEY_2.

Wall-clock on M3: ~3 min (60s + 60s mutate + 30s T10 + nargo overhead).

Usage:
    python3 tools/build_mutate_batch_onchain.py \
        --slot-a 0 --slot-b 1 \
        --out-seed onchain_mutate_batch_b
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
    sponge_39, sponge_6, keystream_39,
    poseidon2_hash_2,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2, ecies_decrypt_v2,
    chain_step, live_state_hash,
    fhex, bx32,
)
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402
from recipient_b_state import load_post_transfer_b_state  # noqa: E402

ROOT = REPO.parent
MUT_DIR = ROOT / "circuits" / "mutate_slot"
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_mutate_batch"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def run(cmd, cwd, timeout=1800):
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s")
    print(f"  [{elapsed:.1f}s]")


def detr_int(salt: bytes, label: bytes, mod: int) -> int:
    """Deterministic int distinct from any mint/transfer/insert prefix."""
    h = hashlib.sha256(b"OMP_RECIPIENT_MUTATE_BATCH_v1:" + label + b":" + salt).digest()
    return int.from_bytes(h, "big") % mod


def synthesize_new_plaintext(slot_idx: int, salt: bytes) -> tuple[list[int], int, int, int]:
    """Pick a NEW pose/dims/indices for the recipient's mutation. Stays
    inside 48x48 canvas, distinct from any prior fixture's witness."""
    pose = pack_pose(x=8 + slot_idx * 3, y=12 + slot_idx)
    w_dim = 12 + (slot_idx % 4)
    h_dim = 10 + ((slot_idx + 1) % 4)
    indices = [
        (j * 13 + slot_idx * 5 + 7) & 0xF
        for j in range(w_dim * h_dim)
    ]
    pt = encode_plaintext_v2(pose, w_dim, h_dim, indices)
    assert len(pt) == PLAINTEXT_FIELDS
    return pt, pose, w_dim, h_dim


def render_array(name: str, vals: list[int]) -> str:
    return f"{name} = [{', '.join(fhex(v) for v in vals)}]"


def write_mutate_prover_toml(w: dict) -> None:
    toml = MUT_DIR / "Prover.toml"
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
        f"c2_field_count_w = {fhex(w['c2_field_count'])}",
    ]
    toml.write_text("\n".join(lines) + "\n")


def build_mutate_witness_for_recipient(slot_state: dict, salt: bytes) -> dict:
    """Build mutate_slot witness for the recipient's mutation against an
    arbitrary current slot state (post-transfer), not assuming mint state."""
    slot_idx = slot_state["slot_idx"]
    owner_pk = (slot_state["owner_pk_x"], slot_state["owner_pk_y"])

    new_pt, new_pose, new_w, new_h = synthesize_new_plaintext(slot_idx, salt)
    new_r = detr_int(salt, f"new_r_{slot_idx}".encode(), GRUMPKIN_ORDER - 1) + 1
    new_c1, new_c2, new_k = ecies_encrypt_v2(new_pt, owner_pk, new_r)

    new_state_commit = sponge_39(new_pt)
    new_ct_commit = sponge_39(new_c2)

    new_count = slot_state["mutation_count"] + 1
    new_chain_tip = chain_step(
        slot_state["chain_tip"], new_state_commit, new_ct_commit,
        new_count, slot_state["origin_face_id"], slot_idx,
    )
    new_lsh = live_state_hash(
        new_state_commit, new_ct_commit, new_c1[0], new_c1[1],
        new_count, new_chain_tip,
    )

    return {
        # PI binding values (must match chain state exactly)
        "shadow_id":          slot_state["shadow_id"],
        "slot_idx":           slot_idx,
        "feature_id":         slot_state["feature_id"],
        "type_idx":           slot_state["type_idx"],
        "origin_face_id":     slot_state["origin_face_id"],
        "palette_commit":     slot_state["palette_commit"],
        "old_lsh":            slot_state["lsh"],
        "new_lsh":            new_lsh,
        "new_ct_commit":      new_ct_commit,
        "c2_field_count":     PLAINTEXT_FIELDS,
        "owner_pk_x":         slot_state["owner_pk_x"],
        "owner_pk_y":         slot_state["owner_pk_y"],
        "prev_chain_tip":     slot_state["chain_tip"],
        "new_chain_tip":      new_chain_tip,
        "prev_mutation_count": slot_state["mutation_count"],
        "new_mutation_count":  new_count,

        # witness
        "old_plaintext":      slot_state["plaintext"],
        "new_plaintext":      new_pt,
        "old_state_commit":   slot_state["state_commit"],
        "old_ct_commit":      slot_state["ct_commit"],
        "old_c1_x":           slot_state["c1_x"],
        "old_c1_y":           slot_state["c1_y"],
        "old_count":          slot_state["mutation_count"],
        "old_chain_tip":      slot_state["chain_tip"],
        "old_k":              slot_state["k"],
        "new_k":              new_k,
        "new_r":              new_r,
        "owner_sk":           slot_state["owner_sk"],
        "w_new":              new_w,
        "h_new":              new_h,

        # event/calldata
        "new_c2":             new_c2,
        "new_c1_x":           new_c1[0],
        "new_c1_y":           new_c1[1],
        "new_pose":           new_pose,
    }


def prove_mutate(label: str, target_subdir: str) -> tuple[bytes, bytes]:
    """Run nargo execute + bb prove for mutate_slot. Each call uses a
    distinct target/proof dir to avoid bb step collisions."""
    print(f"[mutate {label}] nargo execute")
    run([NARGO, "execute"], MUT_DIR, timeout=600)
    target = MUT_DIR / "target"
    if not (target / "vk").exists():
        print(f"[mutate {label}] write_vk")
        run([BB, "write_vk", "-b", str(target / "mutate_slot.json"),
             "-o", str(target),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=900)
    proof_dir = target / target_subdir
    if proof_dir.exists():
        for f in proof_dir.iterdir():
            f.unlink()
    proof_dir.mkdir(exist_ok=True)
    print(f"[mutate {label}] prove")
    run([BB, "prove", "-b", str(target / "mutate_slot.json"),
         "-w", str(target / "mutate_slot.gz"),
         "-o", str(proof_dir),
         "-k", str(target / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=1800)
    print(f"[mutate {label}] verify")
    run([BB, "verify",
         "-k", str(target / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=300)
    return (proof_dir / "proof").read_bytes(), (proof_dir / "public_inputs").read_bytes()


def prove_t10() -> tuple[bytes, bytes]:
    print("[t10] nargo execute")
    run([NARGO, "execute"], T10_DIR, timeout=300)
    target = T10_DIR / "target"
    if not (target / "vk").exists():
        run([BB, "write_vk", "-b", str(target / "shadow_t10.json"),
             "-o", str(target),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    proof_dir = target / "proof_dir"
    if proof_dir.exists():
        for f in proof_dir.iterdir():
            f.unlink()
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target / "shadow_t10.json"),
         "-w", str(target / "shadow_t10.gz"),
         "-o", str(proof_dir),
         "-k", str(target / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    run([BB, "verify",
         "-k", str(target / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=300)
    return (proof_dir / "proof").read_bytes(), (proof_dir / "public_inputs").read_bytes()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slot-a", type=int, default=0)
    ap.add_argument("--slot-b", type=int, default=1)
    ap.add_argument("--salt", default="recipient_mutate_batch_demo",
                    help="deterministic salt for synthesized new_plaintexts/r")
    ap.add_argument("--out-seed", default="onchain_mutate_batch_b")
    ap.add_argument("--transfer-fixture",
                    default="onchain_transfer/onchain_transfer_transfer_recipient_demo")
    args = ap.parse_args()

    if args.slot_a == args.slot_b:
        sys.exit("slot-a and slot-b must differ")

    print(f"[recipient mutateBatch on B] slots=[{args.slot_a}, {args.slot_b}] "
          f"salt={args.salt!r}")

    started_total = time.time()

    state = load_post_transfer_b_state(transfer_fixture=args.transfer_fixture)
    slot_state_a = state["slot_state"][args.slot_a]
    slot_state_b = state["slot_state"][args.slot_b]
    if slot_state_a is None or slot_state_b is None:
        sys.exit(f"slot-a={args.slot_a} or slot-b={args.slot_b} not occupied "
                 f"(occupied={state['occupied_idxs']})")

    salt_bytes = args.salt.encode()

    # ---- 1. mutate proof for slot A ----
    w_a = build_mutate_witness_for_recipient(slot_state_a, salt_bytes)
    write_mutate_prover_toml(w_a)
    proof_a, pi_a = prove_mutate(f"slot{args.slot_a}", f"proof_dir_a_{args.slot_a}")

    # ---- 2. mutate proof for slot B ----
    w_b = build_mutate_witness_for_recipient(slot_state_b, salt_bytes)
    write_mutate_prover_toml(w_b)
    proof_b, pi_b = prove_mutate(f"slot{args.slot_b}", f"proof_dir_b_{args.slot_b}")

    # ---- 3. T10 against post-batch manifest ----
    # Start from the post-transfer lsh_array, override slot_a + slot_b with new_lsh.
    lsh_array = list(state["lsh_array"])
    lsh_array[args.slot_a] = w_a["new_lsh"]
    lsh_array[args.slot_b] = w_b["new_lsh"]

    z_commit = state["z_index_commit"]  # 0 unless setZIndex has run
    shadow_id = state["shadow_id"]

    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[t10] post-batch hi=0x{hi:032x} lo=0x{lo:032x}")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    proof_t10, pi_t10 = prove_t10()

    # ---- 4. write fixture ----
    fix_dir = FIXTURE_ROOT / args.out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_mut_a.bin").write_bytes(proof_a)
    (fix_dir / "public_inputs_mut_a.bin").write_bytes(pi_a)
    (fix_dir / "proof_mut_b.bin").write_bytes(proof_b)
    (fix_dir / "public_inputs_mut_b.bin").write_bytes(pi_b)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)

    c2_a_bytes = b"".join(c.to_bytes(32, "big") for c in w_a["new_c2"])
    c2_b_bytes = b"".join(c.to_bytes(32, "big") for c in w_b["new_c2"])
    (fix_dir / "c2_a.bin").write_bytes(c2_a_bytes)
    (fix_dir / "c2_b.bin").write_bytes(c2_b_bytes)

    def witness_summary(w: dict) -> dict:
        return {
            "slot_idx":            w["slot_idx"],
            "feature_id":          bx32(w["feature_id"]),
            "type_idx":            w["type_idx"],
            "old_lsh":             bx32(w["old_lsh"]),
            "new_lsh":             bx32(w["new_lsh"]),
            "new_ct_commit":       bx32(w["new_ct_commit"]),
            "new_c1_x":            bx32(w["new_c1_x"]),
            "new_c1_y":            bx32(w["new_c1_y"]),
            "prev_chain_tip":      bx32(w["prev_chain_tip"]),
            "new_chain_tip":       bx32(w["new_chain_tip"]),
            "prev_mutation_count": w["prev_mutation_count"],
            "new_mutation_count":  w["new_mutation_count"],
            "c2_field_count":      w["c2_field_count"],
        }

    meta = {
        "kind":                 "onchain_mutate_batch_b",
        "salt":                 args.salt,
        "transfer_fixture":     args.transfer_fixture,
        "shadow_id":            bx32(shadow_id),
        "owner_pk_x":           bx32(state["recipient_pk_x"]),
        "owner_pk_y":           bx32(state["recipient_pk_y"]),
        "z_index_commit":       bx32(z_commit),
        "t10_hi":               bx32(hi),
        "t10_lo":               bx32(lo),
        "post_batch_lsh_array": [bx32(v) for v in lsh_array],
        "slot_a":               witness_summary(w_a),
        "slot_b":               witness_summary(w_b),
        "build_seconds":        round(time.time() - started_total, 1),
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    print(f"[wrote] {fix_dir}/")
    print(f"        proof_mut_a.bin   ({len(proof_a)} B)")
    print(f"        proof_mut_b.bin   ({len(proof_b)} B)")
    print(f"        proof_t10.bin     ({len(proof_t10)} B)")
    print(f"        c2_a.bin          ({len(c2_a_bytes)} B)")
    print(f"        c2_b.bin          ({len(c2_b_bytes)} B)")
    print(f"        wall-clock total  {meta['build_seconds']}s")


if __name__ == "__main__":
    main()
