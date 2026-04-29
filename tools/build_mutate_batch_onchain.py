#!/usr/bin/env python3
"""Build a chained mutateBatch fixture (two `mutate_slot` proofs + one
`shadow_t10` proof) bound to a real on-chain manifest.

Generic: works for any shadow on any pipeline. The witness's per-slot
state is reconstructed from the original mint fixture (deterministic from
seed + image + mint_counter_base), so the builder does NOT need RPC.

Optional `--pre-mutated-fixture` lets you stamp single-slot post-mutate
overrides into the T10's lsh_array, for chained demos where some slots
were mutated in earlier transactions before this batch.

Replaces the old post-transfer-only mode (pipeline-#3 lifecycle artifact);
that flow is preserved in git history at commits before 2026-04-28.

Wall-clock on M3: ~3 min (60s mutate-a + 60s mutate-b + 30s T10).

Usage:
    python3 tools/build_mutate_batch_onchain.py \\
        --mint-fixture contracts/test/fixtures/atomic_mint/atomic_mint_demo_b \\
        --seed atomic_mint_demo_b \\
        --owner-seed atomic_mint_demo \\
        --mint-counter-base 8 \\
        --slot-a 1 --slot-b 2 \\
        --pre-mutated-fixture \\
            contracts/test/fixtures/onchain_mutate/onchain_mutate_b_slot0_p5 \\
        --salt batch_b_p5_demo \\
        --out-seed onchain_mutate_batch_b_p5
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
from build_mutate_slot_onchain import reconstruct_mint_slot_state  # noqa: E402

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
    h = hashlib.sha256(b"OMP_MUTATE_BATCH_v1:" + label + b":" + salt).digest()
    return int.from_bytes(h, "big") % mod


def synthesize_new_plaintext(slot_idx: int, salt: bytes) -> tuple[list[int], int, int, int]:
    """Pick a NEW pose/dims/indices distinct from prior fixtures."""
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


def build_mutate_witness(slot_state: dict, salt: bytes) -> dict:
    """Build mutate_slot witness from a generic slot_state dict."""
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
        # PI
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


def prove_mutate(label: str, target_subdir: str) -> tuple[bytes, bytes]:
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


def load_mint_slot_state(mint_fixture: Path, seed: bytes, owner_seed: bytes,
                        mint_counter_base: int, chain_id: int, slot_idx: int) -> dict:
    """Reconstruct mint-state for `slot_idx` and shape it for build_mutate_witness."""
    meta = json.loads((mint_fixture / "meta.json").read_text())
    image_commit = int(meta["image_commit"], 16)
    palette_commit = int(meta["palette_commits"][slot_idx], 16)
    state = reconstruct_mint_slot_state(seed, image_commit, slot_idx, chain_id,
                                        owner_seed=owner_seed,
                                        mint_counter_base=mint_counter_base,
                                        palette_commit=palette_commit)
    state["mutation_count"] = 0
    return state


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mint-fixture", required=True,
                    help="Path to atomic_mint fixture dir (provides image_commit + lsh_inits)")
    ap.add_argument("--seed", required=True,
                    help="Fixture seed (drives r_i + palette_commit)")
    ap.add_argument("--owner-seed", default=None,
                    help="Owner-key seed (drives owner_sk). Defaults to --seed.")
    ap.add_argument("--mint-counter-base", type=int, default=0,
                    help="Global FeatureNFT.mintCounter at the moment THIS shadow's mint started.")
    ap.add_argument("--chain-id", type=int, default=84532)
    ap.add_argument("--slot-a", type=int, required=True)
    ap.add_argument("--slot-b", type=int, required=True)
    ap.add_argument("--salt", required=True,
                    help="Deterministic salt for synthesized new_plaintexts/r")
    ap.add_argument("--out-seed", required=True)
    ap.add_argument("--pre-mutated-fixture", action="append", default=[],
                    help="Path to a single-slot post-mutate fixture whose new_lsh "
                         "should override the corresponding slot in the T10 "
                         "starting state. Pass multiple times for multiple slots.")
    args = ap.parse_args()

    if args.slot_a == args.slot_b:
        sys.exit("slot-a and slot-b must differ")

    seed = args.seed.encode()
    owner_seed = args.owner_seed.encode() if args.owner_seed else seed
    chain_id = args.chain_id
    salt = args.salt.encode()

    # 1. Reconstruct mint state for both slots.
    print(f"[mutateBatch] mint-state reconstruct slots {args.slot_a}, {args.slot_b}")
    mint_fixture = Path(args.mint_fixture)
    state_a = load_mint_slot_state(mint_fixture, seed, owner_seed,
                                   args.mint_counter_base, chain_id, args.slot_a)
    state_b = load_mint_slot_state(mint_fixture, seed, owner_seed,
                                   args.mint_counter_base, chain_id, args.slot_b)

    started = time.time()

    # 2. Mutate witness + proof for slot A.
    w_a = build_mutate_witness(state_a, salt)
    write_mutate_prover_toml(w_a)
    proof_a, pi_a = prove_mutate(f"slot{args.slot_a}", f"proof_dir_a_{args.slot_a}")

    # 3. Mutate witness + proof for slot B.
    w_b = build_mutate_witness(state_b, salt)
    write_mutate_prover_toml(w_b)
    proof_b, pi_b = prove_mutate(f"slot{args.slot_b}", f"proof_dir_b_{args.slot_b}")

    # 4. T10 against post-batch manifest.
    # Start from full mint lsh_array; override per pre-mutated fixtures + this batch.
    meta = json.loads((mint_fixture / "meta.json").read_text())
    lsh_array = [int(v, 16) for v in meta["lsh_inits"]] + [0] * 8  # slots 0..7 mint, 8..15 empty

    for fix_path in args.pre_mutated_fixture:
        fix = Path(fix_path)
        fmeta = json.loads((fix / "meta.json").read_text())
        # This builder writes the new_lsh to meta.json. Slot index from same.
        slot = fmeta["slot_idx"] if "slot_idx" in fmeta else fmeta.get("slot")
        if slot is None:
            sys.exit(f"pre-mutated fixture {fix} lacks slot_idx in meta.json")
        new_lsh = int(fmeta["new_lsh"], 16)
        lsh_array[slot] = new_lsh
        print(f"  pre-mutated override: slot {slot} lsh = {hex(new_lsh)[:18]}...")

    lsh_array[args.slot_a] = w_a["new_lsh"]
    lsh_array[args.slot_b] = w_b["new_lsh"]

    z_commit = 0  # caller hasn't run setZIndex yet (or it's still 0)
    shadow_id = state_a["shadow_id"]

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

    # 5. Write fixture.
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

    fixture_meta = {
        "kind":                 "onchain_mutate_batch",
        "salt":                 args.salt,
        "seed":                 args.seed,
        "owner_seed":           args.owner_seed or args.seed,
        "mint_counter_base":    args.mint_counter_base,
        "shadow_id":            bx32(shadow_id),
        "owner_pk_x":           bx32(state_a["owner_pk_x"]),
        "owner_pk_y":           bx32(state_a["owner_pk_y"]),
        "z_index_commit":       bx32(z_commit),
        "t10_hi":               bx32(hi),
        "t10_lo":               bx32(lo),
        "post_batch_lsh_array": [bx32(v) for v in lsh_array],
        "slot_a":               witness_summary(w_a),
        "slot_b":               witness_summary(w_b),
        "pre_mutated_fixtures": args.pre_mutated_fixture,
        "build_seconds":        round(time.time() - started, 1),
    }
    (fix_dir / "meta.json").write_text(json.dumps(fixture_meta, indent=2))

    print(f"[wrote] {fix_dir}/")
    print(f"        proof_mut_a.bin   ({len(proof_a)} B)")
    print(f"        proof_mut_b.bin   ({len(proof_b)} B)")
    print(f"        proof_t10.bin     ({len(proof_t10)} B)")
    print(f"        c2_a.bin          ({len(c2_a_bytes)} B)")
    print(f"        c2_b.bin          ({len(c2_b_bytes)} B)")
    print(f"        wall-clock total  {fixture_meta['build_seconds']}s")


if __name__ == "__main__":
    main()
