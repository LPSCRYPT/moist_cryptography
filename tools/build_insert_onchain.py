#!/usr/bin/env python3
"""Generate a chained insertFeature fixture: mutate_slot proof + bundled T10
proof, witness-bound to the LIVE state of two on-chain shadows:

  * SOURCE shadow A (frozen, post-solve): provides the carrier (a now-released
    FeatureNFT whose `liveStateHashCheckpointOf` was set to its slot's LSH at
    extract time).
  * HOST shadow B (mint): provides the EMPTY target slot the carrier will be
    inserted into, plus the on-chain ECDH owner pubkey the new ECIES envelope
    encrypts to.

`insertFeature` reuses the `mutate_slot` circuit. The carrier's checkpoint
is the proof's `old_live_state_hash` (PI[6]); the contract's
`_buildSlotPI` reads `fn.liveStateHashCheckpointOf(args.featureId)` for that
slot. Everything else mirrors the mutate path: the carrier brings its
type_idx / origin_face_id / palette_commit (asserted unchanged from
FeatureNFT's view), the chain tip extends by exactly one step, count
increments by 1.

State reconstruction (no JSON-RPC):

    Source carrier (shadow A, slot src_slot, never mutated before extract):
        atomic_mint_demo seed -> reconstruct_mint_slot_state(seed_a, ic_a, src_slot)
        feature_id, origin_face_id, palette_commit, lsh, chain_tip, count=0,
        owner_pk, owner_sk all derived deterministically.
        old_lsh == liveStateHashCheckpointOf(feature_id) on chain
        (verified at builder start via `--carrier-checkpoint` arg passed in
        by the caller, which they read from chain).

    Host shadow B (just minted):
        atomic_mint_demo_b seed + bob0 face_disc -> mint state for slots 0..7
        of B. We only need B's mint lsh_inits for the T10 (slots 0..7 stay
        unchanged at their mint LSH; the target slot 8..15 gets the new
        insert LSH).

The new (post-insert) state inherits the carrier's identity (origin_face_id,
type_idx, palette_commit, feature_id) but lives in B's slot. The chain
step's slot_idx is B's target_slot (the circuit folds slot_idx into the
chain tip, line 355 of mutate_slot/main.nr), so the carrier's chain
records its journey across hosts.

Usage:
    python3 build_insert_onchain.py \
        --src-mint-fixture contracts/test/fixtures/atomic_mint/atomic_mint_demo \
        --host-mint-fixture contracts/test/fixtures/atomic_mint/atomic_mint_demo_b \
        --src-seed atomic_mint_demo \
        --src-slot 1 \
        --host-target-slot 8 \
        --carrier-checkpoint 0x...   # liveStateHashCheckpointOf(feature_id) read from chain

Wall-clock on M3: ~2 s (mutate proof + T10 proof; both small circuits).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS,
    sponge_39, sponge_6,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2,
    chain_step, live_state_hash,
    fhex, bx32,
)
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402
from build_mutate_slot_onchain import (  # noqa: E402
    reconstruct_mint_slot_state,
    deterministic_int_mutate,
    NARGO,
    BB,
    GRUMPKIN_ORDER,
    MUT_DIR,
    T10_DIR,
)

ROOT = REPO.parent
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_insert"


def render_array(name: str, vals) -> str:
    return f"{name} = [{', '.join(fhex(v) for v in vals)}]"


def write_mutate_prover_toml(w: dict) -> None:
    """Mirror build_mutate_slot_onchain.write_mutate_prover_toml field-for-field."""
    toml = MUT_DIR / "Prover.toml"
    toml.parent.mkdir(parents=True, exist_ok=True)
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


def prove(circuit_dir: Path, json_name: str) -> tuple[bytes, bytes]:
    target_dir = circuit_dir / "target"
    print(f"  nargo execute   {circuit_dir.name}")
    run([NARGO, "execute"], circuit_dir, timeout=900)
    print(f"  bb write_vk     {json_name}")
    run([BB, "write_vk", "-b", str(target_dir / json_name),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"],
        circuit_dir, timeout=900)
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    gz = json_name.replace(".json", ".gz")
    print(f"  bb prove        {gz}")
    run([BB, "prove", "-b", str(target_dir / json_name),
         "-w", str(target_dir / gz),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"],
        circuit_dir, timeout=1800)
    print(f"  bb verify (sanity)")
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"],
        circuit_dir, timeout=300)
    return ((proof_dir / "proof").read_bytes(),
            (proof_dir / "public_inputs").read_bytes())


def build_insert_witness(seed: bytes, src_state: dict, host_shadow_id: int,
                         host_target_slot: int) -> dict:
    """Build the mutate_slot witness for an insertFeature: the carrier
    (`src_state`, never mutated -- count 0) is being inserted into
    `host_shadow_id`'s `host_target_slot`. count: 0 -> 1.

    Caller-owned identity (origin_face_id, type_idx, palette_commit,
    feature_id) travels with the carrier. The chain step's slot_idx is the
    HOST target slot.
    """
    owner_pk = (src_state["owner_pk_x"], src_state["owner_pk_y"])

    # New plaintext: distinct pose/dims so the insert is observable.
    # Use a different deterministic label so the new c2 differs from any
    # mutation builder's c2 even at slot 0.
    new_pose = pack_pose(x=4, y=4)
    new_w, new_h = 10, 10  # under 48x48 canvas
    new_indices = [(j * 13 + host_target_slot + 1) & 0xF for j in range(new_w * new_h)]
    new_plaintext = encode_plaintext_v2(new_pose, new_w, new_h, new_indices)
    assert len(new_plaintext) == PLAINTEXT_FIELDS

    new_r = deterministic_int_mutate(
        seed,
        f"insert_new_r_host{host_shadow_id}_slot{host_target_slot}".encode(),
        GRUMPKIN_ORDER - 1,
    ) + 1
    new_c1, new_c2, new_k = ecies_encrypt_v2(new_plaintext, owner_pk, new_r)

    new_state_commit = sponge_39(new_plaintext)
    new_ct_commit = sponge_39(new_c2)

    new_count = 1  # carrier was at count 0 (slots 1-7 of A, never mutated)
    new_chain_tip = chain_step(
        src_state["chain_tip"],
        new_state_commit,
        new_ct_commit,
        new_count,
        src_state["origin_face_id"],
        host_target_slot,  # circuit folds slot_idx into the chain step
    )
    new_lsh = live_state_hash(
        new_state_commit, new_ct_commit,
        new_c1[0], new_c1[1],
        new_count, new_chain_tip,
    )

    return {
        # PI binding values (16 PIs, mutate_slot circuit)
        "shadow_id":           host_shadow_id,         # PI[0] HOST shadow
        "slot_idx":            host_target_slot,        # PI[1] HOST slot
        "feature_id":          src_state["feature_id"], # PI[2] carrier-bound
        "type_idx":            src_state["type_idx"],   # PI[3]
        "origin_face_id":      src_state["origin_face_id"],  # PI[4]
        "palette_commit":      src_state["palette_commit"],  # PI[5]
        "old_lsh":             src_state["lsh"],        # PI[6] == checkpoint
        "new_lsh":             new_lsh,                 # PI[7]
        "new_ct_commit":       new_ct_commit,           # PI[8]
        "c2_field_count":      PLAINTEXT_FIELDS,        # PI[9]
        "owner_pk_x":          src_state["owner_pk_x"], # PI[10] HOST ecdhPub
        "owner_pk_y":          src_state["owner_pk_y"], # PI[11]
        "prev_chain_tip":      src_state["chain_tip"],  # PI[12]
        "new_chain_tip":       new_chain_tip,           # PI[13]
        "prev_mutation_count": 0,                       # PI[14]
        "new_mutation_count":  new_count,               # PI[15]

        # witness
        "old_plaintext":      src_state["plaintext"],
        "new_plaintext":      new_plaintext,
        "old_state_commit":   src_state["state_commit"],
        "old_ct_commit":      src_state["ct_commit"],
        "old_c1_x":           src_state["c1_x"],
        "old_c1_y":           src_state["c1_y"],
        "old_count":          0,
        "old_chain_tip":      src_state["chain_tip"],
        "old_k":              src_state["k"],
        "new_k":              new_k,
        "new_r":              new_r,
        "owner_sk":           src_state["owner_sk"],
        "w_new":              new_w,
        "h_new":              new_h,

        # event/calldata
        "old_c2":             src_state["c2"],
        "new_c2":             new_c2,
        "new_c1_x":           new_c1[0],
        "new_c1_y":           new_c1[1],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-mint-fixture", required=True,
                    help="Path to atomic_mint fixture for the carrier's source shadow A")
    ap.add_argument("--host-mint-fixture", required=True,
                    help="Path to atomic_mint fixture for the host shadow B (provides B's lsh_inits for T10)")
    ap.add_argument("--src-seed", default="atomic_mint_demo",
                    help="Seed used to build src-mint-fixture (and to derive owner_sk/c1/c2)")
    ap.add_argument("--src-slot", type=int, default=1,
                    help="Carrier source slot in A (default 1; use slot 1..7 for never-mutated carriers)")
    ap.add_argument("--host-target-slot", type=int, default=8,
                    help="Target empty slot in B (default 8; valid 8..15 since B's mint occupies 0..7)")
    ap.add_argument("--chain-id", type=int, default=84532)
    ap.add_argument("--carrier-checkpoint", default=None,
                    help="Optional 0x-hex of liveStateHashCheckpointOf(feature_id) read from chain. "
                         "If supplied, asserted equal to the seed-reconstructed lsh at startup.")
    ap.add_argument("--out-seed", default=None)
    args = ap.parse_args()

    if args.src_slot == 0:
        sys.exit("--src-slot 0 unsupported: shadow A's slot 0 was mutated before extract; "
                 "reconstruction logic here only handles never-mutated carriers (slots 1..7)")
    if args.src_slot < 1 or args.src_slot > 7:
        sys.exit(f"--src-slot must be in 1..7, got {args.src_slot}")
    if args.host_target_slot < 8 or args.host_target_slot > 15:
        sys.exit(f"--host-target-slot must be in 8..15 (B's slots 0..7 are minted occupied), "
                 f"got {args.host_target_slot}")

    src_fix = Path(args.src_mint_fixture)
    host_fix = Path(args.host_mint_fixture)
    if not (src_fix / "meta.json").exists():
        sys.exit(f"src mint fixture not found: {src_fix}")
    if not (host_fix / "meta.json").exists():
        sys.exit(f"host mint fixture not found: {host_fix}")

    src_meta = json.loads((src_fix / "meta.json").read_text())
    host_meta = json.loads((host_fix / "meta.json").read_text())
    src_image_commit = int(src_meta["image_commit"], 16)
    host_image_commit = int(host_meta["image_commit"], 16)
    src_lsh_inits = [int(x, 16) for x in src_meta["lsh_inits"]]
    host_lsh_inits = [int(x, 16) for x in host_meta["lsh_inits"]]
    src_shadow_id = int(src_meta["shadow_id"], 16)
    host_shadow_id = int(host_meta["shadow_id"], 16)
    assert len(src_lsh_inits) == len(host_lsh_inits) == 8

    src_seed = args.src_seed.encode()
    print(f"[onchain_insert fixture] src_slot={args.src_slot} host_slot={args.host_target_slot}")
    print(f"  src shadow_id  = {hex(src_shadow_id)[:18]}...")
    print(f"  host shadow_id = {hex(host_shadow_id)[:18]}...")

    # ---- 1. Reconstruct carrier state from src seed ----
    print(f"[1/4] reconstruct carrier state from src slot {args.src_slot}")
    src_state = reconstruct_mint_slot_state(
        src_seed, src_image_commit, args.src_slot, args.chain_id
    )
    assert src_state["lsh"] == src_lsh_inits[args.src_slot], \
        f"reconstructed src lsh != src_meta.lsh_inits[{args.src_slot}]"
    print(f"  reconstructed lsh matches src_meta")
    print(f"  feature_id      = {hex(src_state['feature_id'])[:18]}...")
    print(f"  type_idx        = {src_state['type_idx']}")
    print(f"  origin_face_id  = {hex(src_state['origin_face_id'])[:18]}...")

    # Optional chain-state cross-check.
    if args.carrier_checkpoint is not None:
        cp = int(args.carrier_checkpoint, 16)
        if cp != src_state["lsh"]:
            sys.exit(
                f"carrier_checkpoint mismatch: chain={hex(cp)} "
                f"reconstructed={hex(src_state['lsh'])} -- "
                "the carrier was mutated or extracted with a different state "
                "than this builder assumes"
            )
        print(f"  on-chain checkpoint matches reconstructed lsh")

    # ---- 2. Build insert witness + proof ----
    print(f"[2/4] insert witness (host shadow {hex(host_shadow_id)[:18]}.., slot {args.host_target_slot})")
    w = build_insert_witness(src_seed, src_state, host_shadow_id, args.host_target_slot)
    write_mutate_prover_toml(w)
    print(f"  new_lsh         = {hex(w['new_lsh'])[:18]}...")
    print(f"  new_chain_tip   = {hex(w['new_chain_tip'])[:18]}...")
    print(f"  new_count       = {w['new_mutation_count']}")
    print(f"[3/4] mutate_slot proof (insert path)")
    proof_ins, pi_ins = prove(MUT_DIR, "mutate_slot.json")

    # ---- 3. T10 against POST-INSERT manifest of HOST shadow B ----
    # Manifest layout:
    #   slots 0..7 of B: B's mint lsh_inits (unchanged)
    #   slot host_target_slot: new_lsh (post-insert)
    #   other slots in 8..15: 0 (still EMPTY)
    post_lsh = list(host_lsh_inits) + [0] * 8
    assert post_lsh[args.host_target_slot] == 0, "target slot expected EMPTY pre-insert"
    post_lsh[args.host_target_slot] = w["new_lsh"]

    # B's z_index_commit is 0 (host has not done setZIndexCommit yet).
    z_commit = 0
    buf = [host_shadow_id, z_commit] + post_lsh
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[4/4] T10: post-insert  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(host_shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in post_lsh)}]\n"
    )
    proof_t10, pi_t10 = prove(T10_DIR, "shadow_t10.json")

    # ---- 4. Write fixture ----
    out_seed = args.out_seed or (
        f"onchain_insert_src{args.src_slot}_host{args.host_target_slot}"
    )
    fix_dir = FIXTURE_ROOT / out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_ins.bin").write_bytes(proof_ins)
    (fix_dir / "public_inputs_ins.bin").write_bytes(pi_ins)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)
    new_c2_bytes = b"".join(c.to_bytes(32, "big") for c in w["new_c2"])
    (fix_dir / "c2.bin").write_bytes(new_c2_bytes)

    meta = {
        "kind": "onchain_insert",
        "src_seed": args.src_seed,
        "src_slot": args.src_slot,
        "host_target_slot": args.host_target_slot,
        "chain_id": args.chain_id,
        "src_shadow_id": bx32(src_shadow_id),
        "host_shadow_id": bx32(host_shadow_id),
        "feature_id": bx32(w["feature_id"]),
        "type_idx": w["type_idx"],
        "origin_face_id": bx32(w["origin_face_id"]),
        "palette_commit": bx32(w["palette_commit"]),
        "owner_pk_x": bx32(w["owner_pk_x"]),
        "owner_pk_y": bx32(w["owner_pk_y"]),
        "old_lsh": bx32(w["old_lsh"]),
        "new_lsh": bx32(w["new_lsh"]),
        "new_ct_commit": bx32(w["new_ct_commit"]),
        "new_c1_x": bx32(w["new_c1_x"]),
        "new_c1_y": bx32(w["new_c1_y"]),
        "prev_chain_tip": bx32(w["prev_chain_tip"]),
        "new_chain_tip": bx32(w["new_chain_tip"]),
        "prev_mutation_count": w["prev_mutation_count"],
        "new_mutation_count": w["new_mutation_count"],
        "c2_field_count": w["c2_field_count"],
        "z_index_commit": bx32(z_commit),
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "post_insert_lsh_array": [bx32(v) for v in post_lsh],
        "new_plaintext_pose": w["new_plaintext"][0],
        "new_plaintext_w": w["w_new"],
        "new_plaintext_h": w["h_new"],
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof_ins.bin  ({len(proof_ins)} B)")
    print(f"        proof_t10.bin  ({len(proof_t10)} B)")


if __name__ == "__main__":
    main()
