#!/usr/bin/env python3
"""Generate a chained transfer_shadow_v2 fixture: one proof rotating all
16 slots' encryption to a fresh recipient, plus a bundled T10 against the
post-rotation manifest.

State reconstruction (no JSON-RPC):

  Host shadow B (just minted + one insert into slot 8):
    - Slots 0..7 of B are mint state: derived from --host-mint-seed +
      bob0 face_disc fixture (image_commit) using the same
      `reconstruct_mint_slot_state` helper as the mutate/insert builders.
      prev_count = 0, prev_chain_tip = mint chain step, prev_lsh = lsh_init.
    - Slot 8 of B is post-insert state: feature_id is from shadow A's
      slot --insert-src-slot; the insert's new_* values are deterministic
      under the insert builder's witness-derivation (see
      `build_insert_witness` for slot host_target_slot=8 with carrier
      from A slot --insert-src-slot). prev_count = 1, prev_chain_tip =
      insert.new_chain_tip, prev_lsh = insert.new_lsh.
    - Slots 9..15 are EMPTY (zeros).

  Recipient: deterministic Grumpkin sk from --recipient-seed; pk derived
  via ec_mul. The recipient's ETH address (--recipient-addr) drives the
  ERC-721 ownership rotation but is not part of the proof.

  Owner (current, prev_owner): same Grumpkin key as shadow A's mint
  (atomic_mint_demo seed) since shadow B was minted under
  --owner-seed atomic_mint_demo.

Per-slot rotation:
  For each OCCUPIED slot i:
    new_r_i      = deterministic_int(seed, "transfer_new_r_{i}", ...)
    (new_c1, new_c2, new_k) = ecies_encrypt_v2(plaintext_i, recipient_pk, new_r_i)
    new_count    = prev_count + 1
    new_chain_tip= sponge_6(prev_chain_tip, TRANSFER_TAG,
                            recipient_pk_x, recipient_pk_y, new_count, i)
    new_lsh      = live_state_hash(prev_state_commit, sponge_39(new_c2),
                                   new_c1.x, new_c1.y,
                                   new_count, new_chain_tip)

Sanity: each new_c2 is decryptable under recipient_sk to the original
plaintext (round-trip checked at builder time).

Usage:
    python3 build_transfer_onchain.py \
        --host-mint-fixture contracts/test/fixtures/atomic_mint/atomic_mint_demo_b \
        --host-mint-seed atomic_mint_demo_b \
        --owner-seed atomic_mint_demo \
        --insert-fixture contracts/test/fixtures/onchain_insert/onchain_insert_src1_host8 \
        --insert-src-mint-fixture contracts/test/fixtures/atomic_mint/atomic_mint_demo \
        --insert-src-seed atomic_mint_demo \
        --insert-src-slot 1 \
        --insert-host-slot 8 \
        --recipient-seed transfer_recipient_demo \
        --recipient-addr 0xFD90Bd22EDA6f54EBA3587E6a3642AB3B5236Ca2

Wall-clock on M3: ~2-5 min (transfer circuit is the heaviest in v2).
"""
from __future__ import annotations

import atexit
import argparse
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
    sponge_39, sponge_16,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2, ecies_decrypt_v2,
    live_state_hash, transfer_chain_step,
    fhex, bx32,
)
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402
from build_mutate_slot_onchain import (  # noqa: E402
    deterministic_int_mint,
    deterministic_int_mutate,
    reconstruct_mint_slot_state,
    NARGO,
    BB,
    T10_DIR,
)
from build_insert_onchain import build_insert_witness  # noqa: E402

ROOT = REPO.parent
TRANSFER_DIR = ROOT / "circuits" / "transfer_shadow_v2"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_transfer"


def _delete_if_exists(path: Path) -> None:
    try:
        path.unlink()
        print(f"[deleted transient] {path}")
    except FileNotFoundError:
        pass


def deterministic_int_transfer(seed: bytes, label: bytes, mod: int) -> int:
    """Distinct prefix so transfer's new_r values are independent from any
    seed-derived value used at mint/mutate/insert time."""
    import hashlib
    h = hashlib.sha256(b"OMP_ONCHAIN_TRANSFER_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def render_array(name: str, vals) -> str:
    return f"{name} = [{', '.join(fhex(v) for v in vals)}]"


def render_2d(name: str, rows) -> str:
    inner = []
    for r in rows:
        inner.append(f"  [{', '.join(fhex(v) for v in r)}]")
    return f"{name} = [\n" + ",\n".join(inner) + "\n]"


def run(cmd, cwd: Path, timeout: int = 1800) -> str:
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


def reconstruct_post_insert_slot_state(
    src_seed: bytes, src_image_commit: int, src_slot: int,
    host_shadow_id: int, host_target_slot: int, chain_id: int,
    src_palette_commit: int | None = None,
) -> dict:
    """Reconstruct the post-insert state of a HOST shadow's slot,
    byte-equivalent to what `build_insert_onchain.py` produced. Returns
    a dict shaped like `reconstruct_mint_slot_state`'s output (so the
    transfer builder can treat slot 8 the same way as slots 0..7)."""
    src_state = reconstruct_mint_slot_state(
        src_seed, src_image_commit, src_slot, chain_id,
        palette_commit=src_palette_commit,
    )
    insert_w = build_insert_witness(
        src_seed, src_state, host_shadow_id, host_target_slot
    )
    # Map insert witness fields to the dict shape transfer expects.
    # state_commit unchanged across re-encryption; ct_commit/c1/k/lsh/chain_tip
    # are post-insert values.
    return {
        "owner_sk": src_state["owner_sk"],
        "owner_pk_x": src_state["owner_pk_x"],
        "owner_pk_y": src_state["owner_pk_y"],
        "shadow_id": host_shadow_id,
        "slot_idx": host_target_slot,
        "plaintext": insert_w["new_plaintext"],
        "c1_x": insert_w["new_c1_x"],
        "c1_y": insert_w["new_c1_y"],
        "c2": insert_w["new_c2"],
        "k": insert_w["new_k"],
        "state_commit": sponge_39(insert_w["new_plaintext"]),
        "ct_commit": insert_w["new_ct_commit"],
        "origin_face_id": src_state["origin_face_id"],
        "palette_commit": src_state["palette_commit"],
        "chain_tip": insert_w["new_chain_tip"],
        "lsh": insert_w["new_lsh"],
        "feature_id": src_state["feature_id"],
        "type_idx": src_state["type_idx"],
        "mint_counter": src_state["mint_counter"],
        "prev_count_for_transfer": insert_w["new_mutation_count"],  # 1 post-insert
    }


def build_transfer_witness(
    seed: bytes,
    host_shadow_id: int,
    occupied_slots: dict,         # {slot_idx: per-slot dict}
    prev_owner_sk: int,
    prev_owner_pk: tuple[int, int],
    recipient_sk: int,
    recipient_pk: tuple[int, int],
) -> dict:
    """Per-slot transfer witness for shadow_id with occupied slots already
    reconstructed (each entry must contain plaintext, state_commit, ct_commit,
    c1_x, c1_y, k, chain_tip, lsh, prev_count_for_transfer (default 0)).
    Slots not in `occupied_slots` are EMPTY. Empty slots keep zero public
    outputs, but their private curve inputs must still be well-formed because
    the Noir circuit unconditionally performs MSM before masking constraints.
    We seed empty prev_c1 with the Grumpkin generator and empty new_r with a
    deterministic nonzero scalar.
    """
    is_occupied = [0] * 16
    plaintexts = [[0] * PLAINTEXT_FIELDS for _ in range(16)]
    prev_state_commit = [0] * 16
    prev_ct_commit = [0] * 16
    prev_c1_x = [G[0]] * 16
    prev_c1_y = [G[1]] * 16
    prev_mutation_count = [0] * 16
    prev_chain_tip = [0] * 16
    prev_k_arr = [0] * 16
    prev_lsh_arr = [0] * 16

    new_k_arr = [0] * 16
    new_r_arr = [deterministic_int_transfer(seed, f"empty_new_r_slot{i}".encode(), GRUMPKIN_ORDER - 1) + 1 for i in range(16)]
    new_lsh_arr = [0] * 16
    new_c1_x_arr = [0] * 16
    new_c1_y_arr = [0] * 16
    new_ct_commit_arr = [0] * 16
    new_chain_tip_arr = [0] * 16
    new_mutation_count_arr = [0] * 16
    new_c2_arr = [[0] * PLAINTEXT_FIELDS for _ in range(16)]

    for i, st in occupied_slots.items():
        is_occupied[i] = 1
        plaintexts[i] = list(st["plaintext"])
        prev_state_commit[i] = st["state_commit"]
        prev_ct_commit[i] = st["ct_commit"]
        prev_c1_x[i] = st["c1_x"]
        prev_c1_y[i] = st["c1_y"]
        prev_chain_tip[i] = st["chain_tip"]
        prev_k_arr[i] = st["k"]
        prev_lsh_arr[i] = st["lsh"]
        prev_mutation_count[i] = st.get("prev_count_for_transfer", 0)

        # Rotate ECIES to recipient.
        new_r = deterministic_int_transfer(
            seed, f"new_r_slot{i}".encode(), GRUMPKIN_ORDER - 1
        ) + 1
        new_c1, new_c2, new_k = ecies_encrypt_v2(plaintexts[i], recipient_pk, new_r)
        new_k_arr[i] = new_k
        new_r_arr[i] = new_r
        new_c1_x_arr[i] = new_c1[0]
        new_c1_y_arr[i] = new_c1[1]
        new_ct_commit_arr[i] = sponge_39(new_c2)
        new_c2_arr[i] = new_c2

        new_count = prev_mutation_count[i] + 1
        new_mutation_count_arr[i] = new_count
        new_chain_tip_arr[i] = transfer_chain_step(
            prev_chain_tip[i], recipient_pk[0], recipient_pk[1], new_count, i,
        )
        new_lsh_arr[i] = live_state_hash(
            prev_state_commit[i],
            new_ct_commit_arr[i],
            new_c1_x_arr[i],
            new_c1_y_arr[i],
            new_count,
            new_chain_tip_arr[i],
        )

        # Sanity: recipient can decrypt the rotated envelope.
        decoded, dk = ecies_decrypt_v2(
            (new_c1_x_arr[i], new_c1_y_arr[i]), new_c2_arr[i], recipient_sk,
        )
        assert decoded == plaintexts[i], f"recipient decrypt mismatch slot {i}"
        assert dk == new_k_arr[i], f"recipient k mismatch slot {i}"

    prev_lsh_root = sponge_16(prev_lsh_arr)
    assert all(prev_c1_x[i] != 0 or prev_c1_y[i] != 0 for i in range(16)), "prev_c1 placeholders must be on-curve"
    assert all(r != 0 for r in new_r_arr), "new_r placeholders must be nonzero"
    new_lsh_root = sponge_16(new_lsh_arr)
    new_chain_tips_root = sponge_16(new_chain_tip_arr)
    new_ct_commits_root = sponge_16(new_ct_commit_arr)
    new_c1_x_root = sponge_16(new_c1_x_arr)
    new_c1_y_root = sponge_16(new_c1_y_arr)

    return {
        # PI (11)
        "shadow_id":            host_shadow_id,
        "recipient_pk_x":       recipient_pk[0],
        "recipient_pk_y":       recipient_pk[1],
        "prev_lsh_root":        prev_lsh_root,
        "new_lsh_root":         new_lsh_root,
        "prev_owner_pk_x":      prev_owner_pk[0],
        "prev_owner_pk_y":      prev_owner_pk[1],
        "new_chain_tips_root":  new_chain_tips_root,
        "new_ct_commits_root":  new_ct_commits_root,
        "new_c1_x_root":       new_c1_x_root,
        "new_c1_y_root":       new_c1_y_root,
        # witness arrays
        "prev_lsh":             prev_lsh_arr,
        "is_occupied":          is_occupied,
        "plaintexts":           plaintexts,
        "prev_state_commit":    prev_state_commit,
        "prev_ct_commit":       prev_ct_commit,
        "prev_c1_x":            prev_c1_x,
        "prev_c1_y":            prev_c1_y,
        "prev_mutation_count":  prev_mutation_count,
        "prev_chain_tip":       prev_chain_tip,
        "prev_k":               prev_k_arr,
        "new_k":                new_k_arr,
        "new_r":                new_r_arr,
        "prev_owner_sk":        prev_owner_sk,
        # post-rotation chain state
        "new_lsh":              new_lsh_arr,
        "new_c1_x":             new_c1_x_arr,
        "new_c1_y":             new_c1_y_arr,
        "new_ct_commit":        new_ct_commit_arr,
        "new_chain_tip":        new_chain_tip_arr,
        "new_mutation_count":   new_mutation_count_arr,
        "new_c2":               new_c2_arr,
        "occupied_idxs":        sorted(occupied_slots.keys()),
    }


def write_transfer_prover_toml(w: dict) -> None:
    """Mirror build_transfer_shadow_v2_fixture.write_prover_toml field order."""
    toml = TRANSFER_DIR / "Prover.toml"
    toml.parent.mkdir(parents=True, exist_ok=True)
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
        f"new_c1_x_root = {fhex(w['new_c1_x_root'])}",
        f"new_c1_y_root = {fhex(w['new_c1_y_root'])}",
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
    toml.write_text("\n".join(lines) + "\n")
    os.chmod(toml, 0o600)

    atexit.register(_delete_if_exists, toml)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slot-spec", required=True,
                    help="Path to JSON describing each occupied slot's state "
                         "source. See tools/slot_state.py module docstring.")
    ap.add_argument("--recipient-seed", required=True,
                    help="Seed deriving recipient's Grumpkin sk")
    ap.add_argument("--recipient-addr", required=True,
                    help="Recipient's ETH address (0x... hex)")
    ap.add_argument("--out-seed", default=None)
    args = ap.parse_args()

    from slot_state import build_occupied_slots  # noqa: E402
    spec, occupied = build_occupied_slots(Path(args.slot_spec))
    host_shadow_id = int(spec["shadow_id"], 16)
    print(f"[onchain_transfer] host_shadow_id = {hex(host_shadow_id)[:18]}...")
    print(f"[onchain_transfer] occupied slots: {sorted(occupied.keys())}")

    # Prev-owner key from spec.owner_seed (matches mint).
    owner_sk = deterministic_int_mint(spec["owner_seed"].encode(),
                                       b"owner_sk", GRUMPKIN_ORDER - 1) + 1
    owner_pk = ec_mul(G, owner_sk)
    assert owner_pk is not None
    # Sanity: every occupied slot's owner_pk must agree with this.
    for i, st in occupied.items():
        assert (st["owner_pk_x"], st["owner_pk_y"]) == owner_pk, \
            f"slot {i} owner_pk mismatch with spec owner_seed"
    print(f"  prev_owner_pk_x = {hex(owner_pk[0])[:18]}...")

    # Each occupied slot must declare its prev_count_for_transfer.
    for i, st in occupied.items():
        st["prev_count_for_transfer"] = st["mutation_count"]

    # Recipient key.
    recipient_sk = deterministic_int_mint(
        args.recipient_seed.encode(), b"owner_sk", GRUMPKIN_ORDER - 1
    ) + 1
    recipient_pk = ec_mul(G, recipient_sk)
    assert recipient_pk is not None
    print(f"  recipient_pk_x  = {hex(recipient_pk[0])[:18]}...")

    # Build transfer witness + prove.
    print(f"[transfer witness] {len(occupied)} occupied slots")
    seed = args.recipient_seed.encode()
    w = build_transfer_witness(
        seed, host_shadow_id, occupied,
        owner_sk, owner_pk, recipient_sk, recipient_pk,
    )
    write_transfer_prover_toml(w)
    print(f"[transfer_shadow_v2 proof]")
    proof, pi = prove(TRANSFER_DIR, "transfer_shadow_v2.json")

    # T10 against POST-TRANSFER manifest (occupied slots = new_lsh, empty = 0).
    post_lsh = list(w["new_lsh"])
    z_commit = int(spec.get("z_index_commit", "0x0"), 16) if isinstance(spec.get("z_index_commit"), str) else 0
    buf = [host_shadow_id, z_commit] + post_lsh
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[T10] post-transfer  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(host_shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in post_lsh)}]\n"
    )
    os.chmod(T10_DIR / "Prover.toml", 0o600)
    atexit.register(_delete_if_exists, T10_DIR / "Prover.toml")
    proof_t10, pi_t10 = prove(T10_DIR, "shadow_t10.json")

    # Write fixture.
    out_seed = args.out_seed or f"onchain_transfer_{args.recipient_seed}"
    fix_dir = FIXTURE_ROOT / out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    if len(pi) != 11 * 32:
        sys.exit(f"unexpected transfer public input length {len(pi)}; want {11 * 32}")
    (fix_dir / "proof.bin").write_bytes(proof)
    (fix_dir / "public_inputs.bin").write_bytes(pi)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)

    c2_per_slot: list[list[str]] = []
    for i in range(16):
        if i in occupied:
            c2_per_slot.append([bx32(v) for v in w["new_c2"][i]])
        else:
            c2_per_slot.append([])

    meta = {
        "kind": "onchain_transfer",
        "slot_spec":      args.slot_spec,
        "recipient_seed": args.recipient_seed,
        "recipient_addr": args.recipient_addr,
        "host_shadow_id": bx32(host_shadow_id),
        "occupied_idxs":  w["occupied_idxs"],
        "recipient_pk_x": bx32(recipient_pk[0]),
        "recipient_pk_y": bx32(recipient_pk[1]),
        "prev_owner_pk_x": bx32(owner_pk[0]),
        "prev_owner_pk_y": bx32(owner_pk[1]),
        "prev_lsh_root":  bx32(w["prev_lsh_root"]),
        "new_lsh_root":   bx32(w["new_lsh_root"]),
        "new_chain_tips_root": bx32(w["new_chain_tips_root"]),
        "new_ct_commits_root": bx32(w["new_ct_commits_root"]),
        "new_c1_x_root": bx32(w["new_c1_x_root"]),
        "new_c1_y_root": bx32(w["new_c1_y_root"]),
        "new_lsh":        [bx32(v) for v in w["new_lsh"]],
        "new_c1_x":       [bx32(v) for v in w["new_c1_x"]],
        "new_c1_y":       [bx32(v) for v in w["new_c1_y"]],
        "new_ct_commit":  [bx32(v) for v in w["new_ct_commit"]],
        "new_chain_tip":  [bx32(v) for v in w["new_chain_tip"]],
        "new_mutation_count": w["new_mutation_count"],
        "c2_per_slot":    c2_per_slot,
        "z_index_commit": bx32(z_commit),
        "t10_hi":         bx32(hi),
        "t10_lo":         bx32(lo),
        "post_transfer_lsh_array": [bx32(v) for v in post_lsh],
        "recipient_sk":   hex(recipient_sk),
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    plaintexts_per_slot: list[list[str]] = []
    for i in range(16):
        if i in occupied:
            plaintexts_per_slot.append([bx32(v) for v in occupied[i]["plaintext"]])
        else:
            plaintexts_per_slot.append([bx32(0)] * PLAINTEXT_FIELDS)
    (fix_dir / "plaintexts.json").write_text(
        json.dumps({"plaintexts": plaintexts_per_slot}, indent=2)
    )

    print(f"[wrote] {fix_dir}/")
    print(f"        proof.bin     ({len(proof)} B)")
    print(f"        proof_t10.bin ({len(proof_t10)} B)")


if __name__ == "__main__":
    main()