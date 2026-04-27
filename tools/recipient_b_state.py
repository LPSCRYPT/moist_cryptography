"""Reconstruct shadow B's full per-slot state AS THE RECIPIENT sees it
post-transfer.

Used by the four recipient-side on-chain builders:
  - build_mutate_batch_onchain_b.py
  - build_extract_onchain_b.py
  - build_zindex_onchain_b.py
  - build_solve_onchain_b.py

Inputs (all already on disk, all deterministic from seeds):
  * atomic_mint_demo_b/{meta.json, plaintexts.json}  -- B's mint state per
                                                         slot (0..7), under
                                                         deployer's pk
  * onchain_insert/onchain_insert_src1_host8/meta.json -- B slot 8's
                                                         post-insert immutables
                                                         (paletteCommit etc.)
  * onchain_transfer/onchain_transfer_transfer_recipient_demo/{meta,plaintexts}.json
                                                       -- post-transfer per-
                                                          slot state under
                                                          recipient_pk

For each slot we return the full bundle a chained-fixture builder needs:
  plaintext, c1_x, c1_y, c2[39], k,
  state_commit, ct_commit, chain_tip, lsh, mutation_count,
  origin_face_id, palette_commit, feature_id, type_idx.

Plus shadow-level: shadow_id, owner_sk (= recipient_sk), owner_pk_x/y.

Design choice: the helper does NOT do JSON-RPC. Everything is loaded from
on-disk fixtures that are themselves the canonical record of what was
broadcast. Anyone re-running the recipient lifecycle on a fresh B can
swap the three input fixture paths and the helper's contract is
unchanged.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from eth_utils import keccak  # type: ignore  # noqa: E402
from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # noqa: E402
from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS, sponge_39, sponge_6,
    poseidon2_hash_2, ecies_decrypt_v2,
)

ROOT = REPO.parent
FIXROOT = ROOT / "contracts" / "test" / "fixtures"

DOMAIN_FEATURE = keccak(text="OMP_FEATURE_NFT_v2")
FR_MOD = P  # Field modulus (Bn254 base field)


def _h(s: str) -> int:
    s = s.lower()
    return int(s[2:] if s.startswith("0x") else s, 16)


def derive_feature_id(chain_id: int, shadow_id: int, slot_idx: int,
                      mint_counter: int) -> int:
    """Mirror FeatureNFT.mintAtShadowMint:
       featureId = keccak256(DOMAIN, chainId, hostShadow, slot, mintCounter) % FR_MOD."""
    enc = (DOMAIN_FEATURE
           + chain_id.to_bytes(32, "big")
           + shadow_id.to_bytes(32, "big")
           + slot_idx.to_bytes(32, "big")
           + mint_counter.to_bytes(32, "big"))
    return int.from_bytes(keccak(enc), "big") % FR_MOD


def derive_recipient_keys(recipient_seed: str) -> tuple[int, int, int]:
    """Mirror tools/build_transfer_onchain.py's recipient sk/pk derivation:
    sk = deterministic_int_mint(recipient_seed, b"owner_sk", GRUMPKIN_ORDER-1) + 1
    where deterministic_int_mint hashes 'OMP_ATOMIC_MINT_FIXTURE_v1:' || label || ':' || seed."""
    import hashlib
    h = hashlib.sha256(b"OMP_ATOMIC_MINT_FIXTURE_v1:owner_sk:" + recipient_seed.encode()).digest()
    sk = (int.from_bytes(h, "big") % (GRUMPKIN_ORDER - 1)) + 1
    pk = ec_mul(G, sk)
    assert pk is not None
    return sk, pk[0], pk[1]


def load_post_transfer_b_state(
    transfer_fixture: str = "onchain_transfer/onchain_transfer_transfer_recipient_demo",
    mint_b_fixture: str = "atomic_mint/atomic_mint_demo_b",
    insert_fixture: str = "onchain_insert/onchain_insert_src1_host8",
    mint_counter_offset: int = 9,
) -> dict:
    """Return the full post-transfer recipient-side state of shadow B.

    Returns dict:
      shadow_id, chain_id, occupied_idxs, recipient_sk, recipient_pk_x/y,
      slot_state[16]  -- each entry None if EMPTY, else the per-slot dict
                          described in the module docstring.
      lsh_array[16]   -- post-transfer lsh values (zero for EMPTY)
      z_index_commit  -- current chain-stored zIndexCommit (0 unless setZIndex
                          has been broadcast post-transfer).
    """
    tf_dir = FIXROOT / transfer_fixture
    mb_dir = FIXROOT / mint_b_fixture
    ins_dir = FIXROOT / insert_fixture

    tf_meta = json.loads((tf_dir / "meta.json").read_text())
    tf_pts = json.loads((tf_dir / "plaintexts.json").read_text())["plaintexts"]
    mb_meta = json.loads((mb_dir / "meta.json").read_text())
    ins_meta = json.loads((ins_dir / "meta.json").read_text())

    shadow_id = _h(tf_meta["host_shadow_id"])
    chain_id = int(tf_meta["chain_id"])
    occupied_idxs = list(tf_meta["occupied_idxs"])
    recipient_sk = _h(tf_meta["recipient_sk"])
    recipient_pk_x = _h(tf_meta["recipient_pk_x"])
    recipient_pk_y = _h(tf_meta["recipient_pk_y"])

    # Verify our recipient-key derivation matches the transfer fixture.
    derived_sk, derived_pk_x, derived_pk_y = derive_recipient_keys(
        tf_meta["recipient_seed"]
    )
    assert derived_sk == recipient_sk, \
        f"recipient_sk mismatch: derived={hex(derived_sk)} vs transfer_meta={hex(recipient_sk)}"
    assert derived_pk_x == recipient_pk_x, "recipient_pk_x mismatch"
    assert derived_pk_y == recipient_pk_y, "recipient_pk_y mismatch"

    # Per-slot post-transfer payload.
    new_lsh = [_h(v) for v in tf_meta["new_lsh"]]
    new_c1_x = [_h(v) for v in tf_meta["new_c1_x"]]
    new_c1_y = [_h(v) for v in tf_meta["new_c1_y"]]
    new_ct_commit = [_h(v) for v in tf_meta["new_ct_commit"]]
    new_chain_tip = [_h(v) for v in tf_meta["new_chain_tip"]]
    new_mutation_count = list(tf_meta["new_mutation_count"])
    c2_per_slot = [[_h(v) for v in s] for s in tf_meta["c2_per_slot"]]
    plaintexts = [[_h(v) for v in s] for s in tf_pts]

    # Per-slot immutables (origin_face_id, palette_commit) per slot 0..7
    # come from B's mint; slot 8 comes from the insert (which carries A
    # slot 1's immutables forward, since insert is custody-only and the
    # carrier's paletteCommit/typeIdx/originFaceId never change).
    origin_face_ids = [_h(v) for v in mb_meta["origin_face_ids"]]
    palette_commits = [_h(v) for v in mb_meta["palette_commits"]]

    # Slot 8 inherits its immutables from the inserted carrier.
    if 8 in occupied_idxs:
        # Sanity: insert meta's host slot must be 8.
        assert int(ins_meta["host_target_slot"]) == 8, "expected insert target slot 8"
        origin_face_ids = list(origin_face_ids) + [_h(ins_meta["origin_face_id"])] + [0] * 7
        palette_commits = list(palette_commits) + [_h(ins_meta["palette_commit"])] + [0] * 7
        ins_feature_id = _h(ins_meta["feature_id"])
        ins_type_idx = int(ins_meta["type_idx"])
    else:
        origin_face_ids = list(origin_face_ids) + [0] * 8
        palette_commits = list(palette_commits) + [0] * 8
        ins_feature_id = 0
        ins_type_idx = 0

    # Build per-slot state.
    slot_state: list[dict | None] = [None] * 16
    for i in range(16):
        if i not in occupied_idxs:
            assert new_lsh[i] == 0, f"empty slot {i} should have lsh=0"
            continue

        # Recompute k = poseidon2(shared.x, shared.y) for sanity.
        c1 = (new_c1_x[i], new_c1_y[i])
        shared = ec_mul(c1, recipient_sk)
        assert shared is not None, f"slot {i} c1*sk yields identity"
        k = poseidon2_hash_2(shared[0], shared[1])

        # Sanity: decrypt c2 under sk and compare to plaintexts[i].
        decoded, dk = ecies_decrypt_v2(c1, c2_per_slot[i], recipient_sk)
        assert dk == k
        assert decoded == plaintexts[i], (
            f"slot {i}: decrypt mismatch — "
            f"plaintext[0]={hex(plaintexts[i][0])[:10]} vs decoded[0]={hex(decoded[0])[:10]}"
        )

        # Sponge sanity: sponge_39(plaintext) == prev_state_commit; sponge_39(c2) == new_ct_commit.
        sc = sponge_39(plaintexts[i])
        cc = sponge_39(c2_per_slot[i])
        assert cc == new_ct_commit[i], f"slot {i}: ct_commit mismatch"

        # Lsh sanity: sponge_6(state, ct, c1.x, c1.y, count, chain_tip) == new_lsh[i].
        lsh_check = sponge_6(sc, cc, c1[0], c1[1], new_mutation_count[i],
                             new_chain_tip[i])
        assert lsh_check == new_lsh[i], f"slot {i}: lsh mismatch"

        # Per-slot immutables.
        if i == 8:
            fid = ins_feature_id
            ti = ins_type_idx
        else:
            # FeatureNFT.mintCounter is GLOBAL across all shadows. A's
            # 8 mints used counters 1..8; B's slots 0..7 used 9..16. The
            # caller provides mint_counter_offset to anchor B's first slot.
            fid = derive_feature_id(chain_id, shadow_id, i,
                                    mint_counter_offset + i)
            ti = i

        slot_state[i] = {
            "slot_idx": i,
            "shadow_id": shadow_id,
            "plaintext": plaintexts[i],
            "c1_x": c1[0],
            "c1_y": c1[1],
            "c2": c2_per_slot[i],
            "k": k,
            "state_commit": sc,
            "ct_commit": cc,
            "chain_tip": new_chain_tip[i],
            "lsh": new_lsh[i],
            "mutation_count": new_mutation_count[i],
            "origin_face_id": origin_face_ids[i],
            "palette_commit": palette_commits[i],
            "feature_id": fid,
            "type_idx": ti,
            "owner_sk": recipient_sk,
            "owner_pk_x": recipient_pk_x,
            "owner_pk_y": recipient_pk_y,
        }

    return {
        "shadow_id": shadow_id,
        "chain_id": chain_id,
        "occupied_idxs": occupied_idxs,
        "recipient_sk": recipient_sk,
        "recipient_pk_x": recipient_pk_x,
        "recipient_pk_y": recipient_pk_y,
        "slot_state": slot_state,
        "lsh_array": new_lsh,
        "z_index_commit": _h(tf_meta["z_index_commit"]),
    }


if __name__ == "__main__":
    # Smoke test: load and print summary.
    s = load_post_transfer_b_state()
    print(f"shadow_id   = {hex(s['shadow_id'])[:18]}...")
    print(f"chain_id    = {s['chain_id']}")
    print(f"occupied    = {s['occupied_idxs']}")
    print(f"recipient_sk= {hex(s['recipient_sk'])[:18]}...")
    print(f"z_commit    = {hex(s['z_index_commit'])[:18]}...")
    for i, ss in enumerate(s["slot_state"]):
        if ss is None:
            print(f"  slot {i:2d}: EMPTY")
        else:
            print(f"  slot {i:2d}: count={ss['mutation_count']} "
                  f"lsh={hex(ss['lsh'])[:18]}... fid={hex(ss['feature_id'])[:18]}...")
    print("OK")
