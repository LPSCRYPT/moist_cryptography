#!/usr/bin/env python3
"""Per-slot state rebuilders for chained on-chain fixture builders.

Each function returns a slot-state dict with the keys the transfer +
solve + bridge builders consume: plaintext, c1_x, c1_y, c2, k,
state_commit, ct_commit, chain_tip, lsh, mutation_count, origin_face_id,
palette_commit, feature_id, type_idx, owner_pk_x, owner_pk_y, owner_sk,
shadow_id, slot_idx.

Driven by a JSON `slot-spec` of shape:

    {
      "shadow_id":         "0x..",         # the shadow under construction
      "mint_fixture":      "path/to/atomic_mint/<seed>",
      "fixture_seed":      "atomic_mint_demo_b",       # drives r_i + palette
      "owner_seed":        "atomic_mint_demo",         # drives owner_sk
      "mint_counter_base": 8,
      "chain_id":          84532,
      "slots": [                          # one entry per OCCUPIED slot
        {"slot": 0, "kind": "post-mutate-single",
                    "fixture": "path/to/onchain_mutate/<seed>"},
        {"slot": 1, "kind": "post-mutate-batch",
                    "fixture": "path/to/onchain_mutate_batch/<seed>",
                    "position": "slot_a"},
        {"slot": 4, "kind": "mint"},
        {"slot": 8, "kind": "post-insert",
                    "fixture": "path/to/onchain_insert/<seed>"}
      ]
    }

Slots not listed in `slots` are treated as EMPTY (lsh=0).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
REPO_ROOT = REPO.parent  # /tools/.. -> repo root
sys.path.insert(0, str(REPO))


def _spec_path(raw: str | Path) -> Path:
    """Resolve a spec-file-supplied path against the repo root, not cwd.

    Per audit M-10: spec JSON files store paths like
    `contracts/test/fixtures/atomic_mint/...` which are repo-relative.
    Callers that ran `cd tools && python3 test_slot_state.py` got
    FileNotFoundError because Path(raw) is cwd-relative.

    Absolute paths pass through unchanged. Relative paths anchor to
    the repo root regardless of cwd."""
    p = Path(raw)
    return p if p.is_absolute() else REPO_ROOT / p

from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # noqa: E402
from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS, sponge_39,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2, mint_chain_step, chain_step, live_state_hash,
    poseidon2_hash_2,
)
from build_mutate_slot_onchain import reconstruct_mint_slot_state  # noqa: E402


def _deterministic_int_mint(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_ATOMIC_MINT_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def _deterministic_int_mutate(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_ONCHAIN_MUTATE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def _deterministic_int_batch(salt: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_MUTATE_BATCH_v1:" + label + b":" + salt).digest()
    return int.from_bytes(h, "big") % mod


def _h(s: str) -> int:
    return int(s, 16) if s.startswith("0x") else int(s)


def _build_mint_slot(spec_root: dict, slot_idx: int) -> dict:
    """Mint state via reconstruct_mint_slot_state, plus mutation_count=0."""
    mint_fix = _spec_path(spec_root["mint_fixture"])
    mint_meta = json.loads((mint_fix / "meta.json").read_text())
    image_commit = int(mint_meta["image_commit"], 16)
    palette_commit = int(mint_meta["palette_commits"][slot_idx], 16)
    state = reconstruct_mint_slot_state(
        spec_root["fixture_seed"].encode(),
        image_commit,
        slot_idx,
        spec_root["chain_id"],
        owner_seed=spec_root.get("owner_seed", spec_root["fixture_seed"]).encode(),
        mint_counter_base=spec_root["mint_counter_base"],
        palette_commit=palette_commit,
    )
    state["mutation_count"] = 0
    return state


def _post_mutate_single(spec_root: dict, slot_idx: int, fixture: Path) -> dict:
    """Apply a single-slot mutate to mint state, byte-equivalent to
    build_mutate_slot_onchain.build_mutate_witness."""
    base = _build_mint_slot(spec_root, slot_idx)
    seed = spec_root["fixture_seed"].encode()
    owner_pk = (base["owner_pk_x"], base["owner_pk_y"])

    # Mirror build_mutate_slot_onchain.build_mutate_witness:
    new_pose = pack_pose(x=10, y=18)
    new_w, new_h = 14, 12
    new_indices = [(j * 11 + slot_idx + 5) & 0xF for j in range(new_w * new_h)]
    new_plaintext = encode_plaintext_v2(new_pose, new_w, new_h, new_indices)
    assert len(new_plaintext) == PLAINTEXT_FIELDS

    new_r = _deterministic_int_mutate(seed, f"new_r_{slot_idx}".encode(),
                                       GRUMPKIN_ORDER - 1) + 1
    new_c1, new_c2, new_k = ecies_encrypt_v2(new_plaintext, owner_pk, new_r)

    new_state_commit = sponge_39(new_plaintext)
    new_ct_commit = sponge_39(new_c2)
    new_count = 1
    new_chain_tip = chain_step(
        base["chain_tip"], new_state_commit, new_ct_commit, new_count,
        base["origin_face_id"], slot_idx,
    )
    new_lsh = live_state_hash(new_state_commit, new_ct_commit,
                              new_c1[0], new_c1[1], new_count, new_chain_tip)

    # Sanity vs fixture meta.
    fmeta = json.loads((fixture / "meta.json").read_text())
    assert _h(fmeta["new_lsh"]) == new_lsh, (
        f"slot {slot_idx} post-mutate-single new_lsh mismatch with fixture")

    return {
        **base,
        "plaintext": new_plaintext,
        "c1_x": new_c1[0], "c1_y": new_c1[1],
        "c2": new_c2,
        "k": new_k,
        "state_commit": new_state_commit,
        "ct_commit": new_ct_commit,
        "chain_tip": new_chain_tip,
        "lsh": new_lsh,
        "mutation_count": new_count,
    }


def _post_mutate_batch(spec_root: dict, slot_idx: int, fixture: Path,
                       position: str) -> dict:
    """Apply a batch-mutate to mint state, mirror build_mutate_batch_onchain.
    `position` is 'slot_a' or 'slot_b' to pick the right witness in the batch.
    """
    fmeta = json.loads((fixture / "meta.json").read_text())
    if fmeta[position]["slot_idx"] != slot_idx:
        raise ValueError(f"batch fixture {fixture} {position} has slot "
                         f"{fmeta[position]['slot_idx']}, spec says {slot_idx}")
    salt = fmeta["salt"].encode()
    base = _build_mint_slot(spec_root, slot_idx)
    owner_pk = (base["owner_pk_x"], base["owner_pk_y"])

    # Mirror build_mutate_batch_onchain.synthesize_new_plaintext + build_mutate_witness
    new_pose = pack_pose(x=8 + slot_idx * 3, y=12 + slot_idx)
    new_w = 12 + (slot_idx % 4)
    new_h = 10 + ((slot_idx + 1) % 4)
    new_indices = [(j * 13 + slot_idx * 5 + 7) & 0xF for j in range(new_w * new_h)]
    new_plaintext = encode_plaintext_v2(new_pose, new_w, new_h, new_indices)
    assert len(new_plaintext) == PLAINTEXT_FIELDS

    new_r = _deterministic_int_batch(salt, f"new_r_{slot_idx}".encode(),
                                      GRUMPKIN_ORDER - 1) + 1
    new_c1, new_c2, new_k = ecies_encrypt_v2(new_plaintext, owner_pk, new_r)

    new_state_commit = sponge_39(new_plaintext)
    new_ct_commit = sponge_39(new_c2)
    new_count = 1
    new_chain_tip = chain_step(
        base["chain_tip"], new_state_commit, new_ct_commit, new_count,
        base["origin_face_id"], slot_idx,
    )
    new_lsh = live_state_hash(new_state_commit, new_ct_commit,
                              new_c1[0], new_c1[1], new_count, new_chain_tip)

    assert _h(fmeta[position]["new_lsh"]) == new_lsh, (
        f"slot {slot_idx} post-mutate-batch new_lsh mismatch with fixture")

    return {
        **base,
        "plaintext": new_plaintext,
        "c1_x": new_c1[0], "c1_y": new_c1[1],
        "c2": new_c2,
        "k": new_k,
        "state_commit": new_state_commit,
        "ct_commit": new_ct_commit,
        "chain_tip": new_chain_tip,
        "lsh": new_lsh,
        "mutation_count": new_count,
    }


def _post_insert(spec_root: dict, slot_idx: int, fixture: Path) -> dict:
    """Reconstruct a post-insertFeature slot state for the HOST. The carrier
    travels with its src identity (origin_face_id, palette_commit, etc.)."""
    fmeta = json.loads((fixture / "meta.json").read_text())
    if fmeta["host_target_slot"] != slot_idx:
        raise ValueError(f"insert fixture's host_target_slot != {slot_idx}")

    # Carrier's source identity (mint state) under the SRC seed/owner.
    src_mint_fixture = Path(_resolve_src_mint_fixture(spec_root, fixture, fmeta))
    src_meta = json.loads((src_mint_fixture / "meta.json").read_text())
    src_image_commit = int(src_meta["image_commit"], 16)
    src_palette_commit = int(src_meta["palette_commits"][fmeta["src_slot"]], 16)
    src_seed = fmeta["src_seed"].encode()
    src_owner_seed = fmeta.get("src_owner_seed", fmeta["src_seed"]).encode()
    src_state = reconstruct_mint_slot_state(
        src_seed, src_image_commit, fmeta["src_slot"], fmeta["chain_id"],
        owner_seed=src_owner_seed,
        mint_counter_base=fmeta.get("src_mint_counter_base", 0),
        palette_commit=src_palette_commit,
    )

    # Mirror build_insert_onchain.build_insert_witness's post-insert state.
    owner_pk = (src_state["owner_pk_x"], src_state["owner_pk_y"])
    new_pose = pack_pose(x=4, y=4)
    new_w, new_h = 10, 10
    new_indices = [(j * 13 + slot_idx + 1) & 0xF for j in range(new_w * new_h)]
    new_plaintext = encode_plaintext_v2(new_pose, new_w, new_h, new_indices)

    host_shadow_id = _h(fmeta["host_shadow_id"])
    new_r = _deterministic_int_mutate(
        src_seed,
        f"insert_new_r_host{host_shadow_id}_slot{slot_idx}".encode(),
        GRUMPKIN_ORDER - 1,
    ) + 1
    new_c1, new_c2, new_k = ecies_encrypt_v2(new_plaintext, owner_pk, new_r)

    new_state_commit = sponge_39(new_plaintext)
    new_ct_commit = sponge_39(new_c2)
    new_count = 1
    new_chain_tip = chain_step(
        src_state["chain_tip"], new_state_commit, new_ct_commit, new_count,
        src_state["origin_face_id"], slot_idx,
    )
    new_lsh = live_state_hash(new_state_commit, new_ct_commit,
                              new_c1[0], new_c1[1], new_count, new_chain_tip)

    assert _h(fmeta["new_lsh"]) == new_lsh, (
        f"slot {slot_idx} post-insert new_lsh mismatch with fixture")

    return {
        # Carrier identity travels.
        "owner_sk": src_state["owner_sk"],
        "owner_pk_x": src_state["owner_pk_x"],
        "owner_pk_y": src_state["owner_pk_y"],
        "shadow_id": host_shadow_id,
        "slot_idx": slot_idx,
        "feature_id": src_state["feature_id"],
        "type_idx": src_state["type_idx"],
        "origin_face_id": src_state["origin_face_id"],
        "palette_commit": src_state["palette_commit"],
        "mint_counter": src_state["mint_counter"],
        # Post-insert state.
        "plaintext": new_plaintext,
        "c1_x": new_c1[0], "c1_y": new_c1[1],
        "c2": new_c2,
        "k": new_k,
        "state_commit": new_state_commit,
        "ct_commit": new_ct_commit,
        "chain_tip": new_chain_tip,
        "lsh": new_lsh,
        "mutation_count": new_count,
    }


def _resolve_src_mint_fixture(spec_root: dict, fixture: Path, fmeta: dict) -> Path:
    """Insert fixture meta does NOT store the src mint fixture path.
    Resolution order: (a) explicit override in slot spec; (b) same-shadow
    case (src == host) — reuse spec_root['mint_fixture']."""
    src_shadow = fmeta["src_shadow_id"]
    host_shadow = fmeta["host_shadow_id"]
    if src_shadow == host_shadow:
        return _spec_path(spec_root["mint_fixture"])
    raise SystemExit(
        f"insert fixture {fixture} has cross-shadow src ({src_shadow} -> "
        f"{host_shadow}); slot spec must include 'src_mint_fixture' override.")


def build_occupied_slots(spec_path: Path) -> tuple[dict, dict]:
    """Returns (root_spec, {slot: state_dict}) for all OCCUPIED slots."""
    spec = json.loads(spec_path.read_text())
    occupied: dict[int, dict] = {}
    for entry in spec["slots"]:
        slot = entry["slot"]
        kind = entry["kind"]
        if kind == "mint":
            occupied[slot] = _build_mint_slot(spec, slot)
        elif kind == "post-mutate-single":
            occupied[slot] = _post_mutate_single(spec, slot, _spec_path(entry["fixture"]))
        elif kind == "post-mutate-batch":
            occupied[slot] = _post_mutate_batch(spec, slot, _spec_path(entry["fixture"]),
                                                 entry["position"])
        elif kind == "post-insert":
            occupied[slot] = _post_insert(spec, slot, _spec_path(entry["fixture"]))
        else:
            raise SystemExit(f"unknown slot kind: {kind!r}")
    return spec, occupied
