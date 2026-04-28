#!/usr/bin/env python3
"""Round-trip tests for tools/slot_state.py + the per-slot state
reconstruction path.

These tests guard against the class of bug that has bitten this repo
twice already (and stranded shadow B' on pipeline #5 unsolvable):

  - `reconstruct_mint_slot_state` must byte-equivalently rebuild what
    `build_atomic_mint_fixture.py` wrote at mint time.
  - `slot_state.build_occupied_slots` must return per-slot lsh values
    that match the SOURCE FIXTURES' `new_lsh` for every kind
    (mint, post-mutate-single, post-mutate-batch, post-insert).
  - When --owner-seed differs from --seed, the reconstruct's owner_pk
    must match the mint fixture's owner_pk_x/y.

Run with: `python3 tools/test_slot_state.py` (no pytest dependency).
Exit 0 = all pass; exit 1 = first failure printed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
ROOT = REPO.parent
sys.path.insert(0, str(REPO))

from build_mutate_slot_onchain import reconstruct_mint_slot_state  # noqa: E402
from slot_state import build_occupied_slots  # noqa: E402


# ---- tiny test framework ----------------------------------------------

_failures: list[str] = []
_passed = 0


def _h(s) -> int:
    if isinstance(s, int):
        return s
    s = s.lower()
    return int(s[2:] if s.startswith("0x") else s, 16)


def expect_eq(label: str, got, want):
    global _passed
    g = _h(got) if isinstance(got, (str, int)) else got
    w = _h(want) if isinstance(want, (str, int)) else want
    if g == w:
        _passed += 1
        return
    msg = (
        f"FAIL [{label}]\n"
        f"  got:  {hex(g) if isinstance(g, int) else g}\n"
        f"  want: {hex(w) if isinstance(w, int) else w}"
    )
    _failures.append(msg)
    print(msg)


def section(name: str):
    print(f"\n=== {name} ===")


# ---- fixtures used by the tests ---------------------------------------

ATOMIC_A = ROOT / "contracts/test/fixtures/atomic_mint/atomic_mint_demo"
ATOMIC_B = ROOT / "contracts/test/fixtures/atomic_mint/atomic_mint_demo_b"
ATOMIC_C = ROOT / "contracts/test/fixtures/atomic_mint/solve_demo_c"
SPEC_B_P5 = ROOT / "contracts/test/fixtures/slot_specs/b_p5_post_insert.json"


# ---- t1: mint reconstruction byte-equivalence -------------------------

def test_reconstruct_mint_a_matches_fixture():
    section("reconstruct_mint_slot_state byte-equivalence: shadow A")
    meta = json.loads((ATOMIC_A / "meta.json").read_text())
    image_commit = _h(meta["image_commit"])
    chain_id = 84532  # Base Sepolia
    for slot_idx in (0, 3, 7):  # sample 3 of 8 -- each EC mul is ~4s
        st = reconstruct_mint_slot_state(
            seed=b"atomic_mint_demo",
            image_commit=image_commit,
            slot_idx=slot_idx,
            chain_id=chain_id,
        )
        expect_eq(
            f"A slot {slot_idx} lsh", st["lsh"], meta["lsh_inits"][slot_idx]
        )
        expect_eq(
            f"A slot {slot_idx} ct_commit", st["ct_commit"],
            meta["ct_commits"][slot_idx],
        )
        expect_eq(
            f"A slot {slot_idx} chain_tip", st["chain_tip"],
            meta["chain_tips"][slot_idx],
        )
    expect_eq("A owner_pk_x", st["owner_pk_x"], meta["owner_pk_x"])
    expect_eq("A owner_pk_y", st["owner_pk_y"], meta["owner_pk_y"])


# ---- t2: split owner-seed must produce correct owner_pk --------------

def test_reconstruct_with_split_owner_seed():
    section("reconstruct_mint_slot_state owner_seed split: shadow C")
    if not ATOMIC_C.exists():
        print("  skip (atomic_mint/solve_demo_c not present)")
        return
    meta = json.loads((ATOMIC_C / "meta.json").read_text())
    image_commit = _h(meta["image_commit"])
    # C was minted with seed=solve_demo_c, owner_seed=palette_reveal_live.
    st_split = reconstruct_mint_slot_state(
        seed=b"solve_demo_c",
        image_commit=image_commit,
        slot_idx=0,
        chain_id=84532,
        owner_seed=b"palette_reveal_live",
    )
    expect_eq("C split-seed owner_pk_x", st_split["owner_pk_x"],
              meta["owner_pk_x"])
    expect_eq("C split-seed owner_pk_y", st_split["owner_pk_y"],
              meta["owner_pk_y"])
    expect_eq("C split-seed lsh[0]", st_split["lsh"], meta["lsh_inits"][0])

    # Negative: WITHOUT the split, owner_pk must NOT match (so we know
    # the bug-detection actually depends on the flag).
    st_collapsed = reconstruct_mint_slot_state(
        seed=b"solve_demo_c",
        image_commit=image_commit,
        slot_idx=0,
        chain_id=84532,
        # owner_seed defaults to seed -> collapsed
    )
    if st_collapsed["owner_pk_x"] == _h(meta["owner_pk_x"]):
        _failures.append(
            "FAIL [C collapsed-seed should NOT match fixture owner_pk_x] -- "
            "but it did. The owner_seed flag is not actually controlling "
            "owner_sk derivation."
        )
        print(_failures[-1])
    else:
        global _passed
        _passed += 1


# ---- t3: mint_counter_base offset for second-shadow case --------------

def test_reconstruct_mint_counter_base():
    section("reconstruct_mint_slot_state mint_counter_base: shadow B")
    meta = json.loads((ATOMIC_B / "meta.json").read_text())
    image_commit = _h(meta["image_commit"])
    # B was minted on pipeline #5 after A had already minted 8 carriers,
    # so B's mint_counter_base = 8.
    for slot_idx in (0, 7):
        st = reconstruct_mint_slot_state(
            seed=b"atomic_mint_demo_b",
            image_commit=image_commit,
            slot_idx=slot_idx,
            chain_id=84532,
            owner_seed=b"atomic_mint_demo",
            mint_counter_base=8,
        )
        expect_eq(
            f"B slot {slot_idx} lsh (counter_base=8)",
            st["lsh"], meta["lsh_inits"][slot_idx],
        )


# ---- t4: build_occupied_slots end-to-end (B' post-insert spec) -------

def test_build_occupied_slots_b_p5_post_insert():
    section("slot_state.build_occupied_slots: B' post-insert spec")
    if not SPEC_B_P5.exists():
        print("  skip (slot spec not present)")
        return
    spec, occupied = build_occupied_slots(SPEC_B_P5)

    # Verify the kinds we expect are populated (and EMPTY slots aren't).
    expect_eq("occupied slot count", len(occupied), 8)
    for s in (0, 1, 2, 4, 5, 6, 7, 8):
        if s not in occupied:
            _failures.append(f"FAIL [slot {s} should be occupied]")
            print(_failures[-1])
    for s in (3, 9, 10, 11, 12, 13, 14, 15):
        if s in occupied:
            _failures.append(f"FAIL [slot {s} should NOT be occupied]")
            print(_failures[-1])

    # The reconstructed lsh values must match what the on-chain manifest
    # has (recorded in the post-transfer fixture's `prev_lsh_root` was
    # built from these). We cross-check against the per-slot transfer
    # fixture's prev_lsh array (= what the transfer builder loaded from
    # build_occupied_slots itself, so this is a within-tool consistency
    # check).
    transfer_meta = json.loads((ROOT / "contracts/test/fixtures"
        / "onchain_transfer/onchain_transfer_b_to_deployer_p5/meta.json"
    ).read_text())
    # The transfer fixture's pre-state per-slot LSH is reconstructed by
    # the transfer builder identically; just sanity-check that the
    # reconstructed `lsh` for slot 0 matches the pre-mutate-single
    # fixture's `new_lsh`.
    pre_mutate_single = json.loads((ROOT / "contracts/test/fixtures"
        / "onchain_mutate/onchain_mutate_b_slot0_p5/meta.json"
    ).read_text())
    expect_eq(
        "B p5 slot 0 (post-mutate-single) lsh",
        occupied[0]["lsh"], pre_mutate_single["new_lsh"],
    )
    pre_mutate_batch = json.loads((ROOT / "contracts/test/fixtures"
        / "onchain_mutate_batch/onchain_mutate_batch_b_p5/meta.json"
    ).read_text())
    expect_eq(
        "B p5 slot 1 (post-mutate-batch slot_a) lsh",
        occupied[1]["lsh"], pre_mutate_batch["slot_a"]["new_lsh"],
    )
    expect_eq(
        "B p5 slot 2 (post-mutate-batch slot_b) lsh",
        occupied[2]["lsh"], pre_mutate_batch["slot_b"]["new_lsh"],
    )
    pre_insert = json.loads((ROOT / "contracts/test/fixtures"
        / "onchain_insert/onchain_insert_b_host8_p5/meta.json"
    ).read_text())
    expect_eq(
        "B p5 slot 8 (post-insert) lsh",
        occupied[8]["lsh"], pre_insert["new_lsh"],
    )


# ---- t5: palette_commit consistency in the atomic_mint builder -------

def test_atomic_mint_palette_commit_consistency():
    section("atomic_mint palette_commit MUST open via sponge_palette_salt")
    from v2_circuit_helpers import sponge_palette_salt  # noqa: E402

    # Shadow C is the only fixture in this repo currently consistent with
    # the new sponge formula; A and B were minted before the redesign.
    if not ATOMIC_C.exists():
        print("  skip (solve_demo_c not present)")
        return
    meta = json.loads((ATOMIC_C / "meta.json").read_text())
    for i in range(8):
        palette = [_h(x) for x in meta["palettes"][i]]
        salt = _h(meta["palette_salts"][i])
        commit = _h(meta["palette_commits"][i])
        expect_eq(
            f"C slot {i} palette_commit opens via sponge",
            sponge_palette_salt(palette, salt), commit,
        )


# ---- run --------------------------------------------------------------

if __name__ == "__main__":
    test_reconstruct_mint_a_matches_fixture()
    test_reconstruct_with_split_owner_seed()
    test_reconstruct_mint_counter_base()
    test_build_occupied_slots_b_p5_post_insert()
    test_atomic_mint_palette_commit_consistency()

    print(f"\n{'='*60}")
    print(f"passed: {_passed}")
    print(f"failed: {len(_failures)}")
    if _failures:
        sys.exit(1)
    sys.exit(0)
