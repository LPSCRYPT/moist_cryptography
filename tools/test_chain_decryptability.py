#!/usr/bin/env python3
"""Regression tests for chain-only ciphertext decryptability.

Each case uses the same public surface an indexer/dashboard receives:

  * c2 ciphertext bytes/fields from the event payload fixture,
  * proof-bound c1 from the emitted event/public-input fixture,
  * the recipient/owner private key from deterministic fixture metadata.

The test then ECIES-decrypts and checks the recovered plaintext against either
an explicit fixture plaintext or the proof-bound liveStateHash components. This
catches regressions where a path emits c2 but omits or misbinds c1.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from v2_circuit_helpers import (  # noqa: E402
    G,
    GRUMPKIN_ORDER,
    PLAINTEXT_FIELDS,
    ec_mul,
    ecies_decrypt_v2,
    live_state_hash,
    mint_chain_step,
    sponge_39,
)

ROOT = REPO / "contracts" / "test" / "fixtures"


def hx(v: str | int) -> int:
    if isinstance(v, int):
        return v
    return int(v, 16)


def load_json(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def load_fields_bin(path: Path) -> list[int]:
    raw = path.read_bytes()
    if len(raw) % 32 != 0:
        raise AssertionError(f"{path}: byte length {len(raw)} is not field-aligned")
    return [int.from_bytes(raw[i:i + 32], "big") for i in range(0, len(raw), 32)]


def fields(values: list[str | int]) -> list[int]:
    return [hx(v) for v in values]


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_ATOMIC_MINT_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def transfer_fixture_int(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_TRANSFER_SHADOW_V2_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod

def owner_sk_from_seed(seed: str) -> int:
    return deterministic_int(seed.encode(), b"owner_sk", GRUMPKIN_ORDER - 1) + 1


def assert_decrypts_to_plaintext(label: str, c1: tuple[int, int], c2: list[int], sk: int, expected: list[int]) -> None:
    if len(c2) != PLAINTEXT_FIELDS:
        raise AssertionError(f"{label}: c2 has {len(c2)} fields, expected {PLAINTEXT_FIELDS}")
    decoded, _ = ecies_decrypt_v2(c1, c2, sk)
    if decoded != expected:
        raise AssertionError(f"{label}: decrypted plaintext mismatch")


def assert_decrypts_to_lsh(
    label: str,
    c1: tuple[int, int],
    c2: list[int],
    sk: int,
    expected_lsh: int,
    mutation_count: int,
    chain_tip: int,
) -> list[int]:
    if len(c2) != PLAINTEXT_FIELDS:
        raise AssertionError(f"{label}: c2 has {len(c2)} fields, expected {PLAINTEXT_FIELDS}")
    decoded, _ = ecies_decrypt_v2(c1, c2, sk)
    state_commit = sponge_39(decoded)
    ct_commit = sponge_39(c2)
    got_lsh = live_state_hash(state_commit, ct_commit, c1[0], c1[1], mutation_count, chain_tip)
    if got_lsh != expected_lsh:
        raise AssertionError(
            f"{label}: decrypted plaintext does not reconstruct liveStateHash; "
            f"got={got_lsh:#x} expected={expected_lsh:#x}"
        )
    return decoded


def test_mint() -> None:
    base = ROOT / "atomic_mint" / "atomic_mint_demo"
    meta = load_json(base / "meta.json")
    plaintexts = load_json(base / "plaintexts.json")["plaintexts"]
    sk = owner_sk_from_seed(meta["seed"])
    pk = ec_mul(G, sk)
    if pk != (hx(meta["owner_pk_x"]), hx(meta["owner_pk_y"])):
        raise AssertionError("mint: reconstructed owner key does not match fixture")

    for i in range(8):
        c1 = (hx(meta["c1_xs"][i]), hx(meta["c1_ys"][i]))
        c2 = fields(meta["c2_per_slot"][i])
        expected = fields(plaintexts[i])
        assert_decrypts_to_plaintext(f"mint slot {i}", c1, c2, sk, expected)
        # Also verify the decrypted event surface reconstructs the mint LSH.
        state_commit = sponge_39(expected)
        ct_commit = sponge_39(c2)
        chain_tip = mint_chain_step(hx(meta["origin_face_ids"][i]), hx(meta["owner_pk_x"]), hx(meta["owner_pk_y"]))
        got_lsh = live_state_hash(state_commit, ct_commit, c1[0], c1[1], 0, chain_tip)
        if got_lsh != hx(meta["lsh_inits"][i]):
            raise AssertionError(f"mint slot {i}: reconstructed LSH mismatch")


def test_mutate_slot_and_insert_surface() -> None:
    # mutateSlot and insertFeature both emit the mutate_slot ciphertext surface:
    # ShadowSlotMutated(c2) + ShadowSlotEnvelope(c1X,c1Y). InsertFeature's
    # persistent Forge test uses this same atomic fixture as its insert proof.
    base = ROOT / "atomic_mutate" / "atomic_demo"
    meta = load_json(base / "meta.json")
    sk = hx(meta["owner_sk"])
    c1 = (hx(meta["new_c1_x"]), hx(meta["new_c1_y"]))
    c2 = load_fields_bin(base / "c2.bin")
    assert_decrypts_to_lsh(
        "mutateSlot event surface",
        c1,
        c2,
        sk,
        hx(meta["new_lsh"]),
        int(meta["new_mutation_count"]),
        hx(meta["new_chain_tip"]),
    )

    # The same public c1+c2 pair is what insertFeature exposes for a newly
    # inserted carrier; verify it is independently sufficient there too.
    assert_decrypts_to_lsh(
        "insertFeature event surface",
        c1,
        c2,
        sk,
        hx(meta["new_lsh"]),
        int(meta["new_mutation_count"]),
        hx(meta["new_chain_tip"]),
    )


def test_mutate_batch() -> None:
    base = ROOT / "atomic_mutate_batch" / "atomic_mutate_batch_demo"
    meta = load_json(base / "meta.json")
    sk = hx(meta["owner_sk"])
    for label, suffix in (("slot_a", "a"), ("slot_b", "b")):
        slot = meta[label]
        c1 = (hx(slot["new_c1_x"]), hx(slot["new_c1_y"]))
        c2 = load_fields_bin(base / f"c2_{suffix}.bin")
        assert_decrypts_to_lsh(
            f"mutateBatch {label}",
            c1,
            c2,
            sk,
            hx(slot["new_lsh"]),
            int(slot["new_mutation_count"]),
            hx(slot["new_chain_tip"]),
        )


def test_transfer_shadow() -> None:
    base = ROOT / "atomic_transfer" / "atomic_transfer_demo"
    meta = load_json(base / "meta.json")
    plaintexts = load_json(base / "plaintexts.json")["plaintexts"]
    sk = transfer_fixture_int(meta["seed"].encode(), b"recipient_sk", GRUMPKIN_ORDER - 1) + 1
    for i in meta["occupied_idxs"]:
        c1 = (hx(meta["new_c1_x"][i]), hx(meta["new_c1_y"][i]))
        c2 = fields(meta["c2_per_slot"][str(i)])
        expected = fields(plaintexts[i])
        assert_decrypts_to_plaintext(f"transferShadow slot {i}", c1, c2, sk, expected)
        assert_decrypts_to_lsh(
            f"transferShadow slot {i} LSH",
            c1,
            c2,
            sk,
            hx(meta["new_lsh"][i]),
            int(meta["new_mutation_count"][i]),
            hx(meta["new_chain_tip"][i]),
        )


def test_transfer_feature_v2() -> None:
    base = ROOT / "onchain_transfer_feature_v2" / "transfer_feature_v2_atomic_mint_demo_slot0"
    meta = load_json(base / "meta.json")
    # This fixture transfers to the same deterministic Grumpkin key as the mint
    # owner; reconstruct from the referenced mint seed and verify the public key.
    sk = owner_sk_from_seed(meta["mint_seed"])
    pk = ec_mul(G, sk)
    if pk != (hx(meta["to_pk_x"]), hx(meta["to_pk_y"])):
        raise AssertionError("transferFeatureV2: reconstructed recipient key does not match fixture")
    c1 = (hx(meta["new_c1_x"]), hx(meta["new_c1_y"]))
    c2 = load_fields_bin(base / "c2.bin")
    assert_decrypts_to_lsh(
        "transferFeatureV2 event surface",
        c1,
        c2,
        sk,
        hx(meta["new_lsh"]),
        int(meta["new_count"]),
        hx(meta["new_chain_tip"]),
    )


def main() -> None:
    tests = [
        test_mint,
        test_mutate_slot_and_insert_surface,
        test_mutate_batch,
        test_transfer_shadow,
        test_transfer_feature_v2,
    ]
    for test in tests:
        test()
        print(f"[ok] {test.__name__}")
    print("ALL CHAIN DECRYPTABILITY TESTS PASSED")


if __name__ == "__main__":
    main()
