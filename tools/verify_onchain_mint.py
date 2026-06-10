#!/usr/bin/env python3
"""End-to-end on-chain mint integrity verification.

Verifies every layer of the on-chain mint of the `atomic_mint_demo`
fixture against the live Base Sepolia ShadowToken contract. Designed
as the canonical "did the chain do what we asked?" check after every
deploy + mint cycle.

What this checks (each is a hard byte-equality assertion, not a
heuristic):

    1.  Contract wiring on chain using public authoritative getters.
    2.  Mint tx receipt: status, gasUsed, expected event count.
    3.  ImageRegistered event emitted with the right imageCommit.
    4.  ShadowMinted event emitted with the right (shadowId, minter,
        mintIdx, imageCommit).
    5.  ShadowT10Updated event emitted with (hi, lo) matching the
        fixture's bundled T10 PI.
    6.  All 8 ShadowSlotMutated finalization events emitted in slot order,
        with empty c2 payloads by design.
    7.  All 8 ShadowMintController.MintCiphertextSubmitted events emitted,
        with c2 payloads byte-equal to the fixture ciphertexts.
    8.  For each slot:
              owner_sk; recovered plaintext field-equals an
              independently-computed expected plaintext (from the
              deterministic seed-derived pose/w/h/indices).
          c.  decoded plaintext (pose, w, h, palette indices) matches
              the fixture's encoded pose / w / h / indices.
          d.  on-chain ManifestEntry.liveStateHash equals the
              fixture's lsh_inits[i] (the proof was accepted on chain
              with this exact lsh root, so per-slot equality
              transitively checks all upstream witness fields).
          e.  on-chain ManifestEntry.featureId belongs to the
              FeatureNFT minted at the same slot, with metadata that
              matches the fixture (typeIdx, originFaceId,
              hostShadowId, hostSlotIdx, owner).
          f.  originFaceId in the slot event derives correctly from
              fixture metadata (binds to imageCommit transitively
              through the proof's chain_tips_root).
    9.  on-chain shadowT10[shadowId] matches the fixture's t10_hi/lo.
   10.  shadowId derives byte-exactly from imageCommit % FR_MOD.
   11.  all 8 decrypted plaintexts are distinct (no collisions).
   12.  register/begin tx emitted ImageRegistered with the right imageCommit
        when image registration was included in that batch.

Anything that fails prints the full diagnostic. Exit code is non-zero
on any failure, so this can be wired into CI.

Performance note: each Poseidon2 permutation shells out to `nargo`,
~500ms wall-clock incl. subprocess startup. Decrypting 8 slots requires
~16 perms (1 hash_2 + 1 keystream_39 per slot, where keystream_39 is
batched into 1 helper call). Total ~10-15s for the decrypt phase.

Usage (against the modular phased-mint stack):
    python3 tools/verify_onchain_mint.py \
        --rpc https://sepolia.base.org \
        --st 0x73a2bb3411B1a5D6f9df5a06d3b4bFBA95970e3d \
        --fn 0x6CfAD30a588a57946b306136D4094ca0c07f51aC \
        --kr 0x8c00dD1B1AA71099C9055942F22dB63Dc4361F9D \
        --mc 0x68f777E5B1b8E6b1099F3d8D6153a7C5c9d19A9b \
        --poseidon39 0xbB664d9Ff720Dc8b381AdBc0422E4fe64c088E03 \
        --poseidon16 0xD81E987464B3c40CFF033C01aeC99C7eB7956080 \
        --register-tx 0xbe542296be09dbd9485a0241b4a8906fd32f39daf47e45d60ed37bf43853d238 \
        --mint-tx 0x99fbc0da74aa89f4eb525320083d52c3272d4f8aeb464a17bbfc818d5f361d39 \
        --submit-tx 0x769307da37b3a4196c0855ff45787304001185f9a3c2501805114725d944bab5 \
        --submit-tx ... \
        --fixture contracts/test/fixtures/atomic_mint/latest_testnet_incremental \
        --seed latest_testnet_incremental
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

from eth_utils import keccak  # type: ignore
from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # type: ignore
from v2_circuit_helpers import (  # type: ignore
    P,
    PLAINTEXT_FIELDS,
    decode_plaintext_v2,
    ecies_decrypt_v2,
    encode_plaintext_v2,
    pack_pose,
)


# Event topic hashes (keccak256 of canonical signature).
TOPIC_IMAGE_REGISTERED = keccak(text="ImageRegistered(bytes32)").hex()
TOPIC_SHADOW_MINTED = keccak(
    text="ShadowMinted(uint256,address,uint64,bytes32)").hex()
TOPIC_SLOT_MUTATED = keccak(
    text="ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)"
).hex()
TOPIC_T10_UPDATED = keccak(
    text="ShadowT10Updated(uint256,bytes32,bytes32)").hex()
TOPIC_MINT_CIPHERTEXT_SUBMITTED = keccak(
    text="MintCiphertextSubmitted(uint256,uint8,bytes32,bytes)").hex()
TOPIC_SHADOW_SLOT_ENVELOPE = keccak(
    text="ShadowSlotEnvelope(uint256,uint8,bytes32,bytes32)").hex()


# ============== Reporting ==============

class Report:
    """Pass/fail with summary."""

    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []

    def ok(self, name: str, detail: str = "") -> None:
        self.checks.append((name, True, detail))
        print(f"  + {name}{('  ' + detail) if detail else ''}")

    def fail(self, name: str, detail: str) -> None:
        self.checks.append((name, False, detail))
        print(f"  X {name}\n     {detail}")

    def warn(self, name: str, detail: str) -> None:
        print(f"  ! {name}\n     {detail}")

    def section(self, name: str) -> None:
        print(f"\n=== {name} ===")

    def summary(self) -> bool:
        passed = sum(1 for _, ok, _ in self.checks if ok)
        failed = sum(1 for _, ok, _ in self.checks if not ok)
        print(f"\n--- {passed} passed, {failed} failed ---")
        if failed:
            print("FAILURES:")
            for n, ok, d in self.checks:
                if not ok:
                    print(f"  X {n}: {d}")
        return failed == 0


# ============== JSON-RPC client ==============

class Rpc:
    def __init__(self, url: str) -> None:
        self.url = url
        self._id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = json.dumps({
            "jsonrpc": "2.0", "id": self._id,
            "method": method, "params": params
        }).encode()
        for attempt in range(5):
            try:
                req = urllib.request.Request(
                    self.url, data=body,
                    headers={"Content-Type": "application/json", "User-Agent": "forge/cast"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    resp = json.loads(r.read())
                if "error" in resp:
                    raise RuntimeError(f"RPC error: {resp['error']}")
                return resp["result"]
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError("unreachable")

    def receipt(self, tx: str) -> dict:
        return self.call("eth_getTransactionReceipt", [tx])

    def call_contract(self, to: str, data: str) -> str:
        return self.call("eth_call", [{"to": to, "data": data}, "latest"])


# ============== ABI encoding helpers ==============

def _selector(sig: str) -> str:
    return keccak(text=sig)[:4].hex()


def _enc_uint(v: int) -> str:
    return f"{v & ((1 << 256) - 1):064x}"


def call_view(rpc: Rpc, addr: str, sig: str, args: list, return_types: list[str]
              ) -> tuple:
    """Encode a view-fn call, decode the return tuple by `return_types`.
    `sig` is the SOL function signature without return types
    (e.g. `slotOf(uint256,uint8)`)."""
    sel = _selector(sig)
    enc_args = ""
    for a in args:
        if isinstance(a, int):
            enc_args += _enc_uint(a)
        elif isinstance(a, bytes):
            if len(a) != 32:
                raise ValueError("bytes32 must be 32 bytes")
            enc_args += a.hex()
        elif isinstance(a, str) and a.startswith("0x"):
            raw = bytes.fromhex(a[2:])
            if len(raw) == 20:
                enc_args += "000000000000000000000000" + a[2:].lower()
            elif len(raw) == 32:
                enc_args += a[2:].lower()
            else:
                raise ValueError(f"bad hex arg length: {len(raw)}")
        else:
            raise ValueError(f"bad arg type: {type(a)}")
    data = "0x" + sel + enc_args
    raw = rpc.call_contract(addr, data)
    raw_bytes = bytes.fromhex(raw[2:])
    out = []
    off = 0
    for t in return_types:
        if t in ("uint8", "uint16", "uint64", "uint256"):
            out.append(int.from_bytes(raw_bytes[off:off + 32], "big"))
        elif t == "bool":
            out.append(raw_bytes[off + 31] == 1)
        elif t == "address":
            out.append("0x" + raw_bytes[off + 12:off + 32].hex())
        elif t == "bytes32":
            out.append(raw_bytes[off:off + 32])
        else:
            raise ValueError(f"bad return type: {t}")
        off += 32
    return tuple(out)


# ============== Deterministic witness from seed ==============

def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    import hashlib
    h = hashlib.sha256(b"OMP_ATOMIC_MINT_FIXTURE_v1:" + label + b":" + seed
                       ).digest()
    return int.from_bytes(h, "big") % mod


def reconstruct_owner_sk(seed_str: str) -> int:
    seed = seed_str.encode()
    return deterministic_int(seed, b"owner_sk", GRUMPKIN_ORDER - 1) + 1


def reconstruct_plaintext_params(seed_str: str
                                  ) -> list[tuple[int, int, int, list[int]]]:
    """For each slot i, recompute (pose, w, h, indices) from the seed.
    These match what build_atomic_mint_fixture.py generates."""
    out = []
    for i in range(8):
        pose = pack_pose(x=2 + i * 2, y=4 + (i % 8))
        w_dim = 6 + (i % 4)
        h_dim = 6 + ((i + 1) % 4)
        indices = [(j * 7 + i + 3) & 0xF for j in range(w_dim * h_dim)]
        out.append((pose, w_dim, h_dim, indices))
    return out


# ============== Event log parsing ==============

def parse_slot_mutated(log: dict) -> dict:
    topics = log["topics"]
    assert topics[0].lower() == "0x" + TOPIC_SLOT_MUTATED.lower()
    shadow_id = int(topics[1], 16)
    slot_idx = int(topics[2], 16)
    origin_face_id = bytes.fromhex(topics[3][2:])
    data = bytes.fromhex(log["data"][2:])
    feature_id = int.from_bytes(data[0:32], "big")
    mutation_count = int.from_bytes(data[32:64], "big")
    prev_chain_tip = data[64:96]
    new_chain_tip = data[96:128]
    c2_offset = int.from_bytes(data[128:160], "big")
    c2_len = int.from_bytes(data[c2_offset:c2_offset + 32], "big")
    c2_bytes = data[c2_offset + 32:c2_offset + 32 + c2_len]
    return {
        "shadow_id": shadow_id,
        "slot_idx": slot_idx,
        "origin_face_id": origin_face_id,
        "feature_id": feature_id,
        "mutation_count": mutation_count,
        "prev_chain_tip": prev_chain_tip,
        "new_chain_tip": new_chain_tip,
        "c2_bytes": c2_bytes,
    }

def parse_mint_ciphertext_submitted(log: dict) -> dict:
    topics = log["topics"]
    assert topics[0].lower() == "0x" + TOPIC_MINT_CIPHERTEXT_SUBMITTED.lower()
    data = bytes.fromhex(log["data"][2:])
    c2_offset = int.from_bytes(data[0:32], "big")
    c2_len = int.from_bytes(data[c2_offset:c2_offset + 32], "big")
    c2_bytes = data[c2_offset + 32:c2_offset + 32 + c2_len]
    return {
        "shadow_id": int(topics[1], 16),
        "slot_idx": int(topics[2], 16),
        "ct_commit": bytes.fromhex(topics[3][2:]),
        "c2_bytes": c2_bytes,
    }


def parse_t10_updated(log: dict) -> dict:
    data = bytes.fromhex(log["data"][2:])
    return {
        "shadow_id": int(log["topics"][1], 16),
        "hi": data[0:32],
        "lo": data[32:64],
    }


def parse_shadow_minted(log: dict) -> dict:
    return {
        "shadow_id": int(log["topics"][1], 16),
        "minter": "0x" + log["topics"][2][-40:],
        "mint_idx": int(log["topics"][3], 16),
        "image_commit": bytes.fromhex(log["data"][2:66]),
    }

def parse_shadow_slot_envelope(log: dict) -> dict:
    data = bytes.fromhex(log["data"][2:])
    return {
        "shadow_id": int(log["topics"][1], 16),
        "slot_idx": int(log["topics"][2], 16),
        "c1_x": int.from_bytes(data[0:32], "big"),
        "c1_y": int.from_bytes(data[32:64], "big"),
    }



# ============== Main verification ==============

def verify(args: argparse.Namespace) -> bool:
    rpc = Rpc(args.rpc)
    rep = Report()

    fix_dir = Path(args.fixture)
    with open(fix_dir / "meta.json") as f:
        meta = json.load(f)
    image_commit = int(meta["image_commit"], 16)
    expected_shadow_id = int(meta["shadow_id"], 16)

    fix_pkx = int(meta["owner_pk_x"], 16)
    fix_pky = int(meta["owner_pk_y"], 16)
    fix_c1 = [(int(x, 16), int(y, 16)) for x, y in
              zip(meta["c1_xs"], meta["c1_ys"])]
    fix_c2_fields = [[int(x, 16) for x in slot] for slot in meta["c2_per_slot"]]
    fix_lsh_inits = [int(x, 16) for x in meta["lsh_inits"]]
    fix_chain_tips = [int(x, 16) for x in meta["chain_tips"]]
    fix_origin_face_ids = [int(x, 16) for x in meta["origin_face_ids"]]

    # Reconstruct seed-derived inputs.
    rep.section("0. Seed-derived inputs (deterministic from seed)")
    owner_sk = reconstruct_owner_sk(args.seed)
    owner_pk = ec_mul(G, owner_sk)
    if owner_pk is None:
        rep.fail("owner_pk reconstruction", "ec_mul -> identity")
        return rep.summary()
    if owner_pk == (fix_pkx, fix_pky):
        rep.ok("owner_pk reconstructed from seed matches fixture")
    else:
        rep.fail("owner_pk reconstruction",
                 f"got=({hex(owner_pk[0])[:18]}, {hex(owner_pk[1])[:18]}); "
                 f"fixture=({hex(fix_pkx)[:18]}, {hex(fix_pky)[:18]})")

    seed_params = reconstruct_plaintext_params(args.seed)
    rep.ok("8 plaintext (pose, w, h, indices) tuples derived from seed")

    # ---- 1. Wiring on chain ----
    rep.section("1. Contract wiring (read on chain)")
    (yulSponge,) = call_view(rpc, args.st, "yulSponge()", [], ["address"])

    def cmp_addr(name: str, got: str, want: str) -> None:
        if got.lower() == want.lower():
            rep.ok(name)
        else:
            rep.fail(name, f"got {got}, expected {want}")

    cmp_addr("ShadowToken.yulSponge -> Poseidon2YulSponge", yulSponge,
             args.poseidon39)
    (mc_yul16,) = call_view(rpc, args.mc, "yulSponge16()", [], ["address"])
    cmp_addr("ShadowMintController.yulSponge16 -> Poseidon2YulSponge16",
             mc_yul16, args.poseidon16)

    # KeyRegistry and FeatureNFT are private on ShadowToken in the current
    # bytecode-budgeted contract; verify reachable behavior below via FeatureNFT
    # back-reference, KeyRegistry.pkOf, T10 storage, and slots.

    (fn_st_addr,) = call_view(rpc, args.fn, "shadowToken()", [], ["address"])
    cmp_addr("FeatureNFT.shadowToken -> ShadowToken (back-reference)",
             fn_st_addr, args.st)

    (deployer_pkx, deployer_pky) = call_view(
        rpc, args.kr, "pkOf(address)", [args.deployer],
        ["bytes32", "bytes32"])
    if (int.from_bytes(deployer_pkx, "big") == fix_pkx
        and int.from_bytes(deployer_pky, "big") == fix_pky):
        rep.ok("KeyRegistry.pkOf(deployer) matches fixture owner_pk")
    else:
        rep.fail("KeyRegistry.pkOf(deployer)",
                 f"got ({deployer_pkx.hex()[:18]}, {deployer_pky.hex()[:18]})")

    # ---- 2. Mint tx receipt + logs ----
    rep.section("2. Mint tx receipt + event count")
    receipt = rpc.receipt(args.mint_tx)
    if receipt is None:
        rep.fail("mint receipt fetch", f"no receipt for {args.mint_tx}")
        return rep.summary()
    if receipt["status"] != "0x1":
        rep.fail("mint tx status", f"status={receipt['status']}")
        return rep.summary()
    rep.ok(f"mint tx status=0x1, gasUsed={int(receipt['gasUsed'], 16):,}")

    minted_logs = []
    slot_logs = []
    t10_logs = []
    envelope_logs = []
    for log in receipt["logs"]:
        if log["address"].lower() != args.st.lower():
            continue
        topic0 = log["topics"][0].lower()
        if topic0 == "0x" + TOPIC_SHADOW_MINTED.lower():
            minted_logs.append(parse_shadow_minted(log))
        elif topic0 == "0x" + TOPIC_SLOT_MUTATED.lower():
            slot_logs.append(parse_slot_mutated(log))
        elif topic0 == "0x" + TOPIC_T10_UPDATED.lower():
            t10_logs.append(parse_t10_updated(log))
        elif topic0 == "0x" + TOPIC_SHADOW_SLOT_ENVELOPE.lower():
            envelope_logs.append(parse_shadow_slot_envelope(log))

    c2_logs = []
    for tx in args.submit_tx:
        sub_receipt = rpc.receipt(tx)
        if sub_receipt is None:
            rep.fail("submit tx receipt", f"no receipt for {tx}")
            continue
        if sub_receipt["status"] != "0x1":
            rep.fail("submit tx status", f"{tx} status={sub_receipt['status']}")
            continue
        rep.ok(f"submit tx status=0x1, gasUsed={int(sub_receipt['gasUsed'], 16):,}")
        for log in sub_receipt["logs"]:
            if (log["address"].lower() == args.mc.lower()
                and log["topics"][0].lower()
                    == "0x" + TOPIC_MINT_CIPHERTEXT_SUBMITTED.lower()):
                c2_logs.append(parse_mint_ciphertext_submitted(log))

    if len(minted_logs) == 1:
        rep.ok("exactly 1 ShadowMinted event")
    else:
        rep.fail("ShadowMinted event count", f"got {len(minted_logs)}")
    if len(slot_logs) == 8:
        rep.ok("exactly 8 ShadowSlotMutated events")
    else:
        rep.fail("ShadowSlotMutated event count", f"got {len(slot_logs)}")
    if len(c2_logs) == 8:
        rep.ok("exactly 8 MintCiphertextSubmitted events")
    else:
        rep.fail("MintCiphertextSubmitted event count", f"got {len(c2_logs)}")
    if len(t10_logs) == 1:
        rep.ok("exactly 1 ShadowT10Updated event")
    else:
        rep.fail("ShadowT10Updated event count", f"got {len(t10_logs)}")
    if len(envelope_logs) == 8:
        rep.ok("exactly 8 ShadowSlotEnvelope events")
    else:
        rep.fail("ShadowSlotEnvelope event count", f"got {len(envelope_logs)}")

    if len(minted_logs) != 1 or len(slot_logs) != 8 or len(c2_logs) != 8 or len(t10_logs) != 1 or len(envelope_logs) != 8:
        return rep.summary()

    # ---- 3. ShadowMinted event payload ----
    rep.section("3. ShadowMinted event payload")
    m = minted_logs[0]
    if m["shadow_id"] == expected_shadow_id:
        rep.ok(f"shadowId in event = {hex(m['shadow_id'])[:18]}...")
    else:
        rep.fail("ShadowMinted.shadowId",
                 f"got {hex(m['shadow_id'])[:18]}")
    if m["mint_idx"] == 1:
        rep.ok("mintIdx = 1 (first ever mint)")
    else:
        rep.fail("ShadowMinted.mintIdx", f"got {m['mint_idx']}")
    if int.from_bytes(m["image_commit"], "big") == image_commit:
        rep.ok("imageCommit in event matches fixture")
    else:
        rep.fail("ShadowMinted.imageCommit", f"got {m['image_commit'].hex()}")
    if expected_shadow_id == image_commit % P:
        rep.ok("shadowId = imageCommit mod FR_MOD (deterministic derivation)")
    else:
        rep.fail("shadowId derivation", "doesn't match imageCommit mod FR_MOD")
    if m["minter"].lower() == args.deployer.lower():
        rep.ok("minter address in event = deployer")
    else:
        rep.fail("ShadowMinted.minter", f"got {m['minter']}")

    # ---- 4. T10 event payload + storage ----
    rep.section("4. ShadowT10Updated event + storage")
    t = t10_logs[0]
    fix_t10_hi = bytes.fromhex(meta["t10_hi"][2:])
    fix_t10_lo = bytes.fromhex(meta["t10_lo"][2:])
    if t["hi"] == fix_t10_hi and t["lo"] == fix_t10_lo:
        rep.ok("T10 (hi, lo) in event byte-equals fixture PI")
    else:
        rep.fail("ShadowT10Updated payload",
                 f"got hi={t['hi'].hex()[:18]} lo={t['lo'].hex()[:18]}")

    (st_t10_hi,) = call_view(rpc, args.st, "shadowT10(uint256,uint256)",
                              [expected_shadow_id, 0], ["bytes32"])
    (st_t10_lo,) = call_view(rpc, args.st, "shadowT10(uint256,uint256)",
                              [expected_shadow_id, 1], ["bytes32"])
    if st_t10_hi == fix_t10_hi and st_t10_lo == fix_t10_lo:
        rep.ok("on-chain shadowT10 storage = event payload = fixture")
    else:
        rep.fail("shadowT10 storage",
                 f"hi={st_t10_hi.hex()[:18]} lo={st_t10_lo.hex()[:18]}")

    # ---- 5. Per-slot integrity ----
    rep.section("5. Per-slot integrity (events + decryption + manifest + carrier)")
    slot_logs.sort(key=lambda x: x["slot_idx"])
    c2_logs.sort(key=lambda x: x["slot_idx"])
    envelope_logs.sort(key=lambda x: x["slot_idx"])
    distinct_plaintexts = set()
    print("    [decrypting all 8 c2s; ~10-15s per slot via nargo]")

    for i in range(8):
        slot_log = slot_logs[i]
        c2_log = c2_logs[i]
        envelope_log = envelope_logs[i]
        if slot_log["slot_idx"] != i or c2_log["slot_idx"] != i or envelope_log["slot_idx"] != i:
            rep.fail(f"slot {i} event ordering",
                     f"slotLog={slot_log['slot_idx']} c2Log={c2_log['slot_idx']} envelopeLog={envelope_log['slot_idx']}")
            continue

        # 5a. on-chain submitted c2 byte-equals fixture c2 (re-encoded as 39 * 32 bytes).
        expected_c2_bytes = b"".join(
            v.to_bytes(32, "big") for v in fix_c2_fields[i])
        if c2_log["c2_bytes"] != expected_c2_bytes:
            rep.fail(f"slot {i}: submitted c2 != fixture c2",
                     f"len {len(c2_log['c2_bytes'])} vs {len(expected_c2_bytes)}")
            continue
        if slot_log["c2_bytes"] != b"":
            rep.fail(f"slot {i}: finalize ShadowSlotMutated c2 not empty",
                     f"len {len(slot_log['c2_bytes'])}")
            continue

        # 5b. ECIES decrypt under owner_sk using c1 from chain, not fixture-only sidecars.
        if (envelope_log["c1_x"], envelope_log["c1_y"]) != fix_c1[i]:
            rep.fail(f"slot {i}: ShadowSlotEnvelope c1 != fixture c1",
                     f"got=({hex(envelope_log['c1_x'])[:18]}, {hex(envelope_log['c1_y'])[:18]})")
            continue
        recovered_plaintext, _k = ecies_decrypt_v2(
            (envelope_log["c1_x"], envelope_log["c1_y"]), fix_c2_fields[i], owner_sk)

        # 5c. Re-encode (pose, w, h, indices) from seed and compare.
        pose, w_dim, h_dim, indices = seed_params[i]
        expected_plaintext = encode_plaintext_v2(pose, w_dim, h_dim, indices)
        if recovered_plaintext != expected_plaintext:
            rep.fail(f"slot {i}: decrypt mismatch",
                     "recovered plaintext != seed-derived plaintext")
            continue

        # 5c-bis. Decoded payload sanity.
        rec_pose, rec_w, rec_h, rec_indices = decode_plaintext_v2(
            recovered_plaintext)
        if (rec_pose, rec_w, rec_h, rec_indices) != (pose, w_dim, h_dim, indices):
            rep.fail(f"slot {i}: decoded payload mismatch",
                     f"got pose={rec_pose}, dims={rec_w}x{rec_h}")
            continue

        # 5d. on-chain ManifestEntry: kind, featureId, lsh.
        # Solidity ABI returns the struct via offset+content; for a 3-field
        # tuple of static types it's just 3 consecutive 32-byte slots.
        sel = _selector("slotOf(uint256,uint8)")
        data = "0x" + sel + _enc_uint(expected_shadow_id) + _enc_uint(i)
        raw = rpc.call_contract(args.st, data)
        raw_bytes = bytes.fromhex(raw[2:])
        kind = int.from_bytes(raw_bytes[0:32], "big")
        feat_id = int.from_bytes(raw_bytes[32:64], "big")
        lsh = raw_bytes[64:96]

        if kind != 1:
            rep.fail(f"slot {i}: kind != OCCUPIED", f"kind={kind}")
            continue
        expected_lsh = fix_lsh_inits[i].to_bytes(32, "big")
        if lsh != expected_lsh:
            rep.fail(f"slot {i}: liveStateHash mismatch",
                     f"got={lsh.hex()[:18]}, expected={expected_lsh.hex()[:18]}")
            continue

        # 5e. originFaceId in the event matches fixture.
        ofi_expected = fix_origin_face_ids[i].to_bytes(32, "big")
        if slot_log["origin_face_id"] != ofi_expected:
            rep.fail(f"slot {i}: originFaceId in event mismatch",
                     f"got={slot_log['origin_face_id'].hex()[:18]}")
            continue

        # 5f. FeatureNFT cross-state.
        (fn_owner,) = call_view(rpc, args.fn, "ownerOf(uint256)",
                                 [feat_id], ["address"])
        if fn_owner.lower() != args.deployer.lower():
            rep.fail(f"slot {i}: carrier owner mismatch",
                     f"got {fn_owner}")
            continue
        (fn_host_shadow,) = call_view(rpc, args.fn, "hostShadowIdOf(uint256)",
                                       [feat_id], ["uint256"])
        if fn_host_shadow != expected_shadow_id:
            rep.fail(f"slot {i}: carrier hostShadowId mismatch",
                     f"got {hex(fn_host_shadow)[:18]}")
            continue
        (fn_host_slot,) = call_view(rpc, args.fn, "hostSlotIdxOf(uint256)",
                                     [feat_id], ["uint8"])
        if fn_host_slot != i:
            rep.fail(f"slot {i}: carrier hostSlotIdx mismatch",
                     f"got {fn_host_slot}")
            continue
        (fn_type,) = call_view(rpc, args.fn, "typeIdxOf(uint256)",
                                [feat_id], ["uint8"])
        if fn_type != i:
            rep.fail(f"slot {i}: carrier typeIdx mismatch",
                     f"got {fn_type}")
            continue
        (fn_ofi,) = call_view(rpc, args.fn, "originFaceIdOf(uint256)",
                               [feat_id], ["bytes32"])
        if fn_ofi != ofi_expected:
            rep.fail(f"slot {i}: carrier originFaceId mismatch",
                     f"got={fn_ofi.hex()[:18]}")
            continue

        # mutationCount on event must be 0 (mint sets initial state).
        if slot_log["mutation_count"] != 0:
            rep.fail(f"slot {i}: mutationCount in event != 0",
                     f"got {slot_log['mutation_count']}")
            continue

        # newChainTip in event must equal fixture's chain_tips[i].
        if int.from_bytes(slot_log["new_chain_tip"], "big") != fix_chain_tips[i]:
            rep.fail(f"slot {i}: newChainTip in event != fixture chain_tip[i]",
                     f"got={slot_log['new_chain_tip'].hex()[:18]}")
            continue

        rep.ok(f"slot {i}: c2 ok  decrypt ok  decode ok  lsh ok  carrier ok  "
               f"({rec_w}x{rec_h} sprite, pose=0x{rec_pose:x}, fid={hex(feat_id)[:18]}...)")
        distinct_plaintexts.add(tuple(recovered_plaintext))

    if len(distinct_plaintexts) == 8:
        rep.ok("all 8 decrypted plaintexts are distinct (no collisions)")
    else:
        rep.fail("plaintext distinctness",
                 f"only {len(distinct_plaintexts)} distinct out of 8")

    # ---- 6. Empty slots 8..15 ----
    rep.section("6. Empty slots (8..15)")
    all_empty = True
    for i in range(8, 16):
        sel = _selector("slotOf(uint256,uint8)")
        data = "0x" + sel + _enc_uint(expected_shadow_id) + _enc_uint(i)
        raw = rpc.call_contract(args.st, data)
        raw_bytes = bytes.fromhex(raw[2:])
        kind = int.from_bytes(raw_bytes[0:32], "big")
        feat_id = int.from_bytes(raw_bytes[32:64], "big")
        lsh = raw_bytes[64:96]
        if kind != 0 or feat_id != 0 or lsh != b"\x00" * 32:
            rep.fail(f"slot {i}: expected EMPTY",
                     f"kind={kind}, fid={feat_id}, lsh={lsh.hex()[:18]}")
            all_empty = False
    if all_empty:
        rep.ok("slots 8..15 all EMPTY (kind=0, fid=0, lsh=0)")

    # ---- 7. Aggregate state ----
    rep.section("7. Aggregate ShadowToken state")
    # mintCounter is private in the bytecode-budgeted ShadowToken; the public
    # ShadowMinted.mintIdx event assertion above verifies the same first-mint
    # invariant without requiring another getter.

    (regd,) = call_view(rpc, args.st, "registeredImages(bytes32)",
                         [meta["image_commit"]], ["bool"])
    if regd:
        rep.ok("registeredImages[imageCommit] = true")
    else:
        rep.fail("registeredImages", "false")

    (minted,) = call_view(rpc, args.st, "mintedOrigins(bytes32)",
                           [meta["image_commit"]], ["bool"])
    if minted:
        rep.ok("mintedOrigins[imageCommit] = true")
    else:
        rep.fail("mintedOrigins", "false")

    (owner,) = call_view(rpc, args.st, "ownerOf(uint256)",
                          [expected_shadow_id], ["address"])
    if owner.lower() == args.deployer.lower():
        rep.ok(f"ownerOf(shadowId) = deployer")
    else:
        rep.fail("ownerOf(shadowId)", f"got {owner}")

    # Shadow header: ecdh pubkey, solved flag, and z-index commitment.
    (s_ecdh_x, s_ecdh_y, s_solved, s_zindex_commit) = call_view(
        rpc, args.st, "shadowHeaderOf(uint256)", [expected_shadow_id],
        ["bytes32", "bytes32", "bool", "bytes32"]
    )
    if (int.from_bytes(s_ecdh_x, "big") == fix_pkx
        and int.from_bytes(s_ecdh_y, "big") == fix_pky):
        rep.ok("Shadow.ecdhPub matches fixture owner_pk")
    else:
        rep.fail("Shadow.ecdhPub",
                 f"got ({s_ecdh_x.hex()[:18]}, {s_ecdh_y.hex()[:18]})")
    if not s_solved:
        rep.ok("Shadow.solved = false (fresh mint)")
    else:
        rep.fail("Shadow.solved", "true; should be false on fresh mint")
    if s_zindex_commit == b"\x00" * 32:
        rep.ok("Shadow.zIndexCommit = 0 (not yet committed)")
    else:
        rep.fail("Shadow.zIndexCommit", f"got {s_zindex_commit.hex()[:18]}")

    # ---- 8. register/begin tx ----
    rep.section("8. register/begin tx receipt + ImageRegistered event")
    reg_receipt = rpc.receipt(args.register_tx)
    if reg_receipt is None:
        rep.fail("register/begin receipt", "no receipt")
    elif reg_receipt["status"] != "0x1":
        rep.fail("register/begin tx status", f"status={reg_receipt['status']}")
    else:
        rep.ok(f"register/begin tx status=0x1, "
               f"gasUsed={int(reg_receipt['gasUsed'], 16):,}")
        for log in reg_receipt["logs"]:
            if (log["address"].lower() == args.st.lower()
                and log["topics"][0].lower()
                    == "0x" + TOPIC_IMAGE_REGISTERED.lower()):
                ev_ic = bytes.fromhex(log["topics"][1][2:])
                if int.from_bytes(ev_ic, "big") == image_commit:
                    rep.ok("ImageRegistered event with correct imageCommit")
                else:
                    rep.fail("ImageRegistered.imageCommit",
                             f"got {ev_ic.hex()[:18]}")
                break
        else:
            rep.fail("ImageRegistered event", "not found in receipt")

    return rep.summary()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="https://base-sepolia.gateway.tenderly.co")
    ap.add_argument("--st", required=True, help="ShadowToken address")
    ap.add_argument("--fn", required=True, help="FeatureNFT address")
    ap.add_argument("--kr", required=True, help="KeyRegistry address")
    ap.add_argument("--poseidon39", required=True,
                    help="Poseidon2YulSponge (sponge_39) address")
    ap.add_argument("--poseidon16", required=True,
                    help="Poseidon2YulSponge16 (sponge_16) address")
    ap.add_argument("--mc", required=True,
                    help="ShadowMintController address")
    ap.add_argument("--mint-tx", required=True)
    ap.add_argument("--register-tx", required=True)
    ap.add_argument("--submit-tx", action="append", default=[],
                    help="ShadowMintController submit tx hash; repeat for each tx containing MintCiphertextSubmitted")
    ap.add_argument("--deployer", required=True)
    ap.add_argument("--fixture",
                    default="contracts/test/fixtures/atomic_mint/atomic_mint_demo")
    ap.add_argument("--seed", default="atomic_mint_demo")
    args = ap.parse_args()

    ok = verify(args)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
