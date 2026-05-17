#!/usr/bin/env python3
"""End-to-end pixel-equality validator.

Verifies that the chain-bound ciphertexts (alice0 mint c2, transfer_shadow
new_c2, extract_slot feature_c2, transfer_feature new_c2) decrypt back to
the SAME bytes that the canonical Python simulation
(`mint_pipeline.compute_face_state`) produces from the source face PNG.

This is the "ground truth" check: chain bytes == Python pipeline bytes,
end-to-end, under recipient's secret key. If anything drifts (encoding,
encryption, sponge, ECDH, keystream), this script catches it.

For each fixture, the script:
  - Recomputes the canonical bytes from the original face image + palette
  - Decrypts the chain-bound c2 with the recipient's sk
  - Asserts byte-for-byte equality
  - Renders the recovered region bytes as a PNG (so a human can look)

Usage:
    python3 validate_pixels.py [--out-dir validation_renders/]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, encrypt_mint_envelope,
    pack_recolored_to_fields, unpack_fields_to_recolored,
    split_into_regions, join_regions,
    poseidon2_sponge_249, poseidon2_hash_2, poseidon2_keystream_249,
    P, REGION_BYTES,
)
from mint_pipeline import compute_face_state, REGION_NAMES, REGION_W, REGION_H  # noqa: E402
from secret_inbox import ec_mul  # noqa: E402
from build_extract_slot_fixture import poseidon2_keystream_42, poseidon2_sponge_42  # noqa: E402

ROOT = REPO.parent
ALICE0_DIR = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
TRANSFER_SHADOW_DIR = ROOT / "contracts" / "test" / "fixtures" / "transfer_shadow" / "alice0_to_bob"
EXTRACT_SLOT_DIR = ROOT / "contracts" / "test" / "fixtures" / "extract_slot" / "alice0_slot3_to_carol"
TRANSFER_FEATURE_DIR = ROOT / "contracts" / "test" / "fixtures" / "transfer_feature" / "carol_to_dave"

ALICE_FACE = ROOT / "examples" / "faces" / "alice0.png"

# Per-region byte counts (matches REGION_BYTES in mint_decrypt.py).
# (1296, 792, 792, 792, 798, 798, 1296, 1152) -> sum 7716
EXPECTED_TOTAL = 7716

GREEN = "\033[32m"
RED   = "\033[31m"
DIM   = "\033[90m"
RESET = "\033[0m"


def parse_pi_file(path: Path) -> list[int]:
    raw = path.read_bytes()
    return [int.from_bytes(raw[i*32:(i+1)*32], "big") for i in range(len(raw) // 32)]


def parse_c2_file(path: Path, n_fields: int) -> list[int]:
    raw = path.read_bytes()
    assert len(raw) == n_fields * 32, f"c2 wrong length: {len(raw)} vs {n_fields * 32}"
    return [int.from_bytes(raw[i*32:(i+1)*32], "big") for i in range(n_fields)]


def assert_equal(label: str, a, b, *, dim_a: bool = False) -> bool:
    if a == b:
        print(f"    {GREEN}OK{RESET}  {label}")
        return True
    print(f"    {RED}FAIL{RESET} {label}")
    if isinstance(a, (bytes, bytearray)) and isinstance(b, (bytes, bytearray)):
        n = min(len(a), len(b))
        diff = next((i for i in range(n) if a[i] != b[i]), n)
        print(f"        first diff at byte {diff}")
        print(f"        canonical[{diff}..{diff+8}] = {a[diff:diff+8].hex()}")
        print(f"        recovered[{diff}..{diff+8}] = {b[diff:diff+8].hex()}")
        print(f"        lengths: canonical={len(a)} recovered={len(b)}")
    elif isinstance(a, list) and isinstance(b, list):
        diff = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
        print(f"        first diff at field {diff}")
        print(f"        canonical: {hex(a[diff])[:24]}...")
        print(f"        recovered: {hex(b[diff])[:24]}...")
    else:
        print(f"        canonical: {a}")
        print(f"        recovered: {b}")
    return False


def render_face_png(per_region_bytes: list[bytes], out_path: Path):
    """Reconstruct a 48x48 RGB face from 8 per-region recolored buffers and
    save as PNG. Each region's bytes are CHW-ordered (channel-first per region).
    Renders at the canonical (origin) pose (no manifest poses applied here).

    The renderer ASSUMES region boundaries are non-overlapping per the v5
    geometry (boxes are computed from CNN landmarks and laid out symmetrically).
    For overlapping renders see render_shadow.py.
    """
    try:
        from PIL import Image
    except ImportError:
        print(f"    (PIL not installed; skipping PNG render)")
        return
    import numpy as np

    canvas = np.zeros((48, 48, 3), dtype=np.uint8)

    # Each region's bytes layout from mint_pipeline._recolor_region:
    # CHW within the region's max_w x max_h bounding box. Use
    # REGION_W / REGION_H to unpack.
    for ftype, region_bytes in enumerate(per_region_bytes):
        max_w = REGION_W[ftype]
        max_h = REGION_H[ftype]
        # The state['regions'][ftype].x1, y1, w, h gives the actual box on the
        # canvas. We don't have those here without recomputing compute_face_state,
        # so render at (0, 0) of each region's max bounding box. The PNG output
        # is for visual sanity only -- the byte-equality check is the canonical
        # validation.
        # Per-region byte layout: CHW order, max_w * max_h * 3 bytes total.
        if len(region_bytes) != max_w * max_h * 3:
            print(f"    region {ftype}: bytes={len(region_bytes)} expected={max_w*max_h*3}; skipping")
            continue
        arr = np.frombuffer(region_bytes, dtype=np.uint8).reshape(max_h, max_w, 3)
        # Just dump regions side-by-side into a debug strip below the canvas.
        # For visual inspection only.
        # (The actual face position needs the box info; we skip for this PNG.)
        # Skip individual region renders — just save the canvas as-is.

    # For a meaningful image, dump a 48x(48 + total_strip_h) image with regions
    # listed below. Or just dump the canvas blank.
    Image.fromarray(canvas).save(out_path)


def assemble_face_png(per_region_bytes: list[bytes], region_geom: list[tuple[int, int, int, int]], out_path: Path):
    """Place per-region bytes at their canonical (x1, y1, w, h) onto a 48x48
    canvas and save. region_geom is per-feature (x1, y1, w, h) at IDENTITY pose."""
    try:
        from PIL import Image
    except ImportError:
        print(f"    (PIL not installed; skipping PNG render)")
        return
    import numpy as np

    canvas = np.zeros((48, 48, 3), dtype=np.uint8)
    for ftype, (region_bytes, (x1, y1, w, h)) in enumerate(zip(per_region_bytes, region_geom)):
        max_w = REGION_W[ftype]; max_h = REGION_H[ftype]
        if len(region_bytes) != max_w * max_h * 3:
            continue
        arr = np.frombuffer(region_bytes, dtype=np.uint8).reshape(max_h, max_w, 3)
        # Use only the in-bounds (h, w) sub-rectangle; the rest is OOB-zero pad.
        # In compute_face_state's _recolor_region, valid pixels are at indices
        # [0..h, 0..w] of the (max_h, max_w) region; the rest are zero pad.
        canvas[y1:y1+h, x1:x1+w, :] = arr[:h, :w, :]
    Image.fromarray(canvas).save(out_path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=str(ROOT / "runs" / "validation_renders"))
    ap.add_argument("--allow-missing", action="store_true",
                    help="Skip (instead of fail) sections whose fixture dirs are absent. "
                         "Default is to fail-fast on missing required fixtures (audit M-09).")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 68)
    print(" Phase 2 pixel-equality validation")
    print("=" * 68)
    all_ok = True

    def _missing(label: str, path: Path) -> bool:
        """Per audit M-09: missing required fixtures must NOT silently skip."""
        if path.exists():
            return False
        if args.allow_missing:
            print(f"  {DIM}skip ({label}): fixture not found at {path}{RESET}")
            return True
        print(f"  FAIL ({label}): required fixture not found at {path}")
        print(f"         re-run the upstream builder, or pass --allow-missing")
        nonlocal all_ok
        all_ok = False
        return True

    # =========================================================================
    # SECTION 1: alice0 mint -- chain bytes equal Python simulation
    # =========================================================================
    print(f"\n{DIM}--- 1. alice0 mint: simulation -> chain bytes ---{RESET}")
    alice_pi = parse_pi_file(ALICE0_DIR / "public_inputs")
    alice_fix = json.loads((ALICE0_DIR / "fixture.json").read_text())
    alice_sk = int(alice_fix["witness"]["recipient_sk"], 16)
    alice_pk_x = int(alice_fix["witness"]["recipient_pk_x"], 16)
    alice_pk_y = int(alice_fix["witness"]["recipient_pk_y"], 16)
    alice_caller_nonce = int(alice_fix["witness"]["caller_nonce"], 16)
    color = int(alice_pi[10])
    print(f"  face        : {ALICE_FACE.name}")
    print(f"  palette     : {color}")
    print(f"  alice pk.x  : {hex(alice_pk_x)[:18]}...")

    # Step 1a: run Python simulation
    print(f"\n  [1a] compute_face_state -> per-region recolored bytes")
    state = compute_face_state(ALICE_FACE, color)
    canonical_per_region = [bytes(r.recolored) for r in state.regions]
    canonical_total_bytes = sum(len(b) for b in canonical_per_region)
    assert canonical_total_bytes == EXPECTED_TOTAL, \
        f"canonical total bytes {canonical_total_bytes} != {EXPECTED_TOTAL}"
    canonical_concat = b"".join(canonical_per_region)
    canonical_packed = pack_recolored_to_fields(canonical_concat)
    assert len(canonical_packed) == 249

    # Step 1b: re-encrypt under alice's witness
    print(f"  [1b] re-encrypt canonical bytes under alice's caller_nonce + pk")
    sim_envelope = encrypt_mint_envelope(
        caller_nonce=alice_caller_nonce,
        recipient_pk_x=alice_pk_x,
        recipient_pk_y=alice_pk_y,
        recolored_packed=canonical_packed,
    )

    # Step 1c: chain c2 bytes
    chain_c2 = parse_c2_file(ALICE0_DIR / "c2.bin", 249)

    # Compare ct_commit (must match alice0.PI[14])
    all_ok &= assert_equal(
        "alice0.PI[14] == sim.ct_commit  (chain proof binding == sim sponge_249)",
        hex(alice_pi[14]),
        hex(sim_envelope.ct_commit),
    )

    # Compare c2 byte-for-byte
    all_ok &= assert_equal(
        "alice0.c2 == sim.c2  (chain ECIES bytes == sim ECIES bytes)",
        chain_c2,
        sim_envelope.c2,
    )

    # Compare c1 (envelope ephemeral pk)
    all_ok &= assert_equal("alice0.PI[12] (c1.x) == sim.c1.x", hex(alice_pi[12]), hex(sim_envelope.c1_x))
    all_ok &= assert_equal("alice0.PI[13] (c1.y) == sim.c1.y", hex(alice_pi[13]), hex(sim_envelope.c1_y))

    # Step 1d: decrypt chain c2 with alice's sk -> recover bytes
    print(f"  [1d] decrypt chain c2 with alice_sk -> recover bytes")
    recovered_packed = decrypt_mint_envelope(
        recipient_sk=alice_sk, c1_x=alice_pi[12], c1_y=alice_pi[13], c2=chain_c2,
    )
    recovered_concat = unpack_fields_to_recolored(recovered_packed)
    recovered_per_region = split_into_regions(recovered_concat)

    all_ok &= assert_equal("decrypted concat bytes == canonical concat", canonical_concat, recovered_concat)
    for ftype, (canon_bytes, rec_bytes) in enumerate(zip(canonical_per_region, recovered_per_region)):
        ok = assert_equal(f"region {ftype} ({REGION_NAMES[ftype]}): {len(canon_bytes)} bytes byte-equal", canon_bytes, rec_bytes)
        all_ok &= ok

    # Step 1e: render the recovered face for human inspection
    geom = [(r.x1, r.y1, r.w, r.h) for r in state.regions]
    canon_png = out_dir / "01_alice0_canonical.png"
    rec_png   = out_dir / "01_alice0_recovered_from_chain.png"
    assemble_face_png(canonical_per_region, geom, canon_png)
    assemble_face_png(recovered_per_region, geom, rec_png)
    print(f"  [1e] rendered: {canon_png.name}, {rec_png.name}")

    # =========================================================================
    # SECTION 2: transfer_shadow -- bob's c2 decrypts to same bytes
    # =========================================================================
    print(f"\n{DIM}--- 2. transfer_shadow: bob's c2 decrypts to alice's plaintext ---{RESET}")
    if _missing("transfer_shadow", TRANSFER_SHADOW_DIR):
        pass
    else:
        bob_fix = json.loads((TRANSFER_SHADOW_DIR / "fixture.json").read_text())
        bob_sk = int(bob_fix["bob_sk"], 16)
        bob_c2 = parse_c2_file(TRANSFER_SHADOW_DIR / "new_c2.bin", 249)

        # Decrypt: shared = c1 * bob_sk; k_mask = Poseidon2(shared);
        # new_k = c2_scalar - k_mask; ks = keystream_249(new_k); plaintext = c2 - ks
        # (Different from mint convention where k = k_mask directly.)
        bob_shared = ec_mul(
            (int(bob_fix["c1_new_x"], 16), int(bob_fix["c1_new_y"], 16)), bob_sk,
        )
        bob_k_mask = poseidon2_hash_2(bob_shared[0], bob_shared[1])
        bob_c2_scalar = int(bob_fix["c2_scalar"], 16)
        bob_new_k = (bob_c2_scalar - bob_k_mask) % P
        bob_ks = poseidon2_keystream_249(bob_new_k)
        bob_recovered_packed = [(bob_c2[i] - bob_ks[i]) % P for i in range(249)]
        bob_recovered_concat = unpack_fields_to_recolored(bob_recovered_packed)
        bob_recovered_per_region = split_into_regions(bob_recovered_concat)

        all_ok &= assert_equal("bob.recovered_packed == alice.recovered_packed (Field-equal)",
                               recovered_packed, bob_recovered_packed)
        all_ok &= assert_equal("bob.recovered_concat == canonical_concat (byte-equal)",
                               canonical_concat, bob_recovered_concat)

        # Render bob's recovered face for human inspection.
        bob_png = out_dir / "02_transfer_shadow_bob_recovered.png"
        assemble_face_png(bob_recovered_per_region, geom, bob_png)
        print(f"  rendered: {bob_png.name}")

    # =========================================================================
    # SECTION 3: extract_slot -- carol's feature_c2 == canonical region payload
    # =========================================================================
    print(f"\n{DIM}--- 3. extract_slot (slot 3 / nose): carol's feature_c2 == canonical ---{RESET}")
    if _missing("extract_slot", EXTRACT_SLOT_DIR):
        pass
    else:
        ex_fix = json.loads((EXTRACT_SLOT_DIR / "fixture.json").read_text())
        carol_sk = int(ex_fix["carol_sk"], 16)
        slot = int(ex_fix["slot"])
        feature_c2 = parse_c2_file(EXTRACT_SLOT_DIR / "feature_c2.bin", 42)

        # Decrypt: shared = c1 * carol_sk; k_mask = Poseidon2(shared); k = c2_scalar - k_mask
        c1_x = int(ex_fix["c1_new_x"], 16); c1_y = int(ex_fix["c1_new_y"], 16)
        carol_shared = ec_mul((c1_x, c1_y), carol_sk)
        carol_k_mask = poseidon2_hash_2(carol_shared[0], carol_shared[1])
        c2_scalar = int(ex_fix["c2_scalar"], 16)
        feature_k = (c2_scalar - carol_k_mask) % P
        ks = poseidon2_keystream_42(feature_k)
        carol_feature_payload = [(feature_c2[i] - ks[i]) % P for i in range(42)]

        # The canonical payload is state.regions[slot].packed_padded (per-feature
        # 42-Field array). Both should match.
        canonical_payload = list(state.regions[slot].packed_padded)
        all_ok &= assert_equal(
            f"carol.feature_payload (slot {slot} = {REGION_NAMES[slot]}) == canonical packed_padded",
            canonical_payload, carol_feature_payload,
        )

        # Also check sponge_42 commitment matches what the chain bound.
        sim_commit = poseidon2_sponge_42(
            [(carol_feature_payload[i] + ks[i]) % P for i in range(42)]
        )
        all_ok &= assert_equal(
            f"carol.feature_ct_commit == sim sponge_42",
            int(ex_fix["feature_ct_commit"], 16), sim_commit,
        )

    # =========================================================================
    # SECTION 4: transfer_feature -- dave's c2 decrypts to same payload as carol
    # =========================================================================
    print(f"\n{DIM}--- 4. transfer_feature: dave's c2 decrypts to carol's payload ---{RESET}")
    if _missing("transfer_feature", TRANSFER_FEATURE_DIR):
        pass
    elif _missing("transfer_feature/extract baseline", EXTRACT_SLOT_DIR):
        pass
    else:
        tf_fix = json.loads((TRANSFER_FEATURE_DIR / "fixture.json").read_text())
        dave_sk = int(tf_fix["dave_sk"], 16)
        dave_c2 = parse_c2_file(TRANSFER_FEATURE_DIR / "new_c2.bin", 42)

        # Decrypt with dave_sk.
        dave_shared = ec_mul((int(tf_fix["c1_new_x"], 16), int(tf_fix["c1_new_y"], 16)), dave_sk)
        dave_k_mask = poseidon2_hash_2(dave_shared[0], dave_shared[1])
        dave_c2_scalar = int(tf_fix["c2_scalar"], 16)
        dave_feature_k = (dave_c2_scalar - dave_k_mask) % P
        dave_ks = poseidon2_keystream_42(dave_feature_k)
        dave_payload = [(dave_c2[i] - dave_ks[i]) % P for i in range(42)]

        # Should equal carol's payload (= canonical packed_padded[slot])
        all_ok &= assert_equal(
            "dave.feature_payload == carol.feature_payload (== canonical)",
            canonical_payload, dave_payload,
        )

    # =========================================================================
    # Summary
    # =========================================================================
    print()
    print("=" * 68)
    if all_ok:
        print(f" {GREEN}ALL CHECKS PASS -- chain bytes equal Python simulation{RESET}")
    else:
        print(f" {RED}SOME CHECKS FAILED -- see above{RESET}")
    print(f" Renders: {out_dir}/")
    print("=" * 68)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
