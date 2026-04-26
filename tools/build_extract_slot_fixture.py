#!/usr/bin/env python3
"""Generate an extract_slot fixture: alice0's slot N extracted to a FeatureNFT.

Pipeline:
  1. Load alice0 mint state + decrypt c2 -> 249-Field shadow plaintext.
  2. Recover prev_k (shadow's keystream seed).
  3. Pick recipient (carol) for the new FeatureNFT.
  4. Slice the slot's 42-Field segment from shadow plaintext (matching the
     circuit's FEATURE_OFFSETS / PACKED_COUNTS layout).
  5. Roll fresh feature_new_k, feature_new_r; encrypt segment + sponge_42.
  6. Write Prover.toml; nargo execute; bb write_vk; bb prove.
  7. Save fixture + generate ExtractSlotVerifier.sol.

Usage:
    python3 build_extract_slot_fixture.py [--seed alice0_slot3_to_carol] [--slot 3]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, poseidon2_hash_2, poseidon2_sponge_249,
    poseidon2_keystream_249, P,
)
from secret_inbox import G, GRUMPKIN_ORDER, ec_mul, is_on_curve, poseidon2_state  # noqa: E402

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "extract_slot"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
ALICE0_DIR = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "extract_slot"

NARGO = Path.home() / ".nargo" / "bin" / "nargo"
BB = Path.home() / ".bb" / "bb"

# Mirrors phase2/circuits/extract_slot/src/main.nr.
FEATURE_OFFSETS = [0, 42, 68, 94, 120, 146, 172, 214]
PACKED_COUNTS = [42, 26, 26, 26, 26, 26, 42, 38]
FEATURE_FIELDS = 42
SHADOW_FIELDS = 249


def deterministic_seed(seed: bytes, label: bytes) -> int:
    h = hashlib.sha256(b"OMP_ES_FIXTURE_v1:" + label + b":" + seed).digest()
    return (int.from_bytes(h, "big") % (GRUMPKIN_ORDER - 1)) + 1


def hex_field(v: int) -> str:
    return f'"{hex(v)}"'


def render_array(name: str, vs: list[int]) -> str:
    return f"{name} = [{', '.join(hex_field(v) for v in vs)}]"


def parse_pi_file(path: Path) -> list[int]:
    raw = path.read_bytes()
    return [int.from_bytes(raw[i*32:(i+1)*32], "big") for i in range(len(raw) // 32)]


def run(cmd: list[str], cwd: Path, timeout: int = 600):
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s")
    return p.stdout, elapsed


def poseidon2_keystream_42(k: int) -> list[int]:
    """Bit-exact with the circuit's keystream_42 (rate-3, 14 blocks)."""
    out = []
    for b in range(14):
        block = poseidon2_state(k, b, 0, 0)
        out.extend(block[:3])
    return out


def poseidon2_sponge_42(elems: list[int]) -> int:
    """Bit-exact with the circuit's sponge_42 (rate-3, 14 absorbs + sentinel)."""
    s = [0, 0, 0, 0]
    for b in range(14):
        s[0] = (s[0] + elems[b * 3]) % P
        s[1] = (s[1] + elems[b * 3 + 1]) % P
        s[2] = (s[2] + elems[b * 3 + 2]) % P
        s = list(poseidon2_state(*s))
    s[0] = (s[0] + 1) % P
    s = list(poseidon2_state(*s))
    return s[0]


def slice_feature(shadow: list[int], feature_type: int) -> list[int]:
    """Same slicing logic as the circuit's slice_feature."""
    off = FEATURE_OFFSETS[feature_type]
    out = [0] * FEATURE_FIELDS
    for j in range(FEATURE_FIELDS):
        idx = off + j
        if idx < SHADOW_FIELDS:
            out[j] = shadow[idx]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="alice0_slot3_to_carol")
    ap.add_argument("--chain-id", type=int, default=31337,
                    help="Target chain id for shadowId derivation")
    ap.add_argument("--slot", type=int, default=3,
                    help="Slot index 0..7 to extract (must be ORIGINAL on chain)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--recipient-sk", default=None,
                    help="Hex Grumpkin sk for the feature recipient (overrides deterministic)")
    ap.add_argument("--skip-prove", action="store_true")
    args = ap.parse_args()

    if not (0 <= args.slot < 8):
        sys.exit("--slot must be in [0, 7]")

    fixture_dir = Path(args.out) if args.out else FIXTURE_ROOT / args.seed
    fixture_dir.mkdir(parents=True, exist_ok=True)
    seed_bytes = args.seed.encode()

    print("=" * 68)
    print(f"extract_slot fixture generator (slot={args.slot})")
    print("=" * 68)
    print(f"  seed       : {args.seed}")
    print(f"  slot       : {args.slot}")
    print(f"  fixture dir: {fixture_dir}")
    print()

    # ---- 1-3. Load alice0 + decrypt + recover prev_k -----------------------
    print("[1] Load + decrypt alice0")
    alice_pi = parse_pi_file(ALICE0_DIR / "public_inputs")
    fix = json.loads((ALICE0_DIR / "fixture.json").read_text())
    alice_sk = int(fix["witness"]["recipient_sk"], 16)
    c1_x = alice_pi[12]; c1_y = alice_pi[13]
    alice_c2_bytes = (ALICE0_DIR / "c2.bin").read_bytes()
    alice_c2 = [int.from_bytes(alice_c2_bytes[i*32:(i+1)*32], "big") for i in range(249)]
    plaintext = decrypt_mint_envelope(recipient_sk=alice_sk, c1_x=c1_x, c1_y=c1_y, c2=alice_c2)
    shared = ec_mul((c1_x, c1_y), alice_sk)
    prev_k = poseidon2_hash_2(shared[0], shared[1])
    print(f"    prev_k = {hex(prev_k)[:18]}...")

    # ---- 4. Pick recipient (carol) ----------------------------------------
    print("\n[2] Derive carol recipient pk")
    if args.recipient_sk:
        carol_sk = int(args.recipient_sk, 16)
    else:
        carol_sk = deterministic_seed(seed_bytes, b"recipient_sk")
    carol_pk = ec_mul(G, carol_sk)
    next_pk_x, next_pk_y = carol_pk
    print(f"    carol pk.x: {hex(next_pk_x)[:18]}...")

    # ---- 5. Compute the canonical per-feature packed_padded[42] -----------
    # The circuit witnesses feature_payload directly; the canonical value is
    # what mint_pipeline.compute_face_state produces for the original face,
    # which is the SAME packed_padded the mint witness used per-slot.
    print(f"\n[3] Compute slot {args.slot}'s canonical per-feature packed_padded")
    from mint_pipeline import compute_face_state
    ALICE_FACE = ROOT / "examples" / "faces" / "alice0.png"
    state = compute_face_state(ALICE_FACE, color=int(alice_pi[10]))
    region = state.regions[args.slot]
    feature_payload = list(region.packed_padded)
    assert len(feature_payload) == 42
    k_for_type = PACKED_COUNTS[args.slot]
    for j in range(FEATURE_FIELDS):
        if j >= k_for_type:
            assert feature_payload[j] == 0, f"non-zero pad at j={j} for slot {args.slot}"
    print(f"    K_i = {k_for_type}; padding OK")
    print(f"    region.recolored ({region.name}) = {len(region.recolored)} bytes")

    print("\n[4] Encrypt feature_payload under feature_new_k")
    feature_new_r = deterministic_seed(seed_bytes, b"feature_new_r")
    feature_new_k = deterministic_seed(seed_bytes, b"feature_new_k_seed")  # fresh secret, not derived from shared
    new_ks = poseidon2_keystream_42(feature_new_k)
    feature_ct = [(feature_payload[i] + new_ks[i]) % P for i in range(FEATURE_FIELDS)]
    feature_ct_commit = poseidon2_sponge_42(feature_ct)

    c1_new = ec_mul(G, feature_new_r)
    c1_new_x, c1_new_y = c1_new
    shared_new = ec_mul(carol_pk, feature_new_r)
    k_mask = poseidon2_hash_2(shared_new[0], shared_new[1])
    c2_scalar = (feature_new_k + k_mask) % P

    # Sanity: carol can decrypt feature_ct.
    carol_shared = ec_mul((c1_new_x, c1_new_y), carol_sk)
    carol_k_mask = poseidon2_hash_2(carol_shared[0], carol_shared[1])
    recovered_k = (c2_scalar - carol_k_mask) % P
    assert recovered_k == feature_new_k
    carol_ks = poseidon2_keystream_42(recovered_k)
    carol_recovered = [(feature_ct[i] - carol_ks[i]) % P for i in range(FEATURE_FIELDS)]
    assert carol_recovered == feature_payload
    print("    OK: carol can decrypt feature_ct")

    # ---- 6. Compute shadow_id (chain-aware) ----------------------
    from chain_ids import shadow_id_for
    face_origin_id = alice_pi[8]
    shadow_id_full = shadow_id_for(face_origin_id, args.chain_id)
    shadow_id_field = shadow_id_full % P

    # ---- 7. Write Prover.toml ---------------------------------------------
    print("\n[5] Write Prover.toml")
    lines = [
        f'shadow_id              = "{hex(shadow_id_field)}"',
        f'slot_idx               = "{hex(args.slot)}"',
        f'feature_type_pub       = "{hex(args.slot)}"',
        f'prev_shadow_ct_commit  = "{hex(alice_pi[14])}"',
        f'next_pk_x              = "{hex(next_pk_x)}"',
        f'next_pk_y              = "{hex(next_pk_y)}"',
        f'c1_x                   = "{hex(c1_new_x)}"',
        f'c1_y                   = "{hex(c1_new_y)}"',
        f'c2_scalar              = "{hex(c2_scalar)}"',
        f'feature_ct_commit      = "{hex(feature_ct_commit)}"',
        render_array("shadow_plaintext", plaintext),
        f'shadow_prev_k          = "{hex(prev_k)}"',
        render_array("feature_payload", feature_payload),
        f'feature_new_k          = "{hex(feature_new_k)}"',
        f'feature_new_r          = "{hex(feature_new_r)}"',
    ]
    PROVER_TOML.write_text("\n".join(lines) + "\n")
    print(f"    {PROVER_TOML} ({PROVER_TOML.stat().st_size:,} bytes)")

    # ---- 8. nargo execute -------------------------------------------------
    print("\n[6] nargo execute")
    out, t_exec = run([NARGO, "execute", "--silence-warnings"], CIRCUIT_DIR, timeout=600)
    print(f"    {t_exec:.1f}s")

    if args.skip_prove:
        return 0

    # ---- 9. bb write_vk + prove ------------------------------------------
    print("\n[7] bb write_vk + prove")
    out, t_vk = run([BB, "write_vk", "-b", "target/extract_slot.json", "-o", "target", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
    print(f"    write_vk: {t_vk:.1f}s")

    proof_dir = CIRCUIT_DIR / "target" / "proof"
    if proof_dir.exists():
        for f in proof_dir.iterdir(): f.unlink()
    out, t_prove = run([BB, "prove", "-b", "target/extract_slot.json", "-w", "target/extract_slot.gz", "-o", "target/proof", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=900)
    print(f"    prove: {t_prove:.1f}s")

    out, t_ver = run([BB, "verify", "-k", "target/vk", "-p", "target/proof/proof", "-i", "target/proof/public_inputs", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
    print(f"    verify: {t_ver:.1f}s")

    # ---- 10. Save fixture + generate verifier ----------------------------
    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes    = (proof_dir / "public_inputs").read_bytes()
    feature_c2_bytes = b"".join(c.to_bytes(32, "big") for c in feature_ct)

    (fixture_dir / "proof").write_bytes(proof_bytes)
    (fixture_dir / "public_inputs").write_bytes(pi_bytes)
    (fixture_dir / "feature_c2.bin").write_bytes(feature_c2_bytes)

    fixture_meta = {
        "version": 1,
        "seed": args.seed,
        "slot": args.slot,
        "feature_type": args.slot,
        "shadow_id": hex(shadow_id_full),
        "shadow_id_field": hex(shadow_id_field),
        "carol_sk": hex(carol_sk),
        "carol_pk_x": hex(next_pk_x),
        "carol_pk_y": hex(next_pk_y),
        "feature_ct_commit": hex(feature_ct_commit),
        "c1_new_x": hex(c1_new_x),
        "c1_new_y": hex(c1_new_y),
        "c2_scalar": hex(c2_scalar),
        "feature_new_r": hex(feature_new_r),
        "feature_new_k": hex(feature_new_k),
        "n_pi": 10,
        "feature_c2_bytes": len(feature_c2_bytes),
        "timings_seconds": {
            "nargo_execute": t_exec, "bb_write_vk": t_vk, "bb_prove": t_prove, "bb_verify": t_ver,
        },
    }
    (fixture_dir / "fixture.json").write_text(json.dumps(fixture_meta, indent=2))
    print(f"    saved fixture to {fixture_dir}/")

    # ---- 11. Generate Verifier.sol ---------------------------------------
    print("\n[8] bb write_solidity_verifier")
    verifier_out = CIRCUIT_DIR / "target" / "ExtractSlotVerifier.sol"
    out, _ = run([BB, "write_solidity_verifier", "-k", "target/vk", "-o", str(verifier_out)], CIRCUIT_DIR, timeout=300)
    forge_src = ROOT / "contracts" / "src" / "ExtractSlotVerifier.sol"
    text = verifier_out.read_text()
    text = text.replace("contract HonkVerifier", "contract ExtractSlotVerifier")
    forge_src.write_text(text)
    print(f"    wrote {forge_src}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
