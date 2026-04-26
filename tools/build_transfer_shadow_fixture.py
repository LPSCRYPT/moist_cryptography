#!/usr/bin/env python3
"""Generate a transfer_shadow fixture: alice0's shadow re-encrypted to bob.

Pipeline:
  1. Load alice0 mint PI + c2 + recipient_sk from
     `phase2/forge/test/fixtures/mint_shadow/alice0/`.
  2. Decrypt alice0's c2 -> recover the 249-Field plaintext.
  3. Recover alice's prev_k = Poseidon2(shared.x, shared.y) from shared =
     c1 * recipient_sk_alice. (This is the keystream seed the circuit binds.)
  4. Pick bob (deterministic recipient_sk derived from `--seed`).
  5. Roll fresh new_k, new_r; generate ECIES envelope (c1_new, c2_new, ct_commit_new).
  6. Write Prover.toml to `circuits/transfer_shadow/`.
  7. nargo execute -> witness.
  8. bb prove + bb write_solidity_verifier.
  9. Save proof + public_inputs + new_c2.bin to fixture dir.
 10. (Optional) Drop a generated TransferShadowVerifier.sol into forge/src/.

Usage:
    python3 build_transfer_shadow_fixture.py [--seed alice0_to_bob]
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

from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, encrypt_mint_envelope,
    poseidon2_hash_2, poseidon2_sponge_249, poseidon2_keystream_249,
    P, CT_FIELDS,
)
from secret_inbox import G, GRUMPKIN_ORDER, ec_mul, is_on_curve  # noqa: E402

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "transfer_shadow"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
ALICE0_DIR = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "transfer_shadow"

NARGO = Path.home() / ".nargo" / "bin" / "nargo"
BB = Path.home() / ".bb" / "bb"


def deterministic_seed(seed: bytes, label: bytes) -> int:
    h = hashlib.sha256(b"OMP_TS_FIXTURE_v1:" + label + b":" + seed).digest()
    return (int.from_bytes(h, "big") % (GRUMPKIN_ORDER - 1)) + 1


def hex_field(v: int) -> str:
    return f'"{hex(v)}"'


def render_array(name: str, vs: list[int]) -> str:
    return f"{name} = [{', '.join(hex_field(v) for v in vs)}]"


def parse_pi_file(path: Path) -> list[int]:
    raw = path.read_bytes()
    assert len(raw) % 32 == 0, f"PI file not 32-aligned: {len(raw)}"
    return [int.from_bytes(raw[i*32:(i+1)*32], "big") for i in range(len(raw) // 32)]


def run(cmd: list[str], cwd: Path, timeout: int = 600):
    started = time.time()
    p = subprocess.run(
        [str(c) for c in cmd], cwd=str(cwd),
        capture_output=True, text=True, timeout=timeout,
    )
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s: {' '.join(str(c) for c in cmd)}")
    return p.stdout, elapsed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="alice0_to_bob")
    ap.add_argument("--chain-id", type=int, default=31337,
                    help="Target chain id for shadowId derivation (anvil=31337, base sepolia=84532)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--recipient-sk", default=None,
                    help="Hex Grumpkin sk for the recipient (overrides deterministic derivation)")
    ap.add_argument("--skip-prove", action="store_true",
                    help="Stop after writing Prover.toml + nargo execute (no bb prove)")
    args = ap.parse_args()

    fixture_dir = Path(args.out) if args.out else FIXTURE_ROOT / args.seed
    fixture_dir.mkdir(parents=True, exist_ok=True)
    seed_bytes = args.seed.encode()

    print("=" * 68)
    print("transfer_shadow fixture generator")
    print("=" * 68)
    print(f"  seed       : {args.seed}")
    print(f"  fixture dir: {fixture_dir}")
    print()

    # ---- 1. Load alice0 mint state -----------------------------------------
    print("[1] Load alice0 mint PI + c2 + sk")
    alice_pi = parse_pi_file(ALICE0_DIR / "public_inputs")
    if len(alice_pi) != 17:
        sys.exit(f"alice0 PI has {len(alice_pi)} fields, expected 17")
    alice_c2_bytes = (ALICE0_DIR / "c2.bin").read_bytes()
    if len(alice_c2_bytes) != 249 * 32:
        sys.exit(f"alice0 c2 length {len(alice_c2_bytes)}, expected {249*32}")
    alice_c2 = [int.from_bytes(alice_c2_bytes[i*32:(i+1)*32], "big") for i in range(249)]

    fix = json.loads((ALICE0_DIR / "fixture.json").read_text())
    alice_sk = int(fix["witness"]["recipient_sk"], 16)
    alice_pk_x = int(fix["witness"]["recipient_pk_x"], 16)
    alice_pk_y = int(fix["witness"]["recipient_pk_y"], 16)
    print(f"    alice sk  : {hex(alice_sk)[:18]}...")
    print(f"    alice pk.x: {hex(alice_pk_x)[:18]}...")

    # ---- 2. Decrypt alice0's c2 -> plaintext -------------------------------
    print("\n[2] Decrypt alice0's c2 -> 249-Field plaintext")
    c1_x = alice_pi[12]
    c1_y = alice_pi[13]
    plaintext = decrypt_mint_envelope(
        recipient_sk=alice_sk, c1_x=c1_x, c1_y=c1_y, c2=alice_c2,
    )
    assert len(plaintext) == 249

    # ---- 3. Recover alice's prev_k -----------------------------------------
    # prev_k = Poseidon2(shared.x, shared.y) where shared = c1 * alice_sk.
    print("\n[3] Recover prev_k = Poseidon2(shared.x, shared.y)")
    shared = ec_mul((c1_x, c1_y), alice_sk)
    if shared is None:
        sys.exit("shared point is identity")
    prev_k = poseidon2_hash_2(shared[0], shared[1])
    print(f"    prev_k    : {hex(prev_k)[:18]}...")

    # Sanity: re-encrypt under prev_k -> matches alice0's c2 + ct_commit.
    ks = poseidon2_keystream_249(prev_k)
    re_c2 = [(plaintext[i] + ks[i]) % P for i in range(249)]
    if re_c2 != alice_c2:
        sys.exit("prev_k re-encryption mismatch (decrypt path bug)")
    re_commit = poseidon2_sponge_249(re_c2)
    if re_commit != alice_pi[14]:
        sys.exit(f"ct_commit mismatch: {re_commit} vs PI[14]={alice_pi[14]}")
    print("    OK: prev_k regenerates alice0's c2 + ct_commit")

    # ---- 4. Pick bob -------------------------------------------------------
    print("\n[4] Derive bob recipient pk")
    if args.recipient_sk:
        bob_sk = int(args.recipient_sk, 16)
    else:
        bob_sk = deterministic_seed(seed_bytes, b"recipient_sk")
    bob_pk = ec_mul(G, bob_sk)
    assert bob_pk is not None and is_on_curve(*bob_pk)
    next_pk_x, next_pk_y = bob_pk
    print(f"    bob sk  : {hex(bob_sk)[:18]}...")
    print(f"    bob pk.x: {hex(next_pk_x)[:18]}...")

    # ---- 5. New ECIES envelope under (next_pk, new_r, new_k) --------------
    print("\n[5] Generate new ECIES envelope")
    new_r = deterministic_seed(seed_bytes, b"new_r")
    new_k_seed = deterministic_seed(seed_bytes, b"new_k_seed")
    # The circuit's new_k is the keystream-seed scalar. The mint convention
    # uses Poseidon2(shared.x, shared.y) as the seed; we reproduce that here so
    # the recipient can decrypt with their sk + the published c1.
    shared_new = ec_mul(bob_pk, new_r)
    assert shared_new is not None
    new_k = poseidon2_hash_2(shared_new[0], shared_new[1])

    new_ks = poseidon2_keystream_249(new_k)
    new_c2 = [(plaintext[i] + new_ks[i]) % P for i in range(249)]
    new_ct_commit = poseidon2_sponge_249(new_c2)

    c1_new = ec_mul(G, new_r)
    assert c1_new is not None
    c1_new_x, c1_new_y = c1_new

    # c2_scalar = new_k + Poseidon2(shared.x, shared.y) ... but we already set
    # new_k = Poseidon2(shared.x, shared.y), so c2_scalar = 2 * new_k.
    # Wait -- the circuit computes:
    #   shared = next_pk * new_r
    #   k_mask = Poseidon2(shared.x, shared.y)
    #   c2_scalar == new_k + k_mask
    # If new_k is supposed to be a fresh secret unrelated to k_mask, then the
    # publishing "c2_scalar" is the way the recipient recovers new_k via
    #   new_k = c2_scalar - k_mask = c2_scalar - Poseidon2(shared.x, shared.y)
    # Then they apply new_k as the keystream seed.
    #
    # So new_k must be a FRESH random secret, NOT equal to k_mask. Let's pick
    # one independently.
    new_k = new_k_seed  # fresh random keystream seed
    new_ks = poseidon2_keystream_249(new_k)
    new_c2 = [(plaintext[i] + new_ks[i]) % P for i in range(249)]
    new_ct_commit = poseidon2_sponge_249(new_c2)
    k_mask = poseidon2_hash_2(shared_new[0], shared_new[1])
    c2_scalar = (new_k + k_mask) % P

    # Sanity: recipient (bob) should be able to decrypt new_c2 with bob_sk.
    bob_shared = ec_mul((c1_new_x, c1_new_y), bob_sk)
    assert bob_shared == shared_new, "shared mismatch"
    bob_k_mask = poseidon2_hash_2(bob_shared[0], bob_shared[1])
    recovered_k = (c2_scalar - bob_k_mask) % P
    assert recovered_k == new_k, "k recovery mismatch"
    bob_ks = poseidon2_keystream_249(recovered_k)
    bob_plain = [(new_c2[i] - bob_ks[i]) % P for i in range(249)]
    assert bob_plain == plaintext, "decrypt round-trip mismatch"
    print("    OK: bob can decrypt new_c2 to recover plaintext")

    # ---- 6. Write Prover.toml ---------------------------------------------
    print("\n[6] Write Prover.toml")
    # shadow_id is just bound to PI; for fixture purposes, derive from alice's
    # faceOriginId via the same DOMAIN_SHADOW the contract uses.
    domain = int.from_bytes(
        hashlib.sha3_256(b"\xff" * 0).digest(),  # placeholder; real domain in contract
        "big",
    )
    face_origin_id = alice_pi[8]

    # Compute shadowId matching ShadowToken.shadowIdOf for the target chain.
    # The on-chain derivation includes block.chainid so the proof binds to a
    # specific chain. Default 31337 (anvil/forge); override for Sepolia (84532).
    from chain_ids import shadow_id_for
    shadow_id = shadow_id_for(face_origin_id, args.chain_id)
    # NOTE: shadow_id might exceed bn254 field modulus; circuit treats it as a
    # Field, which auto-reduces. The contract uses uint256 directly. Both
    # representations are fine because circuit doesn't use shadow_id for
    # arithmetic (`let _ = shadow_id;`).
    shadow_id_field = shadow_id % P

    lines = [
        f'shadow_id      = "{hex(shadow_id_field)}"',
        f'next_pk_x      = "{hex(next_pk_x)}"',
        f'next_pk_y      = "{hex(next_pk_y)}"',
        f'c1_x           = "{hex(c1_new_x)}"',
        f'c1_y           = "{hex(c1_new_y)}"',
        f'c2_scalar      = "{hex(c2_scalar)}"',
        f'new_ct_commit  = "{hex(new_ct_commit)}"',
        f'prev_ct_commit = "{hex(alice_pi[14])}"',
        render_array("plaintext", plaintext),
        f'prev_k         = "{hex(prev_k)}"',
        f'new_k          = "{hex(new_k)}"',
        f'new_r          = "{hex(new_r)}"',
    ]
    PROVER_TOML.write_text("\n".join(lines) + "\n")
    print(f"    {PROVER_TOML} ({PROVER_TOML.stat().st_size:,} bytes)")

    # ---- 7. nargo execute -------------------------------------------------
    print("\n[7] nargo execute")
    if not NARGO.exists():
        sys.exit(f"nargo not found at {NARGO}")
    out, t_exec = run([NARGO, "execute", "--silence-warnings"], CIRCUIT_DIR, timeout=600)
    print(f"    nargo execute: {t_exec:.1f}s")

    if args.skip_prove:
        print("\n[skipped] bb prove")
        return 0

    # ---- 8. bb write_vk + bb prove ----------------------------------------
    print("\n[8a] bb write_vk")
    if not BB.exists():
        sys.exit(f"bb not found at {BB}")
    out, t_vk = run([
        BB, "write_vk",
        "-b", "target/transfer_shadow.json",
        "-o", "target",
        "--verifier_target", "evm",
    ], CIRCUIT_DIR, timeout=300)
    print(f"    bb write_vk: {t_vk:.1f}s")

    print("\n[8b] bb prove")
    proof_dir = CIRCUIT_DIR / "target" / "proof"
    if proof_dir.exists():
        for f in proof_dir.iterdir():
            f.unlink()
    out, t_prove = run([
        BB, "prove",
        "-b", "target/transfer_shadow.json",
        "-w", "target/transfer_shadow.gz",
        "-o", "target/proof",
        "--verifier_target", "evm",
    ], CIRCUIT_DIR, timeout=900)
    print(f"    bb prove: {t_prove:.1f}s")

    # ---- 9. bb verify -----------------------------------------------------
    print("\n[9] bb verify")
    out, t_ver = run([
        BB, "verify",
        "-k", "target/vk",
        "-p", "target/proof/proof",
        "-i", "target/proof/public_inputs",
        "--verifier_target", "evm",
    ], CIRCUIT_DIR, timeout=300)
    print(f"    bb verify: {t_ver:.1f}s")

    # ---- 10. Save fixture -------------------------------------------------
    print("\n[10] Save fixture")
    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes    = (proof_dir / "public_inputs").read_bytes()
    new_c2_bytes = b"".join(c.to_bytes(32, "big") for c in new_c2)

    (fixture_dir / "proof").write_bytes(proof_bytes)
    (fixture_dir / "public_inputs").write_bytes(pi_bytes)
    (fixture_dir / "new_c2.bin").write_bytes(new_c2_bytes)

    fixture_meta = {
        "version": 1,
        "seed": args.seed,
        "shadow_id": hex(shadow_id),
        "shadow_id_field": hex(shadow_id_field),
        "face_origin_id": hex(face_origin_id),
        "alice_sk": hex(alice_sk),
        "bob_sk": hex(bob_sk),
        "bob_pk_x": hex(next_pk_x),
        "bob_pk_y": hex(next_pk_y),
        "prev_ct_commit": hex(alice_pi[14]),
        "new_ct_commit": hex(new_ct_commit),
        "c1_new_x": hex(c1_new_x),
        "c1_new_y": hex(c1_new_y),
        "c2_scalar": hex(c2_scalar),
        "new_r": hex(new_r),
        "new_k": hex(new_k),
        "n_pi": 8,
        "timings_seconds": {
            "nargo_execute": t_exec,
            "bb_prove": t_prove,
            "bb_verify": t_ver,
        },
    }
    (fixture_dir / "fixture.json").write_text(json.dumps(fixture_meta, indent=2))
    print(f"    saved {fixture_dir}/{{proof,public_inputs,new_c2.bin,fixture.json}}")

    # ---- 11. Generate Verifier.sol ---------------------------------------
    print("\n[11] bb write_solidity_verifier")
    verifier_out = CIRCUIT_DIR / "target" / "TransferShadowVerifier.sol"
    out, _ = run([
        BB, "write_solidity_verifier",
        "-k", "target/vk",
        "-o", str(verifier_out),
    ], CIRCUIT_DIR, timeout=300)

    # Drop into forge/src
    forge_src = ROOT / "contracts" / "src" / "TransferShadowVerifier.sol"
    text = verifier_out.read_text()
    text = text.replace("contract HonkVerifier", "contract TransferShadowVerifier")
    forge_src.write_text(text)
    print(f"    wrote {forge_src}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
