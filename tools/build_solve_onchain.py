#!/usr/bin/env python3
"""Generate a solve_shadow_v2 fixture chained against the live state of
shadow A on Base Sepolia.

Differences from build_solve_shadow_v2_fixture.py:
  - shadow_id, owner keys, per-slot plaintexts, ECIES, chain_tips all
    derive from the atomic_mint seed (not a fresh seed).
  - Slot occupancy reflects the live chain state: slots that have been
    extracted are EMPTY; the rest are OCCUPIED at mint state.
  - z_perm is taken from a CLI-supplied permutation (must match the
    setZIndex op's perm so that PI[3] z_index_commit equals the chain).

Inputs:
    --mint-fixture
    --extracted-slots  comma-separated indices that are EMPTY post-extract
                        (default: "0" -- assumes slot 0 was extracted)
    --slot-overrides   JSON mapping {slot_idx: hex_lsh} for slots whose
                        post-mint state has been mutated. Their state
                        WILL NOT be reconstructible from seed, so this
                        builder requires that overridden slots are ALSO
                        in --extracted-slots (anything mutated must be
                        extracted before solve since the witness can't
                        recover the post-mutate plaintext from the mint
                        seed alone).
    --z-perm           JSON list of 16 ints (must equal the perm used
                        when setZIndexCommit was broadcast)
    --out-seed
"""
from __future__ import annotations

import atexit
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

from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # noqa: E402
from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS,
    sponge_39, sponge_16, sponge_palette_salt,
    poseidon2_hash_2,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2,
    chain_step, mint_chain_step, live_state_hash,
    fhex, bx32,
)

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "solve_shadow_v2"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_solve"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def _delete_if_exists(path: Path) -> None:
    try:
        path.unlink()
        print(f"[deleted transient] {path}")
    except FileNotFoundError:
        pass


def deterministic_int_mint(seed: bytes, label: bytes, mod: int) -> int:
    h = hashlib.sha256(b"OMP_ATOMIC_MINT_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def pack_perm_base16(perm: list[int]) -> int:
    """16 nibbles, base-16 little-endian."""
    acc = 0
    mul = 1
    for v in perm:
        acc += v * mul
        mul *= 16
    return acc


def render_array(name: str, vals: list[int]) -> str:
    return f"{name} = [{', '.join(fhex(v) for v in vals)}]"


def render_2d(name: str, rows: list[list[int]]) -> str:
    inner = []
    for r in rows:
        inner.append(f"  [{', '.join(fhex(v) for v in r)}]")
    return f"{name} = [\n" + ",\n".join(inner) + "\n]"


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


def reconstruct_mint_slot(seed: bytes, image_commit: int, slot_idx: int,
                          owner_pk: tuple[int, int]) -> dict:
    """Recompute slot's mint witness state for the SOLVE circuit's
    per-slot inputs. Must byte-equal what the live mint produced."""
    pose = pack_pose(x=2 + slot_idx * 2, y=4 + (slot_idx % 8))
    w_dim = 6 + (slot_idx % 4)
    h_dim = 6 + ((slot_idx + 1) % 4)
    indices = [(j * 7 + slot_idx + 3) & 0xF for j in range(w_dim * h_dim)]
    plaintext = encode_plaintext_v2(pose, w_dim, h_dim, indices)

    r_i = deterministic_int_mint(seed, f"r_{slot_idx}".encode(), GRUMPKIN_ORDER - 1) + 1
    c1, c2, k = ecies_encrypt_v2(plaintext, owner_pk, r_i)

    state_commit = sponge_39(plaintext)
    ct_commit = sponge_39(c2)
    origin_face_id = poseidon2_hash_2(image_commit, slot_idx)
    chain_tip = mint_chain_step(origin_face_id, owner_pk[0], owner_pk[1])
    lsh = live_state_hash(state_commit, ct_commit, c1[0], c1[1], 0, chain_tip)

    return {
        "plaintext": plaintext,
        "c1_x": c1[0],
        "c1_y": c1[1],
        "ct_commit": ct_commit,
        "state_commit": state_commit,
        "k": k,
        "chain_tip": chain_tip,
        "mutation_count": 0,
        "lsh": lsh,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mint-fixture", required=True)
    ap.add_argument("--seed", default="atomic_mint_demo",
                    help="Drives r_i (envelope nonce) + per-slot palette derivation. "
                         "Must equal the seed used at mint time.")
    ap.add_argument("--owner-seed", default=None,
                    help="Drives owner_sk; defaults to --seed. Pass the SAME owner_seed "
                         "that was passed to build_atomic_mint_fixture for this shadow. "
                         "Without this flag, the witness's owner_pk won't match the chain's "
                         "stored ecdhPub and the proof reverts InvalidProof.")
    ap.add_argument("--extracted-slots", default="0",
                    help="comma-separated slot indices that are EMPTY post-extract")
    ap.add_argument("--z-perm", required=True,
                    help="JSON list of 16 ints (must match setZIndex op's perm)")
    ap.add_argument("--out-seed", required=True)
    args = ap.parse_args()

    mint_fix = Path(args.mint_fixture)
    with open(mint_fix / "meta.json") as f:
        mint_meta = json.load(f)
    image_commit = int(mint_meta["image_commit"], 16)
    shadow_id = image_commit % P
    seed = args.seed.encode()
    owner_seed = (args.owner_seed or args.seed).encode()

    extracted = set()
    if args.extracted_slots.strip():
        extracted = set(int(x) for x in args.extracted_slots.split(",") if x.strip())
    print(f"[onchain_solve] seed={args.seed!r} shadow_id={hex(shadow_id)[:18]}...")
    print(f"  extracted_slots = {sorted(extracted)}")

    z_perm = json.loads(args.z_perm)
    if not (isinstance(z_perm, list) and len(z_perm) == 16
            and sorted(z_perm) == list(range(16))):
        sys.exit(f"--z-perm must be a permutation of [0..15], got {z_perm}")
    z_perm_packed = pack_perm_base16(z_perm)
    z_index_commit = sponge_16(z_perm)
    print(f"  z_perm = {z_perm}")
    print(f"  z_perm_packed = {hex(z_perm_packed)[:18]}...")
    print(f"  z_index_commit = {hex(z_index_commit)[:18]}...")

    # ---- keygen + per-slot reconstruction ----
    owner_sk = deterministic_int_mint(owner_seed, b"owner_sk", GRUMPKIN_ORDER - 1) + 1
    owner_pk = ec_mul(G, owner_sk)
    assert owner_pk is not None
    owner_pk_x, owner_pk_y = owner_pk

    is_occupied = [0] * 16
    plaintexts: list[list[int]] = [[0] * PLAINTEXT_FIELDS for _ in range(16)]
    prev_ct_commit = [0] * 16
    # Empty slots still pass through Noir MSM setup; seed them with a valid
    # Grumpkin point while keeping all public/committed empty-slot data zero.
    prev_c1_x = [G[0]] * 16
    prev_c1_y = [G[1]] * 16
    prev_mutation_count = [0] * 16
    prev_chain_tip = [0] * 16
    owner_k_arr = [0] * 16
    prev_lsh_arr = [0] * 16
    state_commits = [0] * 16

    occupied_slots = [i for i in range(8) if i not in extracted]  # mint occupied 0..7
    print(f"[1/4] occupied slots after extract = {occupied_slots}")

    for i in occupied_slots:
        s = reconstruct_mint_slot(seed, image_commit, i, owner_pk)
        is_occupied[i] = 1
        plaintexts[i] = s["plaintext"]
        prev_ct_commit[i] = s["ct_commit"]
        prev_c1_x[i] = s["c1_x"]
        prev_c1_y[i] = s["c1_y"]
        prev_mutation_count[i] = 0
        prev_chain_tip[i] = s["chain_tip"]
        owner_k_arr[i] = s["k"]
        prev_lsh_arr[i] = s["lsh"]
        state_commits[i] = s["state_commit"]
    assert all(prev_c1_x[i] != 0 or prev_c1_y[i] != 0 for i in range(16)), "prev_c1 placeholders must be on-curve"

    # Per-slot palette + salt: deterministic from same seed used at mint
    # (reveal-update spec; ShadowToken.solve verifies sponge_palette_salt
    # over (palette[16], salt) opens the chain-stored paletteCommit).
    palettes: list[list[int]] = [[0] * 16 for _ in range(16)]
    palette_salts = [0] * 16
    palette_commits = [0] * 16
    for i in occupied_slots:
        pal = []
        for j in range(16):
            d = hashlib.sha256(seed + f":palette:{i}:{j}".encode()).digest()
            pal.append(int.from_bytes(d[:3], "big") & 0xFFFFFF)
        salt = deterministic_int_mint(seed, f"palette_salt_{i}".encode(), P)
        palettes[i] = pal
        palette_salts[i] = salt
        palette_commits[i] = sponge_palette_salt(pal, salt)

    state_commits_root = sponge_16(state_commits)
    lsh_root = sponge_16(prev_lsh_arr)
    print(f"  state_commits_root = {hex(state_commits_root)[:18]}...")
    print(f"  lsh_root           = {hex(lsh_root)[:18]}...")

    # Sanity: lsh_root should match what _sponge16Manifest would compute
    # on chain after extract. Not asserted here (would require a chain
    # read), but documented in meta.json.

    # ---- write Prover.toml ----
    print(f"[2/4] write Prover.toml")
    PROVER_TOML.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"shadow_id = {fhex(shadow_id)}",
        f"state_commits_root = {fhex(state_commits_root)}",
        f"z_perm_packed_pi = {fhex(z_perm_packed)}",
        f"z_index_commit = {fhex(z_index_commit)}",
        f"lsh_root = {fhex(lsh_root)}",
        f"owner_pk_x = {fhex(owner_pk_x)}",
        f"owner_pk_y = {fhex(owner_pk_y)}",
        render_array("is_occupied", is_occupied),
        render_2d("plaintexts", plaintexts),
        render_array("prev_ct_commit", prev_ct_commit),
        render_array("prev_c1_x", prev_c1_x),
        render_array("prev_c1_y", prev_c1_y),
        render_array("prev_mutation_count", prev_mutation_count),
        render_array("prev_chain_tip", prev_chain_tip),
        render_array("owner_k", owner_k_arr),
        render_array("prev_lsh", prev_lsh_arr),
        render_array("z_perm", z_perm),
        f"owner_sk = {fhex(owner_sk)}",
    ]
    PROVER_TOML.write_text("\n".join(lines) + "\n")
    os.chmod(PROVER_TOML, 0o600)
    atexit.register(_delete_if_exists, PROVER_TOML)

    # ---- prove ----
    print(f"[3/4] nargo execute + bb prove")
    target_dir = CIRCUIT_DIR / "target"
    run([NARGO, "execute"], CIRCUIT_DIR, timeout=900)
    run([BB, "write_vk", "-b", str(target_dir / "solve_shadow_v2.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "solve_shadow_v2.json"),
         "-w", str(target_dir / "solve_shadow_v2.gz"),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=1800)
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=300)

    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes = (proof_dir / "public_inputs").read_bytes()
    print(f"  proof  = {len(proof_bytes)} B")
    print(f"  pi     = {len(pi_bytes)} B  ({len(pi_bytes)//32} fields)")

    # ---- write fixture ----
    print(f"[4/4] write fixture")
    fix_dir = FIXTURE_ROOT / args.out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof.bin").write_bytes(proof_bytes)
    (fix_dir / "public_inputs.bin").write_bytes(pi_bytes)

    # plaintexts as 39-field bytes32 arrays for forge consumption
    plaintexts_json = {
        "plaintexts": [
            [bx32(v) for v in plaintexts[i]] for i in range(16)
        ],
    }
    (fix_dir / "plaintexts.json").write_text(json.dumps(plaintexts_json, indent=2))

    meta = {
        "kind": "onchain_solve",
        "seed": args.seed,
        "shadow_id": bx32(shadow_id),
        "extracted_slots": sorted(extracted),
        "occupied_slots": occupied_slots,
        "state_commits_root": bx32(state_commits_root),
        "lsh_root": bx32(lsh_root),
        "z_perm": z_perm,
        "z_perm_packed": bx32(z_perm_packed),
        "z_index_commit": bx32(z_index_commit),
        "owner_pk_x": bx32(owner_pk_x),
        "owner_pk_y": bx32(owner_pk_y),
        "state_commits": [bx32(v) for v in state_commits],
        "prev_lsh_array": [bx32(v) for v in prev_lsh_arr],
        "palettes": [[bx32(v) for v in palettes[i]] for i in range(16)],
        "palette_salts": [bx32(v) for v in palette_salts],
        "palette_commits": [bx32(v) for v in palette_commits],
        "prev_lsh_array": [bx32(v) for v in prev_lsh_arr],
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")


if __name__ == "__main__":
    main()
