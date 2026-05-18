#!/usr/bin/env python3
"""Generate a mutate_slot + shadow_t10 fixture chained against the
already-deployed live state of shadow A.

This is the chained-fixture analogue of
`build_atomic_mutate_fixture.py`. The standalone builder generates a
self-contained fixture with synthetic mint state (it sets all OTHER
slots' lsh to 0 in the post-mutate manifest). For broadcasting against
the live deployment, the OTHER 7 slots already have non-zero lsh on
chain (from the mint), so the T10 proof must bind to those values.

Required deterministic inputs (no JSON-RPC needed; everything is
recomputable from the original mint seed + chain id):

    seed           atomic_mint_demo  (the mint fixture's seed)
    image_commit   from the alice0 face_disc fixture
    shadow_id      = image_commit (since shadow_id = imageCommit % FR_MOD
                                    and image_commit < FR_MOD)
    chain_id       84532 (Base Sepolia) -- needed for feature_id keccak
    slot_idx       0..7  (which slot to mutate; default 0)

Per-slot derivation:

    Mint state (slot i):
        pose, w, h, indices  -- from build_atomic_mint_fixture per-slot
                                synthesis (deterministic from i)
        owner_sk             -- deterministic_int("OMP_ATOMIC_MINT_FIXTURE_v1:owner_sk", seed)
        owner_pk             -- ec_mul(G, owner_sk)
        plaintext            -- encode_plaintext_v2(pose, w, h, indices)
        r_i                  -- deterministic_int("OMP_ATOMIC_MINT_FIXTURE_v1:r_{i}", seed)
        (c1, c2, k)          -- ecies_encrypt_v2(plaintext, owner_pk, r_i)
        state_commit         -- sponge_39(plaintext)
        ct_commit            -- sponge_39(c2)
        origin_face_id       -- poseidon2_hash_2(image_commit, i)
        palette_commit       -- deterministic_int("OMP_ATOMIC_MINT_FIXTURE_v1:palette_{i}", seed)
        chain_tip            -- mint_chain_step(origin_face_id, pk_x, pk_y)
        lsh_init             -- sponge_6(state_commit, ct_commit, c1.x, c1.y, 0, chain_tip)
        feature_id           -- keccak256(DOMAIN_FEATURE, chain_id, shadow_id,
                                          slot_idx, mint_counter) % FR_MOD
                                (mint_counter = slot_idx + 1, since 8 carriers
                                 are minted in sequence at indices 0..7)
        type_idx             -- slot_idx  (per ShadowToken._mintOneAtom)

    Mutation (slot i, count 0 -> 1):
        new_pose, new_w, new_h, new_indices  -- distinct, deterministic from
                                                 (seed, slot_idx) via a
                                                 separate label so the
                                                 plaintext changes
        new_r                -- deterministic_int("OMP_ONCHAIN_MUTATE_v1:new_r:{i}", seed)
        (new_c1, new_c2, new_k) -- ecies_encrypt_v2(new_pt, owner_pk, new_r)
        new_state_commit     -- sponge_39(new_pt)
        new_ct_commit        -- sponge_39(new_c2)
        new_count            -- 1
        new_chain_tip        -- chain_step(prev_chain_tip=lsh_init's chain_tip,
                                           new_state_commit, new_ct_commit,
                                           new_count, origin_face_id, slot_idx)
        new_lsh              -- sponge_6(new_state_commit, new_ct_commit,
                                         new_c1.x, new_c1.y, new_count, new_chain_tip)

T10 (post-mutate manifest):
    z_commit         -- 0  (unchanged)
    lsh_array[i]     -- new_lsh
    lsh_array[j]     -- mint's lsh_init[j] for j in 0..7, j != i
    lsh_array[8..15] -- 0 (slots 8..15 are EMPTY)

Output:
    contracts/test/fixtures/onchain_mutate/<seed>/proof_mut.bin
    contracts/test/fixtures/onchain_mutate/<seed>/public_inputs_mut.bin
    contracts/test/fixtures/onchain_mutate/<seed>/proof_t10.bin
    contracts/test/fixtures/onchain_mutate/<seed>/public_inputs_t10.bin
    contracts/test/fixtures/onchain_mutate/<seed>/c2.bin   (39-field new c2)
    contracts/test/fixtures/onchain_mutate/<seed>/meta.json

Usage:
    python3 build_mutate_slot_onchain.py \
        --mint-fixture contracts/test/fixtures/atomic_mint/atomic_mint_demo \
        --slot 0 \
        --chain-id 84532 \
        [--out-seed onchain_mutate_demo]

Wall-clock on M3: ~90s (mutate proof ~60s, T10 proof ~30s).
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from eth_utils import keccak  # type: ignore
from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # noqa: E402
from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS, CANVAS_W, CANVAS_H,
    sponge_39, sponge_6, keystream_39,
    poseidon2_hash_2,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2, ecies_decrypt_v2,
    chain_step, mint_chain_step, live_state_hash,
    fhex, bx32,
)
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402

ROOT = REPO.parent
MUT_DIR = ROOT / "circuits" / "mutate_slot"
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_mutate"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))

DOMAIN_FEATURE = keccak(text="OMP_FEATURE_NFT_v2")
FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def deterministic_int_mint(seed: bytes, label: bytes, mod: int) -> int:
    """Mirror build_atomic_mint_fixture's prefix exactly so plaintexts/r/palette
    match what the live mint produced."""
    h = hashlib.sha256(b"OMP_ATOMIC_MINT_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def deterministic_int_mutate(seed: bytes, label: bytes, mod: int) -> int:
    """Distinct prefix so the mutation's new_r and new_pt are independent of
    any seed-derived value used at mint time (avoids accidental collision)."""
    h = hashlib.sha256(b"OMP_ONCHAIN_MUTATE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def derive_feature_id(chain_id: int, shadow_id: int, slot_idx: int,
                      mint_counter: int) -> int:
    """Mirror FeatureNFT.mintAtShadowMint:
       featureId = keccak256(DOMAIN, chainId, hostShadow, hostSlot, mintCounter) % FR_MOD"""
    enc = (DOMAIN_FEATURE
           + chain_id.to_bytes(32, "big")
           + shadow_id.to_bytes(32, "big")
           + slot_idx.to_bytes(32, "big")
           + mint_counter.to_bytes(32, "big"))
    return int.from_bytes(keccak(enc), "big") % FR_MOD


def reconstruct_mint_slot_state(seed: bytes, image_commit: int, slot_idx: int,
                                chain_id: int,
                                owner_seed: bytes | None = None,
                                mint_counter_base: int = 0,
                                palette_commit: int | None = None) -> dict:
    """Recompute slot_idx's full mint state byte-for-byte from seed.

    `seed` drives r_i (envelope nonce) and palette_commit. `owner_seed`
    drives owner_sk; defaults to `seed`. The split mirrors
    build_atomic_mint_fixture.py::build_witness, where a single owner key
    can mint multiple shadows under different fixture seeds.

    Returns: dict with keys for plaintext, c1, c2, k, state_commit, ct_commit,
             chain_tip, lsh, origin_face_id, palette_commit, feature_id,
             type_idx, owner_pk_x, owner_pk_y, owner_sk."""
    osd = owner_seed if owner_seed is not None else seed
    owner_sk = deterministic_int_mint(osd, b"owner_sk", GRUMPKIN_ORDER - 1) + 1
    owner_pk = ec_mul(G, owner_sk)
    assert owner_pk is not None
    pk_x, pk_y = owner_pk

    shadow_id = image_commit % P

    # Per-slot deterministic synthesis (matches build_atomic_mint_fixture).
    pose = pack_pose(x=2 + slot_idx * 2, y=4 + (slot_idx % 8))
    w_dim = 6 + (slot_idx % 4)
    h_dim = 6 + ((slot_idx + 1) % 4)
    indices = [(j * 7 + slot_idx + 3) & 0xF for j in range(w_dim * h_dim)]
    plaintext = encode_plaintext_v2(pose, w_dim, h_dim, indices)
    assert len(plaintext) == PLAINTEXT_FIELDS

    r_i = deterministic_int_mint(seed, f"r_{slot_idx}".encode(), GRUMPKIN_ORDER - 1) + 1
    c1, c2, k = ecies_encrypt_v2(plaintext, owner_pk, r_i)

    state_commit = sponge_39(plaintext)
    ct_commit = sponge_39(c2)

    origin_face_id = poseidon2_hash_2(image_commit, slot_idx)
    # palette_commit: the on-chain value is sponge_palette_salt(palette, salt)
    # produced at mint time by build_atomic_mint_fixture.py. The legacy
    # `deterministic_int_mint(seed, "palette_{i}", P)` formula does NOT match
    # what's stored on chain. Callers MUST pass the value from the mint
    # fixture's meta.json::palette_commits[slot_idx] (or another authoritative
    # source). The legacy formula is kept only for back-compat against fixtures
    # that predate the sponge_palette_salt rollover.
    if palette_commit is None:
        palette_commit = deterministic_int_mint(seed, f"palette_{slot_idx}".encode(), P)

    mint_ct = mint_chain_step(origin_face_id, pk_x, pk_y)
    lsh = live_state_hash(state_commit, ct_commit, c1[0], c1[1], 0, mint_ct)

    # Sanity: round-trip decrypt.
    decoded, dk = ecies_decrypt_v2(c1, c2, owner_sk)
    assert decoded == plaintext
    assert dk == k

    mint_counter = mint_counter_base + slot_idx + 1
    feature_id = derive_feature_id(chain_id, shadow_id, slot_idx, mint_counter)
    type_idx = slot_idx  # ShadowToken._mintOneAtom: typeIdx = slot index

    return {
        "owner_sk": owner_sk,
        "owner_pk_x": pk_x,
        "owner_pk_y": pk_y,
        "shadow_id": shadow_id,
        "slot_idx": slot_idx,
        "plaintext": plaintext,
        "c1_x": c1[0],
        "c1_y": c1[1],
        "c2": c2,
        "k": k,
        "state_commit": state_commit,
        "ct_commit": ct_commit,
        "origin_face_id": origin_face_id,
        "palette_commit": palette_commit,
        "chain_tip": mint_ct,
        "lsh": lsh,
        "feature_id": feature_id,
        "type_idx": type_idx,
        "mint_counter": mint_counter,
    }


def build_mutate_witness(seed: bytes, mint_state: dict) -> dict:
    """Build the mutate_slot witness for the FIRST mutation against
    the live mint state. count: 0 -> 1.
    """
    slot_idx = mint_state["slot_idx"]
    owner_pk = (mint_state["owner_pk_x"], mint_state["owner_pk_y"])

    # New plaintext: distinct pose/dims so the mutation is observable.
    new_pose = pack_pose(x=10, y=18)
    new_w, new_h = 14, 12  # under 48x48 canvas
    new_indices = [(j * 11 + slot_idx + 5) & 0xF for j in range(new_w * new_h)]
    new_plaintext = encode_plaintext_v2(new_pose, new_w, new_h, new_indices)
    assert len(new_plaintext) == PLAINTEXT_FIELDS

    new_r = deterministic_int_mutate(seed, f"new_r_{slot_idx}".encode(),
                                     GRUMPKIN_ORDER - 1) + 1
    new_c1, new_c2, new_k = ecies_encrypt_v2(new_plaintext, owner_pk, new_r)

    new_state_commit = sponge_39(new_plaintext)
    new_ct_commit = sponge_39(new_c2)

    new_count = 1  # 0 -> 1 (first mutate)
    new_chain_tip = chain_step(
        mint_state["chain_tip"],
        new_state_commit,
        new_ct_commit,
        new_count,
        mint_state["origin_face_id"],
        slot_idx,
    )
    new_lsh = live_state_hash(
        new_state_commit, new_ct_commit,
        new_c1[0], new_c1[1],
        new_count, new_chain_tip,
    )

    return {
        # PI binding values
        "shadow_id":          mint_state["shadow_id"],
        "slot_idx":           slot_idx,
        "feature_id":         mint_state["feature_id"],
        "type_idx":           mint_state["type_idx"],
        "origin_face_id":     mint_state["origin_face_id"],
        "palette_commit":     mint_state["palette_commit"],
        "old_lsh":            mint_state["lsh"],
        "new_lsh":            new_lsh,
        "new_ct_commit":      new_ct_commit,
        "c2_field_count":     PLAINTEXT_FIELDS,
        "owner_pk_x":         mint_state["owner_pk_x"],
        "owner_pk_y":         mint_state["owner_pk_y"],
        "prev_chain_tip":     mint_state["chain_tip"],
        "new_chain_tip":      new_chain_tip,
        "prev_mutation_count": 0,
        "new_mutation_count":  new_count,

        # witness
        "old_plaintext":      mint_state["plaintext"],
        "new_plaintext":      new_plaintext,
        "old_state_commit":   mint_state["state_commit"],
        "old_ct_commit":      mint_state["ct_commit"],
        "old_c1_x":           mint_state["c1_x"],
        "old_c1_y":           mint_state["c1_y"],
        "old_count":          0,
        "old_chain_tip":      mint_state["chain_tip"],
        "old_k":              mint_state["k"],
        "new_k":              new_k,
        "new_r":              new_r,
        "owner_sk":           mint_state["owner_sk"],
        "w_new":              new_w,
        "h_new":              new_h,

        # event/calldata
        "old_c2":             mint_state["c2"],
        "new_c2":             new_c2,
        "new_c1_x":           new_c1[0],
        "new_c1_y":           new_c1[1],
    }


def write_secret_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except Exception:
        os.close(fd)
        raise
    atexit.register(lambda p=path: p.exists() and p.unlink())


def render_array(name: str, vals: list[int]) -> str:
    return f"{name} = [{', '.join(fhex(v) for v in vals)}]"


def write_mutate_prover_toml(w: dict) -> None:
    """Mirror build_mutate_slot_fixture.write_prover_toml field-for-field
    so the mutate_slot circuit's Prover.toml is byte-equal-shaped."""
    toml = MUT_DIR / "Prover.toml"
    lines = [
        f"shadow_id = {fhex(w['shadow_id'])}",
        f"slot_idx = {fhex(w['slot_idx'])}",
        f"feature_id = {fhex(w['feature_id'])}",
        f"type_idx = {fhex(w['type_idx'])}",
        f"origin_face_id = {fhex(w['origin_face_id'])}",
        f"palette_commit = {fhex(w['palette_commit'])}",
        f"old_live_state_hash = {fhex(w['old_lsh'])}",
        f"new_live_state_hash = {fhex(w['new_lsh'])}",
        f"new_ct_commit = {fhex(w['new_ct_commit'])}",
        f"c2_field_count = {fhex(w['c2_field_count'])}",
        f"owner_pk_x = {fhex(w['owner_pk_x'])}",
        f"owner_pk_y = {fhex(w['owner_pk_y'])}",
        f"prev_chain_tip = {fhex(w['prev_chain_tip'])}",
        f"new_chain_tip_pi = {fhex(w['new_chain_tip'])}",
        f"prev_mutation_count = {fhex(w['prev_mutation_count'])}",
        f"new_mutation_count_pi = {fhex(w['new_mutation_count'])}",
        render_array("old_plaintext", w["old_plaintext"]),
        render_array("new_plaintext", w["new_plaintext"]),
        f"old_state_commit = {fhex(w['old_state_commit'])}",
        f"old_ct_commit = {fhex(w['old_ct_commit'])}",
        f"old_c1_x = {fhex(w['old_c1_x'])}",
        f"old_c1_y = {fhex(w['old_c1_y'])}",
        f"old_mutation_count = {fhex(w['old_count'])}",
        f"old_chain_tip = {fhex(w['old_chain_tip'])}",
        f"old_k = {fhex(w['old_k'])}",
        f"new_k = {fhex(w['new_k'])}",
        f"new_r = {fhex(w['new_r'])}",
        f"owner_sk = {fhex(w['owner_sk'])}",
        f"w_new = {fhex(w['w_new'])}",
        f"h_new = {fhex(w['h_new'])}",
        f"c2_field_count_w = {fhex(w['c2_field_count'])}",
    ]
    write_secret_file(toml, "\n".join(lines) + "\n")


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


def prove(circuit_dir: Path, json_name: str) -> tuple[bytes, bytes]:
    """nargo execute + bb write_vk + bb prove + bb verify; return (proof, pi)."""
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mint-fixture", required=True,
                    help="Path to atomic_mint fixture dir (provides "
                         "image_commit + per-slot lsh_inits for T10 binding)")
    ap.add_argument("--seed", default="atomic_mint_demo",
                    help="Fixture seed (drives r_i + palette_commit)")
    ap.add_argument("--owner-seed", default=None,
                    help="Owner-key seed (drives owner_sk). Defaults to --seed. "
                         "Use a different value when one owner mints multiple shadows.")
    ap.add_argument("--mint-counter-base", type=int, default=0,
                    help="Global FeatureNFT.mintCounter at the moment THIS shadow's "
                         "mint started. 0 if this is the first shadow on the chain. "
                         "For the second shadow on a chain where the first minted 8 "
                         "carriers, pass --mint-counter-base 8.")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--chain-id", type=int, default=84532,
                    help="L2 chain id (Base Sepolia = 84532)")
    ap.add_argument("--out-seed", default=None,
                    help="Output dir name (default: onchain_mutate_<seed>_slot<i>)")
    args = ap.parse_args()

    mint_fix = Path(args.mint_fixture)
    if not (mint_fix / "meta.json").exists():
        sys.exit(f"mint fixture not found: {mint_fix}")
    with open(mint_fix / "meta.json") as f:
        mint_meta = json.load(f)
    image_commit = int(mint_meta["image_commit"], 16)
    mint_lsh_inits = [int(x, 16) for x in mint_meta["lsh_inits"]]
    assert len(mint_lsh_inits) == 8
    # palette_commits[slot_idx] is the on-chain ground truth (sponge_palette_salt).
    mint_palette_commit = int(mint_meta["palette_commits"][args.slot], 16)

    seed = args.seed.encode()
    print(f"[onchain_mutate fixture] seed={args.seed!r} slot={args.slot} chain_id={args.chain_id}")
    print(f"  image_commit  = {hex(image_commit)[:18]}...")
    print(f"  shadow_id     = {hex(image_commit % P)[:18]}...")

    # ---- Step 1: reconstruct mint state for target slot ----
    print(f"[1/4] reconstruct mint state slot {args.slot}")
    owner_seed = args.owner_seed.encode() if args.owner_seed else None
    mint_state = reconstruct_mint_slot_state(seed, image_commit, args.slot, args.chain_id,
                                             owner_seed=owner_seed,
                                             mint_counter_base=args.mint_counter_base,
                                             palette_commit=mint_palette_commit)
    # Sanity: lsh from reconstruction byte-equals fixture's lsh_inits[slot].
    assert mint_state["lsh"] == mint_lsh_inits[args.slot], \
        f"lsh mismatch: reconstructed={hex(mint_state['lsh'])} " \
        f"fixture={hex(mint_lsh_inits[args.slot])}"
    print(f"  reconstructed lsh matches fixture lsh_inits[{args.slot}]")
    print(f"  feature_id    = {hex(mint_state['feature_id'])[:18]}...")
    print(f"  type_idx      = {mint_state['type_idx']}")

    # ---- Step 2: build mutate witness + proof ----
    print(f"[2/4] mutate witness")
    w = build_mutate_witness(seed, mint_state)
    write_mutate_prover_toml(w)
    print(f"  new_lsh       = {hex(w['new_lsh'])[:18]}...")
    print(f"  new_chain_tip = {hex(w['new_chain_tip'])[:18]}...")
    print(f"  new_count     = {w['new_mutation_count']}")
    print(f"[3/4] mutate proof")
    proof_mut, pi_mut = prove(MUT_DIR, "mutate_slot.json")

    # ---- Step 3: T10 against POST-MUTATE manifest ----
    # post-mutate lsh_array: slot[i] = new_lsh, slot[j] = mint_lsh_inits[j] for j != i (j in 0..7), slot[8..15] = 0
    post_lsh = list(mint_lsh_inits) + [0] * 8
    post_lsh[args.slot] = w["new_lsh"]
    z_commit = 0  # unchanged from mint
    buf = [w["shadow_id"], z_commit] + post_lsh
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[4/4] T10: post-mutate t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    write_secret_file(
        T10_DIR / "Prover.toml",
        f"shadow_id = {fhex(w['shadow_id'])}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in post_lsh)}]\n",
    )
    proof_t10, pi_t10 = prove(T10_DIR, "shadow_t10.json")

    # ---- Step 4: write fixture ----
    out_seed = args.out_seed or f"onchain_mutate_{args.seed}_slot{args.slot}"
    fix_dir = FIXTURE_ROOT / out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_mut.bin").write_bytes(proof_mut)
    (fix_dir / "public_inputs_mut.bin").write_bytes(pi_mut)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)
    new_c2_bytes = b"".join(c.to_bytes(32, "big") for c in w["new_c2"])
    (fix_dir / "c2.bin").write_bytes(new_c2_bytes)

    meta = {
        "kind": "onchain_mutate",
        "seed": args.seed,
        "slot_idx": args.slot,
        "chain_id": args.chain_id,
        "shadow_id": bx32(w["shadow_id"]),
        "image_commit": bx32(image_commit),
        "feature_id": bx32(w["feature_id"]),
        "type_idx": w["type_idx"],
        "origin_face_id": bx32(w["origin_face_id"]),
        "palette_commit": bx32(w["palette_commit"]),
        "owner_pk_x": bx32(w["owner_pk_x"]),
        "owner_pk_y": bx32(w["owner_pk_y"]),
        "old_lsh": bx32(w["old_lsh"]),
        "new_lsh": bx32(w["new_lsh"]),
        "new_ct_commit": bx32(w["new_ct_commit"]),
        "new_c1_x": bx32(w["new_c1_x"]),
        "new_c1_y": bx32(w["new_c1_y"]),
        "prev_chain_tip": bx32(w["prev_chain_tip"]),
        "new_chain_tip": bx32(w["new_chain_tip"]),
        "prev_mutation_count": w["prev_mutation_count"],
        "new_mutation_count": w["new_mutation_count"],
        "c2_field_count": w["c2_field_count"],
        "z_index_commit": bx32(z_commit),
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "post_mutate_lsh_array": [bx32(v) for v in post_lsh],
        "new_plaintext_pose": w["new_plaintext"][0],
        "new_plaintext_w": w["w_new"],
        "new_plaintext_h": w["h_new"],
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof_mut.bin  ({len(proof_mut)} B)")
    print(f"        proof_t10.bin  ({len(proof_t10)} B)")


if __name__ == "__main__":
    main()
