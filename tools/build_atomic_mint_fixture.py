#!/usr/bin/env python3
"""Generate a *linked* landmark_regions_v2 + shadow_t10 mint fixture.

Bundles a real-proof set the ShadowToken.mintShadow Forge test consumes:

  - landmark_regions_v2: 8 origin slots witnessed by owner; 7 PI matched
    against on-chain hash-roots (lsh_inits_root, ct_commits_root,
    chain_tips_root) reconstructed from per-slot calldata.
  - face_disc: pre-baked from contracts/test/fixtures/face_disc/alice0
    (its imageCommit drives the mint witness so both proofs share PI[1]).
  - shadow_t10: built against the post-mint manifest array
    (lsh_init[0..7] in slots 0..7, zero in slots 8..15) with z_commit=0.

For the test we don't generate face_disc here -- alice0's fixture is
already on disk. Re-running this fixture is idempotent against the same
seed; alice0's imageCommit is the v2 mint witness's PI[1].

Usage:
    python3 build_atomic_mint_fixture.py [--seed atomic_mint_demo]
"""
from __future__ import annotations

import argparse
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
    sponge_39, sponge_6, sponge_4, sponge_8_pad16, keystream_39,
    poseidon2_hash_2, mint_chain_step, MINT_TAG,
    encode_plaintext_v2, pack_pose,
    ecies_encrypt_v2,
    sponge_palette_salt, encode_palette_packed, encrypt_salt_v2,
    fhex, bx32,
)
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402

ROOT = REPO.parent
MINT_DIR = ROOT / "circuits" / "landmark_regions_v2"
T10_DIR = ROOT / "circuits" / "shadow_t10"
DEFAULT_FACE_DISC_FIXTURE = ROOT / "contracts" / "test" / "fixtures" / "face_disc" / "alice0"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "atomic_mint"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))

N_MINT = 8


def deterministic_int(seed: bytes, label: bytes, mod: int) -> int:
    import hashlib
    h = hashlib.sha256(b"OMP_ATOMIC_MINT_FIXTURE_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


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


def build_witness(seed: bytes, image_commit: int, owner_seed: bytes | None = None) -> dict:
    # owner_seed defaults to the fixture seed (back-compat). Pass a
    # different value (e.g. the seed of a previously-minted shadow) to
    # mint a new shadow under the SAME owner key, so KeyRegistry stays
    # consistent across multiple shadows owned by one wallet.
    osd = owner_seed if owner_seed is not None else seed
    print("[1/9] keygen: owner")
    owner_sk = deterministic_int(osd, b"owner_sk", GRUMPKIN_ORDER - 1) + 1
    owner_pk = ec_mul(G, owner_sk)
    assert owner_pk is not None
    owner_pk_x, owner_pk_y = owner_pk

    # Deterministic shadowId derivation matches contract: shadowId = imageCommit % FR_MOD.
    shadow_id = image_commit % P
    print(f"  shadow_id = {hex(shadow_id)[:18]}...")
    print(f"  image_commit = {hex(image_commit)[:18]}...")

    plaintexts: list[list[int]] = []
    new_r: list[int] = []
    state_commits: list[int] = []
    ct_commits: list[int] = []
    c1_xs: list[int] = []
    c1_ys: list[int] = []
    c2s: list[list[int]] = []
    origin_face_ids: list[int] = []
    chain_tips: list[int] = []
    lsh_inits: list[int] = []
    palette_commits: list[int] = []
    palettes: list[list[int]] = []
    palette_salts: list[int] = []
    palette_salt_cts: list[int] = []
    salt_c1_xs: list[int] = []
    salt_c1_ys: list[int] = []

    print(f"[2/9] per-slot bundles for {N_MINT} origin slots")
    for i in range(N_MINT):
        # Encode plaintext: simple synthetic landmark per slot.
        pose = pack_pose(x=2 + i * 2, y=4 + (i % 8))
        w_dim = 6 + (i % 4)
        h_dim = 6 + ((i + 1) % 4)
        indices = [(j * 7 + i + 3) & 0xF for j in range(w_dim * h_dim)]
        plaintext = encode_plaintext_v2(pose, w_dim, h_dim, indices)
        plaintexts.append(plaintext)

        # ECIES envelope to owner.
        r_i = deterministic_int(seed, f"r_{i}".encode(), GRUMPKIN_ORDER - 1) + 1
        new_r.append(r_i)
        c1, c2, k = ecies_encrypt_v2(plaintext, owner_pk, r_i)
        c1_xs.append(c1[0])
        c1_ys.append(c1[1])
        c2s.append(c2)

        # Per-slot derived values matching the circuit byte-for-byte.
        sc = sponge_39(plaintext)
        cc = sponge_39(c2)
        state_commits.append(sc)
        ct_commits.append(cc)

        ofi = poseidon2_hash_2(image_commit, i)
        origin_face_ids.append(ofi)

        ct = mint_chain_step(ofi, owner_pk_x, owner_pk_y)
        chain_tips.append(ct)

        lsh = sponge_6(sc, cc, c1[0], c1[1], 0, ct)
        lsh_inits.append(lsh)

        # Per-slot 16-color palette + secret salt; commit binds them.
        # Colors are 24-bit; salt is a Field. The owner ECIES-decrypts the
        # salt envelope at reveal time to drive `palette_reveal_v2`.
        import hashlib  # local import keeps top-level minimal
        palette = []
        for j in range(16):
            d = hashlib.sha256(seed + f":palette:{i}:{j}".encode()).digest()
            palette.append(int.from_bytes(d[:3], "big") & 0xFFFFFF)
        palette_salt = deterministic_int(seed, f"palette_salt_{i}".encode(), P)
        commit = sponge_palette_salt(palette, palette_salt)
        # Fresh r_salt per slot for the salt envelope. Reusing the slot's
        # plaintext-envelope `r_i` would tie the two ciphertexts; cheap to
        # use a fresh value, so we do.
        r_salt = deterministic_int(seed, f"r_salt_{i}".encode(), GRUMPKIN_ORDER - 1) + 1
        c1_salt, salt_ct, _salt_k = encrypt_salt_v2(palette_salt, owner_pk, r_salt)

        palettes.append(palette)
        palette_salts.append(palette_salt)
        palette_commits.append(commit)
        palette_salt_cts.append(salt_ct)
        salt_c1_xs.append(c1_salt[0])
        salt_c1_ys.append(c1_salt[1])

    # CONSISTENCY: every emitted palette_commit MUST open via sponge_palette_salt
    # to the published palettes/palette_salts. Without this, ShadowToken.solve will
    # revert at FeatureNFT.revealPaletteAtSolve. Old fixtures (atomic_mint_demo,
    # atomic_mint_demo_b) violated this and stranded their on-chain shadows
    # un-solvable -- assertion blocks any future drift.
    for i in range(N_MINT):
        recomputed = sponge_palette_salt(palettes[i], palette_salts[i])
        if recomputed != palette_commits[i]:
            raise AssertionError(
                f"slot {i}: sponge_palette_salt({palettes[i]}, {hex(palette_salts[i])}) = "
                f"{hex(recomputed)} != fixture palette_commit {hex(palette_commits[i])}"
            )
    print("      [palette_commit consistency] all 8 slots open via sponge_palette_salt")

    lsh_inits_root = sponge_8_pad16(lsh_inits)
    ct_commits_root = sponge_8_pad16(ct_commits)
    chain_tips_root = sponge_8_pad16(chain_tips)

    print(f"[3/9] roots: lsh={hex(lsh_inits_root)[:18]}... "
          f"ct={hex(ct_commits_root)[:18]}... "
          f"chain={hex(chain_tips_root)[:18]}...")

    return {
        # PI (7)
        "shadow_id": shadow_id,
        "image_commit": image_commit,
        "owner_pk_x": owner_pk_x,
        "owner_pk_y": owner_pk_y,
        "lsh_inits_root": lsh_inits_root,
        "ct_commits_root": ct_commits_root,
        "chain_tips_root": chain_tips_root,

        # witness
        "plaintexts": plaintexts,
        "new_r": new_r,
        "owner_sk": owner_sk,

        # post-state for chain seeding + calldata
        "state_commits": state_commits,
        "ct_commits": ct_commits,
        "c1_xs": c1_xs,
        "c1_ys": c1_ys,
        "c2s": c2s,
        "origin_face_ids": origin_face_ids,
        "chain_tips": chain_tips,
        "lsh_inits": lsh_inits,
        "palette_commits": palette_commits,
        "palettes":          palettes,
        "palette_salts":     palette_salts,
        "palette_salt_cts":  palette_salt_cts,
        "salt_c1_xs":        salt_c1_xs,
        "salt_c1_ys":        salt_c1_ys,
    }


def write_mint_prover_toml(w: dict) -> None:
    prover_path = MINT_DIR / "Prover.toml"
    prover_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"shadow_id = {fhex(w['shadow_id'])}",
        f"image_commit = {fhex(w['image_commit'])}",
        f"owner_pk_x = {fhex(w['owner_pk_x'])}",
        f"owner_pk_y = {fhex(w['owner_pk_y'])}",
        f"lsh_inits_root = {fhex(w['lsh_inits_root'])}",
        f"ct_commits_root = {fhex(w['ct_commits_root'])}",
        f"chain_tips_root = {fhex(w['chain_tips_root'])}",
        render_2d("plaintexts", w["plaintexts"]),
        render_array("new_r", w["new_r"]),
    ]
    prover_path.write_text("\n".join(lines) + "\n")
    print(f"[wrote] {prover_path}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="atomic_mint_demo")
    ap.add_argument("--no-prove", action="store_true")
    ap.add_argument("--owner-seed", default=None,
                    help="Seed to derive owner_sk; defaults to --seed. Pass a previously-used seed to reuse that wallet's key.")
    ap.add_argument("--face-disc-fixture", default=str(DEFAULT_FACE_DISC_FIXTURE),
                    type=Path,
                    help="Path to a face_disc fixture dir (must contain proof + public_inputs).")
    args = ap.parse_args()

    seed = args.seed.encode()
    owner_seed = args.owner_seed.encode() if args.owner_seed else None
    face_disc_fixture = Path(args.face_disc_fixture)
    print(f"[atomic_mint fixture] seed={args.seed!r}")
    if args.owner_seed:
        print(f"                      owner_seed={args.owner_seed!r}")
    print(f"                      face_disc={face_disc_fixture}")

    # Pull imageCommit from the face_disc fixture so both proofs
    # share PI[1] byte-for-byte.
    pi_bytes = (face_disc_fixture / "public_inputs").read_bytes()
    if len(pi_bytes) != 32:
        sys.exit(f"face_disc public_inputs unexpected length {len(pi_bytes)}")
    image_commit = int.from_bytes(pi_bytes, "big")
    print(f"[face_disc] imageCommit = {hex(image_commit)[:18]}...")

    w = build_witness(seed, image_commit, owner_seed=owner_seed)
    write_mint_prover_toml(w)

    print("[4/9] nargo execute (landmark_regions_v2)")
    run([NARGO, "execute"], MINT_DIR, timeout=600)

    if args.no_prove:
        return

    target_dir = MINT_DIR / "target"
    print("[5/9] bb write_vk")
    run([BB, "write_vk", "-b", str(target_dir / "landmark_regions_v2.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MINT_DIR, timeout=900)

    print("[6/9] bb prove")
    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_dir / "landmark_regions_v2.json"),
         "-w", str(target_dir / "landmark_regions_v2.gz"),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MINT_DIR, timeout=1800)

    print("[7/9] bb verify (sanity)")
    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MINT_DIR, timeout=300)
    print("[ok] mint proof verified")

    proof_mint_bytes = (proof_dir / "proof").read_bytes()
    pi_mint_bytes = (proof_dir / "public_inputs").read_bytes()

    # ---- shadow_t10 against the post-mint manifest ----
    print("[8/9] shadow_t10: T10 proof against post-mint manifest")
    shadow_id = w["shadow_id"]
    z_commit = 0
    # Manifest: lsh_inits[0..7] go to slots 0..7; slots 8..15 are EMPTY (lsh = 0).
    lsh_array = list(w["lsh_inits"]) + [0] * 8
    assert len(lsh_array) == 16

    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"  post-mint t10  hi={hex(hi)[:18]}... lo={hex(lo)[:18]}...")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    run([NARGO, "execute"], T10_DIR, timeout=300)
    run([BB, "write_vk", "-b", str(T10_DIR / "target/shadow_t10.json"),
         "-o", str(T10_DIR / "target"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    proof_dir_t10 = T10_DIR / "target" / "proof_dir"
    proof_dir_t10.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(T10_DIR / "target/shadow_t10.json"),
         "-w", str(T10_DIR / "target/shadow_t10.gz"),
         "-o", str(proof_dir_t10),
         "-k", str(T10_DIR / "target/vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    run([BB, "verify",
         "-k", str(T10_DIR / "target/vk"),
         "-p", str(proof_dir_t10 / "proof"),
         "-i", str(proof_dir_t10 / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=300)

    proof_t10_bytes = (proof_dir_t10 / "proof").read_bytes()
    pi_t10_bytes = (proof_dir_t10 / "public_inputs").read_bytes()

    # ---- write fixture ----
    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    (fix_dir / "proof_mint.bin").write_bytes(proof_mint_bytes)
    (fix_dir / "public_inputs_mint.bin").write_bytes(pi_mint_bytes)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10_bytes)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10_bytes)
    # Copy face_disc proof + PI for one-stop test consumption.
    (fix_dir / "proof_disc.bin").write_bytes((face_disc_fixture / "proof").read_bytes())
    (fix_dir / "public_inputs_disc.bin").write_bytes(pi_bytes)

    # Per-slot c2 calldata as bytes32 arrays for forge consumption.
    c2_per_slot = [[bx32(v) for v in w["c2s"][i]] for i in range(N_MINT)]

    # Pre-solve, no z_perm is revealed; visualize_shadow_v2 falls back to
    # identity ordering (slot 0 bottom, slot 15 top). Mint occupies slots
    # 0..7; 8..15 stay EMPTY.
    z_perm_identity = list(range(16))
    occupied_idxs = list(range(N_MINT))
    # Manifest LSH array post-mint: lsh_inits[0..7] in slots 0..7, zeros elsewhere.
    post_mint_lsh = list(w["lsh_inits"]) + [0] * 8

    meta = {
        "seed": args.seed,
        "shadow_id": bx32(w["shadow_id"]),
        "image_commit": bx32(w["image_commit"]),
        "owner_pk_x": bx32(w["owner_pk_x"]),
        "owner_pk_y": bx32(w["owner_pk_y"]),
        "lsh_inits_root": bx32(w["lsh_inits_root"]),
        "ct_commits_root": bx32(w["ct_commits_root"]),
        "chain_tips_root": bx32(w["chain_tips_root"]),
        "lsh_inits":       [bx32(v) for v in w["lsh_inits"]],
        "ct_commits":      [bx32(v) for v in w["ct_commits"]],
        "c1_xs":           [bx32(v) for v in w["c1_xs"]],
        "c1_ys":           [bx32(v) for v in w["c1_ys"]],
        "origin_face_ids": [bx32(v) for v in w["origin_face_ids"]],
        "chain_tips":      [bx32(v) for v in w["chain_tips"]],
        "palette_commits":  [bx32(v) for v in w["palette_commits"]],
        # Per-slot palette ECIES envelopes (advisory, emitted in events;
        # not stored on chain). The reveal proof needs the palette + salt
        # pair which the owner re-derives by ECIES-decrypting (saltCt, c1).
        "palette_salt_cts": [bx32(v) for v in w["palette_salt_cts"]],
        "salt_c1_xs":       [bx32(v) for v in w["salt_c1_xs"]],
        "salt_c1_ys":       [bx32(v) for v in w["salt_c1_ys"]],
        # Per-slot palettes + salts, the witness for `palette_reveal_v2`.
        # Mint test consumers can ignore these. Fixture-bound only.
        "palettes":         [[bx32(v) for v in p] for p in w["palettes"]],
        "palette_salts":    [bx32(v) for v in w["palette_salts"]],
        "c2_per_slot":     c2_per_slot,
        "z_index_commit":  "0x0",
        "t10_hi":          bx32(hi),
        "t10_lo":          bx32(lo),

        # Visualizer-friendly compatibility fields. Identity z_perm so
        # `visualize_shadow_v2 from-solve-fixture` renders mint outputs;
        # prev_lsh = post-mint manifest LSH array.
        "z_perm":          z_perm_identity,
        "occupied_idxs":   occupied_idxs,
        "prev_lsh":        [bx32(v) for v in post_mint_lsh],
    }

    # Per-slot plaintexts as bytes32 arrays. Slots 8..15 are empty (39
    # zero fields). Lets the visualizer decode + render mint outputs.
    plaintexts_per_slot: list[list[str]] = []
    for i in range(16):
        if i < N_MINT:
            plaintexts_per_slot.append([bx32(v) for v in w["plaintexts"][i]])
        else:
            plaintexts_per_slot.append([bx32(0)] * PLAINTEXT_FIELDS)
    (fix_dir / "plaintexts.json").write_text(
        json.dumps({"plaintexts": plaintexts_per_slot}, indent=2)
    )
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        proof_mint.bin ({len(proof_mint_bytes)} B)")
    print(f"        proof_disc.bin ({(face_disc_fixture / 'proof').stat().st_size} B)")
    print(f"        proof_t10.bin ({len(proof_t10_bytes)} B)")


if __name__ == "__main__":
    main()
