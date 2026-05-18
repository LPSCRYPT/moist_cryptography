#!/usr/bin/env python3
"""Build a positive-path transfer_feature_v2 fixture for one of A's
already-extracted held carriers.

Targets carrier 0x0c15f2ea... (typeIdx=0, originally slot 0 of shadow A,
mutated once before extract). Its current `liveStateHashCheckpoint` on
chain equals the post-mutate slot-0 lsh — which we recompute here from
the original mint seed without scraping any fixture.

Produces:
  contracts/test/fixtures/onchain_transfer_feature_v2/<seed>/
    proof.bin
    public_inputs.bin
    c2.bin              (39-field new c2; recipient decrypts with sk)
    meta.json           (includes proof-bound new_c1_x/new_c1_y envelope)

Run:
  python3 tools/build_transfer_feature_v2_fixture.py \
    --slot 0 \
    --recipient 0xFD90Bd22EDA6f54EBA3587E6a3642AB3B5236Ca2 \
    --recipient-pk-x 0x2ba2a91c82b297222de69d406e4b991cd4860fabf7f0872f59e91da6d8b6bacf \
    --recipient-pk-y 0x1830895542a5ab1d6a74be764d59576ee8ad84bd6d1d0b1261e93e7c335df1a9 \
    --carrier-checkpoint 0x16aada290c6d3adb246d32fbcd7966e1acefcbc5e66aaaa115528f44d683b91d \
    --out-seed transfer_feature_v2_a_slot0
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

from secret_inbox import G, GRUMPKIN_ORDER, ec_mul, ec_add  # noqa: E402
from v2_circuit_helpers import (  # noqa: E402
    P, PLAINTEXT_FIELDS,
    sponge_39, sponge_6, keystream_39,
    poseidon2_hash_2,
    kdf, KDF_ROLE_PLAINTEXT,
    chain_step, live_state_hash,
    fhex, bx32,
)
from build_mutate_slot_onchain import (  # noqa: E402
    reconstruct_mint_slot_state, build_mutate_witness,
    deterministic_int_mutate,
)

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "transfer_feature_v2"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "onchain_transfer_feature_v2"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))


def _delete_if_exists(path: Path) -> None:
    try:
        path.unlink()
        print(f"[deleted transient] {path}")
    except FileNotFoundError:
        pass


def parse_int_arg(val: str) -> int:
    s = val.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def deterministic_int_transfer(seed: bytes, label: bytes, mod: int) -> int:
    """Distinct prefix so transfer's new_r is independent of mint+mutate."""
    h = hashlib.sha256(b"OMP_TRANSFER_FEATURE_V2_v1:" + label + b":" + seed).digest()
    return int.from_bytes(h, "big") % mod


def build_transfer_witness(seed: bytes, slot_idx: int, image_commit: int,
                           chain_id: int, recipient_pk: tuple[int, int],
                           owner_seed: bytes | None = None,
                           mint_counter_base: int = 0,
                           source_state: str = "post-mutate",
                           mint_fixture_path: str | None = None) -> dict:
    """Reconstruct the carrier's current state (mint -> mutate) and
    build the transfer rotation witness."""
    # 1. Mint state (slot lsh_init).
    mint = reconstruct_mint_slot_state(seed, image_commit, slot_idx, chain_id,
                                       owner_seed=owner_seed,
                                       mint_counter_base=mint_counter_base)
    # palette_commit formula has historically varied (deterministic_int label
    # vs sponge_palette_salt). The on-chain value is what was stored at mint
    # via the live atomic_mint fixture's meta.json -- override here.
    if mint_fixture_path is not None:
        import json as _json
        from pathlib import Path as _Path
        meta = _json.loads((_Path(mint_fixture_path) / "meta.json").read_text())
        mint["palette_commit"] = int(meta["palette_commits"][slot_idx], 16)
    # 2. Pre-transfer carrier state. The carrier may be held in different
    # post-states; the transfer rotation only needs:
    #   plaintext, c1, c2, k, count, chain_tip, lsh.
    if source_state == "mint":
        old_plaintext      = mint["plaintext"]
        old_state_commit   = mint["state_commit"]
        old_ct_commit      = mint["ct_commit"]
        old_c1_x, old_c1_y = mint["c1_x"], mint["c1_y"]
        old_count          = 0
        old_chain_tip      = mint["chain_tip"]
        old_k              = mint["k"]
        old_lsh_recomp     = mint["lsh"]
    elif source_state == "post-mutate":
        # mint -> single mutateSlot -> held. count 0 -> 1.
        mut = build_mutate_witness(seed, mint)
        old_plaintext      = mut["new_plaintext"]
        old_state_commit   = sponge_39(old_plaintext)
        old_ct_commit      = mut["new_ct_commit"]
        old_c1_x, old_c1_y = mut["new_c1_x"], mut["new_c1_y"]
        old_count          = mut["new_mutation_count"]
        old_chain_tip      = mut["new_chain_tip"]
        old_k              = mut["new_k"]
        old_lsh_recomp     = live_state_hash(
            old_state_commit, old_ct_commit, old_c1_x, old_c1_y,
            old_count, old_chain_tip,
        )
        assert old_lsh_recomp == mut["new_lsh"], "post-mutate lsh self-check"
    else:
        sys.exit(f"unsupported --source-state {source_state!r} "
                 "(supported: mint, post-mutate)")

    # 3. Transfer envelope.
    new_r = deterministic_int_transfer(seed, f"new_r_slot{slot_idx}".encode(),
                                       GRUMPKIN_ORDER - 1) + 1
    new_c1 = ec_mul(G, new_r)
    assert new_c1 is not None
    shared = ec_mul(recipient_pk, new_r)
    assert shared is not None
    new_k = kdf(KDF_ROLE_PLAINTEXT, shared[0], shared[1])

    new_ks = keystream_39(new_k)
    new_ct = [(old_plaintext[i] + new_ks[i]) % P for i in range(PLAINTEXT_FIELDS)]
    new_state_commit = old_state_commit  # plaintext unchanged
    new_ct_commit    = sponge_39(new_ct)

    new_count = old_count + 1
    # Salts on transfer: (origin_face_id, type_idx) — type_idx replaces
    # mutate's slot_idx since held carriers have no slot.
    new_chain_tip = chain_step(
        old_chain_tip,
        new_state_commit,
        new_ct_commit,
        new_count,
        mint["origin_face_id"],
        mint["type_idx"],
    )
    new_lsh = live_state_hash(
        new_state_commit, new_ct_commit,
        new_c1[0], new_c1[1],
        new_count, new_chain_tip,
    )

    # 4. Owner-side ECIES sanity round-trip: prove our owner_sk recovers old_k
    #    from old_c1. (mirrors the circuit's constraint #4)
    shared_old = ec_mul((old_c1_x, old_c1_y), mint["owner_sk"])
    assert shared_old is not None
    k_old_check = kdf(KDF_ROLE_PLAINTEXT, shared_old[0], shared_old[1])
    assert k_old_check == old_k, "owner_sk does not recover old_k from old_c1"

    return {
        # PI (11) -- H-02 binds c2; F-01 binds recipient ECIES c1 envelope.
        "feature_id":       mint["feature_id"],
        "next_pk_x":        recipient_pk[0],
        "next_pk_y":        recipient_pk[1],
        "old_lsh":          old_lsh_recomp,
        "new_lsh":          new_lsh,
        "palette_commit":   mint["palette_commit"],
        "type_idx":         mint["type_idx"],
        "origin_face_id":   mint["origin_face_id"],
        "new_ct_commit_pi": new_ct_commit,
        "new_c1_x_pi":      new_c1[0],
        "new_c1_y_pi":      new_c1[1],

        # witness
        "plaintext":         old_plaintext,
        "old_state_commit":  old_state_commit,
        "old_ct_commit":     old_ct_commit,
        "old_c1_x":          old_c1_x,
        "old_c1_y":          old_c1_y,
        "old_count":         old_count,
        "old_chain_tip":     old_chain_tip,
        "old_k":             old_k,
        "owner_sk":          mint["owner_sk"],
        "from_owner_pk_x":   mint["owner_pk_x"],
        "from_owner_pk_y":   mint["owner_pk_y"],
        "new_k":             new_k,
        "new_r":             new_r,

        # event-side / sidecar payload
        "new_ct":            new_ct,
        "new_c1_x":          new_c1[0],
        "new_c1_y":          new_c1[1],
        "new_count":         new_count,
        "new_chain_tip":     new_chain_tip,
        "new_state_commit":  new_state_commit,
        "new_ct_commit":     new_ct_commit,
    }


def render_array(name: str, arr) -> str:
    body = ", ".join(fhex(x) for x in arr)
    return name + " = [" + body + "]"


def write_prover_toml(w: dict, out: Path) -> None:
    """Render Prover.toml in the order Noir expects (matches main.nr signature)."""
    lines = [
        # public inputs (must come first for cleanliness, though Noir
        # doesn't enforce ordering by visibility)
        f'feature_id     = {fhex(w["feature_id"])}',
        f'next_pk_x      = {fhex(w["next_pk_x"])}',
        f'next_pk_y      = {fhex(w["next_pk_y"])}',
        f'old_lsh        = {fhex(w["old_lsh"])}',
        f'new_lsh        = {fhex(w["new_lsh"])}',
        f'palette_commit = {fhex(w["palette_commit"])}',
        f'type_idx       = {fhex(w["type_idx"])}',
        f'origin_face_id   = {fhex(w["origin_face_id"])}',
        f'new_ct_commit_pi = {fhex(w["new_ct_commit_pi"])}',
        f'new_c1_x_pi      = {fhex(w["new_c1_x_pi"])}',
        f'new_c1_y_pi      = {fhex(w["new_c1_y_pi"])}',
        # witness
        render_array("plaintext", w["plaintext"]),
        f'old_state_commit = {fhex(w["old_state_commit"])}',
        f'old_ct_commit    = {fhex(w["old_ct_commit"])}',
        f'old_c1_x         = {fhex(w["old_c1_x"])}',
        f'old_c1_y         = {fhex(w["old_c1_y"])}',
        f'old_count        = {fhex(w["old_count"])}',
        f'old_chain_tip    = {fhex(w["old_chain_tip"])}',
        f'old_k            = {fhex(w["old_k"])}',
        f'owner_sk         = {fhex(w["owner_sk"])}',
        f'new_k            = {fhex(w["new_k"])}',
        f'new_r            = {fhex(w["new_r"])}',
    ]
    out.write_text("\n".join(lines) + "\n")
    os.chmod(out, 0o600)


def run(cmd: list, cwd: Path, timeout: int = 600) -> None:
    print("$", " ".join(str(c) for c in cmd))
    r = subprocess.run([str(c) for c in cmd], cwd=str(cwd), timeout=timeout)
    if r.returncode != 0:
        sys.exit(f"command failed: {cmd}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mint-seed", default="atomic_mint_demo",
                    help="Fixture seed (drives r_i + palette_commit at mint)")
    ap.add_argument("--owner-seed", default=None,
                    help="Owner-key seed (drives owner_sk). Defaults to --mint-seed.")
    ap.add_argument("--mint-counter-base", type=int, default=0,
                    help="Global FeatureNFT.mintCounter when this carrier's host shadow was minted.")
    ap.add_argument("--source-state", default="post-mutate",
                    choices=["mint", "post-mutate"],
                    help="Pre-transfer state: mint (count 0; for solve-auto-extracted carriers) "
                         "or post-mutate (count 1; for mutate-then-extract carriers).")
    ap.add_argument("--shadow-id", default="0x011c687ec30b886164f6506b5ad3972fbe295f2e1da1047bd782d686c645d52a",
                    help="image_commit / shadow_id of the host shadow at carrier mint time")
    ap.add_argument("--mint-fixture", default=None,
                    help="Path to atomic_mint fixture dir; if set, palette_commit is read "
                         "from its meta.json instead of reconstructed.")
    ap.add_argument("--slot", type=int, default=0,
                    help="original slot index in the host shadow (= type_idx)")
    ap.add_argument("--chain-id", type=int, default=84532)
    ap.add_argument("--recipient", required=True,
                    help="recipient EOA (informational; only used in meta.json)")
    ap.add_argument("--recipient-pk-x", required=True)
    ap.add_argument("--recipient-pk-y", required=True)
    ap.add_argument("--carrier-checkpoint", required=True,
                    help="liveStateHashCheckpointOf(featureId) on chain; sanity-check")
    ap.add_argument("--out-seed", default="transfer_feature_v2_a_slot0")
    ap.add_argument("--no-prove", action="store_true",
                    help="just write witness JSON; skip nargo execute / bb prove")
    ap.add_argument("--rebuild-verifier", action="store_true",
                    help="after prove+verify, regenerate contracts/src/TransferFeatureV2Verifier.sol")
    args = ap.parse_args()

    seed = args.mint_seed.encode()
    image_commit = parse_int_arg(args.shadow_id)
    recipient_pk = (parse_int_arg(args.recipient_pk_x), parse_int_arg(args.recipient_pk_y))
    expected_lsh = parse_int_arg(args.carrier_checkpoint)

    print(f"[1/6] reconstruct mint+mutate state for slot {args.slot}")
    owner_seed = args.owner_seed.encode() if args.owner_seed else None
    w = build_transfer_witness(seed, args.slot, image_commit, args.chain_id, recipient_pk,
                                owner_seed=owner_seed,
                                mint_counter_base=args.mint_counter_base,
                                source_state=args.source_state,
                                mint_fixture_path=args.mint_fixture)

    print(f"[2/6] sanity: old_lsh == carrier on-chain checkpoint")
    if w["old_lsh"] != expected_lsh:
        sys.exit(
            f"FATAL: reconstructed old_lsh {fhex(w['old_lsh'])} != "
            f"on-chain checkpoint {fhex(expected_lsh)}"
        )
    print(f"  ok: old_lsh = {fhex(w['old_lsh'])}")
    print(f"  feature_id = {fhex(w['feature_id'])}")
    print(f"  new_lsh    = {fhex(w['new_lsh'])}")

    print(f"[3/6] write Prover.toml")
    prover = CIRCUIT_DIR / "Prover.toml"
    write_prover_toml(w, prover)
    atexit.register(_delete_if_exists, prover)

    fix_dir = FIXTURE_ROOT / args.out_seed
    fix_dir.mkdir(parents=True, exist_ok=True)

    if args.no_prove:
        print("[skip] --no-prove set; stopping after Prover.toml write")
        return

    print(f"[4/6] nargo execute")
    target_dir = CIRCUIT_DIR / "target"
    target_dir.mkdir(exist_ok=True)
    witness_path = target_dir / "witness.gz"
    run([NARGO, "execute", "-p", "Prover.toml", str(witness_path.stem)],
        CIRCUIT_DIR, timeout=300)
    # nargo writes target/<witness_stem>.gz — confirm
    if not witness_path.exists():
        # nargo may use {circuit_name}.gz — find it
        candidates = list(target_dir.glob("witness*.gz")) + list(target_dir.glob("*.gz"))
        candidates = [c for c in candidates if c.name != "transfer_feature_v2.json"]
        if not candidates:
            sys.exit("nargo execute did not produce a witness file")
        witness_path = candidates[0]
    print(f"  witness: {witness_path}")

    print(f"[5/6] bb write_vk + prove + verify")
    run([BB, "write_vk",
         "-b", str(target_dir / "transfer_feature_v2.json"),
         "-o", str(target_dir),
         "--scheme", "ultra_honk",
         "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)

    proof_dir = target_dir / "proof_dir"
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove",
         "-b", str(target_dir / "transfer_feature_v2.json"),
         "-w", str(witness_path),
         "-o", str(proof_dir),
         "-k", str(target_dir / "vk"),
         "--scheme", "ultra_honk",
         "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=900)
    proof_path = proof_dir / "proof"
    pi_path    = proof_dir / "public_inputs"

    run([BB, "verify",
         "-k", str(target_dir / "vk"),
         "-p", str(proof_path),
         "-i", str(pi_path),
         "--scheme", "ultra_honk",
         "--oracle_hash", "keccak"], CIRCUIT_DIR, timeout=300)
    print("  bb verify: ok")

    if args.rebuild_verifier:
        print("[5b/6] bb write_solidity_verifier")
        verifier_tmp = target_dir / "TransferFeatureV2Verifier.tmp.sol"
        run([BB, "write_solidity_verifier",
             "-k", str(target_dir / "vk"),
             "-o", str(verifier_tmp),
             "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
        verifier_dst = ROOT / "contracts" / "src" / "TransferFeatureV2Verifier.sol"
        text = verifier_tmp.read_text().replace(
            "contract HonkVerifier", "contract TransferFeatureV2Verifier")
        verifier_dst.write_text(text)
        verifier_tmp.unlink()
        print(f"  wrote {verifier_dst}")

    print(f"[6/6] save fixture artifacts")
    (fix_dir / "proof.bin").write_bytes(proof_path.read_bytes())
    (fix_dir / "public_inputs.bin").write_bytes(pi_path.read_bytes())
    if pi_path.stat().st_size != 11 * 32:
        sys.exit(f"unexpected public input length {pi_path.stat().st_size}; want {11 * 32}")
    # 39-field new c2 as 32-byte field LE encoding for chain calldata
    c2_bytes = b"".join(int(x).to_bytes(32, "big") for x in w["new_ct"])
    (fix_dir / "c2.bin").write_bytes(c2_bytes)

    meta = {
        "kind": "onchain_transfer_feature_v2",
        "seed": args.out_seed,
        "mint_seed": args.mint_seed,
        "chain_id": args.chain_id,
        "shadow_id_at_mint": bx32(image_commit),
        "slot_at_mint": args.slot,
        "feature_id": bx32(w["feature_id"]),
        "type_idx": w["type_idx"],
        "origin_face_id": bx32(w["origin_face_id"]),
        "palette_commit": bx32(w["palette_commit"]),
        "from_owner_pk_x": bx32(w["from_owner_pk_x"]),
        "from_owner_pk_y": bx32(w["from_owner_pk_y"]),
        "to_addr": args.recipient,
        "to_pk_x": bx32(recipient_pk[0]),
        "to_pk_y": bx32(recipient_pk[1]),
        "old_lsh": bx32(w["old_lsh"]),
        "new_lsh": bx32(w["new_lsh"]),
        "new_ct_commit": bx32(w["new_ct_commit"]),
        "new_c1_x": bx32(w["new_c1_x"]),
        "new_c1_y": bx32(w["new_c1_y"]),
        "new_chain_tip": bx32(w["new_chain_tip"]),
        "old_count": w["old_count"],
        "new_count": w["new_count"],
        # for visualizer sidecar:
        "c2_field_count": PLAINTEXT_FIELDS,
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"  wrote {fix_dir}/{{proof.bin, public_inputs.bin, c2.bin, meta.json}}")
    print(f"DONE: {fix_dir}")


if __name__ == "__main__":
    main()
