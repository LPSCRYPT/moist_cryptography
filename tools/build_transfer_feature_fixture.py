#!/usr/bin/env python3
# **STALE — v1 fixture builder.** v2 transferFeature pending.
"""Generate a transfer_feature fixture: an extracted FeatureNFT re-encrypted
to a new owner.

Pre-requisites: an existing extract_slot fixture (carol owns the feature).
This script transfers it from carol -> dave.

Usage:
    python3 build_transfer_feature_fixture.py [--src alice0_slot3_to_carol] \
                                               [--dst carol_to_dave]
"""
from __future__ import annotations

import argparse, hashlib, json, subprocess, sys, time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from build_extract_slot_fixture import poseidon2_keystream_42, poseidon2_sponge_42  # noqa: E402
from mint_decrypt import poseidon2_hash_2, P  # noqa: E402
from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # noqa: E402

ROOT = REPO.parent
CIRCUIT_DIR = ROOT / "circuits" / "transfer_feature"
PROVER_TOML = CIRCUIT_DIR / "Prover.toml"
EXTRACT_ROOT = ROOT / "contracts" / "test" / "fixtures" / "extract_slot"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "transfer_feature"

NARGO = Path.home() / ".nargo" / "bin" / "nargo"
BB = Path.home() / ".bb" / "bb"


def deterministic_seed(seed: bytes, label: bytes) -> int:
    h = hashlib.sha256(b"OMP_TF_FIXTURE_v1:" + label + b":" + seed).digest()
    return (int.from_bytes(h, "big") % (GRUMPKIN_ORDER - 1)) + 1


def hex_field(v: int) -> str: return f'"{hex(v)}"'
def render_array(name: str, vs: list[int]) -> str:
    return f"{name} = [{', '.join(hex_field(v) for v in vs)}]"


def run(cmd, cwd, timeout=600):
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:]); print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {elapsed:.1f}s")
    return p.stdout, elapsed


def main() -> int:
    # -- Binding requirement -------------------------------------------------
    # The transfer_feature circuit's PI[0] is `feature_nft_id` (a Field). On
    # chain, FeatureNFT.transferEncrypted compares it against the ERC721 token
    # id minted by FeatureNFT.mintFromExtraction:
    #     featureNftId = uint256(keccak256(abi.encode(
    #         DOMAIN_FEATURE, originShadowId, originSlotIdx, mintCounter)))
    #     DOMAIN_FEATURE = keccak256("OMP_FEATURE_NFT_v2")
    # mintCounter is incremented BEFORE the hash, so the first extract on a
    # fresh deployment uses mintCounter=1. The proof's PI[0] must equal this
    # value reduced mod FR_MOD (the bn254 scalar / Noir Field modulus); the
    # contract has no explicit reduction so this only works when chainFid is
    # already < FR_MOD. Pass --feature-nft-id to override the default derivation
    # (e.g. when the chain test runs with a non-fresh deployment).
    # ------------------------------------------------------------------------

    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="alice0_slot3_to_carol",
                    help="Extract fixture seed (carol's source FeatureNFT)")
    ap.add_argument("--dst", default="carol_to_dave",
                    help="Transfer fixture seed (recipient: dave)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--skip-prove", action="store_true")
    ap.add_argument("--chain-id", type=int, default=31337,
                    help="Target chain id for featureNftId derivation")
    ap.add_argument("--recipient-sk", default=None,
                    help="Hex Grumpkin sk for the feature recipient (overrides deterministic)")
    ap.add_argument("--feature-nft-id", default=None,
                    help="Hex chain-side featureNftId (uint256). If omitted, derive\n"
                         "deterministically assuming this is the FIRST extract on a\n"
                         "fresh FeatureNFT deployment (mintCounter=1).")
    args = ap.parse_args()

    src_dir = EXTRACT_ROOT / args.src
    if not src_dir.exists():
        sys.exit(f"source extract_slot fixture not found at {src_dir}")
    dst_dir = Path(args.out) if args.out else FIXTURE_ROOT / args.dst
    dst_dir.mkdir(parents=True, exist_ok=True)
    seed_bytes = args.dst.encode()

    print("=" * 68)
    print(f"transfer_feature fixture: {args.src} -> {args.dst}")
    print("=" * 68)

    src = json.loads((src_dir / "fixture.json").read_text())
    carol_sk = int(src["carol_sk"], 16)
    feature_c2_bytes = (src_dir / "feature_c2.bin").read_bytes()
    feature_c2 = [int.from_bytes(feature_c2_bytes[i*32:(i+1)*32], "big") for i in range(42)]

    # Decrypt feature with carol's sk to recover plaintext.
    print("\n[1] Decrypt source feature_c2 with carol_sk")
    c1_x = int(src["c1_new_x"], 16); c1_y = int(src["c1_new_y"], 16)
    shared = ec_mul((c1_x, c1_y), carol_sk)
    k_mask = poseidon2_hash_2(shared[0], shared[1])
    c2_scalar = int(src["c2_scalar"], 16)
    feature_k_carol = (c2_scalar - k_mask) % P
    ks = poseidon2_keystream_42(feature_k_carol)
    feature_payload = [(feature_c2[i] - ks[i]) % P for i in range(42)]
    print(f"    decrypted feature payload OK")

    # Sanity: re-encrypt and check sponge_42 matches src.
    re_ct = [(feature_payload[i] + ks[i]) % P for i in range(42)]
    re_commit = poseidon2_sponge_42(re_ct)
    assert re_commit == int(src["feature_ct_commit"], 16), "carol decrypt round-trip mismatch"
    print(f"    sponge_42 round-trip OK")

    # Pick dave.
    print("\n[2] Derive dave recipient pk")
    if args.recipient_sk:
        dave_sk = int(args.recipient_sk, 16)
    else:
        dave_sk = deterministic_seed(seed_bytes, b"recipient_sk")
    dave_pk = ec_mul(G, dave_sk)
    dave_pk_x, dave_pk_y = dave_pk
    print(f"    dave pk.x: {hex(dave_pk_x)[:18]}...")

    # Generate new envelope.
    print("\n[3] New ECIES envelope to dave")
    new_r = deterministic_seed(seed_bytes, b"new_r")
    new_k = deterministic_seed(seed_bytes, b"new_k_seed")
    new_ks = poseidon2_keystream_42(new_k)
    new_c2 = [(feature_payload[i] + new_ks[i]) % P for i in range(42)]
    new_ct_commit = poseidon2_sponge_42(new_c2)

    c1_new = ec_mul(G, new_r)
    c1_new_x, c1_new_y = c1_new
    shared_new = ec_mul(dave_pk, new_r)
    new_k_mask = poseidon2_hash_2(shared_new[0], shared_new[1])
    new_c2_scalar = (new_k + new_k_mask) % P

    # Sanity: dave decrypts new_c2.
    dave_shared = ec_mul((c1_new_x, c1_new_y), dave_sk)
    dave_k_mask = poseidon2_hash_2(dave_shared[0], dave_shared[1])
    recovered_k = (new_c2_scalar - dave_k_mask) % P
    dave_ks = poseidon2_keystream_42(recovered_k)
    dave_recovered = [(new_c2[i] - dave_ks[i]) % P for i in range(42)]
    assert dave_recovered == feature_payload, "dave round-trip mismatch"
    print(f"    OK: dave can decrypt new_c2")

    # ----- Bind to chain-side featureNftId -----------------------------------
    # FeatureNFT.mintFromExtraction computes:
    #   featureNftId = uint256(keccak256(abi.encode(
    #       DOMAIN_FEATURE, originShadowId, originSlotIdx, mintCounter)))
    # where DOMAIN_FEATURE = keccak256("OMP_FEATURE_NFT_v2") and mintCounter is
    # incremented BEFORE the hash (so the first extract uses mintCounter=1).
    # originShadowId is the on-chain ERC721 token id, which ShadowToken stores
    # field-reduced (mod FR_MOD); see ShadowToken.FR_MOD comment. The Noir
    # circuit's PI[0] is a Field, so Prover.toml must receive chainFid % FR_MOD.
    FR_MOD = P  # secret_inbox.P == bn254 Fr modulus
    from chain_ids import feature_nft_id_for

    origin_shadow_id = int(src["shadow_id_field"], 16)  # already mod FR_MOD on-chain
    origin_slot_idx  = int(src["slot"])
    mint_counter     = 1  # first extract from a fresh FeatureNFT deployment
    derived_chain_fid = feature_nft_id_for(
        origin_shadow_id, origin_slot_idx, mint_counter, args.chain_id,
    )
    if args.feature_nft_id is not None:
        chain_fid = int(args.feature_nft_id, 16)
    else:
        chain_fid = derived_chain_fid
    feature_nft_id = chain_fid % FR_MOD  # PI[0] is a Field
    print(f"    chain featureNftId  : {hex(chain_fid)}")
    print(f"    PI[0] (mod FR_MOD)  : {hex(feature_nft_id)}")

    print("\n[4] Write Prover.toml")
    lines = [
        f'feature_nft_id = "{hex(feature_nft_id)}"',
        f'next_pk_x      = "{hex(dave_pk_x)}"',
        f'next_pk_y      = "{hex(dave_pk_y)}"',
        f'c1_x           = "{hex(c1_new_x)}"',
        f'c1_y           = "{hex(c1_new_y)}"',
        f'c2_scalar      = "{hex(new_c2_scalar)}"',
        f'new_ct_commit  = "{hex(new_ct_commit)}"',
        f'prev_ct_commit = "{src["feature_ct_commit"]}"',
        render_array("plaintext", feature_payload),
        f'prev_k         = "{hex(feature_k_carol)}"',
        f'new_k          = "{hex(new_k)}"',
        f'new_r          = "{hex(new_r)}"',
    ]
    PROVER_TOML.write_text("\n".join(lines) + "\n")

    print("\n[5] nargo execute")
    out, t_exec = run([NARGO, "execute", "--silence-warnings"], CIRCUIT_DIR, timeout=600)
    print(f"    {t_exec:.1f}s")

    if args.skip_prove:
        return 0

    print("\n[6] bb write_vk + prove")
    out, t_vk = run([BB, "write_vk", "-b", "target/transfer_feature.json", "-o", "target", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
    proof_dir = CIRCUIT_DIR / "target" / "proof"
    if proof_dir.exists():
        for f in proof_dir.iterdir(): f.unlink()
    out, t_prove = run([BB, "prove", "-b", "target/transfer_feature.json", "-w", "target/transfer_feature.gz", "-o", "target/proof", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=900)
    out, t_ver = run([BB, "verify", "-k", "target/vk", "-p", "target/proof/proof", "-i", "target/proof/public_inputs", "--verifier_target", "evm"], CIRCUIT_DIR, timeout=300)
    print(f"    write_vk: {t_vk:.1f}s, prove: {t_prove:.1f}s, verify: {t_ver:.1f}s")

    proof_bytes = (proof_dir / "proof").read_bytes()
    pi_bytes    = (proof_dir / "public_inputs").read_bytes()
    new_c2_bytes = b"".join(c.to_bytes(32, "big") for c in new_c2)

    (dst_dir / "proof").write_bytes(proof_bytes)
    (dst_dir / "public_inputs").write_bytes(pi_bytes)
    (dst_dir / "new_c2.bin").write_bytes(new_c2_bytes)

    fixture_meta = {
        "version": 1,
        "src": args.src,
        "dst": args.dst,
        "feature_nft_id": hex(feature_nft_id),
        "feature_nft_id_field": hex(feature_nft_id),  # PI[0] value (mod FR_MOD)
        "chain_feature_nft_id": hex(chain_fid),       # uint256 the chain mints
        "feature_nft_id_origin_shadow_id": hex(origin_shadow_id),
        "feature_nft_id_origin_slot_idx": origin_slot_idx,
        "feature_nft_id_mint_counter": mint_counter,
        "dave_sk": hex(dave_sk),
        "dave_pk_x": hex(dave_pk_x),
        "dave_pk_y": hex(dave_pk_y),
        "prev_ct_commit": src["feature_ct_commit"],
        "new_ct_commit": hex(new_ct_commit),
        "c1_new_x": hex(c1_new_x),
        "c1_new_y": hex(c1_new_y),
        "c2_scalar": hex(new_c2_scalar),
        "new_r": hex(new_r),
        "new_k": hex(new_k),
        "n_pi": 8,
    }
    (dst_dir / "fixture.json").write_text(json.dumps(fixture_meta, indent=2))
    print(f"\n    saved fixture to {dst_dir}/")

    # Generate verifier.sol
    print("\n[7] bb write_solidity_verifier")
    verifier_out = CIRCUIT_DIR / "target" / "TransferFeatureVerifier.sol"
    run([BB, "write_solidity_verifier", "-k", "target/vk", "-o", str(verifier_out)], CIRCUIT_DIR, timeout=300)
    forge_src = ROOT / "contracts" / "src" / "TransferFeatureVerifier.sol"
    text = verifier_out.read_text().replace("contract HonkVerifier", "contract TransferFeatureVerifier")
    forge_src.write_text(text)
    print(f"    wrote {forge_src}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
