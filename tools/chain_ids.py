"""Chain-aware shadowId / featureNftId derivation.

Mirrors the on-chain derivation in `ShadowToken.sol` and `FeatureNFT.sol`:

    shadowId = keccak256(abi.encode(DOMAIN_SHADOW,
                                    block.chainid,
                                    faceOriginId)) % FR_MOD

    featureNftId = keccak256(abi.encode(DOMAIN_FEATURE,
                                        block.chainid,
                                        originShadowId,
                                        originSlotIdx,
                                        mintCounter)) % FR_MOD

The chainId binding (added in Stage J) prevents cross-chain proof replay:
the same proof generated against chain A's shadowId will fail PI[0] on chain
B because chain B derives a different shadowId for the same faceOriginId.

Common chain ids:
    31337  -> Anvil / Forge default
    84532  -> Base Sepolia
    11155111 -> Ethereum Sepolia (used by ShadowMirrorL1)
"""
from __future__ import annotations

from Crypto.Hash import keccak

FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

DOMAIN_SHADOW_BYTES  = keccak.new(digest_bits=256, data=b"OMP_SHADOW_TOKEN_v2").digest()
DOMAIN_FEATURE_BYTES = keccak.new(digest_bits=256, data=b"OMP_FEATURE_NFT_v2").digest()

ANVIL_CHAIN_ID         = 31337
BASE_SEPOLIA_CHAIN_ID  = 84532
ETH_SEPOLIA_CHAIN_ID   = 11155111


def shadow_id_for(face_origin_id: int, chain_id: int) -> int:
    """Match ShadowToken.shadowIdOf(bytes32) on chain `chain_id`."""
    enc = (DOMAIN_SHADOW_BYTES
           + chain_id.to_bytes(32, "big")
           + face_origin_id.to_bytes(32, "big"))
    h = keccak.new(digest_bits=256, data=enc)
    return int.from_bytes(h.digest(), "big") % FR_MOD


def feature_nft_id_for(origin_shadow_id: int, origin_slot_idx: int,
                        mint_counter: int, chain_id: int) -> int:
    """Match FeatureNFT.mintFromExtraction's id derivation on chain `chain_id`."""
    enc = (DOMAIN_FEATURE_BYTES
           + chain_id.to_bytes(32, "big")
           + origin_shadow_id.to_bytes(32, "big")
           + origin_slot_idx.to_bytes(32, "big")  # uint8 padded
           + mint_counter.to_bytes(32, "big"))    # uint64 padded
    h = keccak.new(digest_bits=256, data=enc)
    return int.from_bytes(h.digest(), "big") % FR_MOD
