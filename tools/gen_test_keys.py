#!/usr/bin/env python3
"""Generate fresh random Grumpkin keypairs for the phase 2 test fixtures.

Replaces the legacy anvil-seed accounts (which are publicly known and have
acquired EIP-7702 delegation hijacks on Base Sepolia). Each keypair is a
derived Grumpkin sk + the corresponding Ethereum-EOA address (derived by
secp256k1 from the same 32-byte seed for convenience -- see note below).

Note on the dual-key setup: the proof system uses Grumpkin (BN254 base) for
ECIES; the EVM uses secp256k1 for tx signing. We need BOTH a Grumpkin sk
(for ECIES decryption of received c2) and a secp256k1 sk (to call ownership-
gated entry points like transferFeature). We pick INDEPENDENT random 32-byte
seeds for each role, since Grumpkin and secp256k1 sks have different valid
ranges.

Output: phase2/harness/test_keys.json
"""
from __future__ import annotations

import json
import secrets
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from secret_inbox import G, GRUMPKIN_ORDER, ec_mul  # noqa: E402

OUT = REPO / "test_keys.json"

# Three test roles for the e2e suite. Names match the legacy fixtures so we
# can drop these in by name without touching downstream consumers.
ROLES = ["bob", "carol", "dave"]


def random_grumpkin_sk() -> int:
    """Uniform random in [1, GRUMPKIN_ORDER - 1]."""
    return secrets.randbelow(GRUMPKIN_ORDER - 1) + 1


def random_secp256k1_seed() -> bytes:
    """32 random bytes; cast wallet treats as the Ethereum private key."""
    return secrets.token_bytes(32)


def address_from_secp_sk(sk_hex: str) -> str:
    """Derive 0x-prefixed checksum address from a 32-byte secp256k1 sk."""
    out = subprocess.check_output(
        ["cast", "wallet", "address", "--private-key", sk_hex],
        text=True,
    )
    return out.strip()


def main() -> int:
    data = {"roles": {}, "comment": (
        "Generated with secrets.token_bytes / randbelow. Each role has BOTH a "
        "Grumpkin sk for ECIES + a secp256k1 sk for EVM tx signing. The "
        "addresses below are fresh, never broadcast, never delegated under "
        "EIP-7702. Use them for phase 2 test fixtures only."
    )}

    for role in ROLES:
        # Grumpkin keypair (for ECIES)
        gk_sk = random_grumpkin_sk()
        gk_pk = ec_mul(G, gk_sk)
        # secp256k1 keypair (for EVM tx signing)
        sk_secp_bytes = random_secp256k1_seed()
        sk_secp_hex = "0x" + sk_secp_bytes.hex()
        addr = address_from_secp_sk(sk_secp_hex)

        data["roles"][role] = {
            "grumpkin_sk":   hex(gk_sk),
            "grumpkin_pk_x": hex(gk_pk[0]),
            "grumpkin_pk_y": hex(gk_pk[1]),
            "secp_sk":       sk_secp_hex,
            "address":       addr,
        }
        print(f"  {role:5s} addr={addr}  gk_sk={hex(gk_sk)[:18]}...")

    OUT.write_text(json.dumps(data, indent=2) + "\n")
    print(f"\nWrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
