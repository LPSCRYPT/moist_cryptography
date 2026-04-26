#!/usr/bin/env python3
"""Off-chain ECIES decrypt for the v5 landmark_regions mint envelope.

The mint circuit packs all 8 region recolored byte buffers (7716 B total,
LSB-first 31-byte chunks) into 249 Field elements, then encrypts under
ECIES on Grumpkin against `recipient_pk`:

    c1     = caller_nonce . G                                  (ephemeral pk)
    shared = caller_nonce . recipient_pk = recipient_sk . c1   (ECDH)
    mask   = Poseidon2([shared.x, shared.y, 0, 0])[0]          (KDF)
    ks[i]  = Poseidon2([mask, b, 0, 0])[i mod 3], for b=i//3   (CTR keystream)
    c2[i]  = recolored_packed[i] + ks[i]                       (encrypt)
    ct_commit = poseidon2_sponge_249(c2)                       (binding hash)

Only `ct_commit, c1_x, c1_y, recipient_pk_x, recipient_pk_y` are in the
mint PI (positions 12..16). The 249-field `c2` is NOT emitted by the
contract today (Mint event extension is a follow-up); it must be
reconstructed off-chain from the witness by anyone who held the original
plaintext or who re-encrypts under a known caller_nonce.

This module provides:
    - `encrypt_mint_envelope(...)`: deterministic re-encrypt from witness,
      so we can verify ct_commit matches the on-chain PI.
    - `decrypt_mint_envelope(...)`: ECIES decrypt: takes recipient_sk +
      c1 + c2, recovers `recolored_packed[249]` then unpacks back to the
      8 per-region byte buffers, suitable for byte-exact comparison
      against `mint_pipeline.compute_face_state(...)`.

Reference circuit: circuits/landmark_regions/src/main.nr (v5, lines
1624-1664 for the encrypt path; lines 596-607 for sponge_249; lines
707-716 for keystream_249).

Layout (matches circuit's `all_pixels` global concatenation):
    region 0 (forehead) :  48 *  9 * 3 = 1296 bytes  -> all_pixels[   0..1296]
    region 1 (eye_l)    :  33 *  8 * 3 =  792 bytes  -> all_pixels[1296..2088]
    region 2 (eye_r)    :  33 *  8 * 3 =  792 bytes  -> all_pixels[2088..2880]
    region 3 (nose)     :  24 * 11 * 3 =  792 bytes  -> all_pixels[2880..3672]
    region 4 (cheek_l)  :  14 * 19 * 3 =  798 bytes  -> all_pixels[3672..4470]
    region 5 (cheek_r)  :  14 * 19 * 3 =  798 bytes  -> all_pixels[4470..5268]
    region 6 (mouth)    :  48 *  9 * 3 = 1296 bytes  -> all_pixels[5268..6564]
    region 7 (chin)     :  48 *  8 * 3 = 1152 bytes  -> all_pixels[6564..7716]
                                          --------
                                           7716 = 31 * 248 + 28

Packing into 249 Fields:
    For i in 0..248: recolored_packed[i] = sum(all_pixels[i*31+j] * 256^j for j in 0..31)
    recolored_packed[248] = sum(all_pixels[7688+j] * 256^j for j in 0..28)

Performance: each Poseidon2 permutation shells out to `nargo execute`,
~100ms per call. Encrypt or decrypt of one envelope needs 1 (mask) +
83 (keystream) + 84 (sponge) = 168 perms ~= 17s. Acceptable for a
validation script that runs a handful of times.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from secret_inbox import (  # noqa: E402
    G,
    P,
    ec_mul,
    is_on_curve,
    poseidon2_state,
)


# -----------------------------------------------------------------------------
# Layout constants (must match landmark_regions circuit & mint_pipeline.py)
# -----------------------------------------------------------------------------

REGION_BYTES = (1296, 792, 792, 792, 798, 798, 1296, 1152)
ALL_PIXELS_BYTES = sum(REGION_BYTES)  # 7716
assert ALL_PIXELS_BYTES == 7716

CT_FIELDS = 249              # c2 length
HEAD_BYTES_PER_FIELD = 31    # bytes per Field for fields 0..247
TAIL_BYTES = 28              # bytes packed into field 248
assert HEAD_BYTES_PER_FIELD * (CT_FIELDS - 1) + TAIL_BYTES == ALL_PIXELS_BYTES


# -----------------------------------------------------------------------------
# Poseidon2 helpers built on the single-permutation shell-out
# -----------------------------------------------------------------------------

def _perm(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """One Poseidon2 4-element permutation. Shells out via secret_inbox."""
    return poseidon2_state(a, b, c, d)


def poseidon2_hash_2(x: int, y: int) -> int:
    """Match circuit's `poseidon2_hash_2`: take state[0] of perm([x, y, 0, 0])."""
    return _perm(x, y, 0, 0)[0]


def poseidon2_keystream_249(k: int) -> list[int]:
    """Match circuit's `poseidon2_keystream_249` exactly.

    For b in 0..83:
        block_state = perm([k, b, 0, 0])
        ks[3b], ks[3b+1], ks[3b+2] = block_state[0], [1], [2]

    Returns 249 Fields.
    """
    ks: list[int] = [0] * CT_FIELDS
    for b in range(83):
        block = _perm(k, b, 0, 0)
        ks[b * 3]     = block[0]
        ks[b * 3 + 1] = block[1]
        ks[b * 3 + 2] = block[2]
    return ks


def poseidon2_sponge_249(elems: list[int]) -> int:
    """Match circuit's `poseidon2_sponge_249`: rate=3, capacity=1, sentinel=1.

    249 / 3 = 83 full absorb blocks, no tail. Final padding block adds
    sentinel=1 to state[0] (an empty pad block, Noir convention).
    """
    if len(elems) != CT_FIELDS:
        raise ValueError(f"sponge_249 needs {CT_FIELDS} elements, got {len(elems)}")
    s0, s1, s2, s3 = 0, 0, 0, 0
    for b in range(83):
        s0 = (s0 + elems[b * 3])     % P
        s1 = (s1 + elems[b * 3 + 1]) % P
        s2 = (s2 + elems[b * 3 + 2]) % P
        s0, s1, s2, s3 = _perm(s0, s1, s2, s3)
    # Sentinel padding block
    s0 = (s0 + 1) % P
    s0, s1, s2, s3 = _perm(s0, s1, s2, s3)
    return s0


# -----------------------------------------------------------------------------
# Plaintext <-> 249-Field codec (matches mint circuit lines 1624-1640)
# -----------------------------------------------------------------------------

def pack_recolored_to_fields(all_pixels: bytes) -> list[int]:
    """all_pixels (7716 B) -> 249 Field elements, LSB-first 31-byte chunks.

    Field i in [0, 247]: int.from_bytes(all_pixels[i*31:(i+1)*31], "little")
    Field 248         : int.from_bytes(all_pixels[7688:7716], "little")  (28 B)
    """
    if len(all_pixels) != ALL_PIXELS_BYTES:
        raise ValueError(
            f"all_pixels: expected {ALL_PIXELS_BYTES} bytes, got {len(all_pixels)}"
        )
    out = [0] * CT_FIELDS
    for i in range(CT_FIELDS - 1):
        out[i] = int.from_bytes(
            all_pixels[i * HEAD_BYTES_PER_FIELD : (i + 1) * HEAD_BYTES_PER_FIELD],
            "little",
        )
    tail_off = HEAD_BYTES_PER_FIELD * (CT_FIELDS - 1)
    out[CT_FIELDS - 1] = int.from_bytes(
        all_pixels[tail_off : tail_off + TAIL_BYTES], "little",
    )
    return out


def unpack_fields_to_recolored(packed: list[int]) -> bytes:
    """Inverse of pack_recolored_to_fields. Recovers 7716 raw bytes.

    Validates that each field fits in its declared byte width to catch
    decrypt-with-wrong-key garbage early (real packed values are never
    larger than 256^31 for head fields, 256^28 for the tail).
    """
    if len(packed) != CT_FIELDS:
        raise ValueError(f"packed: expected {CT_FIELDS} fields, got {len(packed)}")
    head_lim = 1 << (8 * HEAD_BYTES_PER_FIELD)
    tail_lim = 1 << (8 * TAIL_BYTES)
    out = bytearray(ALL_PIXELS_BYTES)
    for i in range(CT_FIELDS - 1):
        v = packed[i] % P
        if v >= head_lim:
            raise ValueError(
                f"packed[{i}] = {hex(v)} exceeds 31-byte range (decrypt with "
                "wrong key, or witness corrupted?)"
            )
        out[i * HEAD_BYTES_PER_FIELD : (i + 1) * HEAD_BYTES_PER_FIELD] = (
            v.to_bytes(HEAD_BYTES_PER_FIELD, "little")
        )
    v_tail = packed[CT_FIELDS - 1] % P
    if v_tail >= tail_lim:
        raise ValueError(
            f"packed[{CT_FIELDS - 1}] = {hex(v_tail)} exceeds {TAIL_BYTES}-byte "
            "range (decrypt with wrong key, or witness corrupted?)"
        )
    tail_off = HEAD_BYTES_PER_FIELD * (CT_FIELDS - 1)
    out[tail_off : tail_off + TAIL_BYTES] = v_tail.to_bytes(TAIL_BYTES, "little")
    return bytes(out)


def split_into_regions(all_pixels: bytes) -> list[bytes]:
    """Split flat all_pixels (7716 B) into the 8 per-region byte buffers."""
    if len(all_pixels) != ALL_PIXELS_BYTES:
        raise ValueError(
            f"all_pixels: expected {ALL_PIXELS_BYTES} bytes, got {len(all_pixels)}"
        )
    out: list[bytes] = []
    off = 0
    for n in REGION_BYTES:
        out.append(all_pixels[off : off + n])
        off += n
    return out


def join_regions(per_region: Iterable[bytes]) -> bytes:
    """Inverse of split_into_regions. Validates per-region byte counts."""
    parts: list[bytes] = []
    for i, b in enumerate(per_region):
        if len(b) != REGION_BYTES[i]:
            raise ValueError(
                f"region {i}: expected {REGION_BYTES[i]} bytes, got {len(b)}"
            )
        parts.append(b)
    return b"".join(parts)


# -----------------------------------------------------------------------------
# ECIES envelope: encrypt + decrypt
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class MintEnvelope:
    """Off-chain reconstruction of the mint circuit's ECIES output."""
    c1_x: int
    c1_y: int
    c2: list[int]           # 249 Fields
    ct_commit: int          # poseidon2_sponge_249(c2)


def encrypt_mint_envelope(
    *,
    caller_nonce: int,
    recipient_pk_x: int,
    recipient_pk_y: int,
    recolored_packed: list[int],
) -> MintEnvelope:
    """Reproduce the mint circuit's ECIES envelope from the witness.

    Used by the validation script to confirm that the in-PI `ct_commit`
    is recoverable from `mint_pipeline` output -- i.e. that the Python
    pipeline's recolored bytes really do encrypt to the same value the
    circuit committed to.
    """
    if len(recolored_packed) != CT_FIELDS:
        raise ValueError(
            f"recolored_packed: expected {CT_FIELDS} fields, got {len(recolored_packed)}"
        )
    if not is_on_curve(recipient_pk_x, recipient_pk_y):
        raise ValueError("recipient_pk is off-curve")

    c1 = ec_mul(G, caller_nonce)
    if c1 is None:
        raise RuntimeError("c1 is identity; choose a different caller_nonce")
    shared = ec_mul((recipient_pk_x, recipient_pk_y), caller_nonce)
    if shared is None:
        raise RuntimeError("ECDH shared point is identity (degenerate witness)")

    mask = poseidon2_hash_2(shared[0], shared[1])
    ks = poseidon2_keystream_249(mask)
    c2 = [(recolored_packed[i] + ks[i]) % P for i in range(CT_FIELDS)]
    ct_commit = poseidon2_sponge_249(c2)
    return MintEnvelope(c1_x=c1[0], c1_y=c1[1], c2=c2, ct_commit=ct_commit)


def decrypt_mint_envelope(
    *,
    recipient_sk: int,
    c1_x: int,
    c1_y: int,
    c2: list[int],
) -> list[int]:
    """Inverse: recover `recolored_packed[249]` from c2 and recipient_sk.

    Caller is responsible for verifying ct_commit == sponge_249(c2)
    before calling (otherwise garbage in -> garbage out).
    """
    if len(c2) != CT_FIELDS:
        raise ValueError(f"c2: expected {CT_FIELDS} fields, got {len(c2)}")
    if not is_on_curve(c1_x, c1_y):
        raise ValueError("c1 is off-curve (corrupt envelope)")

    shared = ec_mul((c1_x, c1_y), recipient_sk)
    if shared is None:
        raise RuntimeError("ECDH shared point is identity (degenerate envelope)")

    mask = poseidon2_hash_2(shared[0], shared[1])
    ks = poseidon2_keystream_249(mask)
    return [(c2[i] - ks[i]) % P for i in range(CT_FIELDS)]
