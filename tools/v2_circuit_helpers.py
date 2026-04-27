"""v2 circuit helpers.

Pure-Python primitives for the v2 mutate_slot / shadow_t10 / zindex_commit /
solve_shadow circuits. All Poseidon2 permutations shell out to nargo via
`secret_inbox.poseidon2_state`. Same `P` and Grumpkin curve as v1.

The constants (PLAINTEXT_FIELDS, etc.) match the circuits' globals
byte-for-byte. If a constant changes here it must change in the matching
.nr file; we test the contract against this.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from secret_inbox import P, GRUMPKIN_ORDER, G, ec_mul, is_on_curve, poseidon2_state  # noqa: E402

# ---- v2 size constants (mirror circuits/mutate_slot/src/main.nr) ----

PLAINTEXT_FIELDS = 39
CANVAS_W = 48
CANVAS_H = 48


# ---- Poseidon2 sponge_39 (rate=3, capacity=1, sentinel=1) ----

def poseidon2_perm(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    return poseidon2_state(a % P, b % P, c % P, d % P)


def sponge_39(elems: list[int]) -> int:
    """Mirrors circuits/mutate_slot/src/main.nr's `sponge_39`.

    Layout: 13 full rate-3 absorb blocks (e[0..39]); no tail; sentinel pad
    after the last absorb. 39 = 13 * 3 so the on-chain Yul sponge can hash
    the c2 calldata directly (39 fields = 1248 bytes = 13 * 96).
    """
    if len(elems) != PLAINTEXT_FIELDS:
        raise ValueError(f"sponge_39 needs {PLAINTEXT_FIELDS} elems, got {len(elems)}")
    s0, s1, s2, s3 = 0, 0, 0, 0
    for b in range(13):
        s0 = (s0 + elems[b * 3]) % P
        s1 = (s1 + elems[b * 3 + 1]) % P
        s2 = (s2 + elems[b * 3 + 2]) % P
        s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    # sentinel pad
    s0 = (s0 + 1) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    return s0


def sponge_6(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    """Mirrors `sponge_6`: 2 full absorbs + sentinel pad."""
    s0, s1, s2, s3 = 0, 0, 0, 0
    s0 = (s0 + a) % P
    s1 = (s1 + b) % P
    s2 = (s2 + c) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    s0 = (s0 + d) % P
    s1 = (s1 + e) % P
    s2 = (s2 + f) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    s0 = (s0 + 1) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    return s0


def poseidon2_hash_2(x: int, y: int) -> int:
    return poseidon2_perm(x, y, 0, 0)[0]


# ---- keystream_39 (CTR mode, matches circuit's `keystream_39`) ----

def keystream_39(k: int) -> list[int]:
    ks: list[int] = [0] * PLAINTEXT_FIELDS
    for b in range(13):
        block = poseidon2_perm(k, b, 0, 0)
        ks[b * 3]     = block[0]
        ks[b * 3 + 1] = block[1]
        ks[b * 3 + 2] = block[2]
    return ks


# ---- pose packing ----
#
# Pose is a 64-bit value laid out in plaintext byte 0..7 LSB-first:
#   bits 0..5    x  (uint6)
#   bits 6..11   y  (uint6)
#   bits 12..27  scaleQ88  (uint16; 256 = 1.0)
#   bits 28..43  cosQ15    (signed 16-bit)
#   bits 44..59  sinQ15    (signed 16-bit)
#   bits 60..63  free
#
# v2 uses a conservative axis-aligned containment check; for v2 fixtures we
# pin pose to identity (no rotation, no scale change) and rely on (w, h) +
# (x, y) for the canvas-containment proof.

def pack_pose(x: int, y: int, scale_q88: int = 256, cos_q15: int = 32767, sin_q15: int = 0) -> int:
    if not (0 <= x < 64 and 0 <= y < 64):
        raise ValueError(f"pose x/y out of range: ({x}, {y})")
    pose = (x & 0x3F) | ((y & 0x3F) << 6) | ((scale_q88 & 0xFFFF) << 12)
    pose |= ((cos_q15 & 0xFFFF) << 28) | ((sin_q15 & 0xFFFF) << 44)
    return pose & 0xFFFFFFFFFFFFFFFF


# ---- plaintext encode/decode ----
#
# Plaintext layout (39 fields x 31 bytes = 1209 bytes available; field 38 is
#   bytes 0..7   pose (uint64 LE)
#   byte 8       w (uint8)
#   byte 9       h (uint8)
#   bytes 10..   palette indices (4 bits per pixel, two pixels per byte)
#   ... zero pad to field boundary ...

def encode_plaintext_v2(pose: int, w: int, h: int, indices: list[int]) -> list[int]:
    """Encode (pose, w, h, palette indices) into 39 packed Fields (last field zero pad)."""
    if not (1 <= w <= CANVAS_W and 1 <= h <= CANVAS_H):
        raise ValueError(f"dims out of range: ({w}, {h})")
    expected = w * h
    if len(indices) != expected:
        raise ValueError(f"indices length {len(indices)} != w*h {expected}")
    if any(i < 0 or i > 15 for i in indices):
        raise ValueError("palette indices must be in [0, 16)")
    # Pack 4-bit indices, two per byte (low nibble = first index).
    nbytes = (expected + 1) // 2
    pixel_bytes = bytearray(nbytes)
    for i, idx in enumerate(indices):
        pixel_bytes[i // 2] |= (idx & 0xF) << (4 * (i & 1))

    plaintext_bytes = bytearray(PLAINTEXT_FIELDS * 31)
    plaintext_bytes[0:8] = pose.to_bytes(8, "little")
    plaintext_bytes[8] = w
    plaintext_bytes[9] = h
    plaintext_bytes[10:10 + nbytes] = pixel_bytes

    # Pack into Fields: each field gets 31 LE bytes.
    fields: list[int] = []
    for f in range(PLAINTEXT_FIELDS):
        chunk = plaintext_bytes[f * 31:(f + 1) * 31]
        fields.append(int.from_bytes(chunk, "little"))
    return fields


def decode_plaintext_v2(fields: list[int]) -> tuple[int, int, int, list[int]]:
    """Inverse of encode_plaintext_v2."""
    if len(fields) != PLAINTEXT_FIELDS:
        raise ValueError(f"expected {PLAINTEXT_FIELDS} fields, got {len(fields)}")
    plaintext_bytes = bytearray(PLAINTEXT_FIELDS * 31)
    for f, val in enumerate(fields):
        chunk = (val & ((1 << (8 * 31)) - 1)).to_bytes(31, "little")
        plaintext_bytes[f * 31:(f + 1) * 31] = chunk
    pose = int.from_bytes(plaintext_bytes[0:8], "little")
    w = plaintext_bytes[8]
    h = plaintext_bytes[9]
    nbytes = (w * h + 1) // 2
    indices: list[int] = []
    for i in range(w * h):
        b = plaintext_bytes[10 + (i // 2)]
        if i & 1:
            indices.append((b >> 4) & 0xF)
        else:
            indices.append(b & 0xF)
    return pose, w, h, indices


# ---- liveStateHash, chainTip ----

def live_state_hash(state_commit: int, ct_commit: int, c1_x: int, c1_y: int,
                    mutation_count: int, chain_tip: int) -> int:
    return sponge_6(state_commit, ct_commit, c1_x, c1_y, mutation_count, chain_tip)


def chain_step(prev_chain_tip: int, new_state_commit: int, new_ct_commit: int,
               new_count: int, origin_face_id: int, slot_idx: int) -> int:
    return sponge_6(prev_chain_tip, new_state_commit, new_ct_commit,
                    new_count, origin_face_id, slot_idx)


# ---- ECIES (Pohlig variant matching circuit) ----
#
# encrypt(plaintext, owner_pk, r):
#     c1 = r * G
#     shared = r * owner_pk = sk * c1
#     k = poseidon2_hash_2(shared.x, shared.y)
#     keystream = keystream_39(k)
#     c2 = plaintext + keystream  (Field-wise, mod P)
#
# Note: in v1's extract_slot, c2_scalar = k + mask was a separate PI.
# In v2's mutate_slot we drop c2_scalar (k is derived per-c1 deterministically;
# the receiver can recover k from owner_sk + c1 directly via ECDH).

def ecies_encrypt_v2(plaintext_fields: list[int], owner_pk: tuple[int, int], r: int
                     ) -> tuple[tuple[int, int], list[int], int]:
    if len(plaintext_fields) != PLAINTEXT_FIELDS:
        raise ValueError("plaintext must be 38 fields")
    c1 = ec_mul(G, r)
    shared = ec_mul(owner_pk, r)
    if c1 is None or shared is None:
        raise ValueError("ec_mul produced identity")
    k = poseidon2_hash_2(shared[0], shared[1])
    ks = keystream_39(k)
    c2 = [(p + s) % P for p, s in zip(plaintext_fields, ks)]
    return c1, c2, k


def ecies_decrypt_v2(c1: tuple[int, int], c2: list[int], owner_sk: int) -> tuple[list[int], int]:
    shared = ec_mul(c1, owner_sk)
    if shared is None:
        raise ValueError("ec_mul produced identity")
    k = poseidon2_hash_2(shared[0], shared[1])
    ks = keystream_39(k)
    plaintext = [(c - s) % P for c, s in zip(c2, ks)]
    return plaintext, k


# ---- field <-> hex ----

def fhex(v: int) -> str:
    return f'"{hex(v % P)}"'
