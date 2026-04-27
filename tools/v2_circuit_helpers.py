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


# ---- palette_reveal_v2 helpers ----
#
# Mirrors circuits/palette_reveal_v2/src/main.nr byte-for-byte. Used by
# build_atomic_mint_fixture (to compute paletteCommit + salt envelope at
# mint) and build_palette_reveal_fixture (to drive the reveal proof).

PALETTE_LEN = 16
PACKED_LEN = 8


def sponge_palette_salt(palette: list[int], salt: int) -> int:
    """Mirrors circuit's `sponge_palette_salt`: 5 full rate-3 absorbs
    over palette[0..15] (15 elements) + 1 partial absorb of (palette[15],
    salt, 0) + sentinel pad. Total 7 permutations.
    """
    if len(palette) != PALETTE_LEN:
        raise ValueError(f"palette must be {PALETTE_LEN} fields, got {len(palette)}")
    s0, s1, s2, s3 = 0, 0, 0, 0
    for b in range(5):
        s0 = (s0 + palette[b * 3]) % P
        s1 = (s1 + palette[b * 3 + 1]) % P
        s2 = (s2 + palette[b * 3 + 2]) % P
        s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    s0 = (s0 + palette[15]) % P
    s1 = (s1 + salt) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    s0 = (s0 + 1) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    return s0


def encode_palette_packed(palette: list[int]) -> list[int]:
    """Pack 16 24-bit colors into 8 Fields:
       packed[i] = palette[2i] + palette[2i+1] * 2^24.
    Each color must fit in 24 bits; higher bits are silently truncated
    by the contract's RGB unpack but are still part of the proof's binding,
    so callers MUST pass clean 24-bit values.
    """
    if len(palette) != PALETTE_LEN:
        raise ValueError(f"palette must be {PALETTE_LEN} fields, got {len(palette)}")
    packed = []
    for i in range(PACKED_LEN):
        lo = palette[2 * i] & 0xFFFFFF
        hi = palette[2 * i + 1] & 0xFFFFFF
        packed.append((lo + hi * (1 << 24)) % P)
    return packed


def encrypt_salt_v2(salt: int, owner_pk: tuple[int, int], r: int
                    ) -> tuple[tuple[int, int], int, int]:
    """Single-Field ECIES envelope for the palette salt.

    Returns (c1, salt_ct, salt_k) where:
       c1     = r * G                       (ephemeral public point)
       shared = r * owner_pk                (= owner_sk * c1)
       salt_k = poseidon2(shared.x, shared.y)
       salt_ct = (salt + salt_k) mod P     (single-Field CTR)

    The owner decrypts via decrypt_salt_v2(c1, salt_ct, owner_sk).
    """
    c1 = ec_mul(G, r)
    shared = ec_mul(owner_pk, r)
    if c1 is None or shared is None:
        raise ValueError("ec_mul produced identity")
    salt_k = poseidon2_hash_2(shared[0], shared[1])
    salt_ct = (salt + salt_k) % P
    return c1, salt_ct, salt_k


def decrypt_salt_v2(c1: tuple[int, int], salt_ct: int, owner_sk: int) -> int:
    """Inverse of encrypt_salt_v2: returns the recovered salt as a Field."""
    shared = ec_mul(c1, owner_sk)
    if shared is None:
        raise ValueError("ec_mul produced identity")
    salt_k = poseidon2_hash_2(shared[0], shared[1])
    return (salt_ct - salt_k) % P


# ---- field <-> hex ----

def fhex(v: int) -> str:
    return f'"{hex(v % P)}"'


def bx32(v: int) -> str:
    """Zero-padded 0x-prefix 32-byte hex literal (66 chars total).

    Forge's `vm.parseJsonBytes32` requires exactly 64 hex digits; Python's
    `hex()` strips leading zeros. Use this for any field emitted into
    fixture meta.json that's read back as `bytes32`.
    """
    return "0x" + format(v % P, "064x")


# ---- sponge_16 (matches both zindex_commit and transfer_shadow_v2) ----

def sponge_16(elems: list[int]) -> int:
    """5 full rate-3 absorb blocks (e[0..15]) + final partial absorb of e[15] + sentinel."""
    if len(elems) != 16:
        raise ValueError(f"sponge_16 needs 16 elems, got {len(elems)}")
    s0, s1, s2, s3 = 0, 0, 0, 0
    for b in range(5):
        s0 = (s0 + elems[b * 3]) % P
        s1 = (s1 + elems[b * 3 + 1]) % P
        s2 = (s2 + elems[b * 3 + 2]) % P
        s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    s0 = (s0 + elems[15]) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    s0 = (s0 + 1) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    return s0


# ---- transfer_shadow_v2 constants (mirror circuit globals) ----

# domain-separation tag for the transfer chain-step. matches circuit:
#   TRANSFER_TAG: Field = 0x1ad75ff_a_e4_711a5_fe_a7_e_ed
TRANSFER_TAG = 0x1ad75ffae4711a5fea7eed


def transfer_chain_step(prev_chain_tip: int, recipient_pk_x: int, recipient_pk_y: int,
                        new_count: int, slot_idx: int) -> int:
    """Mirror transfer_shadow_v2's per-slot chain-tip extension."""
    return sponge_6(prev_chain_tip, TRANSFER_TAG, recipient_pk_x, recipient_pk_y,
                    new_count, slot_idx)


# ---- landmark_regions_v2 (mint) constants + helpers ----

# domain-separation tag for the mint chain-tip. matches circuit:
#   MINT_TAG: Field = 0x9100_15_e_5_a_b_a_d_4_3_e_0_a_d_d_e_d_d_a_7_a
# and Solidity ShadowToken.MINT_TAG byte-for-byte.
MINT_TAG = 0x910015e5abad43e0addedda7a


def sponge_4(a: int, b: int, c: int, d: int) -> int:
    """4-element absorb: 1 rate-3 block + rate-1 partial absorb + sentinel.

    Mirrors landmark_regions_v2's sponge_4. Used for chain_tip[i] =
    sponge_4(MINT_TAG, origin_face_id, owner_pk_x, owner_pk_y)."""
    s0, s1, s2, s3 = 0, 0, 0, 0
    s0 = (s0 + a) % P
    s1 = (s1 + b) % P
    s2 = (s2 + c) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    s0 = (s0 + d) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    s0 = (s0 + 1) % P
    s0, s1, s2, s3 = poseidon2_perm(s0, s1, s2, s3)
    return s0


def sponge_8_pad16(elems: list[int]) -> int:
    """Fold 8 fields by zero-padding to 16 and feeding through sponge_16.

    Reuses on-chain Poseidon2YulSponge16 (the contract feeds the same
    16-field buffer to its yulSponge16 staticcall)."""
    if len(elems) != 8:
        raise ValueError(f"sponge_8_pad16 needs 8 elems, got {len(elems)}")
    return sponge_16(list(elems) + [0] * 8)


def mint_chain_step(origin_face_id: int, owner_pk_x: int, owner_pk_y: int) -> int:
    """Mirror landmark_regions_v2's per-slot mint chain-tip seed."""
    return sponge_4(MINT_TAG, origin_face_id, owner_pk_x, owner_pk_y)

