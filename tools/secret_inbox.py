#!/usr/bin/env python3
"""secret_inbox: off-chain helpers for the SecretInbox contract.

Provides:
    - Grumpkin curve arithmetic in pure Python
    - Poseidon2 helpers via nargo subprocess (byte-identical to circuit)
    - ECIES encrypt / decrypt for N=32-field payloads
    - Plaintext <-> bytes codecs (for strings and arbitrary data)
    - A minimal CLI (keygen / register / send / read)

This module is deliberately self-contained. It shells out to `nargo` for
Poseidon2 and to `cast` for chain interaction. No heavy deps beyond the
Python stdlib.

Spec: docs/SECRET_INBOX.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable, Optional

# =============================================================================
# Grumpkin curve (y^2 = x^3 - 17 over BN254 scalar field)
# =============================================================================

#: BN254 scalar field modulus = Grumpkin base field.
P: int = 21888242871839275222246405745257275088548364400416034343698204186575808495617

#: Grumpkin curve order (= BN254 base field order).
GRUMPKIN_ORDER: int = 21888242871839275222246405745257275088696311157297823662689037894645226208583

#: Grumpkin generator point (per Noir stdlib).
Gx: int = 1
Gy: int = 17631683881184975370165255887551781615748388533673675138860
G: tuple[int, int] = (Gx, Gy)

#: Payload length in field elements. MUST match SecretInbox.sol's N and
#: circuits/_ecies_keystream_helper's N. Change all three together.
N: int = 32

assert (Gy * Gy) % P == (Gx ** 3 - 17) % P, "Grumpkin generator is off-curve"


def _modinv(a: int, p: int) -> int:
    return pow(a, p - 2, p)


def ec_add(p1: Optional[tuple[int, int]],
           p2: Optional[tuple[int, int]]) -> Optional[tuple[int, int]]:
    """Add two affine Grumpkin points. `None` represents the identity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 == y2:
            lam = (3 * x1 * x1) * _modinv(2 * y1, P) % P
        else:
            return None
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(point: tuple[int, int], scalar: int) -> Optional[tuple[int, int]]:
    """Scalar multiplication on Grumpkin. Uses double-and-add."""
    result: Optional[tuple[int, int]] = None
    addend = point
    s = scalar % GRUMPKIN_ORDER
    while s > 0:
        if s & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        s >>= 1
    return result


def is_on_curve(x: int, y: int) -> bool:
    """Check (x, y) satisfies y^2 = x^3 - 17 mod P."""
    if x >= P or y >= P or (x == 0 and y == 0):
        return False
    return (y * y) % P == (x ** 3 - 17) % P


# =============================================================================
# Poseidon2 helpers (shell out to nargo execute)
# =============================================================================

HERE = pathlib.Path(__file__).resolve().parent
# Helper circuits live at <repo-root>/circuits/_*_helper (sibling of tools/)
_CIRCUITS_ROOT = HERE.parent / "circuits"
_STATE_HELPER = _CIRCUITS_ROOT / "_poseidon2_state_helper"
_KEYSTREAM_HELPER = _CIRCUITS_ROOT / "_ecies_keystream_helper"

# Resolve nargo / bb from PATH first, fall back to default install locations.
# Override with NARGO_PATH / BB_PATH env vars or by editing this block.
import shutil  # noqa: E402  -- standard lib, kept local to this block
_NARGO_DEFAULT = pathlib.Path.home() / ".nargo" / "bin" / "nargo"
_BB_DEFAULT = pathlib.Path.home() / ".bb" / "bb"
NARGO = pathlib.Path(os.environ.get("NARGO_PATH") or shutil.which("nargo") or _NARGO_DEFAULT)
BB = pathlib.Path(os.environ.get("BB_PATH") or shutil.which("bb") or _BB_DEFAULT)
_ENV = {
    **os.environ,
    "PATH": f"{NARGO.parent}:{BB.parent}:{os.environ.get('PATH', '')}",
}


def _run(cmd: list[str], cwd: pathlib.Path, timeout: int = 120) -> str:
    r = subprocess.run(
        [str(c) for c in cmd], cwd=cwd, capture_output=True, text=True,
        timeout=timeout, env=_ENV,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"subprocess failed ({' '.join(str(c) for c in cmd)})\n"
            f"stdout: {r.stdout[-1000:]}\n"
            f"stderr: {r.stderr[-1000:]}"
        )
    return r.stdout.strip()


def _extract_outputs(stdout: str) -> list[str]:
    for line in stdout.split("\n"):
        if "Circuit output:" in line:
            return re.findall(r"0x[0-9a-f]+", line)
    return []


def _ensure_compiled(circuit_dir: pathlib.Path, pkg_name: str) -> None:
    target_json = circuit_dir / "target" / f"{pkg_name}.json"
    if not target_json.exists():
        _run([NARGO, "compile"], circuit_dir)


def poseidon2_state(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Poseidon2 permutation over [a, b, c, d], returning 4-element output."""
    _ensure_compiled(_STATE_HELPER, "_poseidon2_state_helper")
    (_STATE_HELPER / "Prover.toml").write_text(
        f'a = "{hex(a)}"\nb = "{hex(b)}"\nc = "{hex(c)}"\nd = "{hex(d)}"\n'
    )
    out = _run([NARGO, "execute"], _STATE_HELPER)
    vals = _extract_outputs(out)
    if len(vals) != 4:
        raise RuntimeError(f"expected 4 outputs from state helper, got {len(vals)}")
    return tuple(int(v, 16) for v in vals)  # type: ignore


def poseidon2_h2(x: int, y: int) -> int:
    """Poseidon2([x, y, 0, 0])[0] -- used as ECIES KDF."""
    return poseidon2_state(x, y, 0, 0)[0]


def keystream(k: int) -> list[int]:
    """Generate N=32 Poseidon2-CTR keystream elements from Field key `k`."""
    _ensure_compiled(_KEYSTREAM_HELPER, "_ecies_keystream_helper")
    (_KEYSTREAM_HELPER / "Prover.toml").write_text(f'k = "{hex(k)}"\n')
    out = _run([NARGO, "execute"], _KEYSTREAM_HELPER)
    vals = _extract_outputs(out)
    if len(vals) != N:
        raise RuntimeError(f"expected {N} keystream elements, got {len(vals)}")
    return [int(v, 16) for v in vals]


# =============================================================================
# Keygen
# =============================================================================


@dataclass(frozen=True)
class KeyPair:
    """A Grumpkin keypair. `sk` is secret; `pk` = sk·G."""
    sk: int
    pk_x: int
    pk_y: int

    def pk(self) -> tuple[int, int]:
        return (self.pk_x, self.pk_y)

    def to_json(self) -> dict:
        return {"sk": hex(self.sk), "pk_x": hex(self.pk_x), "pk_y": hex(self.pk_y)}

    @classmethod
    def from_json(cls, d: dict) -> "KeyPair":
        return cls(
            sk=int(d["sk"], 16),
            pk_x=int(d["pk_x"], 16),
            pk_y=int(d["pk_y"], 16),
        )


def generate_keypair(seed: Optional[bytes] = None) -> KeyPair:
    """Generate a Grumpkin keypair.

    If `seed` is None, uses cryptographic randomness. If `seed` is given,
    the keypair is deterministic (for tests / demos).
    """
    if seed is None:
        sk = secrets.randbelow(GRUMPKIN_ORDER - 1) + 1
    else:
        # Hash seed to get a scalar; retry on the negligible chance of 0.
        h = hashlib.sha256(b"OMP_SECRET_INBOX_KEY_v1:" + seed).digest()
        sk = (int.from_bytes(h, "big") % (GRUMPKIN_ORDER - 1)) + 1
    pk = ec_mul(G, sk)
    assert pk is not None
    return KeyPair(sk=sk, pk_x=pk[0], pk_y=pk[1])


# =============================================================================
# Plaintext codec: arbitrary bytes <-> N field elements
# =============================================================================

#: Each field carries at most 31 bytes (so the encoded value is < 2^248 < P).
#: We reserve one byte per field for length/marker; result: up to 31*N bytes.
FIELD_PLAINTEXT_BYTES: int = 31
MAX_PLAINTEXT_BYTES: int = FIELD_PLAINTEXT_BYTES * N  # 992 for N=32


def encode_plaintext(data: bytes) -> list[int]:
    """Encode arbitrary bytes (<= MAX_PLAINTEXT_BYTES) into N field elements.

    Layout: a 4-byte big-endian length prefix, followed by `data`, zero-padded
    to 31*N bytes. Chunks of 31 bytes are then packed into field elements.
    """
    if len(data) > MAX_PLAINTEXT_BYTES - 4:
        raise ValueError(
            f"plaintext {len(data)} B exceeds max {MAX_PLAINTEXT_BYTES - 4} B "
            f"for N={N}"
        )
    framed = len(data).to_bytes(4, "big") + data
    framed = framed.ljust(FIELD_PLAINTEXT_BYTES * N, b"\x00")
    return [
        int.from_bytes(framed[i * FIELD_PLAINTEXT_BYTES:(i + 1) * FIELD_PLAINTEXT_BYTES], "big")
        for i in range(N)
    ]


def decode_plaintext(fields: list[int]) -> bytes:
    """Inverse of encode_plaintext. Strips length prefix and trailing zeros.

    Raises ValueError if `fields` does not look like a valid encoding --
    typically because the caller tried to decrypt with the wrong key and
    got pseudorandom field elements that exceed the 31-byte codec range
    or decode to an out-of-bounds length prefix.
    """
    if len(fields) != N:
        raise ValueError(f"expected {N} fields, got {len(fields)}")
    parts: list[bytes] = []
    for i, f in enumerate(fields):
        if f < 0 or f >= (1 << (8 * FIELD_PLAINTEXT_BYTES)):
            raise ValueError(
                f"field[{i}] = {hex(f)} exceeds {FIELD_PLAINTEXT_BYTES}-byte "
                f"codec range (garbage? wrong key?)"
            )
        parts.append(f.to_bytes(FIELD_PLAINTEXT_BYTES, "big"))
    framed = b"".join(parts)
    length = int.from_bytes(framed[:4], "big")
    if length > MAX_PLAINTEXT_BYTES - 4:
        raise ValueError(f"decoded length {length} exceeds max (garbage? wrong key?)")
    return framed[4:4 + length]


# =============================================================================
# ECIES: encrypt / decrypt
# =============================================================================


@dataclass(frozen=True)
class Envelope:
    """One encrypted message as it appears on-chain."""
    c1_x: int
    c1_y: int
    c2: int
    ct: list[int]

    def to_json(self) -> dict:
        return {
            "c1_x": hex(self.c1_x),
            "c1_y": hex(self.c1_y),
            "c2": hex(self.c2),
            "ct": [hex(v) for v in self.ct],
        }

    @classmethod
    def from_json(cls, d: dict) -> "Envelope":
        return cls(
            c1_x=int(d["c1_x"], 16),
            c1_y=int(d["c1_y"], 16),
            c2=int(d["c2"], 16),
            ct=[int(v, 16) for v in d["ct"]],
        )


def encrypt_fields(
    bob_pk: tuple[int, int],
    plaintext: list[int],
    *,
    r: Optional[int] = None,
    k: Optional[int] = None,
) -> Envelope:
    """ECIES-encrypt an N-field plaintext to `bob_pk`.

    Args:
        bob_pk:    Grumpkin pubkey (x, y) of the recipient.
        plaintext: exactly N field elements.
        r, k:      blinding scalars (optional; random if None).

    Returns an Envelope (c1_x, c1_y, c2, ct[N]).
    """
    if len(plaintext) != N:
        raise ValueError(f"plaintext must have {N} fields, got {len(plaintext)}")
    if not is_on_curve(bob_pk[0], bob_pk[1]):
        raise ValueError("recipient pubkey is not on Grumpkin curve")

    if r is None:
        r = secrets.randbelow(P - 1) + 1  # constrained to < P for Field compat
    if k is None:
        k = secrets.randbelow(P - 1) + 1

    c1 = ec_mul(G, r)
    shared = ec_mul(bob_pk, r)
    assert c1 is not None and shared is not None
    k_mask = poseidon2_h2(shared[0], shared[1])
    c2 = (k + k_mask) % P

    ks = keystream(k)
    ct = [(plaintext[i] + ks[i]) % P for i in range(N)]
    return Envelope(c1_x=c1[0], c1_y=c1[1], c2=c2, ct=ct)


def decrypt_fields(bob_sk: int, env: Envelope) -> list[int]:
    """ECIES-decrypt an envelope using Bob's Grumpkin private key."""
    c1 = (env.c1_x, env.c1_y)
    if not is_on_curve(c1[0], c1[1]):
        raise ValueError("C1 is not on Grumpkin curve -- envelope corrupted")
    shared = ec_mul(c1, bob_sk)
    assert shared is not None
    k_mask = poseidon2_h2(shared[0], shared[1])
    k = (env.c2 - k_mask) % P
    ks = keystream(k)
    return [(env.ct[i] - ks[i]) % P for i in range(N)]


def encrypt_bytes(bob_pk: tuple[int, int], data: bytes,
                  *, r: Optional[int] = None, k: Optional[int] = None) -> Envelope:
    """Convenience: encrypt `data` bytes (<= MAX_PLAINTEXT_BYTES-4)."""
    return encrypt_fields(bob_pk, encode_plaintext(data), r=r, k=k)


def decrypt_bytes(bob_sk: int, env: Envelope) -> bytes:
    """Convenience: decrypt and decode bytes."""
    return decode_plaintext(decrypt_fields(bob_sk, env))


# =============================================================================
# ECIES + ZK proof of correct encryption
# =============================================================================

_SECRET_INBOX_CIRCUIT = _CIRCUITS_ROOT / "secret_inbox"


def _ensure_secret_inbox_built() -> None:
    """One-time compile + write_vk for the secret_inbox circuit."""
    target_json = _SECRET_INBOX_CIRCUIT / "target" / "secret_inbox.json"
    if not target_json.exists():
        _run([NARGO, "compile"], _SECRET_INBOX_CIRCUIT, timeout=300)
    vk_path = _SECRET_INBOX_CIRCUIT / "target" / "vk" / "vk"
    if not vk_path.exists():
        _run([BB, "write_vk",
              "-b", "target/secret_inbox.json",
              "-o", "target/vk",
              "--oracle_hash", "keccak"], _SECRET_INBOX_CIRCUIT, timeout=300)


def encrypt_and_prove(
    bob_pk: tuple[int, int],
    plaintext: list[int],
    *,
    r: Optional[int] = None,
    k: Optional[int] = None,
) -> tuple[Envelope, bytes, list[int]]:
    """ECIES-encrypt `plaintext` to `bob_pk` and produce a ZK proof.

    Returns (envelope, proof_bytes, public_inputs_words).

    `public_inputs_words` is a list of 37 integers laid out as:
        [bob_pk_x, bob_pk_y, c1_x, c1_y, c2, ct[0], ..., ct[31]]

    Shells out to nargo + bb; ~3-4 s per call on an M3 after the
    one-time circuit compile + VK generation.
    """
    if len(plaintext) != N:
        raise ValueError(f"plaintext must have {N} fields, got {len(plaintext)}")
    if not is_on_curve(bob_pk[0], bob_pk[1]):
        raise ValueError("recipient pubkey is not on Grumpkin curve")

    if r is None:
        r = secrets.randbelow(P - 1) + 1
    if k is None:
        k = secrets.randbelow(P - 1) + 1

    # Off-chain ECIES components (Python only, ec_mul is pure-Python).
    c1 = ec_mul(G, r)
    shared = ec_mul(bob_pk, r)
    assert c1 is not None and shared is not None
    k_mask = poseidon2_h2(shared[0], shared[1])
    c2 = (k + k_mask) % P

    # Write Prover.toml, then nargo execute + bb prove.
    _ensure_secret_inbox_built()
    secret_toml = ", ".join(f'"{hex(s)}"' for s in plaintext)
    prover_toml = (
        f'bob_pk_x = "{hex(bob_pk[0])}"\n'
        f'bob_pk_y = "{hex(bob_pk[1])}"\n'
        f'c1_x = "{hex(c1[0])}"\n'
        f'c1_y = "{hex(c1[1])}"\n'
        f'c2 = "{hex(c2)}"\n'
        f'secret = [{secret_toml}]\n'
        f'k = "{hex(k)}"\n'
        f'r = "{hex(r)}"\n'
    )
    # Audit M-11: this Prover.toml contains the secret plaintext, key k, and
    # nonce r. We restrict perms to 0600 immediately and delete the file as
    # soon as prove+execute have read it. .gitignore separately ensures the
    # path won't be accidentally committed.
    prover_path = _SECRET_INBOX_CIRCUIT / "Prover.toml"
    fd = os.open(str(prover_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(prover_toml)
    try:
        out = _run([NARGO, "execute"], _SECRET_INBOX_CIRCUIT, timeout=120)
        outputs = _extract_outputs(out)
        if len(outputs) < N:
            raise RuntimeError(f"nargo execute returned {len(outputs)} outputs, expected >= {N}")
        ct = [int(v, 16) for v in outputs[:N]]

        _run([BB, "prove",
              "-b", "target/secret_inbox.json",
              "-w", "target/secret_inbox.gz",
              "-k", "target/vk/vk",
              "-o", "target/proof",
              "--oracle_hash", "keccak"], _SECRET_INBOX_CIRCUIT, timeout=180)
    finally:
        try:
            prover_path.unlink()
        except FileNotFoundError:
            pass

    proof_bytes = (_SECRET_INBOX_CIRCUIT / "target" / "proof" / "proof").read_bytes()
    pi_bytes = (_SECRET_INBOX_CIRCUIT / "target" / "proof" / "public_inputs").read_bytes()
    if len(pi_bytes) != 32 * (5 + N):
        raise RuntimeError(
            f"public_inputs length {len(pi_bytes)} != expected {32*(5+N)}"
        )
    pi_words = [int.from_bytes(pi_bytes[i*32:(i+1)*32], "big") for i in range(5 + N)]

    envelope = Envelope(c1_x=c1[0], c1_y=c1[1], c2=c2, ct=ct)
    return envelope, proof_bytes, pi_words


def encrypt_bytes_and_prove(
    bob_pk: tuple[int, int],
    data: bytes,
    *,
    r: Optional[int] = None,
    k: Optional[int] = None,
) -> tuple[Envelope, bytes, list[int]]:
    """Convenience: encrypt bytes + prove. Caps plaintext at MAX_PLAINTEXT_BYTES-4."""
    return encrypt_and_prove(bob_pk, encode_plaintext(data), r=r, k=k)


# =============================================================================
# CLI
# =============================================================================


def _cmd_keygen(args: argparse.Namespace) -> int:
    seed = args.seed.encode() if args.seed else None
    kp = generate_keypair(seed=seed)
    out = json.dumps(kp.to_json(), indent=2)
    if args.out:
        # Audit M-12: keypair JSON contains the Grumpkin secret scalar.
        # Create the file with 0600 from the start (don't rely on umask),
        # so a key file is never world-readable even briefly.
        out_path = pathlib.Path(args.out)
        fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(out + "\n")
        # If the file pre-existed with broader perms, tighten it now.
        os.chmod(out_path, 0o600)
        print(f"wrote {args.out} (mode 0600)", file=sys.stderr)
    else:
        print(out)
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    if args.recipient_json:
        kp_data = json.loads(pathlib.Path(args.recipient_json).read_text())
        bob_pk = (int(kp_data["pk_x"], 16), int(kp_data["pk_y"], 16))
    else:
        bob_pk = (int(args.pk_x, 16), int(args.pk_y, 16))

    if args.message is not None:
        data = args.message.encode()
    else:
        data = sys.stdin.buffer.read()
    env = encrypt_bytes(bob_pk, data)
    print(json.dumps(env.to_json(), indent=2))
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    kp_data = json.loads(pathlib.Path(args.recipient_json).read_text())
    bob_sk = int(kp_data["sk"], 16)
    env_data = json.loads(pathlib.Path(args.envelope).read_text())
    env = Envelope.from_json(env_data)
    plaintext = decrypt_bytes(bob_sk, env)
    sys.stdout.buffer.write(plaintext)
    return 0


def _cmd_roundtrip(args: argparse.Namespace) -> int:
    """End-to-end sanity: generate keys, encrypt, decrypt, verify match."""
    kp = generate_keypair(seed=args.seed.encode() if args.seed else None)
    msg = args.message.encode() if args.message else b"Test message from secret_inbox.py"
    print(f"  plaintext:   {msg!r}")
    print(f"  bob_pk:      ({hex(kp.pk_x)[:20]}..., {hex(kp.pk_y)[:20]}...)")
    print(f"  encrypting...")
    t0 = time.time()
    env = encrypt_bytes(kp.pk(), msg)
    t_enc = time.time() - t0
    print(f"  encrypt:     {t_enc:.2f}s")
    print(f"  c1:          ({hex(env.c1_x)[:20]}..., {hex(env.c1_y)[:20]}...)")
    print(f"  c2:          {hex(env.c2)[:20]}...")
    print(f"  ct[0]:       {hex(env.ct[0])[:20]}...")
    print(f"  decrypting...")
    t0 = time.time()
    recovered = decrypt_bytes(kp.sk, env)
    t_dec = time.time() - t0
    print(f"  decrypt:     {t_dec:.2f}s")
    print(f"  recovered:   {recovered!r}")
    if recovered != msg:
        print(f"  FAIL: mismatch (got {recovered!r}, want {msg!r})", file=sys.stderr)
        return 1
    print(f"  PASS: round-trip OK")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="secret_inbox", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keygen", help="Generate a Grumpkin keypair")
    pk.add_argument("--seed", help="Deterministic seed (optional)")
    pk.add_argument("-o", "--out", help="Write JSON to file instead of stdout")
    pk.set_defaults(func=_cmd_keygen)

    pe = sub.add_parser("encrypt", help="Encrypt a message (stdin or --message) to a recipient")
    pe.add_argument("--recipient-json", help="Path to recipient keypair JSON")
    pe.add_argument("--pk-x", help="Recipient pubkey x (0x hex)")
    pe.add_argument("--pk-y", help="Recipient pubkey y (0x hex)")
    pe.add_argument("-m", "--message", help="Message string (else reads stdin as bytes)")
    pe.set_defaults(func=_cmd_encrypt)

    pd = sub.add_parser("decrypt", help="Decrypt an envelope using recipient's keys")
    pd.add_argument("recipient_json", help="Path to recipient keypair JSON")
    pd.add_argument("envelope", help="Path to envelope JSON (from `encrypt`)")
    pd.set_defaults(func=_cmd_decrypt)

    pr = sub.add_parser("roundtrip", help="Sanity check: keygen + encrypt + decrypt")
    pr.add_argument("-m", "--message", help="Message string")
    pr.add_argument("--seed", help="Deterministic seed")
    pr.set_defaults(func=_cmd_roundtrip)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
