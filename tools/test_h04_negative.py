#!/usr/bin/env python3
"""Negative tests for audit H-04 (mint plaintext geometry validation).

For each attack vector listed in the audit, construct a Prover.toml for
`landmark_regions_v2` whose slot-0 plaintext violates exactly one of the
geometry invariants, then run `nargo execute` and assert the constraint
fires.

Plaintext field 0 layout (low 31 bytes, little-endian within the Field):
  bytes 0..7   pose (uint64; low 12 bits are (x:6bit, y:6bit))
  byte 8       w_dim
  byte 9       h_dim
  bytes 10..30 first 21 (w*h) palette indices, 4-bit packed

The test family:
  * w_zero            -> w_byte = 0           (fails `w_byte != 0`)
  * w_over_canvas     -> w_byte = 49          (fails `w <= 48`)
  * h_zero            -> h_byte = 0           (fails `h_byte != 0`)
  * h_over_canvas     -> h_byte = 49          (fails `h <= 48`)
  * x_w_over_canvas   -> pose x = 46, w = 6   (46+6=52 > 48; fails x+w<=48)
  * y_h_over_canvas   -> pose y = 46, h = 6   (46+6=52 > 48; fails y+h<=48)

The pose tampering keeps the rest of the pose field intact so we don't
incidentally fail an unrelated check. Each tamper toml is written to
`ProverTamperH04.toml` and removed on success.

Run:
  python3 tools/test_h04_negative.py
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CIRCUIT = ROOT / "circuits" / "landmark_regions_v2"
NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))


def get_plaintext_slot0_field0(text: str) -> int:
    """Pull the first quoted hex value from the `plaintexts = [[...]]` array."""
    # Match: plaintexts = [\n  ["0x...", "0x..."...
    m = re.search(r'plaintexts\s*=\s*\[\s*\[\s*"([^"]+)"', text)
    if not m:
        raise RuntimeError("plaintexts slot[0].field[0] not found")
    return int(m.group(1), 16)


def set_plaintext_slot0_field0(text: str, new_val: int) -> str:
    pattern = r'(plaintexts\s*=\s*\[\s*\[\s*)"[^"]+"'
    new_text, n = re.subn(pattern, rf'\1"0x{new_val:x}"', text, count=1)
    if n != 1:
        raise RuntimeError("set_plaintext_slot0_field0: substitution count != 1")
    return new_text


def set_byte(field_val: int, byte_idx: int, new_byte: int) -> int:
    """Set byte_idx (0-indexed) of `field_val` to `new_byte`, big-Field little-endian."""
    if not (0 <= new_byte < 256):
        raise ValueError("byte must be 0..255")
    shift = byte_idx * 8
    mask = 0xFF << shift
    return (field_val & ~mask) | (new_byte << shift)


def set_pose_xy(field_val: int, x: int, y: int) -> int:
    """Replace pose's low 12 bits (x: 6bit, y: 6bit) inside byte 0 + byte 1 low nibble."""
    if not (0 <= x < 64 and 0 <= y < 64):
        raise ValueError("x, y must be 0..63")
    # Clear low 12 bits.
    field_val = field_val & ~((1 << 12) - 1)
    # Pack: bits 0..5 = x, bits 6..11 = y.
    field_val = field_val | x | (y << 6)
    return field_val


def make_tamper(label: str, base: int) -> int:
    if label == "w_zero":
        return set_byte(base, 8, 0)
    if label == "w_over_canvas":
        # 49 still violates "<=48" check.
        return set_byte(base, 8, 49)
    if label == "h_zero":
        return set_byte(base, 9, 0)
    if label == "h_over_canvas":
        return set_byte(base, 9, 49)
    if label == "x_w_over_canvas":
        # Force pose x=46 and w_byte=6 -> 52 > 48 axis containment fails.
        # Need to keep y in valid range; pull current y to avoid collateral check.
        bytes_view = base.to_bytes(32, "little")
        cur_y = ((bytes_view[0] >> 6) | ((bytes_view[1] & 0x0F) << 2)) & 0x3F
        f = set_pose_xy(base, x=46, y=min(cur_y, 41))  # ensure y+h<=48 for h up to 7
        f = set_byte(f, 8, 6)
        # Ensure h is in valid range to isolate the failure.
        f = set_byte(f, 9, 7)
        return f
    if label == "y_h_over_canvas":
        bytes_view = base.to_bytes(32, "little")
        cur_x = bytes_view[0] & 0x3F
        f = set_pose_xy(base, x=min(cur_x, 41), y=46)
        f = set_byte(f, 8, 7)
        f = set_byte(f, 9, 6)
        return f
    raise ValueError(f"unknown tamper label: {label}")


LABELS = [
    "w_zero",
    "w_over_canvas",
    "h_zero",
    "h_over_canvas",
    "x_w_over_canvas",
    "y_h_over_canvas",
]


def run_execute(prover_name: str) -> tuple[int, str]:
    proc = subprocess.run(
        [str(NARGO), "execute", "--prover-name", prover_name, "witness_h04_tamper"],
        cwd=CIRCUIT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    tail = "\n".join(tail[-6:]) if tail else ""
    return proc.returncode, tail


def main() -> int:
    if not NARGO.exists():
        sys.exit(f"nargo not found at {NARGO}")

    tomlp = CIRCUIT / "Prover.toml"
    text = tomlp.read_text()
    base = get_plaintext_slot0_field0(text)

    # Baseline.
    rc, tail = run_execute("Prover")
    if rc != 0:
        print(f"[FAIL baseline] canonical Prover.toml does not execute clean")
        print(tail)
        return 1
    print("[ok baseline] landmark_regions_v2")

    failures: list[str] = []
    for label in LABELS:
        try:
            tampered_val = make_tamper(label, base)
        except Exception as e:
            print(f"[FAIL setup] {label}: {e}")
            failures.append(label)
            continue
        tampered_text = set_plaintext_slot0_field0(text, tampered_val)
        tamperp = CIRCUIT / "ProverTamperH04.toml"
        tamperp.write_text(tampered_text)
        rc, tail = run_execute("ProverTamperH04")
        if rc == 0:
            print(f"[FAIL tamper] {label}: nargo execute SUCCEEDED on tampered witness")
            print(f"             tamper file kept at {tamperp}")
            failures.append(label)
            continue
        tamperp.unlink(missing_ok=True)
        print(f"[ok reject] landmark_regions_v2/{label}  (exit {rc})")

    if failures:
        print(f"\n{len(failures)} negative test(s) FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nAll {len(LABELS)} H-04 negative tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
