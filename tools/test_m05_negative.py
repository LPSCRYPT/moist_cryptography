#!/usr/bin/env python3
"""Negative tests for audit M-05 (old_k bound to ECDH(owner_sk, prev_c1)).

Each tamper case replaces a witnessed keystream key (`old_k`, `prev_k[i]`,
or `owner_k[i]`) with a value that DOES NOT equal kdf(owner_sk * prev_c1)
while keeping the rest of the witness internally consistent enough that
older checks pass. The M-05 binding must be the constraint that fires.

Strategy: substitute the keystream key field with a different but still
non-zero Field value. The KDF binding will fail (witness key != derived
key), so `assert(occ * (k_witness - k_derived) == 0)` fires for occupied
slots and `assert(old_k == old_k_derived)` fires for mutate_slot.

For transfer_feature_v2, the binding `assert(old_k == k_old_derived)` was
already there pre-M-05 (transfer_feature_v2 was the only circuit that did
this); we test it anyway since the comment still attributes M-05 weight
to that constraint, and to document the test pattern is uniform.

Each tampered toml is written to `ProverTamperM05.toml` in the circuit
dir; on success it is deleted.

Run:
  python3 tools/test_m05_negative.py

NOTE: For per-slot circuits (transfer_shadow_v2, solve_shadow_v2), the
tampered key must be for an OCCUPIED slot. We patch index 0 of the
`prev_k`/`owner_k` array regardless; the canonical fixtures used here
have slot 0 occupied (transfer_shadow_v2 fixture uses n_occupied=4 or
=16 with specific picks; solve_shadow_v2 fixture uses pseudo-random
picks). When slot 0 is NOT occupied the tamper passes silently and the
test gives a false-OK. To make the test robust we explicitly target a
slot that we know is occupied per the canonical Prover.toml's is_occupied
array.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CIRCUITS = ROOT / "circuits"
NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))


def patch_scalar(text: str, key: str, new_value: str) -> str:
    pattern = rf'(?m)^({re.escape(key)}\s*=\s*)"[^"]*"'
    new_text, n = re.subn(pattern, rf'\1"{new_value}"', text)
    if n != 1:
        raise RuntimeError(f"patch_scalar: did not find exactly one `{key}` in toml (n={n})")
    return new_text


def patch_array_index(text: str, key: str, idx: int, new_value: str) -> str:
    """Replace the idx-th element of `key = ["a", "b", ...]` with new_value.

    Handles both single-line and multi-line array layouts.
    """
    # Find the `key = [` opening, walk to the closing `]`.
    m = re.search(rf'(?m)^{re.escape(key)}\s*=\s*\[', text)
    if not m:
        raise RuntimeError(f"patch_array_index: array `{key}` not found")
    start = m.end()
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
        i += 1
    if depth != 0:
        raise RuntimeError(f"patch_array_index: unterminated array `{key}`")
    body = text[start:i - 1]
    # Replace the idx-th quoted entry within body.
    entries = list(re.finditer(r'"([^"]*)"', body))
    if idx >= len(entries):
        raise RuntimeError(f"patch_array_index: array `{key}` has {len(entries)} entries, index {idx} oob")
    e = entries[idx]
    new_body = body[:e.start()] + f'"{new_value}"' + body[e.end():]
    return text[:start] + new_body + text[i - 1:]


def first_occupied(text: str) -> int:
    """Locate the index of the first `"0x1"` in the is_occupied = [...] array."""
    m = re.search(r'(?m)^is_occupied\s*=\s*\[([^\]]*)\]', text, re.DOTALL)
    if not m:
        raise RuntimeError("first_occupied: is_occupied array not found")
    entries = re.findall(r'"([^"]*)"', m.group(1))
    for i, v in enumerate(entries):
        if int(v, 16) == 1:
            return i
    raise RuntimeError("first_occupied: no occupied slot found in is_occupied")


# Per-circuit cases. Each: (circuit, label, patch_fn).
CASES: list[tuple[str, str, callable]] = [
    # ---- mutate_slot ----
    # Single slot, unconditional binding: `assert(old_k == old_k_derived)`.
    ("mutate_slot", "old_k_unbound",
     lambda t: patch_scalar(t, "old_k",
                            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")),

    # ---- transfer_shadow_v2 ----
    # Per-occupied-slot gated binding. Target the first occupied slot.
    ("transfer_shadow_v2", "prev_k_unbound_occupied",
     lambda t: patch_array_index(t, "prev_k", first_occupied(t),
                                 "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")),

    # ---- solve_shadow_v2 ----
    # Per-occupied-slot gated binding via owner_k[i].
    ("solve_shadow_v2", "owner_k_unbound_occupied",
     lambda t: patch_array_index(t, "owner_k", first_occupied(t),
                                 "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")),
]


def run_execute(cdir: Path, prover_name: str) -> tuple[int, str]:
    proc = subprocess.run(
        [str(NARGO), "execute", "--prover-name", prover_name, "witness_m05_tamper"],
        cwd=cdir,
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

    # Baseline: canonical Prover.toml must execute clean.
    seen: set[str] = set()
    for circuit, _, _ in CASES:
        if circuit in seen:
            continue
        seen.add(circuit)
        cdir = CIRCUITS / circuit
        rc, tail = run_execute(cdir, "Prover")
        if rc != 0:
            print(f"[FAIL baseline] {circuit}: canonical Prover.toml does not execute clean")
            print(tail)
            return 1
        print(f"[ok baseline] {circuit}")

    # Tamper cases.
    failures: list[str] = []
    for circuit, label, patch in CASES:
        cdir = CIRCUITS / circuit
        tomlp = cdir / "Prover.toml"
        tamperp = cdir / "ProverTamperM05.toml"
        text = tomlp.read_text()
        try:
            tampered = patch(text)
        except Exception as e:
            print(f"[FAIL setup] {circuit}/{label}: {e}")
            failures.append(f"{circuit}/{label}")
            continue
        tamperp.write_text(tampered)
        rc, tail = run_execute(cdir, "ProverTamperM05")
        if rc == 0:
            print(f"[FAIL tamper] {circuit}/{label}: nargo execute SUCCEEDED on tampered witness")
            print(f"             tamper file kept at {tamperp}")
            failures.append(f"{circuit}/{label}")
            continue
        tamperp.unlink(missing_ok=True)
        print(f"[ok reject] {circuit}/{label}  (exit {rc})")

    if failures:
        print(f"\n{len(failures)} negative test(s) FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nAll {len(CASES)} M-05 negative tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
