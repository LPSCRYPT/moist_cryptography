#!/usr/bin/env python3
"""Negative tests for audit M-06 (ECIES well-formedness in v2 circuits).

For each circuit that takes ECIES inputs as witnesses, construct a tampered
Prover.toml derived from the canonical one but with a single field set to
a value that the M-06 assertions must reject:

  - `new_r` set to 0                      (rejects degenerate r=0 envelope)
  - on-curve point set to (1, 1)          (off-curve, fails y^2 = x^3 - 17)

Each tampered toml is written to `ProverTamperM06.toml` in the circuit dir,
then `nargo execute --prover-name ProverTamperM06` runs. We assert the
process exits non-zero (constraint failure) for every tamper case. A clean
run on the unmodified `Prover.toml` is performed first as a sanity check.

Run:
  python3 tools/test_m06_negative.py

No fixture files are touched. Tamper toml is left in place after each run
for inspection if a test fails (deleted on success).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CIRCUITS = ROOT / "circuits"
NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))

# Per-circuit tamper cases: each (label, prover_toml_text -> patched_text).
# Patches operate on the canonical Prover.toml text; we keep them as
# regex replacements so they survive innocuous formatting changes in the
# witness builders.


def patch_scalar(text: str, key: str, new_value: str) -> str:
    """Replace `key = "0x..."` with `key = "<new_value>"`. Field must be present."""
    pattern = rf'(?m)^({re.escape(key)}\s*=\s*)"[^"]*"'
    new_text, n = re.subn(pattern, rf'\1"{new_value}"', text)
    if n != 1:
        raise RuntimeError(f"patch_scalar: did not find exactly one `{key}` in toml (n={n})")
    return new_text


def patch_array_first(text: str, key: str, new_first: str) -> str:
    """Replace the first element of `key = [...]` with `new_first`."""
    pattern = rf'(?m)^({re.escape(key)}\s*=\s*\[)"[^"]*"'
    new_text, n = re.subn(pattern, rf'\1"{new_first}"', text)
    if n != 1:
        raise RuntimeError(f"patch_array_first: did not find exactly one `{key} = [...]` in toml (n={n})")
    return new_text


# All tamper cases. Each entry: (circuit_name, case_label, patch_fn).
# patch_fn takes the original Prover.toml text and returns tampered text.
CASES: list[tuple[str, str, callable]] = [
    # ---- landmark_regions_v2 (mint) ----
    ("landmark_regions_v2", "owner_pk_off_curve",
     lambda t: patch_scalar(patch_scalar(t, "owner_pk_x", "0x1"), "owner_pk_y", "0x1")),
    ("landmark_regions_v2", "new_r0_zero",
     lambda t: patch_array_first(t, "new_r", "0x0")),

    # ---- mutate_slot ----
    ("mutate_slot", "old_c1_off_curve",
     lambda t: patch_scalar(patch_scalar(t, "old_c1_x", "0x1"), "old_c1_y", "0x1")),
    ("mutate_slot", "new_r_zero",
     lambda t: patch_scalar(t, "new_r", "0x0")),

    # ---- transfer_shadow_v2 ----
    ("transfer_shadow_v2", "recipient_pk_off_curve",
     lambda t: patch_scalar(patch_scalar(t, "recipient_pk_x", "0x1"), "recipient_pk_y", "0x1")),
    ("transfer_shadow_v2", "new_r0_zero",
     lambda t: patch_array_first(t, "new_r", "0x0")),

    # ---- transfer_feature_v2 ----
    ("transfer_feature_v2", "next_pk_off_curve",
     lambda t: patch_scalar(patch_scalar(t, "next_pk_x", "0x1"), "next_pk_y", "0x1")),
    ("transfer_feature_v2", "old_c1_off_curve",
     lambda t: patch_scalar(patch_scalar(t, "old_c1_x", "0x1"), "old_c1_y", "0x1")),
    ("transfer_feature_v2", "new_r_zero",
     lambda t: patch_scalar(t, "new_r", "0x0")),
]


def run_execute(cdir: Path, prover_name: str) -> tuple[int, str]:
    """Run `nargo execute --prover-name <name>` in cdir. Returns (exit_code, stderr_tail)."""
    proc = subprocess.run(
        [str(NARGO), "execute", "--prover-name", prover_name, "witness_m06_tamper"],
        cwd=cdir,
        capture_output=True,
        text=True,
        timeout=120,
    )
    # nargo emits constraint failures to stdout typically; merge for grepping.
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    tail = "\n".join(tail[-6:]) if tail else ""
    return proc.returncode, tail


def main() -> int:
    if not NARGO.exists():
        sys.exit(f"nargo not found at {NARGO} -- set NARGO_PATH or install nargo")

    # 1. Sanity: every canonical Prover.toml must execute successfully so
    # we know our baseline is valid before checking negative cases.
    seen_circuits: set[str] = set()
    for circuit, _label, _patch in CASES:
        if circuit in seen_circuits:
            continue
        seen_circuits.add(circuit)
        cdir = CIRCUITS / circuit
        rc, tail = run_execute(cdir, "Prover")
        if rc != 0:
            print(f"[FAIL baseline] {circuit}: canonical Prover.toml does not execute clean")
            print(tail)
            return 1
        print(f"[ok baseline] {circuit}")

    # 2. Each tamper case must FAIL nargo execute (non-zero exit).
    failures: list[str] = []
    for circuit, label, patch in CASES:
        cdir = CIRCUITS / circuit
        tomlp = cdir / "Prover.toml"
        tamperp = cdir / "ProverTamperM06.toml"
        text = tomlp.read_text()
        try:
            tampered = patch(text)
        except Exception as e:
            print(f"[FAIL setup] {circuit}/{label}: patch raised: {e}")
            failures.append(f"{circuit}/{label}")
            continue
        tamperp.write_text(tampered)
        rc, tail = run_execute(cdir, "ProverTamperM06")
        if rc == 0:
            print(f"[FAIL tamper] {circuit}/{label}: nargo execute SUCCEEDED on tampered witness")
            print(f"             tamper file kept at {tamperp}")
            failures.append(f"{circuit}/{label}")
            continue
        # Tamper rejected as expected. Clean up.
        tamperp.unlink(missing_ok=True)
        print(f"[ok reject] {circuit}/{label}  (exit {rc})")

    if failures:
        print(f"\n{len(failures)} negative test(s) FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nAll {len(CASES)} M-06 negative tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
