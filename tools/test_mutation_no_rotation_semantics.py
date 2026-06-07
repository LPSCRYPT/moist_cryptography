#!/usr/bin/env python3
"""Regression tests for mutate_slot pose-only single-mutation semantics.

The mutate circuit must permit exactly one pose mutation class per proof:
rotation, scale, or x/y translation. Non-pose payload bytes are immutable, and
a 0-degree/no-change mutation is rejected.

This test checks:
  * canonical Prover.toml: regenerated as a scale-only mutation with
    quarter_turns=0. This must execute.
  * ProverNoopMutation.toml: old == new plaintext. This must fail at the
    explicit exactly-one-mutation assertion.
  * ProverCombinedMutation.toml: scale + translation in one proof. This must
    fail at the same exactly-one-mutation assertion.
  * ProverPayloadMutation.toml: a non-pose payload field changes. This must
    fail at the payload-preservation assertion.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from v2_circuit_helpers import PLAINTEXT_FIELDS  # noqa: E402

CIRCUIT = ROOT / "circuits" / "mutate_slot"
NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))

ARRAY_KEYS = {"old_plaintext", "new_plaintext"}


def parse_toml_subset(text: str) -> dict[str, object]:
    out: dict[str, object] = {}
    for key in ARRAY_KEYS:
        m = re.search(rf'^{key}\s*=\s*\[(.*?)\]$', text, flags=re.M | re.S)
        if not m:
            raise RuntimeError(f"missing array key {key}")
        out[key] = [int(x, 16) for x in re.findall(r'"(0x[0-9a-fA-F]+)"', m.group(1))]
        if len(out[key]) != PLAINTEXT_FIELDS:  # type: ignore[arg-type]
            raise RuntimeError(f"{key}: expected {PLAINTEXT_FIELDS} fields")
    return out


def replace_scalar(text: str, key: str, value: int) -> str:
    new_text, n = re.subn(
        rf'^{key}\s*=\s*"0x[0-9a-fA-F]+"$',
        f'{key} = "0x{value:x}"',
        text,
        count=1,
        flags=re.M,
    )
    if n != 1:
        raise RuntimeError(f"replace_scalar({key}) count={n}")
    return new_text


def replace_array(text: str, key: str, values: list[int]) -> str:
    encoded = ", ".join(f'"0x{v:x}"' for v in values)
    new_text, n = re.subn(
        rf'^{key}\s*=\s*\[.*?\]$',
        f'{key} = [{encoded}]',
        text,
        count=1,
        flags=re.M | re.S,
    )
    if n != 1:
        raise RuntimeError(f"replace_array({key}) count={n}")
    return new_text


def dims_from_plaintext(plaintext: list[int]) -> tuple[int, int]:
    b = plaintext[0].to_bytes(31, "little")
    return b[8], b[9]


def replace_pose_x(field0: int, new_x: int) -> int:
    b = bytearray(field0.to_bytes(31, "little"))
    b[0] = (b[0] & 0xC0) | (new_x & 0x3F)
    return int.from_bytes(b, "little")


def pose_x(field0: int) -> int:
    return field0 & 0x3F



def run_execute(prover_name: str, witness_name: str) -> tuple[int, str]:
    proc = subprocess.run(
        [str(NARGO), "execute", "--prover-name", prover_name, witness_name],
        cwd=CIRCUIT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    return proc.returncode, "\n".join(tail[-10:]) if tail else ""


def main() -> int:
    if not NARGO.exists():
        sys.exit(f"nargo not found at {NARGO}")

    # This script intentionally relies on freshly regenerated fixture TOMLs whose
    # canonical mutation uses quarter_turns=0 and changes only scale.
    rc, tail = run_execute("Prover", "witness_q0_scale_only")
    if rc != 0:
        print("[FAIL] canonical mutate_slot Prover.toml should allow scale-only mutation with quarter_turns=0")
        print(tail)
        return 1
    print("[ok allow] scale-only mutation with quarter_turns=0")

    text = (CIRCUIT / "Prover.toml").read_text()
    data = parse_toml_subset(text)
    old_plaintext = list(data["old_plaintext"])  # type: ignore[arg-type]
    # Deliberately stale dependent commitments are acceptable for these
    # regressions only because the explicit mutation-shape assertions appear
    # before encryption/hash checks.
    w_old, h_old = dims_from_plaintext(old_plaintext)
    noop = replace_array(text, "new_plaintext", old_plaintext)
    noop = replace_scalar(noop, "w_new", w_old)
    noop = replace_scalar(noop, "h_new", h_old)
    tamperp = CIRCUIT / "ProverNoopMutation.toml"
    tamperp.write_text(noop)
    rc, tail = run_execute("ProverNoopMutation", "witness_noop_reject")
    if rc == 0:
        print("[FAIL] no-op mutation witness executed successfully")
        print(f"       kept {tamperp}")
        return 1
    tamperp.unlink(missing_ok=True)
    if "assert(rotation_changed + scale_changed + translation_changed == 1)" not in tail:
        print("[FAIL] no-op mutation rejected, but not by the exactly-one-mutation assertion")
        print(tail)
        return 1
    print("[ok reject] no-op mutation with quarter_turns=0")

    new_plaintext = list(data["new_plaintext"])  # type: ignore[arg-type]
    combined_plaintext = list(new_plaintext)
    combined_plaintext[0] = replace_pose_x(combined_plaintext[0], pose_x(combined_plaintext[0]) + 1)
    combined = replace_array(text, "new_plaintext", combined_plaintext)
    tamperp = CIRCUIT / "ProverCombinedMutation.toml"
    tamperp.write_text(combined)
    rc, tail = run_execute("ProverCombinedMutation", "witness_combined_reject")
    if rc == 0:
        print("[FAIL] combined scale+translation mutation witness executed successfully")
        print(f"       kept {tamperp}")
        return 1
    tamperp.unlink(missing_ok=True)
    if "assert(rotation_changed + scale_changed + translation_changed == 1)" not in tail:
        print("[FAIL] combined mutation rejected, but not by the exactly-one-mutation assertion")
        print(tail)
        return 1
    print("[ok reject] combined scale+translation mutation")

    payload_plaintext = list(new_plaintext)
    payload_plaintext[1] = (payload_plaintext[1] + 1)
    payload = replace_array(text, "new_plaintext", payload_plaintext)
    tamperp = CIRCUIT / "ProverPayloadMutation.toml"
    tamperp.write_text(payload)
    rc, tail = run_execute("ProverPayloadMutation", "witness_payload_reject")
    if rc == 0:
        print("[FAIL] payload mutation witness executed successfully")
        print(f"       kept {tamperp}")
        return 1
    tamperp.unlink(missing_ok=True)
    if "assert(old_plaintext[i] == new_plaintext[i])" not in tail:
        print("[FAIL] payload mutation rejected, but not by the payload-preservation assertion")
        print(tail)
        return 1
    print("[ok reject] non-pose payload mutation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
