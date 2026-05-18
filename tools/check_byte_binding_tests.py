#!/usr/bin/env python3
"""Fail when byte-bearing ZK surfaces lack named positive/negative tests."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts/test/fixtures/zk_surface_manifest.json"
TEST_ROOT = ROOT / "contracts/test"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    tests_text = "\n".join(path.read_text(errors="ignore") for path in TEST_ROOT.glob("*.t.sol"))
    function_names = set(re.findall(r"function\s+(test[A-Za-z0-9_]+)\s*\(", tests_text))
    errors: list[str] = []

    for surface in manifest.get("surfaces", []):
        name = surface.get("name", "<unnamed>")
        for category in ("positive_tests", "negative_tests"):
            listed = surface.get(category, [])
            if not listed:
                errors.append(f"{name}: no {category} listed")
                continue
            for test_name in listed:
                if test_name not in function_names:
                    errors.append(f"{name}: listed {category[:-1]} {test_name} not found in contracts/test/*.t.sol")
        for output in surface.get("byte_outputs", []):
            binding = output.get("binding", "")
            if not binding or binding.lower() in {"todo", "unknown"}:
                errors.append(f"{name}.{output.get('name')}: byte output lacks concrete binding")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"ok: {len(function_names)} Solidity test functions include all manifest-listed byte-binding tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
