#!/usr/bin/env python3
"""Validate generated-verifier constants and proof/public-input fixtures."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts/test/fixtures/verifier_manifest.json"
CONST_RE = re.compile(r"NUMBER_OF_PUBLIC_INPUTS\s*=\s*(\d+)")
VK_RE = re.compile(r"VK_HASH\s*=\s*(0x[0-9a-fA-F]+)")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_entry(entry: dict, errors: list[str]) -> None:
    verifier = ROOT / entry["verifier"]
    if not verifier.exists():
        errors.append(f"{entry['name']}: missing verifier {entry['verifier']}")
        return
    text = verifier.read_text(errors="ignore")
    const = CONST_RE.search(text)
    if not const:
        errors.append(f"{entry['name']}: verifier lacks NUMBER_OF_PUBLIC_INPUTS")
    elif int(const.group(1)) != entry["generated_public_inputs"]:
        errors.append(
            f"{entry['name']}: generated PI constant {const.group(1)} != manifest {entry['generated_public_inputs']}"
        )
    if entry["generated_public_inputs"] - 8 != entry["external_public_inputs"]:
        errors.append(f"{entry['name']}: external_public_inputs must equal generated_public_inputs - 8")
    vk = VK_RE.search(text)
    entry["source_sha256_observed"] = sha256(verifier)
    if vk:
        entry["vk_hash_observed"] = vk.group(1)

    proof = ROOT / entry.get("proof_path", "")
    pi = ROOT / entry.get("public_inputs_path", "")
    if not proof.exists():
        errors.append(f"{entry['name']}: missing proof fixture {entry.get('proof_path')}")
    elif proof.stat().st_size == 0:
        errors.append(f"{entry['name']}: empty proof fixture {entry.get('proof_path')}")
    if not pi.exists():
        errors.append(f"{entry['name']}: missing public input fixture {entry.get('public_inputs_path')}")
    else:
        expected = entry["external_public_inputs"] * 32
        actual = pi.stat().st_size
        if actual != expected:
            errors.append(f"{entry['name']}: public input fixture size {actual} != {expected}")


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    errors: list[str] = []
    listed = set()
    for entry in manifest.get("verifiers", []):
        listed.add(entry["verifier"])
        check_entry(entry, errors)
    for entry in manifest.get("allowlisted_without_real_fixture", []):
        listed.add(entry["verifier"])
        verifier = ROOT / entry["verifier"]
        if not verifier.exists():
            errors.append(f"allowlisted {entry['name']}: missing verifier")
            continue
        const = CONST_RE.search(verifier.read_text(errors="ignore"))
        if not const or int(const.group(1)) != entry["generated_public_inputs"]:
            errors.append(f"allowlisted {entry['name']}: generated PI constant mismatch")

    all_verifiers = {
        rel(path)
        for path in (ROOT / "contracts/src").glob("*Verifier.sol")
        if path.name != "IVerifier.sol"
    }
    unlisted = sorted(all_verifiers - listed)
    if unlisted:
        errors.append("unlisted verifier files: " + ", ".join(unlisted))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"ok: {len(manifest.get('verifiers', []))} verifier fixtures validated; {len(manifest.get('allowlisted_without_real_fixture', []))} allowlisted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
