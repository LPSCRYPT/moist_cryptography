#!/usr/bin/env python3
"""Validate that tracked ZK/byte-bearing surfaces are explicitly inventoried."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts/test/fixtures/zk_surface_manifest.json"

EVENT_FIELD_RE = re.compile(r"event\s+(\w+)\s*\((.*?)\);", re.S)
BYTEISH = ("bytes", "bytes32", "uint24", "cipher", "plain", "palette", "envelope", "commit", "hash")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def main() -> int:
    errors: list[str] = []
    manifest = json.loads(MANIFEST.read_text())
    surfaces = manifest.get("surfaces", [])
    allowlisted = {entry["verifier"] for entry in manifest.get("allowlisted_verifiers", [])}
    manifest_verifiers = {surface.get("verifier") for surface in surfaces if surface.get("verifier")}

    all_verifiers = {
        rel(path)
        for path in (ROOT / "contracts/src").glob("*Verifier.sol")
        if path.name != "IVerifier.sol"
    }
    missing_verifiers = sorted(all_verifiers - manifest_verifiers - allowlisted)
    if missing_verifiers:
        errors.append("verifiers missing from zk_surface_manifest: " + ", ".join(missing_verifiers))

    for surface in surfaces:
        name = surface.get("name", "<unnamed>")
        if not surface.get("contract_entrypoints"):
            errors.append(f"{name}: missing contract_entrypoints")
        if "external_public_inputs" not in surface:
            errors.append(f"{name}: missing external_public_inputs")
        if not surface.get("byte_outputs"):
            errors.append(f"{name}: missing byte_outputs")
        for output in surface.get("byte_outputs", []):
            if not output.get("binding"):
                errors.append(f"{name}.{output.get('name', '<unnamed>')}: missing binding")
        if not surface.get("positive_tests"):
            errors.append(f"{name}: missing positive_tests")
        if not surface.get("negative_tests"):
            errors.append(f"{name}: missing negative_tests")

    event_names: set[str] = set()
    for source in (ROOT / "contracts/src").glob("*.sol"):
        text = source.read_text(errors="ignore")
        for event, body in EVENT_FIELD_RE.findall(text):
            lowered = f"{event} {body}".lower()
            if any(token in lowered for token in BYTEISH):
                event_names.add(event)

    documented_events = {
        output.get("event")
        for surface in surfaces
        for output in surface.get("byte_outputs", [])
        if output.get("event")
    }
    intentionally_non_zk = {
        "Registered",
        "VerifierSet",
        "VerifierProposed",
        "VerifierApplied",
        "VerifierRotationCanceled",
        "TransferFeatureVerifierSet",
        "PaletteSpongeSet",
        "KeyRegistrySet",
        "YulHash2Set",
        "ShadowBridged",
        "ShadowMirrored",
        "L2BridgeSet",
        "L1MirrorSet",
        "ShadowUnbridged",
        "ShadowUnmirrored",
        "ShadowT10Updated",
        "SlotExtracted",
        "FeatureExtracted",
        "FeatureInserted",
        "FeatureInsertedOwnerRotated",
        "FeaturePaletteSaltEnvelope"
    }
    missing_events = sorted(event_names - documented_events - intentionally_non_zk)
    if missing_events:
        errors.append("byte-like events missing byte_outputs coverage: " + ", ".join(missing_events))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"ok: {len(surfaces)} ZK surfaces and {len(all_verifiers)} verifier files covered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
