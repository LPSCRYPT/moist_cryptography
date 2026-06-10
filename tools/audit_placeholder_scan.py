#!/usr/bin/env python3
"""Audit production proof surfaces for placeholder/mock terminology.

The scanner is intentionally conservative: production paths fail on unresolved
placeholder language unless the path is explicitly classified as non-production
or the term is a known generated-verifier implementation detail.
"""
from __future__ import annotations

import fnmatch
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts/test/fixtures/production_surface_manifest.json"
VERIFIER_MANIFEST = ROOT / "contracts/test/fixtures/verifier_manifest.json"
SURFACE_MANIFEST = ROOT / "contracts/test/fixtures/zk_surface_manifest.json"

FORBIDDEN = [
    "TODO",
    "FIXME",
    "stub",
    "placeholder",
    "dummy",
    "fake",
    "mock",
    "simulated",
    "NotImplementedYet",
    "unused",
    'revert("unused")',
]
SOURCE_SUFFIXES = {".sol", ".nr", ".py", ".sh", ".json"}
GENERATED_VERIFIER_RE = re.compile(r"contracts/src/[^/]*Verifier\.sol$")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    term: str
    text: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: forbidden term {self.term!r}: {self.text.strip()}"


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in SOURCE_SUFFIXES:
            yield path


def is_generated_allowlisted(path: str, term: str, line: str, manifest: dict) -> bool:
    for entry in manifest.get("generated_allowlist_terms", []):
        if fnmatch.fnmatch(path, entry["glob"]) and term == entry["term"]:
            return True
    # Some generated verifiers use dummy_round as a local variable but should not
    # make the entire verifier file exempt from other placeholder vocabulary.
    return bool(GENERATED_VERIFIER_RE.match(path) and term == "dummy" and "dummy_round" in line)


def is_classified_non_production(path: str, classified: set[str]) -> bool:
    return path in classified


def is_scanned_production_file(path: str, classified: set[str]) -> bool:
    if is_classified_non_production(path, classified):
        return False
    if path == "tools/audit_placeholder_scan.py":
        return False
    if path.startswith("contracts/test/"):
        return False
    if path.startswith("audit/") or path.startswith("docs/") or path.startswith("roadmap/"):
        return False
    if "/target/" in path or "/target/" in path.replace("\\", "/"):
        return False
    if path.endswith(".json") and path.startswith("circuits/"):
        return False
    return path.startswith(("contracts/src/", "circuits/", "tools/"))


def scan_terms(manifest: dict) -> list[Finding]:
    classified = {entry["path"] for entry in manifest.get("classified_non_production", [])}
    roots = [ROOT / item for item in manifest["production_roots"]]
    findings: list[Finding] = []
    for base in roots:
        for file_path in iter_files(base):
            path = rel(file_path)
            if not is_scanned_production_file(path, classified):
                continue
            try:
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for idx, line in enumerate(lines, 1):
                for term in FORBIDDEN:
                    if term.lower() not in line.lower():
                        continue
                    if is_generated_allowlisted(path, term, line, manifest):
                        continue
                    findings.append(Finding(path, idx, term, line))
    return findings


def verify_inventory(manifest: dict) -> list[str]:
    errors: list[str] = []
    active_verifiers = set(manifest.get("active_verifiers", []))
    active_circuits = set(manifest.get("active_circuits", []))
    classified = {entry["path"] for entry in manifest.get("classified_non_production", [])}

    verifier_manifest = load_json(VERIFIER_MANIFEST)
    for entry in verifier_manifest.get("verifiers", []):
        verifier = entry["verifier"]
        circuit = f"{entry['circuit_dir']}/src/main.nr"
        if verifier not in active_verifiers:
            errors.append(f"active verifier missing from production manifest: {verifier}")
        if circuit not in active_circuits:
            errors.append(f"active circuit missing from production manifest: {circuit}")

    for entry in verifier_manifest.get("allowlisted_without_real_fixture", []):
        if entry["verifier"] not in classified:
            errors.append(f"legacy verifier lacks production classification: {entry['verifier']}")

    surface_manifest = load_json(SURFACE_MANIFEST)
    for surface in surface_manifest.get("surfaces", []):
        verifier = surface.get("verifier")
        circuit = f"{surface['circuit_dir']}/src/main.nr"
        if verifier and verifier not in active_verifiers:
            errors.append(f"surface {surface['name']} verifier not active/classified: {verifier}")
        if circuit not in active_circuits:
            errors.append(f"surface {surface['name']} circuit not active/classified: {circuit}")

    all_verifiers = {rel(path) for path in (ROOT / "contracts/src").glob("*Verifier.sol") if not path.name.startswith("I")}
    unclassified_verifiers = all_verifiers - active_verifiers - classified
    for verifier in sorted(unclassified_verifiers):
        errors.append(f"verifier is neither active nor classified: {verifier}")

    circuit_mains = {rel(path) for path in (ROOT / "circuits").glob("*/src/main.nr")}
    unclassified_circuits = circuit_mains - active_circuits - classified
    for circuit in sorted(unclassified_circuits):
        errors.append(f"circuit is neither active nor classified: {circuit}")

    for path in sorted(active_verifiers | active_circuits | classified):
        if not (ROOT / path).exists():
            errors.append(f"manifest path does not exist: {path}")

    return sorted(set(errors))


def main() -> int:
    manifest = load_json(MANIFEST)
    inventory_errors = verify_inventory(manifest)
    findings = scan_terms(manifest)

    if inventory_errors:
        print("Inventory errors:")
        for err in inventory_errors:
            print(f"  - {err}")
    if findings:
        print("Placeholder/mock findings:")
        for finding in findings:
            print(f"  - {finding.render()}")
    if inventory_errors or findings:
        print(f"audit_placeholder_scan: FAILED ({len(inventory_errors)} inventory errors, {len(findings)} term findings)")
        return 1
    print("audit_placeholder_scan: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
