#!/usr/bin/env python3
"""Check pinned nargo/bb versions and binary hashes for reproducible proofs."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools/toolchain_manifest.json"


def resolve(tool: dict) -> Path:
    override = os.environ.get(tool["env_override"])
    raw = override or tool["default_path"]
    return Path(os.path.expandvars(raw)).expanduser()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    errors: list[str] = []
    for tool in manifest["tools"]:
        path = resolve(tool)
        if not path.exists():
            errors.append(f"{tool['name']}: missing binary at {path}; install pinned version or set {tool['env_override']}")
            continue
        observed_hash = sha256(path)
        if observed_hash != tool["sha256"]:
            errors.append(f"{tool['name']}: sha256 {observed_hash} != manifest {tool['sha256']}")
        try:
            out = subprocess.check_output([str(path), "--version"], text=True, stderr=subprocess.STDOUT, timeout=20)
        except Exception as exc:  # pragma: no cover - diagnostic path
            errors.append(f"{tool['name']}: --version failed: {exc}")
            continue
        if tool["version_substring"] not in out:
            errors.append(f"{tool['name']}: version output {out.strip()!r} lacks {tool['version_substring']!r}")
        else:
            print(f"ok: {tool['name']} {tool['version_substring']} at {path}")
    if errors:
        print("Pinned toolchain expected:", file=sys.stderr)
        print("  nargo: noirup -v 1.0.0-beta.19, normally $HOME/.nargo/bin/nargo", file=sys.stderr)
        print("  bb:    5.0.0-nightly.20260419, normally $HOME/.bb/bb", file=sys.stderr)
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
