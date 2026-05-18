#!/usr/bin/env python3
"""Check that off-chain tooling does not persist secret witnesses or stale PI assumptions."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
SECRET_WRITER_PATHS = {
    "tools/build_transfer_onchain.py",
    "tools/build_solve_onchain.py",
    "tools/build_transfer_feature_v2_fixture.py",
    "tools/build_solve_shadow_v2_fixture.py",
    "tools/build_mutate_slot_onchain.py",
    "tools/build_insert_onchain.py",
    "tools/secret_inbox.py",
}
SECRET_KEYWORDS = ("owner_sk", "prev_owner_sk", "new_k", "prev_k", "new_r", "plaintext", "secret", "witness")

def main() -> int:
    errors: list[str] = []
    for path in TOOLS.glob("*.py"):
        text = path.read_text(errors="ignore")
        rel = path.relative_to(ROOT).as_posix()
        if rel in SECRET_WRITER_PATHS and "Prover.toml" in text and any(k in text for k in SECRET_KEYWORDS):
            if "0o600" not in text and "chmod" not in text:
                errors.append(f"{rel}: writes secret-bearing Prover.toml without visible 0600 mode/chmod")
            if "unlink" not in text and "atexit" not in text:
                errors.append(f"{rel}: writes secret-bearing Prover.toml without visible cleanup")
        if re.search(r"TRANSFER_PI_LEN\s*=\s*9", text) or re.search(r"TF_PI_LEN\s*=\s*9", text):
            errors.append(f"{rel}: stale 9-public-input transfer assumption")

    for doc in [ROOT / "SPEC.md", ROOT / "circuits/README.md", ROOT / "docs/CIRCUITS.md"]:
        if not doc.exists():
            continue
        text = doc.read_text(errors="ignore")
        if "bb 1.4.0" in text or "barretenberg 1.4.0" in text:
            errors.append(f"{doc.relative_to(ROOT)}: stale bb 1.4.0 documentation; pinned runtime is 5.0.0-nightly.20260419")

    tracked_prover = [p.relative_to(ROOT).as_posix() for p in (ROOT / "circuits").glob("*/Prover.toml")]
    if tracked_prover:
        errors.append("local Prover.toml files present; they must stay untracked/transient: " + ", ".join(tracked_prover))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("ok: metadata/tooling authority checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
