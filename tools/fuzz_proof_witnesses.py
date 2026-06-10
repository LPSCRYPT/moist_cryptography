#!/usr/bin/env python3
"""Bounded circuit-negative assurance runner.

The negative suites mutate canonical Noir ``Prover.toml`` witnesses. This
harness materializes those witnesses from the repository's fixture builders
before running each suite, rejects empty template witnesses, and restores any
pre-existing ``Prover.toml`` files after a successful run so the check does not
leave generated secrets in the working tree.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))

NARGO_CIRCUITS = [
    "landmark_regions_v2",
    "mutate_slot",
    "transfer_shadow_v2",
    "transfer_feature_v2",
    "solve_shadow_v2",
    "zindex_commit",
    "shadow_t10",
]


def run(cmd: list[str], *, cwd: Path = ROOT, timeout: int = 240) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


def require_nargo() -> None:
    if not NARGO.exists() and shutil.which("nargo") is None:
        raise SystemExit(f"nargo not found at {NARGO}; set NARGO_PATH or install Noir toolchain")


def nargo_cmd() -> str:
    return str(NARGO) if NARGO.exists() else "nargo"


def run_nargo_checks(limit: int) -> bool:
    ok = True
    for circuit in NARGO_CIRCUITS[:limit]:
        code, out = run([nargo_cmd(), "check"], cwd=ROOT / "circuits" / circuit, timeout=180)
        if code != 0:
            ok = False
            print(f"[FAIL] nargo check {circuit}")
            print(out)
        else:
            print(f"[OK] nargo check {circuit}")
    return ok


@dataclass(frozen=True)
class Suite:
    name: str
    setup: Callable[[], None]
    test: list[str]
    required: tuple[str, ...]


def face_disc_image_commit() -> int:
    pi = (ROOT / "contracts/test/fixtures/face_disc/alice0/public_inputs").read_bytes()
    if len(pi) != 32:
        raise RuntimeError(f"face_disc public_inputs unexpected length {len(pi)}")
    return int.from_bytes(pi, "big")


def setup_mint() -> None:
    from build_atomic_mint_fixture import build_witness, write_mint_prover_toml

    witness = build_witness(b"atomic_mint_demo", face_disc_image_commit())
    write_mint_prover_toml(witness)


def setup_mutate_slot() -> None:
    from build_mutate_slot_fixture import build_witness, write_prover_toml

    witness = build_witness(b"mutate_demo_v2")
    write_prover_toml(witness)


def setup_transfer_shadow_v2() -> None:
    from build_transfer_shadow_v2_fixture import build_witness, write_prover_toml

    witness = build_witness(b"transfer_demo", 4)
    write_prover_toml(witness)


def setup_solve_shadow_v2() -> None:
    from build_solve_shadow_v2_fixture import build_witness, write_prover_toml

    witness = build_witness(b"solve_demo", 4)
    write_prover_toml(witness)


def setup_transfer_feature_v2() -> None:
    import json

    from build_transfer_feature_v2_fixture import build_transfer_witness, write_prover_toml

    meta_path = ROOT / "contracts/test/fixtures/onchain_transfer_feature_v2/transfer_feature_v2_atomic_mint_demo_slot0/meta.json"
    if not meta_path.exists():
        raise RuntimeError(f"missing transfer_feature_v2 metadata fixture: {meta_path}")

    meta = json.loads(meta_path.read_text())
    recipient_pk = (int(meta["to_pk_x"], 16), int(meta["to_pk_y"], 16))
    witness = build_transfer_witness(
        meta["mint_seed"].encode(),
        int(meta["slot_at_mint"]),
        int(meta["shadow_id_at_mint"], 16),
        int(meta["chain_id"]),
        recipient_pk,
        source_state="post-mutate",
    )
    write_prover_toml(witness, ROOT / "circuits/transfer_feature_v2/Prover.toml")


def setup_m06() -> None:
    setup_mint()
    setup_mutate_slot()
    setup_transfer_shadow_v2()
    setup_transfer_feature_v2()


def setup_m05() -> None:
    setup_mutate_slot()
    setup_transfer_shadow_v2()
    setup_solve_shadow_v2()


SUITES = [
    Suite(
        name="mutate_slot_single_class",
        setup=setup_mutate_slot,
        test=[sys.executable, "tools/test_mutation_no_rotation_semantics.py"],
        required=("circuits/mutate_slot/Prover.toml",),
    ),
    Suite(
        name="ecies_well_formedness",
        setup=setup_m06,
        test=[sys.executable, "tools/test_m06_negative.py"],
        required=(
            "circuits/landmark_regions_v2/Prover.toml",
            "circuits/mutate_slot/Prover.toml",
            "circuits/transfer_shadow_v2/Prover.toml",
            "circuits/transfer_feature_v2/Prover.toml",
        ),
    ),
    Suite(
        name="mint_geometry",
        setup=setup_mint,
        test=[sys.executable, "tools/test_h04_negative.py"],
        required=("circuits/landmark_regions_v2/Prover.toml",),
    ),
    Suite(
        name="mint_noise",
        setup=lambda: None,
        test=[sys.executable, "tools/test_noise_mint.py"],
        required=(),
    ),
    Suite(
        name="h05_metadata",
        setup=setup_m05,
        test=[sys.executable, "tools/test_m05_negative.py"],
        required=(
            "circuits/mutate_slot/Prover.toml",
            "circuits/transfer_shadow_v2/Prover.toml",
            "circuits/solve_shadow_v2/Prover.toml",
        ),
    ),
]


def snapshot_required_witnesses(suites: list[Suite]) -> dict[Path, bytes | None]:
    paths = {ROOT / rel for suite in suites for rel in suite.required}
    return {path: path.read_bytes() if path.exists() else None for path in paths}


def restore_required_witnesses(snapshot: dict[Path, bytes | None]) -> None:
    for path, content in snapshot.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


def assert_no_empty_witness_values(path: Path) -> None:
    text = path.read_text()
    if '""' in text:
        raise RuntimeError(f"{path.relative_to(ROOT)} contains empty witness values")


def validate_required_witnesses(suite: Suite) -> None:
    for rel in suite.required:
        path = ROOT / rel
        if not path.exists():
            raise RuntimeError(f"{suite.name}: missing canonical witness input: {rel}")
        assert_no_empty_witness_values(path)


def run_negative_suites(limit: int) -> tuple[bool, int]:
    ok = True
    ran = 0
    selected = SUITES[:limit]
    snapshot = snapshot_required_witnesses(selected)
    try:
        for suite in selected:
            try:
                suite.setup()
                validate_required_witnesses(suite)
            except Exception as exc:
                ok = False
                print(f"[FAIL setup] {suite.name}")
                print(exc)
                continue

            code, out = run(suite.test, timeout=420)
            ran += 1
            if code != 0:
                ok = False
                print(f"[FAIL] {suite.name}")
                print(out)
            else:
                print(f"[OK] {suite.name}")
    finally:
        if ok:
            restore_required_witnesses(snapshot)
    return ok, ran


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=5, help="maximum negative suites to run")
    parser.add_argument("--skip-nargo-check", action="store_true", help="skip per-circuit nargo check")
    args = parser.parse_args()

    if args.cases < 1:
        raise SystemExit("--cases must be >= 1")
    require_nargo()

    suites_to_run = min(args.cases, len(SUITES))
    circuits_to_check = min(args.cases, len(NARGO_CIRCUITS))

    ok = True
    checked = 0
    if not args.skip_nargo_check:
        ok = run_nargo_checks(circuits_to_check) and ok
        checked = circuits_to_check
    suites_ok, suites_ran = run_negative_suites(suites_to_run)
    ok = suites_ok and ok

    if ok:
        print(f"fuzz_proof_witnesses: OK ({checked} nargo checks, {suites_ran} negative suites, 0 skipped)")
        return 0
    print(f"fuzz_proof_witnesses: FAILED ({checked} nargo checks, {suites_ran} negative suites, 0 skipped)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
