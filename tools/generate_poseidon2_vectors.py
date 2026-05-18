#!/usr/bin/env python3
"""Generate/check Poseidon2 reference vectors used by Solidity/Yul tests."""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from v2_circuit_helpers import P, poseidon2_hash_2, sponge_16, sponge_39, sponge_palette_salt  # noqa: E402

OUT = ROOT / "contracts/test/fixtures/poseidon2_vectors"
TWO_256_MINUS_1 = (1 << 256) - 1


def hex32(value: int) -> str:
    return "0x" + (value % P).to_bytes(32, "big").hex()


def raw_hex32(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def cases(length: int) -> list[tuple[str, list[int]]]:
    rng = random.Random(0xC0FFEE + length)
    edge = [0, 1, P - 1, P, P + 1, 2 * P - 1, 2 * P, TWO_256_MINUS_1]
    out: list[tuple[str, list[int]]] = [
        ("zeros", [0] * length),
        ("ones", [1] * length),
        ("incremental", list(range(length))),
        ("edges_repeated", [edge[i % len(edge)] for i in range(length)]),
        ("deterministic_random", [rng.randrange(0, P) for _ in range(length)]),
        ("noncanonical_random", [rng.randrange(P, min(TWO_256_MINUS_1, P * 4)) for _ in range(length)]),
    ]
    return out


def build() -> dict[str, list[dict]]:
    return {
        "hash2": [
            {"name": name, "inputs": [raw_hex32(v) for v in vals], "expected": hex32(poseidon2_hash_2(vals[0], vals[1]))}
            for name, vals in cases(2)
        ],
        "sponge16": [
            {"name": name, "inputs": [raw_hex32(v) for v in vals], "expected": hex32(sponge_16(vals))}
            for name, vals in cases(16)
        ],
        "sponge39": [
            {"name": name, "inputs": [raw_hex32(v) for v in vals], "expected": hex32(sponge_39(vals))}
            for name, vals in cases(39)
        ],
        "palette_salt": [
            {"name": name, "palette": [raw_hex32(v) for v in vals[:16]], "salt": raw_hex32(vals[16]), "expected": hex32(sponge_palette_salt(vals[:16], vals[16]))}
            for name, vals in cases(17)
        ],
    }


def write_vectors(vectors: dict[str, list[dict]]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for key, entries in vectors.items():
        (OUT / f"{key}.json").write_text(json.dumps({"field_modulus": hex(P), "vectors": entries}, indent=2) + "\n")


def check_vectors(vectors: dict[str, list[dict]]) -> list[str]:
    errors: list[str] = []
    for key, entries in vectors.items():
        path = OUT / f"{key}.json"
        if not path.exists():
            errors.append(f"missing {path.relative_to(ROOT)}")
            continue
        expected = json.dumps({"field_modulus": hex(P), "vectors": entries}, indent=2) + "\n"
        actual = path.read_text()
        if actual != expected:
            errors.append(f"{path.relative_to(ROOT)} differs; run tools/generate_poseidon2_vectors.py")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if tracked vectors differ")
    args = parser.parse_args()
    vectors = build()
    if args.check:
        errors = check_vectors(vectors)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        print(f"ok: Poseidon2 vectors match {OUT.relative_to(ROOT)}")
        return 0
    write_vectors(vectors)
    print(f"wrote Poseidon2 vectors to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
