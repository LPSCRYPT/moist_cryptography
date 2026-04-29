#!/usr/bin/env python3
"""Generate a *max-batch* mutateBatch fixture: N=8 mutate_slot proofs +
1 shadow_t10 proof against the post-batch manifest.

Tests the N=8 worst-case gas path of `ShadowToken.mutateBatch`. Because
each mutate_slot proof costs ~3-4M gas to verify on chain, and the
contract loops over `entries[]` doing one verify per entry, gas grows
linearly. The asymptote test in `MutateBatch.t.sol::test_mutateBatch_per_entry_gas_bounded`
gives the analytical bound; this fixture + test exercises the path
directly so we catch any non-linear regression (loop overhead, calldata
costs, hidden quadratic terms in storage layout).

Slots: 0..7 of the same shadow. The shadow witness is built once via
`build_mutate_witness(seed, slot_idx, label)`; the per-slot derivations
all use the same owner key so the test can seed one shadow + 8 carriers.

Output:
    contracts/test/fixtures/atomic_mutate_batch_max/<seed>/
        proof_mut_<i>.bin, public_inputs_mut_<i>.bin   (i in 0..7)
        c2_<i>.bin                                      (i in 0..7)
        proof_t10.bin, public_inputs_t10.bin            (post-batch T10)
        meta.json                                       (everything the test reads)

Usage:
    python3 build_atomic_mutate_batch_max_fixture.py [--seed atomic_mutate_batch_max_demo]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from build_mutate_slot_fixture import (  # noqa: E402
    build_witness as build_mutate_witness,
    write_prover_toml as write_mut_toml,
)
from build_atomic_mutate_fixture import sponge_18, split_128  # noqa: E402
from v2_circuit_helpers import P, fhex, bx32  # noqa: E402

ROOT = REPO.parent
MUT_DIR = ROOT / "circuits" / "mutate_slot"
T10_DIR = ROOT / "circuits" / "shadow_t10"
FIXTURE_ROOT = ROOT / "contracts" / "test" / "fixtures" / "atomic_mutate_batch_max"

NARGO = Path(os.environ.get("NARGO_PATH", str(Path.home() / ".nargo" / "bin" / "nargo")))
BB = Path(os.environ.get("BB_PATH", str(Path.home() / ".bb" / "bb")))

N_BATCH = 8


def run(cmd: list, cwd: Path, timeout: int = 600) -> str:
    started = time.time()
    p = subprocess.run([str(c) for c in cmd], cwd=str(cwd),
                       capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        print("STDOUT:", p.stdout[-2000:])
        print("STDERR:", p.stderr[-2000:])
        sys.exit(f"command failed (exit {p.returncode}) after {time.time()-started:.1f}s")
    return p.stdout


def prove_mutate(seed: bytes, slot_idx: int, label: bytes) -> tuple[bytes, bytes, dict]:
    """Run mutate_slot for one slot. Returns (proof_bytes, pi_bytes, witness_dict)."""
    print(f"  [slot={slot_idx} label={label!r}] build witness", flush=True)
    w = build_mutate_witness(seed, slot_idx=slot_idx, witness_label=label)
    write_mut_toml(w)
    print(f"  [slot={slot_idx}] nargo execute + bb prove", flush=True)
    run([NARGO, "execute"], MUT_DIR, timeout=600)
    target = MUT_DIR / "target"
    if not (target / "vk").exists():
        run([BB, "write_vk", "-b", str(target / "mutate_slot.json"),
             "-o", str(target),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=900)
    proof_dir = target / f"proof_dir_{slot_idx}"
    if proof_dir.exists():
        for f in proof_dir.iterdir():
            f.unlink()
    proof_dir.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target / "mutate_slot.json"),
         "-w", str(target / "mutate_slot.gz"),
         "-o", str(proof_dir),
         "-k", str(target / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=1800)
    run([BB, "verify",
         "-k", str(target / "vk"),
         "-p", str(proof_dir / "proof"),
         "-i", str(proof_dir / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], MUT_DIR, timeout=300)
    proof = (proof_dir / "proof").read_bytes()
    pi    = (proof_dir / "public_inputs").read_bytes()
    return proof, pi, w


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="atomic_mutate_batch_max_demo")
    args = ap.parse_args()

    seed = args.seed.encode()
    print(f"[atomic_mutate_batch_max fixture] seed={args.seed!r} N={N_BATCH} (slots 0..{N_BATCH-1})")
    started_total = time.time()

    # ---- 1..N: mutate proof for each slot ----
    proofs = []
    pis    = []
    ws     = []
    for slot_idx in range(N_BATCH):
        label = f":slot_{slot_idx}".encode()
        t0 = time.time()
        proof, pi, w = prove_mutate(seed, slot_idx, label)
        print(f"  [slot={slot_idx}] proof done in {time.time()-t0:.1f}s", flush=True)
        proofs.append(proof)
        pis.append(pi)
        ws.append(w)

    # Sanity: all proofs share the same shadow_id and owner_pk.
    shadow_id = ws[0]["shadow_id"]
    owner_pk_x = ws[0]["owner_pk_x"]
    for i, w in enumerate(ws[1:], 1):
        assert w["shadow_id"] == shadow_id, f"slot {i}: shadow_id diverged"
        assert w["owner_pk_x"] == owner_pk_x, f"slot {i}: owner pk diverged"
    z_commit = 0

    # ---- N+1: shadow_t10 against post-batch manifest ----
    # Slots 0..N_BATCH-1 OCCUPIED with their post-mutate new_lsh; rest EMPTY.
    lsh_array = [0] * 16
    for i, w in enumerate(ws):
        lsh_array[i] = w["new_lsh"]

    buf = [shadow_id, z_commit] + lsh_array
    acc = sponge_18(buf)
    hi, lo = split_128(acc)
    print(f"[T10] post-batch hi=0x{hi:032x} lo=0x{lo:032x}")

    (T10_DIR / "Prover.toml").write_text(
        f"shadow_id = {fhex(shadow_id)}\n"
        f"z_index_commit = {fhex(z_commit)}\n"
        f"new_t10_hi = {fhex(hi)}\n"
        f"new_t10_lo = {fhex(lo)}\n"
        f"live_state_hash = [{', '.join(fhex(v) for v in lsh_array)}]\n"
    )
    run([NARGO, "execute"], T10_DIR, timeout=300)
    target_t10 = T10_DIR / "target"
    if not (target_t10 / "vk").exists():
        run([BB, "write_vk", "-b", str(target_t10 / "shadow_t10.json"),
             "-o", str(target_t10),
             "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    proof_dir_t10 = target_t10 / "proof_dir"
    if proof_dir_t10.exists():
        for f in proof_dir_t10.iterdir():
            f.unlink()
    proof_dir_t10.mkdir(exist_ok=True)
    run([BB, "prove", "-b", str(target_t10 / "shadow_t10.json"),
         "-w", str(target_t10 / "shadow_t10.gz"),
         "-o", str(proof_dir_t10),
         "-k", str(target_t10 / "vk"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=900)
    run([BB, "verify",
         "-k", str(target_t10 / "vk"),
         "-p", str(proof_dir_t10 / "proof"),
         "-i", str(proof_dir_t10 / "public_inputs"),
         "--scheme", "ultra_honk", "--oracle_hash", "keccak"], T10_DIR, timeout=300)
    proof_t10 = (proof_dir_t10 / "proof").read_bytes()
    pi_t10    = (proof_dir_t10 / "public_inputs").read_bytes()

    # ---- write fixture ----
    fix_dir = FIXTURE_ROOT / args.seed
    fix_dir.mkdir(parents=True, exist_ok=True)
    for i in range(N_BATCH):
        (fix_dir / f"proof_mut_{i}.bin").write_bytes(proofs[i])
        (fix_dir / f"public_inputs_mut_{i}.bin").write_bytes(pis[i])
        c2_bytes = b"".join(c.to_bytes(32, "big") for c in ws[i]["new_c2"])
        (fix_dir / f"c2_{i}.bin").write_bytes(c2_bytes)
    (fix_dir / "proof_t10.bin").write_bytes(proof_t10)
    (fix_dir / "public_inputs_t10.bin").write_bytes(pi_t10)

    def w_meta(w: dict) -> dict:
        return {
            "slot_idx": w["slot_idx"],
            "feature_id": bx32(w["feature_id"]),
            "type_idx": w["type_idx"],
            "origin_face_id": bx32(w["origin_face_id"]),
            "palette_commit": bx32(w["palette_commit"]),
            "old_lsh": bx32(w["old_lsh"]),
            "new_lsh": bx32(w["new_lsh"]),
            "new_ct_commit": bx32(w["new_ct_commit"]),
            "new_c1_x": bx32(w["new_c1_x"]),
            "new_c1_y": bx32(w["new_c1_y"]),
            "prev_chain_tip": bx32(w["old_chain_tip"]),
            "new_chain_tip": bx32(w["new_chain_tip"]),
            "prev_mutation_count": w["prev_mutation_count"],
            "new_mutation_count": w["new_mutation_count"],
            "c2_field_count": w["c2_field_count"],
        }

    meta = {
        "seed": args.seed,
        "n_batch": N_BATCH,
        "shadow_id": bx32(shadow_id),
        "owner_pk_x": bx32(ws[0]["owner_pk_x"]),
        "owner_pk_y": bx32(ws[0]["owner_pk_y"]),
        "owner_sk":   bx32(ws[0]["owner_sk"]),
        "z_index_commit": "0x0",
        "t10_hi": bx32(hi),
        "t10_lo": bx32(lo),
        "post_batch_lsh": [bx32(v) for v in lsh_array],
        "slots": [w_meta(w) for w in ws],
    }
    (fix_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[wrote] {fix_dir}/")
    print(f"        N_BATCH = {N_BATCH}")
    for i in range(N_BATCH):
        print(f"        proof_mut_{i}.bin ({len(proofs[i])} B)")
    print(f"        proof_t10.bin     ({len(proof_t10)} B)")
    print(f"[total wall-clock] {time.time() - started_total:.1f}s")


if __name__ == "__main__":
    main()
