#!/usr/bin/env python3
"""Mint pipeline robustness: noise images MUST be rejected by face_disc.

Architecture (post-disc):
  Mint requires TWO proofs:
    A. landmark_regions: landmark CNN + region commits + ECIES envelope.
       Has no face/non-face check; will accept whatever pixels Python
       preprocessing emits.
    B. face_disc: discriminator CNN that asserts disc_score(image) > 0.
       Refuses to generate a proof when fed non-faces.

  The contract verifies BOTH proofs and asserts they share image_commit.
  So: the disc circuit is the gating mechanism -- a noise image cannot
  produce a valid mint even if Python preprocessing happens to succeed.

This script:
  1. Generates K random-noise images.
  2. For each: runs Python disc inference. EXPECTS score <= 0 (not face).
  3. With --execute: also runs face_disc nargo execute LOCALLY. Witness
     solving MUST fail at the assert(score > 0) line.
  4. Reports.

Exit code 0 = all noise REJECTED at disc (correct behavior).
Exit code 2 = at least one noise image PASSED disc (regression).

Usage:
    python3 test_noise_mint.py [--num-images N] [--start-seed S] [--execute]
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import tempfile
from pathlib import Path

import cv2
import numpy as np

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from mint_pipeline import compute_face_state, REGION_NAMES  # noqa: E402

sys.path.insert(0, str(REPO / "landmark"))
from discriminator import run_discriminator  # noqa: E402

DEFAULT_COLOR = 7  # alice0 default palette


def gen_noise(seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.integers(0, 256, size=(48, 48, 3), dtype=np.uint8)


def write_image_tmp(img_rgb: np.ndarray) -> Path:
    tmp = Path(tempfile.NamedTemporaryFile(suffix=".png", delete=False).name)
    bgr = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2BGR)
    cv2.imwrite(str(tmp), bgr)
    return tmp


def stage_preprocess(seed: int, color: int) -> dict:
    """Run compute_face_state. Return outcome dict."""
    img = gen_noise(seed)
    img_path = write_image_tmp(img)
    out = {"seed": seed, "image_path": str(img_path), "stage": "preprocess"}
    try:
        state = compute_face_state(img_path, color=color)
        out["status"] = "OK"
        out["landmarks"] = [(int(x), int(y)) for x, y in state.landmarks]
        out["region_dims"] = [
            {"name": r.name, "x1": r.x1, "y1": r.y1, "w": r.w, "h": r.h}
            for r in state.regions
        ]
        out["state"] = state
        return out
    except (ValueError, AssertionError, KeyError, IndexError) as e:
        out["status"] = "FAIL"
        out["error"] = f"{type(e).__name__}: {e}"
        return out


def stage_disc_check(seed: int) -> dict:
    """Run Python disc inference on noise. EXPECTS score <= 0."""
    out = {"seed": seed, "stage": "disc_check"}
    img = gen_noise(seed)
    score = float(run_discriminator(img))
    out["disc_score"] = score
    out["is_face"] = score > 0
    out["status"] = "REJECTED" if score <= 0 else "PASSED"
    return out


def stage_disc_execute(seed: int) -> dict:
    """Run face_disc nargo execute LOCALLY on noise.

    The circuit asserts disc_score > 0; on noise this assertion MUST fail.
    Witness solving (nargo execute) returns nonzero exit code = test passes."""
    out = {"seed": seed, "stage": "face_disc_execute"}
    try:
        img = gen_noise(seed)
        img_path = write_image_tmp(img)
        bgr = cv2.imread(str(img_path))
        rgb_48 = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
        from build_face_disc_fixture import write_prover_toml as write_disc_toml
        write_disc_toml(rgb_48)
        import subprocess, time as _time
        circuit_dir = REPO.parent / "circuits" / "face_disc"
        t0 = _time.time()
        r = subprocess.run(
            [str(Path.home() / ".nargo" / "bin" / "nargo"), "execute", "--silence-warnings"],
            cwd=str(circuit_dir),
            capture_output=True, text=True, timeout=600,
        )
        elapsed = _time.time() - t0
        out["elapsed_s"] = round(elapsed, 1)
        if r.returncode != 0:
            err_tail = (r.stderr or r.stdout)[-300:]
            out["status"] = "REJECTED"
            out["err_tail"] = err_tail
        else:
            out["status"] = "PASSED"
            out["stdout_tail"] = r.stdout[-300:]
        return out
    except Exception as e:
        out["status"] = "EXCEPTION"
        out["error"] = f"{type(e).__name__}: {e}"
        return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--num-images", type=int, default=10)
    ap.add_argument("--start-seed", type=int, default=42_000)
    ap.add_argument("--color", type=int, default=DEFAULT_COLOR)
    ap.add_argument("--execute", action="store_true",
                    help="Also run nargo execute LOCALLY for each image (slow ~90s/image)")
    ap.add_argument("--report", default=None,
                    help="Write JSON report to this path")
    args = ap.parse_args()

    print("=" * 70)
    print("face_disc rejection test on random noise")
    print("=" * 70)
    # (header line above)
    print(f"  num_images : {args.num_images}")
    print(f"  start_seed : {args.start_seed}")
    print(f"  color      : {args.color}")
    print(f"  execute    : {args.execute}")
    print()

    results = []
    n_disc_rejected = 0
    n_circuit_rejected = 0

    for i in range(args.num_images):
        seed = args.start_seed + i
        print(f"[{i+1:2d}/{args.num_images}] seed={seed}")

        # Stage 1: Python disc inference (cheap, runs always).
        dc = stage_disc_check(seed)
        if dc["status"] == "REJECTED":
            n_disc_rejected += 1
            print(f"      OK disc REJECTED: score = {dc['disc_score']:.3f}")
        else:
            print(f"      FAIL disc PASSED on noise: score = {dc['disc_score']:.3f} (regression)")

        # Stage 2 (optional): face_disc circuit witness solving.
        if args.execute:
            ex = stage_disc_execute(seed)
            if ex["status"] == "REJECTED":
                n_circuit_rejected += 1
                print(f"      OK face_disc circuit REJECTED noise ({ex.get('elapsed_s', '?')}s)")
            elif ex["status"] == "PASSED":
                print(f"      FAIL face_disc circuit PASSED noise (regression)")
            else:
                print(f"      EXCEPTION: {ex.get('error', '?')[:200]}")
            dc["execute_result"] = ex

        # For preprocess context (e.g. landmark detector behavior on noise).
        pp = stage_preprocess(seed, args.color)
        if pp["status"] == "OK":
            lm_str = " ".join(f"({x},{y})" for x, y in pp["landmarks"])
            print(f"      preprocess: 5 landmarks {lm_str}")
        else:
            print(f"      preprocess FAILED: {pp['error'][:120]}")
        pp.pop("state", None)
        dc["preprocess_result"] = pp

        results.append(dc)

    print()
    print(f"Summary: disc REJECTED = {n_disc_rejected}/{args.num_images} (Python)", end="")
    if args.execute:
        print(f"  circuit REJECTED = {n_circuit_rejected}/{args.num_images}")
    else:
        print()

    if args.report:
        Path(args.report).write_text(json.dumps(results, indent=2, default=str))
        print(f"Report: {args.report}")

    # Pass: ALL noise rejected by disc (Python and circuit if executed).
    expected = args.num_images
    ok = n_disc_rejected == expected
    if args.execute:
        ok = ok and n_circuit_rejected == expected
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
