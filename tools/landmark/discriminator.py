"""Runs the trained discriminator model on a 48×48 RGB image.

Uses numpy-only implementation of the Conv2d + x² pipeline so this works
anywhere without torch. Weights are loaded from models/disc_weights.json.
"""

import json, os
import numpy as np

DISC_ARCH = {
    "channels": [4, 8, 16, 16],
    "kernel": 4,
    "stride": 2,
    "activation": "x2",
    "scale": 1000,
    "params": 1791,
}

_WEIGHTS_CACHE = None


def _load_weights():
    global _WEIGHTS_CACHE
    if _WEIGHTS_CACHE is not None:
        return _WEIGHTS_CACHE
    # Vendored from pixel-prize-infra/pipeline/discriminator.py.
    # Weights live alongside this module under tools/landmark/weights/.
    path = os.path.join(os.path.dirname(__file__), "weights", "disc_weights.json")
    with open(path) as f:
        data = json.load(f)

    W = {}
    channels = DISC_ARCH["channels"]
    for i, ch_out in enumerate(channels):
        ch_in = 3 if i == 0 else channels[i - 1]
        k = DISC_ARCH["kernel"]
        w_key = f"conv{i}_w"
        b_key = f"conv{i}_b"
        w = np.array(data[w_key], dtype=np.float64).reshape(ch_out, ch_in, k, k) / DISC_ARCH["scale"]
        b = np.array(data[b_key], dtype=np.float64) / DISC_ARCH["scale"]
        W[f"conv{i}_weight"] = w
        W[f"conv{i}_bias"] = b
    W["linear_weight"] = np.array(data["linear_w"], dtype=np.float64).reshape(1, -1) / DISC_ARCH["scale"]
    _WEIGHTS_CACHE = W
    return W


def _conv2d(x, weight, bias, stride=2, padding=1):
    """Conv2d matching PyTorch nn.Conv2d(kernel_size=4, stride=2, padding=1)."""
    c_out, _, kh, kw = weight.shape
    _, h, w = x.shape
    oh = (h + 2 * padding - kh) // stride + 1
    ow = (w + 2 * padding - kw) // stride + 1
    out = np.zeros((c_out, oh, ow), dtype=np.float64)
    for co in range(c_out):
        for i in range(oh):
            for j in range(ow):
                acc = bias[co]
                for ci in range(weight.shape[1]):
                    for ky in range(kh):
                        for kx in range(kw):
                            iy = i * stride + ky - padding
                            ix = j * stride + kx - padding
                            if 0 <= iy < h and 0 <= ix < w:
                                acc += x[ci, iy, ix] * weight[co, ci, ky, kx]
                out[co, i, j] = acc
    return out


def run_discriminator(img_rgb_48: np.ndarray) -> float:
    """Returns a score. score > 0 means face."""
    W = _load_weights()
    img = img_rgb_48.astype(np.float64) / 255.0 if img_rgb_48.dtype == np.uint8 else img_rgb_48
    x = img.transpose(2, 0, 1)
    for i in range(len(DISC_ARCH["channels"])):
        x = _conv2d(x, W[f"conv{i}_weight"], W[f"conv{i}_bias"], stride=2)
        x = x * x  # x² activation
    x = x.mean(axis=(1, 2))
    return float(np.dot(W["linear_weight"].flatten(), x))
