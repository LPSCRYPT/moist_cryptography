"""Maps RGB images to palette-index arrays via Manhattan-distance nearest-neighbor.

Each palette is a list of up to 10 (R, G, B) tuples. Output is an array of
uint8 indices into the palette. 4-bit packing fits 2 indices per byte.

This is deterministic, so the same mapping can be verified in-circuit or
simply trusted and verified off-chain by anyone via a hash commit.
"""

import numpy as np


# 23 palettes — simple one-word names. Each is 10 RGB triples chosen for
# face contrast under quantization (warm + cool + highlight + shadow anchors).
PALETTES = {
    # red / orange / yellow
    'blood':     [(238,0,0),(200,0,0),(160,0,0),(120,0,0),(80,0,0),(40,0,0),(255,50,50),(180,20,20),(100,0,0),(60,0,0)],
    'ember':     [(236,85,38),(247,244,226),(158,187,193),(244,172,18),(30,27,30),(236,85,38),(247,244,226),(158,187,193),(30,27,30),(244,172,18)],
    'rust':      [(183,65,14),(160,55,10),(140,45,8),(120,35,5),(100,28,3),(80,20,0),(200,80,20),(170,60,12),(130,40,6),(90,25,2)],
    'sunset':    [(255,94,77),(255,140,66),(255,185,56),(255,220,80),(200,60,60),(230,100,50),(250,160,60),(255,200,70),(180,50,50),(210,80,45)],
    'gold':      [(255,215,0),(200,165,0),(140,100,0),(40,30,5),(255,250,200),(60,80,140),(255,230,80),(180,140,40),(255,255,255),(90,60,15)],
    'storm':     [(40,45,55),(100,110,125),(180,190,200),(255,255,80),(220,225,235),(15,15,25),(60,70,85),(140,150,170),(255,200,40),(5,5,15)],
    # green
    'moss':      [(34,80,20),(60,120,40),(90,160,60),(140,200,80),(240,235,210),(180,140,80),(110,80,30),(200,160,40),(50,30,15),(25,60,15)],
    'toxic':     [(0,255,0),(200,255,0),(255,255,80),(255,0,200),(50,255,100),(255,80,255),(180,255,30),(0,0,0),(255,255,255),(10,40,5)],
    'jade':      [(20,80,70),(40,140,120),(180,220,200),(200,140,120),(240,180,160),(255,250,240),(60,100,90),(180,90,80),(130,180,170),(10,40,35)],
    'acid':      [(0,255,40),(255,255,0),(255,0,255),(0,0,0),(0,255,255),(180,255,40),(255,0,80),(40,0,80),(255,255,255),(255,140,0)],
    'desert':    [(200,120,80),(160,180,120),(240,220,180),(140,180,220),(100,60,40),(255,200,140),(80,100,70),(220,170,120),(240,240,230),(180,80,50)],
    # contrast / warm-shell / aquatic
    'void':      [(5,5,15),(255,0,80),(80,255,80),(0,180,255),(40,5,40),(255,255,80),(20,20,30),(255,80,255),(140,140,160),(255,255,255)],
    'amber':     [(60,40,30),(100,65,35),(160,100,40),(220,170,70),(240,220,180),(40,25,15),(200,140,60),(140,115,75),(255,200,130),(15,8,5)],
    'ocean':     [(5,10,25),(0,40,90),(0,80,140),(40,130,200),(80,180,220),(140,210,235),(220,240,250),(60,200,180),(0,30,70),(160,220,240)],
    'tide':      [(10,40,80),(30,90,140),(255,140,100),(240,200,160),(180,220,210),(255,255,240),(5,15,40),(90,160,180),(255,180,140),(50,80,110)],
    # purple / magenta
    'violet':    [(100,40,160),(140,60,200),(180,80,240),(80,20,120),(60,10,100),(120,50,180),(160,70,220),(200,90,255),(90,30,140),(70,15,110)],
    'midnight':  [(15,10,40),(50,30,90),(90,60,140),(240,200,80),(255,240,200),(5,0,20),(140,100,200),(200,170,60),(40,20,70),(255,255,255)],
    'aurora':    [(10,30,60),(60,255,160),(140,80,255),(255,80,180),(200,255,240),(40,160,180),(5,15,30),(255,255,200),(80,200,255),(100,40,140)],
    'ghost':     [(250,250,255),(220,220,235),(180,170,200),(255,80,200),(110,90,140),(40,40,60),(200,180,220),(140,255,220),(90,70,110),(10,5,20)],
    'neon':      [(0,255,65),(255,0,110),(0,200,255),(255,255,0),(255,0,255),(0,255,200),(255,100,0),(100,0,255),(0,255,130),(255,50,180)],
    # pink / soft warm
    'blush':     [(255,182,193),(255,140,160),(220,90,120),(140,40,70),(255,240,235),(180,255,220),(255,200,210),(50,20,40),(255,80,140),(240,160,180)],
    'peach':     [(255,200,180),(255,160,140),(180,240,230),(255,240,220),(230,120,100),(60,140,140),(255,220,200),(255,255,245),(140,80,70),(40,90,100)],
    # mineral
    'bone':      [(240,230,210),(220,210,190),(200,190,170),(180,170,150),(160,150,130),(140,130,110),(120,110,90),(100,90,70),(80,70,50),(60,50,30)],
}

_PRIMARY_KEYS = list(PALETTES.keys())  # 23 names, in declaration order



for _name, _p in PALETTES.items():
    assert len(_p) == 10, f"palette {_name} has {len(_p)} entries (must be 10)"
    for _rgb in _p:
        assert len(_rgb) == 3 and all(0 <= c <= 255 for c in _rgb), \
            f"bad RGB in {_name}: {_rgb}"


def quantize_to_palette(img_rgb: np.ndarray, palette: list) -> np.ndarray:
    """Returns uint8 array of indices 0..len(palette)-1."""
    if img_rgb.size == 0:
        return np.zeros(0, dtype=np.uint8)
    pal = np.array(palette, dtype=np.int32)
    h, w = img_rgb.shape[:2]
    rgb = img_rgb.astype(np.int32).reshape(-1, 3)
    dists = np.abs(rgb[:, None, :] - pal[None, :, :]).sum(axis=2)
    return dists.argmin(axis=1).astype(np.uint8).reshape(h, w)



# =============================================================================
# Rarity weights from a Student-t distribution (ν=3, t evenly spaced 0..3).
# Heavy-tailed enough that the rarest is still seeable (1 in ~160 mints), no
# explicit tier buckets. Each palette has a unique probability.
#
# Order = most common -> rarest, curated by aesthetic distinctiveness.
# =============================================================================

PALETTE_RANK = [
    'amber', 'moss', 'bone', 'ocean', 'ember', 'blood', 'desert', 'sunset',
    'jade', 'tide', 'peach', 'gold', 'storm', 'midnight',
    'violet', 'blush', 'rust', 'aurora', 'ghost',
    'toxic', 'acid', 'neon', 'void',
]
assert set(PALETTE_RANK) == set(_PRIMARY_KEYS), \
    f"PALETTE_RANK does not cover all palettes: missing={set(_PRIMARY_KEYS) - set(PALETTE_RANK)}"

# Integer weights from t-PDF(ν=3, t ∈ [0, 3]) scaled so max=1000.
# Computed once and frozen here so the circuit's PALETTE_PREFIX is stable.
PALETTE_WEIGHT = {
    'amber':    1000,  # 10.07%  (swapped with blood)
    'moss':      988,  #  9.95%
    'bone':      952,  #  9.59%
    'ocean':     897,  #  9.03%
    'ember':     828,  #  8.34%
    'blood':     750,  #  7.55%  (swapped with amber)
    'desert':    668,  #  6.73%
    'sunset':    588,  #  5.92%
    'jade':      513,  #  5.17%
    'tide':      443,  #  4.46%
    'peach':     381,  #  3.84%
    'gold':      327,  #  3.29%
    'storm':     279,  #  2.81%
    'midnight':  239,  #  2.41%
    'violet':    204,  #  2.05%
    'blush':     174,  #  1.75%
    'rust':      149,  #  1.50%
    'aurora':    128,  #  1.29%
    'ghost':     111,  #  1.12%
    'toxic':      95,  #  0.96%
    'acid':       83,  #  0.84%
    'neon':       72,  #  0.73%
    'void':       62,  #  0.62%
}

TOTAL_WEIGHT = sum(PALETTE_WEIGHT[n] for n in PALETTE_RANK)  # 9931

# Prefix-sum table the circuit uses: palette_idx = first i where prefix[i] > r,
# r = Poseidon2(face_pixels ‖ nonce) mod TOTAL_WEIGHT.
_cum = 0
PALETTE_PREFIX = []
for _name in PALETTE_RANK:
    _cum += PALETTE_WEIGHT[_name]
    PALETTE_PREFIX.append(_cum)
assert PALETTE_PREFIX[-1] == TOTAL_WEIGHT