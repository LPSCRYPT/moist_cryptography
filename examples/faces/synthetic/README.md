# Synthetic Faces (curated test corpus)

45 face PNGs at 48x48 RGB — the canonical shadow plaintext input shape
(`48 * 48 * 3 = 6912` bytes per face). **None of these are real people.**

The corpus is a frozen, curated subset of a larger generation run. The
maintainer removed the seed-100 trait-axis sweep and both RealVisXL
diffusion subsets, and removed the generator scripts that produced them.
The set shipped here is the canonical test corpus and is not intended to
be regenerated or extended in-tree.

## What's here

| dataset      | count | source                                          |
|--------------|------:|-------------------------------------------------|
| `grid_48/`   |    20 | StyleGAN2-ADA on FFHQ, neutrals for seeds 101..119 plus one s100_smile_+3 sample |
| `random_48/` |    25 | StyleGAN2 random samples (`rand_0000..rand_0024`) |

Plus `examples/faces/alice0.png` — the canonical mint test face, derived
from a recolored neutral face. The fixture's integrity binding is the
sha256 of the recolored byte buffer (`image_chw_sha256` in
`fixture.json`); the file at `alice0.png` is what actually drives every
mint test.

## Naming

* `grid_48/s<seed>_<axis>_<level>.png` — most files are `_neutral.png`
  (axis="neutral", level=0). One legacy `s100_smile_+3.png` remains.
* `random_48/rand_NNNN.png`.

## Metadata

| file                      | covers              | notes                                      |
|---------------------------|---------------------|--------------------------------------------|
| `metadata.json`           | grid_48 + random_48 | trait values per face, generator config    |
| `metadata_scored.json`    | grid_48 + random_48 | adds discriminator scores                  |

Both JSONs were pruned to reference only the on-disk faces; their `note`
fields call out that this is a frozen curated subset.

## Used by

* `tools/landmark/fixed_point_infer.py` — landmark detector smoke test
  defaults to `examples/faces/alice0.png`.
* `contracts/test/fixtures/mint_shadow/alice0/fixture.json` — records
  `examples/faces/alice0.png` as the source face (sha256 binding makes
  the path informational; the actual mint witness is the recolored
  byte buffer).
* The shadow mint pipeline (`tools/mint_pipeline.py`) operates on any
  48x48 RGB face; any image here is a valid drop-in for testing the
  pipeline on a fresh face.

## Why no regeneration recipe

Earlier revisions of this directory shipped `gen_faces.py` and
`gen_realvis.py`. Both were removed. The age-axis InterFaceGAN sweep
(`gen_faces.py`) and the prompt-conditioned diffusion sampler
(`gen_realvis.py`) could each produce age-ambiguous outputs that fall
outside the project's content boundaries, and shipping them would let
anyone reproduce that surface. Use a different, well-audited generation
pipeline if you need to extend the corpus.
