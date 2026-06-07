# Agent operating guide

This repo contains contracts, circuits, mint/render tooling, audit artifacts, and an interactive ShadowNFT simulator. Treat contract/circuit behavior as the source of truth; demo code must mirror it, not invent friendlier semantics.

## High-level rules

- Do not change contracts, circuits, generated fixtures, or audit claims without verifying the corresponding behavior.
- Do not add compatibility shims or parallel APIs when refactoring. Cut over all call sites and remove the old representation.
- For simulator work, edit `/tmp/generate_shadow_sim.py` first, then regenerate `audit/20_INTERACTIVE_SHADOWNFT_SIMULATOR.html`. The HTML is generated output.
- Preserve current on-chain transform semantics in the simulator:
  - Pose fields are `x`, `y`, `scaleQ88`, and `quarterTurns`.
  - Rotation is only exact quarter-turns: 0/90/180/270 degrees clockwise.
  - Rotation is a pixel permutation after scaling; it does not resample or destroy the feature payload.
  - Scaling uses nearest-neighbour sampling from the current stored feature pixel payload.
  - Placement is center-fixed after scaling/rotation and must remain on the 48×48 frame.
- Feature-bank previews are greyscale/shadow-market previews only. Placed features render their full color payload.
- Palette swatches show the selected palette; stored feature pixels conceptually come from palette indices expanded to RGB for rendering convenience.

## Files most agents need

- `contracts/src/PoseLib.sol` — canonical packed pose layout and on-frame checks.
- `tools/render_shadow.py` — canonical off-chain renderer for scale/quarter-turn/placement behavior.
- `tools/mint_pipeline.py` — face-state construction and palette quantization.
- `tools/landmark/palette_quantizer.py` — palette definitions and rank mapping.
- `tools/v2_circuit_helpers.py` — plaintext packing comments/helpers.
- `/tmp/generate_shadow_sim.py` — generator for the interactive simulator HTML.
- `audit/20_INTERACTIVE_SHADOWNFT_SIMULATOR.html` — generated simulator artifact.
- `audit/22_LOCAL_AI_COMPOSER_SERVER.py` — optional local composition API used by the simulator.

## Simulator regeneration and validation

From the repo root:

```sh
python3 /tmp/generate_shadow_sim.py
node - <<'NODE'
const fs=require('fs');
const s=fs.readFileSync('audit/20_INTERACTIVE_SHADOWNFT_SIMULATOR.html','utf8');
const js=s.slice(s.indexOf('<script>')+8,s.indexOf('</script>'));
new Function(js);
console.log('script ok', js.length);
NODE
```

Validate greyscale bank previews after generator changes:

```sh
python3 - <<'PY'
import base64, json, re
from io import BytesIO
from pathlib import Path
from PIL import Image
s=Path('audit/20_INTERACTIVE_SHADOWNFT_SIMULATOR.html').read_text()
features=json.loads(re.search(r'const FEATURES = (.*?);\nconst FACES', s).group(1))
for f in features:
    img=Image.open(BytesIO(base64.b64decode(f['marketSprite'].split(',',1)[1]))).convert('RGB')
    assert all(r == g == b and r in {48,117,186,255} for r,g,b in img.getdata()), f['id']
print('bank greyscale ok', len(features))
PY
```

## Local AI composition API

The workshop calls a local API to compose requested shapes from existing feature-bank entries. This API must call a real OpenAI-compatible model; it must not use hard-coded shape plans or fabricated output.

Start it from the repo root:

```sh
OPENAI_API_KEY=... python3 audit/22_LOCAL_AI_COMPOSER_SERVER.py
```

Optional environment:

```sh
OPENAI_MODEL=gpt-4o-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

Endpoint:

```text
POST http://127.0.0.1:8787/compose
Content-Type: application/json
```

Input shape:

```json
{
  "prompt": "make a horse",
  "canvas": { "w": 48, "h": 48 },
  "features": [
    {
      "id": "...",
      "featureName": "nose",
      "featureType": 3,
      "sourceFace": "...",
      "palette": "...",
      "w": 7,
      "h": 6,
      "location": "bank"
    }
  ]
}
```

Output shape:

```json
{
  "summary": "AI composition plan for 'make a horse' using 6 feature placements",
  "steps": [
    {
      "id": "feature-id-from-input",
      "slot": 0,
      "x": 10,
      "y": 24,
      "scale": 2,
      "quarterTurns": 1,
      "z": 0,
      "note": "head and muzzle"
    }
  ]
}
```

Constraints for any AI composer implementation:

- Use only feature IDs supplied by the page. Do not synthesize pixels.
- Call a real model provider. If the provider is not configured or fails, return an error; do not fabricate a plan.
- Return simulator/on-chain pose operations only: slot, x, y, snapped scale, quarterTurns, z.
- Keep `scale` in the legal simulator set: `0.125, 0.25, 0.5, 1, 2, 4, 8, 16`.
- Keep `quarterTurns` in `{0,1,2,3}`.
- Keep placements on the 48×48 frame; the page clamps as a guard, but the API should still return valid poses.
- Each playback step should be independently meaningful so the user can watch construction of the final image.

## Deployment note

The static workshop can be deployed independently of the local AI API. The deployed site will call `http://127.0.0.1:8787/compose`; if the local API or model provider is unavailable, composition fails visibly.

Known deployment project:

- Production alias: `https://shadownft-vercel.vercel.app`
- Vercel project: `xenomoderns-projects/shadownft-vercel`

Deploy static HTML by copying `audit/20_INTERACTIVE_SHADOWNFT_SIMULATOR.html` to the Vercel directory as `index.html` and running production deploy from that directory.
