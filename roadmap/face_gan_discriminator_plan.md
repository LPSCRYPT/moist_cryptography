# Roadmap: 48x48 Face Generator Against Facial Discriminator

## Goal

Build a research pipeline that trains and evaluates a generator capable of producing `48x48` face-like images that pass the current facial discriminator.

This is both a creative-generation project and an adversarial-security project. The important distinction:

- A generator that makes visually recognizable faces is useful for content generation.
- A generator that passes the discriminator is useful for testing whether the discriminator is gameable.

The success criterion should not be only “high discriminator pass rate.” It should also measure whether outputs are human-recognizable, diverse, and not just adversarial artifacts.

## Non-goals

- Do not treat discriminator pass as proof that an image is a semantically valid face.
- Do not deploy generated outputs directly into production minting without review.
- Do not weaken the facial discriminator to improve generator success.
- Do not rely on a single model family if the objective is security assurance.

## Core Questions

1. Can a generator produce `48x48` images that pass the existing discriminator?
2. Are those images visually recognizable as faces?
3. Are the outputs diverse, or are they near-duplicates/templates?
4. Can the discriminator be exploited by non-face adversarial images?
5. What failure cases should be added to the discriminator’s red-team corpus?

## Phase 1: Define Data and Image Format

### Tasks

1. Confirm the exact input format expected by the facial discriminator:
   - RGB bytes,
   - grayscale,
   - palette-indexed image,
   - normalized tensor,
   - flattened field representation,
   - any preprocessing used before proof/discriminator evaluation.

2. Define canonical image serialization:
   - dimensions: `48x48`,
   - channel count,
   - value range,
   - palette constraints, if any,
   - deterministic resize/crop behavior, if any.

3. Build a small Python utility layer:
   - load image,
   - normalize to discriminator input,
   - run discriminator locally,
   - save generated images,
   - compute pass/fail and score, if available.

### Deliverables

- `tools/facegen/io.py`
- `tools/facegen/discriminator_runner.py`
- A known-good positive/negative smoke-test dataset.

## Phase 2: Build Baseline Dataset

### Positive examples

Collect or synthesize examples that should pass:

- existing valid mint fixtures,
- accepted face crops,
- synthetic pixel-art faces,
- simple face templates with controlled variation.

### Negative examples

Collect examples that should fail:

- random noise,
- blank images,
- geometric patterns,
- non-face icons,
- adversarial-looking blobs,
- near-face but invalid layouts.

### Dataset requirements

The dataset should track:

- image bytes,
- source,
- discriminator result,
- discriminator score if available,
- human label: `face`, `non_face`, `ambiguous`, `artifact`,
- duplicate/near-duplicate hash.

### Deliverables

- `data/facegen/train/positive/`
- `data/facegen/train/negative/`
- `data/facegen/redteam/`
- `data/facegen/metadata.jsonl`

## Phase 3: Start With Non-GAN Baselines

Before training a GAN, establish cheaper baselines. This matters because if simple search can pass the discriminator, the discriminator is weaker than a GAN result would imply.

### Baselines

1. Random sampling over the valid image domain.
2. Template mutation:
   - eye positions,
   - mouth position,
   - symmetry,
   - contrast,
   - head oval/skin-tone region.
3. Evolutionary search:
   - mutate pixels or palette indices,
   - keep candidates with better discriminator score,
   - preserve diversity across candidates.
4. Latent search from an autoencoder, if one exists.

### Acceptance

- Measure discriminator pass rate.
- Save all passing examples.
- Human-review a sample of passing examples.
- Add non-face passers to the red-team corpus.

### Deliverables

- `tools/facegen/search_baseline.py`
- `reports/facegen_baselines.md`
- Red-team image corpus of discriminator false positives.

## Phase 4: Train a Small Generator

A classic GAN is feasible, but for `48x48` small images, also consider a VAE, VQ-VAE, or diffusion model. The first implementation can still be a simple GAN for speed.

### Candidate architectures

1. DCGAN-style generator/discriminator
   - simple,
   - fast,
   - good first baseline.

2. Conditional GAN
   - condition on pose/style/palette class,
   - better if multiple visual categories matter.

3. VQ-VAE or discrete autoencoder
   - useful if final images are palette-indexed,
   - supports latent-space search.

4. Tiny diffusion model
   - better diversity,
   - usually more stable than GANs,
   - slower but still feasible at `48x48`.

### Recommended first model

Start with a small DCGAN or WGAN-GP:

- latent dimension: 64 or 128,
- output: `48x48xC`,
- generator upsampling stack,
- discriminator downsampling stack,
- optional spectral normalization,
- WGAN-GP or hinge loss for stability.

### Deliverables

- `tools/facegen/train_gan.py`
- `tools/facegen/sample_gan.py`
- checkpoints under ignored path such as `artifacts/facegen/`
- sample grids every N epochs.

## Phase 5: Add Discriminator-Pass Objective

After the generator can produce plausible faces, optimize for passing the actual facial discriminator.

### If discriminator is differentiable

Use a combined loss:

```text
generator_loss = image_realism_loss + lambda * discriminator_pass_loss + diversity_loss
```

Where:

- `image_realism_loss` comes from GAN training,
- `discriminator_pass_loss` pushes generated images above the facial-discriminator threshold,
- `diversity_loss` discourages mode collapse and template repetition.

### If discriminator is black-box/pass-fail only

Use reinforcement/evolutionary fine-tuning:

- generate batch,
- score via discriminator,
- keep passers and near-passers,
- mutate latent vectors,
- train generator on successful samples,
- maintain diversity constraints.

### Critical guardrail

Track human-recognizable quality separately from discriminator pass rate.

A generator that outputs adversarial non-faces with a 99% pass rate is not a content generator; it is a discriminator exploit finder.

Both outcomes are useful, but they mean different things.

## Phase 6: Evaluation Metrics

### Quantitative metrics

- discriminator pass rate,
- score distribution,
- human-label pass rate,
- unique output count,
- near-duplicate rate,
- pixel entropy,
- symmetry metrics,
- simple landmark/region consistency,
- distance from training examples.

### Qualitative review

Review generated grids and classify samples:

- clear face,
- stylized face,
- ambiguous,
- artifact,
- non-face adversarial.

### Security metrics

- number of non-face images that pass,
- ease of finding passers from random initialization,
- minimum perturbation needed to flip fail -> pass,
- whether passers cluster around a small number of templates.

## Phase 7: Red-Team the Discriminator

Use the generator as a red-team tool.

### Red-team objectives

1. Maximize pass rate without preserving visual face quality.
2. Find minimal adversarial changes to non-faces.
3. Find template-like images that pass repeatedly.
4. Find edge cases around threshold boundaries.
5. Find palette/index patterns that exploit preprocessing.

### Deliverables

- `data/facegen/redteam/generated_passers/`
- `reports/discriminator_redteam.md`
- recommended discriminator hardening changes.

## Phase 8: Hardening Recommendations

If the generator finds bad passers, strengthen the discriminator before treating it as a protocol gate.

Possible mitigations:

1. Adversarial training using generated false positives.
2. Add geometric/landmark consistency checks.
3. Add entropy/contrast sanity checks.
4. Reject near-duplicate templates.
5. Require multiple independent discriminators to agree.
6. Keep discriminator/threshold updateable through the existing verifier/governance path.
7. Maintain a permanent red-team regression corpus.

## Suggested Repository Layout

```text
roadmap/
  face_gan_discriminator_plan.md

tools/facegen/
  io.py
  discriminator_runner.py
  search_baseline.py
  train_gan.py
  sample_gan.py
  evaluate.py

data/facegen/
  train/positive/
  train/negative/
  redteam/
  metadata.jsonl

reports/
  facegen_baselines.md
  discriminator_redteam.md

artifacts/facegen/        # ignored: checkpoints, samples, intermediate outputs
```

## Acceptance Criteria

The project is successful when it can answer these questions with evidence:

1. What pass rate can a trained generator achieve?
2. What percentage of generated passers are human-recognizable faces?
3. Can non-face artifacts pass the discriminator?
4. How diverse are passing outputs?
5. What discriminator weaknesses were discovered?
6. What red-team examples should be permanently added to regression tests?

## Recommended First Milestone

Build the discriminator runner and evolutionary baseline before training a GAN.

Reason: if simple search can produce passing non-faces, that is a stronger and cheaper signal than GAN success. It tells us the discriminator is directly exploitable and should be hardened before investing in better generative models.

First milestone deliverables:

- local discriminator runner,
- 100 known positive/negative samples,
- random/template/evolutionary baseline,
- report with passers and human labels.

Only after that should the project train the GAN or diffusion model.
