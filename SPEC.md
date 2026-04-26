# moist_cryptography — Technical Specification

## What it is

A face image becomes a sovereign cryptographic object. The image is encrypted
under the owner's key (ECIES over the Grumpkin curve); only the owner can
decrypt. On chain, the face exists as eight Poseidon2 commitments to its
eight landmark regions plus a single ciphertext commitment. Every state
transition that touches the encrypted bytes is gated by a zero-knowledge
proof — there is no privileged "trust the deployer" path.

The system runs on Base L2 with an Ethereum L1 mirror via the OP
CrossDomainMessenger.

## Core actions

| action | what happens | who can do it |
|---|---|---|
| **mint**        | Submit a face. The chain stores 8 region commitments, an ECIES ciphertext, and a 16-slot manifest (8 ORIGINAL + 8 EMPTY). | anyone with a valid mint proof for an unminted face |
| **mutate**      | Move / scale / rotate any slot's pose. Encrypted bytes unchanged; only the public manifest updates. | owner |
| **extract**     | Pull a single slot's bytes out as a standalone FeatureNFT, encrypted under a new recipient's key. The slot becomes EMPTY. | owner |
| **insert / remove** | Bind / unbind an existing FeatureNFT into / out of an EMPTY slot. Reversible; no proof required. | owner |
| **transfer**    | Re-encrypt the ciphertext to a new owner's key, atomically with NFT transfer. The new owner can decrypt; nobody else ever could. | owner |
| **solve**       | Reveal the full plaintext on chain. Locks all dynamic operations; the shadow becomes a static ERC-721. | owner |
| **setShadowT10** | Refresh the public 16×16 grayscale silhouette derived from the current encrypted state + current poses. | anyone holding a valid proof |
| **bridge**      | Lock the (solved) shadow on L2; mint a mirror on L1 via OP messenger. | owner |

## The seven zk proofs

Built in Noir 1.0.0-beta.19, proven with UltraHonk (Aztec `bb`), verified
on chain by Solidity verifiers (≤24,342 bytes for six of them; T10 is
larger and lives in its own slot).

| circuit | gates | proves (in plain English) |
|---|---|---|
| `face_disc`        | **mint** (gate)  | "The image I'm encrypting is a face: a small CNN discriminator (Conv[3->4->8->16->16] + x^2 + GAP + Linear) run in i64 fixed-point on the same image scores > 0." |
| `landmark_regions` | **mint**     | "That same image really has these 8 region commitments and packs into this ciphertext under this recipient's key." |
| `transfer_shadow`  | **transfer** | "I knew the previous owner's key. The new ciphertext is the same plaintext re-encrypted to the new owner — not a different image." |
| `extract_slot`     | **extract**  | "The 42 fields I'm extracting into a new FeatureNFT are byte-equal to the corresponding slot's bytes inside the shadow's plaintext." |
| `transfer_feature` | **transfer FeatureNFT** | Same shape as `transfer_shadow` but over the 42-field feature payload. |
| `solve_shadow`     | **solve**    | "I know the original face. The bytes I'm publishing match the commitments stored at mint." |
| `shadow_t10`       | **public silhouette refresh** | "The 256 public bits I'm posting are the deterministic composite of the encrypted bytes under the manifest's current poses, downsampled to a 16×16 grid of 4-level grayscale." |

`mintShadow` requires **both** a `face_disc` proof and a `landmark_regions`
proof in the same call. Each circuit emits
`image_commit = poseidon2_sponge_6912(image)` over the same 6912-element
CHW image as a public input (`face_disc.PI[0]` and `landmark_regions.PI[17]`).
The contract requires the two values to be equal, so a single private
image is bound under both circuits. A non-face image fails `face_disc` at
proof generation (the `assert(score > 0)` line in
`circuits/face_disc/src/main.nr`), so the mint cannot be completed even
if a legitimate landmark proof is in hand.

Every proof is bound to:

* the specific shadow (`shadowId` includes `chainid` — no cross-chain replay)
* the current ciphertext on chain (`prev_ct_commit` — no stale-witness replay)
* the current state nonce, where applicable (`stateNonce` — no out-of-order proofs)

The contract refuses any proof whose public inputs don't match what's stored
on chain.

## Where ML fits

Two CNNs run **inside** zk circuits as part of the mint. Both operate in
i64 fixed-point so their output is bit-exact and the prover cannot drift
from the constraints:

* **Landmark CNN** (in `landmark_regions`) — 5-point face landmark
  detector. The circuit constrains the CNN forward pass on the private
  image witness and asserts that the resulting landmark coordinates
  produce the 8 region byte-slices whose Poseidon2 commitments become the
  shadow's stateCommits. The image -> landmarks -> regions -> commitments
  chain is end-to-end constrained.
* **Disc CNN** (in `face_disc`, new) — a binary face / not-face
  discriminator: `Conv[3->4->8->16->16] + x^2 + GAP + Linear(16->1)`,
  ~1.8k parameters, weights at `tools/landmark/weights/disc_weights.json`
  (Python reference at `tools/landmark/discriminator.py`). The circuit
  evaluates the network on the private image at scale=1000 and asserts
  the output score is positive. Random noise fails this assertion at
  `nargo execute` time — there is no proof to submit.

The two circuits bind to the **same** private image via
`image_commit = poseidon2_sponge_6912(image)`, emitted as a public input
by both. The contract verifies both proofs and requires the two image
commits to match, so the discriminator's verdict applies to the exact
image whose region commitments are stored on chain.

Result: **non-face inputs cannot mint.** Cryptographic integrity (image
<-> ciphertext <-> commitments) and content gating (face / not-face) are
both enforced by zk, not by an off-chain oracle.

## Blockchain integration — beyond basic NFT functionality

The work does not use the chain as a registry of pointers to off-chain
images. The chain is the **substrate** of the work — the encrypted face,
its commitments, and the gates that govern its visibility all live there.

What the chain provides that no other medium does:

* **Custody as cryptographic proof, not as a database row.** Ownership *is*
  the decryption key. Transfer is not a row update — it is a re-encryption
  that the chain refuses unless a zk proof attests the plaintext is
  preserved. There is no admin who can "reset" or "recover" a face; the
  encryption is end-to-end against everyone, including the contract author.
* **Public ritual, private content.** Every state transition (mint,
  mutate, extract, insert, transfer, solve) is a public, indexable, and
  irreversible event. *That* something happened is fully visible to all.
  *What* the underlying face contains is visible only to whoever currently
  holds the key. The chain is a **consent ledger** — the audit trail of
  who has seen, and who can see.
* **Composability of identity.** A face is not monolithic. It is a 16-slot
  manifest, eight of which can be extracted into standalone FeatureNFTs and
  re-bound into different shadows. Eyes from one face can be inserted into
  another, removed, traded, recombined — all enforced by per-slot zk proofs
  that preserve byte-level integrity. Identity becomes a **construction**,
  visibly assembled and disassembled in public.
* **Two-tier persistence.** The L2 shadow is **dynamic and mortal** — it
  can be mutated, extracted from, transferred, finally solved. The L1
  mirror, reached via the OP messenger, is **frozen and eternal** — once
  bridged, the shadow exists on Ethereum mainnet's settlement layer as a
  static record. The work has a deliberate temporal architecture: change
  on Base, permanence on Ethereum.
* **The T10 silhouette as public art.** A 16×16 four-level grayscale grid
  derived from the encrypted bytes — the "small still voice" of the title.
  It is the *only* part of the face that anyone other than the owner can
  see, and it is itself the output of a zk proof. The public sees a
  whisper of the face: enough to recognise change (mutate, scale, rotate,
  pose) but never enough to recognise the person. Watching a shadow over
  time is watching the silhouette breathe.
* **Cross-chain message as ritual gesture.** Bridging is not a UX
  convenience — it is a one-way invocation. The L2 shadow locks
  irrevocably; an OP withdrawal-period later, the L1 mirror is mintable.
  The act of bridging marks the moment a private object enters a more
  conservative substrate.

### Artistic relevance

The piece is about **the conditions under which a face can be seen**. It
takes the technical apparatus of zero-knowledge proofs — engineered for
financial privacy and computational integrity — and uses it as the
grammar of consent.

Every viewer encounters the work twice. From the outside, they see only
the public T10 silhouette: a low-resolution, four-level grayscale
breathing pattern that responds to the owner's mutations but never
discloses identity. From the inside — only if they are the owner, or
have been granted custody — they see the face itself, decrypted from the
on-chain ciphertext with a key the chain itself enforces nobody else
possesses.

The title "il sussurro di una brezza leggera" / "small still voice"
(1 Kings 19:12) names the public artifact: not in the earthquake or the
fire, but in the whisper. What the chain shows the world about a face is
deliberately almost-nothing. What it shows the holder is everything.

The composability layer makes identity itself the medium. A face can be
unmade slot by slot, traded apart, recombined, eventually solved into
plaintext and frozen on L1. Each operation is a small, public, dated
gesture that survives all subsequent ones. The whole becomes a record of
how a face was lived through.

## Stack and dependencies

### Cryptography & proofs

* **Noir 1.0.0-beta.19** — circuit DSL. Seven production circuits + two
  helper circuits used by the Python harness for in-circuit-equivalent
  Poseidon2 hashing.
* **Aztec `bb` (barretenberg) 1.4.0** — UltraHonk-Keccak prover and
  Solidity verifier generator (`bb write_solidity_verifier`).
* **Poseidon2** over BN254 Fr — all on-chain commitments. Hand-written
  Yul sponge wrapper (`Poseidon2YulSponge.sol`) for gas-efficient
  binding checks.
* **ECIES on Grumpkin** (BN254 base field) — owner-bound encryption
  envelopes. Per-shadow `c2` is 249 fields; per-feature `c2_feat` is 42
  fields.

### EVM stack

* **Solidity 0.8.27**, `cancun` EVM, optimizer runs = 100 (calibrated
  to keep Honk verifiers under EIP-170 24,576-byte limit).
* **Foundry** (`forge`, `cast`, `anvil`) for contracts, tests, deploys,
  scripted e2e.
* **OpenZeppelin Contracts v5.4.0** — vendored as a git submodule.
  ERC-721 baseline.
* **forge-std v1.15.0** — vendored as a git submodule.
* **OP Stack `CrossDomainMessenger`** — L2 → L1 messaging for the bridge.

### Chains

* **Base Sepolia** (chainid 84532) — primary L2 deployment + e2e test
  target.
* **Ethereum Sepolia** (chainid 11155111) — L1 mirror.
* **Anvil** — local dev / CI.

### Off-chain harness

* **Python 3.11+** with `numpy`, `opencv-python`, `pillow`. The Python
  harness is the source of truth for fixture generation, byte-equality
  validation against on-chain ciphertexts, and end-to-end deployment
  scripting.
* **5-point landmark CNN** — vendored under `tools/landmark/`. Inference
  in fixed-point integer arithmetic so it agrees bit-exactly with the
  Noir circuit constraints. ~40 KB weights JSON.
* **Palette quantizer** — 23 fixed 10-color palettes used during the
  recolor step at mint.

### Generative tooling (data only, not part of the on-chain stack)

* **StyleGAN2-ADA** + **InterFaceGAN** — originally used to generate the
  parametric face grid and random samples; the curated subset that ships
  here covers seeds 101..119 unsteered (`grid_48/`) plus 25 random
  samples (`random_48/`).
* Two further diffusion-based subsets and the generator scripts that
  produced them were removed by the maintainer; the corpus shipped in
  `examples/faces/synthetic/` is a frozen 45-face curated test set.
  **None of the faces are real people.**

### Infrastructure

* **vast.ai (rented GPU)** — used for the heavy proof generation passes
  (`bb prove` on the T10 circuit needs ~16 GB RAM and ~12 minutes per
  proof). Compiled ACIR + witnesses are cached there; only the small
  per-step proof + public-input binaries are pulled back into the repo
  fixtures.
* **Local M-series Apple Silicon** — sufficient for everything else
  (forge, nargo execute, fixture rebuilds for the six verifier-bounded
  circuits including `face_disc`, all e2e harness execution). On an M3
  Pro, `face_disc` compile is ~7 min and `bb prove` ~3:24; `landmark_regions`
  compile is ~16 min and `bb prove` ~3:47.

### Reproducibility

* All proofs ship as binary fixtures under
  `contracts/test/fixtures/<circuit>/`. Forge tests verify them without
  needing nargo or bb installed.
* Submodules pinned to specific tags (`forge-std@v1.15.0`,
  `openzeppelin-contracts@v5.4.0`); see `lib/VERSIONS.md`.
* Visual demonstrations checked in at
  `examples/demo_t10_anvil.png` and `examples/demo_t10_sepolia.png`
  (chain-derived 8-step strips of the public silhouette + private composite).

## Verification

* **111 / 111** forge unit tests pass.
* **Phase 2 (6 verifier-bounded circuits, including `face_disc`) on Anvil**:
  full mint → mutate → extract → transferFeature → solve → transferFrom
  flow passes; mintShadow at 11,584,099 gas (under the 16,777,216-gas
  Sepolia per-tx cap). A noise-image negative test in
  `tools/test_noise_mint.py` confirms `face_disc` rejects non-faces at
  proof-generation time. Tx hashes for the prior 5-circuit Sepolia run
  are recorded in `examples/verification.md`; those addresses are stale
  and a fresh redeploy is required for the `face_disc` rollout.
* **T10 (7th circuit) on Base Sepolia**: 8 / 8 `setShadowT10` txs land,
  on-chain `(hi, lo)` byte-equals Python reference at every step.
  Visual artifact: `examples/demo_t10_sepolia.png`.
* **Cross-chain bridge L2 leg** verified on Sepolia. L1 mint completes
  after the OP withdrawal challenge period.
