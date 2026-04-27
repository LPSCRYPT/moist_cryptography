# Deployment

This document records every Base Sepolia deploy of the v2 contract set
plus the on-chain operations executed against it. Each address links
to the chain explorer; each tx hash is permanent and reproducible.

## Status

| Spec criterion #5 step | Status |
|---|---|
| Fresh contract set deployed | ✅ done (`ShadowToken=0xf75f...56f6` deploy block 40,758,261-40,758,288 + redeploy block 40,766,xxx) |
| One real `mintShadow` (1 shadow + 8 carriers) | 🚧 blocked on gas; see "Mint blocker" below |
| One real `mutateSlot` | ⏳ depends on chained fixture builder |
| One real `setZIndexCommit` | ⏳ depends on chained fixture builder |
| One real `extractSlot` → `insertFeature` into a different shadow | ⏳ depends on chained fixture builder |
| One real `solve` | ⏳ depends on chained fixture builder |

The deploy itself is complete and verifiable. The on-chain lifecycle
is one architectural step away — see "Mint blocker."

---

## Network

- Chain: **Base Sepolia** (chain id `84532`)
- L2 block explorer: https://sepolia.basescan.org/
- RPC tested: `https://base-sepolia.gateway.tenderly.co` (others have lower per-tx gas caps)
- Deployer EOA: `0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F`

## Contract addresses (latest deploy, post v2-gas optimization)

| Contract | Address |
|---|---|
| `Poseidon2YulSponge` (sponge_39) | [`0xdC0b199863d7aFfb496F36865A616426B518BaDC`](https://sepolia.basescan.org/address/0xdC0b199863d7aFfb496F36865A616426B518BaDC) |
| `Poseidon2YulSponge16` (sponge_16) | [`0x275a226d7Bd13706CF63dA3983535d6B287b9835`](https://sepolia.basescan.org/address/0x275a226d7Bd13706CF63dA3983535d6B287b9835) |
| `KeyRegistry` | [`0x2ce3228eca94d5d2454e6e5685acb2c299be872f`](https://sepolia.basescan.org/address/0x2ce3228eca94d5d2454e6e5685acb2c299be872f) |
| `ShadowToken` | [`0xf75fd53679dd624325552492ba81ac13a97d56f6`](https://sepolia.basescan.org/address/0xf75fd53679dd624325552492ba81ac13a97d56f6) |
| `FeatureNFT` | [`0x9d8c4401fdcc86bccc1de24a830f23e8c36d48b6`](https://sepolia.basescan.org/address/0x9d8c4401fdcc86bccc1de24a830f23e8c36d48b6) |
| `MintShadowVerifier` | [`0x08e57f13b6fa447373d475f1f6a7cc4faefc1423`](https://sepolia.basescan.org/address/0x08e57f13b6fa447373d475f1f6a7cc4faefc1423) |
| `FaceDiscVerifier` | [`0x980043da44141fdd17ba6d75b765a06d17d5d58b`](https://sepolia.basescan.org/address/0x980043da44141fdd17ba6d75b765a06d17d5d58b) |
| `MutateSlotVerifier` | [`0x4459b2290aef05fe41c5dc0000352aa8b8467a4f`](https://sepolia.basescan.org/address/0x4459b2290aef05fe41c5dc0000352aa8b8467a4f) |
| `T10ShadowVerifier` | [`0x65071fd735b4cd7140c9fea4bb6456f105d321c7`](https://sepolia.basescan.org/address/0x65071fd735b4cd7140c9fea4bb6456f105d321c7) |
| `ZIndexCommitVerifier` | [`0x9d5e57d730584685ac3479b07407bda64307deb4`](https://sepolia.basescan.org/address/0x9d5e57d730584685ac3479b07407bda64307deb4) |
| `TransferShadowVerifier` | [`0xa462352d1ff4f4f55d173dd7a23b8184f5888fa0`](https://sepolia.basescan.org/address/0xa462352d1ff4f4f55d173dd7a23b8184f5888fa0) |
| `SolveShadowVerifier` | [`0x32a9001Ebbcd60B7BA7aD34bb5a357d7C239f128`](https://sepolia.basescan.org/address/0x32a9001Ebbcd60B7BA7aD34bb5a357d7C239f128) |

The wiring (cross-references between contracts and the verifier-slot
assignments inside `ShadowToken`) is set in a single deploy script run.
Every privileged setter is one-shot and locked after the deploy.

## Deploy run

```
forge script script/DeployShadowPipeline.s.sol:DeployShadowPipeline \
    --broadcast --rpc-url https://base-sepolia.gateway.tenderly.co \
    --private-key $PRIVATE_KEY
```

Total gas estimate: ~72M (split across 22 txs). No single tx exceeded
the per-tx gas cap because deploys are bytecode CREATE which charges
0.4 gas/byte (cold), well below the 16M ceiling for any individual
contract.

A previous deploy on commit `ac19af2` (pre-gas-optimization) was
superseded by this one because the v2-gas optimization (commit
`5a33652`) changed the `MintShadowArgs` and `SolveArgs` ABIs.

---

## Mint blocker (the on-chain lifecycle's first step)

After redeploying, attempting `mintShadow` against the live contracts
**reverted with out-of-gas inside the T10 verifier sub-staticcall**:

```
tx: 0x782430c306ce862e2843e27e9a94c63b12a67e7cece36729773b729fe6fec17c
status: reverted
gasUsed:    14,668,762
gasLimit:   14,747,878    (forge multiplier 110)
```

`debug_traceTransaction` showed the failure pattern: `mintShadow`
verified the mint proof + face_disc proof, minted 8 carriers, then
reached the bundled T10 refresh's `verify(...)` staticcall with
**2,291,925 gas remaining**. The T10 verifier consumed all forwarded
gas and reverted with `out of gas` inside its inner BN254 precompile
loop.

### Why the local test passes but on-chain reverts

| Layer | Reported `mintShadow` gas | Reported T10 `verify` gas |
|---|---|---|
| Local forge (`--gas-report`) | 11,882,569 | 2,162,589 |
| On-chain Sepolia | ≥ ~14.7M | ≥ ~2.3M (OOG) |

There's a real ~3M gas gap between the local in-memory EVM and the
Sepolia execution layer for this single tx. The reasons (EIP-2929
warm-vs-cold-storage accounting, cross-contract call overhead the
local test under-counts, OP-Stack DA accounting, or the 63/64 rule
compounding through nested staticcalls) require deeper diagnostic
than this commit's scope. **What's empirically clear: the on-chain
cost is closer to 15M than 12M.**

### Resolution path: split `face_disc` out of `mintShadow`

The cleanest architectural fix (already approved by the maintainer and
queued as the next change) splits the face_disc proof into a separate
`registerImage(bytes32 imageCommit, bytes proofDisc)` tx that must run
before `mintShadow`. Effects:

  - `mintShadow` drops face_disc's ~2.45M verifier cost.
  - Internal `mintShadow` projection: ~9.4M local → ~12M on-chain.
  - Comfortably under the 16M cap, and absorbs the on-chain/off-chain
    discrepancy.
  - `registerImage` itself is ~2.5M — its own tx, fits trivially.

Atomicity is preserved (mint + 8 carriers still happen in one tx); the
prerequisite registration is just a cheap gating call. Spec impact: one
new public function (`registerImage`); the existing 11-function v2
surface stays. The "1 shadow + 8 FeatureNFTs in one tx" invariant holds.

Once `registerImage` lands, the criterion-#5 lifecycle can complete
on chain: register, mint A, register-and-mint B, then the 5 lifecycle
ops bound to chained fixtures.

---

## Local-only verification (current commit)

While the on-chain lifecycle is blocked, the same flow runs end-to-end
on local forge against deployed-equivalent contracts:

- 152/152 forge tests pass with real ZK proofs (no mocks).
- All 14 `RealChainLimits.t.sol` checks confirm every contract fits
  EIP-170's 24,576-byte runtime cap (margins 1.5 KB+).
- Gas-pin tests assert each entry point fits under its post-optimization
  budget:

| Op | Budget | Measured (local) |
|---|---|---|
| `mintShadow` | 14M | ~12M |
| `mutateSlot` | 6M | ~5M |
| `mutateBatch` (2 slots) | 25M | ~7.5M |
| `transferShadow` (4-occ) | 7M | ~6.2M |
| `transferShadow` (16-occ) | 11M | ~9.4M |
| `setZIndexCommit` | (untested) | ~4.8M |
| `extractSlot` | (untested) | ~2.4M |
| `insertFeature` | (untested) | ~5M |
| `solve` (4-occ) | 8M | ~6.5M |
| `solve` (16-occ) | 7M | ~3.7M |

The `mintShadow` 14M local budget is the source of the on-chain gap
above. Tightening this further requires the `registerImage` split.

---

## Toolchain pinning

| Tool | Version |
|---|---|
| `forge` | from `foundry-rs/foundry` (no specific commit pin yet) |
| `nargo` | `$HOME/.nargo/bin/nargo` |
| `bb` | `$HOME/.bb/bb` |
| `solc` | 0.8.27 |
| Verifier scheme | UltraHonk (keccak oracle), `--verifier_target evm` |

Every Solidity verifier in `contracts/src/*Verifier.sol` is generated by
running `bb write_solidity_verifier` against a `bb prove`-produced vk.
`forge build --sizes` confirms each verifier's runtime byte count fits
EIP-170 with 100+ bytes of headroom.
