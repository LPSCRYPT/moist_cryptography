> **v1 historical document.** Describes the bridge protocol as deployed
> for v1 on Base Sepolia ↔ Ethereum Sepolia. The `staging` branch ships
> a reshaped v2 payload (per-slot `liveStateHash[16]`, `zIndexCommit`,
> `zIndexRevealed`, `t10Hi/t10Lo`); the cross-chain protocol itself is
> unchanged. See [`V2_STATUS.md`](V2_STATUS.md) for the v2 surface.

---

# Cross-chain bridge

A solved shadow on Base Sepolia (L2) can bridge to Ethereum Sepolia (L1) via
the OP-Stack `CrossDomainMessenger`. Burn / re-mint architecture:

```
L2 (Base Sepolia)                               L1 (Ethereum Sepolia)

┌─────────────────────────────┐                ┌────────────────────────────┐
│ ShadowToken                 │                │ ShadowMirrorL1 (ERC721)    │
│   solved[sid] = true        │                │                            │
│                             │                │                            │
│ ShadowBridgeL2              │                │                            │
│   bridgeShadow(sid, pi)     │                │                            │
│   bridged[sid] = OWNED_ON_L1│                │                            │
│   transferFrom(user,this,sid)               │                            │
│   sendMessage(L1Mirror, ...) ───────message ──>                          │
│                             │   ~7-day wait   │  receive from messenger;  │
│                             │   for L1 final  │  xDomainSender == bridge  │
│                             │                 │  mintFromBridge(payload)  │
│                             │                 │  _mint(recipient, sid)    │
└─────────────────────────────┘                └────────────────────────────┘

                 round-trip back to L2:

                                                   burnAndUnbridge(sid, l2)
                                                   sendMessage(L2Bridge, ...)
                              ─── unbridge msg ─────────────────────────┐
   unbridgeShadow(sid, recip)                                            │
   bridged[sid] = OWNED_ON_L2                                            │
   transferFrom(this, recip, sid) <───────────────────────────────────────┘
```

## Why solved-only

Pre-solve, the shadow's plaintext is encrypted under the L2 owner's key. If
we bridged the encrypted state to L1, decryption would still require the L2
owner's secret key — the L1 token would carry no extra information. After
`solve` the plaintext is publicly known on L2 (announced via the
`ShadowSolved` event) and the L1 mirror becomes a durable, permissionless
record of that revelation.

`ShadowBridgeL2.bridgeShadow` enforces `solved[sid] == true` at the contract
level. Pre-solve shadows revert with `NotSolved`.

## Trust model

The bridge is **trust-minimal**. The only party that can mint on L1 is the
canonical `L1CrossDomainMessenger` for Base Sepolia
(`0xC34855F4De64F1840e5686e64278da901e261f20` on Eth Sepolia), and only when
the cross-domain sender (set by the messenger) equals the deployed
`ShadowBridgeL2` address.

```solidity
function mintFromBridge(BridgePayload calldata p) external {
    if (msg.sender != l1Messenger) revert NotMessenger();
    address xsender = ICrossDomainMessenger(l1Messenger).xDomainMessageSender();
    if (xsender != l2Bridge) revert NotL2Bridge(xsender);
    ...
}
```

The L2 side is symmetric: `unbridgeShadow` is gated on
`msg.sender == L2_MESSENGER && xDomainMessageSender() == l1Mirror`.

`L2_MESSENGER` is the OP-Stack predeploy at
`0x4200000000000000000000000000000000000007` on every OP-Stack L2.

## Finality

The L2 → L1 path uses a standard OP-Stack withdrawal:

| Step                                          | Latency              |
|-----------------------------------------------|----------------------|
| L2 `bridgeShadow` confirmation                | ~2 s (Base soft-finality) |
| L2 output root proposal published on L1       | ~30 min              |
| `OptimismPortal.proveWithdrawalTransaction`   | call anytime after the proposal |
| Withdrawal challenge period                   | **7 days** on Base mainnet (configurable on Sepolia) |
| `OptimismPortal.finalizeWithdrawalTransaction`| call after challenge period; relays to L1 messenger which calls `mintFromBridge` |

In practice you wait 7 days, then submit two L1 transactions to claim. The
bridge gives you the L2 lock + L2 messenger receipt up-front; the L1 mint
arrives later. There is no escape hatch: if Base's challenge mechanism
operates as designed, your message will mint on L1.

The L1 → L2 path (`burnAndUnbridge`) is fast — L1 → L2 messages settle in
about a minute on OP Stack.

## Payload

The bridge sends the entire mirror state in the message:

```solidity
struct BridgePayload {
    uint256 shadowId;
    address recipient;            // L1 mintee
    bytes32 faceOriginId;
    uint8   color;
    bytes32 c2Commit;             // sponge_249 of original ciphertext
    bytes32 stateCommitsHash;
    bytes32 ecdhPubX;
    uint64[8] origPoses;
    ManifestEntry[16] manifest;   // kind / typeIdx / featureId / pose
    bytes   revealedPi;           // 261 * 32-byte solve PI (per-region commits + bytes)
}
```

`revealedPi` lets L1 indexers reconstruct the rendered face without joining
back to L2 events. The bridge verifies on the L2 side that
`keccak256(revealedPi[0..256]) == s.stateCommitsHash` so the L1 mirror's
stored data is provably consistent with what `solve` attested on L2.

## Round-trip

`ShadowMirrorL1.burnAndUnbridge` is the symmetric return path:

```solidity
function burnAndUnbridge(uint256 shadowId, address l2Recipient) external {
    if (ownerOf(shadowId) != msg.sender) revert NotMirrorOwner();
    _burn(shadowId);
    delete _mirrors[shadowId];
    delete _revealedPi[shadowId];
    ICrossDomainMessenger(l1Messenger).sendMessage(
        l2Bridge,
        abi.encodeWithSignature("unbridgeShadow(uint256,address)", shadowId, l2Recipient),
        DEFAULT_L2_GAS_LIMIT
    );
}
```

The L2 side resets `bridged[sid]` to `OWNED_ON_L2` and `transferFrom`s the
locked shadow to `l2Recipient`.

## Deployed (Base Sepolia ↔ Eth Sepolia)

A reference deployment is in [`examples/verification.md`](../examples/verification.md):

| Side | Contract | Address |
|------|----------|---------|
| L1 (Eth Sepolia)   | `ShadowMirrorL1` | `0x710559A34F5702460bEf0ca0a3b3181510aB4aA6` |
| L2 (Base Sepolia)  | `ShadowBridgeL2` | `0x04d79cf8E6a2A7B20823b298Ac59657b07981112` |

The L2 leg of one canonical run is recorded:

```
bridgeShadow tx     0x2dd6e98effda9a7427635f7ccbf893d073607f385a63967423a62f240506ddac
gas                 721,109   (4.3% of 16.78M cap)
bridge state        OWNED_ON_L1
```

## Cost

Single-trip:

| Side | Op | Gas | Approx cost @ 0.011 gwei |
|------|----|----:|---:|
| L2   | bridgeShadow             | 721,109 | ~0.000008 ETH |
| L1   | proveWithdrawal          | ~250,000 | depends on L1 gas |
| L1   | finalizeWithdrawal       | ~150,000 | depends on L1 gas |

Round-trip adds:

| Side | Op | Gas | Notes |
|------|----|----:|---|
| L1   | burnAndUnbridge          | ~150,000 | sends message |
| L2   | unbridgeShadow (relayed) | ~80,000  | called by L2 messenger |
