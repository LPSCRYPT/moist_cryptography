// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Minimal pause + verifier-rotation timelock mixin.
///
/// Inheriting contract must:
///   - call `_initPausable(deployer)` from its constructor
///   - apply `whenNotPaused` to every state-changing entry point
///   - call `_requireDeployer()` from its `pause` / `unpause` overrides if it
///     wants different access control (default: stored deployer)
///
/// Verifier rotation lives here so both ShadowToken and FeatureNFT can pause
/// + rotate verifiers without copying the same code. The pattern:
///   - Initial set: deployer calls `setVerifier(slot, addr)` once; takes effect
///     immediately, sets `lockedAt[slot] = block.timestamp`.
///   - Subsequent rotation: deployer calls `proposeVerifier(slot, addr)`
///     (records `proposed[slot] = addr` + `proposedAt[slot] = block.timestamp`),
///     then waits TIMELOCK_DURATION, then calls `applyVerifier(slot)` to
///     replace the active verifier.
///   - Emergency: when contract is paused, deployer can `applyVerifierImmediate`
///     to bypass the timelock (the contract is unusable while paused, so the
///     timelock's "give users time to react" purpose is moot).
abstract contract PausableMixin {
    // ============== events ==============

    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event VerifierProposed(uint8 indexed slot, address newVerifier, uint64 unlockAt);
    event VerifierApplied(uint8 indexed slot, address newVerifier);
    event VerifierRotationCanceled(uint8 indexed slot);

    // ============== errors ==============

    error PausableNotDeployer();
    error PausableContractIsPaused();
    error PausableAlreadyPaused();
    error PausableNotPaused();
    error VerifierTimelockNotExpired(uint64 unlockAt, uint64 nowTs);
    error NoPendingRotation(uint8 slot);
    error EmergencyOnlyWhenPaused();

    // ============== state ==============

    /// 7-day timelock. Sufficient for users + indexers to react to a rotation.
    uint64 public constant TIMELOCK_DURATION = 7 days;

    address internal _pausableDeployer;
    bool public paused;

    // Per-slot rotation state. Slots are caller-defined uint8 ids.
    mapping(uint8 => address) public proposedVerifier;
    mapping(uint8 => uint64) public proposedAt;

    // ============== modifiers ==============

    modifier whenNotPaused() {
        if (paused) revert PausableContractIsPaused();
        _;
    }

    modifier whenPaused() {
        if (!paused) revert PausableNotPaused();
        _;
    }

    modifier onlyPausableDeployer() {
        if (msg.sender != _pausableDeployer) revert PausableNotDeployer();
        _;
    }

    // ============== init ==============

    function _initPausable(address deployer_) internal {
        _pausableDeployer = deployer_;
    }

    // ============== pause control ==============

    function pause() external onlyPausableDeployer {
        if (paused) revert PausableAlreadyPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyPausableDeployer {
        if (!paused) revert PausableNotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ============== verifier rotation ==============

    /// Propose a new verifier for `slot`. Inheriting contract decides what
    /// each slot id means (e.g. 0 = mint, 1 = transfer_shadow, etc.).
    function proposeVerifier(uint8 slot, address newVerifier) external onlyPausableDeployer {
        proposedVerifier[slot] = newVerifier;
        proposedAt[slot] = uint64(block.timestamp);
        uint64 unlockAt = uint64(block.timestamp) + TIMELOCK_DURATION;
        emit VerifierProposed(slot, newVerifier, unlockAt);
    }

    /// Cancel a pending rotation (deployer escape hatch).
    function cancelVerifierRotation(uint8 slot) external onlyPausableDeployer {
        proposedVerifier[slot] = address(0);
        proposedAt[slot] = 0;
        emit VerifierRotationCanceled(slot);
    }

    /// Apply a pending rotation after the timelock expires. Anyone may call
    /// (after timelock); the rotation was proposed by the deployer.
    /// Inheriting contract overrides `_writeVerifierSlot` to actually swap
    /// the verifier address into its storage layout.
    function applyVerifier(uint8 slot) external {
        address newV = proposedVerifier[slot];
        uint64 ts = proposedAt[slot];
        if (newV == address(0) || ts == 0) revert NoPendingRotation(slot);
        uint64 unlockAt = ts + TIMELOCK_DURATION;
        if (block.timestamp < unlockAt) {
            revert VerifierTimelockNotExpired(unlockAt, uint64(block.timestamp));
        }
        proposedVerifier[slot] = address(0);
        proposedAt[slot] = 0;
        _writeVerifierSlot(slot, newV);
        emit VerifierApplied(slot, newV);
    }

    /// Emergency immediate apply when contract is paused. Bypasses the
    /// timelock since the contract is unusable while paused -- the timelock's
    /// "give users time to react" purpose doesn't apply.
    function applyVerifierImmediate(uint8 slot) external onlyPausableDeployer whenPaused {
        address newV = proposedVerifier[slot];
        if (newV == address(0)) revert NoPendingRotation(slot);
        proposedVerifier[slot] = address(0);
        proposedAt[slot] = 0;
        _writeVerifierSlot(slot, newV);
        emit VerifierApplied(slot, newV);
    }

    /// Inheriting contract MUST implement: write `newVerifier` into the
    /// storage location indexed by `slot`.
    function _writeVerifierSlot(uint8 slot, address newVerifier) internal virtual;
}
