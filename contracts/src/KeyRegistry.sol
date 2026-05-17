// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Binds an EOA address to its declared Grumpkin public key
///         (pkX, pkY). Once registered, the binding is immutable for that
///         EOA -- preventing a malicious caller from minting / receiving
///         tokens encrypted to a pk whose secret key they don't control.
///
///         Mints and transfers in the phase-2 stack assert
///         `keyRegistry.pkOf(msg.sender) == (pi.recipient_pk_x, pi.recipient_pk_y)`
///         for self-mint flows, and analogously for the recipient on
///         transfers. The registry itself is permissionless: anyone can
///         register THEIR OWN address with ANY pk. The trust assumption is
///         "if you registered a pk you don't have the sk for, you locked
///         yourself out -- not anybody else."
///
///         Future enhancement: require a Grumpkin Schnorr signature over
///         (msg.sender, chainId) at register time so the chain knows the
///         caller actually has the sk. Today's exhibition stack runs in a
///         trusted-deployer model so this is deferred.
contract KeyRegistry {
    error AlreadyRegistered();
    error NotRegistered(address who);
    error InvalidPk();

    /// EOA -> Grumpkin pkX. (0, 0) is the sentinel for unregistered.
    /// `register` rejects (0, 0) so a successful `Registered` event always
    /// corresponds to a non-sentinel binding (audit M-04).
    mapping(address => bytes32) public pkX;
    mapping(address => bytes32) public pkY;

    event Registered(address indexed who, bytes32 pkX, bytes32 pkY);

    /// Register caller's pk. One-shot per address (immutable after first call).
    /// (0, 0) is reserved as the unregistered sentinel and is rejected.
    function register(bytes32 _pkX, bytes32 _pkY) external {
        if (_pkX == bytes32(0) && _pkY == bytes32(0)) revert InvalidPk();
        if (pkX[msg.sender] != bytes32(0) || pkY[msg.sender] != bytes32(0)) {
            revert AlreadyRegistered();
        }
        pkX[msg.sender] = _pkX;
        pkY[msg.sender] = _pkY;
        emit Registered(msg.sender, _pkX, _pkY);
    }

    /// Returns (pkX, pkY) for `who`. Reverts if not registered. Callers that
    /// want the (0, 0) sentinel for unregistered can read pkX/pkY directly.
    function pkOf(address who) external view returns (bytes32, bytes32) {
        bytes32 x = pkX[who];
        bytes32 y = pkY[who];
        if (x == bytes32(0) && y == bytes32(0)) revert NotRegistered(who);
        return (x, y);
    }

    function isRegistered(address who) external view returns (bool) {
        return !(pkX[who] == bytes32(0) && pkY[who] == bytes32(0));
    }
}
