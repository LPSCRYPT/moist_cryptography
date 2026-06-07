// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {PoseLib} from "../src/PoseLib.sol";

/// Wrapper exposing PoseLib internals as external functions so vm.expectRevert
/// works across the call boundary. (Inlined library calls revert in the same
/// frame, which expectRevert can't catch.)
contract PoseLibHarness {
    function pack(uint8 cx, uint8 cy, uint16 sc, uint8 turns) external pure returns (uint64) {
        return PoseLib.pack(cx, cy, sc, turns);
    }

    function requireSane(uint64 p) external pure {
        PoseLib.requireSane(p);
    }

    function requireOnFrame(uint64 p, uint8 w, uint8 h) external pure {
        PoseLib.requireOnFrame(p, w, h);
    }

    function identity(uint8 cx, uint8 cy) external pure returns (uint64) {
        return PoseLib.identity(cx, cy);
    }

    function unpack(uint64 p) external pure returns (uint8, uint8, uint16, uint8) {
        return PoseLib.unpack(p);
    }
}

contract PoseLibTest is Test {
    PoseLibHarness h;

    function setUp() public {
        h = new PoseLibHarness();
    }

    function test_PackUnpack_RoundTrip() public view {
        uint64 p = h.pack(0, 0, 256, 0);
        (uint8 cx, uint8 cy, uint16 sc, uint8 turns) = h.unpack(p);
        assertEq(cx, 0);
        assertEq(cy, 0);
        assertEq(sc, 256);
        assertEq(turns, 0);
    }

    function test_PackUnpack_QuarterTurn() public view {
        uint64 p = h.pack(10, 20, 512, 1);
        (uint8 cx, uint8 cy, uint16 sc, uint8 turns) = h.unpack(p);
        assertEq(cx, 10);
        assertEq(cy, 20);
        assertEq(sc, 512);
        assertEq(turns, 1);
        h.requireSane(p);
    }

    function test_Pack_Reverts_curX_OutOfBounds() public {
        vm.expectRevert(abi.encodeWithSelector(PoseLib.PoseFieldOutOfRange.selector, uint8(0), uint256(64)));
        h.pack(64, 0, 256, 0);
    }

    function test_Pack_Reverts_QuarterTurns_OutOfBounds() public {
        vm.expectRevert(abi.encodeWithSelector(PoseLib.PoseFieldOutOfRange.selector, uint8(3), uint256(4)));
        h.pack(10, 10, 256, 4);
    }

    function test_RequireSane_RejectsCurXAboveFrame() public {
        // Pack accepts 47..63 (uint6); requireSane rejects >= 48 (frame).
        uint64 p = h.pack(48, 0, 256, 0);
        vm.expectRevert();
        h.requireSane(p);
    }

    function test_RequireSane_RejectsZeroScale() public {
        uint64 p = h.pack(10, 10, 0, 0);
        vm.expectRevert(PoseLib.PoseScaleZero.selector);
        h.requireSane(p);
    }

    function test_RequireSane_RejectsReservedBitsSet() public {
        uint64 p = h.identity(10, 10);
        uint64 tampered = p | (uint64(1) << 30);
        vm.expectRevert();
        h.requireSane(tampered);
    }

    function test_RequireOnFrame_AcceptsOnFrame() public view {
        uint64 p = h.identity(10, 20);
        // eye is 33x8; 10 + 33 = 43 <= 48. OK.
        h.requireOnFrame(p, 33, 8);
    }

    function test_RequireOnFrame_AcceptsCenteredQuarterTurn() public view {
        // 24x11 at (12, 18), rotated 90 degrees around its center, occupies
        // x=[18,29), y=[12,36), preserving center while swapping extents.
        uint64 p = h.pack(12, 18, 256, 1);
        h.requireOnFrame(p, 24, 11);
    }

    function test_RequireOnFrame_RejectsQuarterTurnOffFrameX() public {
        // 24x11 at x=40 has center x=52. A 90-degree turn still overflows the frame.
        uint64 p = h.pack(40, 18, 256, 1);
        vm.expectRevert();
        h.requireOnFrame(p, 24, 11);
    }

    function test_RequireOnFrame_RejectsOffFrameX() public {
        uint64 p = h.identity(20, 0);
        vm.expectRevert();
        h.requireOnFrame(p, 48, 9);
    }

    function test_RequireOnFrame_RejectsOffFrameY() public {
        uint64 p = h.identity(0, 40);
        vm.expectRevert();
        h.requireOnFrame(p, 24, 11);
    }

    function test_Identity_HasUnitScale_AndZeroTurns() public view {
        uint64 p = h.identity(15, 25);
        (uint8 cx, uint8 cy, uint16 sc, uint8 turns) = h.unpack(p);
        assertEq(cx, 15);
        assertEq(cy, 25);
        assertEq(sc, 256);
        assertEq(turns, 0);
        h.requireSane(p);
    }
}
