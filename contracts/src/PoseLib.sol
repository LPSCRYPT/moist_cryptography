// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Pure-Solidity helpers for the 64-bit packed pose word stored
///         in each slot plaintext.
///
///         Layout (LSB-first):
///           bits  0.. 5  curX          (uint6, 0..63 -- 6 bits is intentional;
///                                       range-check enforces 0..47 at update)
///           bits  6..11  curY          (uint6, same)
///           bits 12..27  scaleQ88      (uint16; 256 = 1.0; max 65535 ~= 256.0)
///           bits 28..29  quarterTurns  (uint2; clockwise 90-degree turns)
///           bits 30..63  reserved      (must be zero on read)
///         Total: 30 live bits; fits in uint64.
///
///         Identity pose = pack(curX, curY, 256, 0).
///
///         Range checks are split into two layers:
///         - `requireSane(pose)`: everything that fits the bit layout.
///         - `requireOnFrame(pose, regionW, regionH)`: feature-aware bounds
///           after scale and 90-degree rotation. The caller passes the slot's
///           feature width/height because PoseLib doesn't know slot type.
library PoseLib {
    error PoseFieldOutOfRange(uint8 fieldIdx, uint256 got);
    error PoseOffFrame(uint8 dim, uint256 got, uint256 max);
    error PoseScaleZero();

    /// Frame width and height for the canvas rendered into.
    uint16 internal constant FRAME_DIM = 48;

    function pack(uint8 curX, uint8 curY, uint16 scaleQ88, uint8 quarterTurns) internal pure returns (uint64) {
        if (curX >= 64) revert PoseFieldOutOfRange(0, curX);
        if (curY >= 64) revert PoseFieldOutOfRange(1, curY);
        if (quarterTurns >= 4) revert PoseFieldOutOfRange(3, quarterTurns);

        uint64 p = uint64(curX);
        p |= uint64(curY) << 6;
        p |= uint64(scaleQ88) << 12;
        p |= uint64(quarterTurns) << 28;
        return p;
    }

    function unpack(uint64 p) internal pure returns (uint8 curX, uint8 curY, uint16 scaleQ88, uint8 quarterTurns) {
        curX = uint8(p & 0x3F);
        curY = uint8((p >> 6) & 0x3F);
        scaleQ88 = uint16((p >> 12) & 0xFFFF);
        quarterTurns = uint8((p >> 28) & 0x03);
        // Reserved bits 30..63 must be zero on read; not asserted here, but
        // pack() never sets them so any non-zero value implies tampering.
    }

    /// Identity pose (no translation, unit scale, no rotation).
    function identity(uint8 curX, uint8 curY) internal pure returns (uint64) {
        return pack(curX, curY, 256, 0);
    }

    /// Bit-layout sanity. Cheap; called by every mutator.
    function requireSane(uint64 p) internal pure {
        // Reserved bits 30..63 must be zero.
        if ((p >> 30) != 0) revert PoseFieldOutOfRange(4, p >> 30);

        (uint8 curX, uint8 curY, uint16 scaleQ88,) = unpack(p);

        // curX/curY must be on the frame (not just within their 6-bit slot).
        if (curX >= FRAME_DIM) revert PoseFieldOutOfRange(0, curX);
        if (curY >= FRAME_DIM) revert PoseFieldOutOfRange(1, curY);

        // scale > 0; scale = 0 = invisible (no point allowing).
        if (scaleQ88 == 0) revert PoseScaleZero();
    }

    /// Feature-aware on-frame check for a center-fixed, scaled quarter-turn.
    /// `curX`/`curY` define the unrotated top-left. Rotation occurs around the
    /// unrotated feature center; 90/270 degree turns swap the effective extent.
    function requireOnFrame(uint64 p, uint8 regionW, uint8 regionH) internal pure {
        (uint8 curX, uint8 curY, uint16 scaleQ88, uint8 quarterTurns) = unpack(p);
        uint256 scaledW = _ceilScale(regionW, scaleQ88);
        uint256 scaledH = _ceilScale(regionH, scaleQ88);
        uint256 extentW = (quarterTurns & 1) == 0 ? scaledW : scaledH;
        uint256 extentH = (quarterTurns & 1) == 0 ? scaledH : scaledW;

        uint256 center2X = uint256(curX) * 2 + scaledW;
        uint256 center2Y = uint256(curY) * 2 + scaledH;

        if (center2X < extentW) revert PoseOffFrame(0, 0, FRAME_DIM);
        if (center2Y < extentH) revert PoseOffFrame(1, 0, FRAME_DIM);

        uint256 max2X = center2X + extentW;
        uint256 max2Y = center2Y + extentH;

        if ((max2X + 1) / 2 > FRAME_DIM) revert PoseOffFrame(0, (max2X + 1) / 2, FRAME_DIM);
        if ((max2Y + 1) / 2 > FRAME_DIM) revert PoseOffFrame(1, (max2Y + 1) / 2, FRAME_DIM);
    }

    function _ceilScale(uint8 dim, uint16 scaleQ88) private pure returns (uint256) {
        return (uint256(dim) * uint256(scaleQ88) + 255) >> 8;
    }
}
