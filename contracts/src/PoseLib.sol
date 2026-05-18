// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Pure-Solidity helpers for the 64-bit packed pose word stored
///         per slot in `ShadowToken.manifest`.
///
///         Layout (LSB-first):
///           bits  0.. 5  curX        (uint6, 0..63 -- 6 bits is intentional;
///                                     range-check enforces 0..47 at update)
///           bits  6..11  curY        (uint6, same)
///           bits 12..27  scaleQ88    (uint16; 256 = 1.0; max 65535 ~= 256.0)
///           bits 28..43  cosQ15      (int16; range [-32768, 32767]; 32767 ~= 1.0)
///           bits 44..59  sinQ15      (int16; same)
///           bits 60..63  reserved    (must be zero on read)
///         Total: 60 bits; fits in uint64.
///
///         Identity pose = pack(curX, curY, 256, 32767, 0).
///
///         Range checks are split into two layers:
///         - `requireSane(pose)`: everything that fits the bit layout
///           (no field exceeds its bit width).
///         - `requireOnFrame(pose, regionW, regionH)`: feature-aware bounds
///           (curX + regionW <= 48, etc.). The caller passes the slot's
///           feature width/height because PoseLib doesn't know slot type.
library PoseLib {
    error PoseFieldOutOfRange(uint8 fieldIdx, uint256 got);
    error PoseRotationNotUnit(int256 dotMinusOne);
    error PoseOffFrame(uint8 dim, uint256 got, uint256 max);
    error PoseScaleZero();

    /// Frame width and height for the canvas rendered into.
    uint16 internal constant FRAME_DIM = 48;

    /// Q15 fixed-point unit. (cos, sin) must satisfy cos^2 + sin^2 ~= ONE_Q30
    /// within a small tolerance to be a valid rotation.
    int256 internal constant ONE_Q30 = int256(1) << 30;
    /// Tolerance: ~0.0001 in Q30. Prevents numerical drift while rejecting
    /// obviously-bogus rotations (e.g. cos=sin=0 which would draw nothing).
    int256 internal constant ROT_TOLERANCE_Q30 = 1 << 20; // ~9.5e-4

    function pack(uint8 curX, uint8 curY, uint16 scaleQ88, int16 cosQ15, int16 sinQ15) internal pure returns (uint64) {
        if (curX >= 64) revert PoseFieldOutOfRange(0, curX);
        if (curY >= 64) revert PoseFieldOutOfRange(1, curY);
        // scaleQ88 is uint16 already; cosQ15/sinQ15 are int16 — both fit 16 bits.

        uint64 p = uint64(curX);
        p |= uint64(curY) << 6;
        p |= uint64(scaleQ88) << 12;
        p |= uint64(uint16(cosQ15)) << 28;
        p |= uint64(uint16(sinQ15)) << 44;
        return p;
    }

    function unpack(uint64 p)
        internal
        pure
        returns (uint8 curX, uint8 curY, uint16 scaleQ88, int16 cosQ15, int16 sinQ15)
    {
        curX = uint8(p & 0x3F);
        curY = uint8((p >> 6) & 0x3F);
        scaleQ88 = uint16((p >> 12) & 0xFFFF);
        cosQ15 = int16(uint16((p >> 28) & 0xFFFF));
        sinQ15 = int16(uint16((p >> 44) & 0xFFFF));
        // Reserved bits 60..63 must be zero on read; not asserted here, but
        // pack() never sets them so any non-zero value implies tampering.
    }

    /// Identity pose (no translation, no scaling, no rotation).
    function identity(uint8 curX, uint8 curY) internal pure returns (uint64) {
        return pack(curX, curY, 256, int16(32767), int16(0));
    }

    /// Bit-layout sanity. Cheap; called by every mutator.
    function requireSane(uint64 p) internal pure {
        // Reserved bits 60..63 must be zero.
        if ((p >> 60) != 0) revert PoseFieldOutOfRange(5, p >> 60);

        (uint8 curX, uint8 curY, uint16 scaleQ88, int16 cosQ15, int16 sinQ15) = unpack(p);

        // curX/curY must be on the frame (not just within their 6-bit slot).
        if (curX >= FRAME_DIM) revert PoseFieldOutOfRange(0, curX);
        if (curY >= FRAME_DIM) revert PoseFieldOutOfRange(1, curY);

        // scale > 0; scale = 0 = invisible (no point allowing).
        if (scaleQ88 == 0) revert PoseScaleZero();

        // (cos, sin) must be a unit rotation up to small numerical drift.
        // cos^2 + sin^2 should equal 32767^2 in Q30 = (2^15 - 1)^2 ~= 2^30.
        int256 cos = int256(cosQ15);
        int256 sin = int256(sinQ15);
        int256 dot = cos * cos + sin * sin;
        int256 diff = dot - ONE_Q30;
        if (diff > ROT_TOLERANCE_Q30 || -diff > ROT_TOLERANCE_Q30) {
            revert PoseRotationNotUnit(diff);
        }
    }

    /// Feature-aware on-frame check: the slot's content has bounding box
    /// (regionW x regionH) when scaleQ88 = 256 (identity scale). After scaling
    /// the effective box grows; we conservatively require that the unscaled
    /// box at curX, curY stays inside FRAME_DIM. This is a coarse bound; a
    /// more precise check would account for scale + rotation, but this is the
    /// minimum to keep the renderer from drawing off-frame slot ANCHORS.
    /// (Bytes that spill past the frame are clipped by the renderer.)
    function requireOnFrame(uint64 p, uint8 regionW, uint8 regionH) internal pure {
        (uint8 curX, uint8 curY,,,) = unpack(p);
        uint256 maxX = uint256(curX) + uint256(regionW);
        uint256 maxY = uint256(curY) + uint256(regionH);
        if (maxX > FRAME_DIM) revert PoseOffFrame(0, maxX, FRAME_DIM);
        if (maxY > FRAME_DIM) revert PoseOffFrame(1, maxY, FRAME_DIM);
    }
}
