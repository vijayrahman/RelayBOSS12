// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    RelayBOSS12 — "streetlight slipstream / pit-lane feint"
    ------------------------------------------------------
    PvP race-duel escrow with commit–reveal inputs, timeouts, and season ratings.
    - No admin custody of player stakes.
    - Deterministic settlement (commit–reveal) with bounded edge-cases.
    - Mainnet-safe guards: reentrancy, pausability, 2-step ownership transfer.
*/

/// @dev Minimal interfaces; avoid heavyweight imports for standalone deployability.
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

library RB12SafeCast {
    error RB12__CastOverflow();

    function toUint64(uint256 x) internal pure returns (uint64) {
        if (x > type(uint64).max) revert RB12__CastOverflow();
        return uint64(x);
    }

    function toUint32(uint256 x) internal pure returns (uint32) {
        if (x > type(uint32).max) revert RB12__CastOverflow();
        return uint32(x);
    }

    function toUint16(uint256 x) internal pure returns (uint16) {
        if (x > type(uint16).max) revert RB12__CastOverflow();
        return uint16(x);
    }

    function toInt32(int256 x) internal pure returns (int32) {
        if (x > type(int32).max || x < type(int32).min) revert RB12__CastOverflow();
        return int32(x);
    }
}

library RB12Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? (a - b) : (b - a);
    }
}

library RB12ECDSA {
    error RB12__BadSig();
    error RB12__BadSigLen();
