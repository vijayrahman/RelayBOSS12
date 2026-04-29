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

    // secp256k1n / 2
    bytes32 internal constant _HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert RB12__BadSigLen();
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (uint256(s) > uint256(_HALF_N)) revert RB12__BadSig();
        if (v != 27 && v != 28) revert RB12__BadSig();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert RB12__BadSig();
        return signer;
    }

    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}

abstract contract RB12ReentrancyGuard {
    uint256 private _rb12Guard;
    error RB12__Reentrancy();

    modifier nonReentrant() {
        if (_rb12Guard == 2) revert RB12__Reentrancy();
        _rb12Guard = 2;
        _;
        _rb12Guard = 1;
    }

    constructor() {
        _rb12Guard = 1;
    }
}

abstract contract RB12Pausable {
    event RB12Pause(bool paused, uint64 at);
    error RB12__Paused();

    bool public paused;

    modifier whenNotPaused() {
        if (paused) revert RB12__Paused();
        _;
    }

    function _setPaused(bool v) internal {
        paused = v;
        emit RB12Pause(v, uint64(block.timestamp));
    }
}

abstract contract RB12Ownable2Step {
    event RB12OwnershipProposed(address indexed previousOwner, address indexed proposedOwner, uint64 at);
    event RB12OwnershipTransferred(address indexed previousOwner, address indexed newOwner, uint64 at);
    error RB12__OwnerOnly();
    error RB12__PendingOwnerOnly();
    error RB12__BadOwner();

    address public owner;
    address public pendingOwner;

    modifier onlyOwner() {
        if (msg.sender != owner) revert RB12__OwnerOnly();
        _;
    }

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert RB12__BadOwner();
        owner = initialOwner;
        emit RB12OwnershipTransferred(address(0), initialOwner, uint64(block.timestamp));
    }

    function proposeOwner(address nextOwner) external onlyOwner {
        if (nextOwner == address(0)) revert RB12__BadOwner();
        pendingOwner = nextOwner;
        emit RB12OwnershipProposed(owner, nextOwner, uint64(block.timestamp));
    }

    function acceptOwner() external {
        if (msg.sender != pendingOwner) revert RB12__PendingOwnerOnly();
        address prev = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit RB12OwnershipTransferred(prev, owner, uint64(block.timestamp));
    }
}

contract RelayBOSS12 is RB12ReentrancyGuard, RB12Pausable, RB12Ownable2Step {
    using RB12SafeCast for uint256;
    using RB12Math for uint256;

    // =============================================================
    // Errors (unique prefix)
    // =============================================================
    error RB12__BadInput();
    error RB12__BadState();
    error RB12__NotPlayer();
    error RB12__AlreadyJoined();
    error RB12__NotOpen();
    error RB12__NotReady();
    error RB12__WrongValue();
    error RB12__TransferFailed();
    error RB12__TooEarly();
    error RB12__TooLate();
    error RB12__CommitMismatch();
    error RB12__RevealMismatch();
    error RB12__NotSettled();
    error RB12__AlreadySettled();
    error RB12__Unauthorized();
    error RB12__FeeTooHigh();
    error RB12__EtherRejected();
    error RB12__SigDenied();

    // =============================================================
    // Events (unique names)
    // =============================================================
    event RB12Config(
        uint16 feeBps,
        uint32 commitWindow,
        uint32 revealWindow,
        uint32 graceWindow,
        uint32 seasonId,
