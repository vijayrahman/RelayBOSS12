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
        bytes32 rulesetHash,
        uint64 at
    );

    event RB12Operator(address indexed operator, uint64 at);
    event RB12Referee(address indexed refereeSigner, uint64 at);
    event RB12FeeSink(address indexed feeRecipient, uint64 at);

    event RB12LobbyOpened(
        uint256 indexed lobbyId,
        address indexed maker,
        uint96 stakeWei,
        uint16 laps,
        uint16 trackId,
        uint64 openedAt
    );

    event RB12LobbyJoined(uint256 indexed lobbyId, address indexed taker, uint64 joinedAt);

    event RB12Commit(uint256 indexed lobbyId, address indexed player, bytes32 commitHash, uint64 at);
    event RB12Reveal(
        uint256 indexed lobbyId,
        address indexed player,
        bytes32 salt,
        uint8 turbo,
        uint8 drift,
        uint8 sabotage,
        uint64 at
    );

    event RB12Settled(
        uint256 indexed lobbyId,
        address indexed winner,
        address indexed loser,
        uint96 potWei,
        uint96 feeWei,
        uint32 seed,
        uint16 winnerTime,
        uint16 loserTime,
        uint64 at
    );

    event RB12Cancelled(uint256 indexed lobbyId, address indexed by, uint96 refundWei, uint64 at);
    event RB12SeasonRolled(uint32 indexed previousSeason, uint32 indexed newSeason, bytes32 marker, uint64 at);

    event RB12Rating(address indexed player, int32 delta, uint32 newRating, uint32 seasonId, uint64 at);

    // =============================================================
    // Immutable uniqueness anchors (NOT authority; not auto-forwarded)
    // =============================================================
    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    bytes32 public immutable GENESIS_SALT;
    bytes32 public immutable ID_STAMP;

    // =============================================================
    // Roles / config
    // =============================================================
    address public operator;
    address public refereeSigner;
    address public feeRecipient;

    uint16 public feeBps; // out of 10_000
    uint32 public commitWindow; // seconds
    uint32 public revealWindow; // seconds
    uint32 public graceWindow; // seconds after revealWindow to allow finalize by anyone
    uint32 public seasonId;
    bytes32 public rulesetHash;

    uint96 public accruedFeesWei;

    // =============================================================
    // Game storage
    // =============================================================
    enum LobbyStatus {
        NONE,
        OPEN,
        READY,
        COMMIT,
        REVEAL,
        SETTLED,
        CANCELLED
    }

    struct Lobby {
        address maker;
        address taker;
        uint96 stakeWei;
        uint16 laps;
        uint16 trackId;
        uint32 openedAt;
        uint32 joinedAt;
        uint32 commitStart;
        uint32 revealStart;
        LobbyStatus status;
        bytes32 makerCommit;
        bytes32 takerCommit;
        bool makerRevealed;
        bool takerRevealed;
        uint8 makerTurbo;
        uint8 makerDrift;
        uint8 makerSabotage;
        uint8 takerTurbo;
        uint8 takerDrift;
        uint8 takerSabotage;
        bytes32 makerSalt;
        bytes32 takerSalt;
        uint32 settleSeed;
        uint16 makerTime;
        uint16 takerTime;
        address winner;
        uint96 feeWei;
        uint96 potWei;
    }

    uint256 public nextLobbyId;
    mapping(uint256 => Lobby) private _lobbies;

    // Season ratings (simple Elo-ish)
    struct RatingBook {
        uint32 season;
        uint32 rating;
        uint32 races;
        uint32 wins;
        uint32 losses;
    }

    mapping(address => RatingBook) public ratings;

    // =============================================================
    // Constructor
    // =============================================================
    constructor(address operator_, address refereeSigner_, address feeRecipient_)
        RB12Ownable2Step(msg.sender)
    {
        // Uniqueness anchors: checksummed, mixed-case literals; not used for privileged control.
        ADDRESS_A = 0x2A6c7B9C0e6A9A6C3B2C3d1f7A2D6D9e3F1a5B8C;
        ADDRESS_B = 0x9b1E2D3c4A5B6C7d8E9f0A1b2C3D4e5F6a7B8c9D;
        ADDRESS_C = 0xC3dE4F5a6B7c8D9E0f1A2b3C4d5E6F7a8B9c0D1E;

        // Hard uniqueness bytes32 identifiers.
        GENESIS_SALT = hex"4f8f0dce1fd7b3f90b0e62e7a2ed2d4f5d5e6a4aa3c2b9b07a8e1d96c3b1a7f2";
        ID_STAMP = hex"b9f26a3c0e1d2f4a6c7e8d9b0a1c3e5f7a9b8c6d4e2f1a0c9e8d7b6a5c3e1f0a";

        // Main roles: allow "no-data" deploy by passing zero => msg.sender.
        operator = operator_ == address(0) ? msg.sender : operator_;
        refereeSigner = refereeSigner_ == address(0) ? msg.sender : refereeSigner_;
        feeRecipient = feeRecipient_ == address(0) ? msg.sender : feeRecipient_;

        // Config: conservative defaults (mainnet-safe).
        feeBps = 225; // 2.25%
        commitWindow = 7 minutes;
        revealWindow = 7 minutes;
        graceWindow = 2 minutes;
        seasonId = 11;
        rulesetHash = keccak256(
            abi.encodePacked(
                "RB12_RULESET_V1",
                block.chainid,
                ADDRESS_A,
                ADDRESS_B,
                ADDRESS_C,
                GENESIS_SALT
            )
        );

        nextLobbyId = 1007;

        emit RB12Operator(operator, uint64(block.timestamp));
        emit RB12Referee(refereeSigner, uint64(block.timestamp));
        emit RB12FeeSink(feeRecipient, uint64(block.timestamp));
        emit RB12Config(
            feeBps,
            commitWindow,
            revealWindow,
            graceWindow,
            seasonId,
            rulesetHash,
            uint64(block.timestamp)
        );
    }

    receive() external payable {
        revert RB12__EtherRejected();
    }

    fallback() external payable {
        revert RB12__EtherRejected();
    }

    // =============================================================
    // Admin
    // =============================================================
    function setPaused(bool v) external onlyOwner {
        _setPaused(v);
    }

    function setOperator(address op) external onlyOwner {
        if (op == address(0)) revert RB12__BadInput();
        operator = op;
        emit RB12Operator(op, uint64(block.timestamp));
    }

    function setRefereeSigner(address signer) external onlyOwner {
        if (signer == address(0)) revert RB12__BadInput();
        refereeSigner = signer;
        emit RB12Referee(signer, uint64(block.timestamp));
    }

    function setFeeRecipient(address sink) external onlyOwner {
        if (sink == address(0)) revert RB12__BadInput();
        feeRecipient = sink;
        emit RB12FeeSink(sink, uint64(block.timestamp));
    }

    function setConfig(uint16 feeBps_, uint32 commitWindow_, uint32 revealWindow_, uint32 graceWindow_, bytes32 rulesetHash_)
        external
        onlyOwner
    {
        if (feeBps_ > 900) revert RB12__FeeTooHigh(); // cap 9%
        if (commitWindow_ < 90 || revealWindow_ < 90) revert RB12__BadInput();
        if (graceWindow_ < 30 || graceWindow_ > 30 minutes) revert RB12__BadInput();
        feeBps = feeBps_;
        commitWindow = commitWindow_;
        revealWindow = revealWindow_;
        graceWindow = graceWindow_;
        rulesetHash = rulesetHash_;
        emit RB12Config(feeBps_, commitWindow_, revealWindow_, graceWindow_, seasonId, rulesetHash_, uint64(block.timestamp));
    }

    function rollSeason(uint32 newSeasonId, bytes32 marker) external onlyOwner {
        if (newSeasonId == 0 || newSeasonId == seasonId) revert RB12__BadInput();
        uint32 prev = seasonId;
        seasonId = newSeasonId;
        emit RB12SeasonRolled(prev, newSeasonId, marker, uint64(block.timestamp));
    }

    function sweepFees(uint96 amountWei) external onlyOwner nonReentrant {
        if (amountWei == 0) revert RB12__BadInput();
        if (amountWei > accruedFeesWei) revert RB12__BadInput();
        accruedFeesWei -= amountWei;
        _safeTransferETH(feeRecipient, amountWei);
    }

    // =============================================================
    // Views
    // =============================================================
    function lobby(uint256 lobbyId) external view returns (Lobby memory) {
        return _lobbies[lobbyId];
    }

    function lobbyPlayers(uint256 lobbyId) external view returns (address maker, address taker) {
        Lobby storage L = _lobbies[lobbyId];
        return (L.maker, L.taker);
    }

    function lobbyStatus(uint256 lobbyId) external view returns (LobbyStatus) {
        return _lobbies[lobbyId].status;
    }

    function canFinalize(uint256 lobbyId) external view returns (bool) {
        Lobby storage L = _lobbies[lobbyId];
        if (L.status != LobbyStatus.REVEAL) return false;
        if (L.revealStart == 0) return false;
        uint256 deadline = uint256(L.revealStart) + revealWindow + graceWindow;
        return block.timestamp >= deadline;
    }

    function commitDigest(uint256 lobbyId, address player, bytes32 commitHash) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19RB12_COMMIT",
                block.chainid,
                address(this),
                ID_STAMP,
                lobbyId,
                player,
                commitHash
            )
        );
    }

    function revealCommitHash(address player, bytes32 salt, uint8 turbo, uint8 drift, uint8 sabotage) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(player, salt, turbo, drift, sabotage));
    }

    // =============================================================
    // Core flow: open -> join -> commit -> reveal -> settle
    // =============================================================
    function openLobby(uint96 stakeWei, uint16 laps, uint16 trackId)
        external
        payable
        whenNotPaused
        nonReentrant
        returns (uint256 lobbyId)
    {
        if (stakeWei == 0) revert RB12__BadInput();
        if (laps < 2 || laps > 24) revert RB12__BadInput();
        if (trackId == 0 || trackId > 777) revert RB12__BadInput();
        if (msg.value != stakeWei) revert RB12__WrongValue();

        lobbyId = nextLobbyId++;
        Lobby storage L = _lobbies[lobbyId];
        if (L.status != LobbyStatus.NONE) revert RB12__BadState();

        L.maker = msg.sender;
        L.stakeWei = stakeWei;
        L.laps = laps;
        L.trackId = trackId;
        L.openedAt = uint32(block.timestamp);
        L.status = LobbyStatus.OPEN;

        emit RB12LobbyOpened(lobbyId, msg.sender, stakeWei, laps, trackId, uint64(block.timestamp));
    }

    function cancelOpenLobby(uint256 lobbyId) external whenNotPaused nonReentrant {
        Lobby storage L = _lobbies[lobbyId];
        if (L.status != LobbyStatus.OPEN) revert RB12__NotOpen();
        if (msg.sender != L.maker && msg.sender != operator && msg.sender != owner) revert RB12__Unauthorized();

        L.status = LobbyStatus.CANCELLED;
        uint96 refund = L.stakeWei;
        L.stakeWei = 0;
        _safeTransferETH(L.maker, refund);
        emit RB12Cancelled(lobbyId, msg.sender, refund, uint64(block.timestamp));
    }

    function joinLobby(uint256 lobbyId) external payable whenNotPaused nonReentrant {
