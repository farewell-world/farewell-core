// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, euint128, euint32, externalEuint32, externalEuint128} from "@fhevm/solidity/lib/FHE.sol";
import {SepoliaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title Farewell POC (email-recipient version)
/// @notice Minimal on-chain PoC for posthumous message release via timeout.
/// - Recipients are EMAILS (string), not wallet addresses.
/// - Anyone can call `claim` after timeout; we emit an event with (email, data).
/// - On-chain data is public. Treat `data` as ciphertext in real use.
contract Farewell is SepoliaConfig {
    struct UserConfig {
        uint64 checkInPeriod; // seconds
        uint64 gracePeriod; // seconds
        uint64 lastCheckIn; // timestamp
        bool deceased; // set after timeout
        euint128 _skShare;
    }

    struct Message {
        string recipientEmail; // human-friendly identifier
        bytes32 recipientEmailHash; // keccak256(bytes(recipientEmail)) for indexed lookups
        bool delivered;
        bytes data; // store ciphertext or plaintext (PoC)
    }

    mapping(address => UserConfig) public users;
    mapping(address => Message[]) private _messages;

    event UserRegistered(address indexed user, uint64 checkInPeriod, uint64 gracePeriod);
    event Ping(address indexed user, uint64 when);
    event Deceased(address indexed user, uint64 when);

    // Indexed by email hash for efficient filtering; full email included (not indexed)
    event MessageAdded(
        address indexed user,
        uint256 indexed index,
        bytes32 indexed recipientEmailHash,
        string recipientEmail
    );
    event MessageClaimed(
        address indexed user,
        uint256 indexed index,
        bytes32 indexed recipientEmailHash,
        string recipientEmail,
        bytes data,
        euint128 skShare
    );

    // --- User lifecycle ---
    uint64 constant DEFAULT_CHECKIN = 30 days;
    uint64 constant DEFAULT_GRACE = 7 days;

    function registerDefault(externalEuint128 skShare, bytes calldata skShareProof) external {
        uint64 checkInPeriod = DEFAULT_CHECKIN;
        uint64 gracePeriod = DEFAULT_GRACE;
        UserConfig storage u = users[msg.sender];
        require(u.lastCheckIn == 0, "already registered");

        u._skShare = FHE.fromExternal(skShare, skShareProof);
        FHE.allowThis(u._skShare);

        u.checkInPeriod = checkInPeriod;
        u.gracePeriod = gracePeriod;
        u.lastCheckIn = uint64(block.timestamp);
        u.deceased = false;
        emit UserRegistered(msg.sender, checkInPeriod, gracePeriod);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    function register(
        uint64 checkInPeriod,
        uint64 gracePeriod,
        externalEuint128 skShare,
        bytes calldata skShareProof
    ) external {
        UserConfig storage u = users[msg.sender];
        require(u.lastCheckIn == 0, "already registered");

        u._skShare = FHE.fromExternal(skShare, skShareProof);
        FHE.allowThis(u._skShare);
        FHE.allow(u._skShare, msg.sender);

        u.checkInPeriod = checkInPeriod;
        u.gracePeriod = gracePeriod;
        u.lastCheckIn = uint64(block.timestamp);
        u.deceased = false;
        emit UserRegistered(msg.sender, checkInPeriod, gracePeriod);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    function ping() external {
        UserConfig storage u = users[msg.sender];
        require(u.checkInPeriod > 0, "not registered");
        require(!u.deceased, "user marked deceased");
        u.lastCheckIn = uint64(block.timestamp);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    function markDeceased(address user) external {
        UserConfig storage u = users[user];
        require(u.checkInPeriod > 0, "user not registered");
        require(!u.deceased, "user already deceased");
        // timeout condition: now > lastCheckIn + checkInPeriod + grace
        uint256 deadline = uint256(u.lastCheckIn) + uint256(u.checkInPeriod) + uint256(u.gracePeriod);
        require(block.timestamp > deadline, "not timed out");
        u.deceased = true;
        FHE.allow(u._skShare, msg.sender);
        users[user] = u;
        emit Deceased(user, uint64(block.timestamp));
    }

    // --- Messages ---

    function addMessage(string calldata recipientEmail, bytes calldata data) external returns (uint256 index) {
        require(users[msg.sender].checkInPeriod > 0, "register first");
        require(bytes(recipientEmail).length > 3, "bad email");
        require(data.length > 0 && data.length <= 2000, "bad size"); // keep small for PoC gas

        bytes32 emailHash = keccak256(bytes(recipientEmail));
        _messages[msg.sender].push(
            Message({recipientEmail: recipientEmail, recipientEmailHash: emailHash, delivered: false, data: data})
        );
        index = _messages[msg.sender].length - 1;
        emit MessageAdded(msg.sender, index, emailHash, recipientEmail);
    }

    function messageCount(address user) external view returns (uint256) {
        return _messages[user].length;
    }

    function getMessageMeta(
        address user,
        uint256 index
    ) external view returns (string memory recipientEmail, bytes32 recipientEmailHash, bool delivered) {
        require(index < _messages[user].length, "invalid index");
        Message storage m = _messages[user][index];
        return (m.recipientEmail, m.recipientEmailHash, m.delivered);
    }

    /// @notice Anyone may trigger delivery after user is deceased.
    /// @dev Emits data+email; mark delivered to prevent duplicates.
    function claim(address user, uint256 index) external view returns (euint128) {
        UserConfig storage u = users[user];
        require(u.deceased, "not deliverable");
        Message storage m = _messages[user][index];
        require(!m.delivered, "already delivered");
        // m.delivered = true;
        return u._skShare;
    }

    function getMyAddress() external view returns (address) {
        return msg.sender;
    }
}
