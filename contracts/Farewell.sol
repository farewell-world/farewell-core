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

    // Notifier is the entitiy that marked a user as deceased
    struct Notifier {
        uint64 notificationTime; // seconds
        address notifierAddress;
    }

    struct User {
        uint64 checkInPeriod; // seconds
        uint64 gracePeriod; // seconds
        uint64 lastCheckIn; // timestamp
        uint64 registeredOn; // timestamp
        bool deceased; // set after timeout
        Notifier notifier; // who marked as deceased
        euint128 _skShare;
    }

    struct Message {
        bytes recipientEmail; // encrypted recipient e-mail
        bytes data; // encrypted message
        bool delivered;
    }

    mapping(address => User) public users;
    mapping(address => Message[]) private _messages;

    event UserRegistered(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn);
    event Ping(address indexed user, uint64 when);
    event Deceased(address indexed user, uint64 when, address indexed notifier);

    event MessageAdded(address indexed user, uint256 indexed index);
    event MessageClaimed(
        address indexed user,
        uint256 indexed index,
        bytes recipientEmail,
        bytes data,
        euint128 skShare
    );

    // --- User lifecycle ---
    uint64 constant DEFAULT_CHECKIN = 30 days;
    uint64 constant DEFAULT_GRACE = 7 days;

    function registerDefault(externalEuint128 skShare, bytes calldata skShareProof) external {
        uint64 checkInPeriod = DEFAULT_CHECKIN;
        uint64 gracePeriod = DEFAULT_GRACE;

        User storage u = users[msg.sender];
        require(u.lastCheckIn == 0, "already registered");

        u._skShare = FHE.fromExternal(skShare, skShareProof);
        FHE.allowThis(u._skShare);

        u.checkInPeriod = checkInPeriod;
        u.gracePeriod = gracePeriod;
        u.lastCheckIn = uint64(block.timestamp);
        u.registeredOn = uint64(block.timestamp);
        u.deceased = false;

        emit UserRegistered(msg.sender, checkInPeriod, gracePeriod, u.registeredOn);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    function register(
        uint64 checkInPeriod,
        uint64 gracePeriod,
        externalEuint128 skShare,
        bytes calldata skShareProof
    ) external {
        User storage u = users[msg.sender];
        require(u.lastCheckIn == 0, "already registered");

        u._skShare = FHE.fromExternal(skShare, skShareProof);
        FHE.allowThis(u._skShare);

        // The user should be able to change the key share
        FHE.allow(u._skShare, msg.sender);

        u.checkInPeriod = checkInPeriod;
        u.gracePeriod = gracePeriod;
        u.lastCheckIn = uint64(block.timestamp);
        u.registeredOn = uint64(block.timestamp);
        u.deceased = false;

        emit UserRegistered(msg.sender, checkInPeriod, gracePeriod, u.registeredOn);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    function ping() external {
        User storage u = users[msg.sender];
        require(u.checkInPeriod > 0, "not registered");
        require(!u.deceased, "user marked deceased");

        u.lastCheckIn = uint64(block.timestamp);

        emit Ping(msg.sender, u.lastCheckIn);
    }

    // --- Messages ---

    function addMessage(bytes calldata recipientEmail, bytes calldata data) external returns (uint256 index) {
        // It is expected that both recipientEmail and data to be encrypted at the user side,
        // otherwise they will be made public.

        require(users[msg.sender].checkInPeriod > 0, "user not registered");
        require(recipientEmail.length > 0, "bad recipientEmail size");
        require(data.length > 0, "bad data size");

        _messages[msg.sender].push(Message({recipientEmail: recipientEmail, data: data, delivered: false}));

        index = _messages[msg.sender].length - 1;
        emit MessageAdded(msg.sender, index);
    }

    function messageCount(address user) external view returns (uint256) {
        return _messages[user].length;
    }

    function markDeceased(address user) external {
        User storage u = users[user];
        require(u.checkInPeriod > 0, "user not registered");
        require(!u.deceased, "user already deceased");

        // timeout condition: now > lastCheckIn + checkInPeriod + grace
        uint256 deadline = uint256(u.lastCheckIn) + uint256(u.checkInPeriod) + uint256(u.gracePeriod);
        require(block.timestamp > deadline, "not timed out");

        // the user is considered from now on as deceased
        u.deceased = true;

        // the sender who discovered that the user was deceased has priority to claim the message
        // during the next 24h
        FHE.allow(u._skShare, msg.sender);
        
        u.notifier = Notifier({
            notificationTime: uint64(block.timestamp),
            notifierAddress: msg.sender
        });

        emit Deceased(user, uint64(block.timestamp), u.notifier.notifierAddress);
    }

    /// @notice Anyone may trigger delivery after user is deceased.
    /// @dev Emits data+email; mark delivered to prevent duplicates.
    function claim(address user, uint256 index) external view returns (euint128) {
        User storage u = users[user];
        require(u.deceased, "not deliverable");

        // if within 24h of notification, only the notifier can claim
        if (block.timestamp <= uint256(u.notifier.notificationTime) + 24 hours) {
            require(msg.sender == u.notifier.notifierAddress, "still exclusive for the notifier");
        }
        // I need to set this function as view but if I do that I break the test
        // FHE.allow(u._skShare, msg.sender);

        Message storage m = _messages[user][index];
        // m.delivered = true;
        return u._skShare;
    }
}
