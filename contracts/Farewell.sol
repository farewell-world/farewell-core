// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    FHE,
    euint256,
    euint128,
    euint32,
    externalEuint32,
    externalEuint128,
    externalEuint256
} from "@fhevm/solidity/lib/FHE.sol";
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

    /// @dev Encrypted recipient “string” as 32-byte limbs (each limb is an euint256) + original length.
    struct EncryptedString {
        euint256[] limbs; // each 32 bytes of the UTF-8 email packed as uint256
        uint32 byteLen; // original email length in bytes (not chars)
    }

    struct Message {
        // Encrypted recipient email (coprocessor-backed euints) + encrypted skShare.
        EncryptedString recipientEmail; // encrypted recipient e-mail
        euint128 _skShare;
        // Your payload (already encrypted off-chain, e.g., tar+gpg) is fine to be public bytes
        bytes payload; // encrypted message
        uint64 createdAt;
        bool claimed;
        address claimedBy;
        string publicMessage;
    }

    struct User {
        uint64 checkInPeriod; // seconds
        uint64 gracePeriod; // seconds
        uint64 lastCheckIn; // timestamp
        uint64 registeredOn; // timestamp
        bool deceased; // set after timeout
        Notifier notifier; // who marked as deceased
        // All messages for this user live here
        Message[] messages;
    }

    mapping(address => User) public users;

    // -----------------------
    // Events
    // -----------------------

    event UserRegistered(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn);
    event Ping(address indexed user, uint64 when);
    event Deceased(address indexed user, uint64 when, address indexed notifier);

    event MessageAdded(address indexed user, uint256 indexed index);
    event Claimed(address indexed user, uint256 indexed index, address indexed claimer);

    // --- User lifecycle ---
    uint64 constant DEFAULT_CHECKIN = 30 days;
    uint64 constant DEFAULT_GRACE = 7 days;

    function _register(uint64 checkInPeriod, uint64 gracePeriod) internal {
        User storage u = users[msg.sender];
        require(u.lastCheckIn == 0, "already registered");

        u.checkInPeriod = checkInPeriod;
        u.gracePeriod = gracePeriod;
        u.lastCheckIn = uint64(block.timestamp);
        u.registeredOn = uint64(block.timestamp);
        u.deceased = false;

        emit UserRegistered(msg.sender, checkInPeriod, gracePeriod, u.registeredOn);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    function register(uint64 checkInPeriod, uint64 gracePeriod) external {
        _register(checkInPeriod, gracePeriod);
    }

    function register() external {
        uint64 checkInPeriod = DEFAULT_CHECKIN;
        uint64 gracePeriod = DEFAULT_GRACE;

        _register(checkInPeriod, gracePeriod);
    }

    function ping() external {
        User storage u = users[msg.sender];
        require(u.checkInPeriod > 0, "not registered");
        require(!u.deceased, "user marked deceased");

        u.lastCheckIn = uint64(block.timestamp);

        emit Ping(msg.sender, u.lastCheckIn);
    }

    // --- Messages ---

    function addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof
    ) external returns (uint256 index) {
        // It is expected that payload is encrypted at the user side,
        // otherwise it will be made public.
        User storage u = users[msg.sender];

        require(u.checkInPeriod > 0, "user not registered");
        require(emailByteLen > 0, "email len=0");
        require(limbs.length > 0, "no limbs");
        require(payload.length > 0, "bad payload size");

        // limbs count must match ceil(emailByteLen / 32)
        uint256 expected = (uint256(emailByteLen) + 31) / 32;
        require(limbs.length == expected, "limb count mismatch");

        // Stores the message inside the user array
        uint idx = u.messages.length;
        u.messages.push(); // grow array by one
        Message storage m = u.messages[idx];

        // Allocate the storage array for the limbs
        m.recipientEmail.limbs = new euint256[](limbs.length);

        // Convert handles -> encrypted values (proof is checked here)
        euint256[] storage stored = m.recipientEmail.limbs;
        for (uint i = 0; i < limbs.length; ) {
            stored[i] = FHE.fromExternal(limbs[i], inputProof);

            FHE.allowThis(stored[i]);
            FHE.allow(stored[i], msg.sender);

            unchecked {
                ++i;
            } // this skips overflow checks on the increment
        }

        euint128 storedShare = FHE.fromExternal(encSkShare, inputProof);
        m.recipientEmail = EncryptedString({limbs: stored, byteLen: emailByteLen});
        m._skShare = storedShare;
        m.payload = payload;
        m.createdAt = uint64(block.timestamp);

        FHE.allowThis(m._skShare);
        FHE.allow(m._skShare, msg.sender);

        emit MessageAdded(msg.sender, idx);
        return idx;
    }

    function addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage
    ) external returns (uint256 index) {
        // It is expected that payload is encrypted at the user side,
        // otherwise it will be made public.
        User storage u = users[msg.sender];

        require(u.checkInPeriod > 0, "user not registered");
        require(emailByteLen > 0, "email len=0");
        require(limbs.length > 0, "no limbs");
        require(payload.length > 0, "bad payload size");

        // limbs count must match ceil(emailByteLen / 32)
        uint256 expected = (uint256(emailByteLen) + 31) / 32;
        require(limbs.length == expected, "limb count mismatch");

        // Stores the message inside the user array
        uint idx = u.messages.length;
        u.messages.push(); // grow array by one
        Message storage m = u.messages[idx];

        // Allocate the storage array for the limbs
        m.recipientEmail.limbs = new euint256[](limbs.length);

        // Convert handles -> encrypted values (proof is checked here)
        euint256[] storage stored = m.recipientEmail.limbs;
        for (uint i = 0; i < limbs.length; ) {
            stored[i] = FHE.fromExternal(limbs[i], inputProof);

            FHE.allowThis(stored[i]);
            FHE.allow(stored[i], msg.sender);

            unchecked {
                ++i;
            } // this skips overflow checks on the increment
        }

        euint128 storedShare = FHE.fromExternal(encSkShare, inputProof);
        m.recipientEmail = EncryptedString({limbs: stored, byteLen: emailByteLen});
        m._skShare = storedShare;
        m.payload = payload;
        m.createdAt = uint64(block.timestamp);
        m.publicMessage = publicMessage;

        FHE.allowThis(m._skShare);
        FHE.allow(m._skShare, msg.sender);

        emit MessageAdded(msg.sender, idx);
        return idx;
    }

    function messageCount(address user) external view returns (uint256) {
        User storage u = users[user];
        require(u.checkInPeriod > 0, "user not registered");
        return u.messages.length;
    }

    // --- Death and delivery ---
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
        u.notifier = Notifier({notificationTime: uint64(block.timestamp), notifierAddress: msg.sender});

        emit Deceased(user, uint64(block.timestamp), u.notifier.notifierAddress);
    }

    /// @notice Anyone may trigger delivery after user is deceased.
    /// @dev Emits data+email; mark delivered to prevent duplicates.
    function claim(address user, uint256 index) external {
        User storage u = users[user];
        require(u.deceased, "not deliverable");

        address claimerAddress = msg.sender;

        // if within 24h of notification, only the notifier can claim
        if (block.timestamp <= uint256(u.notifier.notificationTime) + 24 hours) {
            require(claimerAddress == u.notifier.notifierAddress, "still exclusive for the notifier");
        }

        Message storage m = u.messages[index];
        m.claimed = true;
        m.claimedBy = claimerAddress;

        FHE.allow(m._skShare, claimerAddress);
        for (uint i = 0; i < m.recipientEmail.limbs.length; ) {
            FHE.allow(m.recipientEmail.limbs[i], claimerAddress);
            unchecked {
                ++i;
            } // this skips overflow checks on the increment
        }

        emit Claimed(user, index, claimerAddress);
    }

    function retrieve(
        address owner,
        uint256 index
    )
        external
        view
        returns (
            euint128 skShare,
            euint256[] memory encodedRecipientEmail,
            uint32 emailByteLen,
            bytes memory payload,
            string memory publicMessage
        )
    {
        User storage u = users[owner];
        require(index < u.messages.length, "invalid index");

        Message storage m = u.messages[index];

        bool isOwner = (msg.sender == owner);

        if (!isOwner) {
            // Only non-owners must satisfy delivery rules
            require(u.deceased, "owner not deceased");
            require(m.claimed, "message not claimed");
            require(m.claimedBy == msg.sender, "not claimant");
        }

        skShare = m._skShare;
        encodedRecipientEmail = m.recipientEmail.limbs; // copies to memory
        emailByteLen = m.recipientEmail.byteLen;
        payload = m.payload;
        publicMessage = m.publicMessage;
    }
}
