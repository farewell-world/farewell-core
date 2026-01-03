// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    FHE, euint256, euint128, euint32, externalEuint32, externalEuint128, externalEuint256
} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

// OZ upgradeable imports
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @title Farewell POC (email-recipient version)
/// @notice Minimal on-chain PoC for posthumous message release via timeout.
/// - Recipients are EMAILS (string), not wallet addresses.
/// - Anyone can call `claim` after timeout; we emit an event with (email, data).
/// - On-chain data is public. Treat `data` as ciphertext in real use.
/// @dev NOTE: There is no recovery mechanism if a user is legitimately marked deceased
///      but was actually unable to ping (hospitalization, lost keys, etc.).
///      This is a known limitation to be addressed in future versions.
contract Farewell is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    // Notifier is the entity that marked a user as deceased
    struct Notifier {
        uint64 notificationTime; // seconds
        address notifierAddress;
    }

    /// @dev Encrypted recipient "string" as 32-byte limbs (each limb is an euint256) + original length.
    /// @notice byteLen stores the original length for trimming during decryption.
    ///         All emails are padded to MAX_EMAIL_BYTE_LEN before encryption to prevent length leakage.
    struct EncryptedString {
        euint256[] limbs; // each 32 bytes of the UTF-8 email packed as uint256
        uint32 byteLen;   // original email length in bytes (not chars) - used for trimming padding
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
        /// @notice Public message stored in cleartext - visible to anyone
        string publicMessage;
        bytes32 hash;  // Hash of all input attributes
        bool deleted;   // Marks if message has been deleted by owner
    }

    struct User {
        string name;          // optional
        uint64 checkInPeriod; // seconds
        uint64 gracePeriod;   // seconds
        uint64 lastCheckIn;   // timestamp
        uint64 registeredOn;  // timestamp
        bool deceased;        // set after timeout
        Notifier notifier;    // who marked as deceased
        // All messages for this user live here
        Message[] messages;
    }

    mapping(address => User) public users;

    // Mapping to track message hashes for efficient lookup
    mapping(bytes32 => bool) public messageHashes;

    // Solidity automatically initializes all storage variables to zero by default.
    uint64 private totalUsers;
    uint64 private totalMessages;

    // Storage gap for upgradeability safety
    uint256[50] private __gap;

    // -----------------------
    // Events
    // -----------------------

    event UserUpdated(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn);
    event UserRegistered(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn);
    event Ping(address indexed user, uint64 when);
    event Deceased(address indexed user, uint64 when, address indexed notifier);

    event MessageAdded(address indexed user, uint256 indexed index);
    event Claimed(address indexed user, uint256 indexed index, address indexed claimer);
    event MessageDeleted(address indexed user, uint256 indexed index);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // REPLACES constructors & default constants wiring, sets initial owner
    function initialize() public initializer {
        __Ownable_init(msg.sender); // set initial owner (OZ v5 style)
        __UUPSUpgradeable_init();
        // Initialize FHEVM coprocessor using ZamaConfig (v0.9 - auto-resolves by chainId)
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
    }

    /// @notice Reinitializer for v2 upgrade - updates coprocessor config to new SDK version
    /// @dev This must be called after upgrading from v1 to v2 (FHEVM v0.9)
    function initializeV2() public reinitializer(2) {
        // Update the coprocessor config to use FHEVM v0.9 ZamaConfig
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
    }

    // UUPS authorization hook
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}

    /// @notice Expose the protocol id (useful for clients/frontends)
    function confidentialProtocolId() public view returns (uint256) {
        return ZamaConfig.getConfidentialProtocolId();
    }

    // --- User lifecycle ---
    uint64 constant DEFAULT_CHECKIN = 30 days;
    uint64 constant DEFAULT_GRACE = 7 days;
    
    // --- Message constants ---
    /// @notice Maximum email byte length (emails are padded to this length to prevent length leakage)
    uint32 constant MAX_EMAIL_BYTE_LEN = 256;
    /// @notice Maximum payload byte length (optional, for future payload padding)
    uint32 constant MAX_PAYLOAD_BYTE_LEN = 10240; // 10KB

    function _register(string memory name, uint64 checkInPeriod, uint64 gracePeriod) internal {
        require(checkInPeriod >= 1 days, "checkInPeriod too short");
        require(gracePeriod >= 1 days, "gracePeriod too short");
        require(bytes(name).length <= 100, "name too long");
        
        User storage u = users[msg.sender];

        if (u.lastCheckIn != 0) {
            // user is already registered, update configs
            u.checkInPeriod = checkInPeriod;
            u.gracePeriod = gracePeriod;
            emit UserUpdated(msg.sender, checkInPeriod, gracePeriod, u.registeredOn);
        } else {
            // new user
            u.name = name;
            u.checkInPeriod = checkInPeriod;
            u.gracePeriod = gracePeriod;
            u.lastCheckIn = uint64(block.timestamp);
            u.registeredOn = uint64(block.timestamp);
            u.deceased = false;
            totalUsers++;
            emit UserRegistered(msg.sender, checkInPeriod, gracePeriod, u.registeredOn);
        }

        emit Ping(msg.sender, u.lastCheckIn);
    }

    function register(string memory name, uint64 checkInPeriod, uint64 gracePeriod) external {
        _register(name, checkInPeriod, gracePeriod);
    }

    function register(uint64 checkInPeriod, uint64 gracePeriod) external {
        _register("", checkInPeriod, gracePeriod);
    }

    function register(string memory name) external {
        uint64 checkInPeriod = DEFAULT_CHECKIN;
        uint64 gracePeriod = DEFAULT_GRACE;
        _register(name, checkInPeriod, gracePeriod);
    }

    function register() external {
        uint64 checkInPeriod = DEFAULT_CHECKIN;
        uint64 gracePeriod = DEFAULT_GRACE;
        _register("", checkInPeriod, gracePeriod);
    }

    function isRegistered(address user) external view returns (bool) {
        return users[user].lastCheckIn != 0;
    }

    function getUserName(address user) external view returns (string memory) {
        User storage u = users[user];
        require(u.lastCheckIn != 0, "not registered");
        return u.name;
    }

    /// @notice Update the user's display name
    function setName(string memory newName) external {
        User storage u = users[msg.sender];
        require(u.lastCheckIn != 0, "not registered");
        require(bytes(newName).length <= 100, "name too long");
        u.name = newName;
        emit UserUpdated(msg.sender, u.checkInPeriod, u.gracePeriod, u.registeredOn);
    }

    function getRegisteredOn(address user) external view returns (uint64) {
        User storage u = users[user];
        require(u.lastCheckIn != 0, "not registered");
        return u.registeredOn;
    }

    function getLastCheckIn(address user) external view returns (uint64) {
        User storage u = users[user];
        require(u.lastCheckIn != 0, "not registered");
        return u.lastCheckIn;
    }

    function getDeceasedStatus(address user) external view returns (bool) {
        User storage u = users[user];
        require(u.lastCheckIn != 0, "not registered");
        return u.deceased;
    }

    function getNumberOfRegisteredUsers() external view returns (uint64) {
        return totalUsers;
    }

    function getNumberOfAddedMessages() external view returns (uint64) {
        return totalMessages;
    }

    function ping() external {
        User storage u = users[msg.sender];
        require(u.checkInPeriod > 0, "not registered");
        require(!u.deceased, "user marked deceased");

        u.lastCheckIn = uint64(block.timestamp);

        emit Ping(msg.sender, u.lastCheckIn);
    }

    // --- Messages ---

    function _addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string memory publicMessage
    ) internal returns (uint256 index) {
        User storage u = users[msg.sender];
        require(u.checkInPeriod > 0, "user not registered");
        require(emailByteLen > 0, "email len=0");
        require(emailByteLen <= MAX_EMAIL_BYTE_LEN, "email too long");
        require(limbs.length > 0, "no limbs");
        require(payload.length > 0, "bad payload size");
        require(payload.length <= MAX_PAYLOAD_BYTE_LEN, "payload too long");
        // All emails must be padded to MAX_EMAIL_BYTE_LEN (8 limbs for 256 bytes)
        require(limbs.length == (uint256(MAX_EMAIL_BYTE_LEN) + 31) / 32, "limbs must match padded length");

        index = u.messages.length;
        u.messages.push();
        Message storage m = u.messages[index];

        // allocate and fill limbs directly, avoid extra locals
        m.recipientEmail.limbs = new euint256[](limbs.length);
        for (uint i = 0; i < limbs.length;) {
            euint256 v = FHE.fromExternal(limbs[i], inputProof);
            m.recipientEmail.limbs[i] = v;
            FHE.allowThis(v);
            FHE.allow(v, msg.sender);
            unchecked { ++i; }
        }
        m.recipientEmail.byteLen = emailByteLen;

        // assign directly, no temp var
        m._skShare = FHE.fromExternal(encSkShare, inputProof);
        FHE.allowThis(m._skShare);
        FHE.allow(m._skShare, msg.sender);

        m.payload = payload;
        m.createdAt = uint64(block.timestamp);
        if (bytes(publicMessage).length != 0) {
            m.publicMessage = publicMessage;
        }

        // Compute hash of all input attributes
        bytes32 messageHash = keccak256(abi.encodePacked(
            limbs,
            emailByteLen,
            encSkShare,
            payload,
            publicMessage
        ));
        m.hash = messageHash;
        messageHashes[messageHash] = true;  // Track hash for lookup

        totalMessages++;
        emit MessageAdded(msg.sender, index);
    }

    function addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof
    ) external returns (uint256 index) {
        return _addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, "");
    }

    function addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage
    ) external returns (uint256 index) {
        return _addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, publicMessage);
    }

    function messageCount(address user) external view returns (uint256) {
        User storage u = users[user];
        require(u.checkInPeriod > 0, "user not registered");
        return u.messages.length;
    }

    /// @notice Remove a message (only owner, not deceased, not claimed)
    /// @param index The index of the message to remove
    function removeMessage(uint256 index) external {
        User storage u = users[msg.sender];
        require(u.checkInPeriod > 0, "not registered");
        require(!u.deceased, "user is deceased");
        require(index < u.messages.length, "invalid index");
        
        Message storage m = u.messages[index];
        require(!m.deleted, "already deleted");
        require(!m.claimed, "cannot delete claimed message");
        
        m.deleted = true;
        emit MessageDeleted(msg.sender, index);
    }

    /// @notice Compute the hash of message inputs without adding the message
    /// @dev Useful for checking if a message with these inputs already exists
    function computeMessageHash(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        string calldata publicMessage
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            limbs,
            emailByteLen,
            encSkShare,
            payload,
            publicMessage
        ));
    }

    // --- Death and delivery ---
    /// @notice Mark a user as deceased after timeout period
    /// @dev Block timestamps can be manipulated by miners/validators within ~15 second windows.
    ///      Impact is low given reasonable check-in periods, but worth noting.
    function markDeceased(address user) external {
        User storage u = users[user];
        require(u.checkInPeriod > 0, "user not registered");
        require(!u.deceased, "user already deceased");

        // timeout condition: now > lastCheckIn + checkInPeriod + grace
        uint256 deadline = uint256(u.lastCheckIn) + uint256(u.checkInPeriod) + uint256(u.gracePeriod);
        require(block.timestamp > deadline, "not timed out");

        // the user is considered from now on as deceased
        u.deceased = true;

        // the sender who discovered that the user was deceased has priority to claim the message during the next 24h
        u.notifier = Notifier({
            notificationTime: uint64(block.timestamp),
            notifierAddress: msg.sender
        });

        emit Deceased(user, uint64(block.timestamp), u.notifier.notifierAddress);
    }

    /// @notice Anyone may trigger delivery after user is deceased.
    /// @dev Emits data+email; mark delivered to prevent duplicates.
    /// @dev NOTE: Re-claiming messages after the 24h exclusivity window is currently allowed.
    ///      This is a known limitation that will be addressed with a proof-of-delivery mechanism.
    ///      Once a claimer submits proof of message delivery after retrieve(), re-claiming should be prevented.
    ///      This mechanism is not yet implemented and should be added in a future version.
    /// @dev NOTE: Once FHE.allow() is called for a claimer, that permission persists.
    ///      If multiple parties claim different messages from the same user, they all get decryption access.
    ///      This may be intended behavior, but should be considered when designing the protocol.
    function claim(address user, uint256 index) external {
        User storage u = users[user];
        require(u.deceased, "not deliverable");
        require(index < u.messages.length, "invalid index");

        address claimerAddress = msg.sender;

        // if within 24h of notification, only the notifier can claim
        if (block.timestamp <= uint256(u.notifier.notificationTime) + 24 hours) {
            require(claimerAddress == u.notifier.notifierAddress, "still exclusive for the notifier");
        }

        Message storage m = u.messages[index];
        m.claimed = true;
        m.claimedBy = claimerAddress;

        FHE.allow(m._skShare, claimerAddress);
        for (uint i = 0; i < m.recipientEmail.limbs.length;) {
            FHE.allow(m.recipientEmail.limbs[i], claimerAddress);
            unchecked { ++i; }
        }

        emit Claimed(user, index, claimerAddress);
    }

    /// @notice Retrieve message data (encrypted handles are returned but can only be decrypted
    ///         by authorized parties via FHE.allow() permissions)
    /// @param owner The address of the message owner
    /// @param index The index of the message to retrieve
    function retrieve(address owner, uint256 index) external view returns (
        euint128 skShare,
        euint256[] memory encodedRecipientEmail,
        uint32 emailByteLen,
        bytes memory payload,
        string memory publicMessage,
        bytes32 hash
    ) {
        User storage u = users[owner];
        require(index < u.messages.length, "invalid index");

        Message storage m = u.messages[index];
        require(!m.deleted, "message was deleted");

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
        hash = m.hash;
    }
}

