// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

import {
    FHE, euint256, euint128, euint32, externalEuint32, externalEuint128, externalEuint256
} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

// OZ upgradeable imports
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @title Groth16 verifier interface for zk-email proofs
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[] calldata pubSignals
    ) external view returns (bool);
}

/// @title Farewell POC (email-recipient version)
/// @notice Minimal on-chain PoC for posthumous message release via timeout.
/// - Recipients are EMAILS (string), not wallet addresses.
/// - Anyone can call `claim` after timeout; we emit an event with (email, data).
/// - On-chain data is public. Treat `data` as ciphertext in real use.
/// @dev NOTE: There is no recovery mechanism if a user is legitimately marked deceased
///      but was actually unable to ping (hospitalization, lost keys, etc.).
///      This is a known limitation to be addressed in future versions.
contract Farewell is Initializable, UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
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
        bool revoked;  // Marks if message has been revoked by owner (cannot be claimed)

        // ZK-Email reward fields
        uint256 reward;  // Per-message ETH reward for delivery
        bytes32[] recipientEmailHashes;  // Poseidon hashes of each recipient email (for multi-recipient)
        bytes32 payloadContentHash;  // Keccak256 hash of decrypted payload content
        uint256 provenRecipientsBitmap;  // Bitmap tracking which recipients have been proven (up to 256)
    }

    struct CouncilMember {
        address member;       // Council member address
        uint64 joinedAt;      // Timestamp when member joined
    }

    /// @notice User status enum for getUserState
    enum UserStatus {
        Alive,          // User is active and within check-in period
        Grace,          // User missed check-in but is within grace period
        Deceased,       // User is deceased (finalized or timeout)
        FinalAlive      // User was voted alive by council - cannot be marked deceased
    }

    /// @notice Council vote during grace period to decide alive/dead status
    struct GraceVote {
        mapping(address => bool) hasVoted;      // Track who has voted
        mapping(address => bool) votedAlive;    // Track how each member voted (true=alive, false=dead)
        uint256 aliveVotes;                     // Count of alive votes
        uint256 deadVotes;                      // Count of dead votes
        bool decided;                           // Whether a decision has been reached
        bool decisionAlive;                     // The decision (true=alive, false=dead)
    }

    struct User {
        string name;          // optional
        uint64 checkInPeriod; // seconds
        uint64 gracePeriod;   // seconds
        uint64 lastCheckIn;   // timestamp
        uint64 registeredOn;  // timestamp
        bool deceased;        // set after timeout or council vote
        bool finalAlive;      // set if council voted user alive - prevents future deceased status
        Notifier notifier;    // who marked as deceased
        uint256 deposit;      // ETH deposited for delivery costs
        // All messages for this user live here
        Message[] messages;
    }

    mapping(address => User) public users;
    mapping(address => CouncilMember[]) public councils;  // Per-user council members
    mapping(address => mapping(address => bool)) public councilMembers;  // Quick lookup: user => member => isMember
    mapping(address => GraceVote) internal graceVotes;  // Per-user grace period voting
    mapping(address => address[]) public memberToUsers;  // Reverse index: member => users they're council for
    mapping(bytes32 => bool) public rewardsClaimed;  // Track if reward was already claimed (user+messageIndex hash)

    // Mapping to track message hashes for efficient lookup
    mapping(bytes32 => bool) public messageHashes;

    // ZK-Email verifier storage
    address public zkEmailVerifier;  // Groth16 verifier contract address
    mapping(bytes32 => mapping(uint256 => bool)) public trustedDkimKeys;  // domainHash => pubkeyHash => isValid
    mapping(address => uint256) public lockedRewards;  // Total locked rewards per user

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
    event MessageEdited(address indexed user, uint256 indexed index);
    event MessageRevoked(address indexed user, uint256 indexed index);
    event CouncilMemberAdded(address indexed user, address indexed member);
    event CouncilMemberRemoved(address indexed user, address indexed member);
    event GraceVoteCast(address indexed user, address indexed voter, bool votedAlive);
    event StatusDecided(address indexed user, bool isAlive);
    event DepositAdded(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 indexed messageIndex, address indexed claimer, uint256 amount);
    event DeliveryProven(address indexed user, uint256 indexed messageIndex, uint256 recipientIndex, address claimer);
    event ZkEmailVerifierSet(address verifier);
    event DkimKeyUpdated(bytes32 domain, uint256 pubkeyHash, bool trusted);

    modifier onlyRegistered(address user) {
        require(users[user].lastCheckIn != 0, "not registered");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // REPLACES constructors & default constants wiring, sets initial owner
    function initialize() public initializer {
        __Ownable_init(msg.sender); // set initial owner (OZ v5 style)
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
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
    // Reduced from 256 to fit within 2048-bit FHEVM limit (7 limbs = 1792 bits + 128 bits s = 1920 bits)
    uint32 constant MAX_EMAIL_BYTE_LEN = 224;
    /// @notice Maximum payload byte length (optional, for future payload padding)
    uint32 constant MAX_PAYLOAD_BYTE_LEN = 10240; // 10KB
    
    // --- Reward constants ---
    uint256 constant BASE_REWARD = 0.01 ether;        // Base reward per message
    uint256 constant REWARD_PER_KB = 0.005 ether;    // Additional reward per KB of payload

    // --- Council constants ---
    uint256 constant MAX_COUNCIL_SIZE = 20;

    function _register(string memory name, uint64 checkInPeriod, uint64 gracePeriod) internal {
        require(checkInPeriod >= 1 days, "checkInPeriod too short");
        require(gracePeriod >= 1 days, "gracePeriod too short");
        require(bytes(name).length <= 100, "name too long");
        
        User storage u = users[msg.sender];

        if (u.lastCheckIn != 0) {
            // user is already registered, update configs
            require(!u.deceased, "user is deceased");
            uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
            require(block.timestamp <= checkInEnd, "check-in period expired");
            u.name = name;
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

    function ping() external onlyRegistered(msg.sender) {
        User storage u = users[msg.sender];
        require(!u.deceased, "user marked deceased");

        // If user was voted finalAlive, clear that status and reset vote state
        // so they re-enter the normal liveness cycle
        if (u.finalAlive) {
            u.finalAlive = false;
            _resetGraceVote(msg.sender);
        }

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
    ) internal onlyRegistered(msg.sender) returns (uint256 index) {
        User storage u = users[msg.sender];
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
        m.publicMessage = publicMessage;

        // Compute hash of all input attributes
        bytes32 messageHash = keccak256(abi.encode(
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

    /// @notice Add a message with per-message reward for delivery verification
    /// @param limbs Encrypted email limbs
    /// @param emailByteLen Original email byte length
    /// @param encSkShare Encrypted secret key share
    /// @param payload Encrypted message payload
    /// @param inputProof FHE input proof
    /// @param publicMessage Public message (optional)
    /// @param recipientEmailHashes Poseidon hashes of all recipient emails
    /// @param payloadContentHash Keccak256 hash of decrypted payload content
    function addMessageWithReward(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage,
        bytes32[] calldata recipientEmailHashes,
        bytes32 payloadContentHash
    ) external payable returns (uint256 index) {
        require(msg.value > 0, "must include reward");
        require(recipientEmailHashes.length > 0, "must have at least one recipient");
        require(recipientEmailHashes.length <= 256, "too many recipients");

        index = _addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, publicMessage);

        // Store reward and verification data
        User storage u = users[msg.sender];
        Message storage m = u.messages[index];
        m.reward = msg.value;
        m.recipientEmailHashes = recipientEmailHashes;
        m.payloadContentHash = payloadContentHash;
        m.provenRecipientsBitmap = 0;

        // Track locked rewards
        lockedRewards[msg.sender] += msg.value;
    }

    function messageCount(address user) external view onlyRegistered(user) returns (uint256) {
        return users[user].messages.length;
    }

    /// @notice Revoke a message (only owner, not deceased, not claimed)
    /// @param index The index of the message to revoke
    function revokeMessage(uint256 index) external nonReentrant onlyRegistered(msg.sender) {
        User storage u = users[msg.sender];
        require(!u.deceased, "user is deceased");
        require(index < u.messages.length, "invalid index");
        
        Message storage m = u.messages[index];
        require(!m.revoked, "already revoked");
        require(!m.claimed, "cannot revoke claimed message");
        
        m.revoked = true;

        // Refund reward if one was attached
        if (m.reward > 0) {
            uint256 refund = m.reward;
            m.reward = 0;
            lockedRewards[msg.sender] -= refund;
            (bool success, ) = payable(msg.sender).call{value: refund}("");
            require(success, "ETH transfer failed");
        }

        emit MessageRevoked(msg.sender, index);
    }
    
    /// @notice Edit a message (only owner, not deceased, not claimed, not revoked)
    /// @param index The index of the message to edit
    function editMessage(
        uint256 index,
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage
    ) external onlyRegistered(msg.sender) {
        User storage u = users[msg.sender];
        require(!u.deceased, "user is deceased");
        require(index < u.messages.length, "invalid index");

        Message storage m = u.messages[index];
        require(!m.revoked, "cannot edit revoked message");
        require(!m.claimed, "cannot edit claimed message");
        require(emailByteLen > 0, "email len=0");
        require(emailByteLen <= MAX_EMAIL_BYTE_LEN, "email too long");
        require(limbs.length > 0, "no limbs");
        require(payload.length > 0, "bad payload size");
        require(payload.length <= MAX_PAYLOAD_BYTE_LEN, "payload too long");
        require(limbs.length == (uint256(MAX_EMAIL_BYTE_LEN) + 31) / 32, "limbs must match padded length");
        
        // Update encrypted email limbs
        m.recipientEmail.limbs = new euint256[](limbs.length);
        for (uint i = 0; i < limbs.length;) {
            euint256 v = FHE.fromExternal(limbs[i], inputProof);
            m.recipientEmail.limbs[i] = v;
            FHE.allowThis(v);
            FHE.allow(v, msg.sender);
            unchecked { ++i; }
        }
        m.recipientEmail.byteLen = emailByteLen;
        
        // Update encrypted skShare
        m._skShare = FHE.fromExternal(encSkShare, inputProof);
        FHE.allowThis(m._skShare);
        FHE.allow(m._skShare, msg.sender);
        
        // Update payload and public message
        m.payload = payload;
        m.publicMessage = publicMessage;

        // Invalidate old hash and recompute
        messageHashes[m.hash] = false;
        bytes32 messageHash = keccak256(abi.encode(
            limbs,
            emailByteLen,
            encSkShare,
            payload,
            publicMessage
        ));
        m.hash = messageHash;
        messageHashes[messageHash] = true;
        
        emit MessageEdited(msg.sender, index);
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
        return keccak256(abi.encode(
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
    /// @dev Users who have been voted "alive" by council cannot be marked deceased.
    function markDeceased(address user) external onlyRegistered(user) {
        User storage u = users[user];
        require(!u.deceased, "user already deceased");
        require(!u.finalAlive, "user voted alive by council");

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
        require(!m.revoked, "message was revoked");
        require(!m.claimed, "already claimed");
        m.claimed = true;
        m.claimedBy = claimerAddress;

        FHE.allow(m._skShare, claimerAddress);
        for (uint i = 0; i < m.recipientEmail.limbs.length;) {
            FHE.allow(m.recipientEmail.limbs[i], claimerAddress);
            unchecked { ++i; }
        }

        emit Claimed(user, index, claimerAddress);
    }

    // --- ZK-Email Proof Delivery ---

    /// @notice ZK-Email proof structure for Groth16 verification
    struct ZkEmailProof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        uint256[] publicSignals;  // [0]=recipientEmailHash, [1]=dkimPubkeyHash, [2]=contentHash
    }

    /// @notice Prove delivery to a single recipient (can be called multiple times for multi-recipient)
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    /// @param recipientIndex The recipient index within the message's recipientEmailHashes array
    /// @param proof The zk-email Groth16 proof
    function proveDelivery(
        address user,
        uint256 messageIndex,
        uint256 recipientIndex,
        ZkEmailProof calldata proof
    ) external {
        User storage u = users[user];
        require(u.deceased, "user not deceased");

        Message storage m = u.messages[messageIndex];
        require(m.claimed, "message not claimed");
        require(m.claimedBy == msg.sender, "not the claimer");
        require(recipientIndex < m.recipientEmailHashes.length, "invalid recipient");

        // Check not already proven for this recipient
        require((m.provenRecipientsBitmap & (1 << recipientIndex)) == 0, "already proven");

        // Verify proof
        require(_verifyZkEmailProof(proof, m, recipientIndex), "invalid proof");

        // Mark recipient as proven
        m.provenRecipientsBitmap |= (1 << recipientIndex);

        emit DeliveryProven(user, messageIndex, recipientIndex, msg.sender);
    }

    /// @notice Internal function to verify zk-email proof
    function _verifyZkEmailProof(
        ZkEmailProof calldata proof,
        Message storage m,
        uint256 recipientIndex
    ) internal view returns (bool) {
        // Public signals layout (zk-email circuit):
        // [0] = Poseidon hash of recipient email (TO field)
        // [1] = DKIM public key hash
        // [2] = Content hash from email body

        // 1. Verify recipient email hash matches stored commitment
        if (proof.publicSignals.length < 3) {
            return false;
        }
        if (bytes32(proof.publicSignals[0]) != m.recipientEmailHashes[recipientIndex]) {
            return false;
        }

        // 2. Verify DKIM key is trusted (using global domain for now)
        if (!_isTrustedDkimKey(proof.publicSignals[1])) {
            return false;
        }

        // 3. Verify content hash matches
        if (bytes32(proof.publicSignals[2]) != m.payloadContentHash) {
            return false;
        }

        // 4. Verify Groth16 proof
        require(zkEmailVerifier != address(0), "verifier not configured");
        return IGroth16Verifier(zkEmailVerifier).verifyProof(
            proof.pA,
            proof.pB,
            proof.pC,
            proof.publicSignals
        );
    }

    /// @notice Check if a DKIM public key hash is trusted
    function _isTrustedDkimKey(uint256 pubkeyHash) internal view returns (bool) {
        // Check against global trusted keys (bytes32(0) represents global/any domain)
        return trustedDkimKeys[bytes32(0)][pubkeyHash];
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
        require(!m.revoked, "message was revoked");

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
    
    // --- Council functions ---
    
    /// @notice Add a council member (no stake required, max 20 members)
    /// @param member The address to add as council member
    function addCouncilMember(address member) external onlyRegistered(msg.sender) {
        require(member != address(0), "invalid member");
        require(member != msg.sender, "cannot add self");
        
        require(!councilMembers[msg.sender][member], "already a member");
        require(councils[msg.sender].length < MAX_COUNCIL_SIZE, "council full");

        councils[msg.sender].push(CouncilMember({
            member: member,
            joinedAt: uint64(block.timestamp)
        }));
        councilMembers[msg.sender][member] = true;
        
        // Add to reverse index
        memberToUsers[member].push(msg.sender);
        
        emit CouncilMemberAdded(msg.sender, member);
    }
    
    /// @notice Remove a council member (can be called by user only)
    /// @param member The address to remove from council
    function removeCouncilMember(address member) external {
        require(councilMembers[msg.sender][member], "not a member");
        
        CouncilMember[] storage council = councils[msg.sender];
        uint256 length = council.length;
        
        for (uint256 i = 0; i < length;) {
            if (council[i].member == member) {
                // Remove from array (swap with last element)
                if (i < length - 1) {
                    council[i] = council[length - 1];
                }
                council.pop();
                councilMembers[msg.sender][member] = false;

                // Clear stale vote if member voted during an active grace vote
                GraceVote storage vote = graceVotes[msg.sender];
                if (vote.hasVoted[member]) {
                    if (vote.votedAlive[member]) {
                        vote.aliveVotes--;
                    } else {
                        vote.deadVotes--;
                    }
                    delete vote.hasVoted[member];
                    delete vote.votedAlive[member];
                }

                // Remove from reverse index
                _removeFromMemberToUsers(member, msg.sender);

                emit CouncilMemberRemoved(msg.sender, member);
                return;
            }
            unchecked { ++i; }
        }
        revert("member not found");
    }
    
    /// @notice Internal helper to reset grace vote state for a user
    function _resetGraceVote(address user) internal {
        GraceVote storage vote = graceVotes[user];
        CouncilMember[] storage council = councils[user];
        uint256 length = council.length;
        for (uint256 i = 0; i < length;) {
            address m = council[i].member;
            delete vote.hasVoted[m];
            delete vote.votedAlive[m];
            unchecked { ++i; }
        }
        vote.aliveVotes = 0;
        vote.deadVotes = 0;
        vote.decided = false;
        vote.decisionAlive = false;
    }

    /// @notice Internal helper to remove user from memberToUsers reverse index
    function _removeFromMemberToUsers(address member, address userAddr) internal {
        address[] storage userList = memberToUsers[member];
        uint256 length = userList.length;
        for (uint256 i = 0; i < length;) {
            if (userList[i] == userAddr) {
                if (i < length - 1) {
                    userList[i] = userList[length - 1];
                }
                userList.pop();
                return;
            }
            unchecked { ++i; }
        }
    }
    
    /// @notice Vote on a user's status during grace period
    /// @param user The user to vote on
    /// @param voteAlive True to vote the user is alive, false to vote dead
    function voteOnStatus(address user, bool voteAlive) external onlyRegistered(user) {
        require(councilMembers[user][msg.sender], "not a council member");

        User storage u = users[user];
        require(!u.deceased, "user already deceased");
        require(!u.finalAlive, "status already finalized");
        
        // Check user is in grace period
        uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
        uint256 graceEnd = checkInEnd + uint256(u.gracePeriod);
        require(block.timestamp > checkInEnd, "not in grace period");
        require(block.timestamp <= graceEnd, "grace period ended");
        
        GraceVote storage vote = graceVotes[user];
        require(!vote.decided, "vote already decided");
        require(!vote.hasVoted[msg.sender], "already voted");
        
        vote.hasVoted[msg.sender] = true;
        vote.votedAlive[msg.sender] = voteAlive;
        
        if (voteAlive) {
            vote.aliveVotes++;
        } else {
            vote.deadVotes++;
        }
        
        emit GraceVoteCast(user, msg.sender, voteAlive);
        
        // Check for majority
        uint256 councilSize = councils[user].length;
        uint256 majority = (councilSize / 2) + 1;
        
        if (vote.aliveVotes >= majority) {
            // Majority voted alive - reset check-in and mark as finalAlive
            vote.decided = true;
            vote.decisionAlive = true;
            u.lastCheckIn = uint64(block.timestamp);
            u.finalAlive = true;
            emit StatusDecided(user, true);
            emit Ping(user, u.lastCheckIn);
        } else if (vote.deadVotes >= majority) {
            // Majority voted dead - mark as deceased
            vote.decided = true;
            vote.decisionAlive = false;
            u.deceased = true;
            u.notifier = Notifier({
                notificationTime: uint64(block.timestamp),
                notifierAddress: msg.sender
            });
            emit StatusDecided(user, false);
            emit Deceased(user, uint64(block.timestamp), msg.sender);
        }
    }
    
    /// @notice Get user's current status
    /// @param user The user address
    /// @return status The user's current status
    /// @return graceSecondsLeft Seconds left in grace period (0 if not in grace)
    function getUserState(address user) external view onlyRegistered(user) returns (UserStatus status, uint64 graceSecondsLeft) {
        User storage u = users[user];
        
        if (u.deceased) {
            return (UserStatus.Deceased, 0);
        }
        
        if (u.finalAlive) {
            return (UserStatus.FinalAlive, 0);
        }
        
        uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
        uint256 graceEnd = checkInEnd + uint256(u.gracePeriod);
        
        if (block.timestamp <= checkInEnd) {
            return (UserStatus.Alive, 0);
        } else if (block.timestamp <= graceEnd) {
            uint64 remaining = uint64(graceEnd - block.timestamp);
            return (UserStatus.Grace, remaining);
        } else {
            // Past grace period but not yet marked deceased
            return (UserStatus.Deceased, 0);
        }
    }
    
    /// @notice Get all users that a member is council for
    /// @param member The council member address
    /// @return userAddresses Array of user addresses
    function getUsersForCouncilMember(address member) external view returns (address[] memory userAddresses) {
        return memberToUsers[member];
    }
    
    /// @notice Get council members for a user
    /// @param user The user address
    /// @return members Array of council member addresses
    /// @return joinedAts Array of join timestamps
    function getCouncilMembers(address user) external view returns (
        address[] memory members,
        uint64[] memory joinedAts
    ) {
        CouncilMember[] storage council = councils[user];
        uint256 length = council.length;
        
        members = new address[](length);
        joinedAts = new uint64[](length);
        
        for (uint256 i = 0; i < length;) {
            members[i] = council[i].member;
            joinedAts[i] = council[i].joinedAt;
            unchecked { ++i; }
        }
    }
    
    /// @notice Get grace vote status for a user
    /// @param user The user address
    /// @return aliveVotes Number of alive votes
    /// @return deadVotes Number of dead votes
    /// @return decided Whether a decision has been reached
    /// @return decisionAlive The decision if decided (true=alive)
    function getGraceVoteStatus(address user) external view returns (
        uint256 aliveVotes,
        uint256 deadVotes,
        bool decided,
        bool decisionAlive
    ) {
        GraceVote storage vote = graceVotes[user];
        return (vote.aliveVotes, vote.deadVotes, vote.decided, vote.decisionAlive);
    }
    
    /// @notice Check if a council member has voted on a user's grace period
    /// @param user The user address
    /// @param member The council member address
    /// @return hasVoted Whether the member has voted
    /// @return votedAlive How they voted (only valid if hasVoted is true)
    function getGraceVote(address user, address member) external view returns (bool hasVoted, bool votedAlive) {
        GraceVote storage vote = graceVotes[user];
        return (vote.hasVoted[member], vote.votedAlive[member]);
    }
    
    // --- Deposits and Rewards ---
    
    /// @notice Deposit ETH to fund delivery costs
    function deposit() external payable onlyRegistered(msg.sender) {
        require(msg.value > 0, "must deposit something");

        User storage u = users[msg.sender];
        u.deposit += msg.value;
        
        emit DepositAdded(msg.sender, msg.value);
    }
    
    /// @notice Get user's deposit balance
    /// @param user The user address
    function getDeposit(address user) external view returns (uint256) {
        return users[user].deposit;
    }
    
    /// @notice Calculate reward for a message
    /// @param user The user address
    /// @param messageIndex The message index
    function calculateReward(address user, uint256 messageIndex) public view returns (uint256) {
        User storage u = users[user];
        require(messageIndex < u.messages.length, "invalid index");
        
        Message storage m = u.messages[messageIndex];
        uint256 payloadSizeKB = (m.payload.length + 1023) / 1024; // Round up to KB
        
        uint256 reward = BASE_REWARD + (payloadSizeKB * REWARD_PER_KB);
        
        // Cap reward at user's deposit
        if (reward > u.deposit) {
            reward = u.deposit;
        }
        
        return reward;
    }
    
    /// @notice Claim reward after ALL recipients have been proven via zk-email
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    function claimReward(
        address user,
        uint256 messageIndex
    ) external nonReentrant {
        User storage u = users[user];
        require(u.deceased, "user not deceased");
        require(messageIndex < u.messages.length, "invalid index");

        Message storage m = u.messages[messageIndex];
        require(m.claimed, "message not claimed");
        require(m.claimedBy == msg.sender, "not the claimer");
        require(m.reward > 0, "no reward");

        // Check all recipients have been proven
        uint256 numRecipients = m.recipientEmailHashes.length;
        if (numRecipients > 0) {
            uint256 requiredBitmap = (1 << numRecipients) - 1;
            require(m.provenRecipientsBitmap == requiredBitmap, "not all recipients proven");
        }

        // Check if reward already claimed (prevent double claiming)
        bytes32 rewardKey = keccak256(abi.encode(user, messageIndex));
        require(!rewardsClaimed[rewardKey], "already claimed");
        rewardsClaimed[rewardKey] = true;

        uint256 reward = m.reward;
        m.reward = 0;
        lockedRewards[user] -= reward;

        (bool success, ) = payable(msg.sender).call{value: reward}("");
        require(success, "ETH transfer failed");

        emit RewardClaimed(user, messageIndex, msg.sender, reward);
    }

    // --- Admin Functions ---

    /// @notice Set the zk-email Groth16 verifier contract address
    /// @param _verifier The verifier contract address
    function setZkEmailVerifier(address _verifier) external onlyOwner {
        zkEmailVerifier = _verifier;
        emit ZkEmailVerifierSet(_verifier);
    }

    /// @notice Set a DKIM public key hash as trusted or untrusted
    /// @param domain The domain hash (use bytes32(0) for global)
    /// @param pubkeyHash The DKIM public key hash
    /// @param trusted Whether this key should be trusted
    function setTrustedDkimKey(bytes32 domain, uint256 pubkeyHash, bool trusted) external onlyOwner {
        trustedDkimKeys[domain][pubkeyHash] = trusted;
        emit DkimKeyUpdated(domain, pubkeyHash, trusted);
    }

    /// @notice Get message reward information
    /// @param user The user's address
    /// @param messageIndex The message index
    function getMessageRewardInfo(address user, uint256 messageIndex) external view returns (
        uint256 reward,
        uint256 numRecipients,
        uint256 provenRecipientsBitmap,
        bytes32 payloadContentHash
    ) {
        User storage u = users[user];
        require(messageIndex < u.messages.length, "invalid index");

        Message storage m = u.messages[messageIndex];
        return (
            m.reward,
            m.recipientEmailHashes.length,
            m.provenRecipientsBitmap,
            m.payloadContentHash
        );
    }

    /// @notice Get recipient email hash at a specific index
    /// @param user The user's address
    /// @param messageIndex The message index
    /// @param recipientIndex The recipient index
    function getRecipientEmailHash(address user, uint256 messageIndex, uint256 recipientIndex) external view returns (bytes32) {
        User storage u = users[user];
        require(messageIndex < u.messages.length, "invalid index");

        Message storage m = u.messages[messageIndex];
        require(recipientIndex < m.recipientEmailHashes.length, "invalid recipient");

        return m.recipientEmailHashes[recipientIndex];
    }
}

