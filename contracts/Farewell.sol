// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

import {FHE, euint256, euint128, externalEuint128, externalEuint256} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

// OZ upgradeable imports
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @title Groth16 verifier interface for zk-email proofs
/// @author Farewell Protocol
/// @notice Interface for Groth16 zk-SNARK proof verification used in zk-email delivery proofs
interface IGroth16Verifier {
    /// @notice Verify a Groth16 proof
    /// @param pA First proof element (G1 point)
    /// @param pB Second proof element (G2 point)
    /// @param pC Third proof element (G1 point)
    /// @param pubSignals Public signals for the proof
    /// @return True if the proof is valid, false otherwise
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[] calldata pubSignals
    ) external view returns (bool);
}

/// @title Farewell (email-recipient version)
/// @author Farewell Protocol
/// @notice On-chain posthumous message release via timeout.
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
        uint32 byteLen; // original email length in bytes (not chars) - used for trimming padding
    }

    struct Message {
        // Encrypted recipient email (coprocessor-backed euints) + encrypted skShare.
        EncryptedString recipientEmail; // encrypted recipient e-mail
        euint128 _skShare;
        // ZK-Email reward fields
        uint256 reward; // Per-message ETH reward for delivery
        uint256 provenRecipientsBitmap; // Bitmap tracking which recipients have been proven (up to 256)
        bytes32[] recipientEmailHashes; // Poseidon hashes of each recipient email (for multi-recipient)
        bytes32 payloadContentHash; // Keccak256 hash of decrypted payload content
        bytes32 hash; // Hash of all input attributes
        // Your payload (already encrypted off-chain, e.g., tar+gpg) is fine to be public bytes
        bytes payload; // encrypted message
        uint64 createdAt;
        address claimedBy;
        bool claimed;
        bool revoked; // Marks if message has been revoked by owner (cannot be claimed)
        /// @notice Public message stored in cleartext - visible to anyone
        string publicMessage;
    }

    struct CouncilMember {
        address member; // Council member address
        uint64 joinedAt; // Timestamp when member joined
    }

    /// @notice User status enum for getUserState
    enum UserStatus {
        Alive, // User is active and within check-in period
        Grace, // User missed check-in but is within grace period
        Deceased, // User is deceased (finalized or timeout)
        FinalAlive // User was voted alive by council - cannot be marked deceased
    }

    /// @notice Council vote during grace period to decide alive/dead status
    struct GraceVote {
        mapping(address => bool) hasVoted; // Track who has voted
        mapping(address => bool) votedAlive; // Track how each member voted (true=alive, false=dead)
        uint256 aliveVotes; // Count of alive votes
        uint256 deadVotes; // Count of dead votes
        bool decided; // Whether a decision has been reached
        bool decisionAlive; // The decision (true=alive, false=dead)
    }

    struct User {
        string name; // optional
        uint64 checkInPeriod; // seconds
        uint64 gracePeriod; // seconds
        uint64 lastCheckIn; // timestamp
        uint64 registeredOn; // timestamp
        bool deceased; // set after timeout or council vote
        bool finalAlive; // set if council voted user alive - prevents future deceased status
        Notifier notifier; // who marked as deceased
        uint256 deposit; // ETH deposited for delivery costs
        // All messages for this user live here
        Message[] messages;
    }

    // --- Custom Errors ---
    error NotRegistered();
    error UserDeceased();
    error UserAlive();
    error InvalidIndex();
    error AlreadyClaimed();
    error MessageWasRevoked();
    error AlreadyRevoked();
    error NotDeliverable();
    error InvalidMember();
    error CannotAddSelf();
    error AlreadyCouncilMember();
    error CouncilFull();
    error NotCouncilMember();
    error MemberNotFound();
    error NotInGracePeriod();
    error GracePeriodEnded();
    error VoteAlreadyDecided();
    error AlreadyVoted();
    error MustDepositSomething();
    error EthTransferFailed();
    error CheckInPeriodTooShort();
    error GracePeriodTooShort();
    error NameTooLong();
    error CheckInExpired();
    error EmailLenZero();
    error EmailTooLong();
    error NoLimbs();
    error BadPayloadSize();
    error PayloadTooLong();
    error LimbsMismatch();
    error MustIncludeReward();
    error MustHaveRecipient();
    error TooManyRecipients();
    error NotClaimant();
    error AlreadyProven();
    error InvalidProof();
    error VerifierNotConfigured();
    error NoReward();
    error NotAllRecipientsProven();
    error AlreadyRewardClaimed();
    error StillExclusiveForNotifier();
    error UserVotedAlive();
    error NotTimedOut();
    error MessageNotClaimed();

    /// @notice Mapping of user address to user data
    mapping(address user => User config) public users;
    /// @notice Mapping of user address to their council members
    mapping(address user => CouncilMember[] members) public councils;
    /// @notice Quick lookup: user => member => isMember
    mapping(address user => mapping(address member => bool isMember)) public councilMembers;
    /// @notice Per-user grace period voting state
    mapping(address user => GraceVote vote) internal graceVotes;
    /// @notice Reverse index: member => users they're council for
    mapping(address member => address[] users) public memberToUsers;
    /// @notice Track if reward was already claimed (user+messageIndex hash)
    mapping(bytes32 rewardKey => bool claimed) public rewardsClaimed;

    /// @notice Mapping to track message hashes for efficient lookup
    mapping(bytes32 msgHash => bool exists) public messageHashes;

    /// @notice Groth16 verifier contract address for zk-email proofs
    address public zkEmailVerifier;
    /// @notice Trusted DKIM public key hashes per domain
    mapping(bytes32 domain => mapping(uint256 pubkeyHash => bool trusted)) public trustedDkimKeys;
    /// @notice Total locked rewards per user
    mapping(address user => uint256 amount) public lockedRewards;

    // Solidity automatically initializes all storage variables to zero by default.
    uint64 private totalUsers;
    uint64 private totalMessages;

    // Storage gap for upgradeability safety
    uint256[50] private __gap;

    // -----------------------
    // Events
    // -----------------------

    /// @notice Emitted when a user's registration settings are updated
    /// @param user The user's address
    /// @param checkInPeriod The new check-in period in seconds
    /// @param gracePeriod The new grace period in seconds
    /// @param registeredOn The original registration timestamp
    event UserUpdated(
        address indexed user,
        uint64 indexed checkInPeriod,
        uint64 indexed gracePeriod,
        uint64 registeredOn
    );

    /// @notice Emitted when a new user registers
    /// @param user The user's address
    /// @param checkInPeriod The check-in period in seconds
    /// @param gracePeriod The grace period in seconds
    /// @param registeredOn The registration timestamp
    event UserRegistered(
        address indexed user,
        uint64 indexed checkInPeriod,
        uint64 indexed gracePeriod,
        uint64 registeredOn
    );

    /// @notice Emitted when a user performs a check-in
    /// @param user The user's address
    /// @param when The timestamp of the check-in
    event Ping(address indexed user, uint64 indexed when);

    /// @notice Emitted when a user is marked as deceased
    /// @param user The user's address
    /// @param when The timestamp of the deceased marking
    /// @param notifier The address that triggered the deceased marking
    event Deceased(address indexed user, uint64 indexed when, address indexed notifier);

    /// @notice Emitted when a message is added
    /// @param user The owner's address
    /// @param index The index of the new message
    event MessageAdded(address indexed user, uint256 indexed index);

    /// @notice Emitted when a message is claimed
    /// @param user The owner's address
    /// @param index The message index
    /// @param claimer The address that claimed the message
    event Claimed(address indexed user, uint256 indexed index, address indexed claimer);

    /// @notice Emitted when a message is edited
    /// @param user The owner's address
    /// @param index The message index
    event MessageEdited(address indexed user, uint256 indexed index);

    /// @notice Emitted when a message is revoked
    /// @param user The owner's address
    /// @param index The message index
    event MessageRevoked(address indexed user, uint256 indexed index);

    /// @notice Emitted when a council member is added
    /// @param user The user's address
    /// @param member The council member's address
    event CouncilMemberAdded(address indexed user, address indexed member);

    /// @notice Emitted when a council member is removed
    /// @param user The user's address
    /// @param member The removed council member's address
    event CouncilMemberRemoved(address indexed user, address indexed member);

    /// @notice Emitted when a council member casts a grace period vote
    /// @param user The user being voted on
    /// @param voter The council member casting the vote
    /// @param votedAlive True if the voter voted alive, false if voted dead
    event GraceVoteCast(address indexed user, address indexed voter, bool indexed votedAlive);

    /// @notice Emitted when the council reaches a majority decision
    /// @param user The user whose status was decided
    /// @param isAlive True if the council voted alive, false if deceased
    event StatusDecided(address indexed user, bool indexed isAlive);

    /// @notice Emitted when ETH is deposited for delivery costs
    /// @param user The depositing user's address
    /// @param amount The deposited ETH amount
    event DepositAdded(address indexed user, uint256 indexed amount);

    /// @notice Emitted when a delivery reward is claimed after proof submission
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    /// @param claimer The address claiming the reward
    /// @param amount The reward amount in wei
    event RewardClaimed(address indexed user, uint256 indexed messageIndex, address indexed claimer, uint256 amount);

    /// @notice Emitted when a zk-email delivery proof is verified for a recipient
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    /// @param recipientIndex The recipient index within the message
    /// @param claimer The address that submitted the proof
    event DeliveryProven(
        address indexed user,
        uint256 indexed messageIndex,
        uint256 recipientIndex,
        address indexed claimer
    );

    /// @notice Emitted when the zk-email verifier contract address is updated
    /// @param verifier The new verifier contract address
    event ZkEmailVerifierSet(address indexed verifier);

    /// @notice Emitted when a DKIM key trust status is updated
    /// @param domain The domain hash
    /// @param pubkeyHash The DKIM public key hash
    /// @param trusted Whether the key is now trusted
    event DkimKeyUpdated(bytes32 domain, uint256 indexed pubkeyHash, bool indexed trusted);

    /// @notice Restricts call to registered users only
    modifier onlyRegistered(address user) {
        if (users[user].lastCheckIn == 0) revert NotRegistered();
        _;
    }

    /// @notice Constructor disables initializers to prevent direct deployment
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract, sets initial owner and coprocessor config
    /// @dev Replaces constructor; sets owner, upgradeable base contracts, and FHEVM coprocessor
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

    /// @notice Authorize an upgrade to a new implementation; authorization enforced by onlyOwner modifier
    /// @param newImpl The new implementation address
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {} // solhint-disable-line no-empty-blocks

    /// @notice Expose the protocol id (useful for clients/frontends)
    /// @return The confidential protocol ID from ZamaConfig
    function confidentialProtocolId() public view returns (uint256) {
        return ZamaConfig.getConfidentialProtocolId();
    }

    // --- User lifecycle ---
    uint64 internal constant DEFAULT_CHECKIN = 30 days;
    uint64 internal constant DEFAULT_GRACE = 7 days;

    // --- Message constants ---
    /// @notice Maximum email byte length (emails are padded to this length to prevent length leakage)
    // Reduced from 256 to fit within 2048-bit FHEVM limit (7 limbs = 1792 bits + 128 bits s = 1920 bits)
    uint32 internal constant MAX_EMAIL_BYTE_LEN = 224;
    /// @notice Maximum payload byte length (optional, for future payload padding)
    uint32 internal constant MAX_PAYLOAD_BYTE_LEN = 10240; // 10KB

    // --- Reward constants ---
    uint256 internal constant BASE_REWARD = 0.01 ether; // Base reward per message
    uint256 internal constant REWARD_PER_KB = 0.005 ether; // Additional reward per KB of payload

    // --- Council constants ---
    uint256 internal constant MAX_COUNCIL_SIZE = 20;

    /// @notice Internal registration logic for new and existing users
    /// @param name Optional display name (max 100 bytes)
    /// @param checkInPeriod Check-in period in seconds (min 1 day)
    /// @param gracePeriod Grace period in seconds (min 1 day)
    function _register(string memory name, uint64 checkInPeriod, uint64 gracePeriod) internal {
        if (!(checkInPeriod > 1 days - 1)) revert CheckInPeriodTooShort();
        if (!(gracePeriod > 1 days - 1)) revert GracePeriodTooShort();
        if (!(bytes(name).length < 101)) revert NameTooLong();

        User storage u = users[msg.sender];

        if (u.lastCheckIn != 0) {
            // user is already registered, update configs
            if (u.deceased) revert UserDeceased();
            uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
            if (!(block.timestamp < checkInEnd + 1)) revert CheckInExpired();
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
            ++totalUsers;
            emit UserRegistered(msg.sender, checkInPeriod, gracePeriod, u.registeredOn);
        }

        emit Ping(msg.sender, u.lastCheckIn);
    }

    /// @notice Register with a name and custom check-in and grace periods
    /// @param name Optional display name (max 100 bytes)
    /// @param checkInPeriod Check-in period in seconds (min 1 day)
    /// @param gracePeriod Grace period in seconds (min 1 day)
    function register(string calldata name, uint64 checkInPeriod, uint64 gracePeriod) external {
        _register(name, checkInPeriod, gracePeriod);
    }

    /// @notice Register with custom check-in and grace periods and no name
    /// @param checkInPeriod Check-in period in seconds (min 1 day)
    /// @param gracePeriod Grace period in seconds (min 1 day)
    function register(uint64 checkInPeriod, uint64 gracePeriod) external {
        _register("", checkInPeriod, gracePeriod);
    }

    /// @notice Register with a name and default check-in and grace periods
    /// @param name Optional display name (max 100 bytes)
    function register(string calldata name) external {
        uint64 checkInPeriod = DEFAULT_CHECKIN;
        uint64 gracePeriod = DEFAULT_GRACE;
        _register(name, checkInPeriod, gracePeriod);
    }

    /// @notice Register with default check-in and grace periods and no name
    function register() external {
        uint64 checkInPeriod = DEFAULT_CHECKIN;
        uint64 gracePeriod = DEFAULT_GRACE;
        _register("", checkInPeriod, gracePeriod);
    }

    /// @notice Check if an address is registered
    /// @param user The address to check
    /// @return True if the user is registered
    function isRegistered(address user) external view returns (bool) {
        return users[user].lastCheckIn != 0;
    }

    /// @notice Get the display name of a registered user
    /// @param user The user's address
    /// @return The user's display name
    function getUserName(address user) external view returns (string memory) {
        User storage u = users[user];
        if (u.lastCheckIn == 0) revert NotRegistered();
        return u.name;
    }

    /// @notice Update the user's display name
    /// @param newName The new display name (max 100 bytes)
    function setName(string calldata newName) external {
        User storage u = users[msg.sender];
        if (u.lastCheckIn == 0) revert NotRegistered();
        if (!(bytes(newName).length < 101)) revert NameTooLong();
        u.name = newName;
        emit UserUpdated(msg.sender, u.checkInPeriod, u.gracePeriod, u.registeredOn);
    }

    /// @notice Get the registration timestamp of a user
    /// @param user The user's address
    /// @return The registration timestamp
    function getRegisteredOn(address user) external view returns (uint64) {
        User storage u = users[user];
        if (u.lastCheckIn == 0) revert NotRegistered();
        return u.registeredOn;
    }

    /// @notice Get the last check-in timestamp of a user
    /// @param user The user's address
    /// @return The last check-in timestamp
    function getLastCheckIn(address user) external view returns (uint64) {
        User storage u = users[user];
        if (u.lastCheckIn == 0) revert NotRegistered();
        return u.lastCheckIn;
    }

    /// @notice Get the deceased status of a user
    /// @param user The user's address
    /// @return True if the user is marked deceased
    function getDeceasedStatus(address user) external view returns (bool) {
        User storage u = users[user];
        if (u.lastCheckIn == 0) revert NotRegistered();
        return u.deceased;
    }

    /// @notice Get the total number of registered users
    /// @return The total count of registered users
    function getNumberOfRegisteredUsers() external view returns (uint64) {
        return totalUsers;
    }

    /// @notice Get the total number of messages added across all users
    /// @return The total count of messages
    function getNumberOfAddedMessages() external view returns (uint64) {
        return totalMessages;
    }

    /// @notice Reset the check-in timer to prove liveness
    function ping() external onlyRegistered(msg.sender) {
        User storage u = users[msg.sender];
        if (u.deceased) revert UserDeceased();

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

    /// @notice Validate message input parameters (email, limbs, payload)
    /// @param emailByteLen Original email byte length before padding
    /// @param limbs Encrypted email limbs
    /// @param payload Encrypted message payload
    function _validateMessageInput(
        uint32 emailByteLen,
        externalEuint256[] calldata limbs,
        bytes calldata payload
    ) internal pure {
        if (emailByteLen == 0) revert EmailLenZero();
        if (!(emailByteLen < MAX_EMAIL_BYTE_LEN + 1)) revert EmailTooLong();
        if (limbs.length == 0) revert NoLimbs();
        if (payload.length == 0) revert BadPayloadSize();
        if (!(payload.length < MAX_PAYLOAD_BYTE_LEN + 1)) revert PayloadTooLong();
        // All emails must be padded to MAX_EMAIL_BYTE_LEN (8 limbs for 256 bytes)
        if (limbs.length != (uint256(MAX_EMAIL_BYTE_LEN) + 31) / 32) revert LimbsMismatch();
    }

    /// @notice Store encrypted email limbs and grant FHE access to the caller
    /// @param recipientEmail Storage reference to the encrypted string struct
    /// @param limbs Encrypted email limbs from the caller
    /// @param emailByteLen Original email byte length
    /// @param inputProof FHE input proof for the encrypted values
    function _storeEncryptedEmail(
        EncryptedString storage recipientEmail,
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        bytes calldata inputProof
    ) internal {
        recipientEmail.limbs = new euint256[](limbs.length);
        for (uint256 i = 0; i < limbs.length; ) {
            euint256 v = FHE.fromExternal(limbs[i], inputProof);
            recipientEmail.limbs[i] = v;
            FHE.allowThis(v);
            FHE.allow(v, msg.sender);
            unchecked {
                ++i;
            }
        }
        recipientEmail.byteLen = emailByteLen;
    }

    /// @notice Internal function to add an encrypted message for the caller
    /// @param limbs Encrypted email limbs (each 32-byte chunk as euint256)
    /// @param emailByteLen Original email byte length before padding
    /// @param encSkShare Encrypted secret key share (euint128)
    /// @param payload AES-encrypted message payload
    /// @param inputProof FHE input proof for the encrypted values
    /// @param publicMessage Optional cleartext public message
    /// @return index The index of the newly added message
    function _addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string memory publicMessage
    ) internal onlyRegistered(msg.sender) returns (uint256 index) {
        _validateMessageInput(emailByteLen, limbs, payload);

        User storage u = users[msg.sender];
        index = u.messages.length;
        u.messages.push();
        Message storage m = u.messages[index];

        _storeEncryptedEmail(m.recipientEmail, limbs, emailByteLen, inputProof);

        // assign directly, no temp var
        m._skShare = FHE.fromExternal(encSkShare, inputProof);
        FHE.allowThis(m._skShare);
        FHE.allow(m._skShare, msg.sender);

        m.payload = payload;
        m.createdAt = uint64(block.timestamp);
        m.publicMessage = publicMessage;

        // Compute hash of all input attributes
        bytes32 messageHash = keccak256(abi.encode(limbs, emailByteLen, encSkShare, payload, publicMessage));
        m.hash = messageHash;
        messageHashes[messageHash] = true; // Track hash for lookup

        ++totalMessages;
        emit MessageAdded(msg.sender, index);
    }

    /// @notice Add an encrypted message without a public message
    /// @param limbs Encrypted email limbs (each 32-byte chunk as euint256)
    /// @param emailByteLen Original email byte length before padding
    /// @param encSkShare Encrypted secret key share (euint128)
    /// @param payload AES-encrypted message payload
    /// @param inputProof FHE input proof for the encrypted values
    /// @return index The index of the newly added message
    function addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof
    ) external returns (uint256 index) {
        return _addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, "");
    }

    /// @notice Add an encrypted message with an optional public message
    /// @param limbs Encrypted email limbs (each 32-byte chunk as euint256)
    /// @param emailByteLen Original email byte length before padding
    /// @param encSkShare Encrypted secret key share (euint128)
    /// @param payload AES-encrypted message payload
    /// @param inputProof FHE input proof for the encrypted values
    /// @param publicMessage Optional cleartext public message
    /// @return index The index of the newly added message
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
    /// @return index The index of the newly added message
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
        if (msg.value == 0) revert MustIncludeReward();
        if (recipientEmailHashes.length == 0) revert MustHaveRecipient();
        if (!(recipientEmailHashes.length < 257)) revert TooManyRecipients();

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

    /// @notice Get the number of messages for a user
    /// @param user The user's address
    /// @return The number of messages
    function messageCount(address user) external view onlyRegistered(user) returns (uint256) {
        return users[user].messages.length;
    }

    /// @notice Revoke a message (only owner, not deceased, not claimed)
    /// @param index The index of the message to revoke
    function revokeMessage(uint256 index) external nonReentrant onlyRegistered(msg.sender) {
        User storage u = users[msg.sender];
        if (u.deceased) revert UserDeceased();
        if (!(index < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[index];
        if (m.revoked) revert AlreadyRevoked();
        if (m.claimed) revert AlreadyClaimed();

        m.revoked = true;

        // Refund reward if one was attached
        if (m.reward > 0) {
            uint256 refund = m.reward;
            m.reward = 0;
            lockedRewards[msg.sender] -= refund;
            (bool success, ) = payable(msg.sender).call{value: refund}("");
            if (!success) revert EthTransferFailed();
        }

        emit MessageRevoked(msg.sender, index);
    }

    /// @notice Edit a message (only owner, not deceased, not claimed, not revoked)
    /// @param index The index of the message to edit
    /// @param limbs Encrypted email limbs (each 32-byte chunk as euint256)
    /// @param emailByteLen Original email byte length before padding
    /// @param encSkShare Encrypted secret key share (euint128)
    /// @param payload AES-encrypted message payload
    /// @param inputProof FHE input proof for the encrypted values
    /// @param publicMessage Optional cleartext public message
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
        if (u.deceased) revert UserDeceased();
        if (!(index < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[index];
        if (m.revoked) revert MessageWasRevoked();
        if (m.claimed) revert AlreadyClaimed();
        _validateMessageInput(emailByteLen, limbs, payload);

        // Update encrypted email and skShare
        _storeEncryptedEmail(m.recipientEmail, limbs, emailByteLen, inputProof);
        m._skShare = FHE.fromExternal(encSkShare, inputProof);
        FHE.allowThis(m._skShare);
        FHE.allow(m._skShare, msg.sender);

        // Update payload and public message
        m.payload = payload;
        m.publicMessage = publicMessage;

        // Invalidate old hash and recompute
        messageHashes[m.hash] = false;
        bytes32 messageHash = keccak256(abi.encode(limbs, emailByteLen, encSkShare, payload, publicMessage));
        m.hash = messageHash;
        messageHashes[messageHash] = true;

        emit MessageEdited(msg.sender, index);
    }

    /// @notice Compute the hash of message inputs without adding the message
    /// @dev Useful for checking if a message with these inputs already exists
    /// @param limbs Encrypted email limbs
    /// @param emailByteLen Original email byte length
    /// @param encSkShare Encrypted secret key share
    /// @param payload Encrypted message payload
    /// @param publicMessage Optional cleartext public message
    /// @return The keccak256 hash of all message inputs
    function computeMessageHash(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        string calldata publicMessage
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(limbs, emailByteLen, encSkShare, payload, publicMessage));
    }

    // --- Death and delivery ---
    /// @notice Mark a user as deceased after timeout period
    /// @dev Block timestamps can be manipulated by miners/validators within ~15 second windows.
    ///      Impact is low given reasonable check-in periods, but worth noting.
    /// @dev Users who have been voted "alive" by council cannot be marked deceased.
    /// @param user The user address to mark as deceased
    function markDeceased(address user) external onlyRegistered(user) {
        User storage u = users[user];
        if (u.deceased) revert UserDeceased();
        if (u.finalAlive) revert UserVotedAlive();

        // timeout condition: now > lastCheckIn + checkInPeriod + grace
        uint256 deadline = uint256(u.lastCheckIn) + uint256(u.checkInPeriod) + uint256(u.gracePeriod);
        if (!(block.timestamp > deadline)) revert NotTimedOut();

        // the user is considered from now on as deceased
        u.deceased = true;

        // the sender who discovered that the user was deceased has priority to claim the message during the next 24h
        u.notifier = Notifier({notificationTime: uint64(block.timestamp), notifierAddress: msg.sender});

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
    /// @param user The deceased user's address
    /// @param index The message index to claim
    function claim(address user, uint256 index) external {
        User storage u = users[user];
        if (!u.deceased) revert NotDeliverable();
        if (!(index < u.messages.length)) revert InvalidIndex();

        address claimerAddress = msg.sender;

        // if within 24h of notification, only the notifier can claim
        if (!(block.timestamp > uint256(u.notifier.notificationTime) + 24 hours)) {
            if (claimerAddress != u.notifier.notifierAddress) revert StillExclusiveForNotifier();
        }

        Message storage m = u.messages[index];
        if (m.revoked) revert MessageWasRevoked();
        if (m.claimed) revert AlreadyClaimed();
        m.claimed = true;
        m.claimedBy = claimerAddress;

        FHE.allow(m._skShare, claimerAddress);
        for (uint256 i = 0; i < m.recipientEmail.limbs.length; ) {
            FHE.allow(m.recipientEmail.limbs[i], claimerAddress);
            unchecked {
                ++i;
            }
        }

        emit Claimed(user, index, claimerAddress);
    }

    // --- ZK-Email Proof Delivery ---

    /// @notice ZK-Email proof structure for Groth16 verification
    struct ZkEmailProof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        uint256[] publicSignals; // [0]=recipientEmailHash, [1]=dkimPubkeyHash, [2]=contentHash
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
        if (!u.deceased) revert UserAlive();

        Message storage m = u.messages[messageIndex];
        if (!m.claimed) revert MessageNotClaimed();
        if (m.claimedBy != msg.sender) revert NotClaimant();
        if (!(recipientIndex < m.recipientEmailHashes.length)) revert InvalidIndex();

        // Check not already proven for this recipient
        if ((m.provenRecipientsBitmap & (1 << recipientIndex)) != 0) revert AlreadyProven();

        // Verify proof
        if (!_verifyZkEmailProof(proof, m, recipientIndex)) revert InvalidProof();

        // Mark recipient as proven
        m.provenRecipientsBitmap |= (1 << recipientIndex);

        emit DeliveryProven(user, messageIndex, recipientIndex, msg.sender);
    }

    /// @notice Internal function to verify zk-email proof
    /// @param proof The Groth16 proof to verify
    /// @param m The message storage reference
    /// @param recipientIndex The recipient index to verify
    /// @return True if the proof is valid
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
        if (zkEmailVerifier == address(0)) revert VerifierNotConfigured();
        return IGroth16Verifier(zkEmailVerifier).verifyProof(proof.pA, proof.pB, proof.pC, proof.publicSignals);
    }

    /// @notice Check if a DKIM public key hash is trusted
    /// @param pubkeyHash The DKIM public key hash to check
    /// @return True if the key hash is trusted
    function _isTrustedDkimKey(uint256 pubkeyHash) internal view returns (bool) {
        // Check against global trusted keys (bytes32(0) represents global/any domain)
        return trustedDkimKeys[bytes32(0)][pubkeyHash];
    }

    /// @notice Retrieve message data (encrypted handles are returned but can only be decrypted
    ///         by authorized parties via FHE.allow() permissions)
    /// @param owner The address of the message owner
    /// @param index The index of the message to retrieve
    /// @return skShare The encrypted secret key share handle
    /// @return encodedRecipientEmail The encrypted recipient email limbs
    /// @return emailByteLen The original email byte length
    /// @return payload The AES-encrypted message payload
    /// @return publicMessage The optional cleartext public message
    /// @return hash The hash of all message inputs
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
            string memory publicMessage,
            bytes32 hash
        )
    {
        User storage u = users[owner];
        if (!(index < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[index];
        if (m.revoked) revert MessageWasRevoked();

        bool isOwner = (msg.sender == owner);

        if (!isOwner) {
            // Only non-owners must satisfy delivery rules
            if (!u.deceased) revert NotDeliverable();
            if (!m.claimed) revert MessageNotClaimed();
            if (m.claimedBy != msg.sender) revert NotClaimant();
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
        if (member == address(0)) revert InvalidMember();
        if (member == msg.sender) revert CannotAddSelf();

        if (councilMembers[msg.sender][member]) revert AlreadyCouncilMember();
        if (!(councils[msg.sender].length < MAX_COUNCIL_SIZE)) revert CouncilFull();

        councils[msg.sender].push(CouncilMember({member: member, joinedAt: uint64(block.timestamp)}));
        councilMembers[msg.sender][member] = true;

        // Add to reverse index
        memberToUsers[member].push(msg.sender);

        emit CouncilMemberAdded(msg.sender, member);
    }

    /// @notice Remove a council member (can be called by user only)
    /// @param member The address to remove from council
    function removeCouncilMember(address member) external {
        if (!councilMembers[msg.sender][member]) revert NotCouncilMember();

        CouncilMember[] storage council = councils[msg.sender];
        uint256 length = council.length;

        for (uint256 i = 0; i < length; ) {
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
                        --vote.aliveVotes;
                    } else {
                        --vote.deadVotes;
                    }
                    delete vote.hasVoted[member];
                    delete vote.votedAlive[member];
                }

                // Remove from reverse index
                _removeFromMemberToUsers(member, msg.sender);

                emit CouncilMemberRemoved(msg.sender, member);
                return;
            }
            unchecked {
                ++i;
            }
        }
        revert MemberNotFound();
    }

    /// @notice Internal helper to reset grace vote state for a user
    /// @param user The user whose grace vote state should be reset
    function _resetGraceVote(address user) internal {
        GraceVote storage vote = graceVotes[user];
        CouncilMember[] storage council = councils[user];
        uint256 length = council.length;
        for (uint256 i = 0; i < length; ) {
            address m = council[i].member;
            delete vote.hasVoted[m];
            delete vote.votedAlive[m];
            unchecked {
                ++i;
            }
        }
        vote.aliveVotes = 0;
        vote.deadVotes = 0;
        vote.decided = false;
        vote.decisionAlive = false;
    }

    /// @notice Internal helper to remove user from memberToUsers reverse index
    /// @param member The council member address
    /// @param userAddr The user address to remove from the member's list
    function _removeFromMemberToUsers(address member, address userAddr) internal {
        address[] storage userList = memberToUsers[member];
        uint256 length = userList.length;
        for (uint256 i = 0; i < length; ) {
            if (userList[i] == userAddr) {
                if (i < length - 1) {
                    userList[i] = userList[length - 1];
                }
                userList.pop();
                return;
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Apply a majority-alive council decision: reset check-in and mark finalAlive
    /// @param user The user whose status is being decided
    /// @param u Storage reference to the user
    /// @param vote Storage reference to the grace vote
    function _applyAliveDecision(address user, User storage u, GraceVote storage vote) internal {
        vote.decided = true;
        vote.decisionAlive = true;
        u.lastCheckIn = uint64(block.timestamp);
        u.finalAlive = true;
        emit StatusDecided(user, true);
        emit Ping(user, u.lastCheckIn);
    }

    /// @notice Apply a majority-dead council decision: mark user as deceased
    /// @param user The user whose status is being decided
    /// @param u Storage reference to the user
    /// @param vote Storage reference to the grace vote
    function _applyDeadDecision(address user, User storage u, GraceVote storage vote) internal {
        vote.decided = true;
        vote.decisionAlive = false;
        u.deceased = true;
        u.notifier = Notifier({notificationTime: uint64(block.timestamp), notifierAddress: msg.sender});
        emit StatusDecided(user, false);
        emit Deceased(user, uint64(block.timestamp), msg.sender);
    }

    /// @notice Validate grace period voting preconditions and record a vote
    /// @param user The user being voted on
    /// @param u Storage reference to the user
    /// @param vote Storage reference to the grace vote
    /// @param voteAlive True if voting alive, false if voting dead
    function _recordGraceVote(address user, User storage u, GraceVote storage vote, bool voteAlive) internal {
        if (u.deceased) revert UserDeceased();
        if (u.finalAlive) revert VoteAlreadyDecided();

        uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
        uint256 graceEnd = checkInEnd + uint256(u.gracePeriod);
        if (!(block.timestamp > checkInEnd)) revert NotInGracePeriod();
        if (!(block.timestamp < graceEnd + 1)) revert GracePeriodEnded();

        if (vote.decided) revert VoteAlreadyDecided();
        if (vote.hasVoted[msg.sender]) revert AlreadyVoted();

        vote.hasVoted[msg.sender] = true;
        vote.votedAlive[msg.sender] = voteAlive;

        if (voteAlive) {
            ++vote.aliveVotes;
        } else {
            ++vote.deadVotes;
        }

        emit GraceVoteCast(user, msg.sender, voteAlive);
    }

    /// @notice Vote on a user's status during grace period
    /// @param user The user to vote on
    /// @param voteAlive True to vote the user is alive, false to vote dead
    function voteOnStatus(address user, bool voteAlive) external onlyRegistered(user) {
        if (!councilMembers[user][msg.sender]) revert NotCouncilMember();

        User storage u = users[user];
        GraceVote storage vote = graceVotes[user];
        _recordGraceVote(user, u, vote, voteAlive);

        uint256 majority = (councils[user].length / 2) + 1;
        if (!(vote.aliveVotes < majority)) {
            _applyAliveDecision(user, u, vote);
        } else if (!(vote.deadVotes < majority)) {
            _applyDeadDecision(user, u, vote);
        }
    }

    /// @notice Get user's current status
    /// @param user The user address
    /// @return status The user's current status
    /// @return graceSecondsLeft Seconds left in grace period (0 if not in grace)
    function getUserState(
        address user
    ) external view onlyRegistered(user) returns (UserStatus status, uint64 graceSecondsLeft) {
        User storage u = users[user];

        if (u.deceased) {
            return (UserStatus.Deceased, 0);
        }

        if (u.finalAlive) {
            return (UserStatus.FinalAlive, 0);
        }

        uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
        uint256 graceEnd = checkInEnd + uint256(u.gracePeriod);

        if (!(block.timestamp > checkInEnd)) {
            return (UserStatus.Alive, 0);
        } else if (!(block.timestamp > graceEnd)) {
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
    function getCouncilMembers(
        address user
    ) external view returns (address[] memory members, uint64[] memory joinedAts) {
        CouncilMember[] storage council = councils[user];
        uint256 length = council.length;

        members = new address[](length);
        joinedAts = new uint64[](length);

        for (uint256 i = 0; i < length; ) {
            members[i] = council[i].member;
            joinedAts[i] = council[i].joinedAt;
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Get grace vote status for a user
    /// @param user The user address
    /// @return aliveVotes Number of alive votes
    /// @return deadVotes Number of dead votes
    /// @return decided Whether a decision has been reached
    /// @return decisionAlive The decision if decided (true=alive)
    function getGraceVoteStatus(
        address user
    ) external view returns (uint256 aliveVotes, uint256 deadVotes, bool decided, bool decisionAlive) {
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
        if (msg.value == 0) revert MustDepositSomething();

        User storage u = users[msg.sender];
        u.deposit += msg.value;

        emit DepositAdded(msg.sender, msg.value);
    }

    /// @notice Get user's deposit balance
    /// @param user The user address
    /// @return The user's deposit balance in wei
    function getDeposit(address user) external view returns (uint256) {
        return users[user].deposit;
    }

    /// @notice Calculate reward for a message
    /// @param user The user address
    /// @param messageIndex The message index
    /// @return The calculated reward amount in wei
    function calculateReward(address user, uint256 messageIndex) public view returns (uint256) {
        User storage u = users[user];
        if (!(messageIndex < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[messageIndex];
        uint256 payloadSizeKB = (m.payload.length + 1023) / 1024; // Round up to KB

        uint256 reward = BASE_REWARD + (payloadSizeKB * REWARD_PER_KB);

        // Cap reward at user's deposit
        if (reward > u.deposit) {
            reward = u.deposit;
        }

        return reward;
    }

    /// @notice Check that all recipients in a message have been proven, revert if not
    /// @param m Storage reference to the message
    function _assertAllRecipientsProven(Message storage m) internal view {
        uint256 numRecipients = m.recipientEmailHashes.length;
        if (numRecipients > 0) {
            uint256 requiredBitmap = (1 << numRecipients) - 1;
            if (m.provenRecipientsBitmap != requiredBitmap) revert NotAllRecipientsProven();
        }
    }

    /// @notice Claim reward after ALL recipients have been proven via zk-email
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    function claimReward(address user, uint256 messageIndex) external nonReentrant {
        User storage u = users[user];
        if (!u.deceased) revert UserAlive();
        if (!(messageIndex < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[messageIndex];
        if (!m.claimed) revert MessageNotClaimed();
        if (m.claimedBy != msg.sender) revert NotClaimant();
        if (m.reward == 0) revert NoReward();

        _assertAllRecipientsProven(m);

        // Check if reward already claimed (prevent double claiming)
        bytes32 rewardKey = keccak256(abi.encode(user, messageIndex));
        if (rewardsClaimed[rewardKey]) revert AlreadyRewardClaimed();
        rewardsClaimed[rewardKey] = true;

        uint256 reward = m.reward;
        m.reward = 0;
        lockedRewards[user] -= reward;

        (bool success, ) = payable(msg.sender).call{value: reward}("");
        if (!success) revert EthTransferFailed();

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
    /// @return reward The per-message ETH reward amount
    /// @return numRecipients The number of recipients for proof verification
    /// @return provenRecipientsBitmap Bitmap of which recipients have been proven
    /// @return payloadContentHash Keccak256 hash of the decrypted payload content
    function getMessageRewardInfo(
        address user,
        uint256 messageIndex
    )
        external
        view
        returns (uint256 reward, uint256 numRecipients, uint256 provenRecipientsBitmap, bytes32 payloadContentHash)
    {
        User storage u = users[user];
        if (!(messageIndex < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[messageIndex];
        return (m.reward, m.recipientEmailHashes.length, m.provenRecipientsBitmap, m.payloadContentHash);
    }

    /// @notice Get recipient email hash at a specific index
    /// @param user The user's address
    /// @param messageIndex The message index
    /// @param recipientIndex The recipient index
    /// @return The Poseidon hash of the recipient email
    function getRecipientEmailHash(
        address user,
        uint256 messageIndex,
        uint256 recipientIndex
    ) external view returns (bytes32) {
        User storage u = users[user];
        if (!(messageIndex < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[messageIndex];
        if (!(recipientIndex < m.recipientEmailHashes.length)) revert InvalidIndex();

        return m.recipientEmailHashes[recipientIndex];
    }
}
