// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

import {FHE, euint256, euint128, euint64, euint8, ebool, externalEuint128, externalEuint256, externalEuint64, externalEuint8} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

// OZ non-upgradeable imports
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// ERC-20 support
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

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

/// @title Confidential ERC-20 interface (Zama fhEVM wrapped tokens)
/// @notice Interface for confidential ERC-20 tokens that operate on encrypted balances
interface IConfidentialERC20 {
    function transfer(address to, euint64 amount) external returns (bool);
    function transferFrom(address from, address to, euint64 amount) external returns (bool);
    function underlying() external view returns (address);
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
contract Farewell is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

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

    /// @notice Reward type for messages
    enum RewardType { None, Eth, Erc20, ConfidentialErc20 }

    struct Message {
        // Encrypted recipient email (coprocessor-backed euints) + encrypted skShare.
        EncryptedString recipientEmail; // encrypted recipient e-mail
        euint128 _skShare;
        // Multi-token reward fields
        RewardType rewardType;
        address rewardToken;              // address(0) for ETH
        uint256 reward;                   // plaintext amount (ETH or ERC-20), 0 for confidential
        euint64 encryptedRewardAmount;    // encrypted amount (ConfidentialErc20 only)
        // ZK-Email proof fields
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
        // === Fields added for passphrase-based key derivation ===
        string cryptoScheme;              // e.g., "AES-128-GCM;SHAKE128"
        EncryptedString passphraseHint;   // FHE-encrypted optional hint (max 64 bytes, 2 limbs)
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

    /// @notice Encrypted council vote state using FHEVM
    struct EncryptedGraceVote {
        mapping(address => bool) hasAttempted; // who has called the function (plaintext, for trigger)
        mapping(address => euint8) voterAliveContrib; // per-voter alive contribution (0 or 1, encrypted)
        mapping(address => euint8) voterDeadContrib; // per-voter dead contribution (0 or 1, encrypted)
        euint8 encAliveSum; // running sum of alive votes (encrypted)
        euint8 encDeadSum; // running sum of dead votes (encrypted)
        uint256 uniqueAttempts; // plaintext count of unique voters (for trigger)
        bool decryptionRequested; // whether decryption was triggered
        euint8 encResult; // packed result handle (0/1/2)
        uint8 decryptedResult; // cleartext after KMS verification
        bool resultVerified; // KMS proof verified
        bool decided; // decision applied
        bool decisionAlive; // the applied decision
    }

    /// @notice Pending unshielded claim for confidential token rewards
    struct PendingUnshieldedClaim {
        address claimer;
        address cToken;
        euint64 encAmount;
        bool decryptionRequested;
        bool executed;
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
        // All messages for this user live here
        Message[] messages;
        // Encrypted council voting
        bool encryptedVoting; // Whether council votes use FHE encryption (default true for new users)
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
    error AlreadyDiscoverable();
    error NotDiscoverable();
    error CouncilFrozenDuringGrace();
    error PublicMessageTooLong();
    error HintTooLong();
    error DecryptionNotRequested();
    error DecryptionAlreadyRequested();
    error ResultAlreadyVerified();
    error PlaintextVotingMode();
    error EncryptedVotingMode();
    error NoVotesCast();
    error TokenNotAllowed();
    error InvalidRewardType();

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

    // Solidity automatically initializes all storage variables to zero by default.
    uint64 private totalUsers;
    uint64 private totalMessages;

    /// @notice Enumerable list of users who opted into discoverability
    address[] internal discoverableUsers;
    /// @notice 1-indexed position in discoverableUsers (0 = not in list)
    mapping(address user => uint256 position) internal discoverableIndex;

    /// @notice Per-user encrypted grace period voting state
    mapping(address user => EncryptedGraceVote vote) internal encryptedGraceVotes;

    /// @notice Whitelisted reward tokens (ERC-20 and confidential ERC-20)
    mapping(address token => bool allowed) public allowedRewardTokens;
    /// @notice Per-user per-token locked reward amounts (ETH and ERC-20)
    mapping(address user => mapping(address token => uint256)) public lockedTokenRewards;
    /// @notice Per-user per-token locked confidential reward amounts
    mapping(address user => mapping(address token => euint64)) internal lockedConfidentialRewards;
    /// @notice Pending unshielded claims awaiting KMS decryption
    mapping(bytes32 claimKey => PendingUnshieldedClaim) internal pendingUnshieldedClaims;

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

    /// @notice Emitted when a user changes their discoverability setting
    /// @param user The user's address
    /// @param discoverable Whether the user is now discoverable
    event DiscoverabilityChanged(address indexed user, bool indexed discoverable);

    /// @notice Emitted when an encrypted council vote is cast (vote value is NOT revealed)
    /// @param user The user being voted on
    /// @param voter The council member casting the encrypted vote
    event EncryptedGraceVoteCast(address indexed user, address indexed voter);

    /// @notice Emitted when decryption of an encrypted vote result is requested
    /// @param user The user whose vote result is being decrypted
    event VoteDecryptionRequested(address indexed user);

    /// @notice Emitted when an encrypted vote result is verified and applied
    /// @param user The user whose status was decided
    /// @param result The decrypted result (0=no majority, 1=alive, 2=deceased)
    event EncryptedVoteResolved(address indexed user, uint8 result);

    /// @notice Emitted when a reward token is whitelisted or removed
    /// @param token The token address
    /// @param allowed Whether the token is now allowed
    event RewardTokenWhitelisted(address indexed token, bool indexed allowed);

    /// @notice Emitted when a token (ERC-20) reward is claimed
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    /// @param claimer The address claiming the reward
    /// @param token The token address
    /// @param amount The reward amount
    event TokenRewardClaimed(address indexed user, uint256 indexed messageIndex, address indexed claimer, address token, uint256 amount);

    /// @notice Emitted when a confidential token reward is claimed
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    /// @param claimer The address claiming the reward
    /// @param token The confidential token address
    /// @param shielded Whether the claim was shielded (encrypted transfer) or unshielded
    event ConfidentialRewardClaimed(address indexed user, uint256 indexed messageIndex, address indexed claimer, address token, bool shielded);

    /// @notice Restricts call to registered users only
    modifier onlyRegistered(address user) {
        if (users[user].lastCheckIn == 0) revert NotRegistered();
        _;
    }

    /// @notice Constructor sets initial owner and coprocessor config
    /// @param initialOwner The address that will own this contract
    constructor(address initialOwner) Ownable(initialOwner) {
        // Initialize FHEVM coprocessor using ZamaConfig (v0.9 - auto-resolves by chainId)
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
    }

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

    // --- Public message constants ---
    uint32 internal constant MAX_PUBLIC_MESSAGE_BYTE_LEN = 1024; // 1KB

    // --- Passphrase hint constants ---
    uint32 internal constant MAX_HINT_BYTE_LEN = 64; // 2 limbs max

    // --- Council constants ---
    uint256 internal constant MAX_COUNCIL_SIZE = 20;

    /// @notice Internal registration logic for new and existing users
    /// @param name Optional display name (max 100 bytes)
    /// @param checkInPeriod Check-in period in seconds (min 1 day)
    /// @param gracePeriod Grace period in seconds (min 1 day)
    /// @param encryptedVoting Whether council votes should use FHE encryption
    function _register(string memory name, uint64 checkInPeriod, uint64 gracePeriod, bool encryptedVoting) internal {
        if (!(checkInPeriod > 1 days - 1)) revert CheckInPeriodTooShort();
        if (!(gracePeriod > 1 days - 1)) revert GracePeriodTooShort();
        if (!(bytes(name).length < 101)) revert NameTooLong();

        User storage u = users[msg.sender];

        if (u.lastCheckIn != 0) {
            // user is already registered, update configs
            if (u.deceased) revert UserDeceased();
            uint256 graceEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod) + uint256(u.gracePeriod);
            if (!(block.timestamp < graceEnd + 1)) revert CheckInExpired();
            u.name = name;
            u.checkInPeriod = checkInPeriod;
            u.gracePeriod = gracePeriod;
            u.encryptedVoting = encryptedVoting;
            emit UserUpdated(msg.sender, checkInPeriod, gracePeriod, u.registeredOn);
        } else {
            // new user
            u.name = name;
            u.checkInPeriod = checkInPeriod;
            u.gracePeriod = gracePeriod;
            u.lastCheckIn = uint64(block.timestamp);
            u.registeredOn = uint64(block.timestamp);
            u.deceased = false;
            u.encryptedVoting = encryptedVoting;
            ++totalUsers;
            emit UserRegistered(msg.sender, checkInPeriod, gracePeriod, u.registeredOn);
        }

        emit Ping(msg.sender, u.lastCheckIn);
    }

    /// @notice Register with a name, custom periods, and encrypted voting preference
    /// @param name Optional display name (max 100 bytes)
    /// @param checkInPeriod Check-in period in seconds (min 1 day)
    /// @param gracePeriod Grace period in seconds (min 1 day)
    /// @param encryptedVoting Whether council votes should use FHE encryption
    function register(string calldata name, uint64 checkInPeriod, uint64 gracePeriod, bool encryptedVoting) external {
        _register(name, checkInPeriod, gracePeriod, encryptedVoting);
    }

    /// @notice Register with a name and custom check-in and grace periods (encrypted voting defaults to true)
    /// @param name Optional display name (max 100 bytes)
    /// @param checkInPeriod Check-in period in seconds (min 1 day)
    /// @param gracePeriod Grace period in seconds (min 1 day)
    function register(string calldata name, uint64 checkInPeriod, uint64 gracePeriod) external {
        _register(name, checkInPeriod, gracePeriod, true);
    }

    /// @notice Register with custom check-in and grace periods and no name (encrypted voting defaults to true)
    /// @param checkInPeriod Check-in period in seconds (min 1 day)
    /// @param gracePeriod Grace period in seconds (min 1 day)
    function register(uint64 checkInPeriod, uint64 gracePeriod) external {
        _register("", checkInPeriod, gracePeriod, true);
    }

    /// @notice Register with a name and default check-in and grace periods (encrypted voting defaults to true)
    /// @param name Optional display name (max 100 bytes)
    function register(string calldata name) external {
        _register(name, DEFAULT_CHECKIN, DEFAULT_GRACE, true);
    }

    /// @notice Register with default check-in and grace periods and no name (encrypted voting defaults to true)
    function register() external {
        _register("", DEFAULT_CHECKIN, DEFAULT_GRACE, true);
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
        if (u.deceased) revert UserDeceased();
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
            if (u.encryptedVoting) {
                _resetEncryptedGraceVote(msg.sender);
            } else {
                _resetGraceVote(msg.sender);
            }
        } else {
            // Reset any stale grace votes from a previous cycle
            // (e.g., user entered grace, votes were cast, then user pinged before grace ended)
            uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
            if (block.timestamp > checkInEnd) {
                if (u.encryptedVoting) {
                    _resetEncryptedGraceVote(msg.sender);
                } else {
                    _resetGraceVote(msg.sender);
                }
            }
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
        // All emails must be padded to MAX_EMAIL_BYTE_LEN (7 limbs for 224 bytes)
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

    /// @notice Store encrypted passphrase hint limbs and grant FHE access
    /// @param hint Storage reference to the encrypted string struct
    /// @param hintLimbs Encrypted hint limbs from the caller
    /// @param hintByteLen Original hint byte length
    /// @param hintInputProof FHE input proof for the hint values
    function _storeEncryptedHint(
        EncryptedString storage hint,
        externalEuint256[] memory hintLimbs,
        uint32 hintByteLen,
        bytes memory hintInputProof
    ) internal {
        hint.limbs = new euint256[](hintLimbs.length);
        for (uint256 i = 0; i < hintLimbs.length; ) {
            euint256 v = FHE.fromExternal(hintLimbs[i], hintInputProof);
            hint.limbs[i] = v;
            FHE.allowThis(v);
            FHE.allow(v, msg.sender);
            unchecked {
                ++i;
            }
        }
        hint.byteLen = hintByteLen;
    }

    /// @notice Internal function to add an encrypted message for the caller
    /// @param limbs Encrypted email limbs (each 32-byte chunk as euint256)
    /// @param emailByteLen Original email byte length before padding
    /// @param encSkShare Encrypted secret key share (euint128)
    /// @param payload AES-encrypted message payload
    /// @param inputProof FHE input proof for the encrypted values
    /// @param publicMessage Optional cleartext public message
    /// @param cryptoScheme Encryption scheme descriptor (e.g., "AES-128-GCM;SHAKE128")
    /// @param hintLimbs Encrypted passphrase hint limbs (empty if no hint)
    /// @param hintByteLen Original hint byte length (0 if no hint)
    /// @param hintInputProof FHE input proof for hint values (empty if no hint)
    /// @return index The index of the newly added message
    function _addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string memory publicMessage,
        string memory cryptoScheme,
        externalEuint256[] memory hintLimbs,
        uint32 hintByteLen,
        bytes memory hintInputProof
    ) internal onlyRegistered(msg.sender) returns (uint256 index) {
        _validateMessageInput(emailByteLen, limbs, payload);
        if (!(bytes(publicMessage).length < MAX_PUBLIC_MESSAGE_BYTE_LEN + 1)) revert PublicMessageTooLong();

        User storage u = users[msg.sender];
        if (u.deceased) revert UserDeceased();
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
        m.cryptoScheme = cryptoScheme;

        // Store encrypted hint if provided
        if (hintLimbs.length > 0) {
            if (!(hintByteLen < MAX_HINT_BYTE_LEN + 1)) revert HintTooLong();
            if (hintLimbs.length != (uint256(MAX_HINT_BYTE_LEN) + 31) / 32) revert LimbsMismatch();
            _storeEncryptedHint(m.passphraseHint, hintLimbs, hintByteLen, hintInputProof);
        }

        // Compute hash of all input attributes
        bytes32 messageHash = keccak256(abi.encode(limbs, emailByteLen, encSkShare, payload, publicMessage));
        m.hash = messageHash;
        messageHashes[messageHash] = true; // Track hash for lookup

        ++totalMessages;
        emit MessageAdded(msg.sender, index);
    }

    /// @notice Add an encrypted message without hint
    /// @param limbs Encrypted email limbs (each 32-byte chunk as euint256)
    /// @param emailByteLen Original email byte length before padding
    /// @param encSkShare Encrypted secret key share (euint128)
    /// @param payload AES-encrypted message payload
    /// @param inputProof FHE input proof for the encrypted values
    /// @param publicMessage Optional cleartext public message
    /// @param cryptoScheme Encryption scheme descriptor (e.g., "AES-128-GCM;SHAKE128")
    /// @return index The index of the newly added message
    function addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage,
        string calldata cryptoScheme
    ) external returns (uint256 index) {
        return _addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, publicMessage, cryptoScheme,
            new externalEuint256[](0), 0, "");
    }

    /// @notice Add an encrypted message with passphrase hint
    /// @param limbs Encrypted email limbs (each 32-byte chunk as euint256)
    /// @param emailByteLen Original email byte length before padding
    /// @param encSkShare Encrypted secret key share (euint128)
    /// @param payload AES-encrypted message payload
    /// @param inputProof FHE input proof for the encrypted values
    /// @param publicMessage Optional cleartext public message
    /// @param cryptoScheme Encryption scheme descriptor
    /// @param hintLimbs Encrypted passphrase hint limbs
    /// @param hintByteLen Original hint byte length
    /// @param hintInputProof FHE input proof for hint values
    /// @return index The index of the newly added message
    function addMessage(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage,
        string calldata cryptoScheme,
        externalEuint256[] calldata hintLimbs,
        uint32 hintByteLen,
        bytes calldata hintInputProof
    ) external returns (uint256 index) {
        return _addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, publicMessage, cryptoScheme,
            hintLimbs, hintByteLen, hintInputProof);
    }

    /// @notice Add a message with ETH or ERC-20 reward for delivery verification (without hint)
    /// @param limbs Encrypted email limbs
    /// @param emailByteLen Original email byte length
    /// @param encSkShare Encrypted secret key share
    /// @param payload Encrypted message payload
    /// @param inputProof FHE input proof
    /// @param publicMessage Public message (optional)
    /// @param cryptoScheme Encryption scheme descriptor
    /// @param recipientEmailHashes Poseidon hashes of all recipient emails
    /// @param payloadContentHash Keccak256 hash of decrypted payload content
    /// @param rewardToken Token address (address(0) for ETH)
    /// @param rewardAmount Reward amount (ignored for ETH - uses msg.value)
    /// @return index The index of the newly added message
    function addMessageWithReward(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage,
        string calldata cryptoScheme,
        bytes32[] calldata recipientEmailHashes,
        bytes32 payloadContentHash,
        address rewardToken,
        uint256 rewardAmount
    ) external payable returns (uint256 index) {
        return _addMessageWithReward(limbs, emailByteLen, encSkShare, payload, inputProof,
            publicMessage, cryptoScheme, new externalEuint256[](0), 0, "",
            recipientEmailHashes, payloadContentHash, rewardToken, rewardAmount);
    }

    /// @notice Add a message with ETH or ERC-20 reward and passphrase hint
    function addMessageWithReward(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage,
        string calldata cryptoScheme,
        externalEuint256[] calldata hintLimbs,
        uint32 hintByteLen,
        bytes calldata hintInputProof,
        bytes32[] calldata recipientEmailHashes,
        bytes32 payloadContentHash,
        address rewardToken,
        uint256 rewardAmount
    ) external payable returns (uint256 index) {
        return _addMessageWithReward(limbs, emailByteLen, encSkShare, payload, inputProof,
            publicMessage, cryptoScheme, hintLimbs, hintByteLen, hintInputProof,
            recipientEmailHashes, payloadContentHash, rewardToken, rewardAmount);
    }

    function _addMessageWithReward(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage,
        string calldata cryptoScheme,
        externalEuint256[] memory hintLimbs,
        uint32 hintByteLen,
        bytes memory hintInputProof,
        bytes32[] calldata recipientEmailHashes,
        bytes32 payloadContentHash,
        address rewardToken,
        uint256 rewardAmount
    ) internal returns (uint256 index) {
        if (recipientEmailHashes.length == 0) revert MustHaveRecipient();
        if (!(recipientEmailHashes.length < 257)) revert TooManyRecipients();

        index = _addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, publicMessage, cryptoScheme,
            hintLimbs, hintByteLen, hintInputProof);

        Message storage m = users[msg.sender].messages[index];
        m.recipientEmailHashes = recipientEmailHashes;
        m.payloadContentHash = payloadContentHash;
        m.provenRecipientsBitmap = 0;

        if (rewardToken == address(0)) {
            // ETH reward
            if (msg.value == 0) revert MustIncludeReward();
            m.rewardType = RewardType.Eth;
            m.rewardToken = address(0);
            m.reward = msg.value;
            lockedTokenRewards[msg.sender][address(0)] += msg.value;
        } else {
            // ERC-20 reward
            if (!allowedRewardTokens[rewardToken]) revert TokenNotAllowed();
            if (rewardAmount == 0) revert MustIncludeReward();
            m.rewardType = RewardType.Erc20;
            m.rewardToken = rewardToken;
            m.reward = rewardAmount;
            lockedTokenRewards[msg.sender][rewardToken] += rewardAmount;
            IERC20(rewardToken).safeTransferFrom(msg.sender, address(this), rewardAmount);
        }
    }

    /// @notice Add a message with confidential ERC-20 reward (cUSDT/cUSDC)
    /// @param limbs Encrypted email limbs
    /// @param emailByteLen Original email byte length
    /// @param encSkShare Encrypted secret key share
    /// @param payload Encrypted message payload
    /// @param inputProof FHE input proof
    /// @param publicMessage Public message (optional)
    /// @param cryptoScheme Encryption scheme descriptor
    /// @param recipientEmailHashes Poseidon hashes of all recipient emails
    /// @param payloadContentHash Keccak256 hash of decrypted payload content
    /// @param cToken Confidential token contract address
    /// @param encAmount FHE-encrypted reward amount
    /// @param rewardInputProof FHE input proof for the reward amount
    /// @return index The index of the newly added message
    function addMessageWithConfidentialReward(
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage,
        string calldata cryptoScheme,
        bytes32[] calldata recipientEmailHashes,
        bytes32 payloadContentHash,
        address cToken,
        externalEuint64 encAmount,
        bytes calldata rewardInputProof
    ) external returns (uint256 index) {
        if (recipientEmailHashes.length == 0) revert MustHaveRecipient();
        if (!(recipientEmailHashes.length < 257)) revert TooManyRecipients();
        if (!allowedRewardTokens[cToken]) revert TokenNotAllowed();

        index = _addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, publicMessage, cryptoScheme,
            new externalEuint256[](0), 0, "");

        Message storage m = users[msg.sender].messages[index];
        m.recipientEmailHashes = recipientEmailHashes;
        m.payloadContentHash = payloadContentHash;
        m.provenRecipientsBitmap = 0;

        m.rewardType = RewardType.ConfidentialErc20;
        m.rewardToken = cToken;

        // Internalize the encrypted amount
        euint64 amount = FHE.fromExternal(encAmount, rewardInputProof);
        FHE.allowThis(amount);
        m.encryptedRewardAmount = amount;

        // Transfer confidential tokens to this contract
        IConfidentialERC20(cToken).transferFrom(msg.sender, address(this), amount);

        // Track locked confidential rewards
        if (FHE.isInitialized(lockedConfidentialRewards[msg.sender][cToken])) {
            lockedConfidentialRewards[msg.sender][cToken] = FHE.add(
                lockedConfidentialRewards[msg.sender][cToken], amount
            );
        } else {
            lockedConfidentialRewards[msg.sender][cToken] = amount;
        }
        FHE.allowThis(lockedConfidentialRewards[msg.sender][cToken]);
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

        // Refund reward based on type
        _refundReward(m, msg.sender);

        emit MessageRevoked(msg.sender, index);
    }

    /// @notice Internal helper to refund reward from a message back to its owner
    /// @param m The message storage reference
    /// @param owner The owner to refund to
    function _refundReward(Message storage m, address owner) internal {
        if (m.rewardType == RewardType.Eth) {
            uint256 refund = m.reward;
            if (refund > 0) {
                m.reward = 0;
                lockedTokenRewards[owner][address(0)] -= refund;
                (bool success, ) = payable(owner).call{value: refund}("");
                if (!success) revert EthTransferFailed();
            }
        } else if (m.rewardType == RewardType.Erc20) {
            uint256 refund = m.reward;
            if (refund > 0) {
                m.reward = 0;
                lockedTokenRewards[owner][m.rewardToken] -= refund;
                IERC20(m.rewardToken).safeTransfer(owner, refund);
            }
        } else if (m.rewardType == RewardType.ConfidentialErc20) {
            if (FHE.isInitialized(m.encryptedRewardAmount)) {
                euint64 refundAmt = m.encryptedRewardAmount;
                m.encryptedRewardAmount = euint64.wrap(0);
                // Note: lockedConfidentialRewards tracking is best-effort for FHE sums
                IConfidentialERC20(m.rewardToken).transfer(owner, refundAmt);
            }
        }
    }

    /// @notice Edit a message (only owner, not deceased, not claimed, not revoked)
    /// @param index The index of the message to edit
    /// @param limbs Encrypted email limbs (each 32-byte chunk as euint256)
    /// @param emailByteLen Original email byte length before padding
    /// @param encSkShare Encrypted secret key share (euint128)
    /// @param payload AES-encrypted message payload
    /// @param inputProof FHE input proof for the encrypted values
    /// @param publicMessage Optional cleartext public message
    /// @param cryptoScheme Encryption scheme descriptor
    /// @param hintLimbs Encrypted passphrase hint limbs (empty to keep existing)
    /// @param hintByteLen Original hint byte length (0 to keep existing)
    /// @param hintInputProof FHE input proof for hint values
    function editMessage(
        uint256 index,
        externalEuint256[] calldata limbs,
        uint32 emailByteLen,
        externalEuint128 encSkShare,
        bytes calldata payload,
        bytes calldata inputProof,
        string calldata publicMessage,
        string calldata cryptoScheme,
        externalEuint256[] calldata hintLimbs,
        uint32 hintByteLen,
        bytes calldata hintInputProof
    ) external nonReentrant onlyRegistered(msg.sender) {
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

        // Update payload, public message, and crypto scheme
        m.payload = payload;
        m.publicMessage = publicMessage;
        m.cryptoScheme = cryptoScheme;

        // Update hint if provided
        if (hintLimbs.length > 0) {
            if (!(hintByteLen < MAX_HINT_BYTE_LEN + 1)) revert HintTooLong();
            if (hintLimbs.length != (uint256(MAX_HINT_BYTE_LEN) + 31) / 32) revert LimbsMismatch();
            _storeEncryptedHint(m.passphraseHint, hintLimbs, hintByteLen, hintInputProof);
        }

        // Refund and reset reward/proof fields if message had a reward attached
        // (proof commitments no longer match the new content)
        if (m.rewardType != RewardType.None) {
            _refundReward(m, msg.sender);
            m.rewardType = RewardType.None;
            m.rewardToken = address(0);
            delete m.recipientEmailHashes;
            m.payloadContentHash = bytes32(0);
            m.provenRecipientsBitmap = 0;
        }

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
    /// @param user The deceased user's address
    /// @param index The message index to claim
    function claim(address user, uint256 index) external nonReentrant {
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

        // Also allow hint limbs if they exist
        for (uint256 i = 0; i < m.passphraseHint.limbs.length; ) {
            FHE.allow(m.passphraseHint.limbs[i], claimerAddress);
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
        if (!(messageIndex < u.messages.length)) revert InvalidIndex();

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
    /// @return cryptoScheme The encryption scheme descriptor
    /// @return hintLimbs The encrypted passphrase hint limbs
    /// @return hintByteLen The original hint byte length
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
            bytes32 hash,
            string memory cryptoScheme,
            euint256[] memory hintLimbs,
            uint32 hintByteLen
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
        cryptoScheme = m.cryptoScheme;
        hintLimbs = m.passphraseHint.limbs;
        hintByteLen = m.passphraseHint.byteLen;
    }

    // --- Council functions ---

    /// @notice Check if a user is currently in their grace period
    /// @param u Storage reference to the user
    /// @return True if the user is in grace period
    function _isInGracePeriod(User storage u) internal view returns (bool) {
        uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
        uint256 graceEnd = checkInEnd + uint256(u.gracePeriod);
        return block.timestamp > checkInEnd && !(block.timestamp > graceEnd);
    }

    /// @notice Add a council member (no stake required, max 20 members)
    /// @param member The address to add as council member
    function addCouncilMember(address member) external onlyRegistered(msg.sender) {
        if (_isInGracePeriod(users[msg.sender])) revert CouncilFrozenDuringGrace();
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
        if (users[msg.sender].lastCheckIn != 0 && _isInGracePeriod(users[msg.sender]))
            revert CouncilFrozenDuringGrace();

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

    /// @notice Vote on a user's status during grace period (plaintext mode only)
    /// @param user The user to vote on
    /// @param voteAlive True to vote the user is alive, false to vote dead
    function voteOnStatus(address user, bool voteAlive) external onlyRegistered(user) {
        if (users[user].encryptedVoting) revert EncryptedVotingMode();
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

    // --- Encrypted council voting (FHEVM) ---

    /// @notice Cast an encrypted vote on a user's status during grace period
    /// @dev Vote values: 1=alive, 2=not-alive. Invalid values (not 1 or 2) are silently ignored.
    ///      Voters can re-submit to replace their previous vote (enables recovery from invalid submissions).
    /// @param user The user to vote on
    /// @param encVote FHE-encrypted vote value
    /// @param inputProof The FHE input proof for the encrypted vote
    function voteOnStatusEncrypted(
        address user,
        externalEuint8 encVote,
        bytes calldata inputProof
    ) external onlyRegistered(user) {
        if (!users[user].encryptedVoting) revert PlaintextVotingMode();
        if (!councilMembers[user][msg.sender]) revert NotCouncilMember();

        User storage u = users[user];
        if (u.deceased) revert UserDeceased();
        if (u.finalAlive) revert VoteAlreadyDecided();

        // Validate grace period
        uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
        uint256 graceEnd = checkInEnd + uint256(u.gracePeriod);
        if (!(block.timestamp > checkInEnd)) revert NotInGracePeriod();
        if (!(block.timestamp < graceEnd + 1)) revert GracePeriodEnded();

        EncryptedGraceVote storage evote = encryptedGraceVotes[user];
        if (evote.decided) revert VoteAlreadyDecided();
        if (evote.decryptionRequested) revert DecryptionAlreadyRequested();

        // Verify and internalize the encrypted vote
        euint8 vote = FHE.fromExternal(encVote, inputProof);
        FHE.allowThis(vote);

        // Compute contributions: only 1 (alive) or 2 (dead) produce non-zero values
        ebool isAlive = FHE.eq(vote, FHE.asEuint8(1));
        ebool isDead = FHE.eq(vote, FHE.asEuint8(2));
        euint8 aliveContrib = FHE.select(isAlive, FHE.asEuint8(1), FHE.asEuint8(0));
        euint8 deadContrib = FHE.select(isDead, FHE.asEuint8(1), FHE.asEuint8(0));

        // Subtract previous contribution if exists (replacement semantics)
        if (FHE.isInitialized(evote.voterAliveContrib[msg.sender])) {
            evote.encAliveSum = FHE.sub(evote.encAliveSum, evote.voterAliveContrib[msg.sender]);
            evote.encDeadSum = FHE.sub(evote.encDeadSum, evote.voterDeadContrib[msg.sender]);
        }

        // Store new per-voter contribution
        evote.voterAliveContrib[msg.sender] = aliveContrib;
        evote.voterDeadContrib[msg.sender] = deadContrib;
        FHE.allowThis(aliveContrib);
        FHE.allowThis(deadContrib);

        // Add new contribution to sums
        if (FHE.isInitialized(evote.encAliveSum)) {
            evote.encAliveSum = FHE.add(evote.encAliveSum, aliveContrib);
            evote.encDeadSum = FHE.add(evote.encDeadSum, deadContrib);
        } else {
            evote.encAliveSum = aliveContrib;
            evote.encDeadSum = deadContrib;
        }
        FHE.allowThis(evote.encAliveSum);
        FHE.allowThis(evote.encDeadSum);

        // Track unique callers (plaintext, for triggering majority check)
        if (!evote.hasAttempted[msg.sender]) {
            evote.hasAttempted[msg.sender] = true;
            ++evote.uniqueAttempts;
        }

        emit EncryptedGraceVoteCast(user, msg.sender);

        // Auto-trigger decryption when enough unique voters have attempted
        uint256 councilSize = councils[user].length;
        uint256 majority = (councilSize / 2) + 1;
        if (evote.uniqueAttempts >= majority) {
            _requestVoteDecryption(user, evote, majority);
        }
    }

    /// @notice Internal: compute encrypted result and mark for public decryption
    /// @param user The user whose vote is being resolved
    /// @param evote Storage reference to the encrypted vote state
    /// @param majority The majority threshold
    function _requestVoteDecryption(
        address user,
        EncryptedGraceVote storage evote,
        uint256 majority
    ) internal {
        if (evote.decryptionRequested) return;

        euint8 encMajority = FHE.asEuint8(uint8(majority));

        // Check each side independently
        ebool aliveWins = FHE.ge(evote.encAliveSum, encMajority);
        ebool deadWins = FHE.ge(evote.encDeadSum, encMajority);

        // Pack result: 0=no majority, 1=alive, 2=dead
        euint8 result = FHE.select(aliveWins, FHE.asEuint8(1), FHE.asEuint8(0));
        result = FHE.select(deadWins, FHE.asEuint8(2), result);

        // Mark for public decryption (KMS signers will produce proof)
        evote.encResult = FHE.makePubliclyDecryptable(result);
        FHE.allowThis(evote.encResult);
        evote.decryptionRequested = true;

        emit VoteDecryptionRequested(user);
    }

    /// @notice Request decryption of encrypted vote result (callable by anyone)
    /// @dev Use when auto-trigger didn't fire (e.g., grace period expired with votes cast)
    /// @param user The user whose vote result should be decrypted
    function requestVoteDecryption(address user) external onlyRegistered(user) {
        User storage u = users[user];
        if (!u.encryptedVoting) revert PlaintextVotingMode();
        if (u.deceased) revert UserDeceased();

        EncryptedGraceVote storage evote = encryptedGraceVotes[user];
        if (evote.decided) revert VoteAlreadyDecided();
        if (evote.decryptionRequested) revert DecryptionAlreadyRequested();
        if (evote.uniqueAttempts == 0) revert NoVotesCast();

        uint256 majority = (councils[user].length / 2) + 1;
        _requestVoteDecryption(user, evote, majority);
    }

    /// @notice Resolve an encrypted vote by providing KMS decryption proof
    /// @param user The user whose vote is being resolved
    /// @param decryptedResult The cleartext result (0=no majority, 1=alive, 2=deceased)
    /// @param decryptionProof The KMS proof of correct decryption
    function resolveEncryptedVote(
        address user,
        uint8 decryptedResult,
        bytes calldata decryptionProof
    ) external onlyRegistered(user) {
        User storage u = users[user];
        EncryptedGraceVote storage evote = encryptedGraceVotes[user];

        if (!evote.decryptionRequested) revert DecryptionNotRequested();
        if (evote.resultVerified) revert ResultAlreadyVerified();
        if (evote.decided) revert VoteAlreadyDecided();

        // Verify KMS signatures
        bytes32[] memory handlesList = new bytes32[](1);
        handlesList[0] = euint8.unwrap(evote.encResult);

        bytes memory abiEncodedCleartexts = abi.encode(decryptedResult);
        FHE.checkSignatures(handlesList, abiEncodedCleartexts, decryptionProof);

        // Store verified result
        evote.decryptedResult = decryptedResult;
        evote.resultVerified = true;

        emit EncryptedVoteResolved(user, decryptedResult);

        // Apply decision based on result
        if (decryptedResult == 1) {
            // Alive wins
            evote.decided = true;
            evote.decisionAlive = true;
            u.lastCheckIn = uint64(block.timestamp);
            u.finalAlive = true;
            emit StatusDecided(user, true);
            emit Ping(user, u.lastCheckIn);
        } else if (decryptedResult == 2) {
            // Dead wins
            evote.decided = true;
            evote.decisionAlive = false;
            u.deceased = true;
            u.notifier = Notifier({notificationTime: uint64(block.timestamp), notifierAddress: msg.sender});
            emit StatusDecided(user, false);
            emit Deceased(user, uint64(block.timestamp), msg.sender);
        }
        // If decryptedResult == 0: no majority. Reset decryption state to allow more votes.
        if (decryptedResult == 0) {
            evote.decryptionRequested = false;
            evote.resultVerified = false;
            evote.decryptedResult = 0;
        }
    }

    /// @notice Internal helper to reset encrypted grace vote state for a user
    /// @param user The user whose encrypted grace vote state should be reset
    function _resetEncryptedGraceVote(address user) internal {
        EncryptedGraceVote storage evote = encryptedGraceVotes[user];
        CouncilMember[] storage council = councils[user];
        uint256 length = council.length;
        for (uint256 i = 0; i < length; ) {
            address m = council[i].member;
            delete evote.hasAttempted[m];
            // Reset per-voter encrypted contributions to uninitialized state
            evote.voterAliveContrib[m] = euint8.wrap(0);
            evote.voterDeadContrib[m] = euint8.wrap(0);
            unchecked {
                ++i;
            }
        }
        evote.encAliveSum = euint8.wrap(0);
        evote.encDeadSum = euint8.wrap(0);
        evote.encResult = euint8.wrap(0);
        evote.uniqueAttempts = 0;
        evote.decryptionRequested = false;
        evote.decryptedResult = 0;
        evote.resultVerified = false;
        evote.decided = false;
        evote.decisionAlive = false;
    }

    /// @notice Toggle encrypted voting mode (cannot change during grace period)
    /// @param enabled Whether to enable encrypted council voting
    function setEncryptedVoting(bool enabled) external onlyRegistered(msg.sender) {
        User storage u = users[msg.sender];
        if (u.deceased) revert UserDeceased();
        if (_isInGracePeriod(u)) revert CouncilFrozenDuringGrace();
        u.encryptedVoting = enabled;
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

    /// @notice Get grace vote status for a user (plaintext mode)
    /// @dev For encrypted mode, use getEncryptedGraceVoteStatus instead
    /// @param user The user address
    /// @return aliveVotes Number of alive votes (0 for encrypted mode)
    /// @return deadVotes Number of dead votes (0 for encrypted mode)
    /// @return decided Whether a decision has been reached
    /// @return decisionAlive The decision if decided (true=alive)
    function getGraceVoteStatus(
        address user
    ) external view returns (uint256 aliveVotes, uint256 deadVotes, bool decided, bool decisionAlive) {
        if (users[user].encryptedVoting) {
            EncryptedGraceVote storage evote = encryptedGraceVotes[user];
            return (0, 0, evote.decided, evote.decisionAlive);
        }
        GraceVote storage vote = graceVotes[user];
        return (vote.aliveVotes, vote.deadVotes, vote.decided, vote.decisionAlive);
    }

    /// @notice Check if a council member has voted on a user's grace period
    /// @param user The user address
    /// @param member The council member address
    /// @return hasVoted Whether the member has voted (for encrypted mode: whether they attempted)
    /// @return votedAlive How they voted (always false for encrypted mode)
    function getGraceVote(address user, address member) external view returns (bool hasVoted, bool votedAlive) {
        if (users[user].encryptedVoting) {
            EncryptedGraceVote storage evote = encryptedGraceVotes[user];
            return (evote.hasAttempted[member], false);
        }
        GraceVote storage vote = graceVotes[user];
        return (vote.hasVoted[member], vote.votedAlive[member]);
    }

    /// @notice Get encrypted grace vote status for a user
    /// @param user The user address
    /// @return uniqueAttempts Number of unique voters who have attempted
    /// @return decryptionRequested Whether decryption has been requested
    /// @return resultVerified Whether the KMS result has been verified
    /// @return decryptedResult The verified result (0=none/no majority, 1=alive, 2=deceased)
    /// @return decided Whether a decision was reached
    /// @return decisionAlive The decision (valid only if decided==true)
    function getEncryptedGraceVoteStatus(
        address user
    )
        external
        view
        returns (
            uint256 uniqueAttempts,
            bool decryptionRequested,
            bool resultVerified,
            uint8 decryptedResult,
            bool decided,
            bool decisionAlive
        )
    {
        EncryptedGraceVote storage evote = encryptedGraceVotes[user];
        return (
            evote.uniqueAttempts,
            evote.decryptionRequested,
            evote.resultVerified,
            evote.decryptedResult,
            evote.decided,
            evote.decisionAlive
        );
    }

    /// @notice Check if a user has encrypted voting enabled
    /// @param user The user address
    /// @return True if the user has encrypted voting enabled
    function getEncryptedVoting(address user) external view onlyRegistered(user) returns (bool) {
        return users[user].encryptedVoting;
    }

    // --- Rewards ---

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
    /// @dev Routes by rewardType: ETH direct transfer, ERC-20 via SafeERC20, or confidential shielded transfer
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    function claimReward(address user, uint256 messageIndex) external nonReentrant {
        User storage u = users[user];
        if (!u.deceased) revert UserAlive();
        if (!(messageIndex < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[messageIndex];
        if (!m.claimed) revert MessageNotClaimed();
        if (m.claimedBy != msg.sender) revert NotClaimant();

        _assertAllRecipientsProven(m);

        // Check if reward already claimed (prevent double claiming)
        bytes32 rewardKey = keccak256(abi.encode(user, messageIndex));
        if (rewardsClaimed[rewardKey]) revert AlreadyRewardClaimed();
        rewardsClaimed[rewardKey] = true;

        if (m.rewardType == RewardType.Eth) {
            uint256 reward = m.reward;
            if (reward == 0) revert NoReward();
            m.reward = 0;
            lockedTokenRewards[user][address(0)] -= reward;

            (bool success, ) = payable(msg.sender).call{value: reward}("");
            if (!success) revert EthTransferFailed();

            emit RewardClaimed(user, messageIndex, msg.sender, reward);
        } else if (m.rewardType == RewardType.Erc20) {
            uint256 reward = m.reward;
            if (reward == 0) revert NoReward();
            m.reward = 0;
            lockedTokenRewards[user][m.rewardToken] -= reward;

            IERC20(m.rewardToken).safeTransfer(msg.sender, reward);

            emit TokenRewardClaimed(user, messageIndex, msg.sender, m.rewardToken, reward);
        } else if (m.rewardType == RewardType.ConfidentialErc20) {
            if (!FHE.isInitialized(m.encryptedRewardAmount)) revert NoReward();
            euint64 amount = m.encryptedRewardAmount;
            m.encryptedRewardAmount = euint64.wrap(0);

            // Shielded delivery: transfer confidential tokens directly
            IConfidentialERC20(m.rewardToken).transfer(msg.sender, amount);

            emit ConfidentialRewardClaimed(user, messageIndex, msg.sender, m.rewardToken, true);
        } else {
            revert NoReward();
        }
    }

    /// @notice Claim confidential reward as plaintext tokens (step 1: request decryption)
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    function claimRewardUnshielded(address user, uint256 messageIndex) external nonReentrant {
        User storage u = users[user];
        if (!u.deceased) revert UserAlive();
        if (!(messageIndex < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[messageIndex];
        if (!m.claimed) revert MessageNotClaimed();
        if (m.claimedBy != msg.sender) revert NotClaimant();
        if (m.rewardType != RewardType.ConfidentialErc20) revert InvalidRewardType();
        if (!FHE.isInitialized(m.encryptedRewardAmount)) revert NoReward();

        _assertAllRecipientsProven(m);

        bytes32 rewardKey = keccak256(abi.encode(user, messageIndex));
        if (rewardsClaimed[rewardKey]) revert AlreadyRewardClaimed();
        rewardsClaimed[rewardKey] = true;

        // Mark encrypted amount for public decryption
        euint64 amount = m.encryptedRewardAmount;
        m.encryptedRewardAmount = euint64.wrap(0);
        euint64 decryptableAmount = FHE.makePubliclyDecryptable(amount);
        FHE.allowThis(decryptableAmount);

        bytes32 claimKey = keccak256(abi.encode(user, messageIndex, msg.sender));
        pendingUnshieldedClaims[claimKey] = PendingUnshieldedClaim({
            claimer: msg.sender,
            cToken: m.rewardToken,
            encAmount: decryptableAmount,
            decryptionRequested: true,
            executed: false
        });
    }

    /// @notice Execute unshielded claim after KMS decryption (step 2)
    /// @param user The deceased user's address
    /// @param messageIndex The message index
    /// @param decryptedAmount The plaintext reward amount
    /// @param decryptionProof The KMS proof of correct decryption
    function executeUnshieldedClaim(
        address user,
        uint256 messageIndex,
        uint64 decryptedAmount,
        bytes calldata decryptionProof
    ) external nonReentrant {
        bytes32 claimKey = keccak256(abi.encode(user, messageIndex, msg.sender));
        PendingUnshieldedClaim storage pending = pendingUnshieldedClaims[claimKey];

        if (!pending.decryptionRequested) revert DecryptionNotRequested();
        if (pending.executed) revert AlreadyRewardClaimed();
        if (pending.claimer != msg.sender) revert NotClaimant();

        // Verify KMS signatures
        bytes32[] memory handlesList = new bytes32[](1);
        handlesList[0] = euint64.unwrap(pending.encAmount);
        bytes memory abiEncodedCleartexts = abi.encode(decryptedAmount);
        FHE.checkSignatures(handlesList, abiEncodedCleartexts, decryptionProof);

        pending.executed = true;

        // Get underlying token from confidential wrapper
        address underlying = IConfidentialERC20(pending.cToken).underlying();
        IERC20(underlying).safeTransfer(msg.sender, uint256(decryptedAmount));

        emit ConfidentialRewardClaimed(user, messageIndex, msg.sender, pending.cToken, false);
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

    /// @notice Whitelist or delist a reward token
    /// @param token The token address (ERC-20 or confidential ERC-20)
    /// @param allowed Whether the token is allowed as a reward
    function setAllowedRewardToken(address token, bool allowed) external onlyOwner {
        allowedRewardTokens[token] = allowed;
        emit RewardTokenWhitelisted(token, allowed);
    }

    /// @notice Get message reward information
    /// @param user The user's address
    /// @param messageIndex The message index
    /// @return reward The per-message reward amount (0 for confidential)
    /// @return numRecipients The number of recipients for proof verification
    /// @return provenRecipientsBitmap Bitmap of which recipients have been proven
    /// @return payloadContentHash Keccak256 hash of the decrypted payload content
    /// @return rewardToken The reward token address (address(0) for ETH)
    /// @return rewardType The type of reward
    function getMessageRewardInfo(
        address user,
        uint256 messageIndex
    )
        external
        view
        returns (
            uint256 reward,
            uint256 numRecipients,
            uint256 provenRecipientsBitmap,
            bytes32 payloadContentHash,
            address rewardToken,
            RewardType rewardType
        )
    {
        User storage u = users[user];
        if (!(messageIndex < u.messages.length)) revert InvalidIndex();

        Message storage m = u.messages[messageIndex];
        return (m.reward, m.recipientEmailHashes.length, m.provenRecipientsBitmap, m.payloadContentHash, m.rewardToken, m.rewardType);
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

    // --- Discoverability ---
    // Implements the opt-in discoverable users list described in docs/discoverability.md.
    // Deceased users intentionally remain in the list so claimers can find and process them.

    /// @notice Toggle discoverability for the calling user
    /// @param _discoverable Whether the user should be discoverable
    function setDiscoverable(bool _discoverable) external onlyRegistered(msg.sender) {
        if (_discoverable) {
            if (discoverableIndex[msg.sender] != 0) revert AlreadyDiscoverable();
            discoverableUsers.push(msg.sender);
            discoverableIndex[msg.sender] = discoverableUsers.length; // 1-indexed
            emit DiscoverabilityChanged(msg.sender, true);
        } else {
            uint256 idx = discoverableIndex[msg.sender];
            if (idx == 0) revert NotDiscoverable();
            // Swap-and-pop removal
            uint256 lastIdx = discoverableUsers.length - 1;
            if (idx - 1 != lastIdx) {
                address lastUser = discoverableUsers[lastIdx];
                discoverableUsers[idx - 1] = lastUser;
                discoverableIndex[lastUser] = idx;
            }
            discoverableUsers.pop();
            discoverableIndex[msg.sender] = 0;
            emit DiscoverabilityChanged(msg.sender, false);
        }
    }

    /// @notice Get paginated list of discoverable users
    /// @param offset Starting index in the discoverable users array
    /// @param limit Maximum number of addresses to return
    /// @return result Array of discoverable user addresses
    function getDiscoverableUsers(uint256 offset, uint256 limit) external view returns (address[] memory result) {
        uint256 total = discoverableUsers.length;
        if (!(offset < total)) {
            return new address[](0);
        }
        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }
        uint256 count = end - offset;
        result = new address[](count);
        for (uint256 i = 0; i < count; ) {
            result[i] = discoverableUsers[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Get total number of discoverable users
    /// @return Total count of users who opted into discoverability
    function getDiscoverableCount() external view returns (uint256) {
        return discoverableUsers.length;
    }
}
