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

/// @title FarewellStorage - Abstract base contract with all shared state for the Farewell protocol
/// @author Farewell Protocol
/// @notice Contains all structs, enums, errors, events, storage variables, constants, and modifiers
///         shared between Farewell and FarewellExtension. Both contracts inherit from this to
///         guarantee identical storage layouts, which is required for the delegatecall pattern.
abstract contract FarewellStorage is Ownable, ReentrancyGuard {
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

    /// @notice ZK-Email proof structure for Groth16 verification
    struct ZkEmailProof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        uint256[] publicSignals; // [0]=recipientEmailHash, [1]=dkimPubkeyHash, [2]=contentHash
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
    error NotAlive();

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
    uint64 internal totalUsers;
    uint64 internal totalMessages;

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

    // solhint-disable-next-line no-empty-blocks
    constructor(address initialOwner) Ownable(initialOwner) {}

    // --- User lifecycle constants ---
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

    /// @notice Restricts call to registered users only
    modifier onlyRegistered(address user) {
        if (users[user].lastCheckIn == 0) revert NotRegistered();
        _;
    }
}
