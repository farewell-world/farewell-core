// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

import {FHE, euint256, euint128, euint64, euint8, ebool, externalEuint128, externalEuint256, externalEuint64, externalEuint8} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {FarewellStorage, IConfidentialERC20} from "./FarewellStorage.sol";

/// @title Farewell (email-recipient version)
/// @author Farewell Protocol
/// @notice On-chain posthumous message release via timeout.
/// - Recipients are EMAILS (string), not wallet addresses.
/// - Anyone can call `claim` after timeout; we emit an event with (email, data).
/// - On-chain data is public. Treat `data` as ciphertext in real use.
/// @dev NOTE: There is no recovery mechanism if a user is legitimately marked deceased
///      but was actually unable to ping (hospitalization, lost keys, etc.).
///      This is a known limitation to be addressed in future versions.
/// @dev Unknown function calls are forwarded to `extension` via delegatecall.
///      Council, voting, rewards, ZK proofs, discoverability, and admin functions
///      all live in FarewellExtension but execute in this contract's storage context.
contract Farewell is FarewellStorage {
    using SafeERC20 for IERC20;

    /// @notice Immutable address of the FarewellExtension contract
    /// @dev Stored in bytecode (not storage), so it does not affect the storage layout
    address public immutable extension;

    /// @notice Constructor sets initial owner, extension address, and coprocessor config
    /// @param initialOwner The address that will own this contract
    /// @param _extension The FarewellExtension contract address
    constructor(address initialOwner, address _extension) FarewellStorage(initialOwner) {
        extension = _extension;
        // Initialize FHEVM coprocessor using ZamaConfig (v0.9 - auto-resolves by chainId)
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
    }

    /// @notice Expose the protocol id (useful for clients/frontends)
    /// @return The confidential protocol ID from ZamaConfig
    function confidentialProtocolId() public view returns (uint256) {
        return ZamaConfig.getConfidentialProtocolId();
    }

    // --- User lifecycle ---

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

    /// @notice Internal helper to reset grace vote state for a user
    /// @param user The user whose grace vote state should be reset
    function _resetGraceVote(address user) private {
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

    /// @notice Internal helper to reset encrypted grace vote state for a user
    /// @param user The user whose encrypted grace vote state should be reset
    function _resetEncryptedGraceVote(address user) private {
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

    // --- Fallback: delegate unknown calls to extension ---

    /// @notice Fallback function that delegates all unknown calls to the extension contract
    /// @dev The extension executes in this contract's storage context via delegatecall.
    ///      This enables council, voting, rewards, ZK proofs, discoverability, and admin
    ///      functions to be split into a separate contract while sharing the same storage.
    fallback() external payable {
        address ext = extension;
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), ext, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice Accept plain ETH transfers
    receive() external payable {}
}
