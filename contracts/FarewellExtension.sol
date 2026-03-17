// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

import {FHE, euint256, euint128, euint64, euint8, ebool, externalEuint128, externalEuint256, externalEuint64, externalEuint8} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {FarewellStorage, IConfidentialERC20, IGroth16Verifier} from "./FarewellStorage.sol";

/// @title FarewellExtension - Extension contract for council, rewards, ZK proofs, and admin
/// @author Farewell Protocol
/// @notice Deployed as a separate contract. Farewell's fallback() delegates unknown calls here
///         via delegatecall, so all storage reads/writes happen in Farewell's storage context.
///         Both contracts inherit FarewellStorage to guarantee identical storage layouts.
contract FarewellExtension is FarewellStorage {
    using SafeERC20 for IERC20;

    /// @notice Constructor sets initial owner and coprocessor config
    /// @param initialOwner The address that will own this contract (must match Farewell's owner)
    constructor(address initialOwner) FarewellStorage(initialOwner) {
        // Initialize FHEVM coprocessor using ZamaConfig (v0.9 - auto-resolves by chainId)
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
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

    // --- ZK-Email Proof Delivery ---

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
