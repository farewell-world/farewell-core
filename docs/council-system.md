# Council System

This document provides a complete technical specification of the council voting system in the Farewell protocol,
covering both the plaintext and encrypted (FHEVM) voting modes.

## 1. Overview

### 1.1 Purpose

The Farewell protocol uses a dead man's switch: users must periodically call `ping()` to prove liveness. When a user
misses their check-in deadline, they enter a **grace period** before being marked deceased. The council system exists to
provide a human-judgment layer during this grace period, allowing trusted individuals to vote on whether the user is
truly unresponsive or merely temporarily unavailable.

Without a council, the only path from grace to deceased is timeout. With a council, members can:

- **Vote "alive"** to reset the user's check-in timer and prevent premature deceased marking (e.g., the user is
  hospitalized but expected to recover).
- **Vote "dead"** to accelerate the deceased transition, releasing messages to claimers sooner.

### 1.2 Voting Modes

The protocol supports two voting modes, selectable per user:

| Mode | Privacy | On-chain cost | Resolution |
|------|---------|---------------|------------|
| **Plaintext** | Votes are publicly visible on-chain | Lower gas (~50-100k per vote) | Immediate on majority |
| **Encrypted (FHEVM)** | Individual votes are secret | Higher gas (~1200-1500k per vote) | Asynchronous (requires KMS decryption) |

Encrypted voting protects council members from social pressure. When votes are public, a family member or business
partner could face retaliation for voting "dead" on someone who turns out to be alive, or for voting "alive" when
others want the messages released. Encrypted voting removes this dynamic entirely: nobody can see how any individual
voted, only the final outcome.

### 1.3 User Lifecycle Integration

The council system operates within the broader user lifecycle:

```
Alive --(checkInPeriod expires)--> Grace --(gracePeriod expires)--> Deceased
  ^                                  |
  |                           Council votes here
  |                                  |
  +-- ping() resets <----------------+-- Vote alive: FinalAlive (timer reset)
                                     +-- Vote dead: Deceased (immediate)
                                     +-- No majority: timeout proceeds normally
```

## 2. Council Management

### 2.1 Adding Members

```solidity
function addCouncilMember(address member) external
```

A registered user can add trusted addresses to their council. Requirements:

- Caller must be the registered user (`msg.sender`)
- `member` must not be `address(0)`
- `member` must not be the caller themselves (cannot add self)
- `member` must not already be on the council
- Council size must be below `MAX_COUNCIL_SIZE` (20)
- User must **not** be in a grace period (council is frozen during grace)

The function stores a `CouncilMember` struct with the member address and join timestamp, updates the
`councilMembers` lookup mapping, and adds the user to the `memberToUsers` reverse index.

Event: `CouncilMemberAdded(address indexed user, address indexed member)`

### 2.2 Removing Members

```solidity
function removeCouncilMember(address member) external
```

The user can remove a council member at any time, with one restriction: the council is frozen during grace periods to
prevent manipulation of the voter set while voting is active.

Removal uses swap-and-pop on the `councils` array for gas efficiency. If the removed member had already cast a
plaintext vote during an active grace period, that vote is subtracted from the tally:

```solidity
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
```

The member is also removed from the `memberToUsers` reverse index.

Event: `CouncilMemberRemoved(address indexed user, address indexed member)`

**Note:** In encrypted voting mode, removing a member does not retroactively adjust the encrypted sums. This is because
the encrypted values cannot be conditionally modified without the voter's ciphertext. However, since the council is
frozen during grace periods (when votes are cast), this situation cannot arise in practice.

### 2.3 Reverse Index

The `memberToUsers` mapping provides a reverse lookup: given a council member address, it returns all users who have
that address on their council. This enables the UI to show a council member which users they are responsible for
monitoring.

```solidity
mapping(address member => address[] users) public memberToUsers;
```

### 2.4 Constraints

| Constraint | Value | Rationale |
|-----------|-------|-----------|
| `MAX_COUNCIL_SIZE` | 20 | Gas limit safety for iteration during resets |
| Cannot add self | N/A | Prevents trivially self-voting |
| Frozen during grace | N/A | Prevents voter set manipulation during active voting |
| No registration required for members | N/A | Council members need not be Farewell users |

## 3. Grace Period Voting -- Plaintext Mode

### 3.1 When Votes Can Be Cast

Voting is only allowed during the grace period window:

```
checkInEnd = lastCheckIn + checkInPeriod
graceEnd   = checkInEnd + gracePeriod

Voting allowed when: block.timestamp > checkInEnd AND block.timestamp <= graceEnd
```

Additional preconditions:
- The user must not already be deceased
- The user must not be in `FinalAlive` state
- No decision must have been reached yet (`!vote.decided`)
- The caller must be a council member of the user
- The caller must not have already voted in this grace cycle
- The user must have `encryptedVoting == false`

### 3.2 Vote Recording

Each council member calls `voteOnStatus(user, voteAlive)` with a boolean indicating their vote. The function records
the vote and increments the appropriate counter:

```solidity
vote.hasVoted[msg.sender] = true;
vote.votedAlive[msg.sender] = voteAlive;

if (voteAlive) {
    ++vote.aliveVotes;
} else {
    ++vote.deadVotes;
}
```

Event: `GraceVoteCast(address indexed user, address indexed voter, bool votedAlive)`

### 3.3 Majority Calculation

After each vote, the contract checks whether a majority has been reached:

```solidity
uint256 majority = (councils[user].length / 2) + 1;

if (vote.aliveVotes >= majority) {
    // Alive wins
} else if (vote.deadVotes >= majority) {
    // Dead wins
}
```

Both thresholds use `(councilSize / 2) + 1`, which is strict majority. For a council of size `n`:

| Council size | Majority threshold | Alive needs | Dead needs |
|-------------|-------------------|-------------|------------|
| 1 | 1 | 1 | 1 |
| 2 | 2 | 2 | 2 |
| 3 | 2 | 2 | 2 |
| 4 | 3 | 3 | 3 |
| 5 | 3 | 3 | 3 |
| 20 | 11 | 11 | 11 |

### 3.4 Decision Application

**Alive decision** (`_applyAliveDecision`):
1. Sets `vote.decided = true` and `vote.decisionAlive = true`
2. Resets `lastCheckIn` to current timestamp (effectively restarting the check-in cycle)
3. Sets `u.finalAlive = true` (prevents `markDeceased()` from being called)
4. Emits `StatusDecided(user, true)` and `Ping(user, timestamp)`

**Dead decision** (`_applyDeadDecision`):
1. Sets `vote.decided = true` and `vote.decisionAlive = false`
2. Sets `u.deceased = true`
3. Records the voting tx sender as the notifier (gets 24-hour claim priority)
4. Emits `StatusDecided(user, false)` and `Deceased(user, timestamp, sender)`

### 3.5 Vote Reset

The `_resetGraceVote` function clears all plaintext voting state:

```solidity
function _resetGraceVote(address user) internal {
    GraceVote storage vote = graceVotes[user];
    CouncilMember[] storage council = councils[user];
    for (uint256 i = 0; i < council.length; ) {
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
```

This is called when:
- `ping()` is called while in grace period (user came back, votes are stale)
- `ping()` is called while in `FinalAlive` state (user re-enters normal cycle)

## 4. Grace Period Voting -- Encrypted Mode (FHEVM)

### 4.1 Motivation

In plaintext mode, anyone can read the blockchain and see exactly how each council member voted. This creates social
pressure: a family member who voted "dead" on a user who later recovers may face consequences, and a business partner
who voted "alive" against the wishes of heirs could be blamed for delaying message release.

Encrypted voting solves this by keeping individual votes secret on-chain. Only the aggregate outcome (alive majority,
dead majority, or no majority) is ever revealed. Individual vote values remain encrypted for the lifetime of the
contract.

### 4.2 Vote Encoding

Votes are encoded as `euint8` FHE ciphertexts with the following convention:

| Value | Meaning |
|-------|---------|
| 1 | Alive |
| 2 | Not alive (dead) |
| Other | Invalid (silently ignored) |

The voter encrypts their choice client-side using the FHEVM SDK and submits it along with an input proof:

```solidity
function voteOnStatusEncrypted(
    address user,
    externalEuint8 encVote,
    bytes calldata inputProof
) external
```

### 4.3 FHE Operations

The contract uses Zama FHEVM's homomorphic operations to process votes without decrypting them.

**Step 1: Validate and internalize the ciphertext**

```solidity
euint8 vote = FHE.fromExternal(encVote, inputProof);
FHE.allowThis(vote);
```

**Step 2: Compute per-voter contributions**

```solidity
ebool isAlive = FHE.eq(vote, FHE.asEuint8(1));
ebool isDead  = FHE.eq(vote, FHE.asEuint8(2));
euint8 aliveContrib = FHE.select(isAlive, FHE.asEuint8(1), FHE.asEuint8(0));
euint8 deadContrib  = FHE.select(isDead,  FHE.asEuint8(1), FHE.asEuint8(0));
```

This produces two encrypted values per voter:
- `aliveContrib`: encrypted 1 if vote == 1, else encrypted 0
- `deadContrib`: encrypted 1 if vote == 2, else encrypted 0

If the voter submits an invalid value (e.g., 0 or 3), both contributions are encrypted 0, and the vote has no effect
on the tally. The voter can re-submit with a valid value.

**Step 3: Replacement semantics**

If the voter has previously submitted a vote, their old contributions are subtracted before adding the new ones:

```solidity
if (FHE.isInitialized(evote.voterAliveContrib[msg.sender])) {
    evote.encAliveSum = FHE.sub(evote.encAliveSum, evote.voterAliveContrib[msg.sender]);
    evote.encDeadSum  = FHE.sub(evote.encDeadSum,  evote.voterDeadContrib[msg.sender]);
}
```

This allows voters to correct mistakes or change their mind during the grace period.

**Step 4: Update running sums**

```solidity
evote.voterAliveContrib[msg.sender] = aliveContrib;
evote.voterDeadContrib[msg.sender]  = deadContrib;

if (FHE.isInitialized(evote.encAliveSum)) {
    evote.encAliveSum = FHE.add(evote.encAliveSum, aliveContrib);
    evote.encDeadSum  = FHE.add(evote.encDeadSum,  deadContrib);
} else {
    evote.encAliveSum = aliveContrib;
    evote.encDeadSum  = deadContrib;
}
```

### 4.4 Dual-Sum Approach

Unlike plaintext mode where a single boolean tracks each vote, the encrypted mode tracks two independent sums:

- `encAliveSum`: encrypted count of votes for "alive"
- `encDeadSum`: encrypted count of votes for "dead"

This is necessary because FHE operations cannot branch on encrypted values. The contract cannot inspect whether a vote
is alive or dead; it can only homomorphically compute both contributions and add them to their respective sums.

### 4.5 Majority Check and Decryption Trigger

The contract tracks `uniqueAttempts` as a plaintext counter of distinct voters. This counter increments only once per
voter (even if they re-submit). After each vote, the contract checks:

```solidity
uint256 majority = (councils[user].length / 2) + 1;
if (evote.uniqueAttempts >= majority) {
    _requestVoteDecryption(user, evote, majority);
}
```

When enough unique voters have participated, the contract computes the encrypted result and triggers decryption. The
threshold is the same majority count used for plaintext voting.

**Note:** The trigger is based on the number of _unique voters_, not the number of valid votes. If some voters
submitted invalid values, the decryption may reveal no majority even though enough voters participated. In this case,
the decryption state is reset and more votes can be cast (see Section 4.7).

### 4.6 Asynchronous Decryption Flow

Encrypted voting uses a three-phase resolution process:

#### Phase 1: Compute encrypted result and request decryption

The `_requestVoteDecryption` function computes the outcome homomorphically:

```solidity
euint8 encMajority = FHE.asEuint8(uint8(majority));

ebool aliveWins = FHE.ge(evote.encAliveSum, encMajority);
ebool deadWins  = FHE.ge(evote.encDeadSum, encMajority);

// Pack result: 0=no majority, 1=alive, 2=dead
euint8 result = FHE.select(aliveWins, FHE.asEuint8(1), FHE.asEuint8(0));
result = FHE.select(deadWins, FHE.asEuint8(2), result);

evote.encResult = FHE.makePubliclyDecryptable(result);
evote.decryptionRequested = true;
```

`FHE.makePubliclyDecryptable()` signals to the FHEVM KMS (Key Management Service) that this ciphertext should be
decrypted. The KMS signers will produce a decryption proof off-chain.

Event: `VoteDecryptionRequested(address indexed user)`

#### Phase 2: KMS produces decryption proof (off-chain)

The KMS network observes the `makePubliclyDecryptable` call and collaboratively produces a proof that the decrypted
value corresponds to the ciphertext handle. This happens asynchronously and typically takes a few seconds to minutes.

#### Phase 3: Anyone calls `resolveEncryptedVote()` with the proof

```solidity
function resolveEncryptedVote(
    address user,
    uint8 decryptedResult,
    bytes calldata decryptionProof
) external
```

The resolver provides the claimed cleartext result and the KMS proof. The contract verifies the proof using
`FHE.checkSignatures()`:

```solidity
bytes32[] memory handlesList = new bytes32[](1);
handlesList[0] = euint8.unwrap(evote.encResult);
bytes memory abiEncodedCleartexts = abi.encode(decryptedResult);
FHE.checkSignatures(handlesList, abiEncodedCleartexts, decryptionProof);
```

If verification succeeds, the result is applied:

| `decryptedResult` | Meaning | Action |
|-------------------|---------|--------|
| 0 | No majority | Reset decryption state, allow more votes |
| 1 | Alive majority | Set `FinalAlive`, reset check-in timer |
| 2 | Dead majority | Mark deceased, record notifier |

Event: `EncryptedVoteResolved(address indexed user, uint8 result)`

Anyone can call `resolveEncryptedVote()` -- it does not require being a council member. This is intentional: the proof
is cryptographically verified, so the caller's identity is irrelevant.

### 4.7 No-Majority Resolution

When the decrypted result is 0 (no majority reached), the contract resets the decryption-related state but preserves
the existing votes:

```solidity
if (decryptedResult == 0) {
    evote.decryptionRequested = false;
    evote.resultVerified = false;
    evote.decryptedResult = 0;
}
```

This allows additional council members to cast votes. A new decryption will be triggered when enough unique voters
have participated, or manually via `requestVoteDecryption()`.

### 4.8 Manual Decryption Request

If the auto-trigger did not fire (e.g., the grace period expired with some votes cast but below the automatic
threshold), anyone can manually request decryption:

```solidity
function requestVoteDecryption(address user) external
```

Requirements:
- User must have `encryptedVoting` enabled
- User must not be deceased
- Vote must not be already decided
- Decryption must not have been already requested
- At least one vote must have been cast (`uniqueAttempts > 0`)

This is useful when the council is small and every member has voted, but the total is still below the automatic trigger
(which should not happen in practice since `uniqueAttempts >= majority` triggers automatically, and majority is always
<= council size).

### 4.9 Vote Secrecy Guarantees

**What is secret:**
- The value of each individual vote (alive or dead)
- The running alive and dead sums (encrypted on-chain)
- Whether a voter submitted a valid or invalid value

**What is public:**
- Whether a council member has attempted to vote (the `hasAttempted` mapping is plaintext)
- How many unique voters have participated (`uniqueAttempts` is plaintext)
- The final outcome after decryption (alive majority, dead majority, or no majority)

**What is NOT guaranteed:**
- If only one council member exists and votes, the outcome trivially reveals their vote. Privacy guarantees scale with
  council size.
- The `uniqueAttempts` counter reveals participation timing. An observer can see when each member submitted their
  transaction, even though the vote content is hidden.

## 5. User Configuration

### 5.1 The `encryptedVoting` Field

Each user has an `encryptedVoting` boolean in their `User` struct that determines which voting mode is used:

```solidity
struct User {
    // ... other fields ...
    bool encryptedVoting; // Whether council votes use FHE encryption
}
```

### 5.2 Default Values

- **New registrations**: `encryptedVoting` defaults to `true`. All `register()` overloads that do not accept an
  explicit `encryptedVoting` parameter pass `true` to the internal `_register()` function.
- **Explicit registration**: The four-parameter overload `register(name, checkInPeriod, gracePeriod, encryptedVoting)`
  allows the user to choose their mode at registration time.
- **Existing users (pre-upgrade)**: Users who registered before the encrypted voting feature was added have
  `encryptedVoting == false` by default (Solidity zero-initializes new storage fields). This ensures backward
  compatibility: existing users continue to use plaintext voting unless they explicitly opt in.

### 5.3 Toggling the Mode

```solidity
function setEncryptedVoting(bool enabled) external
```

A registered user can toggle their voting mode at any time, with two restrictions:
- The user must not be deceased
- The user must not be in a grace period (to prevent switching modes while votes are in progress)

The function simply sets `u.encryptedVoting = enabled`. There is no event emitted for this change.

### 5.4 Mode Enforcement

The voting functions enforce mutual exclusivity:

- `voteOnStatus()` reverts with `EncryptedVotingMode()` if `encryptedVoting` is true
- `voteOnStatusEncrypted()` reverts with `PlaintextVotingMode()` if `encryptedVoting` is false

## 6. Integration with User Lifecycle

### 6.1 How `ping()` Resets Vote State

When a user calls `ping()`, the contract checks whether vote state needs to be cleared:

**Case 1: User is in `FinalAlive` state** (council previously voted them alive):
```solidity
if (u.finalAlive) {
    u.finalAlive = false;
    if (u.encryptedVoting) {
        _resetEncryptedGraceVote(msg.sender);
    } else {
        _resetGraceVote(msg.sender);
    }
}
```

**Case 2: User was in grace period** (check-in expired but user pinged before grace ended):
```solidity
uint256 checkInEnd = uint256(u.lastCheckIn) + uint256(u.checkInPeriod);
if (block.timestamp > checkInEnd) {
    if (u.encryptedVoting) {
        _resetEncryptedGraceVote(msg.sender);
    } else {
        _resetGraceVote(msg.sender);
    }
}
```

In both cases, the reset function corresponding to the user's current voting mode is called.

### 6.2 How `markDeceased()` Works

The `markDeceased()` function operates independently of the council system. It simply checks whether the full timeout
has elapsed:

```solidity
uint256 deadline = uint256(u.lastCheckIn) + uint256(u.checkInPeriod) + uint256(u.gracePeriod);
if (!(block.timestamp > deadline)) revert NotTimedOut();
```

It does **not** check council votes. If the grace period expires without a council majority, anyone can call
`markDeceased()` regardless of any votes that were cast. The council system can only override the timeout by reaching a
majority _during_ the grace period.

The function also checks `u.finalAlive` and reverts with `UserVotedAlive()` if the council has already voted the user
alive, preventing `markDeceased()` from overriding a council decision.

### 6.3 `FinalAlive` State

When a council votes "alive" by majority, the user enters the `FinalAlive` state:

- `u.finalAlive = true`
- `u.lastCheckIn` is reset to the current timestamp
- `markDeceased()` is blocked (reverts with `UserVotedAlive()`)

The user remains in `FinalAlive` until they call `ping()`, which clears `finalAlive` and resets vote state, returning
them to the normal `Alive` cycle. If the user never pings again, they will eventually re-enter grace and a new round of
voting can begin.

## 7. API Reference

### 7.1 Council Management Functions

```solidity
// Add a council member (max 20, frozen during grace)
function addCouncilMember(address member) external

// Remove a council member (frozen during grace)
function removeCouncilMember(address member) external

// Toggle encrypted voting mode (frozen during grace)
function setEncryptedVoting(bool enabled) external
```

### 7.2 Plaintext Voting Functions

```solidity
// Cast a plaintext vote (council member only, grace period only)
function voteOnStatus(address user, bool voteAlive) external
```

### 7.3 Encrypted Voting Functions

```solidity
// Cast an encrypted vote (council member only, grace period only)
function voteOnStatusEncrypted(
    address user,
    externalEuint8 encVote,
    bytes calldata inputProof
) external

// Manually request decryption of encrypted vote result
function requestVoteDecryption(address user) external

// Resolve encrypted vote with KMS decryption proof
function resolveEncryptedVote(
    address user,
    uint8 decryptedResult,
    bytes calldata decryptionProof
) external
```

### 7.4 View Functions

```solidity
// Get council members and join timestamps
function getCouncilMembers(address user)
    external view returns (address[] memory members, uint64[] memory joinedAts)

// Get all users a member is council for
function getUsersForCouncilMember(address member)
    external view returns (address[] memory userAddresses)

// Get plaintext vote status (returns zeros for encrypted mode)
function getGraceVoteStatus(address user)
    external view returns (uint256 aliveVotes, uint256 deadVotes, bool decided, bool decisionAlive)

// Check if a member has voted (for encrypted mode: whether they attempted)
function getGraceVote(address user, address member)
    external view returns (bool hasVoted, bool votedAlive)

// Get encrypted vote status
function getEncryptedGraceVoteStatus(address user)
    external view returns (
        uint256 uniqueAttempts,
        bool decryptionRequested,
        bool resultVerified,
        uint8 decryptedResult,
        bool decided,
        bool decisionAlive
    )

// Check if encrypted voting is enabled for a user
function getEncryptedVoting(address user) external view returns (bool)

// Get user lifecycle state
function getUserState(address user)
    external view returns (UserStatus status, uint64 graceSecondsLeft)
```

### 7.5 Events

```solidity
// Council membership
event CouncilMemberAdded(address indexed user, address indexed member);
event CouncilMemberRemoved(address indexed user, address indexed member);

// Plaintext voting
event GraceVoteCast(address indexed user, address indexed voter, bool votedAlive);
event StatusDecided(address indexed user, bool isAlive);

// Encrypted voting
event EncryptedGraceVoteCast(address indexed user, address indexed voter);
event VoteDecryptionRequested(address indexed user);
event EncryptedVoteResolved(address indexed user, uint8 result);
```

### 7.6 Errors

```solidity
// Council management
error InvalidMember();           // address(0) passed as member
error CannotAddSelf();           // user tried to add themselves
error AlreadyCouncilMember();    // member already on council
error CouncilFull();             // council has 20 members
error NotCouncilMember();        // caller is not a council member
error MemberNotFound();          // member not found in array during removal
error CouncilFrozenDuringGrace(); // council modification attempted during grace period

// Voting preconditions
error NotInGracePeriod();        // user is not in grace period
error GracePeriodEnded();        // grace period has expired
error VoteAlreadyDecided();      // decision already reached
error AlreadyVoted();            // member already voted (plaintext mode)
error UserDeceased();            // user is already deceased
error UserVotedAlive();          // user has FinalAlive status

// Mode enforcement
error PlaintextVotingMode();     // encrypted function called but user uses plaintext
error EncryptedVotingMode();     // plaintext function called but user uses encrypted

// Encrypted vote resolution
error DecryptionNotRequested();      // resolveEncryptedVote called before decryption requested
error DecryptionAlreadyRequested();  // decryption already in progress
error ResultAlreadyVerified();       // KMS proof already verified
error NoVotesCast();                 // manual decryption requested but no votes exist
```

## 8. Security Considerations

### 8.1 Vote Secrecy

Encrypted voting provides computational secrecy for individual votes. The security relies on:

- **FHEVM encryption**: Votes are encrypted under the network's FHE public key. Breaking vote secrecy requires
  breaking the underlying TFHE scheme.
- **KMS threshold**: The decryption key is distributed among KMS signers. A threshold of signers must collude to
  decrypt individual votes (the contract only requests decryption of the aggregate result, never individual votes).
- **On-chain opacity**: The `encAliveSum`, `encDeadSum`, and per-voter contributions are stored as FHE ciphertext
  handles. Reading storage reveals only opaque handles, not plaintext values.

**Limitations:**
- Small councils (1-2 members) provide weak privacy since the outcome may trivially reveal individual votes.
- Transaction timing reveals when each member voted, which may leak information in some social contexts.
- The FHEVM trust model applies (see the main protocol documentation for the full threat model).

### 8.2 Gas Costs

Encrypted voting is significantly more expensive than plaintext voting due to FHE operations:

| Operation | Approximate gas |
|-----------|----------------|
| `voteOnStatusEncrypted` (first vote) | ~1,200,000 - 1,500,000 |
| `voteOnStatusEncrypted` (replacement) | ~1,500,000 - 1,800,000 |
| `resolveEncryptedVote` | ~200,000 - 300,000 |
| `voteOnStatus` (plaintext) | ~50,000 - 100,000 |

Users should consider gas costs when choosing their voting mode. For testnet usage, this is not a concern. For mainnet
deployment, the cost difference may influence the choice.

### 8.3 Invalid Vote Handling

In encrypted mode, submitting a value other than 1 or 2 results in both `aliveContrib` and `deadContrib` being
encrypted 0. The vote has no effect on the tally, but the `uniqueAttempts` counter still increments. This means:

- An attacker who is a council member could submit invalid votes to trigger the decryption threshold without actually
  voting, potentially causing a no-majority result.
- This is mitigated by the no-majority recovery: when decryption reveals no majority, the state resets and more votes
  can be cast.
- Voters who accidentally submit invalid values can re-submit with a valid value (replacement semantics).

### 8.4 Council Size Limits

The `MAX_COUNCIL_SIZE = 20` limit exists primarily for gas safety:

- `_resetGraceVote` and `_resetEncryptedGraceVote` iterate over all council members to clear per-voter state.
- `removeCouncilMember` iterates over the council array to find the member.
- These loops must complete within block gas limits.

### 8.5 Decryption Liveness

The encrypted voting flow depends on the FHEVM KMS network producing decryption proofs. If the KMS becomes unavailable:

- `resolveEncryptedVote()` cannot be called (no valid proof exists)
- The grace period will eventually expire, and `markDeceased()` can be called by anyone
- Council votes are effectively ignored in this scenario

This is an inherent dependency of the encrypted voting mode. Users who require guaranteed council intervention should
consider whether the KMS availability meets their reliability requirements.

### 8.6 Re-Voting and Replacement

In encrypted mode, voters can re-submit to replace their previous vote. This is tracked via `FHE.isInitialized()` on
the per-voter contribution handles. The replacement is done by subtracting the old contribution and adding the new one.

In plaintext mode, re-voting is not allowed. Once a member votes, `AlreadyVoted()` is reverted on subsequent attempts.

This difference exists because plaintext votes are public and irrevocable (changing them would be visible and
controversial), while encrypted votes are private and the replacement is indistinguishable from a first-time vote to
observers.
