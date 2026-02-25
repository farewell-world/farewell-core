# Farewell Protocol Specification

This document provides a complete technical specification of the Farewell protocol, including user lifecycle management,
message encryption, cryptographic key sharing, FHE integration, claiming workflows, delivery verification, and the
council voting system.

## 1. Overview

Farewell is a decentralized protocol for posthumous encrypted messages using Fully Homomorphic Encryption (FHE) on
Ethereum. The protocol is designed around three core principles:

1. **No central operator**: The protocol runs entirely on-chain via a smart contract. Once messages are stored, they
   persist indefinitely without depending on any service.

2. **Blockchain persistence**: Messages are cryptographically committed to the blockchain, making them tamper-proof and
   permanently available once released.

3. **Encryption and access control**: Messages remain encrypted until a user stops checking in (liveness timeout), after
   which council members and the contract can prove the user is deceased and release messages to authorized claimers.

The protocol combines:

- **Zama FHEVM** for on-chain encryption of sensitive fields (recipient emails, key shares)
- **AES-128-GCM** for client-side encryption of message payloads
- **Groth16 zero-knowledge proofs** (via zk-email) for proof-of-delivery
- **Council voting** for liveness determination during grace periods

Live deployment: https://farewell.world (Sepolia testnet)

---

## 2. User Lifecycle

### 2.1 Status Enum

Users progress through four possible states:

```solidity
enum UserStatus {
  Alive, // Within current check-in period
  Grace, // Check-in period expired, within grace period
  Deceased, // User marked deceased (grace period expired or finalized)
  FinalAlive // Council voted alive, timer reset
}
```

### 2.2 State Transitions

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER LIFECYCLE STATES                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Alive                                                         │
│   ──────────────────────────────────────────────────────────   │
│   ├─ User registered at block X                               │
│   ├─ ping() can be called any time to reset timer             │
│   ├─ If ping() called before (X + checkInPeriod): stays Alive │
│   └─ If checkInPeriod expires without ping(): enter Grace     │
│                                                                 │
│         ↓                                                        │
│                                                                 │
│   Grace                                                         │
│   ────────────────────────────────────────────────────────────│
│   ├─ Timer at (X + checkInPeriod)                             │
│   ├─ Lasts until (X + checkInPeriod + gracePeriod)            │
│   ├─ Council members can vote during this window              │
│   ├─ If ping() called: resets to Alive                        │
│   ├─ If councilVote → majority alive: → FinalAlive            │
│   ├─ If councilVote → majority dead: → Deceased               │
│   └─ If gracePeriod expires: anyone can call markDeceased()   │
│                                                                 │
│         ↓                                                        │
│                                                                 │
│   Deceased                                                      │
│   ────────────────────────────────────────────────────────────│
│   ├─ User is finalized as deceased                            │
│   ├─ Messages become claimable                                │
│   ├─ No transitions out of Deceased                           │
│   └─ claim() and retrieve() functions become available        │
│                                                                 │
│         ↓ (voter becomes "notifier" with 24h claim priority)   │
│                                                                 │
│   FinalAlive                                                    │
│   ────────────────────────────────────────────────────────────│
│   ├─ Council voted majority alive                             │
│   ├─ Timer and grace period are reset                         │
│   ├─ User re-enters normal check-in cycle                     │
│   ├─ ping() is required again to stay alive                   │
│   ├─ If ping() called: back to Alive (grace votes cleared)    │
│   └─ If checkInPeriod expires again: → Grace                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Registration

Users register once with customizable check-in and grace periods:

```solidity
function register(
    string calldata name,
    uint64 checkInPeriod,
    uint64 gracePeriod
) external
```

Parameters:

- `name`: Display name (max 100 bytes)
- `checkInPeriod`: Minimum time between pings (min 1 day, max ~50 years)
- `gracePeriod`: Time for council voting after timeout (min 1 day, max ~50 years)

Event: `UserRegistered(user, checkInPeriod, gracePeriod, registeredOn)`

### 2.4 Liveness Check (Ping)

Users must periodically call `ping()` to reset their timer:

```solidity
function ping() external
```

Effects:

- Resets `lastPing` to current block timestamp
- If user was in Grace: reverts to Alive
- If user was in FinalAlive: clears council votes, resets to Alive

Event: `Ping(user, when)`

### 2.5 Marking Deceased

After both `checkInPeriod` and `gracePeriod` have expired without a ping or council decision, anyone can mark the user
deceased:

```solidity
function markDeceased(address user) external
```

Requirements:

- `block.timestamp >= lastPing[user] + checkInPeriod[user] + gracePeriod[user]`
- User status must not be FinalAlive

Effects:

- Sets `status[user] = Deceased`
- Records the caller as the "notifier" (eligible for 24-hour claim priority)
- Messages become claimable

Event: `Deceased(user, when, notifier)`

---

## 3. Message Encryption

### 3.1 Client-Side Encryption (AES-128-GCM)

Messages are encrypted client-side using AES-128-GCM before submission to the contract. This is critical because all
data stored on-chain is publicly visible.

#### Packed Format

AES-128-GCM ciphertexts are packed into a single hex string:

```
┌─────────────────────────────────────────────────────────────┐
│  0x  │  IV (12 bytes)  │  ciphertext  │  GCM-tag (16 bytes) │
└─────────────────────────────────────────────────────────────┘
      12 bytes         variable        16 bytes
                     (ciphertext length)
```

Total overhead: 28 bytes (12-byte IV + 16-byte authentication tag)

Example:

```
0xAB12...CD | 000102030405060708090A0B | 48656C6C6F 20576F726C64 | 0102030405060708090A0B0C0D0E0F10
           └─ IV                      └─ plaintext (hello world)  └─ GCM tag
```

#### Format Selection

The packed AES format is chosen because:

- Chainable: IV and tag remain in the same field
- Deterministic: No additional parameters needed for decryption
- Compact: Minimal on-chain storage
- Recipient-verifiable: Recipients can independently verify the contentHash

### 3.2 On-Chain Payload Storage

The AES-encrypted payload is stored on-chain as raw `bytes`:

```solidity
bytes payload;  // AES-128-GCM encrypted message
```

Constraints:

- Maximum 10,240 bytes (10 KB) to prevent spam
- Publicly visible on-chain (encryption is mandatory)
- Immutable after creation (cannot be changed, only revoked)

---

## 4. Key Sharing Scheme

### 4.1 Overview

The protocol uses an XOR-based key sharing scheme to prevent decryption until after the user's death. This design
ensures that before death, neither the recipient (who has incomplete information) nor on-chain observers can decrypt the
message.

### 4.2 Key Split Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      KEY SHARING SCHEME                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  USER (while alive)              RECIPIENT (after death)      │
│  ─────────────────────           ──────────────────────────   │
│                                                                │
│  Generate message M              Receives s' from user        │
│  ├─ Choose AES-128 key sk        (e.g., email, QR code)      │
│  │                                                             │
│  ├─ Generate random s (128-bit)  Receives claim package       │
│  │  Example: s = 0x12345...      └─ Contains s (on-chain,     │
│  │                                  FHE-decrypted)           │
│  ├─ Compute s' = sk XOR s                                      │
│  │  Example: if sk = 0xABCD...   Computes sk:                │
│  │           s' = 0x...          sk = s XOR s'               │
│  │                               = 0x...                      │
│  │                                                             │
│  └─ Share s' with recipient      Uses sk to decrypt:         │
│     (off-chain, any channel)      AES-128-GCM.decrypt(       │
│                                     sk, encryptedPayload)    │
│                                                                │
│  Store on-chain:                                              │
│  ├─ enc(s) via FHE (euint128)                                 │
│  └─ enc_aes(M) as bytes                                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 4.3 Security Properties

**Before user death:**

- Recipient has s' but cannot derive sk without s
- sk is encrypted on-chain as euint128 via FHE
- Even contract observers cannot see s or sk (FHE hides plaintext)
- Message remains secure

**After user death:**

- Claimer retrieves encrypted s via FHE.allow()
- Recipient gets s and uses their off-chain s' to compute sk
- Only the intended recipient can reconstruct sk and decrypt M

**Attack resistance:**

- Attacker with only s' cannot decrypt (needs s)
- Attacker with only enc(s) cannot decrypt (FHE keeps s hidden)
- Attacker with both s' and enc(s) still cannot proceed without FHE decryption capability (granted only to claimed
  recipients)

---

## 5. FHE-Encrypted Data

### 5.1 Email Encryption

Recipient emails are encrypted using Zama's FHEVM. To prevent length-based leakage attacks, all emails are first padded
to a fixed length.

#### Padding and Limb Structure

```
┌──────────────────────────────────────────────────────────┐
│                    EMAIL ENCRYPTION FLOW                 │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Input: "alice@example.com" (21 bytes)                  │
│                                                          │
│  Step 1: Pad to MAX_EMAIL_BYTE_LEN (224 bytes)          │
│  ───────────────────────────────────────────────────     │
│  "alice@example.com" + 203 zero bytes                   │
│  = 224-byte padded string                               │
│                                                          │
│  Step 2: Split into 7 x 32-byte limbs                   │
│  ────────────────────────────────────────               │
│  224 bytes / 32 = 7 limbs (no remainder)                │
│                                                          │
│  Limb structure:                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Limb[0] │ Limb[1] │ ... │ Limb[6]             │   │
│  │ 32 bytes│ 32 bytes│     │ 32 bytes (padded)   │   │
│  └─────────────────────────────────────────────────┘   │
│   0-31      32-63             192-223                   │
│                                                          │
│  Step 3: Encrypt each limb as euint256                  │
│  ──────────────────────────────────────                 │
│  For each 32-byte limb L:                               │
│    limb_encrypted = FHE.asEuint256(L)                   │
│                                                          │
│  Result: 7 FHE-encrypted limbs (euint256[])             │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Why this approach:**

- **Prevents length leakage**: All emails appear 224 bytes (even "a@b.c")
- **euint256 is 256 bits**: Each 32-byte limb fits exactly in one euint256
- **No overflow**: 7 × 256 = 1792 bits out of FHEVM's 2048-bit limit
- **Deterministic**: Receiver knows to split into 7 limbs without additional metadata

### 5.2 Key Share Encryption

The 128-bit key share `s` is stored as euint128:

```solidity
euint128 encSkShare;  // FHE-encrypted 128-bit key share
```

Total FHE input per message:

- 7 × euint256 (recipient email limbs) = 1792 bits
- 1 × euint128 (key share) = 128 bits
- **Total = 1920 bits** (within 2048-bit FHEVM limit)

### 5.3 FHE Access Control

Messages are stored with restricted FHE visibility:

**Initial state (message just added):**

```
Message owner: Can FHE-decrypt email limbs and key share
Contract: Can manage FHE permissions but not decrypt
Claimer: No access
```

**After claim(user, messageIndex):**

```
FHE.allow(encSkShare, claimer);           // Grant access to key share
FHE.allow(encRecipientEmail[i], claimer); // Grant access to each email limb
```

The FHE.allow() call is irreversible — once a claimer is granted access, it cannot be revoked.

---

## 6. Claiming and Delivery

### 6.1 Claim Exclusivity Window

After markDeceased() is called, the caller (notifier) receives a 24-hour priority window to claim messages before anyone
else can:

```
┌──────────────────────────────────────────────────┐
│         24-HOUR CLAIM EXCLUSIVITY                 │
├──────────────────────────────────────────────────┤
│                                                  │
│  T0: markDeceased() called by Address A          │
│      └─ notifier = Address A                     │
│      └─ notifierClaimDeadline = T0 + 24 hours   │
│                                                  │
│  T0 to T0+24h:                                   │
│      └─ Only Address A can call claim()         │
│      └─ Others: revert("Too early")             │
│                                                  │
│  T0+24h onwards:                                 │
│      └─ Anyone can call claim()                 │
│      └─ notifier loses priority                 │
│                                                  │
└──────────────────────────────────────────────────┘
```

Purpose: Incentivize good-faith notification of death and allow original notifier first access to attach delivery
proofs.

### 6.2 Claim Operation

```solidity
function claim(address user, uint256 index) external
```

Requirements:

- User must be Deceased
- Message must not already be claimed
- Caller must either be notifier (within 24h) or 24h has passed
- User must still be deceased (not revived by recovery mechanism)

Effects:

- Sets `claimed[user][index] = true`
- Calls `FHE.allow()` to grant caller decryption access:
  ```solidity
  FHE.allow(messages[user][index].encSkShare, msg.sender);
  for (uint i = 0; i < 7; i++) {
    FHE.allow(messages[user][index].encRecipientEmail[i], msg.sender);
  }
  ```

Event: `Claimed(user, index, claimer)`

### 6.3 Retrieve Operation

```solidity
function retrieve(address owner, uint256 index) external view
  returns (
    euint128 skShare,
    euint256[] memory encRecipientEmail,
    uint32 emailByteLen,
    bytes memory payload,
    string memory publicMessage,
    bytes32 contentHash
  )
```

Requirements:

- Message must be claimed by caller (FHE access granted)
- Returns the encrypted data and metadata

Process:

1. User supplies the claimed message
2. Contract returns FHE-encrypted email limbs and key share (only callable by claimer due to FHE permissions)
3. Claimer's client-side FHEVM library decrypts the email and key share locally
4. Claimer proceeds to delivery workflow

---

## 7. Claim Package Format

The claim package is a JSON file downloaded after claiming a message. It contains all the data needed for delivery
verification and recipient decryption.

### 7.1 Claim Package Structure

```json
{
  "type": "farewell-claim-package",
  "version": 1,
  "owner": "0x1234567890123456789012345678901234567890",
  "messageIndex": 0,
  "recipients": ["alice@example.com", "bob@example.com"],
  "skShare": "0x75554596171405abc...",
  "encryptedPayload": "0xab12...cd",
  "contentHash": "0x1234567890abcdef...",
  "subject": "Farewell Message"
}
```

### 7.2 Field Reference

| Field              | Type     | Purpose                                                                 |
| ------------------ | -------- | ----------------------------------------------------------------------- |
| `type`             | string   | Must be `"farewell-claim-package"` (format identifier for claimer tool) |
| `version`          | number   | Schema version for backward compatibility (currently 1)                 |
| `owner`            | address  | Message creator's wallet address                                        |
| `messageIndex`     | number   | Index in owner's message array                                          |
| `recipients`       | string[] | Email addresses to receive the message                                  |
| `skShare`          | hex      | FHE-decrypted on-chain half of AES-128 key (128 bits)                   |
| `encryptedPayload` | hex      | AES-128-GCM encrypted message (packed format)                           |
| `contentHash`      | hex      | keccak256 of plaintext message (for proof verification)                 |
| `subject`          | string   | Email subject line                                                      |

### 7.3 Data Flow

```
┌─────────────────────────────────────┐
│  retrieve() on-chain               │
│  ├─ encryptedPayload (AES ciphertext)
│  ├─ contentHash (keccak256 of plaintext)
│  ├─ encSkShare (FHE-encrypted on-chain half)
│  ├─ encRecipientEmail (FHE-encrypted limbs)
│  └─ recipients (plaintext email array)
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│  Claim Package JSON                 │
│  ├─ contentHash (passed through)    │
│  ├─ encryptedPayload (passed through)
│  ├─ skShare (FHE-decrypted)         │
│  ├─ recipients (passed through)     │
│  └─ owner, messageIndex (metadata)  │
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│  farewell-claimer (Python tool)     │
│  ├─ Sends email with claim package  │
│  ├─ Proves delivery via zk-email    │
│  └─ Generates DeliveryProofJson     │
└─────────────────────────────────────┘
```

---

## 8. Delivery Rewards

### 8.1 Reward Calculation

Each message can have an optional ETH reward for delivery proof:

```
reward = BASE_REWARD + REWARD_PER_KB × ceil(payloadSize / 1024)
```

where:

- `BASE_REWARD = 0.01 ETH`
- `REWARD_PER_KB = 0.005 ETH`
- `payloadSize = encryptedPayload.length` in bytes

Example: 5 KB payload

```
payloadSize = 5120 bytes
ceil(5120 / 1024) = 5 KB
reward = 0.01 + 0.005 × 5 = 0.035 ETH
```

### 8.2 Multi-Recipient Tracking

Messages can target multiple recipients. Each recipient's proof is tracked separately using a bitmap:

```solidity
uint256 provenRecipientsBitmap;
// Bit i set to 1 if recipient[i] has proven delivery
```

#### Bitmap Logic

```
N = number of recipients

For each proven recipient at index i:
  provenRecipientsBitmap |= (1 << i)

Example: 3 recipients, indices 0, 1, 2
  All proven: (1 << 0) | (1 << 1) | (1 << 2)
             = 0b001 | 0b010 | 0b100
             = 0b111 = 7

Reward claimable when:
  provenRecipientsBitmap == (2^N - 1)

  For N=3: (1 << 3) - 1 = 0b111 = 7 ✓
```

### 8.3 Reward Claiming

```solidity
function claimReward(address user, uint256 messageIndex) external
```

Requirements:

- All recipients must be proven: `provenRecipientsBitmap == (2^numRecipients - 1)`
- Caller must be the message claimer
- Reward has not already been claimed

Effects:

- Transfers locked reward to claimer
- Clears reward amount to prevent double-claiming

Event: `RewardClaimed(user, messageIndex, claimer, amount)`

---

## 9. Council System

### 9.1 Council Membership

Each user can designate up to 20 trusted council members to vote on their liveness during the grace period:

```solidity
mapping(address user => address[] councilMembers) council;

// Constraint: councilMembers[user].length <= 20
```

### 9.2 Adding and Removing Members

```solidity
function addCouncilMember(address member) external
```

Requirements:

- Caller must be the user
- Member must not already be on council
- Council size must be less than 20

Effects:

- Adds member to user's council
- Member can now vote during grace periods

Event: `CouncilMemberAdded(user, member)`

```solidity
function removeCouncilMember(address member) external
```

Effects:

- Removes member from council
- Clears any active votes by this member

Event: `CouncilMemberRemoved(user, member)`

### 9.3 Voting During Grace Period

```solidity
function voteOnStatus(address user, bool voteAlive) external
```

Requirements:

- Caller must be a council member of user
- User must currently be in Grace status
- Caller must not have already voted on this grace period

Effects:

- Records vote (alive or deceased)
- May trigger immediate resolution if majority is reached

Event: `GraceVoteCast(user, voter, voteAlive)`

### 9.4 Vote Resolution

```
┌─────────────────────────────────────────────────────┐
│              GRACE PERIOD VOTING FLOW                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  User enters Grace status                          │
│  └─ Council votes can now be cast                  │
│     voting_deadline = grace_period_start + gracePeriod
│                                                     │
│  During voting:                                    │
│  ├─ Council members call voteOnStatus(alive/dead) │
│  ├─ Votes are recorded: aliveCounts, deadCounts   │
│  └─ If majority reached instantly:                │
│     ├─ If alive majority (>= councilSize/2 + 1):  │
│     │  └─ user status = FinalAlive                 │
│     │  └─ ping() timer is reset                    │
│     │  └─ user must ping to re-enter normal cycle  │
│     │                                              │
│     └─ If dead majority (> councilSize/2):        │
│        └─ user status = Deceased                   │
│        └─ voter becomes notifier                   │
│        └─ messages become claimable               │
│                                                     │
│  Grace period expires without resolution:         │
│  └─ Anyone can call markDeceased()                │
│     └─ user status = Deceased (finalized)         │
│                                                     │
│  User pings during grace:                         │
│  └─ Reverts to Alive status                       │
│  └─ Votes are cleared                             │
│  └─ Council must start over if user times out again
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 9.5 Majority Calculation

```solidity
uint councilSize = council[user].length;
uint majorityRequired = (councilSize / 2) + 1;

// Alive majority
if (aliveCounts >= majorityRequired) {
  status[user] = FinalAlive;
  lastPing[user] = block.timestamp;  // Reset timer
}

// Dead majority
if (deadCounts > (councilSize / 2)) {
  status[user] = Deceased;
  notifier[user] = currentVoter;
}
```

---

## 10. Delivery Proof and ZK-Email

For detailed specifications of the proof format, verification flow, and zk-email integration, see
[docs/proof-structure.md](proof-structure.md).

Key concepts:

- **Claim Package**: Downloaded from UI after claiming a message
- **Delivery**: Claimer uses farewell-claimer tool to send email and generate proof
- **Proof Format**: Groth16 proof with 3 public signals (recipient hash, DKIM key hash, content hash)
- **Bitmap Tracking**: Multi-recipient messages tracked via bitmaps
- **Reward Claim**: Once all recipients proven, claimer withdraws ETH

---

## 11. Security Considerations

### 11.1 Known Limitations

#### No Recovery Mechanism

Users marked as Deceased cannot be recovered except via council vote _before_ the grace period expires and the Deceased
status is finalized.

Mitigation:

- Set reasonable grace periods (default 7 days)
- Use council members as additional liveness confirmation

#### FHE Permissions Are Permanent

Once `FHE.allow()` grants a claimer access to encrypted data, it cannot be revoked.

Implication:

- Claimers must be trusted (they can FHE-decrypt all recipient emails)
- No revocation if claimer becomes malicious
- Separate proof-of-delivery prevents unrewarded claims

#### Timestamp Manipulation

Block timestamps can be manipulated by miners/validators within ~15 seconds.

Impact:

- Low for multi-day check-in periods (30 days default)
- Negligible compared to protocol timeouts
- No practical attack vector at current parameter values

#### On-Chain Data Is Public

All payloads, emails, and metadata are visible on the blockchain.

Mitigation:

- Mandatory client-side AES encryption of payloads
- FHE encryption of emails (hidden to network observers)
- Recipient emails visible in claim package only after claiming

#### User-Provided Key Entropy

If a user generates a weak AES-128 key sk, encryption is compromised.

Mitigation:

- Client uses Web Crypto API with system randomness (strong entropy)
- Key derivation from seed phrases uses KDF
- User education on secure key generation

#### Re-Claiming Window

After the 24-hour notifier exclusivity window, anyone can claim messages. Current implementation allows repeated claims.

Status:

- Beta implementation doesn't prevent this yet
- Proof-of-delivery framework prevents repeated reward claims
- Future: Message can be marked delivered/complete after first full proof

#### ZK Verifier Configuration

Current implementation has a placeholder verifier that accepts all proofs if no verifier is set.

Implication:

- Delivery proofs are not cryptographically verified in beta
- Cannot claim rewards without proper verifier configured
- Future: Real Groth16 verifier deployed

---

## 12. Constants

All protocol constants are defined in the smart contract:

| Constant                         | Type    | Value                 | Rationale                                   |
| -------------------------------- | ------- | --------------------- | ------------------------------------------- |
| `DEFAULT_CHECKIN`                | uint64  | 30 days (2,592,000 s) | Default monthly check-in interval           |
| `DEFAULT_GRACE`                  | uint64  | 7 days (604,800 s)    | One week for council voting                 |
| `MAX_EMAIL_BYTE_LEN`             | uint32  | 224                   | Padded email length (7 × 32-byte FHE limbs) |
| `MAX_PAYLOAD_BYTE_LEN`           | uint32  | 10,240                | 10 KB max message size (spam prevention)    |
| `BASE_REWARD`                    | uint256 | 0.01 ether            | Entry fee for delivery proofs               |
| `REWARD_PER_KB`                  | uint256 | 0.005 ether           | Scaling reward for larger messages          |
| `MAX_COUNCIL_SIZE`               | uint8   | 20                    | Prevents unbounded voting loops             |
| `NOTIFIER_CLAIM_PRIORITY_WINDOW` | uint256 | 24 hours              | Exclusivity window for markDeceased caller  |

---

## 13. Events

The contract emits the following events:

### User Lifecycle Events

```solidity
event UserRegistered(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn);

event UserUpdated(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn);

event Ping(address indexed user, uint64 when);

event Deceased(address indexed user, uint64 when, address indexed notifier);
```

### Message Events

```solidity
event MessageAdded(address indexed user, uint256 indexed index);

event MessageEdited(address indexed user, uint256 indexed index);

event MessageRevoked(address indexed user, uint256 indexed index);

event Claimed(address indexed user, uint256 indexed index, address indexed claimer);
```

### Council Events

```solidity
event CouncilMemberAdded(address indexed user, address indexed member);

event CouncilMemberRemoved(address indexed user, address indexed member);

event GraceVoteCast(address indexed user, address indexed voter, bool votedAlive);

event StatusDecided(address indexed user, bool isAlive);
```

### Reward Events

```solidity
event DeliveryProven(address indexed user, uint256 indexed messageIndex, uint256 recipientIndex, address claimer);

event RewardClaimed(address indexed user, uint256 indexed messageIndex, address indexed claimer, uint256 amount);
```

### Configuration Events

```solidity
event ZkEmailVerifierSet(address verifier);

event DkimKeyUpdated(bytes32 domain, uint256 pubkeyHash, bool trusted);
```

---

## 14. Protocol Variants and Extensions

### 14.1 Custom Check-In Periods

The protocol supports arbitrary check-in and grace periods:

```solidity
// Example: Weekly check-in, 3-day grace
register("Alice", 1 weeks, 3 days);

// Example: Annual check-in, 30-day grace
register("Bob", 365 days, 30 days);
```

Each user can choose independent durations, allowing flexible liveness strategies.

### 14.2 Optional Public Messages

In addition to encrypted payloads, messages can include cleartext:

```solidity
struct Message {
  // ... encrypted fields ...
  string publicMessage; // Optional cleartext
}
```

Use cases:

- Funeral instructions
- Memorial text
- Will preview (without sensitive data)
- Messages to people who are not on email list

### 14.3 Multiple Recipients per Message

The claim package and proof system support multiple recipients via the `recipients` array:

- Each recipient has their own `s'` (off-chain)
- All recipients get the same encrypted payload
- Claimer proves delivery to each independently via zk-email
- Bitmap tracks completion for each recipient

---

## 15. Gas Optimization Notes

The contract implements several gas optimizations:

1. **Unchecked arithmetic**: Where overflow is impossible
2. **Storage pointers**: Avoid redundant SLOAD/SSTORE
3. **Bitmap operations**: Single uint256 tracks up to 256 recipients
4. **Event indexing**: Three indexed parameters per event for efficient filtering
5. **FHE limbs**: Exactly 7 × euint256 fits cleanly with euint128 within FHEVM limits

---

## 16. Deployment Checklist

Before deploying Farewell to a new network:

1. **Verify FHEVM Support**: Network must support Zama FHEVM with coprocessor
2. **Set DKIM Trusted Keys**: Call `setTrustedDkimKey()` for major email providers (Gmail, Outlook, etc.)
3. **Deploy ZK Verifier**: Set verifier via `setZkEmailVerifier()`
4. **Test Council Functions**: Verify voting works with different council sizes
5. **Test Claim Packages**: Download and verify claim package JSON schema
6. **Gas Limits**: Verify all transactions fit within network gas limits
7. **Monitor Events**: Set up off-chain indexers for UserRegistered, Ping, Deceased events
8. **Documentation**: Update URLs and chain IDs in all references

---

## Related Documentation

For more information on specific aspects of the protocol:

- [Contract API Reference](contract-api.md) — Function signatures, events, errors, and constants
- [Building a Client](building-a-client.md) — Step-by-step guide with TypeScript examples
- [Delivery Proof Architecture](proof-structure.md) — ZK-email proofs and verification
- [Zama FHEVM Documentation](https://docs.zama.ai/fhevm) — Homomorphic encryption details
