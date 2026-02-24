# Farewell Contract API Reference

Complete API documentation for the Farewell smart contract. This is the authoritative reference for all public functions, events, constants, enums, and structs.

## Overview

**Contract**: `Farewell.sol`

**Inheritance**:
- `Initializable` — OpenZeppelin proxy initialization
- `UUPSUpgradeable` — UUPS upgradeable proxy pattern
- `OwnableUpgradeable` — Owner-based access control
- `ReentrancyGuardUpgradeable` — Reentrancy protection

**FHE Runtime**: Zama FHEVM (coprocessor-backed encrypted types)

**Solidity Version**: 0.8.27

**License**: BSD 3-Clause Clear

---

## Deployed Addresses

| Network | Chain ID | Proxy Address |
|---------|----------|---------------|
| **Sepolia** | 11155111 | `0x3997c9dD0eAEE743F6f94754fD161c3E9d0596B3` |
| **Hardhat** | 31337 | Local deployment (varies) |

---

## Getting the ABI

After cloning the repository, compile the contract:

```bash
npx hardhat compile
```

The contract ABI and bytecode are available at:
```
artifacts/contracts/Farewell.sol/Farewell.json
```

For web3 integrations, the ABI can be imported from TypeScript tooling or the `farewell` UI package generates TypeScript bindings via `genabi`.

---

## Constants

All constants are immutable and defined at compile-time.

| Constant | Type | Value | Description |
|----------|------|-------|-------------|
| `DEFAULT_CHECKIN` | `uint64` | `30 days` | Default check-in period if not specified during registration |
| `DEFAULT_GRACE` | `uint64` | `7 days` | Default grace period if not specified during registration |
| `MAX_EMAIL_BYTE_LEN` | `uint32` | `224` | Maximum email length in bytes. Emails are padded to this length to prevent length leakage via FHE. Equals 7 × 32-byte limbs (224 bytes). |
| `MAX_PAYLOAD_BYTE_LEN` | `uint32` | `10240` | Maximum encrypted payload size (10 KB). Prevents extremely large messages from being stored. |
| `BASE_REWARD` | `uint256` | `0.01 ether` | Base ETH reward per message with delivery proof. Used when calculating `calculateReward()`. |
| `REWARD_PER_KB` | `uint256` | `0.005 ether` | Additional reward per KB of payload size. Incentivizes larger messages proportionally. |
| `MAX_COUNCIL_SIZE` | `uint256` | `20` | Maximum council members per user. Prevents council voting from becoming too expensive (O(n) operations). |

---

## Enums

### UserStatus

Returned by `getUserState()`. Represents the lifecycle state of a user.

```solidity
enum UserStatus {
    Alive,      // 0 - User is within check-in period (liveness confirmed)
    Grace,      // 1 - User missed check-in but within grace period (council may vote)
    Deceased,   // 2 - User is deceased (messages claimable)
    FinalAlive  // 3 - User was voted alive by council (cannot be marked deceased again)
}
```

**Status Transitions**:
- `Alive` → `Grace` — Check-in period expires
- `Alive` → `Deceased` — Manually marked deceased via `markDeceased()` after timeout
- `Grace` → `Alive` (to `FinalAlive`) — Council votes alive before grace expires
- `Grace` → `Deceased` — Council votes dead or grace period expires without majority

---

## Data Structures

### ZkEmailProof

```solidity
struct ZkEmailProof {
    uint256[2] pA;           // Groth16 proof component A
    uint256[2][2] pB;        // Groth16 proof component B (2x2 matrix)
    uint256[2] pC;           // Groth16 proof component C
    uint256[] publicSignals; // Public circuit outputs:
                             // [0] = Poseidon hash of recipient email (TO field)
                             // [1] = DKIM public key hash (RSA-2048)
                             // [2] = Keccak256 hash of decrypted payload content
}
```

Used by `proveDelivery()`. The proof proves that an email with a specific recipient, from a specific domain (DKIM), containing specific content, was actually sent. See [proof-structure.md](proof-structure.md) for details.

### User (Internal Storage)

```solidity
struct User {
    string name;           // Display name (optional, max 100 bytes)
    uint64 checkInPeriod;  // Seconds user has to call ping()
    uint64 gracePeriod;    // Seconds council can vote after check-in expires
    uint64 lastCheckIn;    // Timestamp of last ping() or registration (also indicates registration)
    uint64 registeredOn;   // Timestamp of initial registration
    bool deceased;         // true if user marked deceased or council voted dead
    bool finalAlive;       // true if council voted user alive (locks status as Alive)
    Notifier notifier;     // Who marked the user deceased (for 24h claim exclusivity)
    uint256 deposit;       // ETH balance for funding delivery rewards
    Message[] messages;    // Array of messages
}
```

Stored in `mapping(address => User) public users`.

### Message (Internal Storage)

```solidity
struct Message {
    EncryptedString recipientEmail;  // FHE-encrypted email padded to MAX_EMAIL_BYTE_LEN
    euint128 _skShare;               // FHE-encrypted AES key share (128-bit)
    bytes payload;                   // Encrypted message payload (client-side encrypted)
    uint64 createdAt;                // Timestamp when message was created
    bool claimed;                    // true if claimer called claim()
    address claimedBy;               // Address of the claimer (if claimed)
    string publicMessage;            // Plaintext public message visible to all
    bytes32 hash;                    // Keccak256 hash of all inputs (for deduplication)
    bool revoked;                    // true if owner revoked the message
    uint256 reward;                  // ETH reward for delivery proof (0 if none)
    bytes32[] recipientEmailHashes;  // Poseidon hashes of each recipient email
    bytes32 payloadContentHash;      // Keccak256 hash of decrypted payload
    uint256 provenRecipientsBitmap;  // Bitmap: bit i set = recipient i proven
}
```

Stored in `User.messages[]` array.

### EncryptedString (Internal Storage)

```solidity
struct EncryptedString {
    euint256[] limbs;  // Email padded to MAX_EMAIL_BYTE_LEN and split into 32-byte chunks,
                       // each encrypted as euint256 (7 limbs for 224 bytes)
    uint32 byteLen;    // Original email length (before padding) for trimming during decryption
}
```

### CouncilMember (Internal Storage)

```solidity
struct CouncilMember {
    address member;   // Council member address
    uint64 joinedAt;  // Timestamp when member was added
}
```

---

## Initialization & Upgradeability

### initialize()

```solidity
function initialize() public initializer
```

Initializes the contract for proxy deployment. Sets owner, enables UUPS, reentrancy guard, and FHE coprocessor config. Called once during proxy deployment (typically via `ERC1967Proxy` or Hardhat deployment scripts).

**Access**: Anyone (but only once — enforced by `initializer` modifier)

**Parameters**: None

**Reverts**: N/A (reverts if called more than once)

**Emits**: (OpenZeppelin internal events)

**Notes**:
- This function replaces the constructor in upgradeable contracts.
- Sets `ZamaConfig.getEthereumCoprocessorConfig()` for the FHE runtime.
- Disabled initializers in constructor prevent reinitialization attacks.

---

### initializeV2()

```solidity
function initializeV2() public reinitializer(2)
```

Reinitializer for the v2 upgrade. Updates the FHE coprocessor configuration to FHEVM v0.9 standards. Must be called after upgrading from v1 to v2.

**Access**: Anyone (but only during upgrade — enforced by `reinitializer(2)` modifier)

**Parameters**: None

**Reverts**: N/A

**Emits**: (Internal FHE configuration events)

**Notes**:
- Called during the upgrade process via the proxy admin.
- `reinitializer(2)` ensures this runs only once and only after `initialize()` has run.

---

### confidentialProtocolId()

```solidity
function confidentialProtocolId() public view returns (uint256)
```

Returns the FHEVM protocol ID from `ZamaConfig`. Useful for clients to determine which FHEVM version is active.

**Access**: Public (view)

**Parameters**: None

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `uint256` | Protocol ID (typically a large number indicating FHEVM SDK version) |

**Reverts**: None

**Notes**:
- Deterministic return based on the active FHEVM SDK version.
- Used by frontends to verify compatibility with the contract's FHE runtime.

---

## User Lifecycle Management

### register (4 overloads)

#### register(string name, uint64 checkInPeriod, uint64 gracePeriod)

```solidity
function register(string memory name, uint64 checkInPeriod, uint64 gracePeriod) external
```

Register a new user or update an existing user's settings with a custom name and periods.

**Access**: Anyone (but caller must not be deceased)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `name` | `string` | Display name (max 100 bytes, can be empty) |
| `checkInPeriod` | `uint64` | Seconds between required check-ins (min 1 day, recommended 30 days) |
| `gracePeriod` | `uint64` | Seconds for council voting after check-in expires (min 1 day, recommended 7 days) |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"checkInPeriod too short"` | `checkInPeriod < 1 days` |
| `"gracePeriod too short"` | `gracePeriod < 1 days` |
| `"name too long"` | `bytes(name).length > 100` |
| `"user is deceased"` | Caller is marked deceased (cannot modify) |
| `"check-in period expired"` | Attempting to update after check-in window closed (new registration only) |

**Emits**:
- `UserRegistered(msg.sender, checkInPeriod, gracePeriod, registeredOn)` — if new user
- `UserUpdated(msg.sender, checkInPeriod, gracePeriod, registeredOn)` — if existing user
- `Ping(msg.sender, block.timestamp)` — always emitted to reset check-in timer

**Notes**:
- If user is already registered (has non-zero `lastCheckIn`), this updates settings instead of creating a new registration.
- Automatically calls `ping()` to reset the check-in timer.
- If user was previously voted `FinalAlive`, calling register/ping will reset that status.

#### register(uint64 checkInPeriod, uint64 gracePeriod)

```solidity
function register(uint64 checkInPeriod, uint64 gracePeriod) external
```

Register with custom periods but empty name.

**Same as above with `name = ""`.**

---

#### register(string name)

```solidity
function register(string memory name) external
```

Register with custom name but default periods (30 days check-in, 7 days grace).

**Same as the full overload with `checkInPeriod = 30 days` and `gracePeriod = 7 days`.**

---

#### register()

```solidity
function register() external
```

Register with empty name and default periods (30 days check-in, 7 days grace).

**Same as the full overload with `name = ""`, `checkInPeriod = 30 days`, and `gracePeriod = 7 days`.**

---

### isRegistered()

```solidity
function isRegistered(address user) external view returns (bool)
```

Check if an address is registered.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address to check |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `bool` | `true` if user has called register at least once |

**Reverts**: None

**Notes**:
- Returns `true` if `users[user].lastCheckIn != 0`.
- Does not check if user is alive, deceased, or in grace period.

---

### getUserName()

```solidity
function getUserName(address user) external view returns (string memory)
```

Get a user's display name.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `string` | User's display name (can be empty string) |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | User has not registered |

**Notes**:
- Does not validate that the name is unique or non-empty (users can have empty names).

---

### setName()

```solidity
function setName(string memory newName) external
```

Update the caller's display name.

**Access**: Only registered users (`msg.sender`)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `newName` | `string` | New display name (max 100 bytes) |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | Caller has not registered |
| `"name too long"` | `bytes(newName).length > 100` |

**Emits**:
- `UserUpdated(msg.sender, checkInPeriod, gracePeriod, registeredOn)`

**Notes**:
- Does not reset the check-in timer (use `ping()` for that).
- Can be called while deceased or in grace period.

---

### getRegisteredOn()

```solidity
function getRegisteredOn(address user) external view returns (uint64)
```

Get when a user first registered.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `uint64` | Unix timestamp of registration (never changes) |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | User has not registered |

---

### getLastCheckIn()

```solidity
function getLastCheckIn(address user) external view returns (uint64)
```

Get the timestamp of the user's last check-in.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `uint64` | Unix timestamp of last `ping()` or registration |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | User has not registered |

**Notes**:
- Updated by `register()` and `ping()`.
- Used to compute check-in deadline: `lastCheckIn + checkInPeriod`.

---

### getDeceasedStatus()

```solidity
function getDeceasedStatus(address user) external view returns (bool)
```

Check if a user is marked deceased.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `bool` | `true` if user is marked deceased |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | User has not registered |

**Notes**:
- Returns `true` after `markDeceased()` or council vote for death.
- Does not indicate grace period status — use `getUserState()` for full status.

---

### getNumberOfRegisteredUsers()

```solidity
function getNumberOfRegisteredUsers() external view returns (uint64)
```

Get the total count of registered users.

**Access**: Public (view)

**Parameters**: None

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `uint64` | Total users who have called register at least once |

**Reverts**: None

---

### getNumberOfAddedMessages()

```solidity
function getNumberOfAddedMessages() external view returns (uint64)
```

Get the total count of messages added across all users.

**Access**: Public (view)

**Parameters**: None

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `uint64` | Total messages added via `addMessage()` or `addMessageWithReward()` |

**Reverts**: None

**Notes**:
- Includes revoked and claimed messages.
- Does not decrement when messages are revoked.

---

### ping()

```solidity
function ping() external
```

Reset the caller's check-in timer. Confirms the user is alive.

**Access**: Registered users only

**Parameters**: None

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | Caller has not registered |
| `"user marked deceased"` | Caller is already marked deceased |

**Emits**:
- `Ping(msg.sender, block.timestamp)`

**Notes**:
- Resets `lastCheckIn` to current block timestamp.
- Clears `finalAlive` status, returning user to normal liveness cycle.
- Resets grace vote if one is in progress.
- Can be called at any time (even before check-in period expires).

---

### getUserState()

```solidity
function getUserState(address user) external view returns (UserStatus status, uint64 graceSecondsLeft)
```

Get a user's current lifecycle status and remaining grace period.

**Access**: Public (view, but user must be registered)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `status` | `UserStatus` | Current status (Alive, Grace, Deceased, or FinalAlive) |
| `graceSecondsLeft` | `uint64` | Remaining seconds in grace period (0 if not in grace) |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | User has not registered |

**Logic**:
```
1. If user.deceased = true         → return (Deceased, 0)
2. If user.finalAlive = true       → return (FinalAlive, 0)
3. If now <= lastCheckIn + checkInPeriod  → return (Alive, 0)
4. If now <= lastCheckIn + checkInPeriod + gracePeriod  → return (Grace, remaining)
5. Otherwise                       → return (Deceased, 0)
```

**Notes**:
- Status 5 (past grace, not yet marked deceased) still returns `Deceased` because the user is de facto deceased and claimable.
- `graceSecondsLeft` is computed as `graceEnd - now` if in grace, else 0.

---

### markDeceased()

```solidity
function markDeceased(address user) external
```

Mark a user as deceased after their check-in and grace periods have expired. Caller becomes the notifier with 24-hour claim exclusivity.

**Access**: Anyone, but subject to requirements

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address to mark deceased |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | User has not registered |
| `"user already deceased"` | User is already marked deceased |
| `"user voted alive by council"` | User has `finalAlive` status (council voted alive) |
| `"not timed out"` | `now <= lastCheckIn + checkInPeriod + gracePeriod` |

**Emits**:
- `Deceased(user, block.timestamp, msg.sender)`

**Notes**:
- Caller (notifier) has exclusive claim access for 24 hours via `claim()`.
- After 24 hours, anyone can claim.
- Setting `user.deceased = true` allows messages to be claimed.
- The caller becomes the `notifier` for `user.notifier.notifierAddress`.

---

## Message Management

### addMessage (2 overloads)

#### addMessage(externalEuint256[] limbs, uint32 emailByteLen, externalEuint128 encSkShare, bytes payload, bytes inputProof)

```solidity
function addMessage(
    externalEuint256[] calldata limbs,
    uint32 emailByteLen,
    externalEuint128 encSkShare,
    bytes calldata payload,
    bytes calldata inputProof
) external returns (uint256 index)
```

Add a message without a public message component.

**Access**: Registered users only

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `limbs` | `externalEuint256[]` | FHE-encrypted email split into 32-byte chunks (7 limbs for 224 bytes) |
| `emailByteLen` | `uint32` | Original email length before padding |
| `encSkShare` | `externalEuint128` | FHE-encrypted AES key share (128-bit) |
| `payload` | `bytes` | Encrypted message payload (AES-encrypted client-side) |
| `inputProof` | `bytes` | FHE input proof for encryption verification |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `index` | `uint256` | Index of the newly added message in `users[msg.sender].messages[]` |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | Caller has not registered |
| `"email len=0"` | `emailByteLen == 0` |
| `"email too long"` | `emailByteLen > MAX_EMAIL_BYTE_LEN` (224) |
| `"no limbs"` | `limbs.length == 0` |
| `"bad payload size"` | `payload.length == 0` |
| `"payload too long"` | `payload.length > MAX_PAYLOAD_BYTE_LEN` (10 KB) |
| `"limbs must match padded length"` | `limbs.length != 7` (for 224-byte padding) |

**Emits**:
- `MessageAdded(msg.sender, index)`

**Notes**:
- Email must be padded to exactly `MAX_EMAIL_BYTE_LEN` (224 bytes) before encryption to prevent length leakage.
- `emailByteLen` stores the original length for trimming padding during decryption.
- FHE limbs are granted to `msg.sender` via `FHE.allow()`.
- Computes and stores a Keccak256 hash of all inputs for deduplication.
- No reward attached. Use `addMessageWithReward()` for incentivized delivery.

---

#### addMessage(externalEuint256[] limbs, uint32 emailByteLen, externalEuint128 encSkShare, bytes payload, bytes inputProof, string publicMessage)

```solidity
function addMessage(
    externalEuint256[] calldata limbs,
    uint32 emailByteLen,
    externalEuint128 encSkShare,
    bytes calldata payload,
    bytes calldata inputProof,
    string calldata publicMessage
) external returns (uint256 index)
```

Add a message with an optional public message.

**Same as above with the addition of:**

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `publicMessage` | `string` | Plaintext message visible to all (e.g., "Dear loved ones, ...") |

**Notes**:
- `publicMessage` is stored in cleartext on-chain.
- Useful for personal notes, context, or instructions.
- Can be empty string.

---

### addMessageWithReward()

```solidity
function addMessageWithReward(
    externalEuint256[] calldata limbs,
    uint32 emailByteLen,
    externalEuint128 encSkShare,
    bytes calldata payload,
    bytes calldata inputProof,
    string calldata publicMessage,
    bytes32[] calldata recipientEmailHashes,
    bytes32 payloadContentHash
) external payable returns (uint256 index)
```

Add a message with an ETH reward for delivery proof via zk-email.

**Access**: Registered users only, with ETH payment

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `limbs` | `externalEuint256[]` | FHE-encrypted email (7 limbs) |
| `emailByteLen` | `uint32` | Original email length |
| `encSkShare` | `externalEuint128` | FHE-encrypted key share |
| `payload` | `bytes` | Encrypted payload |
| `inputProof` | `bytes` | FHE input proof |
| `publicMessage` | `string` | Plaintext public message |
| `recipientEmailHashes` | `bytes32[]` | Poseidon hashes of each recipient email (for multi-recipient support) |
| `payloadContentHash` | `bytes32` | Keccak256 hash of decrypted payload (for verification) |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `index` | `uint256` | Index of newly added message |

**Value Sent** (`msg.value`): ETH amount as reward (must be > 0)

**Reverts**:
| Error | Reason |
|-------|--------|
| `"must include reward"` | `msg.value == 0` |
| `"must have at least one recipient"` | `recipientEmailHashes.length == 0` |
| `"too many recipients"` | `recipientEmailHashes.length > 256` |
| (plus all reverts from `addMessage()`) | Email and payload validation |

**Emits**:
- `MessageAdded(msg.sender, index)`

**Notes**:
- Caller must send ETH via `msg.value` (payable function).
- `recipientEmailHashes` should be Poseidon hashes of recipient emails (computed off-chain).
- `payloadContentHash` is the Keccak256 hash of the *decrypted* payload (known only to the claimer after decryption).
- Reward is locked in contract until `claimReward()` is called (after all recipients proven).
- Max 256 recipients due to bitmap tracking (see `provenRecipientsBitmap`).

---

### messageCount()

```solidity
function messageCount(address user) external view returns (uint256)
```

Get the number of messages stored by a user.

**Access**: Public (view), user must be registered

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `uint256` | Length of `users[user].messages[]` array |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | User has not registered |

---

### editMessage()

```solidity
function editMessage(
    uint256 index,
    externalEuint256[] calldata limbs,
    uint32 emailByteLen,
    externalEuint128 encSkShare,
    bytes calldata payload,
    bytes calldata inputProof,
    string calldata publicMessage
) external
```

Edit an unclaimed, unrevoked message (owner only).

**Access**: Message owner only

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `index` | `uint256` | Message index in `users[msg.sender].messages[]` |
| `limbs` | `externalEuint256[]` | New FHE-encrypted email |
| `emailByteLen` | `uint32` | New email length |
| `encSkShare` | `externalEuint128` | New FHE-encrypted key share |
| `payload` | `bytes` | New encrypted payload |
| `inputProof` | `bytes` | FHE input proof |
| `publicMessage` | `string` | New public message |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | Caller has not registered |
| `"user is deceased"` | Caller is marked deceased |
| `"invalid index"` | `index >= users[msg.sender].messages.length` |
| `"cannot edit revoked message"` | Message is already revoked |
| `"cannot edit claimed message"` | Message has been claimed |
| (plus email/payload validation) | Same as `addMessage()` |

**Emits**:
- `MessageEdited(msg.sender, index)`

**Notes**:
- All message fields are replaced (no partial updates).
- Cannot edit after claim (claimer has FHE access to old data).
- Cannot edit revoked messages.
- Recomputes message hash (old hash marked invalid, new one marked valid).

---

### revokeMessage()

```solidity
function revokeMessage(uint256 index) external nonReentrant
```

Revoke an unclaimed message and refund any attached reward.

**Access**: Message owner only, nonReentrant

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `index` | `uint256` | Message index |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | Caller has not registered |
| `"user is deceased"` | Caller is deceased |
| `"invalid index"` | `index >= users[msg.sender].messages.length` |
| `"already revoked"` | Message is already revoked |
| `"cannot revoke claimed message"` | Message has been claimed |
| `"ETH transfer failed"` | Refund failed |

**Emits**:
- `MessageRevoked(msg.sender, index)`

**Notes**:
- Refunds any ETH reward attached to the message.
- Cannot revoke after claim.
- Sets `message.revoked = true`, preventing future claims.
- Nonreentrant to prevent double-refunds via callbacks.

---

### computeMessageHash()

```solidity
function computeMessageHash(
    externalEuint256[] calldata limbs,
    uint32 emailByteLen,
    externalEuint128 encSkShare,
    bytes calldata payload,
    string calldata publicMessage
) external pure returns (bytes32)
```

Compute the Keccak256 hash of message inputs without adding the message.

**Access**: Public (pure)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `limbs` | `externalEuint256[]` | Message limbs |
| `emailByteLen` | `uint32` | Email length |
| `encSkShare` | `externalEuint128` | Encrypted key share |
| `payload` | `bytes` | Message payload |
| `publicMessage` | `string` | Public message |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `bytes32` | Keccak256 hash of abi.encode(all inputs) |

**Reverts**: None

**Notes**:
- Useful for checking if a message with identical inputs already exists.
- Same hash computation as used internally in `addMessage()`.
- Pure function — no state changes.

---

## Message Claiming & Delivery

### claim()

```solidity
function claim(address user, uint256 index) external
```

Claim a message for delivery. Grants FHE decryption access to the claimer.

**Access**: Anyone, but user must be deceased

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | Deceased user address |
| `index` | `uint256` | Message index |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not deliverable"` | User is not deceased |
| `"invalid index"` | `index >= users[user].messages.length` |
| `"still exclusive for the notifier"` | Within 24 hours of marking deceased and caller is not notifier |
| `"message was revoked"` | Message was revoked by owner |
| `"already claimed"` | Message already claimed |

**Emits**:
- `Claimed(user, index, msg.sender)`

**Notes**:
- Notifier (who called `markDeceased()`) has exclusive claim access for 24 hours.
- After 24 hours, anyone can claim the same message.
- Grants FHE decryption access via `FHE.allow()` to `msg.sender` for both the email and key share.
- Once claimed, message cannot be edited or revoked.
- Only one claimer per message (first to claim wins).

---

### retrieve()

```solidity
function retrieve(address owner, uint256 index) external view returns (
    euint128 skShare,
    euint256[] memory encodedRecipientEmail,
    uint32 emailByteLen,
    bytes memory payload,
    string memory publicMessage,
    bytes32 hash
)
```

Retrieve message data. FHE handles are returned but can only be decrypted by authorized parties.

**Access**: Public (view), subject to authorization

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `owner` | `address` | Message owner address |
| `index` | `uint256` | Message index |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `skShare` | `euint128` | FHE-encrypted key share (decryptable only by owner or approved claimer) |
| `encodedRecipientEmail` | `euint256[]` | FHE-encrypted email limbs |
| `emailByteLen` | `uint32` | Original email length |
| `payload` | `bytes` | Encrypted payload (AES-encrypted client-side) |
| `publicMessage` | `string` | Plaintext public message |
| `hash` | `bytes32` | Keccak256 hash of original inputs |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"invalid index"` | `index >= users[owner].messages.length` |
| `"message was revoked"` | Message is revoked |
| `"owner not deceased"` | Non-owner trying to retrieve from alive user |
| `"message not claimed"` | Non-owner trying to retrieve before claim |
| `"not claimant"` | Non-owner, not the claimer |

**Access Rules**:
- Owner (`msg.sender == owner`) — can retrieve anytime
- Non-owner — must satisfy:
  1. Owner is deceased
  2. Message has been claimed
  3. Caller is the claimer

**Notes**:
- FHE-encrypted fields can only be decrypted if `FHE.allow()` permissions were granted via `claim()`.
- `payload` is plaintext on-chain (already encrypted client-side), so no permission check needed.
- Returns copies of encrypted data to memory (view function does not modify state).

---

## ZK-Email Proof & Delivery

### proveDelivery()

```solidity
function proveDelivery(
    address user,
    uint256 messageIndex,
    uint256 recipientIndex,
    ZkEmailProof calldata proof
) external
```

Submit a zk-email proof for one recipient. Can be called multiple times for multi-recipient messages.

**Access**: Message claimer only

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | Deceased user address |
| `messageIndex` | `uint256` | Message index |
| `recipientIndex` | `uint256` | Index within `message.recipientEmailHashes[]` (0-based) |
| `proof` | `ZkEmailProof` | Groth16 zk-email proof (pA, pB, pC, publicSignals) |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"user not deceased"` | User is not deceased |
| `"message not claimed"` | Message has not been claimed |
| `"not the claimer"` | Caller is not the message claimer |
| `"invalid recipient"` | `recipientIndex >= message.recipientEmailHashes.length` |
| `"already proven"` | Recipient already proven (bitmap bit already set) |
| `"invalid proof"` | Proof verification failed |
| `"verifier not configured"` | `zkEmailVerifier` address not set by owner |

**Emits**:
- `DeliveryProven(user, messageIndex, recipientIndex, msg.sender)`

**Proof Verification Logic**:
1. Check `proof.publicSignals[0]` (Poseidon email hash) matches `message.recipientEmailHashes[recipientIndex]`
2. Check `proof.publicSignals[1]` (DKIM key hash) is in trusted set
3. Check `proof.publicSignals[2]` (content hash) matches `message.payloadContentHash`
4. Verify Groth16 proof via `zkEmailVerifier.verifyProof()`

**Notes**:
- Claimer proves that an email was actually sent to the intended recipient, from a trusted domain, with the correct content.
- Bitmap tracking allows up to 256 recipients per message.
- For single-recipient messages, this function must be called exactly once before `claimReward()`.
- See [proof-structure.md](proof-structure.md) for circuit details.

---

### claimReward()

```solidity
function claimReward(address user, uint256 messageIndex) external nonReentrant
```

Claim ETH reward after all recipients have been proven via `proveDelivery()`.

**Access**: Message claimer only, nonReentrant

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | Deceased user address |
| `messageIndex` | `uint256` | Message index |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"user not deceased"` | User is not deceased |
| `"invalid index"` | `messageIndex >= users[user].messages.length` |
| `"message not claimed"` | Message has not been claimed |
| `"not the claimer"` | Caller is not the message claimer |
| `"no reward"` | Message has no reward attached (reward == 0) |
| `"not all recipients proven"` | Not all recipients have submitted proofs |
| `"already claimed"` | Reward already claimed (double-claim protection) |
| `"ETH transfer failed"` | ETH transfer to claimer failed |

**Emits**:
- `RewardClaimed(user, messageIndex, msg.sender, rewardAmount)`

**Notes**:
- Requires all recipients to have submitted proofs (bitmap fully populated).
- For single-recipient messages, 1 proof required.
- For N-recipient messages, N proofs required (one per `proveDelivery()` call).
- Double-claim protection via hash: `keccak256(abi.encode(user, messageIndex))`.
- Transfers ETH to caller via `call{}` (low-level, not `transfer()`).
- Nonreentrant to prevent reentrancy attacks during ETH transfer.

---

### getMessageRewardInfo()

```solidity
function getMessageRewardInfo(address user, uint256 messageIndex) external view returns (
    uint256 reward,
    uint256 numRecipients,
    uint256 provenRecipientsBitmap,
    bytes32 payloadContentHash
)
```

Get reward amount, recipient count, proof bitmap, and payload hash for a message.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |
| `messageIndex` | `uint256` | Message index |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `reward` | `uint256` | ETH reward amount (0 if no reward) |
| `numRecipients` | `uint256` | Number of recipient hashes |
| `provenRecipientsBitmap` | `uint256` | Bitmap: bit i set = recipient i proven |
| `payloadContentHash` | `bytes32` | Keccak256 hash of decrypted payload |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"invalid index"` | `messageIndex >= users[user].messages.length` |

**Notes**:
- Useful for monitoring delivery progress.
- Bitmap can be decoded: `(bitmap & (1 << i)) != 0` means recipient i proven.

---

### getRecipientEmailHash()

```solidity
function getRecipientEmailHash(address user, uint256 messageIndex, uint256 recipientIndex) external view returns (bytes32)
```

Get the Poseidon hash of a specific recipient email.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |
| `messageIndex` | `uint256` | Message index |
| `recipientIndex` | `uint256` | Recipient index (0-based) |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `bytes32` | Poseidon hash of the recipient email |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"invalid index"` | `messageIndex >= users[user].messages.length` |
| `"invalid recipient"` | `recipientIndex >= message.recipientEmailHashes.length` |

---

### calculateReward()

```solidity
function calculateReward(address user, uint256 messageIndex) public view returns (uint256)
```

Calculate the reward for a message based on payload size and deposit.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |
| `messageIndex` | `uint256` | Message index |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `uint256` | Calculated reward amount in Wei |

**Reverts**:
| Error | Reason |
|-------|--------|
| `"invalid index"` | `messageIndex >= users[user].messages.length` |

**Calculation**:
```
payloadSizeKB = ceil(payload.length / 1024)
reward = BASE_REWARD + (payloadSizeKB * REWARD_PER_KB)
if reward > user.deposit:
    reward = user.deposit  // Cap at deposit
```

**Notes**:
- Base reward is 0.01 ETH.
- Additional 0.005 ETH per KB of payload.
- Capped at user's deposit balance.
- Used as a reference; actual reward comes from `addMessageWithReward()`.

---

## Council Management

### addCouncilMember()

```solidity
function addCouncilMember(address member) external
```

Add a council member (trusted person who can vote on liveness during grace period).

**Access**: Registered users only

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `member` | `address` | Address to add as council member |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | Caller has not registered |
| `"invalid member"` | `member == address(0)` |
| `"cannot add self"` | `member == msg.sender` |
| `"already a member"` | `member` already in council |
| `"council full"` | Council size >= MAX_COUNCIL_SIZE (20) |

**Emits**:
- `CouncilMemberAdded(msg.sender, member)`

**Notes**:
- Each user has a separate council (up to 20 members).
- No stake or permission check — council members are trusted by the user.
- Council members can only vote during grace period.

---

### removeCouncilMember()

```solidity
function removeCouncilMember(address member) external
```

Remove a council member.

**Access**: User only (caller is the user whose council it is)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `member` | `address` | Address to remove |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not a member"` | `member` not in caller's council |
| `"member not found"` | Member not found in array (should not happen) |

**Emits**:
- `CouncilMemberRemoved(msg.sender, member)`

**Notes**:
- Clears any active vote by the member.
- Removes from reverse index (`memberToUsers`).
- Swaps with last element for efficient removal.

---

### voteOnStatus()

```solidity
function voteOnStatus(address user, bool voteAlive) external
```

Cast a vote on whether a user is alive or deceased during grace period.

**Access**: Council members only

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User to vote on |
| `voteAlive` | `bool` | `true` = vote alive, `false` = vote deceased |

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | User has not registered |
| `"not a council member"` | Caller is not in `user`'s council |
| `"user already deceased"` | User is already marked deceased |
| `"status already finalized"` | User has `finalAlive` status |
| `"not in grace period"` | Before check-in expires (`now <= lastCheckIn + checkInPeriod`) |
| `"grace period ended"` | After grace period expires (`now > lastCheckIn + checkInPeriod + gracePeriod`) |
| `"vote already decided"` | Majority already reached |
| `"already voted"` | Caller already voted |

**Emits**:
- `GraceVoteCast(user, msg.sender, voteAlive)` — always emitted
- `StatusDecided(user, isAlive)` — if majority reached
- `Ping(user, block.timestamp)` — if voted alive and majority reached
- `Deceased(user, block.timestamp, msg.sender)` — if voted dead and majority reached

**Majority Logic**:
- Majority = `(councilSize / 2) + 1`
- If alive votes reach majority:
  - Set `user.finalAlive = true`
  - Reset `user.lastCheckIn = block.timestamp`
  - User returns to Alive status
- If dead votes reach majority:
  - Set `user.deceased = true`
  - User becomes immediately claimable

**Notes**:
- Voting is per-member (each member votes once).
- Once majority reached, voting closes (cannot change result).
- Council can override timeout for users believed to be alive due to unavoidable circumstances.

---

### getUsersForCouncilMember()

```solidity
function getUsersForCouncilMember(address member) external view returns (address[] memory userAddresses)
```

Get all users that a council member is serving on.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `member` | `address` | Council member address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `userAddresses` | `address[]` | Array of user addresses |

**Reverts**: None

---

### getCouncilMembers()

```solidity
function getCouncilMembers(address user) external view returns (
    address[] memory members,
    uint64[] memory joinedAts
)
```

Get all council members and their join timestamps for a user.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `members` | `address[]` | Array of council member addresses |
| `joinedAts` | `uint64[]` | Array of join timestamps |

**Reverts**: None

**Notes**:
- Arrays are parallel: `members[i]` joined at `joinedAts[i]`.

---

### getGraceVoteStatus()

```solidity
function getGraceVoteStatus(address user) external view returns (
    uint256 aliveVotes,
    uint256 deadVotes,
    bool decided,
    bool decisionAlive
)
```

Get the grace period vote status for a user.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `aliveVotes` | `uint256` | Number of alive votes cast |
| `deadVotes` | `uint256` | Number of dead votes cast |
| `decided` | `bool` | Whether a majority has been reached |
| `decisionAlive` | `bool` | The decision if decided (`true` = alive) |

**Reverts**: None

**Notes**:
- If `decided == false`, `decisionAlive` is meaningless.

---

### getGraceVote()

```solidity
function getGraceVote(address user, address member) external view returns (bool hasVoted, bool votedAlive)
```

Get how a specific council member voted on a user.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |
| `member` | `address` | Council member address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `hasVoted` | `bool` | Whether the member has voted |
| `votedAlive` | `bool` | How they voted (only valid if `hasVoted == true`) |

**Reverts**: None

**Notes**:
- If `hasVoted == false`, `votedAlive` is meaningless.

---

## Deposits & Rewards

### deposit()

```solidity
function deposit() external payable
```

Deposit ETH to fund delivery costs (used to cap rewards via `calculateReward()`).

**Access**: Registered users only, payable

**Parameters**: None (ETH sent via `msg.value`)

**Value Sent**: ETH amount (must be > 0)

**Returns**: None

**Reverts**:
| Error | Reason |
|-------|--------|
| `"not registered"` | Caller has not registered |
| `"must deposit something"` | `msg.value == 0` |

**Emits**:
- `DepositAdded(msg.sender, msg.value)`

**Notes**:
- Deposit accumulates (multiple calls add to the balance).
- Used as a cap for reward calculation.
- Not required for basic message operations, only for reward-based delivery.

---

### getDeposit()

```solidity
function getDeposit(address user) external view returns (uint256)
```

Get a user's ETH deposit balance.

**Access**: Public (view)

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `user` | `address` | User address |

**Returns**:
| Name | Type | Description |
|------|------|-------------|
| `` | `uint256` | Deposit balance in Wei |

**Reverts**: None

**Notes**:
- Returns 0 if user has no deposit or is not registered.

---

## Admin Functions

### setZkEmailVerifier()

```solidity
function setZkEmailVerifier(address _verifier) external
```

Set the Groth16 verifier contract address (owner only). Required for `proveDelivery()` to work.

**Access**: Owner only

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `_verifier` | `address` | Address of Groth16 verifier contract |

**Returns**: None

**Reverts**: None (reverts if not owner, from `onlyOwner` modifier)

**Emits**:
- `ZkEmailVerifierSet(_verifier)`

**Notes**:
- Verifier must implement `IGroth16Verifier.verifyProof()`.
- If not set, `proveDelivery()` will revert with `"verifier not configured"`.

---

### setTrustedDkimKey()

```solidity
function setTrustedDkimKey(bytes32 domain, uint256 pubkeyHash, bool trusted) external
```

Set a DKIM public key hash as trusted or untrusted (owner only).

**Access**: Owner only

**Parameters**:
| Name | Type | Description |
|------|------|-------------|
| `domain` | `bytes32` | Domain hash (use `bytes32(0)` for global trust, or domain-specific hash) |
| `pubkeyHash` | `uint256` | DKIM public key hash (RSA-2048) |
| `trusted` | `bool` | Whether to trust this key |

**Returns**: None

**Reverts**: None

**Emits**:
- `DkimKeyUpdated(domain, pubkeyHash, trusted)`

**Notes**:
- Currently uses `bytes32(0)` as global domain.
- Future versions may support domain-specific keys.
- DKIM public key hashes are checked during `proveDelivery()`.

---

## Events

All events listed with their parameters and descriptions.

### UserRegistered

```solidity
event UserRegistered(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn)
```

Emitted when a new user registers.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | New user's address |
| No | `checkInPeriod` | `uint64` | Check-in period in seconds |
| No | `gracePeriod` | `uint64` | Grace period in seconds |
| No | `registeredOn` | `uint64` | Registration timestamp |

---

### UserUpdated

```solidity
event UserUpdated(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn)
```

Emitted when an existing user updates their settings (name, periods).

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | User's address |
| No | `checkInPeriod` | `uint64` | New check-in period |
| No | `gracePeriod` | `uint64` | New grace period |
| No | `registeredOn` | `uint64` | Original registration timestamp (unchanged) |

---

### Ping

```solidity
event Ping(address indexed user, uint64 when)
```

Emitted when a user checks in via `ping()`, `register()`, or after council votes alive.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | User's address |
| No | `when` | `uint64` | Check-in timestamp |

---

### Deceased

```solidity
event Deceased(address indexed user, uint64 when, address indexed notifier)
```

Emitted when a user is marked deceased via `markDeceased()` or council vote.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | User's address |
| No | `when` | `uint64` | Timestamp of marking |
| Yes | `notifier` | `address` | Address that marked the user deceased |

---

### MessageAdded

```solidity
event MessageAdded(address indexed user, uint256 indexed index)
```

Emitted when a message is added via `addMessage()` or `addMessageWithReward()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | Message owner |
| Yes | `index` | `uint256` | Message index in `users[user].messages[]` |

---

### MessageEdited

```solidity
event MessageEdited(address indexed user, uint256 indexed index)
```

Emitted when a message is edited via `editMessage()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | Message owner |
| Yes | `index` | `uint256` | Message index |

---

### MessageRevoked

```solidity
event MessageRevoked(address indexed user, uint256 indexed index)
```

Emitted when a message is revoked via `revokeMessage()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | Message owner |
| Yes | `index` | `uint256` | Message index |

---

### Claimed

```solidity
event Claimed(address indexed user, uint256 indexed index, address indexed claimer)
```

Emitted when a message is claimed via `claim()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | Deceased user's address |
| Yes | `index` | `uint256` | Message index |
| Yes | `claimer` | `address` | Address claiming the message |

---

### CouncilMemberAdded

```solidity
event CouncilMemberAdded(address indexed user, address indexed member)
```

Emitted when a council member is added via `addCouncilMember()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | User adding the member |
| Yes | `member` | `address` | New council member address |

---

### CouncilMemberRemoved

```solidity
event CouncilMemberRemoved(address indexed user, address indexed member)
```

Emitted when a council member is removed via `removeCouncilMember()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | User removing the member |
| Yes | `member` | `address` | Removed council member address |

---

### GraceVoteCast

```solidity
event GraceVoteCast(address indexed user, address indexed voter, bool votedAlive)
```

Emitted when a council member votes during grace period via `voteOnStatus()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | User being voted on |
| Yes | `voter` | `address` | Council member voting |
| No | `votedAlive` | `bool` | How they voted (`true` = alive) |

---

### StatusDecided

```solidity
event StatusDecided(address indexed user, bool isAlive)
```

Emitted when council voting reaches a majority decision.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | User whose status was decided |
| No | `isAlive` | `bool` | Decision result (`true` = alive, `false` = deceased) |

---

### DepositAdded

```solidity
event DepositAdded(address indexed user, uint256 amount)
```

Emitted when a user deposits ETH via `deposit()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | User depositing |
| No | `amount` | `uint256` | ETH amount in Wei |

---

### DeliveryProven

```solidity
event DeliveryProven(address indexed user, uint256 indexed messageIndex, uint256 recipientIndex, address claimer)
```

Emitted when a delivery proof is verified via `proveDelivery()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | Deceased user |
| Yes | `messageIndex` | `uint256` | Message index |
| No | `recipientIndex` | `uint256` | Recipient index proven |
| No | `claimer` | `address` | Claimer submitting the proof |

---

### RewardClaimed

```solidity
event RewardClaimed(address indexed user, uint256 indexed messageIndex, address indexed claimer, uint256 amount)
```

Emitted when a claimer claims a reward via `claimReward()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| Yes | `user` | `address` | Deceased user |
| Yes | `messageIndex` | `uint256` | Message index |
| Yes | `claimer` | `address` | Claimer receiving reward |
| No | `amount` | `uint256` | ETH amount in Wei |

---

### ZkEmailVerifierSet

```solidity
event ZkEmailVerifierSet(address verifier)
```

Emitted when the zk-email Groth16 verifier is set via `setZkEmailVerifier()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| No | `verifier` | `address` | Verifier contract address |

---

### DkimKeyUpdated

```solidity
event DkimKeyUpdated(bytes32 domain, uint256 pubkeyHash, bool trusted)
```

Emitted when a DKIM key trust status is updated via `setTrustedDkimKey()`.

| Indexed | Name | Type | Description |
|---------|------|------|-------------|
| No | `domain` | `bytes32` | Domain hash |
| No | `pubkeyHash` | `uint256` | DKIM public key hash |
| No | `trusted` | `bool` | New trust status |

---

## Error Reference

Complete table of all error strings and their causes.

| Error String | Function(s) | When Thrown |
|--------------|-------------|-------------|
| `"checkInPeriod too short"` | `register()` overloads | `checkInPeriod < 1 days` |
| `"gracePeriod too short"` | `register()` overloads | `gracePeriod < 1 days` |
| `"name too long"` | `register()`, `setName()` | `bytes(name).length > 100` |
| `"user is deceased"` | `register()`, `editMessage()`, `revokeMessage()` | User marked deceased |
| `"check-in period expired"` | `register()` (existing user) | Attempting update after check-in window |
| `"not registered"` | Multiple | User has not registered (`lastCheckIn == 0`) |
| `"user marked deceased"` | `ping()` | User is deceased |
| `"user already deceased"` | `markDeceased()`, `voteOnStatus()` | User already deceased |
| `"user voted alive by council"` | `markDeceased()` | User has `finalAlive` status |
| `"not timed out"` | `markDeceased()` | Timeout deadline not reached |
| `"email len=0"` | `addMessage()`, `editMessage()` | `emailByteLen == 0` |
| `"email too long"` | `addMessage()`, `editMessage()` | `emailByteLen > 224` |
| `"no limbs"` | `addMessage()`, `editMessage()` | `limbs.length == 0` |
| `"bad payload size"` | `addMessage()`, `editMessage()` | `payload.length == 0` |
| `"payload too long"` | `addMessage()`, `editMessage()` | `payload.length > 10240` |
| `"limbs must match padded length"` | `addMessage()`, `editMessage()` | `limbs.length != 7` |
| `"must include reward"` | `addMessageWithReward()` | `msg.value == 0` |
| `"must have at least one recipient"` | `addMessageWithReward()` | `recipientEmailHashes.length == 0` |
| `"too many recipients"` | `addMessageWithReward()` | `recipientEmailHashes.length > 256` |
| `"invalid index"` | Multiple | Message index out of bounds |
| `"already revoked"` | `revokeMessage()` | Message already revoked |
| `"cannot revoke claimed message"` | `revokeMessage()` | Message already claimed |
| `"cannot edit revoked message"` | `editMessage()` | Message already revoked |
| `"cannot edit claimed message"` | `editMessage()` | Message already claimed |
| `"not deliverable"` | `claim()` | User not deceased |
| `"still exclusive for the notifier"` | `claim()` | Within 24h of marking and caller not notifier |
| `"message was revoked"` | `claim()`, `retrieve()` | Message revoked |
| `"already claimed"` | `claim()` | Message already claimed |
| `"owner not deceased"` | `retrieve()` | Non-owner retrieving for alive user |
| `"message not claimed"` | `retrieve()`, `proveDelivery()`, `claimReward()` | Message not claimed |
| `"not claimant"` | `retrieve()` | Non-owner not the claimer |
| `"not the claimer"` | `proveDelivery()`, `claimReward()` | Caller not the claimer |
| `"user not deceased"` | `proveDelivery()`, `claimReward()` | User not deceased |
| `"invalid recipient"` | `proveDelivery()`, `getRecipientEmailHash()` | Recipient index out of bounds |
| `"already proven"` | `proveDelivery()` | Recipient already proven (bitmap bit set) |
| `"invalid proof"` | `proveDelivery()` | ZK proof verification failed |
| `"verifier not configured"` | `_verifyZkEmailProof()` (internal) | `zkEmailVerifier == address(0)` |
| `"no reward"` | `claimReward()` | Message has no reward |
| `"not all recipients proven"` | `claimReward()` | Bitmap incomplete |
| `"already claimed"` (reward) | `claimReward()` | Reward already claimed (double-claim) |
| `"ETH transfer failed"` | `revokeMessage()`, `claimReward()` | ETH transfer reverted |
| `"must deposit something"` | `deposit()` | `msg.value == 0` |
| `"invalid member"` | `addCouncilMember()` | `member == address(0)` |
| `"cannot add self"` | `addCouncilMember()` | `member == msg.sender` |
| `"already a member"` | `addCouncilMember()` | Member already in council |
| `"council full"` | `addCouncilMember()` | `councils[user].length >= 20` |
| `"not a member"` | `removeCouncilMember()` | Member not in council |
| `"member not found"` | `removeCouncilMember()` | Member not found in array |
| `"not a council member"` | `voteOnStatus()` | Caller not in user's council |
| `"status already finalized"` | `voteOnStatus()` | User has `finalAlive` status |
| `"not in grace period"` | `voteOnStatus()` | Before grace period starts |
| `"grace period ended"` | `voteOnStatus()` | After grace period expires |
| `"vote already decided"` | `voteOnStatus()` | Majority already reached |
| `"already voted"` | `voteOnStatus()` | Member already voted |

---

## Related Documentation

- **[Protocol Specification](protocol.md)** — High-level protocol design and user flow
- **[Delivery Proof Architecture](proof-structure.md)** — ZK-email proof format, circuit details, and verification
- **[Building a Client](building-a-client.md)** — Step-by-step guide with TypeScript examples
- **[README](../README.md)** — Project overview, key sharing scheme, and features
- **[Zama FHEVM Docs](https://docs.zama.ai/fhevm)** — FHE runtime documentation
- **[zk.email](https://docs.zk.email/)** — ZK email proof specification

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2025-02-24 | Initial contract deployment on Sepolia |
| 2.0 | Pending | FHEVM v0.9 upgrade (initiated via `initializeV2()`) |

---

## License

BSD 3-Clause Clear License
