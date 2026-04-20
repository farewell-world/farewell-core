# CLAUDE.md - Farewell Core (Smart Contracts)

## Project Overview

Farewell Core contains the smart contracts for the Farewell protocol - a decentralized application for posthumous
encrypted messages using Fully Homomorphic Encryption (FHE) on Ethereum.

**Status**: Beta on Sepolia testnet.

**Live Demo**: https://farewell.world

**License**: BSD 3-Clause Clear

## Repository Structure

```
farewell-core/
├── contracts/
│   ├── Farewell.sol              # Main contract with all protocol logic
│   ├── FarewellStorage.sol       # Shared storage layout (structs, mappings, events)
│   ├── FarewellExtension.sol     # Council, voting, rewards, ZK proofs (delegatecall)
│   └── test/
│       ├── FarewellTestMode.sol  # Test-only contract for arbitrary user state setup
│       ├── MockERC20.sol         # Mock ERC-20 for reward testing
│       └── MockGroth16Verifier.sol # Always-true verifier for ZK proof testing
├── deploy/                        # Deployment scripts
├── docs/
│   ├── protocol.md               # Full protocol specification
│   ├── contract-api.md           # Complete API reference
│   ├── building-a-client.md      # Guide for building alternative clients
│   ├── proof-structure.md        # Delivery proof architecture & zk-email spec
│   ├── discoverability.md        # Opt-in discoverable users list
│   └── council-system.md         # Council voting system
├── test/
│   ├── Farewell.ts               # Core contract tests
│   └── FarewellTestMode.ts       # Test mode scenario tests
├── hardhat.config.ts
├── package.json
└── README.md
```

## Quick Start

```bash
npm install
npx hardhat compile
npx hardhat test
npx hardhat deploy --network <network>
```

## Key Technologies

- **Smart Contracts**: Solidity 0.8.27
- **FHE**: Zama FHEVM (fhevmjs v0.9)
- **Framework**: Hardhat
- **Upgradeable**: OpenZeppelin UUPS proxy pattern
- **ZK Proofs**: Groth16 verifier interface for zk-email

## Contract Architecture

### Main Contract: `Farewell.sol`

The contract is upgradeable using UUPS pattern and manages:

1. **User Lifecycle**
   - Registration with configurable check-in and grace periods
   - Periodic ping to prove liveness
   - Deceased marking after timeout
   - Council voting during grace period (plaintext or FHE-encrypted modes)

2. **Encrypted Messages**
   - FHE-encrypted recipient emails (split into 32-byte limbs)
   - FHE-encrypted key shares (128-bit)
   - AES-encrypted payloads (stored as bytes)
   - Optional public messages (cleartext)

3. **Claiming and Delivery**
   - 24-hour exclusivity window for notifier
   - FHE.allow() grants decryption access to claimer
   - Message retrieval with encrypted handles

4. **ZK-Email Rewards**
   - Per-message ETH rewards
   - Poseidon hash commitments for recipient verification
   - Groth16 proof verification for delivery
   - Multi-recipient support with bitmap tracking

### Key Constants

```solidity
uint64 constant DEFAULT_CHECKIN = 30 days;
uint64 constant DEFAULT_GRACE = 7 days;
uint32 constant MAX_NAME_BYTE_LEN = 128;
uint32 constant MAX_EMAIL_BYTE_LEN = 224;
uint32 constant MAX_PAYLOAD_BYTE_LEN = 10240; // 10KB
uint256 constant BASE_REWARD = 0.01 ether;
uint256 constant REWARD_PER_KB = 0.005 ether;
```

### User Status Enum

```solidity
enum UserStatus {
  Alive, // Within check-in period
  Grace, // Missed check-in, within grace period
  Deceased, // Finalized deceased or timeout
  FinalAlive // Council voted alive - cannot be marked deceased
}
```

## Contract Functions

### User Lifecycle

- `register(nameLimbs, nameByteLen, nameInputProof, checkInPeriod, gracePeriod)` - Register with encrypted name and custom periods
- `register(nameLimbs, nameByteLen, nameInputProof)` - Register with encrypted name and defaults
- `ping()` - Reset check-in timer
- `markDeceased(user)` - Mark user as deceased after timeout
- `getUserState(user)` - Get current status and grace time remaining

### Messages

- `addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, publicMessage)` - Add encrypted message
- `addMessageWithReward(...)` - Add message with ETH reward for delivery verification
- `editMessage(index, ...)` - Edit existing message (owner only, not claimed)
- `revokeMessage(index)` - Revoke message (owner only, not claimed)
- `messageCount(user)` - Get number of messages for user

### Claiming & Delivery

- `claim(user, index)` - Claim a message (grants FHE decryption access)
- `retrieve(owner, index)` - Retrieve encrypted message data

### ZK-Email Verification

- `proveDelivery(user, messageIndex, recipientIndex, proof)` - Submit delivery proof
- `claimReward(user, messageIndex)` - Claim reward after all proofs
- `getMessageRewardInfo(user, index)` - Get reward and proof status

### Council

- `addCouncilMember(member)` - Add trusted council member
- `removeCouncilMember(member)` - Remove council member
- `setEncryptedVoting(enabled)` - Toggle encrypted voting mode
- `voteOnStatus(user, voteAlive)` - Vote during grace period (plaintext mode)
- `voteOnStatusEncrypted(user, encVote, inputProof)` - Vote during grace period (encrypted mode)
- `requestVoteDecryption(user)` - Manually request decryption of encrypted vote result
- `resolveEncryptedVote(user, decryptedResult, decryptionProof)` - Resolve encrypted vote with KMS proof
- `getCouncilMembers(user)` - Get council member list
- `getEncryptedGraceVoteStatus(user)` - Get encrypted vote status

### Admin (Owner Only)

- `setZkEmailVerifier(address)` - Set Groth16 verifier contract
- `setTrustedDkimKey(domain, pubkeyHash, trusted)` - Manage trusted DKIM keys

## Events

```solidity
event UserRegistered(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn);
event UserUpdated(address indexed user, uint64 checkInPeriod, uint64 gracePeriod, uint64 registeredOn);
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
event DeliveryProven(address indexed user, uint256 indexed messageIndex, uint256 recipientIndex, address claimer);
event RewardClaimed(address indexed user, uint256 indexed messageIndex, address indexed claimer, uint256 amount);
event ZkEmailVerifierSet(address verifier);
event DkimKeyUpdated(bytes32 domain, uint256 pubkeyHash, bool trusted);
event DiscoverabilityChanged(address indexed user, bool discoverable);
event EncryptedGraceVoteCast(address indexed user, address indexed voter);
event VoteDecryptionRequested(address indexed user);
event EncryptedVoteResolved(address indexed user, uint8 result);
```

## FHE Integration

The contract uses Zama's FHEVM for encrypted data:

- **Encrypted Strings**: Emails are padded to MAX_EMAIL_BYTE_LEN and split into euint256 limbs
- **Encrypted Integers**: Key shares stored as euint128
- **Encrypted Council Votes**: `euint8` values (1=alive, 2=dead) with homomorphic tallying via `FHE.eq`, `FHE.select`, `FHE.add`, `FHE.ge`; async decryption via `FHE.makePubliclyDecryptable` and `FHE.checkSignatures`
- **Access Control**: `FHE.allow()` grants decryption access to specific addresses
- **Coprocessor**: Uses ZamaConfig for coprocessor configuration

## Security Considerations

### Known Limitations

1. **No Recovery**: Users marked deceased cannot be recovered (except via council vote before finalization)
2. **FHE Permissions**: Once `FHE.allow()` is called, it cannot be revoked
3. **Timestamp Manipulation**: Block timestamps can be manipulated ~15 seconds
4. **ZK Verifier Configuration**: Current beta implementation requires the verifier contract to be set by the owner

## Development Guidelines

### Code Style

- Use OpenZeppelin patterns for upgradeability
- Prefer `unchecked` blocks for gas optimization where safe
- Use `storage` pointers to avoid unnecessary copies
- Follow Solidity naming conventions

### Testing

```bash
npx hardhat test                              # Run all tests
npx hardhat test test/FarewellTestMode.ts     # Run test mode scenario tests only
npx hardhat test --grep "register"            # Run specific tests
npx hardhat coverage                          # Generate coverage report
```

### Test Mode (`FarewellTestMode.sol`)

**WARNING: Sepolia / Hardhat only. NEVER deploy to mainnet.**

`FarewellTestMode` inherits from `Farewell` and adds `onlyOwner` functions that directly write to storage, allowing users to be placed in any lifecycle state without waiting for real time to pass. The constructor hard-reverts on any chain that is not Sepolia (11155111) or Hardhat (31337).

**Functions:**
- `setupTestUser(user, checkInPeriod, gracePeriod, backdateSeconds)` — Register a user with backdated `lastCheckIn`. Use `backdateSeconds` to control state: 0 = alive, `checkIn + grace/2` = in grace, `checkIn + grace + buffer` = past grace.
- `setupTestCouncil(user, members[])` — Add council members bypassing grace-period freeze.
- `forceMarkDeceased(user, notifier)` — Set `deceased=true` without time checks.
- `forceSetFinalAlive(user)` — Set `finalAlive=true` without voting.

**Pre-configured test users** (in `test/FarewellTestMode.ts`):

| Signer | Name | State | Purpose |
|--------|------|-------|---------|
| [1] | Alice | Past grace, not marked | Test `markDeceased` eligibility |
| [2] | Bob | In grace, 3 council | Council saves (votes alive → FinalAlive) |
| [3] | Charlie | In grace, 3 council | Council kills (votes dead → Deceased) |
| [4] | Dave | Already deceased | Test deceased restrictions |
| [5] | Elias | Alive | Test normal alive operations |
| [6] | Fiona | In grace, no council | Test raw grace state and expiry |

**Deployment:**
```bash
npx hardhat deploy --tags FarewellTestMode --network sepolia
```
The deploy script (`deploy/06_deploy_testmode.ts`) skips mainnet automatically. The main Farewell contract is deployed via `deploy/07_deploy_farewell_v5.ts`.

### Deployment

```bash
npx hardhat deploy --network sepolia
npx hardhat verify --network sepolia <address>
```

### Upgrading (UUPS Proxy)

The contract uses OpenZeppelin's UUPS proxy pattern. The upgrade workflow:

```bash
npx hardhat deploy --network sepolia
```

**CRITICAL: `.openzeppelin/sepolia.json` must always be committed.** This manifest tracks proxy-to-implementation mappings and storage layouts. Without it, `upgrades.upgradeProxy()` refuses to run — and more importantly, it cannot validate storage layout compatibility between old and new implementations. A bad storage layout change on mainnet would silently corrupt all user data with no recovery path.

- **Never delete or gitignore** `.openzeppelin/*.json` files
- **Always commit** the updated manifest after any upgrade
- If the manifest is ever lost, recover it with `upgrades.forceImport()` using the **current** contract factory against the live proxy, **before** making any code changes. Then commit immediately. See the `forceImport` docs: if you pass a factory with new bytecode, it registers the new code as "current" and `upgradeProxy` will no-op.

## Cross-Project Compatibility

**IMPORTANT**: Changes to the contract interface affect both the Farewell UI and farewell-claimer:

1. **Farewell UI** ([farewell.world](https://farewell.world)) — generates ABIs from this contract via `genabi`. If you
   change function signatures, events, or structs, the UI's ABI must be regenerated.
2. **farewell-claimer** ([repo](https://github.com/farewell-world/farewell-claimer)) — parses claim package JSON files
   that contain data from `retrieve()`. If you change the retrieve return format or message struct fields, update the
   claimer's `_load_claim_package()` accordingly.
3. The claim package JSON format uses fields: `recipients`, `skShare`, `encryptedPayload`, `contentHash` — these map to
   contract data returned by `retrieve()`.

## Documentation

| Document                                               | Description                                                                             |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| [docs/protocol.md](docs/protocol.md)                   | Full protocol specification — lifecycle, encryption, key sharing, FHE, council, rewards |
| [docs/contract-api.md](docs/contract-api.md)           | Complete API reference — every function, event, struct, constant, and error             |
| [docs/building-a-client.md](docs/building-a-client.md) | Guide with TypeScript examples for building alternative clients                         |
| [docs/proof-structure.md](docs/proof-structure.md)     | Delivery proof architecture — zk-email format, Groth16 verification, data structures    |
| [docs/discoverability.md](docs/discoverability.md)     | Opt-in discoverable users list — claimer workflow, privacy considerations                |
| [docs/council-system.md](docs/council-system.md)       | Council voting system — plaintext and FHE-encrypted modes, async decryption, security    |

## Related Projects

- **Farewell UI**: https://farewell.world
- **Farewell Claimer**: https://github.com/farewell-world/farewell-claimer
- **Farewell Decrypter**: https://github.com/farewell-world/farewell-decrypter
- **Zama FHEVM**: https://docs.zama.ai/fhevm

## Git Guidelines

- Use conventional commit messages (feat:, fix:, docs:, refactor:, etc.)
- Keep commits focused on a single logical change

## Maintenance Instructions

**IMPORTANT**: When making changes to this codebase:

1. **Update this CLAUDE.md** if contract interfaces, events, or architecture change
2. **Update README.md** if user-facing documentation changes
3. **Regenerate ABI** in farewell UI repo: `npm run genabi`
4. **Run tests** before committing: `npx hardhat test`
5. **Check gas costs** for new functions: `npx hardhat test --reporter gas`
6. **Keep documentation in sync** with code changes:
   - When adding/changing/removing contract functions, events, or constants → update `docs/contract-api.md`
   - When changing protocol behavior (lifecycle, encryption, claiming, rewards) → update `docs/protocol.md`
   - When changing function signatures or FHE encryption patterns → update `docs/building-a-client.md`
   - When changing proof verification or delivery flow → update `docs/proof-structure.md`
   - When changing deployed addresses → update `README.md`, `docs/contract-api.md`, and `docs/building-a-client.md`

Any AI agent working on this repository should ensure documentation stays synchronized with code changes.
