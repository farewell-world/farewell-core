# CLAUDE.md - Farewell Core (Smart Contracts)

## Project Overview

Farewell Core contains the smart contracts for the Farewell protocol - a decentralized application for posthumous encrypted messages using Fully Homomorphic Encryption (FHE) on Ethereum.

**Status**: Proof-of-concept deployed on Sepolia testnet. Not production-ready.

**Live Demo**: https://farewell.world

**License**: BSD 3-Clause Clear

## Repository Structure

```
farewell-core/
├── contracts/
│   └── Farewell.sol          # Main contract with all protocol logic
├── deploy/                    # Deployment scripts
├── docs/
│   └── proof-structure.md    # Delivery proof architecture & verification spec
├── test/                      # Hardhat tests
├── hardhat.config.ts          # Hardhat configuration
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
   - Council voting during grace period

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
uint32 constant MAX_EMAIL_BYTE_LEN = 224;
uint32 constant MAX_PAYLOAD_BYTE_LEN = 10240; // 10KB
uint256 constant BASE_REWARD = 0.01 ether;
uint256 constant REWARD_PER_KB = 0.005 ether;
```

### User Status Enum

```solidity
enum UserStatus {
    Alive,       // Within check-in period
    Grace,       // Missed check-in, within grace period
    Deceased,    // Finalized deceased or timeout
    FinalAlive   // Council voted alive - cannot be marked deceased
}
```

## Contract Functions

### User Lifecycle
- `register(name, checkInPeriod, gracePeriod)` - Register with custom periods
- `register(name)` - Register with defaults
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
- `voteOnStatus(user, voteAlive)` - Vote during grace period
- `getCouncilMembers(user)` - Get council member list

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
```

## FHE Integration

The contract uses Zama's FHEVM for encrypted data:

- **Encrypted Strings**: Emails are padded to MAX_EMAIL_BYTE_LEN and split into euint256 limbs
- **Encrypted Integers**: Key shares stored as euint128
- **Access Control**: `FHE.allow()` grants decryption access to specific addresses
- **Coprocessor**: Uses ZamaConfig for coprocessor configuration

## Security Considerations

### Known Limitations
1. **No Recovery**: Users marked deceased cannot be recovered (except via council vote before finalization)
2. **FHE Permissions**: Once `FHE.allow()` is called, it cannot be revoked
3. **Timestamp Manipulation**: Block timestamps can be manipulated ~15 seconds
4. **ZK Verifier Placeholder**: Current implementation accepts proofs without verifier if not set

### Audit Findings
See `/home/pedro/Code/farewell/AUDIT.md` for security audit results.

## Development Guidelines

### Code Style
- Use OpenZeppelin patterns for upgradeability
- Prefer `unchecked` blocks for gas optimization where safe
- Use `storage` pointers to avoid unnecessary copies
- Follow Solidity naming conventions

### Testing
```bash
npx hardhat test                    # Run all tests
npx hardhat test --grep "register"  # Run specific tests
npx hardhat coverage                # Generate coverage report
```

### Deployment
```bash
npx hardhat deploy --network sepolia
npx hardhat verify --network sepolia <address>
```

## Cross-Project Compatibility

**IMPORTANT**: Changes to the contract interface affect both the Farewell UI and farewell-claimer:

1. **Farewell UI** (`../farewell/packages/site`) — generates ABIs from this contract via `genabi`. If you change function signatures, events, or structs, the UI's ABI must be regenerated.
2. **farewell-claimer** (`../farewell-claimer`) — parses claim package JSON files that contain data from `retrieve()`. If you change the retrieve return format or message struct fields, update the claimer's `_load_claim_package()` accordingly.
3. The claim package JSON format uses fields: `recipients`, `skShare`, `encryptedPayload`, `contentHash` — these map to contract data returned by `retrieve()`.

## Proof Architecture

See [docs/proof-structure.md](docs/proof-structure.md) for the complete delivery proof specification, including:
- End-to-end message lifecycle with ASCII diagrams
- Claim package and DeliveryProofJson formats
- Public signals (recipientEmailHash, dkimPubkeyHash, contentHash)
- Contract verification flow (`_verifyZkEmailProof`)
- Multi-recipient bitmap tracking
- Current PoC status vs future zk-email integration

## Related Projects

- **Farewell UI**: https://github.com/pdroalves/farewell
- **Farewell Claimer**: https://github.com/pdroalves/farewell-claimer
- **Farewell Decrypter**: https://github.com/pdroalves/farewell-decrypter
- **Zama FHEVM**: https://docs.zama.ai/fhevm

## Git Guidelines

- Use conventional commit messages (feat:, fix:, docs:, refactor:, etc.)
- Keep commits focused on a single logical change

## Maintenance Instructions

**IMPORTANT**: When making changes to this codebase:

1. **Update this CLAUDE.md** if contract interfaces, events, or architecture change
2. **Update README.md** if user-facing documentation changes
3. **Regenerate ABI** in farewell UI repo: `npm run genabi`
4. **Update docs/instructions_to_build_client.md** in farewell repo if APIs change
5. **Run tests** before committing: `npx hardhat test`
6. **Check gas costs** for new functions: `npx hardhat test --reporter gas`

Any AI agent working on this repository should ensure documentation stays synchronized with code changes.
