# Building a Farewell Client

This document provides detailed instructions for building a client that implements all features supported by the
Farewell smart contract. The goal is to enable developers to create alternative frontends, mobile apps, or integrations
with the Farewell protocol.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Contract Overview](#contract-overview)
3. [Connecting to the Contract](#connecting-to-the-contract)
4. [FHE (Fully Homomorphic Encryption) Setup](#fhe-setup)
5. [User Lifecycle](#user-lifecycle)
6. [Message Operations](#message-operations)
7. [Council System](#council-system)
8. [Claiming and Delivery](#claiming-and-delivery)
9. [ZK-Email Proof Verification](#zk-email-proof-verification)
10. [Rewards System](#rewards-system)
11. [Error Handling](#error-handling)
12. [Events](#events)
13. [Complete Example: Full Workflow](#complete-example-full-workflow)
14. [Additional Resources](#additional-resources)

---

## Prerequisites

### Required Dependencies

```bash
npm install ethers fhevmjs
```

Note: The npm package is `fhevmjs` (from Zama), not `@fhenixprotocol/fhevmjs`.

### Contract Information

| Network         | Chain ID | Contract Address                             |
| --------------- | -------- | -------------------------------------------- |
| Sepolia         | 11155111 | `0x3997c9dD0eAEE743F6f94754fD161c3E9d0596B3` |
| Hardhat (Local) | 31337    | Varies per deployment                        |

### Loading the ABI

After compiling the contract with Hardhat, the ABI is available at `artifacts/contracts/Farewell.sol/Farewell.json`:

```typescript
// In your build process, you'll have compiled the contract:
// npx hardhat compile

// Import the ABI from the compiled artifact
import FarewellArtifact from "../artifacts/contracts/Farewell.sol/Farewell.json";

// Or, for browsers, manually copy the ABI from the artifact JSON file
const FarewellABI = FarewellArtifact.abi;
```

The artifact contains both the ABI and bytecode. For client usage, only the ABI is needed.

---

## Contract Overview

The Farewell contract manages:

- **Users**: Registration, check-in periods, grace periods
- **Messages**: Encrypted messages with FHE-protected recipient emails and key shares
- **Council**: Optional trusted members who can vote during grace period
- **Rewards**: ETH rewards for message delivery verification

### Key Constants

```solidity
uint64 constant DEFAULT_CHECKIN = 30 days;
uint64 constant DEFAULT_GRACE = 7 days;
uint32 constant MAX_EMAIL_BYTE_LEN = 224;
uint32 constant MAX_PAYLOAD_BYTE_LEN = 10240; // 10KB
uint256 constant BASE_REWARD = 0.01 ether;
uint256 constant REWARD_PER_KB = 0.005 ether;
```

---

## Connecting to the Contract

### Basic Setup

```typescript
import { ethers, BrowserProvider, Contract } from "ethers";
import FarewellArtifact from "../artifacts/contracts/Farewell.sol/Farewell.json";

const FAREWELL_ADDRESSES: Record<number, string> = {
  11155111: "0x3997c9dD0eAEE743F6f94754fD161c3E9d0596B3", // Sepolia
  // 31337: '0x...', // Hardhat (varies per deployment)
};

async function connectToContract() {
  // Get provider from wallet (MetaMask, WalletConnect, etc.)
  const provider = new BrowserProvider(window.ethereum);
  const signer = await provider.getSigner();
  const chainId = (await provider.getNetwork()).chainId;

  // Get contract address for current chain
  const address = FAREWELL_ADDRESSES[Number(chainId)];
  if (!address) throw new Error(`Unsupported chain: ${chainId}`);

  // Create contract instance
  const contract = new Contract(address, FarewellArtifact.abi, signer);

  return { contract, provider, signer };
}
```

---

## FHE Setup

Farewell uses Zama's FHEVM for encrypting recipient emails and key shares. You must initialize the FHE instance before
performing encryption operations.

### Initialize FHEVM

```typescript
import { createFhevmInstance, FhevmInstance } from "fhevmjs";

async function initFhevm(provider: BrowserProvider): Promise<FhevmInstance> {
  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);

  // Get FHE public key from the contract/coprocessor
  const instance = await createFhevmInstance({
    networkUrl: provider._network?.name,
    gatewayUrl: "https://gateway.zama.ai", // Zama's gateway
  });

  return instance;
}
```

### Encrypt a String (Email)

Emails must be padded to `MAX_EMAIL_BYTE_LEN` (224 bytes) and split into 32-byte limbs for FHE encryption.

```typescript
function padEmail(email: string): Uint8Array {
  const encoder = new TextEncoder();
  const emailBytes = encoder.encode(email);

  if (emailBytes.length > 224) {
    throw new Error("Email too long (max 224 bytes)");
  }

  // Pad to MAX_EMAIL_BYTE_LEN
  const padded = new Uint8Array(224);
  padded.set(emailBytes);
  return padded;
}

async function encryptEmail(
  fhevmInstance: FhevmInstance,
  email: string,
  contractAddress: string,
  userAddress: string,
): Promise<{ limbHandles: bigint[]; byteLen: number; inputProof: Uint8Array }> {
  const padded = padEmail(email);
  const byteLen = new TextEncoder().encode(email).length;

  // Split into 32-byte limbs (7 limbs for 224 bytes)
  const numLimbs = Math.ceil(224 / 32); // 7 limbs
  const limbHandles: bigint[] = [];

  const input = fhevmInstance.createEncryptedInput(contractAddress, userAddress);

  for (let i = 0; i < numLimbs; i++) {
    const limb = padded.slice(i * 32, (i + 1) * 32);
    const value = BigInt("0x" + Buffer.from(limb).toString("hex"));
    input.add256(value);
  }

  const encrypted = await input.encrypt();

  return {
    limbHandles: encrypted.handles,
    byteLen,
    inputProof: encrypted.inputProof,
  };
}
```

### Encrypt a Key Share (128-bit)

```typescript
async function encryptKeyShare(
  fhevmInstance: FhevmInstance,
  keyShare: Uint8Array, // 16 bytes (128 bits)
  contractAddress: string,
  userAddress: string,
): Promise<{ handle: bigint; inputProof: Uint8Array }> {
  if (keyShare.length !== 16) {
    throw new Error("Key share must be 16 bytes (128 bits)");
  }

  const value = BigInt("0x" + Buffer.from(keyShare).toString("hex"));

  const input = fhevmInstance.createEncryptedInput(contractAddress, userAddress);
  input.add128(value);

  const encrypted = await input.encrypt();

  return {
    handle: encrypted.handles[0],
    inputProof: encrypted.inputProof,
  };
}
```

---

## User Lifecycle

### States

```typescript
enum UserStatus {
  Alive = 0, // Within check-in period
  Grace = 1, // Missed check-in, within grace period
  Deceased = 2, // Finalized deceased or timeout
  FinalAlive = 3, // Council voted alive - cannot be marked deceased
}
```

### Register a User

```typescript
async function register(
  contract: Contract,
  name: string,
  checkInPeriod: number, // in seconds (min 1 day = 86400)
  gracePeriod: number, // in seconds (min 1 day = 86400)
): Promise<void> {
  const tx = await contract.register(name, checkInPeriod, gracePeriod);
  await tx.wait();
}

// Or use defaults (30 days check-in, 7 days grace)
async function registerWithDefaults(contract: Contract, name: string): Promise<void> {
  const tx = await contract["register(string)"](name);
  await tx.wait();
}
```

### Check Registration Status

```typescript
async function isRegistered(contract: Contract, address: string): Promise<boolean> {
  return await contract.isRegistered(address);
}
```

### Get User State

```typescript
async function getUserState(
  contract: Contract,
  address: string,
): Promise<{ status: UserStatus; graceSecondsLeft: bigint }> {
  const [status, graceSecondsLeft] = await contract.getUserState(address);
  return { status: Number(status) as UserStatus, graceSecondsLeft };
}
```

### Ping (Check-in)

Users must ping before their check-in period expires to remain "alive".

```typescript
async function ping(contract: Contract): Promise<void> {
  const tx = await contract.ping();
  await tx.wait();
}
```

### Mark as Deceased

Anyone can mark a user as deceased after their check-in + grace period expires.

```typescript
async function markDeceased(contract: Contract, userAddress: string): Promise<void> {
  const tx = await contract.markDeceased(userAddress);
  await tx.wait();
}
```

---

## Message Operations

### Add a Message

```typescript
async function addMessage(
  contract: Contract,
  fhevmInstance: FhevmInstance,
  recipientEmail: string,
  payload: Uint8Array, // AES-encrypted message content
  keyShare: Uint8Array, // 16-byte key share
  publicMessage?: string, // Optional cleartext message
): Promise<bigint> {
  const contractAddress = await contract.getAddress();
  const userAddress = await contract.runner.getAddress();

  // Encrypt recipient email
  const {
    limbHandles,
    byteLen,
    inputProof: emailProof,
  } = await encryptEmail(fhevmInstance, recipientEmail, contractAddress, userAddress);

  // Encrypt key share
  const { handle: skShareHandle, inputProof: skProof } = await encryptKeyShare(
    fhevmInstance,
    keyShare,
    contractAddress,
    userAddress,
  );

  // Combine input proofs
  const inputProof = new Uint8Array([...emailProof, ...skProof]);

  // Convert payload to hex
  const payloadHex = "0x" + Buffer.from(payload).toString("hex");

  const tx = await contract.addMessage(
    limbHandles,
    byteLen,
    skShareHandle,
    payloadHex,
    inputProof,
    publicMessage || "",
  );

  const receipt = await tx.wait();

  // Extract message index from event
  const event = receipt.logs.find((log) => log.topics[0] === contract.interface.getEvent("MessageAdded").topicHash);
  const decoded = contract.interface.decodeEventLog("MessageAdded", event.data, event.topics);

  return decoded.index;
}
```

### Add a Message with Reward

For zk-email verified delivery rewards:

```typescript
async function addMessageWithReward(
  contract: Contract,
  fhevmInstance: FhevmInstance,
  recipientEmail: string,
  payload: Uint8Array,
  keyShare: Uint8Array,
  publicMessage: string | undefined,
  recipientEmailHashes: `0x${string}`[], // Poseidon hashes of recipient emails
  payloadContentHash: `0x${string}`, // keccak256 of decrypted payload
  rewardAmount: bigint, // ETH reward in wei
): Promise<bigint> {
  // ... same encryption as above ...

  const tx = await contract.addMessageWithReward(
    limbHandles,
    byteLen,
    skShareHandle,
    payloadHex,
    inputProof,
    publicMessage || "",
    recipientEmailHashes,
    payloadContentHash,
    { value: rewardAmount },
  );

  const receipt = await tx.wait();
  // Extract index from event...
  return index;
}
```

### Get Message Count

```typescript
async function getMessageCount(contract: Contract, userAddress: string): Promise<bigint> {
  return await contract.messageCount(userAddress);
}
```

### Revoke a Message

Only the owner can revoke unclaimed messages while alive.

```typescript
async function revokeMessage(contract: Contract, index: bigint): Promise<void> {
  const tx = await contract.revokeMessage(index);
  await tx.wait();
}
```

### Edit a Message

```typescript
async function editMessage(
  contract: Contract,
  fhevmInstance: FhevmInstance,
  index: bigint,
  newRecipientEmail: string,
  newPayload: Uint8Array,
  newKeyShare: Uint8Array,
  newPublicMessage?: string,
): Promise<void> {
  // Similar to addMessage but calls editMessage
  const tx = await contract.editMessage(
    index,
    limbHandles,
    byteLen,
    skShareHandle,
    payloadHex,
    inputProof,
    newPublicMessage || "",
  );
  await tx.wait();
}
```

---

## Council System

Users can designate trusted council members who can vote during the grace period.

### Add Council Member

```typescript
async function addCouncilMember(contract: Contract, memberAddress: string): Promise<void> {
  const tx = await contract.addCouncilMember(memberAddress);
  await tx.wait();
}
```

### Remove Council Member

```typescript
async function removeCouncilMember(contract: Contract, memberAddress: string): Promise<void> {
  const tx = await contract.removeCouncilMember(memberAddress);
  await tx.wait();
}
```

### Get Council Members

```typescript
async function getCouncilMembers(
  contract: Contract,
  userAddress: string,
): Promise<{ members: string[]; joinedAts: bigint[] }> {
  const [members, joinedAts] = await contract.getCouncilMembers(userAddress);
  return { members, joinedAts };
}
```

### Vote on User Status (Council Only)

During grace period, council members can vote:

```typescript
async function voteOnStatus(contract: Contract, userAddress: string, voteAlive: boolean): Promise<void> {
  const tx = await contract.voteOnStatus(userAddress, voteAlive);
  await tx.wait();
}
```

### Get Vote Status

```typescript
async function getGraceVoteStatus(
  contract: Contract,
  userAddress: string,
): Promise<{
  aliveVotes: bigint;
  deadVotes: bigint;
  decided: boolean;
  decisionAlive: boolean;
}> {
  const [aliveVotes, deadVotes, decided, decisionAlive] = await contract.getGraceVoteStatus(userAddress);
  return { aliveVotes, deadVotes, decided, decisionAlive };
}
```

---

## Claiming and Delivery

### Claim a Message

After a user is marked deceased, anyone can claim messages. The person who marked the user deceased has a 24-hour
exclusivity window.

```typescript
async function claimMessage(contract: Contract, userAddress: string, messageIndex: bigint): Promise<void> {
  const tx = await contract.claim(userAddress, messageIndex);
  await tx.wait();
}
```

### Retrieve Message Data

After claiming, retrieve the encrypted data:

```typescript
async function retrieveMessage(
  contract: Contract,
  ownerAddress: string,
  index: bigint,
): Promise<{
  skShare: bigint;
  encodedRecipientEmail: bigint[];
  emailByteLen: number;
  payload: Uint8Array;
  publicMessage: string;
  hash: `0x${string}`;
}> {
  const result = await contract.retrieve(ownerAddress, index);
  return {
    skShare: result.skShare,
    encodedRecipientEmail: result.encodedRecipientEmail,
    emailByteLen: Number(result.emailByteLen),
    payload: ethers.getBytes(result.payload),
    publicMessage: result.publicMessage,
    hash: result.hash,
  };
}
```

### Decrypt Retrieved Data

Use FHEVM's decryption mechanism:

```typescript
async function decryptMessage(
  fhevmInstance: FhevmInstance,
  skShareHandle: bigint,
  emailLimbHandles: bigint[],
  emailByteLen: number,
  contractAddress: string,
  userAddress: string,
): Promise<{ email: string; keyShare: Uint8Array }> {
  // Request decryption from the gateway
  const decryptedKeyShare = await fhevmInstance.decrypt128(contractAddress, skShareHandle);

  // Decrypt email limbs
  const decryptedLimbs: Uint8Array[] = [];
  for (const handle of emailLimbHandles) {
    const decrypted = await fhevmInstance.decrypt256(contractAddress, handle);
    decryptedLimbs.push(decrypted);
  }

  // Reconstruct email from limbs
  const fullEmail = new Uint8Array(224);
  for (let i = 0; i < decryptedLimbs.length; i++) {
    fullEmail.set(decryptedLimbs[i], i * 32);
  }

  // Trim to actual length
  const email = new TextDecoder().decode(fullEmail.slice(0, emailByteLen));

  return {
    email,
    keyShare: decryptedKeyShare,
  };
}
```

---

## ZK-Email Proof Verification

For messages with rewards, claimers must prove delivery via zk-email proofs.

### Proof Structure

```typescript
interface ZkEmailProof {
  pA: [bigint, bigint];
  pB: [[bigint, bigint], [bigint, bigint]];
  pC: [bigint, bigint];
  publicSignals: bigint[]; // [recipientEmailHash, dkimPubkeyHash, contentHash]
}
```

### Prove Delivery

```typescript
async function proveDelivery(
  contract: Contract,
  userAddress: string,
  messageIndex: bigint,
  recipientIndex: number,
  proof: ZkEmailProof,
): Promise<void> {
  const tx = await contract.proveDelivery(userAddress, messageIndex, recipientIndex, {
    pA: proof.pA,
    pB: proof.pB,
    pC: proof.pC,
    publicSignals: proof.publicSignals,
  });
  await tx.wait();
}
```

### Get Reward Info

```typescript
async function getMessageRewardInfo(
  contract: Contract,
  userAddress: string,
  messageIndex: bigint,
): Promise<{
  reward: bigint;
  numRecipients: bigint;
  provenRecipientsBitmap: bigint;
  payloadContentHash: `0x${string}`;
}> {
  const result = await contract.getMessageRewardInfo(userAddress, messageIndex);
  return {
    reward: result.reward,
    numRecipients: result.numRecipients,
    provenRecipientsBitmap: result.provenRecipientsBitmap,
    payloadContentHash: result.payloadContentHash,
  };
}
```

---

## Rewards System

### Deposit ETH for Delivery Costs

```typescript
async function deposit(contract: Contract, amount: bigint): Promise<void> {
  const tx = await contract.deposit({ value: amount });
  await tx.wait();
}
```

### Get Deposit Balance

```typescript
async function getDeposit(contract: Contract, userAddress: string): Promise<bigint> {
  return await contract.getDeposit(userAddress);
}
```

### Claim Reward (After All Proofs)

```typescript
async function claimReward(contract: Contract, userAddress: string, messageIndex: bigint): Promise<void> {
  const tx = await contract.claimReward(userAddress, messageIndex);
  await tx.wait();
}
```

---

## Error Handling

### Common Contract Errors

| Error Message                        | Cause                                     | Solution                         |
| ------------------------------------ | ----------------------------------------- | -------------------------------- |
| `"not registered"`                   | User hasn't registered                    | Call `register()` first          |
| `"user marked deceased"`             | Cannot modify deceased user's data        | N/A                              |
| `"not timed out"`                    | Trying to mark deceased too early         | Wait for check-in + grace period |
| `"still exclusive for the notifier"` | Trying to claim within 24h exclusivity    | Wait for exclusivity to expire   |
| `"message was revoked"`              | Message was revoked by owner              | Cannot claim revoked messages    |
| `"not the claimer"`                  | Trying to retrieve without claiming first | Call `claim()` first             |
| `"not all recipients proven"`        | Trying to claim reward before all proofs  | Submit remaining proofs          |

### Extracting Revert Reasons

```typescript
function extractRevertReason(error: unknown): string {
  if (error instanceof Error) {
    // Check for revert reason in error message
    const match = error.message.match(/reason="([^"]+)"/);
    if (match) return match[1];

    // Check for custom error
    if ("reason" in error) return (error as any).reason;

    return error.message;
  }
  return String(error);
}
```

---

## Events

Subscribe to contract events for real-time updates:

```typescript
// User events
contract.on("UserRegistered", (user, checkInPeriod, gracePeriod, registeredOn) => {
  console.log("User registered:", user);
});

contract.on("Ping", (user, when) => {
  console.log("User pinged:", user);
});

contract.on("Deceased", (user, when, notifier) => {
  console.log("User marked deceased:", user, "by", notifier);
});

// Message events
contract.on("MessageAdded", (user, index) => {
  console.log("Message added:", user, "index:", index);
});

contract.on("Claimed", (user, index, claimer) => {
  console.log("Message claimed:", user, "index:", index, "by:", claimer);
});

// Reward events
contract.on("DeliveryProven", (user, messageIndex, recipientIndex, claimer) => {
  console.log("Delivery proven:", user, messageIndex, recipientIndex);
});

contract.on("RewardClaimed", (user, messageIndex, claimer, amount) => {
  console.log("Reward claimed:", claimer, "amount:", amount);
});
```

---

## Complete Example: Full Workflow

```typescript
async function farewellWorkflow() {
  // 1. Connect
  const { contract, provider, signer } = await connectToContract();
  const fhevmInstance = await initFhevm(provider);
  const userAddress = await signer.getAddress();

  // 2. Register
  if (!(await contract.isRegistered(userAddress))) {
    await register(contract, "My Name", 30 * 24 * 3600, 7 * 24 * 3600);
  }

  // 3. Add a message
  const message = "Goodbye, my friend. You meant the world to me.";
  const aesKey = crypto.getRandomValues(new Uint8Array(16));
  const keyShare = crypto.getRandomValues(new Uint8Array(16));

  // Encrypt message with AES
  const encrypted = await aesEncrypt(message, aesKey);

  // Store s' = sk XOR s (for recipient)
  const sPrime = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    sPrime[i] = aesKey[i] ^ keyShare[i];
  }
  // Share sPrime with recipient off-chain

  const messageIndex = await addMessage(
    contract,
    fhevmInstance,
    "recipient@example.com",
    encrypted,
    keyShare, // s (stored on-chain encrypted)
    "A message for when I'm gone",
  );

  // 4. Ping periodically
  await ping(contract);

  // 5. (If deceased) Claim and deliver
  // ... handled by claimer ...
}
```

---

## Additional Resources

### Live Demos and Tools

- **Farewell Web UI**: [farewell.world](https://farewell.world)
- **Farewell Claimer**: [github.com/farewell-world/farewell-claimer](https://github.com/farewell-world/farewell-claimer)
- **Farewell Decrypter**:
  [github.com/farewell-world/farewell-decrypter](https://github.com/farewell-world/farewell-decrypter)

### External Documentation

- **Zama FHEVM Docs**: [docs.zama.ai/fhevm](https://docs.zama.ai/fhevm)
- **zk-email**: [prove.email](https://prove.email)

### Related Documentation

- [Protocol Specification](protocol.md)
- [Contract API Reference](contract-api.md)
- [Delivery Proof Architecture](proof-structure.md)
