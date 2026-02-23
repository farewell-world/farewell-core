# Farewell

<p align="center"> <img src="assets/farewell-logo.png" alt="Farewell Logo" width="600"/> </p>

**Farewell** is a smart contract that allows people to leave **posthumous encrypted messages** to their loved ones.
It uses [Zama FHEVM](https://github.com/zama-ai/fhevm) to store encrypted data on-chain, enforce liveness checks, and release messages only after a configurable timeout.

Deployed on Ethereum, **Farewell inherits the reliability of decentralized infrastructure** — designed to keep functioning for decades without a central operator. Messages cannot be lost or tampered with once stored.

**Live Demo (Sepolia testnet)**: [https://farewell.world](https://farewell.world)

> **Status**: Proof-of-concept. Not production-ready.

---

## Features

- **Liveness check-in**: Users set a `checkInPeriod` (e.g. 6 months) and must periodically call `ping()` to prove they're alive.

- **Grace period with council voting**: After the check-in expires, a `gracePeriod` allows for unexpected delays. During this time, designated **council members** (up to 20) can vote to confirm liveness or assert death.

- **Encrypted messages with FHE**: Each message contains:
  - AES-encrypted payload (encrypted client-side before submission)
  - Recipient email encrypted via FHE (hidden until released)
  - Secret key share encrypted via FHE (for key reconstruction)
  - Optional public message (cleartext)

- **Claiming and delivery**: After a user is marked deceased:
  - Anyone can call `claim()` to mark a message for release (the `markDeceased()` caller has a 24-hour priority window)
  - `retrieve()` returns the FHE-decrypted delivery package: recipient email, key share, and encrypted payload

- **Rewards and proof of delivery**: Users can attach ETH rewards to messages. Claimers prove email delivery via zk-email proofs and claim the reward after all recipients are verified. See the [farewell-claimer](https://github.com/pdroalves/farewell-claimer) tool.

- **Blockchain persistence**: Running as a smart contract on Ethereum, the system needs no central server. Messages are permanent once stored.

---

## Protocol Flow

```
 ┌────────────┐      ┌────────────┐      ┌────────────┐      ┌────────────┐
 │   ALIVE    │─────>│   GRACE    │─────>│  DECEASED   │─────>│  CLAIMED   │
 │            │      │  PERIOD    │      │             │      │            │
 │ ping()     │      │ Council    │      │ markDeceased│      │ claim()    │
 │ resets     │      │ can vote   │      │ by anyone   │      │ retrieve() │
 │ timer      │      │            │      │             │      │            │
 └────────────┘      └────────────┘      └─────────────┘      └────────────┘
       ▲                   │                                        │
       │             Council votes                            Claimer sends
       │             user alive                           email + proves via
       └───────────────────┘                              zk-email, claims
                                                          reward on-chain
```

### Step by Step

1. **Register** — User sets name, check-in period, grace period. Optionally adds council members.

2. **Add messages** — User encrypts a message with AES-128, [splits the key using XOR](#key-sharing-scheme), and stores the encrypted payload + FHE-encrypted email + FHE-encrypted key share on-chain.

3. **Stay alive** — User calls `ping()` periodically to reset their check-in timer.

4. **Timeout** — If the user misses their check-in:
   - Grace period begins. Council members can vote.
   - If council votes "alive": timer resets, user gets `FinalAlive` status.
   - If council votes "deceased" or grace period expires without action: anyone can call `markDeceased()`.

5. **Claim** — After deceased status:
   - `claim(user, index)` grants the caller FHE decryption access.
   - `retrieve(user, index)` returns the encrypted data — the caller can now FHE-decrypt the recipient email and key share.

6. **Deliver & earn reward** — The claimer:
   - Downloads a claim package JSON from the [Farewell UI](https://farewell.world).
   - Uses the [farewell-claimer](https://github.com/pdroalves/farewell-claimer) tool to decrypt the message (using the off-chain secret `s'`), send it via email, and generate zk-email proofs.
   - Submits proofs on-chain via `proveDelivery()` and claims the reward with `claimReward()`.

---

## Key Sharing Scheme

The recipient needs a way to decrypt the message after the user passes away. Farewell uses a XOR-based key splitting scheme:

```
  User (while alive)                      Recipient (after death)
  ─────────────────                       ──────────────────────
  sk = AES-128 key                        Has s' (received off-chain)
  s  = random 128-bit                     Gets s  (FHE-decrypted from chain)
  s' = sk ⊕ s                             sk = s ⊕ s'
  ───────────────                         ──────────────────────
  Stores:                                 Decrypts:
    enc(s) on-chain (FHE)                   AES-128-GCM(sk, message)
    enc_sk(message) on-chain (AES)
  Shares s' with recipient off-chain
```

This ensures:
- **Before death**: Neither the recipient (has only `s'`) nor on-chain observers (see only `enc(s)`) can decrypt.
- **After death**: Only the intended recipient can combine both halves to reconstruct `sk`.

---

## Securing Messages

Messages are stored on the blockchain and are **publicly visible**, so they **must be encrypted client-side** before submission. The [Farewell UI](https://farewell.world) uses AES-128-GCM for this.

The recipient email and key share are stored via FHEVM — Zama's protocol keeps them hidden until a claimer is granted access via `FHE.allow()`.

---

## Contract API

### User Lifecycle

| Function | Description |
|----------|-------------|
| `register(name, checkInPeriod, gracePeriod)` | Register with custom periods |
| `register(name)` | Register with defaults (30 days check-in, 7 days grace) |
| `ping()` | Reset check-in timer |
| `markDeceased(user)` | Mark user deceased after timeout |
| `getUserState(user)` | Returns `(UserStatus, graceTimeRemaining)` |
| `setName(newName)` | Update display name |

### Messages

| Function | Description |
|----------|-------------|
| `addMessage(limbs, emailByteLen, encSkShare, payload, inputProof, publicMessage)` | Add FHE-encrypted message |
| `addMessageWithReward(...)` | Same, with ETH reward attached (sent as `msg.value`) |
| `editMessage(index, ...)` | Edit unclaimed message (owner only) |
| `revokeMessage(index)` | Revoke unclaimed message, refunds reward |
| `messageCount(user)` | Get number of messages |

### Claiming & Delivery

| Function | Description |
|----------|-------------|
| `claim(user, index)` | Claim message, grants FHE decryption access |
| `retrieve(owner, index)` | Retrieve encrypted message data (FHE handles + payload) |
| `proveDelivery(user, msgIndex, recipientIndex, proof)` | Submit Groth16 zk-email proof |
| `claimReward(user, msgIndex)` | Claim ETH reward after all recipients proven |
| `getMessageRewardInfo(user, index)` | Get reward amount and proof bitmap |

### Council

| Function | Description |
|----------|-------------|
| `addCouncilMember(member)` | Add council member (max 20) |
| `removeCouncilMember(member)` | Remove council member |
| `voteOnStatus(user, voteAlive)` | Vote during grace period |
| `getCouncilMembers(user)` | Get council member list |
| `getGraceVoteStatus(user)` | Get vote counts and decision |

### Key Constants

```solidity
uint64  constant DEFAULT_CHECKIN        = 30 days;
uint64  constant DEFAULT_GRACE          = 7 days;
uint32  constant MAX_EMAIL_BYTE_LEN     = 224;       // padded to prevent length leakage
uint32  constant MAX_PAYLOAD_BYTE_LEN   = 10240;     // 10 KB
uint256 constant BASE_REWARD            = 0.01 ether;
uint256 constant REWARD_PER_KB          = 0.005 ether;
uint8   constant MAX_COUNCIL_SIZE       = 20;
```

---

## Usage

### Build and Test

```bash
npm install
npx hardhat compile
npx hardhat test
```

### Deploy

```bash
npx hardhat deploy --network sepolia
```

---

## Notes & Limitations

- **Proof of Concept** — not production-ready. No guarantees of security, privacy, or delivery.
- **On-chain data is public** — message payloads are visible, which is why they must be encrypted client-side.
- **No recovery** — users marked deceased cannot be recovered (except via council vote *before* finalization).
- **FHE permissions are permanent** — once `FHE.allow()` is called, it cannot be revoked.
- **Timestamp risk** — block timestamps can be manipulated by ~15 seconds.

---

## Open Questions

### On-chain secrecy without external protocols

Is it possible to store and release encrypted key shares purely on-chain without depending on the Zama coprocessor?

[Discussion on GitHub](https://github.com/pdroalves/farewell-core/issues/2)

### Reliable delivery protocol

How can we define a delivery protocol that is friendly to delivery proofs and potentially better than email in terms of reliability and censorship resistance?

[Discussion on GitHub](https://github.com/pdroalves/farewell-core/issues/1)

---

## Building Alternative Clients

For a detailed guide on interacting with the Farewell contract programmatically (including FHE encryption, message operations, council management, and claiming workflows), see [instructions_to_build_client.md](https://github.com/pdroalves/farewell/blob/main/docs/instructions_to_build_client.md) in the main Farewell repository.

---

## Related Projects

- [Farewell UI](https://farewell.world) — Web application ([source](https://github.com/pdroalves/farewell))
- [farewell-claimer](https://github.com/pdroalves/farewell-claimer) — CLI tool for claiming rewards
- [Zama FHEVM](https://docs.zama.ai/fhevm) — Fully Homomorphic Encryption for Ethereum
- [zk.email](https://docs.zk.email/) — ZK email proofs

---

## Buy Me a Coffee (on-chain)

If you like this project:

**`0x6DB81c37e192f19197430ad027916495542B04bd`**

---

## Disclaimer

This is a personal project by the author, who is employed by [Zama](https://www.zama.ai/). Farewell is **not** an official Zama product, and Zama bears no responsibility for its development, maintenance, or use. All views and code are the author's own.

---

## License

BSD 3-Clause Clear License (see [LICENSE](LICENSE))
