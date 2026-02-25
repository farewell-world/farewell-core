# Farewell

[![CI](https://github.com/farewell-world/farewell-core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/farewell-world/farewell-core/actions/workflows/ci.yml?query=branch%3Amain)
[![License: BSD-3-Clause-Clear](https://img.shields.io/badge/License-BSD--3--Clause--Clear-blue.svg)](LICENSE)

<p align="center"> <img src="assets/farewell-white-bg.png" alt="Farewell Logo" width="600"/> </p>

**Farewell** is a smart contract that lets people leave **posthumous encrypted messages** to their loved ones. It uses
[Zama FHEVM](https://github.com/zama-ai/fhevm) to store encrypted data on-chain, enforces liveness checks, and releases
messages only after a configurable timeout.

Running on Ethereum, Farewell inherits the reliability of decentralized infrastructure — designed to keep functioning
for decades without a central operator.

**Live on Sepolia**: [farewell.world](https://farewell.world)

> **Status**: Beta — deployed on Sepolia testnet.

---

## How It Works

1. **Register** — Set a check-in period (e.g. 6 months) and optionally add trusted council members.

2. **Store messages** — Encrypt a message with AES-128,
   [split the key using XOR](docs/protocol.md#4-key-sharing-scheme), and store the encrypted payload along with
   FHE-encrypted recipient email and key share on-chain.

3. **Stay alive** — Call `ping()` periodically to reset the check-in timer.

4. **Timeout** — If a check-in is missed, a grace period begins. Council members can vote on liveness. If the grace
   period expires without action, anyone can call `markDeceased()`.

5. **Claim and deliver** — After deceased status, a claimer calls `claim()` and `retrieve()` to get the encrypted data,
   delivers the message to recipients via email, and earns an ETH reward by proving delivery with zk-email proofs.

For the full protocol specification, see [docs/protocol.md](docs/protocol.md).

---

## Features

- **Liveness check-in** with configurable period and grace window
- **Council voting** — up to 20 trusted members can vote during the grace period
- **FHE-encrypted** recipient emails and key shares (Zama FHEVM)
- **AES-128-GCM** client-side message encryption with XOR key splitting
- **Delivery rewards** — ETH rewards for verified email delivery via zk-email proofs
- **Blockchain persistence** — no central server, messages are permanent once stored

---

## Quick Start

```bash
npm install
npx hardhat compile
npx hardhat test
```

### Deploy

```bash
npx hardhat deploy --network sepolia
```

### Deployed Addresses

| Network | Chain ID | Proxy Address                                |
| ------- | -------- | -------------------------------------------- |
| Sepolia | 11155111 | `0x3997c9dD0eAEE743F6f94754fD161c3E9d0596B3` |
| Hardhat | 31337    | Local deployment (varies)                    |

---

## Contract API (Quick Reference)

### User Lifecycle

| Function                                     | Description                         |
| -------------------------------------------- | ----------------------------------- |
| `register(name, checkInPeriod, gracePeriod)` | Register or update settings         |
| `register(name)`                             | Register with defaults (30d / 7d)   |
| `ping()`                                     | Reset check-in timer                |
| `markDeceased(user)`                         | Mark user deceased after timeout    |
| `getUserState(user)`                         | Get status and grace time remaining |
| `setName(newName)`                           | Update display name                 |

### Messages

| Function                    | Description                     |
| --------------------------- | ------------------------------- |
| `addMessage(...)`           | Add FHE-encrypted message       |
| `addMessageWithReward(...)` | Add message with ETH reward     |
| `editMessage(index, ...)`   | Edit unclaimed message          |
| `revokeMessage(index)`      | Revoke message (refunds reward) |
| `messageCount(user)`        | Get message count               |

### Claiming & Delivery

| Function                                               | Description                       |
| ------------------------------------------------------ | --------------------------------- |
| `claim(user, index)`                                   | Claim message, grants FHE access  |
| `retrieve(owner, index)`                               | Retrieve encrypted data           |
| `proveDelivery(user, msgIndex, recipientIndex, proof)` | Submit zk-email delivery proof    |
| `claimReward(user, msgIndex)`                          | Claim ETH reward after all proofs |

### Council

| Function                        | Description                 |
| ------------------------------- | --------------------------- |
| `addCouncilMember(member)`      | Add council member (max 20) |
| `removeCouncilMember(member)`   | Remove council member       |
| `voteOnStatus(user, voteAlive)` | Vote during grace period    |

For full signatures, parameters, return values, events, and error messages, see the
[Contract API Reference](docs/contract-api.md).

---

## Documentation

| Document                                               | Description                                                                      |
| ------------------------------------------------------ | -------------------------------------------------------------------------------- |
| [Protocol Specification](docs/protocol.md)             | Full protocol design — lifecycle, encryption, key sharing, FHE, council, rewards |
| [Contract API Reference](docs/contract-api.md)         | Every function, event, struct, constant, and error message                       |
| [Building a Client](docs/building-a-client.md)         | Step-by-step guide with TypeScript examples for building alternative clients     |
| [Delivery Proof Architecture](docs/proof-structure.md) | zk-email proof format, verification flow, and data structures                    |

---

## Building Alternative Clients

Want to build your own frontend, mobile app, or tool that interacts with Farewell? The
[Building a Client](docs/building-a-client.md) guide covers everything: FHE setup, email encryption, message operations,
council management, claiming workflows, and a complete working example.

To get the ABI, compile the contract and load it from the Hardhat artifact:

```bash
npx hardhat compile
# ABI at: artifacts/contracts/Farewell.sol/Farewell.json
```

---

## Limitations

- **No recovery** — users marked deceased cannot be recovered (except via council vote before finalization).
- **FHE permissions are permanent** — once `FHE.allow()` is called, it cannot be revoked.
- **On-chain data is public** — payloads are visible, so they must be encrypted client-side.
- **Timestamp risk** — block timestamps can be manipulated by ~15 seconds.
- **ZK verifier** — the Groth16 verifier contract must be configured by the contract owner.

---

## Open Questions

### On-chain secrecy without external protocols

Is it possible to store and release encrypted key shares purely on-chain without depending on the Zama coprocessor?

[Discussion on GitHub](https://github.com/farewell-world/farewell-core/issues/2)

### Reliable delivery protocol

How can we define a delivery protocol that is friendly to delivery proofs and potentially better than email in terms of
reliability and censorship resistance?

[Discussion on GitHub](https://github.com/farewell-world/farewell-core/issues/1)

---

## Related Projects

- [Farewell UI](https://farewell.world) — Web application
- [farewell-claimer](https://github.com/farewell-world/farewell-claimer) — CLI tool for claiming and delivering messages
- [farewell-decrypter](https://github.com/farewell-world/farewell-decrypter) — Browser-based message decryption tool
- [Zama FHEVM](https://docs.zama.ai/fhevm) — Fully Homomorphic Encryption for Ethereum
- [zk.email](https://docs.zk.email/) — ZK email proofs

---

## Support the Project

If you find Farewell interesting or useful, consider sending a donation on Ethereum or any EVM-compatible chain:

**`0x6DB81c37e192f19197430ad027916495542B04bd`**

---

## Disclaimer

This is a personal project by the author, who is employed by [Zama](https://www.zama.ai/). Farewell is **not** an
official Zama product, and Zama bears no responsibility for its development, maintenance, or use. All views and code are
the author's own.

---

## License

BSD 3-Clause Clear License (see [LICENSE](LICENSE))
